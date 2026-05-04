// Package graph — dashboard_queries.go
//
// DashboardQueries provides per-tenant Cypher helpers used by the
// GraphService gRPC handlers. All queries route through ExecuteRead on a
// per-tenant SessionGraphClient so that tenant isolation is enforced both by
// the Neo4j per-database chokepoint (pool.For) and by explicit
// WHERE n.tenant_id = $tenant predicates (defense in depth, per design D7).
//
// Cypher bodies are ported from
// enterprise/platform/dashboard/src/lib/neo4j-client.ts (lines 324–439).
// That TypeScript file is deleted in Phase 8; this Go file is the canonical
// source of graph query logic after that point.
package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j/dbtype"
	"github.com/zero-day-ai/sdk/auth"
	graphpb "github.com/zero-day-ai/sdk/api/gen/gibson/graph/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// DefaultGraphLimit is used when the caller sends limit = 0.
	DefaultGraphLimit uint32 = 1000
	// MaxGraphLimit is the hard server-side cap on returned nodes (design Component 4).
	MaxGraphLimit uint32 = 5000
	// DefaultPathDepth is used when the caller sends max_depth = 0.
	DefaultPathDepth uint32 = 5
	// MaxPathDepth is the hard cap on path hops to prevent runaway queries.
	MaxPathDepth uint32 = 10
	// MaxPathCount is the maximum number of paths returned by QueryPaths.
	MaxPathCount = 100
)

// DashboardQueries executes graph reads for the GraphService gRPC handlers.
// One instance should be created per RPC call (not shared across goroutines).
type DashboardQueries struct {
	client GraphClient
}

// NewDashboardQueries wraps client with the dashboard-specific query helpers.
func NewDashboardQueries(client GraphClient) *DashboardQueries {
	return &DashboardQueries{client: client}
}

// GetFullGraph returns the tenant's graph up to limit nodes, optionally
// filtered to nodes carrying any of the requested labels.
//
// Returns (nodes, edges, truncated, totalNodeCount, error).
// totalNodeCount is the pre-truncation count; truncated is true when it
// exceeds limit. limit=0 → DefaultGraphLimit; limit>MaxGraphLimit → MaxGraphLimit.
func (q *DashboardQueries) GetFullGraph(
	ctx context.Context,
	tenantID auth.TenantID,
	limit uint32,
	labels []string,
) ([]*graphpb.Node, []*graphpb.Edge, bool, uint32, error) {
	limit = applyLimitCap(limit)
	tenant := tenantID.String()

	// --- Phase 1: total count (for truncation flag) ---
	totalCount, err := q.countNodes(ctx, tenant, labels)
	if err != nil {
		return nil, nil, false, 0, err
	}

	// --- Phase 2: fetch nodes ---
	nodes, err := q.fetchNodes(ctx, tenant, labels, limit)
	if err != nil {
		return nil, nil, false, 0, err
	}
	if len(nodes) == 0 {
		return nil, nil, false, totalCount, nil
	}

	// --- Phase 3: fetch edges between returned nodes ---
	nodeIDs := make([]string, 0, len(nodes))
	for _, n := range nodes {
		nodeIDs = append(nodeIDs, n.Id)
	}
	edges, err := q.fetchEdges(ctx, tenant, nodeIDs)
	if err != nil {
		return nil, nil, false, 0, err
	}

	truncated := totalCount > limit
	return nodes, edges, truncated, totalCount, nil
}

// GetMissionGraph returns the subgraph for a specific mission within the
// tenant. The WHERE clause enforces tenant ownership (defense in depth on top
// of the FGA check at ext-authz).
func (q *DashboardQueries) GetMissionGraph(
	ctx context.Context,
	tenantID auth.TenantID,
	missionID string,
) ([]*graphpb.Node, []*graphpb.Edge, error) {
	tenant := tenantID.String()

	cypher := `
MATCH (run:mission_run {mission_id: $mission_id})
WHERE run.tenant_id = $tenant
MATCH (n)-[:BELONGS_TO]->(run)
WHERE n.tenant_id = $tenant
RETURN DISTINCT n, labels(n) AS lbls
LIMIT 5000
`
	nodes, err := q.runNodeFetch(ctx, cypher, map[string]any{
		"mission_id": missionID,
		"tenant":     tenant,
	})
	if err != nil {
		return nil, nil, err
	}
	if len(nodes) == 0 {
		return nil, nil, nil
	}

	nodeIDs := make([]string, 0, len(nodes))
	for _, n := range nodes {
		nodeIDs = append(nodeIDs, n.Id)
	}
	edges, err := q.fetchEdges(ctx, tenant, nodeIDs)
	if err != nil {
		return nil, nil, err
	}
	return nodes, edges, nil
}

// QueryPaths runs a bounded path search from fromID to either a specific
// toNodeID or any node of toNodeKind, capped at maxDepth hops and MaxPathCount.
// Exactly one of toNodeID or toNodeKind must be non-empty.
//
// Returns (paths, de-duplicated nodes, de-duplicated edges, truncated, error).
func (q *DashboardQueries) QueryPaths(
	ctx context.Context,
	tenantID auth.TenantID,
	fromID, toNodeID, toNodeKind string,
	maxDepth uint32,
) ([]*graphpb.Path, []*graphpb.Node, []*graphpb.Edge, bool, error) {
	maxDepth = applyDepthCap(maxDepth)
	tenant := tenantID.String()

	var cypher string
	params := map[string]any{
		"from_id":   fromID,
		"tenant":    tenant,
		"max_paths": MaxPathCount + 1, // fetch one extra to detect truncation
	}

	if toNodeID != "" {
		cypher = fmt.Sprintf(`
MATCH (a {id: $from_id}), (b {id: $to_id})
WHERE a.tenant_id = $tenant AND b.tenant_id = $tenant
MATCH p = (a)-[*1..%d]->(b)
RETURN p
LIMIT $max_paths
`, maxDepth)
		params["to_id"] = toNodeID
	} else {
		// toNodeKind is already validated by the caller; embed directly in the
		// query string because Cypher does not support parameterised label names.
		// The caller must sanitise the input (alphanumeric + underscore).
		cypher = fmt.Sprintf(`
MATCH (a {id: $from_id})
WHERE a.tenant_id = $tenant
MATCH p = (a)-[*1..%d]->(b:%s)
WHERE b.tenant_id = $tenant
RETURN p
LIMIT $max_paths
`, maxDepth, toNodeKind)
	}

	type result struct {
		paths    []*graphpb.Path
		nodes    map[string]*graphpb.Node
		edges    map[string]*graphpb.Edge
		rawCount int
	}

	raw, err := q.client.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}
		records, err := res.Collect(ctx)
		if err != nil {
			return nil, err
		}

		pr := &result{
			nodes: make(map[string]*graphpb.Node),
			edges: make(map[string]*graphpb.Edge),
		}
		pr.rawCount = len(records)

		for _, rec := range records {
			rawPath, ok := rec.Get("p")
			if !ok {
				continue
			}
			neoPath, ok := rawPath.(dbtype.Path)
			if !ok {
				continue
			}

			pbPath := &graphpb.Path{}
			for _, neoNode := range neoPath.Nodes {
				pbNode := neoNodeToProto(neoNode)
				pr.nodes[pbNode.Id] = pbNode
				pbPath.NodeIds = append(pbPath.NodeIds, pbNode.Id)
			}
			for _, neoRel := range neoPath.Relationships {
				pbEdge := neoRelToProto(neoRel)
				pr.edges[pbEdge.Id] = pbEdge
				pbPath.EdgeIds = append(pbPath.EdgeIds, pbEdge.Id)
			}
			pr.paths = append(pr.paths, pbPath)
		}
		return pr, nil
	})
	if err != nil {
		return nil, nil, nil, false, err
	}
	if raw == nil {
		return nil, nil, nil, false, nil
	}

	pr := raw.(*result)
	truncated := pr.rawCount > MaxPathCount
	if truncated && len(pr.paths) > MaxPathCount {
		pr.paths = pr.paths[:MaxPathCount]
	}

	outNodes := make([]*graphpb.Node, 0, len(pr.nodes))
	for _, n := range pr.nodes {
		outNodes = append(outNodes, n)
	}
	outEdges := make([]*graphpb.Edge, 0, len(pr.edges))
	for _, e := range pr.edges {
		outEdges = append(outEdges, e)
	}
	return pr.paths, outNodes, outEdges, truncated, nil
}

// ---------------------------------------------------------------------------
// Internal query helpers
// ---------------------------------------------------------------------------

func (q *DashboardQueries) countNodes(ctx context.Context, tenant string, labels []string) (uint32, error) {
	cypher, params := buildCountCypher(tenant, labels)
	raw, err := q.client.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}
		records, err := res.Collect(ctx)
		if err != nil {
			return nil, err
		}
		if len(records) == 0 {
			return uint32(0), nil
		}
		val, ok := records[0].Get("count")
		if !ok {
			return uint32(0), nil
		}
		return toUint32(val), nil
	})
	if err != nil {
		return 0, err
	}
	if raw == nil {
		return 0, nil
	}
	return raw.(uint32), nil
}

func (q *DashboardQueries) fetchNodes(ctx context.Context, tenant string, labels []string, limit uint32) ([]*graphpb.Node, error) {
	cypher, params := buildNodeFetchCypher(tenant, labels, limit)
	return q.runNodeFetch(ctx, cypher, params)
}

func (q *DashboardQueries) runNodeFetch(ctx context.Context, cypher string, params map[string]any) ([]*graphpb.Node, error) {
	raw, err := q.client.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}
		records, err := res.Collect(ctx)
		if err != nil {
			return nil, err
		}
		var nodes []*graphpb.Node
		for _, rec := range records {
			rawNode, ok := rec.Get("n")
			if !ok {
				continue
			}
			neoNode, ok := rawNode.(dbtype.Node)
			if !ok {
				continue
			}
			nodes = append(nodes, neoNodeToProto(neoNode))
		}
		return nodes, nil
	})
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	return raw.([]*graphpb.Node), nil
}

func (q *DashboardQueries) fetchEdges(ctx context.Context, tenant string, nodeIDs []string) ([]*graphpb.Edge, error) {
	if len(nodeIDs) == 0 {
		return nil, nil
	}
	cypher := `
MATCH (n1)-[r]->(n2)
WHERE n1.id IN $node_ids AND n2.id IN $node_ids
  AND n1.tenant_id = $tenant AND n2.tenant_id = $tenant
RETURN DISTINCT r, type(r) AS rel_type,
       n1.id AS src_id,
       n2.id AS tgt_id,
       toString(id(r)) AS rel_id
`
	raw, err := q.client.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cypher, map[string]any{
			"node_ids": nodeIDs,
			"tenant":   tenant,
		})
		if err != nil {
			return nil, err
		}
		records, err := res.Collect(ctx)
		if err != nil {
			return nil, err
		}
		var edges []*graphpb.Edge
		for _, rec := range records {
			relID, _ := rec.Get("rel_id")
			srcID, _ := rec.Get("src_id")
			tgtID, _ := rec.Get("tgt_id")
			relType, _ := rec.Get("rel_type")

			edge := &graphpb.Edge{
				Id:         stringify(relID),
				SourceId:   stringify(srcID),
				TargetId:   stringify(tgtID),
				Type:       stringify(relType),
				Properties: make(map[string]string),
			}

			// Fill properties from the relationship if available.
			if rawRel, ok := rec.Get("r"); ok {
				if neoRel, ok := rawRel.(dbtype.Relationship); ok {
					edge.Properties = coerceProps(neoRel.Props)
				}
			}
			edges = append(edges, edge)
		}
		return edges, nil
	})
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	return raw.([]*graphpb.Edge), nil
}

// ---------------------------------------------------------------------------
// Cypher builders
// ---------------------------------------------------------------------------

func buildCountCypher(tenant string, labels []string) (string, map[string]any) {
	params := map[string]any{"tenant": tenant}
	q := "MATCH (n) WHERE n.tenant_id = $tenant"
	if len(labels) > 0 {
		conds := make([]string, 0, len(labels))
		for _, lbl := range labels {
			conds = append(conds, fmt.Sprintf("n:`%s`", lbl))
		}
		q += " AND (" + strings.Join(conds, " OR ") + ")"
	}
	q += " RETURN count(n) AS count"
	return q, params
}

func buildNodeFetchCypher(tenant string, labels []string, limit uint32) (string, map[string]any) {
	params := map[string]any{
		"tenant": tenant,
		"limit":  int64(limit),
	}
	q := "MATCH (n) WHERE n.tenant_id = $tenant"
	if len(labels) > 0 {
		conds := make([]string, 0, len(labels))
		for _, lbl := range labels {
			conds = append(conds, fmt.Sprintf("n:`%s`", lbl))
		}
		q += " AND (" + strings.Join(conds, " OR ") + ")"
	}
	q += " RETURN DISTINCT n, labels(n) AS lbls LIMIT $limit"
	return q, params
}

// ---------------------------------------------------------------------------
// Neo4j → proto coercion (ported from neo4j-client.ts lines 365–373, 416–424)
// ---------------------------------------------------------------------------

// neoNodeToProto converts a dbtype.Node to a graphpb.Node.
// Properties are coerced to strings to preserve integer and temporal type
// fidelity through proto3 (design Component 1).
func neoNodeToProto(n dbtype.Node) *graphpb.Node {
	id := ""
	if v, ok := n.Props["id"]; ok {
		id = stringify(v)
	} else {
		id = fmt.Sprintf("%d", n.Id)
	}

	severity := ""
	if v, ok := n.Props["severity"]; ok {
		severity = stringify(v)
	}

	var firstSeen *timestamppb.Timestamp
	for _, key := range []string{"first_seen_at", "created_at"} {
		if v, ok := n.Props[key]; ok {
			if ts := toTimestamp(v); ts != nil {
				firstSeen = ts
				break
			}
		}
	}

	return &graphpb.Node{
		Id:          id,
		Labels:      n.Labels,
		Properties:  coerceProps(n.Props),
		FirstSeenAt: firstSeen,
		Severity:    severity,
	}
}

// neoRelToProto converts a dbtype.Relationship to a graphpb.Edge.
func neoRelToProto(r dbtype.Relationship) *graphpb.Edge {
	return &graphpb.Edge{
		Id:         fmt.Sprintf("%d", r.Id),
		SourceId:   fmt.Sprintf("%d", r.StartId),
		TargetId:   fmt.Sprintf("%d", r.EndId),
		Type:       r.Type,
		Properties: coerceProps(r.Props),
	}
}

// coerceProps converts a Neo4j properties map to map[string]string for proto.
// Each value is stringified to preserve integer, float, temporal and list
// fidelity — matching the TypeScript coercion in neo4j-client.ts:365–373,416–424.
func coerceProps(props map[string]any) map[string]string {
	out := make(map[string]string, len(props))
	for k, v := range props {
		out[k] = valueToString(v)
	}
	return out
}

// valueToString converts a single Neo4j property value to its string form.
func valueToString(v any) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case bool:
		if val {
			return "true"
		}
		return "false"
	case int64:
		return fmt.Sprintf("%d", val)
	case float64:
		return fmt.Sprintf("%g", val)
	case int:
		return fmt.Sprintf("%d", val)
	case int32:
		return fmt.Sprintf("%d", val)
	default:
		// For complex types (lists, maps, neo4j temporal structs), JSON-encode.
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(b)
	}
}

// stringify converts any value to a plain string (not JSON-encoded).
func stringify(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// toUint32 converts a count value to uint32.
func toUint32(v any) uint32 {
	switch val := v.(type) {
	case int64:
		if val < 0 {
			return 0
		}
		return uint32(val)
	case float64:
		if val < 0 {
			return 0
		}
		return uint32(val)
	case int:
		if val < 0 {
			return 0
		}
		return uint32(val)
	default:
		return 0
	}
}

// toTimestamp converts Neo4j temporal dbtype values to proto Timestamps.
// The Neo4j v5 Go driver represents DateTime (with timezone) as time.Time;
// Date, LocalDateTime, LocalTime are distinct Go types defined in dbtype.
func toTimestamp(v any) *timestamppb.Timestamp {
	switch val := v.(type) {
	case time.Time:
		if !val.IsZero() {
			return timestamppb.New(val)
		}
		return nil
	case dbtype.Date:
		return timestamppb.New(val.Time())
	case dbtype.LocalDateTime:
		return timestamppb.New(val.Time())
	default:
		_ = val
		return nil
	}
}

// applyLimitCap clamps limit to [1, MaxGraphLimit]; zero → DefaultGraphLimit.
func applyLimitCap(limit uint32) uint32 {
	if limit == 0 {
		return DefaultGraphLimit
	}
	if limit > MaxGraphLimit {
		return MaxGraphLimit
	}
	return limit
}

// applyDepthCap clamps maxDepth to [1, MaxPathDepth]; zero → DefaultPathDepth.
func applyDepthCap(depth uint32) uint32 {
	if depth == 0 {
		return DefaultPathDepth
	}
	if depth > MaxPathDepth {
		return MaxPathDepth
	}
	return depth
}
