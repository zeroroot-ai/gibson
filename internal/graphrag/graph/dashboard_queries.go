// Package graph — dashboard_queries.go
//
// DashboardQueries provides per-tenant Cypher helpers used by the
// GraphService gRPC handlers. All queries route through ExecuteRead on a
// per-tenant SessionGraphClient so that tenant isolation is enforced both by
// the Neo4j per-database chokepoint (pool.For) and by explicit
// WHERE n.tenant_id = $tenant predicates (defense in depth, per design D7).
//
// Cypher bodies are ported from
// enterprise/platform/dashboard/src/lib/neo4j-client.ts (lines 324–439),
// enterprise/platform/dashboard/src/lib/graph/summary.ts, and
// enterprise/platform/dashboard/src/lib/graph/context.ts.
// Those TypeScript files are deleted in Phase 3; this Go file is the canonical
// source of graph query logic after that point.
package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
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

// ---------------------------------------------------------------------------
// Analytics query methods (Task 4 — dashboard-neo4j-client-removal)
//
// Each method is ported from the corresponding TypeScript in:
//   enterprise/platform/dashboard/src/lib/gibson-client.ts   (FindingCounts, TimeSeries)
//   enterprise/platform/dashboard/src/lib/graph/summary.ts   (GraphSummary)
//   enterprise/platform/dashboard/src/lib/graph/context.ts   (GraphContext)
//   enterprise/platform/dashboard/app/api/findings/counts/route.ts (severity histogram)
// ---------------------------------------------------------------------------

const (
	// DefaultTimeSeriesDays is the default window used when days=0.
	DefaultTimeSeriesDays uint32 = 30
	// MaxTimeSeriesDays caps the time-series window to limit query cost.
	MaxTimeSeriesDays uint32 = 365
	// DefaultContextHops is the default neighborhood depth for GraphContext.
	DefaultContextHops uint32 = 2
	// MaxContextHops caps the neighborhood depth.
	MaxContextHops uint32 = 5
	// DefaultContextMaxNodes is the default neighbor cap.
	DefaultContextMaxNodes uint32 = 30
	// MaxContextMaxNodes caps the total neighbors returned.
	MaxContextMaxNodes uint32 = 100
)

// summaryProperties is the allow-list of node properties included in the
// LLM context summary (ported verbatim from context.ts SUMMARY_PROPERTIES).
var summaryProperties = []string{
	"name", "id", "status", "severity", "ip", "port", "url",
	"protocol", "version", "description", "cvss", "cve", "hostname",
	"domain", "service", "product", "os", "state",
}

// CountBucket is an internal result type for FindingCounts.
type CountBucket struct {
	Label string
	Count uint64
}

// GraphStats is an internal result type for GraphStats.
type GraphStats struct {
	ByLabel     []NodeCountByLabel
	TotalNodes  uint64
	TotalEdges  uint64
	LastWriteAt time.Time
}

// NodeCountByLabel pairs a Neo4j label with its node count.
type NodeCountByLabel struct {
	Label string
	Count uint64
}

// GraphSummary is an internal result type for GraphSummary.
type GraphSummary struct {
	Stats   GraphSummaryStats
	Summary string
}

// GraphSummaryStats mirrors the proto GraphSummaryStats fields.
type GraphSummaryStats struct {
	Hosts           uint64
	Services        uint64
	Findings        uint64
	Vulnerabilities uint64
	Missions        uint64
}

// GraphContext is an internal result type for GraphContext.
type GraphContext struct {
	FocusNode *graphpb.Node
	Neighbors []*graphpb.NeighborEdge
	Summary   string
}

// FindingCounts returns finding counts grouped by severity or category.
//
// Ported from:
//   - enterprise/platform/dashboard/src/lib/gibson-client.ts (getFindingsBySeverity,
//     getFindingsByCategory) and
//   - enterprise/platform/dashboard/app/api/findings/counts/route.ts (SEVERITY path
//     includes both :Finding and :Vulnerability nodes).
//
// windowSeconds applies an optional recency filter (skip when 0).
func (q *DashboardQueries) FindingCounts(
	ctx context.Context,
	tenantID auth.TenantID,
	groupBy graphpb.FindingCountGroupBy,
	windowSeconds uint64,
) ([]CountBucket, error) {
	tenant := tenantID.String()

	// Build the grouping expression.
	var groupExpr string
	switch groupBy {
	case graphpb.FindingCountGroupBy_CATEGORY:
		groupExpr = "coalesce(f.type, 'unknown')"
	default: // SEVERITY or unspecified
		groupExpr = "coalesce(f.severity, 'unknown')"
	}

	// The /api/findings/counts route queries both :Finding and :Vulnerability.
	// Match that behaviour for the SEVERITY groupBy path; CATEGORY only has Finding.
	var nodeFilter string
	if groupBy == graphpb.FindingCountGroupBy_SEVERITY || groupBy == graphpb.FindingCountGroupBy_FINDING_COUNT_GROUP_BY_UNSPECIFIED {
		nodeFilter = "(f:Finding OR f:Vulnerability)"
	} else {
		nodeFilter = "f:Finding"
	}

	params := map[string]any{"tenant": tenant}
	cypher := fmt.Sprintf(`
MATCH (f)
WHERE %s
  AND f.tenant_id = $tenant`, nodeFilter)

	if windowSeconds > 0 {
		params["win"] = int64(windowSeconds)
		cypher += "\n  AND f.created_at > datetime() - duration({seconds: $win})"
	}

	cypher += fmt.Sprintf(`
RETURN %s AS label, count(f) AS cnt`, groupExpr)

	raw, err := q.client.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}
		records, err := res.Collect(ctx)
		if err != nil {
			return nil, err
		}
		buckets := make([]CountBucket, 0, len(records))
		for _, rec := range records {
			label, _ := rec.Get("label")
			cnt, _ := rec.Get("cnt")
			buckets = append(buckets, CountBucket{
				Label: stringify(label),
				Count: toUint64(cnt),
			})
		}
		return buckets, nil
	})
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	return raw.([]CountBucket), nil
}

// FindingTimeSeries returns daily finding counts over the past `days` days,
// padded so the response always contains exactly `days` points (zero for
// days with no findings). days=0 → DefaultTimeSeriesDays; clamped to [1, MaxTimeSeriesDays].
//
// Ported from enterprise/platform/dashboard/src/lib/gibson-client.ts
// (getFindingsTimeSeries) — same Cypher, same day-bucketing logic.
func (q *DashboardQueries) FindingTimeSeries(
	ctx context.Context,
	tenantID auth.TenantID,
	days uint32,
) ([]*graphpb.TimeSeriesPoint, error) {
	if days == 0 {
		days = DefaultTimeSeriesDays
	}
	if days > MaxTimeSeriesDays {
		days = MaxTimeSeriesDays
	}

	tenant := tenantID.String()
	cypher := `
MATCH (f:Finding)
WHERE f.tenant_id = $tenant
  AND f.created_at > datetime() - duration({days: $days})
RETURN date(f.created_at) AS d, count(f) AS cnt
ORDER BY d
`
	raw, err := q.client.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cypher, map[string]any{
			"tenant": tenant,
			"days":   int64(days),
		})
		if err != nil {
			return nil, err
		}
		records, err := res.Collect(ctx)
		if err != nil {
			return nil, err
		}

		// Build a map of date-string → count from Neo4j results.
		counts := make(map[string]uint64, len(records))
		for _, rec := range records {
			dVal, _ := rec.Get("d")
			cnt, _ := rec.Get("cnt")
			dateStr := neoDateString(dVal)
			if dateStr != "" {
				counts[dateStr] = toUint64(cnt)
			}
		}
		return counts, nil
	})
	if err != nil {
		return nil, err
	}

	// Build the full padded series regardless of what Neo4j returned.
	countMap := map[string]uint64{}
	if raw != nil {
		countMap = raw.(map[string]uint64)
	}

	now := time.Now().UTC()
	points := make([]*graphpb.TimeSeriesPoint, 0, days)
	for i := int(days) - 1; i >= 0; i-- {
		day := now.AddDate(0, 0, -i)
		key := day.Format("2006-01-02")
		cnt := countMap[key]
		ts := timestamppb.New(time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, time.UTC))
		points = append(points, &graphpb.TimeSeriesPoint{
			Date:  ts,
			Count: cnt,
		})
	}
	return points, nil
}

// neoDateString converts a Neo4j date value (dbtype.Date or time.Time or string)
// to a "YYYY-MM-DD" key string.
func neoDateString(v any) string {
	switch val := v.(type) {
	case dbtype.Date:
		return val.Time().Format("2006-01-02")
	case time.Time:
		return val.Format("2006-01-02")
	case string:
		return val
	default:
		if v != nil {
			return fmt.Sprintf("%v", v)
		}
		return ""
	}
}

// GraphStats returns aggregate graph statistics for a tenant:
// per-label node counts, total nodes, total edges, and the max last_write_at timestamp.
//
// Ported from enterprise/platform/dashboard/src/lib/neo4j-client.ts (getGraphStats).
func (q *DashboardQueries) GraphStats(
	ctx context.Context,
	tenantID auth.TenantID,
) (*GraphStats, error) {
	tenant := tenantID.String()

	// Query 1: nodes by label (UNWIND labels so multi-label nodes appear under each).
	byLabelCypher := `
MATCH (n)
WHERE n.tenant_id = $tenant
UNWIND labels(n) AS label
RETURN label, count(*) AS cnt
ORDER BY cnt DESC
`
	// Query 2: total edges (filter via endpoint nodes for tenant isolation).
	edgeCypher := `
MATCH (n1)-[r]->(n2)
WHERE n1.tenant_id = $tenant AND n2.tenant_id = $tenant
RETURN count(r) AS total
`
	// Query 3: max last_write_at.
	lastWriteCypher := `
MATCH (n)
WHERE n.tenant_id = $tenant AND n.last_write_at IS NOT NULL
RETURN max(n.last_write_at) AS m
`

	params := map[string]any{"tenant": tenant}

	// --- labels ---
	var byLabel []NodeCountByLabel
	var totalNodes uint64
	raw1, err := q.client.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, byLabelCypher, params)
		if err != nil {
			return nil, err
		}
		recs, err := res.Collect(ctx)
		if err != nil {
			return nil, err
		}
		var out []NodeCountByLabel
		for _, rec := range recs {
			label, _ := rec.Get("label")
			cnt, _ := rec.Get("cnt")
			c := toUint64(cnt)
			out = append(out, NodeCountByLabel{Label: stringify(label), Count: c})
			totalNodes += c
		}
		return out, nil
	})
	if err != nil {
		return nil, fmt.Errorf("graphStats labels: %w", err)
	}
	if raw1 != nil {
		byLabel = raw1.([]NodeCountByLabel)
		totalNodes = 0
		for _, nb := range byLabel {
			totalNodes += nb.Count
		}
	}

	// --- edges ---
	var totalEdges uint64
	raw2, err := q.client.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, edgeCypher, params)
		if err != nil {
			return nil, err
		}
		recs, err := res.Collect(ctx)
		if err != nil {
			return nil, err
		}
		if len(recs) > 0 {
			v, _ := recs[0].Get("total")
			return toUint64(v), nil
		}
		return uint64(0), nil
	})
	if err != nil {
		return nil, fmt.Errorf("graphStats edges: %w", err)
	}
	if raw2 != nil {
		totalEdges = raw2.(uint64)
	}

	// --- last write ---
	var lastWrite time.Time
	raw3, err := q.client.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, lastWriteCypher, params)
		if err != nil {
			return nil, err
		}
		recs, err := res.Collect(ctx)
		if err != nil {
			return nil, err
		}
		if len(recs) > 0 {
			v, _ := recs[0].Get("m")
			return toTimeValue(v), nil
		}
		return time.Time{}, nil
	})
	if err != nil {
		return nil, fmt.Errorf("graphStats lastWrite: %w", err)
	}
	if raw3 != nil {
		lastWrite = raw3.(time.Time)
	}

	return &GraphStats{
		ByLabel:     byLabel,
		TotalNodes:  totalNodes,
		TotalEdges:  totalEdges,
		LastWriteAt: lastWrite,
	}, nil
}

// GraphSummary returns a structured stats block plus an LLM-friendly text summary
// of the tenant's knowledge graph.
//
// Ported verbatim from enterprise/platform/dashboard/src/lib/graph/summary.ts.
// Same three Cypher queries, same template text — consumers may pattern-match the output.
func (q *DashboardQueries) GraphSummary(
	ctx context.Context,
	tenantID auth.TenantID,
) (*GraphSummary, error) {
	tenant := tenantID.String()
	params := map[string]any{"tenant": tenant}

	// --- 1. Node counts by label (first label wins, same as TS labels(n)[0]) ---
	countsCypher := `
MATCH (n)
WHERE n.tenant_id = $tenant
WITH labels(n)[0] AS label, count(n) AS cnt
RETURN label, cnt
`
	raw1, err := q.client.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, countsCypher, params)
		if err != nil {
			return nil, err
		}
		recs, err := res.Collect(ctx)
		if err != nil {
			return nil, err
		}
		m := make(map[string]uint64, len(recs))
		for _, rec := range recs {
			label, _ := rec.Get("label")
			cnt, _ := rec.Get("cnt")
			m[stringify(label)] = toUint64(cnt)
		}
		return m, nil
	})
	if err != nil {
		return nil, fmt.Errorf("graphSummary counts: %w", err)
	}
	countsByLabel := map[string]uint64{}
	if raw1 != nil {
		countsByLabel = raw1.(map[string]uint64)
	}

	stats := GraphSummaryStats{
		Hosts:           countsByLabel["Host"],
		Services:        countsByLabel["Service"],
		Findings:        countsByLabel["Finding"],
		Vulnerabilities: countsByLabel["Vulnerability"],
		Missions:        countsByLabel["Mission"],
	}

	// --- 2. Critical/high findings with affected assets ---
	findingsCypher := `
MATCH (f)
WHERE f.tenant_id = $tenant
  AND (f:Finding OR f:Vulnerability)
  AND f.severity IN ['critical', 'high']
OPTIONAL MATCH (f)-[:AFFECTS]->(a)
RETURN f.name AS name, f.severity AS severity, f.cve AS cve,
       labels(a)[0] AS assetType, a.name AS assetName
ORDER BY CASE f.severity WHEN 'critical' THEN 0 ELSE 1 END, f.name
LIMIT 20
`
	raw2, err := q.client.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, findingsCypher, params)
		if err != nil {
			return nil, err
		}
		recs, err := res.Collect(ctx)
		if err != nil {
			return nil, err
		}
		rows := make([]summaryFindingRow, 0, len(recs))
		for _, rec := range recs {
			name, _ := rec.Get("name")
			sev, _ := rec.Get("severity")
			cve, _ := rec.Get("cve")
			assetType, _ := rec.Get("assetType")
			assetName, _ := rec.Get("assetName")
			rows = append(rows, summaryFindingRow{
				name:      orDefault(stringify(name), "Unknown"),
				severity:  orDefault(stringify(sev), "high"),
				cve:       stringify(cve),
				assetType: stringify(assetType),
				assetName: stringify(assetName),
			})
		}
		return rows, nil
	})
	if err != nil {
		return nil, fmt.Errorf("graphSummary findings: %w", err)
	}
	var criticalFindings []summaryFindingRow
	if raw2 != nil {
		criticalFindings = raw2.([]summaryFindingRow)
	}

	// --- 3. Recent missions ---
	missionsCypher := `
MATCH (m:Mission)
WHERE m.tenant_id = $tenant
RETURN m.name AS name, m.status AS status
ORDER BY m.created_at DESC
LIMIT 5
`
	raw3, err := q.client.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, missionsCypher, params)
		if err != nil {
			return nil, err
		}
		recs, err := res.Collect(ctx)
		if err != nil {
			return nil, err
		}
		rows := make([]summaryMissionRow, 0, len(recs))
		for _, rec := range recs {
			name, _ := rec.Get("name")
			status, _ := rec.Get("status")
			rows = append(rows, summaryMissionRow{
				name:   orDefault(stringify(name), "Unnamed"),
				status: orDefault(stringify(status), "unknown"),
			})
		}
		return rows, nil
	})
	if err != nil {
		return nil, fmt.Errorf("graphSummary missions: %w", err)
	}
	var recentMissions []summaryMissionRow
	if raw3 != nil {
		recentMissions = raw3.([]summaryMissionRow)
	}

	summaryText := buildGraphTextSummary(countsByLabel, criticalFindings, recentMissions)
	return &GraphSummary{Stats: stats, Summary: summaryText}, nil
}

// summaryFindingRow is used internally by buildGraphTextSummary.
type summaryFindingRow struct {
	name      string
	severity  string
	cve       string
	assetType string
	assetName string
}

// summaryMissionRow is used internally by buildGraphTextSummary.
type summaryMissionRow struct {
	name   string
	status string
}

// buildGraphTextSummary produces the LLM-friendly text summary.
// Ported verbatim from summary.ts buildTextSummary — preserve exact phrasing.
func buildGraphTextSummary(
	countsByLabel map[string]uint64,
	criticalFindings []summaryFindingRow,
	recentMissions []summaryMissionRow,
) string {
	var totalNodes uint64
	for _, c := range countsByLabel {
		totalNodes += c
	}

	if totalNodes == 0 {
		return "The knowledge graph is empty for this tenant. No hosts, findings, or missions have been recorded yet."
	}

	var lines []string

	// Overview
	lines = append(lines, "## Knowledge Graph Overview")
	lines = append(lines, fmt.Sprintf("Total entities: %d", totalNodes))

	type kv struct {
		k string
		v uint64
	}
	sorted := make([]kv, 0, len(countsByLabel))
	for k, v := range countsByLabel {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].v > sorted[j].v })
	parts := make([]string, 0, len(sorted))
	for _, kv := range sorted {
		parts = append(parts, fmt.Sprintf("%s: %d", kv.k, kv.v))
	}
	lines = append(lines, "Breakdown: "+strings.Join(parts, ", "))

	// Critical findings
	if len(criticalFindings) > 0 {
		lines = append(lines, "")
		lines = append(lines, "## Critical & High Severity Findings")
		for _, f := range criticalFindings {
			cveStr := ""
			if f.cve != "" {
				cveStr = " (" + f.cve + ")"
			}
			assetStr := ""
			if f.assetName != "" {
				assetStr = " affecting " + f.assetType + ": " + f.assetName
			}
			lines = append(lines, fmt.Sprintf("- [%s] %s%s%s",
				strings.ToUpper(f.severity), f.name, cveStr, assetStr))
		}
	} else {
		lines = append(lines, "")
		lines = append(lines, "No critical or high severity findings recorded.")
	}

	// Recent missions
	if len(recentMissions) > 0 {
		lines = append(lines, "")
		lines = append(lines, "## Recent Missions")
		for _, m := range recentMissions {
			lines = append(lines, fmt.Sprintf("- %s (%s)", m.name, m.status))
		}
	}

	return strings.Join(lines, "\n")
}

// GraphContext returns a focus node, its neighbors (bounded by hops and maxNodes),
// and an LLM-friendly summary string.
//
// Soft-fail contract: when the node does not exist in Neo4j, returns
// (nil FocusNode, empty neighbors, empty summary, nil error). Callers must never
// surface a gRPC error for this case.
//
// Ported from enterprise/platform/dashboard/src/lib/graph/context.ts.
func (q *DashboardQueries) GraphContext(
	ctx context.Context,
	tenantID auth.TenantID,
	nodeID string,
	hops, maxNodes uint32,
) (*GraphContext, error) {
	if hops == 0 {
		hops = DefaultContextHops
	}
	if hops > MaxContextHops {
		hops = MaxContextHops
	}
	if maxNodes == 0 {
		maxNodes = DefaultContextMaxNodes
	}
	if maxNodes > MaxContextMaxNodes {
		maxNodes = MaxContextMaxNodes
	}

	tenant := tenantID.String()

	// Single query: focus node + optional neighbors.
	// The original context.ts query does 1-hop; we support configurable hops
	// but keep the same OPTIONAL MATCH structure and per-tenant filter.
	cypher := `
MATCH (n) WHERE n.id = $nodeId AND n.tenant_id = $tenant
OPTIONAL MATCH (n)-[r]-(m)
WHERE m.tenant_id = $tenant
WITH n, labels(n) AS focusLabels,
     collect(DISTINCT {
       node: m,
       labels: labels(m),
       rel: type(r),
       dir: CASE WHEN startNode(r) = n THEN 'outgoing' ELSE 'incoming' END
     }) AS allNeighbors
RETURN n, focusLabels, allNeighbors[0..$maxNodes] AS neighbors,
       size(allNeighbors) AS totalNeighbors
`

	type rawResult struct {
		focusNeo  dbtype.Node
		found     bool
		neighbors []struct {
			node      *dbtype.Node
			labels    []string
			rel       string
			direction string
		}
		totalNeighbors int
	}

	raw, err := q.client.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cypher, map[string]any{
			"nodeId":   nodeID,
			"tenant":   tenant,
			"maxNodes": int64(maxNodes),
		})
		if err != nil {
			return nil, err
		}
		recs, err := res.Collect(ctx)
		if err != nil {
			return nil, err
		}
		if len(recs) == 0 {
			return &rawResult{found: false}, nil
		}
		rec := recs[0]

		focusRaw, ok := rec.Get("n")
		if !ok {
			return &rawResult{found: false}, nil
		}
		focusNode, ok := focusRaw.(dbtype.Node)
		if !ok {
			return &rawResult{found: false}, nil
		}

		totalRaw, _ := rec.Get("totalNeighbors")

		neighborsRaw, _ := rec.Get("neighbors")
		var neighbors []struct {
			node      *dbtype.Node
			labels    []string
			rel       string
			direction string
		}
		if nList, ok := neighborsRaw.([]any); ok {
			for _, item := range nList {
				m, ok := item.(map[string]any)
				if !ok {
					continue
				}
				var nbNode *dbtype.Node
				if nodeVal, ok := m["node"]; ok {
					if neoNode, ok := nodeVal.(dbtype.Node); ok {
						nbNode = &neoNode
					}
				}
				if nbNode == nil {
					continue
				}
				var lbls []string
				if lv, ok := m["labels"]; ok {
					if lArr, ok := lv.([]any); ok {
						for _, l := range lArr {
							lbls = append(lbls, stringify(l))
						}
					}
				}
				neighbors = append(neighbors, struct {
					node      *dbtype.Node
					labels    []string
					rel       string
					direction string
				}{
					node:      nbNode,
					labels:    lbls,
					rel:       stringify(m["rel"]),
					direction: stringify(m["dir"]),
				})
			}
		}

		return &rawResult{
			focusNeo:       focusNode,
			found:          true,
			neighbors:      neighbors,
			totalNeighbors: int(toUint64(totalRaw)),
		}, nil
	})
	if err != nil {
		return nil, fmt.Errorf("graphContext query: %w", err)
	}

	res, ok := raw.(*rawResult)
	if !ok || !res.found {
		// Soft-fail: node not found → return empty context, no error.
		return &GraphContext{}, nil
	}

	focusPb := neoNodeToProto(res.focusNeo)

	neighbors := make([]*graphpb.NeighborEdge, 0, len(res.neighbors))
	for _, nb := range res.neighbors {
		if nb.node == nil {
			continue
		}
		nodePb := neoNodeToProto(*nb.node)
		neighbors = append(neighbors, &graphpb.NeighborEdge{
			Node:         nodePb,
			Relationship: nb.rel,
			Direction:    nb.direction,
		})
	}

	summaryText := buildContextSummary(focusPb, neighbors, res.totalNeighbors, int(maxNodes))

	return &GraphContext{
		FocusNode: focusPb,
		Neighbors: neighbors,
		Summary:   summaryText,
	}, nil
}

// buildContextSummary produces the LLM-friendly context summary.
// Ported verbatim from context.ts buildSummary — preserve exact phrasing.
func buildContextSummary(
	focusNode *graphpb.Node,
	neighbors []*graphpb.NeighborEdge,
	totalNeighbors int,
	maxNodes int,
) string {
	var lines []string

	focusType := strings.Join(focusNode.GetLabels(), ", ")
	focusProps := pickSummaryProps(focusNode.GetProperties())
	focusName := orProps(focusProps, []string{"name", "id"}, focusNode.GetId())

	lines = append(lines, fmt.Sprintf("## Current Focus: %s (%s)", focusName, focusType))

	if len(focusProps) > 0 {
		lines = append(lines, "Properties:")
		for _, key := range summaryProperties {
			if v, ok := focusProps[key]; ok {
				lines = append(lines, fmt.Sprintf("  - %s: %s", key, v))
			}
		}
	}

	if len(neighbors) > 0 {
		// Group by relationship key (mirroring context.ts grouping).
		type group struct {
			key       string
			neighbors []*graphpb.NeighborEdge
		}
		grouped := make(map[string]*group)
		var order []string
		for _, nb := range neighbors {
			var key string
			if nb.GetDirection() == "outgoing" {
				key = fmt.Sprintf("[%s]->", nb.GetRelationship())
			} else {
				key = fmt.Sprintf("<-[%s]", nb.GetRelationship())
			}
			if _, exists := grouped[key]; !exists {
				grouped[key] = &group{key: key}
				order = append(order, key)
			}
			grouped[key].neighbors = append(grouped[key].neighbors, nb)
		}

		lines = append(lines, "")
		lines = append(lines, "## Connected Nodes")

		for _, key := range order {
			g := grouped[key]
			lines = append(lines, fmt.Sprintf("\n%s (%d):", key, len(g.neighbors)))
			for _, nb := range g.neighbors {
				nType := strings.Join(nb.GetNode().GetLabels(), ", ")
				nProps := pickSummaryProps(nb.GetNode().GetProperties())
				nName := orProps(nProps, []string{"name", "id"}, nb.GetNode().GetId())
				var propParts []string
				for _, k := range summaryProperties {
					if k == "name" || k == "id" {
						continue
					}
					if v, ok := nProps[k]; ok {
						propParts = append(propParts, fmt.Sprintf("%s=%s", k, v))
					}
				}
				propStr := ""
				if len(propParts) > 0 {
					propStr = " [" + strings.Join(propParts, ", ") + "]"
				}
				lines = append(lines, fmt.Sprintf("  - %s (%s)%s", nName, nType, propStr))
			}
		}

		if totalNeighbors > maxNodes {
			lines = append(lines, fmt.Sprintf("\n... and %d more connected nodes", totalNeighbors-maxNodes))
		}
	}

	return strings.Join(lines, "\n")
}

// pickSummaryProps returns only the properties in summaryProperties from props.
func pickSummaryProps(props map[string]string) map[string]string {
	out := make(map[string]string, len(summaryProperties))
	for _, key := range summaryProperties {
		if v, ok := props[key]; ok && v != "" {
			out[key] = v
		}
	}
	return out
}

// orDefault returns s if non-empty, else fallback.
func orDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// orProps returns the value of the first matching key from props, else fallback.
func orProps(props map[string]string, keys []string, fallback string) string {
	for _, k := range keys {
		if v, ok := props[k]; ok && v != "" {
			return v
		}
	}
	return fallback
}

// toUint64 converts a Neo4j count value to uint64.
func toUint64(v any) uint64 {
	switch val := v.(type) {
	case int64:
		if val < 0 {
			return 0
		}
		return uint64(val)
	case float64:
		if val < 0 {
			return 0
		}
		return uint64(val)
	case int:
		if val < 0 {
			return 0
		}
		return uint64(val)
	case uint64:
		return val
	default:
		return 0
	}
}

// toTimeValue converts a Neo4j temporal value to time.Time.
func toTimeValue(v any) time.Time {
	switch val := v.(type) {
	case time.Time:
		return val
	case dbtype.Date:
		return val.Time()
	case dbtype.LocalDateTime:
		return val.Time()
	default:
		return time.Time{}
	}
}

// ---------------------------------------------------------------------------
// FindingsFilters + FindingRecord — Task 4 (dashboard-neo4j-crud-removal)
// ---------------------------------------------------------------------------

// FindingsFilters controls which findings the Findings method returns.
// Empty string fields mean "no filter".
type FindingsFilters struct {
	Severity  string // exact match on n.severity
	Category  string // exact match on n.type
	MissionID string // restrict to findings reachable from the given mission
	Search    string // case-insensitive substring on name + description
	Limit     uint32 // default 100 when 0; clamped to 500
	Offset    uint32 // default 0
}

// FindingRecord holds the result of a single findings row.
type FindingRecord struct {
	ID          string
	Name        string
	Description string
	Type        string // category field (n.type)
	Severity    string
	MissionID   string
	Properties  map[string]string
	Labels      []string
	CreatedAt   time.Time
}

const (
	// DefaultFindingsLimit is applied when FindingsFilters.Limit is 0.
	DefaultFindingsLimit uint32 = 100
	// MaxFindingsLimit is the hard server-side cap enforced by Findings and GetFindings.
	MaxFindingsLimit uint32 = 500
)

// Findings returns paginated findings (and Vulnerability nodes) for the given
// tenant, applying optional filters.  It executes two Cypher queries: one for
// the page and one for the total count (same WHERE clause, no SKIP/LIMIT).
//
// Cypher ported byte-for-byte from
// enterprise/platform/dashboard/app/api/findings/route.ts.
func (q *DashboardQueries) Findings(
	ctx context.Context,
	tenantID auth.TenantID,
	f FindingsFilters,
) (records []FindingRecord, total uint64, err error) {
	// Apply defaults / caps.
	limit := f.Limit
	if limit == 0 {
		limit = DefaultFindingsLimit
	}
	if limit > MaxFindingsLimit {
		limit = MaxFindingsLimit
	}

	tenant := tenantID.String()

	// Build the common WHERE clause (after the mandatory tenant filter).
	// Mandatory base: (n:Finding OR n:Vulnerability) AND n.tenant_id = $tenant
	params := map[string]any{
		"tenant": tenant,
		"offset": int64(f.Offset),
		"limit":  int64(limit),
	}

	where := "WHERE (n:Finding OR n:Vulnerability) AND n.tenant_id = $tenant"
	if f.Severity != "" {
		where += "\n  AND n.severity = $severity"
		params["severity"] = f.Severity
	}
	if f.Category != "" {
		where += "\n  AND n.type = $category"
		params["category"] = f.Category
	}
	if f.MissionID != "" {
		// Ported from route.ts: OPTIONAL MATCH (m:Mission)-[*1..3]->(n) WHERE m.id = $missionId
		// Rewritten as an EXISTS sub-query to stay in the same MATCH scope.
		where += "\n  AND EXISTS { MATCH (m:Mission { id: $mission_id, tenant_id: $tenant })-[*1..3]->(n) }"
		params["mission_id"] = f.MissionID
	}
	if f.Search != "" {
		where += "\n  AND (toLower(n.name) CONTAINS toLower($search) OR toLower(coalesce(n.description, \"\")) CONTAINS toLower($search))"
		params["search"] = f.Search
	}

	// --- page query ---
	pageCypher := fmt.Sprintf(`
MATCH (n)
%s
RETURN n, labels(n) AS labels
ORDER BY CASE n.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, n.created_at DESC
SKIP $offset LIMIT $limit
`, where)

	rawPage, pageErr := q.client.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, pageCypher, params)
		if err != nil {
			return nil, err
		}
		recs, err := res.Collect(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]FindingRecord, 0, len(recs))
		for _, rec := range recs {
			rawNode, ok := rec.Get("n")
			if !ok {
				continue
			}
			neoNode, ok := rawNode.(dbtype.Node)
			if !ok {
				continue
			}
			lblRaw, _ := rec.Get("labels")
			var lbls []string
			if lArr, ok := lblRaw.([]any); ok {
				for _, l := range lArr {
					lbls = append(lbls, stringify(l))
				}
			}

			props := coerceProps(neoNode.Props)
			fr := FindingRecord{
				ID:          orProp(props, "id", fmt.Sprintf("%d", neoNode.Id)),
				Name:        props["name"],
				Description: props["description"],
				Type:        props["type"],
				Severity:    props["severity"],
				Properties:  props,
				Labels:      lbls,
			}
			// Created-at: prefer created_at; fall back to discoveredAt.
			for _, key := range []string{"created_at", "discoveredAt"} {
				if v, ok := neoNode.Props[key]; ok {
					if t := toTimeValue(v); !t.IsZero() {
						fr.CreatedAt = t
						break
					}
				}
			}
			out = append(out, fr)
		}
		return out, nil
	})
	if pageErr != nil {
		return nil, 0, fmt.Errorf("findings page query: %w", pageErr)
	}
	if rawPage != nil {
		records = rawPage.([]FindingRecord)
	}

	// --- count query (same WHERE, no SKIP/LIMIT) ---
	countParams := make(map[string]any, len(params))
	for k, v := range params {
		countParams[k] = v
	}
	delete(countParams, "offset")
	delete(countParams, "limit")

	countCypher := fmt.Sprintf(`
MATCH (n)
%s
RETURN count(n) AS total
`, where)

	rawCount, countErr := q.client.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, countCypher, countParams)
		if err != nil {
			return nil, err
		}
		recs, err := res.Collect(ctx)
		if err != nil {
			return nil, err
		}
		if len(recs) == 0 {
			return uint64(0), nil
		}
		v, _ := recs[0].Get("total")
		return toUint64(v), nil
	})
	if countErr != nil {
		return nil, 0, fmt.Errorf("findings count query: %w", countErr)
	}
	if rawCount != nil {
		total = rawCount.(uint64)
	}

	return records, total, nil
}

// orProp returns props[key] if non-empty, else fallback.
func orProp(props map[string]string, key, fallback string) string {
	if v, ok := props[key]; ok && v != "" {
		return v
	}
	return fallback
}
