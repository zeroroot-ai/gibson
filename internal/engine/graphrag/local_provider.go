// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package graphrag

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool/vectordb"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// LocalGraphRAGProvider is the production GraphRAGProvider: graph structure in
// the tenant's Neo4j database, embeddings in the tenant's vector collection.
//
// LIFETIME. It is built per request from an already-open datapool.Conn and owns
// neither connection. That is the decision the seam forced (gibson#1190): the
// interface has Initialize and Close, which read as a long-lived resource, while
// datapool.Conn is acquired per request and released on defer. Caching a
// provider per tenant would mean owning a lifecycle alongside the pool's
// eviction — two things deciding when the same session dies. So Initialize
// validates rather than dials, Close is a no-op, and the pool stays the single
// owner. This follows graph.SessionGraphClient, which already documents itself
// as the per-call client for exactly this purpose.
//
// TENANT SCOPE comes from the Conn, never from a predicate. Per-tenant Neo4j
// databases and vector collections are physically separate, so there is no
// tenant_id to filter on and no query that could reach another tenant's data.
//
// CONCURRENCY. neo4j.SessionWithContext is not safe for concurrent use, so a
// provider instance must not be shared across goroutines — which the per-request
// construction gives for free.
type LocalGraphRAGProvider struct {
	graph  graph.GraphClient
	vector vectordb.Client
}

// NewLocalGraphRAGProvider builds a provider over an open graph client and
// vector client, both owned by the caller's datapool.Conn.
func NewLocalGraphRAGProvider(g graph.GraphClient, v vectordb.Client) *LocalGraphRAGProvider {
	return &LocalGraphRAGProvider{graph: g, vector: v}
}

var _ GraphRAGProvider = (*LocalGraphRAGProvider)(nil)

// Initialize validates that the provider has what it needs.
//
// It deliberately does not dial: the connections arrive already open from the
// pool. Reporting a missing dependency here rather than on first use keeps the
// failure at the seam, where the caller can answer Unimplemented honestly
// instead of half-serving a query.
func (p *LocalGraphRAGProvider) Initialize(_ context.Context) error {
	if p.graph == nil {
		return NewConfigError("graph client is nil; the tenant's Neo4j session was not acquired", nil)
	}
	if p.vector == nil {
		return NewConfigError("vector client is nil; the tenant's vector collection was not acquired", nil)
	}
	return nil
}

// QueryNodes performs exact property-based lookup.
func (p *LocalGraphRAGProvider) QueryNodes(ctx context.Context, query NodeQuery) ([]GraphNode, error) {
	params := map[string]any{}
	wheres := make([]cypherFrag, 0, len(query.Properties)+2)

	for i, k := range sortedKeys(query.Properties) {
		// Parameterised values, identifier from a sorted key list: property
		// names cannot be parameterised in Cypher, so they are sanitised, and
		// sorting keeps the generated query stable for a given input.
		param := paramFrag("p", i)
		wheres = append(wheres, cypherf("n.%s = $%s", sanitizeIdentifier(k), param))
		params[string(param)] = query.Properties[k]
	}
	if query.MissionID != nil {
		wheres = append(wheres, cypherFrag("n.mission_id = $mission_id"))
		params["mission_id"] = query.MissionID.String()
	}
	if query.MissionRunID != "" {
		wheres = append(wheres, cypherFrag("n.mission_run_id = $mission_run_id"))
		params["mission_run_id"] = query.MissionRunID
	}

	match := cypherFrag("MATCH (n)")
	if len(query.NodeTypes) > 0 {
		labels := make([]string, 0, len(query.NodeTypes))
		for _, t := range query.NodeTypes {
			labels = append(labels, string(t))
		}
		match = cypherf("MATCH (n:%s)", labelExpr(labels))
	}

	cypher := match
	if len(wheres) > 0 {
		cypher = cypherf("%s WHERE %s", cypher, joinFrags(wheres, " AND "))
	}
	cypher = cypherf("%s RETURN n LIMIT %s", cypher, intFrag(effectiveLimit(query.Limit)))

	res, err := p.graph.Query(ctx, string(cypher), params)
	if err != nil {
		return nil, NewQueryError("query nodes", err)
	}
	return recordsToNodes(res.Records), nil
}

// QueryRelationships retrieves edges matching the criteria.
func (p *LocalGraphRAGProvider) QueryRelationships(ctx context.Context, query RelQuery) ([]Relationship, error) {
	params := map[string]any{}
	wheres := make([]cypherFrag, 0, len(query.Properties)+3)

	if query.FromID != nil {
		wheres = append(wheres, cypherFrag("a.id = $from"))
		params["from"] = query.FromID.String()
	}
	if query.ToID != nil {
		wheres = append(wheres, cypherFrag("b.id = $to"))
		params["to"] = query.ToID.String()
	}
	if query.MinWeight > 0 {
		wheres = append(wheres, cypherFrag("coalesce(r.weight, 0) >= $min_weight"))
		params["min_weight"] = query.MinWeight
	}
	for i, k := range sortedKeys(query.Properties) {
		param := paramFrag("rp", i)
		wheres = append(wheres, cypherf("r.%s = $%s", sanitizeIdentifier(k), param))
		params[string(param)] = query.Properties[k]
	}

	relExpr := cypherFrag("")
	if len(query.Types) > 0 {
		relTypes := make([]cypherFrag, 0, len(query.Types))
		for _, t := range query.Types {
			relTypes = append(relTypes, sanitizeIdentifier(string(t)))
		}
		relExpr = cypherf(":%s", joinFrags(relTypes, "|"))
	}

	cypher := cypherf("MATCH (a)-[r%s]->(b)", relExpr)
	if len(wheres) > 0 {
		cypher = cypherf("%s WHERE %s", cypher, joinFrags(wheres, " AND "))
	}
	cypher = cypherf("%s RETURN a.id AS from_id, b.id AS to_id, type(r) AS rel_type, r AS rel LIMIT %s",
		cypher, intFrag(effectiveLimit(query.Limit)))

	res, err := p.graph.Query(ctx, string(cypher), params)
	if err != nil {
		return nil, NewQueryError("query relationships", err)
	}
	return recordsToRelationships(res.Records), nil
}

// TraverseGraph walks outward from a start node up to maxHops.
//
// Undirected on purpose: a caller asking what a finding is connected to means
// both what it points at and what points at it. Direction is available through
// QueryRelationships when it matters.
func (p *LocalGraphRAGProvider) TraverseGraph(
	ctx context.Context, startID string, maxHops int, filters TraversalFilters,
) ([]GraphNode, error) {
	if startID == "" {
		return nil, NewInvalidQueryError("traverse: start node id is required")
	}
	hops := maxHops
	if hops <= 0 {
		hops = 1
	}
	if hops > maxTraversalHops {
		// A tenant graph is small but not bounded, and an unbounded variable-
		// length match is the classic way to hang a Neo4j session.
		hops = maxTraversalHops
	}

	if filters.MaxDepth > 0 && filters.MaxDepth < hops {
		// The filter's own depth is the caller's later, more specific word.
		hops = filters.MaxDepth
	}

	params := map[string]any{"start": startID}
	wheres := []cypherFrag{cypherFrag("n.id <> $start")}
	if len(filters.AllowedNodeTypes) > 0 {
		wheres = append(wheres, cypherFrag("any(l IN labels(n) WHERE l IN $allowed_labels)"))
		params["allowed_labels"] = nodeTypeStrings(filters.AllowedNodeTypes)
	}
	if len(filters.BlockedNodeTypes) > 0 {
		// Blocked wins over allowed: a caller that names both means "these, but
		// never those", and the safe reading of a conflict is to exclude.
		wheres = append(wheres, cypherFrag("none(l IN labels(n) WHERE l IN $blocked_labels)"))
		params["blocked_labels"] = nodeTypeStrings(filters.BlockedNodeTypes)
	}
	if filters.MinWeight > 0 {
		wheres = append(wheres, cypherFrag("all(r IN relationships(path) WHERE coalesce(r.weight, 0) >= $min_weight)"))
		params["min_weight"] = filters.MinWeight
	}
	if len(filters.BlockedRelations) > 0 {
		wheres = append(wheres, cypherFrag("none(r IN relationships(path) WHERE type(r) IN $blocked_rels)"))
		params["blocked_rels"] = relationTypeStrings(filters.BlockedRelations)
	}

	// Allowed relations are expressed in the pattern rather than the WHERE
	// clause so Neo4j prunes during expansion instead of after it.
	relExpr := cypherFrag("")
	if len(filters.AllowedRelations) > 0 {
		rels := make([]cypherFrag, 0, len(filters.AllowedRelations))
		for _, t := range filters.AllowedRelations {
			rels = append(rels, sanitizeIdentifier(string(t)))
		}
		relExpr = cypherf(":%s", joinFrags(rels, "|"))
	}

	cypher := cypherf(
		"MATCH path = (s {id: $start})-[%s*1..%s]-(n) WHERE %s RETURN DISTINCT n LIMIT %s",
		relExpr, intFrag(hops), joinFrags(wheres, " AND "), intFrag(defaultQueryLimit),
	)
	res, err := p.graph.Query(ctx, string(cypher), params)
	if err != nil {
		return nil, NewQueryError("traverse graph", err)
	}
	return recordsToNodes(res.Records), nil
}

// VectorSearch performs similarity search over the tenant's collection.
func (p *LocalGraphRAGProvider) VectorSearch(
	ctx context.Context, embedding []float64, topK int, filters map[string]any,
) ([]VectorResult, error) {
	if len(embedding) == 0 {
		return nil, NewInvalidQueryError("vector search: embedding is empty")
	}
	k := topK
	if k <= 0 {
		k = defaultVectorTopK
	}

	if k < 0 {
		k = defaultVectorTopK
	}
	hits, err := p.vector.Search(ctx, toFloat32(embedding), uint64(k), payloadFilter(filters)) //nolint:gosec // k is clamped positive just above
	if err != nil {
		return nil, NewQueryError("vector search", err)
	}

	results := make([]VectorResult, 0, len(hits))
	for _, h := range hits {
		id, idErr := types.ParseID(h.ID)
		if idErr != nil {
			// A point whose ID is not a node ID cannot be joined back to the
			// graph. Skipping it beats returning a result the caller cannot
			// resolve.
			continue
		}
		results = append(results, VectorResult{
			NodeID:     id,
			Similarity: float64(h.Score),
			Metadata:   h.Payload,
		})
	}
	return results, nil
}

// Health reports whether the graph side answers. The vector client has no
// probe on its interface, so a healthy result here means "graph reachable",
// which is what the caller can act on.
func (p *LocalGraphRAGProvider) Health(ctx context.Context) types.HealthStatus {
	if p.graph == nil {
		return types.NewHealthStatus(types.HealthStateUnhealthy, "no graph client")
	}
	return p.graph.Health(ctx)
}

// Close is a no-op: the datapool.Conn owns both connections and releases them.
// Closing them here would take a pooled session out from under the pool.
func (p *LocalGraphRAGProvider) Close() error { return nil }

const (
	// maxTraversalHops bounds variable-length matches.
	maxTraversalHops = 5
	// defaultVectorTopK is used when a caller asks for no particular count.
	defaultVectorTopK = 10
	// defaultQueryLimit bounds an unbounded query.
	defaultQueryLimit = 100
)

func effectiveLimit(n int) int {
	if n <= 0 {
		return defaultQueryLimit
	}
	return n
}

// cypherFrag is a piece of Cypher query TEXT — never a value; values always
// travel as bound parameters — that has been proven safe to splice into a
// query string. Node labels, relationship types and property names cannot be
// parameters in Cypher, so they are the one part of a query built from
// caller input that has to become query text, and cypherFrag is the sole door
// through which that text may be produced.
//
// gibson#1440: #1266's acceptance criterion for the write path claimed a
// structural property ("no fmt.Sprintf-built Cypher") that the read path in
// this file only delivered as a filtering one (assembled Cypher with a
// sanitiser in front of it). A per-call-site sanitiser is a convention a new
// call site can forget; cypherFrag makes the convention the only way to reach
// the format string. The taxonomy of node/relationship types is agent
// extensible at runtime (see sdk/graphrag.TaxonomyRegistry), so a fixed
// allow-list would reject legitimate custom types — this closes the gap by
// construction instead, without narrowing what a query can ask for.
//
// A value of this type can only come from:
//   - sanitizeIdentifier, which strips everything outside [A-Za-z0-9_]
//   - intFrag / paramFrag, which format integers (always safe: decimal
//     digits are inside the safe character set regardless of the int's
//     origin)
//   - cypherf / joinFrags / labelExpr, which combine existing cypherFrags
//   - converting a Go string CONSTANT, e.g. cypherFrag("a.id = $from")
//
// gibsoncheck's cypheridentifier analyzer enforces this from the outside: it
// flags any fmt.Sprintf or string concatenation in this package whose format
// text looks like Cypher, and any conversion to cypherFrag whose argument is
// not one of the constructors above or a compile-time constant. Together they
// are what makes "a new call site forgets to sanitise" a build failure
// instead of a silent mangle.
type cypherFrag string

// sanitizeIdentifier strips everything that is not a safe Cypher identifier
// character, producing a cypherFrag.
//
// Labels, relationship types and property names cannot be query parameters in
// Cypher — they are part of the query text — so this is the boundary that keeps
// a caller-supplied node type from becoming an injection. Values always go
// through parameters. It is the sole sanitiser: every caller-supplied label,
// relationship type or property name reaches Cypher text only by passing
// through this function (directly, or via labelExpr).
func sanitizeIdentifier(s string) cypherFrag {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		}
	}
	return cypherFrag(b.String())
}

// intFrag formats n as decimal digits. Always safe regardless of n's origin:
// an int cannot carry Cypher syntax, and its decimal rendering is entirely
// inside the identifier-safe character set.
func intFrag(n int) cypherFrag {
	return cypherFrag(strconv.Itoa(n))
}

// paramFrag builds a Cypher bound-parameter name such as "p3": a fixed
// literal prefix the caller supplies in source, followed by intFrag's
// decimal digits. Always safe for the same reason intFrag is.
func paramFrag(prefix string, i int) cypherFrag {
	return cypherFrag(prefix) + intFrag(i)
}

// cypherf builds Cypher text from a literal format string and cypherFrags.
// The signature is the enforcement: frags is []cypherFrag, not []any, so a
// call site cannot hand a plain string to a %s verb — the compiler refuses
// it, not a runtime check.
func cypherf(format string, frags ...cypherFrag) cypherFrag {
	args := make([]any, len(frags))
	for i, f := range frags {
		args[i] = string(f)
	}
	return cypherFrag(fmt.Sprintf(format, args...))
}

// joinFrags joins frags with sep, a fixed literal at every call site in this
// file (never caller-controlled). The result is safe because every element
// already is: joining vetted text with a fixed separator introduces nothing
// new that was not already sanitised.
func joinFrags(frags []cypherFrag, sep string) cypherFrag {
	strs := make([]string, len(frags))
	for i, f := range frags {
		strs[i] = string(f)
	}
	return cypherFrag(strings.Join(strs, sep))
}

// labelExpr joins labels for a Cypher pattern, sanitising each.
func labelExpr(labels []string) cypherFrag {
	clean := make([]cypherFrag, 0, len(labels))
	for _, l := range labels {
		if s := sanitizeIdentifier(l); s != "" {
			clean = append(clean, s)
		}
	}
	if len(clean) == 0 {
		return cypherFrag("Node")
	}
	return joinFrags(clean, ":")
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func toFloat32(in []float64) []float32 {
	out := make([]float32, len(in))
	for i, v := range in {
		out[i] = float32(v)
	}
	return out
}

// payloadFilter turns a plain map into the vector store's filter. Unsupported
// value shapes are dropped rather than guessed at — a filter that silently
// means something else is worse than one term less.
func payloadFilter(filters map[string]any) *vectordb.Filter {
	if len(filters) == 0 {
		return nil
	}
	f := &vectordb.Filter{}
	for _, k := range sortedKeys(filters) {
		switch v := filters[k].(type) {
		case string:
			f.Must = append(f.Must, vectordb.FieldCondition{Key: k, Value: v})
		case fmt.Stringer:
			f.Must = append(f.Must, vectordb.FieldCondition{Key: k, Value: v.String()})
		}
	}
	if len(f.Must) == 0 {
		return nil
	}
	return f
}

func nodeTypeStrings(in []NodeType) []string {
	out := make([]string, 0, len(in))
	for _, t := range in {
		out = append(out, string(t))
	}
	return out
}

func relationTypeStrings(in []RelationType) []string {
	out := make([]string, 0, len(in))
	for _, t := range in {
		out = append(out, string(t))
	}
	return out
}
