package graphrag

// semantic_queries.go — Ontology-expanded query helpers for the GraphRAG service layer.
//
// These functions use an injected Reasoner to expand a single IRI to its full
// descendant set at query time, then issue an IN filter against the Neo4j graph.
// The compliance evaluator and write path are NOT changed — only matched IRIs
// are written to compliance_signal.control_ids; rollup is a pure read-side
// projection implemented here.
//
// Thread safety: SemanticQuerier is safe for concurrent use once constructed.

import (
	"context"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/zeroroot-ai/gibson/internal/graphrag/graph"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
)

// ComplianceSignalSummary is a lightweight projection of a compliance_signal
// node returned by the semantic rollup query. It holds only the fields needed
// by callers of FindingsByControl and TechniquesByAncestor.
type ComplianceSignalSummary struct {
	// NodeID is the internal graph node identifier.
	NodeID string
	// ControlIDs is the raw slice of control IRIs stamped on this signal by the
	// compliance evaluator (before ontology expansion).
	ControlIDs []string
	// Action is the compliance_signal.action field.
	Action string
	// Effect is the compliance_signal.effect field.
	Effect string
	// TenantID is the tenant that owns this node.
	TenantID string
}

// SemanticQuerier adds ontology-aware read methods on top of a GraphClient.
// Construct via NewSemanticQuerier.
type SemanticQuerier struct {
	client   graph.GraphClient
	reasoner sdkgraphrag.Reasoner
}

// NewSemanticQuerier constructs a SemanticQuerier.
// client is the graph database client (per-tenant or shared).
// reasoner is the in-process ontology reasoner.
func NewSemanticQuerier(client graph.GraphClient, reasoner sdkgraphrag.Reasoner) *SemanticQuerier {
	return &SemanticQuerier{client: client, reasoner: reasoner}
}

// FindingsByControl returns all compliance_signal nodes whose control_ids
// list contains controlIRI OR any descendant of controlIRI in the loaded
// ontology hierarchy. tenantID scopes the query to a single tenant.
//
// This implements the read-side rollup: the evaluator writes only the matched
// IRI; this method projects parent-level queries down to all children at
// read time, without any second write or SAME_AS edges in Neo4j.
//
// Returns an empty slice (not an error) if controlIRI is not known to the
// reasoner or no matching signals exist.
func (q *SemanticQuerier) FindingsByControl(ctx context.Context, tenantID, controlIRI string) ([]ComplianceSignalSummary, error) {
	// Expand to self + all descendants.
	irIs := expandWithDescendants(q.reasoner, controlIRI)
	if len(irIs) == 0 {
		return nil, nil
	}
	return q.queryComplianceSignalsByControlIDs(ctx, tenantID, irIs)
}

// TechniquesByAncestor returns all compliance_signal nodes whose control_ids
// list contains any technique IRI that is a descendant of ancestorIRI.
// This is the symmetric ancestor query for technique hierarchies (e.g., all
// signals matching any sub-technique of a MITRE tactic).
func (q *SemanticQuerier) TechniquesByAncestor(ctx context.Context, tenantID, ancestorIRI string) ([]ComplianceSignalSummary, error) {
	return q.FindingsByControl(ctx, tenantID, ancestorIRI)
}

// expandWithDescendants returns a slice containing iri plus all transitive
// descendants of iri. If iri is unknown to the reasoner, returns [iri] so the
// caller still queries for the literal IRI (no data loss).
func expandWithDescendants(r sdkgraphrag.Reasoner, iri string) []string {
	desc := r.Descendants(iri)
	result := make([]string, 0, 1+len(desc))
	result = append(result, iri)
	result = append(result, desc...)
	return result
}

// queryComplianceSignalsByControlIDs runs a Cypher IN filter against
// compliance_signal nodes, matching any node whose control_ids array
// contains at least one element from the provided set.
func (q *SemanticQuerier) queryComplianceSignalsByControlIDs(
	ctx context.Context,
	tenantID string,
	controlIDs []string,
) ([]ComplianceSignalSummary, error) {
	if len(controlIDs) == 0 {
		return nil, nil
	}

	// Convert []string to []any for the neo4j driver parameter.
	ids := make([]any, len(controlIDs))
	for i, id := range controlIDs {
		ids[i] = id
	}

	// ANY(id IN $ids WHERE id IN cs.control_ids) handles multi-valued control_ids.
	// No WHERE cs.tenant_id predicate: nodes are written without a tenant_id
	// property and tenant isolation is the per-tenant Neo4j database resolved by
	// pool.For (database-per-tenant-data-plane; matches the C18 closure in
	// graphrag/queries and graphrag/provider). The predicate would match zero
	// rows and silently empty every result.
	cypher := `
MATCH (cs:compliance_signal)
WHERE ANY(id IN $ids WHERE id IN cs.control_ids)
RETURN cs.id        AS node_id,
       cs.control_ids AS control_ids,
       cs.action    AS action,
       cs.effect    AS effect,
       cs.tenant_id AS tenant_id
ORDER BY cs.id
`
	params := map[string]any{
		// tenantID is retained for call-site symmetry; the per-tenant database is
		// the isolation boundary, so the query itself does not reference $tenant.
		"tenant": tenantID,
		"ids":    ids,
	}

	raw, err := q.client.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, fmt.Errorf("semantic query: run cypher: %w", err)
		}
		records, err := res.Collect(ctx)
		if err != nil {
			return nil, fmt.Errorf("semantic query: collect: %w", err)
		}

		sigs := make([]ComplianceSignalSummary, 0, len(records))
		for _, rec := range records {
			sig := ComplianceSignalSummary{}
			if v, ok := rec.Get("node_id"); ok && v != nil {
				sig.NodeID = fmt.Sprintf("%v", v)
			}
			if v, ok := rec.Get("action"); ok && v != nil {
				sig.Action = fmt.Sprintf("%v", v)
			}
			if v, ok := rec.Get("effect"); ok && v != nil {
				sig.Effect = fmt.Sprintf("%v", v)
			}
			if v, ok := rec.Get("tenant_id"); ok && v != nil {
				sig.TenantID = fmt.Sprintf("%v", v)
			}
			if v, ok := rec.Get("control_ids"); ok && v != nil {
				sig.ControlIDs = toStringSlice(v)
			}
			sigs = append(sigs, sig)
		}
		return sigs, nil
	})
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	return raw.([]ComplianceSignalSummary), nil
}

// toStringSlice converts a Neo4j list value to []string.
func toStringSlice(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, el := range t {
			if s, ok := el.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	}
	return nil
}
