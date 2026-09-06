// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/sdk/auth"
)

// PoolFindingQuerier reads a tenant's findings back out of its own graph
// (gibson#1186 slice B).
//
// It is the read counterpart of GraphRAGFindingSubmitter, which already writes
// findings through the same per-tenant pool. Tenant isolation is the pool: each
// tenant has its own Neo4j database, so the records carry no tenant_id predicate
// and there is no cross-tenant query to get wrong (see the note in
// DashboardQueries.Findings).
//
// The wire format is JSON on both sides — `filter_json` decodes to the same
// shape the SDK's finding.Filter marshals, and `findings_json` encodes the SDK
// finding.Finding shape the daemon already accepts on SubmitFinding.
type PoolFindingQuerier struct {
	pool   datapool.Pool
	logger *slog.Logger
}

// NewPoolFindingQuerier constructs a PoolFindingQuerier over the per-tenant pool.
func NewPoolFindingQuerier(pool datapool.Pool, logger *slog.Logger) *PoolFindingQuerier {
	if logger == nil {
		logger = slog.Default()
	}
	return &PoolFindingQuerier{pool: pool, logger: logger}
}

// Compile-time assertion that the querier satisfies the service seam.
var _ FindingQuerier = (*PoolFindingQuerier)(nil)

// findingFilter is the decoded `filter_json`. Field names match the SDK's
// finding.Filter JSON tags so an agent can send the same document it would send
// to any other Gibson surface.
type findingFilter struct {
	Severity  string `json:"severity,omitempty"`
	Category  string `json:"category,omitempty"`
	MissionID string `json:"mission_id,omitempty"`
	Search    string `json:"search,omitempty"`
	Limit     uint32 `json:"limit,omitempty"`
	Offset    uint32 `json:"offset,omitempty"`
}

// GetFindings returns JSON-encoded findings matching the filter.
func (q *PoolFindingQuerier) GetFindings(
	ctx context.Context,
	tenant string,
	filterJSON []byte,
) ([]byte, error) {
	filter, err := decodeFindingFilter(filterJSON)
	if err != nil {
		return nil, err
	}
	return q.query(ctx, tenant, filter)
}

// GetRunFindings returns findings scoped to mission runs.
//
// scope is "previous" or "all" in the SDK's contract. Both are served from the
// same store; "previous" narrows to the mission that produced workID when the
// caller supplied one. An off-cluster caller with no work item passes an empty
// workID, which degrades to the unscoped query rather than returning nothing —
// an agent asking for its prior findings should not get silence because it has
// no mission.
func (q *PoolFindingQuerier) GetRunFindings(
	ctx context.Context,
	tenant, workID, scope string,
	filterJSON []byte,
) ([]byte, error) {
	filter, err := decodeFindingFilter(filterJSON)
	if err != nil {
		return nil, err
	}
	if scope == "previous" && workID != "" {
		filter.MissionID = workID
	}
	return q.query(ctx, tenant, filter)
}

func (q *PoolFindingQuerier) query(
	ctx context.Context,
	tenant string,
	filter findingFilter,
) ([]byte, error) {
	tenantID, err := auth.NewTenantID(tenant)
	if err != nil {
		return nil, fmt.Errorf("finding querier: invalid tenant %q: %w", tenant, err)
	}

	conn, err := q.pool.For(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("finding querier: acquire tenant data plane: %w", err)
	}
	defer conn.Release()

	queries := graph.NewDashboardQueries(graph.NewSessionGraphClient(conn.Neo4j))
	records, _, err := queries.Findings(ctx, tenantID, graph.FindingsFilters{
		Severity:  filter.Severity,
		Category:  filter.Category,
		MissionID: filter.MissionID,
		Search:    filter.Search,
		Limit:     filter.Limit,
		Offset:    filter.Offset,
	})
	if err != nil {
		return nil, fmt.Errorf("finding querier: query findings: %w", err)
	}

	out := make([]map[string]any, 0, len(records))
	for _, r := range records {
		out = append(out, findingRecordToSDKShape(r))
	}

	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("finding querier: encode findings: %w", err)
	}
	q.logger.DebugContext(ctx, "finding querier: query completed",
		"tenant", tenant, "count", len(out))
	return encoded, nil
}

// findingRecordToSDKShape maps a graph record onto the SDK finding.Finding JSON
// shape, so a caller decodes findings it reads with the same type it uses to
// submit them.
//
// The graph is lossy relative to a submitted finding — it stores the fields the
// loader projects (title, severity, description, category) plus arbitrary
// properties. Anything the graph does not carry is omitted rather than invented.
func findingRecordToSDKShape(r graph.FindingRecord) map[string]any {
	out := map[string]any{
		"id":          r.ID,
		"title":       r.Name,
		"description": r.Description,
		"category":    r.Type,
		"severity":    r.Severity,
		"mission_id":  r.MissionID,
	}
	if !r.CreatedAt.IsZero() {
		out["created_at"] = r.CreatedAt.UTC().Format(time.RFC3339)
	}
	if len(r.Properties) > 0 {
		// Graph properties are the finding's extensible tail; surfacing them under
		// `metadata` keeps them addressable without colliding with typed fields.
		metadata := make(map[string]any, len(r.Properties))
		for k, v := range r.Properties {
			metadata[k] = v
		}
		out["metadata"] = metadata
	}
	if len(r.Labels) > 0 {
		out["tags"] = r.Labels
	}
	return out
}

// decodeFindingFilter parses `filter_json`. An empty payload is a valid
// unfiltered query — the caller asked for everything.
func decodeFindingFilter(filterJSON []byte) (findingFilter, error) {
	var filter findingFilter
	if len(filterJSON) == 0 {
		return filter, nil
	}
	if err := json.Unmarshal(filterJSON, &filter); err != nil {
		return filter, fmt.Errorf("finding querier: decode filter: %w", err)
	}
	return filter, nil
}
