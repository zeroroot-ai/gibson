// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/engine/finding/pgstore"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/sdk/auth"
)

// PoolFindingQuerier reads a tenant's findings back out of the findings table of
// its own Postgres database (gibson#1186 slice B, gibson#1383).
//
// It is the read counterpart of GraphRAGFindingSubmitter, which already writes
// findings through the same per-tenant pool. Tenant isolation is the pool: each
// tenant has its own Postgres database, so the query carries no tenant_id
// predicate and there is no cross-tenant query to get wrong. The graph holds a
// finding node for relations only.
//
// The wire format is JSON on both sides — `filter_json` decodes to the same
// shape the SDK's finding.Filter marshals, and `findings_json` encodes the SDK
// finding.Finding shape the daemon already accepts on SubmitFinding.
type PoolFindingQuerier struct {
	lister findingLister
	logger *slog.Logger
}

// findingLister reads a page of the findings of a tenant. pgstore.Store is the
// implementation.
type findingLister interface {
	Find(ctx context.Context, tenantID string, q pgstore.Query) ([]finding.EnhancedFinding, int, error)
}

// NewPoolFindingQuerier constructs a PoolFindingQuerier over the per-tenant pool.
func NewPoolFindingQuerier(pool datapool.Pool, logger *slog.Logger) *PoolFindingQuerier {
	if logger == nil {
		logger = slog.Default()
	}
	return &PoolFindingQuerier{
		lister: pgstore.New(func() datapool.Pool { return pool }),
		logger: logger,
	}
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
	if _, err := auth.NewTenantID(tenant); err != nil {
		return nil, fmt.Errorf("finding querier: invalid tenant %q: %w", tenant, err)
	}

	query := pgstore.Query{
		Category: filter.Category,
		Search:   filter.Search,
		Limit:    int(filter.Limit),
		Offset:   int(filter.Offset),
	}
	if filter.Severity != "" {
		query.Severities = []string{filter.Severity}
	}
	if filter.MissionID != "" {
		missionID, err := types.ParseID(filter.MissionID)
		if err != nil {
			// No finding has a mission ID that is not a UUID. The answer is none.
			return []byte("[]"), nil
		}
		query.MissionID = missionID
	}

	// A list holds no evidence. The finding comes from Postgres by the query.
	records, _, err := q.lister.Find(ctx, tenant, query)
	if err != nil {
		return nil, fmt.Errorf("finding querier: query findings: %w", err)
	}

	out := make([]map[string]any, 0, len(records))
	for _, r := range records {
		out = append(out, findingToSDKShape(r))
	}

	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("finding querier: encode findings: %w", err)
	}
	q.logger.DebugContext(ctx, "finding querier: query completed",
		"tenant", tenant, "count", len(out))
	return encoded, nil
}

// findingToSDKShape maps a stored finding onto the SDK finding.Finding JSON
// shape, so a caller decodes findings it reads with the same type it uses to
// submit them. It holds no evidence, because this answer is a list.
func findingToSDKShape(f finding.EnhancedFinding) map[string]any {
	out := map[string]any{
		"id":          f.ID.String(),
		"title":       f.Title,
		"description": f.Description,
		"category":    f.Category,
		"severity":    string(f.Severity),
		"mission_id":  f.MissionID.String(),
		// The registered name of the agent that submitted the finding
		// (gibson#208), the SDK's agent_name.
		"agent_name": f.AgentName,
	}
	if !f.CreatedAt.IsZero() {
		out["created_at"] = f.CreatedAt.UTC().Format(time.RFC3339)
	}
	metadata := make(map[string]any, len(f.Metadata)+2)
	for k, v := range f.Metadata {
		metadata[k] = v
	}
	// The verified submitter and the enroller travel under metadata.
	if f.SubmittedBy != "" {
		metadata["submitted_by"] = f.SubmittedBy
	}
	if f.EnrolledBy != "" {
		metadata["enrolled_by"] = f.EnrolledBy
	}
	if len(metadata) > 0 {
		out["metadata"] = metadata
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
