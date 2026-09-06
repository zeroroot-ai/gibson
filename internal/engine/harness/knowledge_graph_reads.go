// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"encoding/json"
	"fmt"

	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// Graph reads on the daemon-side harness.
//
// These delegate to the SAME component.GraphRAGQuerier the daemon already hands
// to ComponentService — one querier, one implementation, reached two ways.
// Before this, ComponentService could serve these and nothing on the harness
// path could, which is why a dispatched agent could not read the tenant graph
// (zerocool-plugins ADR-0006, sdk docs/adr/0001-callback-knowledge-reads.md).
//
// Every read derives its tenant from the call context. No method takes a tenant,
// so reaching another tenant's graph is unrepresentable rather than refused.
//
// A nil querier is ErrKnowledgeUnavailable, never an empty slice: an agent that
// cannot tell "the graph knows nothing" from "I could not read the graph"
// reports a clean history for a target nobody checked.

// tenantForRead resolves the tenant a knowledge read runs as, and refuses the
// system tenant — a component read must always be some tenant's.
func (h *DefaultAgentHarness) tenantForRead(ctx context.Context) (string, error) {
	if h.graphrag == nil {
		return "", fmt.Errorf("graph reads: no graphrag querier wired: %w", ErrKnowledgeUnavailable)
	}
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" || tenant == auth.SystemTenantString {
		return "", fmt.Errorf("graph reads: no tenant on context: %w", ErrKnowledgeUnavailable)
	}
	return tenant, nil
}

// QueryNodes searches the tenant knowledge graph with hybrid vector + graph scoring.
func (h *DefaultAgentHarness) QueryNodes(ctx context.Context, query *graphragpb.GraphQuery) ([]*graphragpb.QueryResult, error) {
	tenant, err := h.tenantForRead(ctx)
	if err != nil {
		return nil, err
	}
	ctx, span := h.tracer.Start(ctx, "AgentHarness.QueryNodes")
	defer span.End()
	results, err := h.graphrag.QueryNodes(ctx, tenant, query)
	if err != nil {
		return nil, fmt.Errorf("query nodes: %w", err)
	}
	return results, nil
}

// FindSimilarAttacks returns attack patterns semantically close to content.
func (h *DefaultAgentHarness) FindSimilarAttacks(ctx context.Context, content string, topK int) ([]*graphragpb.AttackPattern, error) {
	tenant, err := h.tenantForRead(ctx)
	if err != nil {
		return nil, err
	}
	ctx, span := h.tracer.Start(ctx, "AgentHarness.FindSimilarAttacks")
	defer span.End()
	raw, err := h.graphrag.FindSimilarAttacks(ctx, tenant, content, topK)
	if err != nil {
		return nil, fmt.Errorf("find similar attacks: %w", err)
	}
	return decodeGraphResults[graphragpb.AttackPattern](raw, "attack patterns")
}

// GetAttackChains returns multi-hop technique paths from a starting technique.
func (h *DefaultAgentHarness) GetAttackChains(ctx context.Context, techniqueID string, maxDepth int) ([]*graphragpb.AttackChain, error) {
	tenant, err := h.tenantForRead(ctx)
	if err != nil {
		return nil, err
	}
	ctx, span := h.tracer.Start(ctx, "AgentHarness.GetAttackChains")
	defer span.End()
	raw, err := h.graphrag.GetAttackChains(ctx, tenant, techniqueID, maxDepth)
	if err != nil {
		return nil, fmt.Errorf("get attack chains: %w", err)
	}
	return decodeGraphResults[graphragpb.AttackChain](raw, "attack chains")
}

// FindSimilarFindings returns findings semantically close to the given one.
func (h *DefaultAgentHarness) FindSimilarFindings(ctx context.Context, findingID string, topK int) ([]*graphragpb.FindingNode, error) {
	tenant, err := h.tenantForRead(ctx)
	if err != nil {
		return nil, err
	}
	ctx, span := h.tracer.Start(ctx, "AgentHarness.FindSimilarFindings")
	defer span.End()
	raw, err := h.graphrag.FindSimilarFindings(ctx, tenant, findingID, topK)
	if err != nil {
		return nil, fmt.Errorf("find similar findings: %w", err)
	}
	return decodeGraphResults[graphragpb.FindingNode](raw, "finding nodes")
}

// GetRelatedFindings returns findings reachable from the given one by graph relationship.
func (h *DefaultAgentHarness) GetRelatedFindings(ctx context.Context, findingID string) ([]*graphragpb.FindingNode, error) {
	tenant, err := h.tenantForRead(ctx)
	if err != nil {
		return nil, err
	}
	ctx, span := h.tracer.Start(ctx, "AgentHarness.GetRelatedFindings")
	defer span.End()
	raw, err := h.graphrag.GetRelatedFindings(ctx, tenant, findingID)
	if err != nil {
		return nil, fmt.Errorf("get related findings: %w", err)
	}
	return decodeGraphResults[graphragpb.FindingNode](raw, "finding nodes")
}

// decodeGraphResults converts the querier's JSON payload into typed messages.
//
// The querier still answers in JSON because ComponentService's wire does; the
// callback wire is typed (sdk#496). This decode is the ONE place the two meet,
// rather than every caller parsing bytes — which is the state that let the
// schema live in a comment and drift.
//
// The proto field names match the JSON tags on gibson's internal structs, so
// encoding/json maps them directly; a field the proto deliberately omits
// (embedding) is simply dropped.
func decodeGraphResults[T any](raw []byte, what string) ([]*T, error) {
	if len(raw) == 0 {
		return []*T{}, nil
	}
	var out []*T
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode %s: %w", what, err)
	}
	return out, nil
}

// ApplicationFindings returns the Findings of one Application with, per
// Finding, whether the code it affects is inside an Image that a Deployment of
// that Application runs, and whether that Deployment exposes a Host.
//
// It is a traversal, not a search, which is why QueryNodes could not answer it:
// hybrid vector-and-graph scoring over a node-type filter has no way to say
// "this Package is in an Image this Application deploys" (gibson#1669).
//
// The distinction matters because of what an agent does with an unanswerable
// question. A triage rule table reads "not reachable" as "nothing runs this"
// and ranks the finding last, so a missing answer does not surface as an error
// — it silently buries a backlog. Like every read here, an unavailable graph is
// reported and never answered with an empty list.
func (h *DefaultAgentHarness) ApplicationFindings(
	ctx context.Context, application string, statuses []string, limit int,
) ([]byte, error) {
	tenant, err := h.tenantForRead(ctx)
	if err != nil {
		return nil, err
	}
	ctx, span := h.tracer.Start(ctx, "AgentHarness.ApplicationFindings")
	defer span.End()
	results, err := h.graphrag.ApplicationFindings(ctx, tenant, application, statuses, limit)
	if err != nil {
		return nil, fmt.Errorf("application findings: %w", err)
	}
	return results, nil
}
