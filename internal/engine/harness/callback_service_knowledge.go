// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/component"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
)

// Knowledge reads over the callback service.
//
// Each handler resolves the task's harness with getHarness(ctx, req.Context) and
// delegates — the same shape every other handler in this service uses. That
// resolution is why these carry ContextInfo rather than a bare work_id: it is
// what getHarness needs, and it also names mission_run_id, which mission-scoped
// reads require.
//
// UNAVAILABLE IS NOT EMPTY. A harness with no querier wired returns
// ErrKnowledgeUnavailable, and that maps to codes.Unavailable here so the
// distinction survives the wire. Answering an empty slice with a nil error would
// tell a dispatched agent the tenant knows nothing, which it cannot distinguish
// from a genuinely empty graph — a silent false negative in a security product,
// and the same defect the WorldView seam had.

// knowledgeErr maps a harness read failure onto a gRPC status.
func knowledgeErr(err error) error {
	if errors.Is(err, ErrKnowledgeUnavailable) {
		return status.Error(codes.Unavailable, err.Error())
	}
	return status.Error(codes.Internal, err.Error())
}

// QueryNodes searches the tenant knowledge graph for the calling task.
func (s *HarnessCallbackService) QueryNodes(ctx context.Context, req *harnesspb.QueryNodesRequest) (*harnesspb.QueryNodesResponse, error) {
	h, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	results, err := h.QueryNodes(ctx, req.GetQuery())
	if err != nil {
		return nil, knowledgeErr(err)
	}
	return &harnesspb.QueryNodesResponse{Results: results}, nil
}

// FindSimilarAttacks returns attack patterns semantically close to content.
func (s *HarnessCallbackService) FindSimilarAttacks(ctx context.Context, req *harnesspb.FindSimilarAttacksRequest) (*harnesspb.FindSimilarAttacksResponse, error) {
	h, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	results, err := h.FindSimilarAttacks(ctx, req.GetContent(), int(req.GetTopK()))
	if err != nil {
		return nil, knowledgeErr(err)
	}
	return &harnesspb.FindSimilarAttacksResponse{Results: results}, nil
}

// GetAttackChains returns multi-hop technique paths from a starting technique.
func (s *HarnessCallbackService) GetAttackChains(ctx context.Context, req *harnesspb.GetAttackChainsRequest) (*harnesspb.GetAttackChainsResponse, error) {
	h, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	results, err := h.GetAttackChains(ctx, req.GetTechniqueId(), int(req.GetMaxDepth()))
	if err != nil {
		return nil, knowledgeErr(err)
	}
	return &harnesspb.GetAttackChainsResponse{Results: results}, nil
}

// FindSimilarFindings returns findings semantically close to the given one.
func (s *HarnessCallbackService) FindSimilarFindings(ctx context.Context, req *harnesspb.FindSimilarFindingsRequest) (*harnesspb.FindSimilarFindingsResponse, error) {
	h, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	results, err := h.FindSimilarFindings(ctx, req.GetFindingId(), int(req.GetTopK()))
	if err != nil {
		return nil, knowledgeErr(err)
	}
	return &harnesspb.FindSimilarFindingsResponse{Results: results}, nil
}

// GetRelatedFindings returns findings reachable from the given one by graph relationship.
func (s *HarnessCallbackService) GetRelatedFindings(ctx context.Context, req *harnesspb.GetRelatedFindingsRequest) (*harnesspb.GetRelatedFindingsResponse, error) {
	h, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	results, err := h.GetRelatedFindings(ctx, req.GetFindingId())
	if err != nil {
		return nil, knowledgeErr(err)
	}
	return &harnesspb.GetRelatedFindingsResponse{Results: results}, nil
}

// GetFindings returns previously submitted findings matching a filter.
func (s *HarnessCallbackService) GetFindings(ctx context.Context, req *harnesspb.GetFindingsRequest) (*harnesspb.GetFindingsResponse, error) {
	h, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	findings, err := h.GetFindings(ctx, findingFilterFromProto(req.GetFilter()))
	if err != nil {
		return nil, knowledgeErr(err)
	}
	return &harnesspb.GetFindingsResponse{Findings: findingsToProto(findings)}, nil
}

// GetRunFindings returns findings from earlier runs of the calling mission.
func (s *HarnessCallbackService) GetRunFindings(ctx context.Context, req *harnesspb.GetRunFindingsRequest) (*harnesspb.GetRunFindingsResponse, error) {
	h, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	findings, err := h.GetRunFindings(ctx, req.GetScope(), findingFilterFromProto(req.GetFilter()))
	if err != nil {
		return nil, knowledgeErr(err)
	}
	return &harnesspb.GetRunFindingsResponse{Findings: findingsToProto(findings)}, nil
}

// GetMissionRunHistory returns every run of the calling mission.
func (s *HarnessCallbackService) GetMissionRunHistory(ctx context.Context, req *harnesspb.GetMissionRunHistoryRequest) (*harnesspb.GetMissionRunHistoryResponse, error) {
	h, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	runs, err := h.GetMissionRunHistory(ctx)
	if err != nil {
		return nil, knowledgeErr(err)
	}
	return &harnesspb.GetMissionRunHistoryResponse{Runs: runSummariesToProto(runs)}, nil
}

// ── conversions ─────────────────────────────────────────────────────────────

func findingFilterFromProto(pf *harnesspb.FindingFilter) FindingFilter {
	var f FindingFilter
	if pf == nil {
		return f
	}
	if s := pf.GetSeverity(); s != typespb.FindingSeverity_FINDING_SEVERITY_UNSPECIFIED {
		sev := protoSeverityToAgentSeverity(s)
		f.Severity = &sev
	}
	return f
}

// agentFindingToProto is the reverse of protoFindingToFinding. Only the reverse
// direction existed, because until now nothing on the daemon sent findings back
// out over this service.
func agentFindingToProto(f *agent.Finding) *typespb.Finding {
	if f == nil {
		return nil
	}
	pf := &typespb.Finding{
		Id:          f.ID.String(),
		Title:       f.Title,
		Description: f.Description,
		Category:    f.Category,
		Confidence:  f.Confidence,
		Severity:    agentSeverityToProto(f.Severity),
	}
	if f.TargetID != nil {
		pf.TargetId = f.TargetID.String()
	}
	return pf
}

func agentSeverityToProto(s agent.FindingSeverity) typespb.FindingSeverity {
	switch s {
	case agent.SeverityCritical:
		return typespb.FindingSeverity_FINDING_SEVERITY_CRITICAL
	case agent.SeverityHigh:
		return typespb.FindingSeverity_FINDING_SEVERITY_HIGH
	case agent.SeverityMedium:
		return typespb.FindingSeverity_FINDING_SEVERITY_MEDIUM
	case agent.SeverityLow:
		return typespb.FindingSeverity_FINDING_SEVERITY_LOW
	case agent.SeverityInfo:
		return typespb.FindingSeverity_FINDING_SEVERITY_INFO
	default:
		return typespb.FindingSeverity_FINDING_SEVERITY_UNSPECIFIED
	}
}

func findingsToProto(fs []agent.Finding) []*typespb.Finding {
	out := make([]*typespb.Finding, 0, len(fs))
	for i := range fs {
		out = append(out, agentFindingToProto(&fs[i]))
	}
	return out
}

func runSummariesToProto(rs []MissionRunSummarySDK) []*typespb.MissionRunSummary {
	out := make([]*typespb.MissionRunSummary, 0, len(rs))
	for _, r := range rs {
		s := &typespb.MissionRunSummary{
			MissionId:     r.MissionID,
			RunNumber:     boundedInt32(r.RunNumber),
			Status:        r.Status,
			FindingsCount: boundedInt32(r.FindingsCount),
			CreatedAt:     r.CreatedAt.UnixMilli(),
		}
		// completed_at stays 0 while the run is in flight; a zero timestamp
		// would read as "finished at the epoch".
		if r.CompletedAt != nil {
			s.CompletedAt = r.CompletedAt.UnixMilli()
		}
		out = append(out, s)
	}
	return out
}

// boundedInt32 narrows a count to the wire's int32 without wrapping. A negative
// or absurd value is upstream corruption, and wrapping it would put a negative
// run number on the wire rather than surfacing the problem.
func boundedInt32(n int) int32 {
	if n < 0 {
		return 0
	}
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(n)
}

// ApplicationFindings returns the open Findings of one Application with, per
// Finding, whether a running Deployment actually contains the code it affects.
//
// The handler exists for the same reason the classification does: admitting the
// RPC to the Envoy peer without one would let an external component pass every
// auth gate and then get codes.Unimplemented — a denial that looks like a bug in
// the caller rather than a gap in the server (gibson#1450).
//
// The harness answers in JSON because the traversal is shaped by the query, not
// by a proto. Decoding here rather than in the harness keeps the wire type out
// of the graph read, which has no other reason to know about it.
func (s *HarnessCallbackService) ApplicationFindings(ctx context.Context, req *harnesspb.ApplicationFindingsRequest) (*harnesspb.ApplicationFindingsResponse, error) {
	h, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	raw, err := h.ApplicationFindings(ctx, req.GetApplication(), req.GetStatuses(), int(req.GetLimit()))
	if err != nil {
		return nil, knowledgeErr(err)
	}
	findings, err := applicationFindingsToProto(raw)
	if err != nil {
		return nil, knowledgeErr(err)
	}
	return &harnesspb.ApplicationFindingsResponse{Findings: findings}, nil
}

// applicationFindingsToProto decodes the harness's JSON answer onto the wire.
//
// An empty answer decodes to an empty slice, never nil, so "this Application has
// nothing open" stays distinguishable on the wire from a read that failed —
// which is the distinction the whole lifecycle read exists to preserve.
//
// The priority triple (gibson#1684) is carried through exactly as read, and the
// two ways of "improving" it are both wrong:
//
// Substituting a default for an unranked Finding — a P4, say — makes it
// indistinguishable from a ranking somebody actually made. The triage rule that
// keeps the previous priority when EPSS or KEV is unavailable would then keep a
// value nobody decided, and that Finding would never be triaged again.
//
// Treating a ranked-but-unexplained Finding as incomplete is the mirror of it.
// Priority and reason are written by different steps — a rule table decides, a
// model explains — so a Finding legitimately arrives ranked with no sentence
// attached whenever the model answered short or not at all. Dropping the
// ranking on that basis would let a model outage erase decisions that were
// computed deterministically and never involved a model.
//
// Empty means "no pass has decided", which is a fact about the Finding, not a
// gap to fill.
func applicationFindingsToProto(raw []byte) ([]*harnesspb.ApplicationFinding, error) {
	if len(raw) == 0 {
		return []*harnesspb.ApplicationFinding{}, nil
	}
	var decoded []component.ApplicationFinding
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("application findings: decode: %w", err)
	}
	out := make([]*harnesspb.ApplicationFinding, 0, len(decoded))
	for _, f := range decoded {
		out = append(out, &harnesspb.ApplicationFinding{
			FindingId:       f.FindingID,
			Status:          f.Status,
			Severity:        f.Severity,
			VulnerabilityId: f.VulnerabilityID,
			PlaceLabel:      f.PlaceLabel,
			PlaceKey:        f.PlaceKey,
			Reachable:       f.Reachable,
			Exposed:         f.Exposed,
			DeploymentKey:   f.DeploymentKey,
			ImageKey:        f.ImageKey,
			Priority:        f.Priority,
			PriorityRule:    f.PriorityRule,
			PriorityReason:  f.PriorityReason,
		})
	}
	return out, nil
}
