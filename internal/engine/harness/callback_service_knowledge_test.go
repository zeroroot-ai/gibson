// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
)

// Handler tests for the knowledge reads on the callback service.
//
// Each covers the two outcomes that matter and are easy to get wrong: a served
// read returns typed results, and an ABSENT SEAM returns codes.Unavailable
// rather than an empty slice. The second is the whole point of
// ErrKnowledgeUnavailable — an agent that reads "unavailable" as "nothing found"
// reports a clean prior record for a target nobody checked.

// stubQuerier serves the graph reads from canned JSON, standing in for
// PoolGraphRAGQuerier. nil fields make that read fail.
type stubQuerier struct {
	queryErr error
	nodes    []*graphragpb.QueryResult
	attacks  []byte
	chains   []byte
	findings []byte
	related  []byte
	appFinds []byte
}

func (s *stubQuerier) QueryNodes(context.Context, string, *graphragpb.GraphQuery) ([]*graphragpb.QueryResult, error) {
	return s.nodes, s.queryErr
}
func (s *stubQuerier) FindSimilarAttacks(context.Context, string, string, int) ([]byte, error) {
	return s.attacks, nil
}
func (s *stubQuerier) GetAttackChains(context.Context, string, string, int) ([]byte, error) {
	return s.chains, nil
}
func (s *stubQuerier) FindSimilarFindings(context.Context, string, string, int) ([]byte, error) {
	return s.findings, nil
}
func (s *stubQuerier) GetRelatedFindings(context.Context, string, string) ([]byte, error) {
	return s.related, nil
}

func (s *stubQuerier) ApplicationFindings(context.Context, string, string, []string, int) ([]byte, error) {
	return s.appFinds, s.queryErr
}

func knowledgeService(t *testing.T, q *stubQuerier) (*HarnessCallbackService, *harnesspb.ContextInfo) {
	t.Helper()
	mid := types.NewID()
	h := &observeMockHarness{missionID: mid, tenantID: "acme", targetID: types.NewID()}
	// Assigned only when non-nil: a typed nil pointer stored in an interface is
	// NOT nil, so `h.graphrag = (*stubQuerier)(nil)` would sail past the
	// absent-seam guard and then panic dereferencing the receiver. Leaving the
	// field untouched is what "no querier wired" actually looks like.
	if q != nil {
		h.graphrag = q
	}
	// The factory always wires a tracer; only a hand-built mock lacks one.
	h.tracer = noop.NewTracerProvider().Tracer("test")
	registry := NewCallbackHarnessRegistry()
	registry.Register(mid.String(), "recon-agent", h)
	svc := NewHarnessCallbackServiceWithRegistry(slog.New(slog.DiscardHandler), registry)
	return svc, &harnesspb.ContextInfo{MissionId: mid.String(), AgentName: "recon-agent"}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func TestFindSimilarAttacks(t *testing.T) {
	svc, cinfo := knowledgeService(t, &stubQuerier{
		attacks: mustJSON(t, []map[string]any{{"technique_id": "T1566", "name": "Phishing"}}),
	})
	resp, err := svc.FindSimilarAttacks(acmeCtx(), &harnesspb.FindSimilarAttacksRequest{
		Context: cinfo, Content: "credential harvesting", TopK: 5,
	})
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	assert.Equal(t, "T1566", resp.Results[0].TechniqueId)
}

func TestFindSimilarAttacks_UnavailableWhenNoQuerier(t *testing.T) {
	svc, cinfo := knowledgeService(t, nil)
	resp, err := svc.FindSimilarAttacks(acmeCtx(), &harnesspb.FindSimilarAttacksRequest{Context: cinfo, Content: "x"})
	require.Error(t, err, "an absent querier must fail, never report zero attack patterns")
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Nil(t, resp)
}

func TestGetAttackChains(t *testing.T) {
	svc, cinfo := knowledgeService(t, &stubQuerier{
		chains: mustJSON(t, []map[string]any{{"id": "chain-1", "severity": "high"}}),
	})
	resp, err := svc.GetAttackChains(acmeCtx(), &harnesspb.GetAttackChainsRequest{
		Context: cinfo, TechniqueId: "T1566", MaxDepth: 3,
	})
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	assert.Equal(t, "chain-1", resp.Results[0].Id)
}

func TestGetAttackChains_UnavailableWhenNoQuerier(t *testing.T) {
	svc, cinfo := knowledgeService(t, nil)
	_, err := svc.GetAttackChains(acmeCtx(), &harnesspb.GetAttackChainsRequest{Context: cinfo, TechniqueId: "T1566"})
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestFindSimilarFindings(t *testing.T) {
	svc, cinfo := knowledgeService(t, &stubQuerier{
		findings: mustJSON(t, []map[string]any{{"id": "f-1", "title": "XSS"}}),
	})
	resp, err := svc.FindSimilarFindings(acmeCtx(), &harnesspb.FindSimilarFindingsRequest{
		Context: cinfo, FindingId: "f-0", TopK: 5,
	})
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	assert.Equal(t, "XSS", resp.Results[0].Title)
}

func TestFindSimilarFindings_UnavailableWhenNoQuerier(t *testing.T) {
	svc, cinfo := knowledgeService(t, nil)
	_, err := svc.FindSimilarFindings(acmeCtx(), &harnesspb.FindSimilarFindingsRequest{Context: cinfo, FindingId: "f-0"})
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestGetRelatedFindings(t *testing.T) {
	svc, cinfo := knowledgeService(t, &stubQuerier{
		related: mustJSON(t, []map[string]any{{"id": "f-2", "severity": "medium"}}),
	})
	resp, err := svc.GetRelatedFindings(acmeCtx(), &harnesspb.GetRelatedFindingsRequest{
		Context: cinfo, FindingId: "f-1",
	})
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	assert.Equal(t, "f-2", resp.Results[0].Id)
}

func TestGetRelatedFindings_UnavailableWhenNoQuerier(t *testing.T) {
	svc, cinfo := knowledgeService(t, nil)
	_, err := svc.GetRelatedFindings(acmeCtx(), &harnesspb.GetRelatedFindingsRequest{Context: cinfo, FindingId: "f-1"})
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestQueryNodes(t *testing.T) {
	svc, cinfo := knowledgeService(t, &stubQuerier{
		nodes: []*graphragpb.QueryResult{{Score: 0.9, Node: &graphragpb.GraphNode{Id: "n-1"}}},
	})
	resp, err := svc.QueryNodes(acmeCtx(), &harnesspb.QueryNodesRequest{
		Context: cinfo, Query: &graphragpb.GraphQuery{Text: "prior findings"},
	})
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	assert.Equal(t, "n-1", resp.Results[0].Node.Id)
}

func TestQueryNodes_UnavailableWhenNoQuerier(t *testing.T) {
	svc, cinfo := knowledgeService(t, nil)
	_, err := svc.QueryNodes(acmeCtx(), &harnesspb.QueryNodesRequest{Context: cinfo, Query: &graphragpb.GraphQuery{Text: "x"}})
	require.Error(t, err, "an absent querier must fail, never report an empty graph")
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

// ── the harness methods themselves ──────────────────────────────────────────

func knowledgeHarness(t *testing.T, q *stubQuerier) *DefaultAgentHarness {
	t.Helper()
	h := &observeMockHarness{missionID: types.NewID(), tenantID: "acme", targetID: types.NewID()}
	if q != nil {
		h.graphrag = q
	}
	h.tracer = noop.NewTracerProvider().Tracer("test")
	h.logger = slog.New(slog.DiscardHandler)
	return &h.DefaultAgentHarness
}

func TestDefaultAgentHarness_GraphReadsDecodeJSON(t *testing.T) {
	h := knowledgeHarness(t, &stubQuerier{
		attacks:  mustJSON(t, []map[string]any{{"technique_id": "T1566"}}),
		chains:   mustJSON(t, []map[string]any{{"id": "c-1"}}),
		findings: mustJSON(t, []map[string]any{{"id": "f-1"}}),
		related:  mustJSON(t, []map[string]any{{"id": "f-2"}}),
		nodes:    []*graphragpb.QueryResult{{Score: 1, Node: &graphragpb.GraphNode{Id: "n-1"}}},
	})
	ctx := acmeCtx()

	nodes, err := h.QueryNodes(ctx, &graphragpb.GraphQuery{Text: "x"})
	require.NoError(t, err)
	assert.Len(t, nodes, 1)

	atk, err := h.FindSimilarAttacks(ctx, "phishing", 5)
	require.NoError(t, err)
	require.Len(t, atk, 1)
	assert.Equal(t, "T1566", atk[0].TechniqueId)

	ch, err := h.GetAttackChains(ctx, "T1566", 3)
	require.NoError(t, err)
	assert.Equal(t, "c-1", ch[0].Id)

	sim, err := h.FindSimilarFindings(ctx, "f-0", 5)
	require.NoError(t, err)
	assert.Equal(t, "f-1", sim[0].Id)

	rel, err := h.GetRelatedFindings(ctx, "f-1")
	require.NoError(t, err)
	assert.Equal(t, "f-2", rel[0].Id)
}

// TestDefaultAgentHarness_GraphReadsUnavailable: every read reports unavailable
// when no querier is wired, and none of them answers an empty slice. An agent
// that cannot tell those apart reports a clean prior record for a target nobody
// checked.
func TestDefaultAgentHarness_GraphReadsUnavailable(t *testing.T) {
	h := knowledgeHarness(t, nil)
	ctx := acmeCtx()

	checks := map[string]func() error{
		"QueryNodes":          func() error { _, err := h.QueryNodes(ctx, nil); return err },
		"FindSimilarAttacks":  func() error { _, err := h.FindSimilarAttacks(ctx, "x", 1); return err },
		"GetAttackChains":     func() error { _, err := h.GetAttackChains(ctx, "T1", 1); return err },
		"FindSimilarFindings": func() error { _, err := h.FindSimilarFindings(ctx, "f", 1); return err },
		"GetRelatedFindings":  func() error { _, err := h.GetRelatedFindings(ctx, "f"); return err },
		"ApplicationFindings": func() error {
			_, err := h.ApplicationFindings(ctx, "customer-portal", nil, 10)
			return err
		},
	}
	for name, call := range checks {
		err := call()
		require.Error(t, err, "%s must fail, not report an empty graph", name)
		assert.ErrorIs(t, err, ErrKnowledgeUnavailable, "%s must be matchable", name)
	}
}

// TestDefaultAgentHarness_GraphReadsRefuseSystemTenant: a knowledge read is
// always some tenant's. The system tenant is refused rather than served, so a
// missing tenant on the context cannot quietly read across the boundary.
func TestDefaultAgentHarness_GraphReadsRefuseSystemTenant(t *testing.T) {
	h := knowledgeHarness(t, &stubQuerier{})
	_, err := h.QueryNodes(context.Background(), &graphragpb.GraphQuery{Text: "x"})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKnowledgeUnavailable)
}

func TestDecodeGraphResults(t *testing.T) {
	// Empty payload is an empty answer, not an error: a graph with no matching
	// attack patterns is an ordinary result.
	out, err := decodeGraphResults[graphragpb.AttackPattern](nil, "attack patterns")
	require.NoError(t, err)
	assert.Empty(t, out)

	// Malformed payload IS an error — silently returning nothing would look
	// identical to "the graph knows nothing".
	_, err = decodeGraphResults[graphragpb.AttackPattern]([]byte("{not json"), "attack patterns")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode attack patterns")
}

func TestRunSummariesToProto(t *testing.T) {
	done := time.UnixMilli(1_700_000_000_000)
	out := runSummariesToProto([]MissionRunSummarySDK{
		{MissionID: "m-1", RunNumber: 2, Status: "completed", FindingsCount: 3, CreatedAt: done, CompletedAt: &done},
		{MissionID: "m-2", RunNumber: 3, Status: "running", CreatedAt: done},
	})
	require.Len(t, out, 2)
	assert.Equal(t, int32(2), out[0].RunNumber)
	assert.Equal(t, done.UnixMilli(), out[0].CompletedAt)
	// An in-flight run leaves completed_at at 0 rather than claiming it finished
	// at the epoch.
	assert.Equal(t, int64(0), out[1].CompletedAt)
}

func TestBoundedInt32(t *testing.T) {
	// Clamps rather than wraps: a negative run number on the wire would be
	// upstream corruption presented as data.
	assert.Equal(t, int32(0), boundedInt32(-1))
	assert.Equal(t, int32(7), boundedInt32(7))
	assert.Equal(t, int32(math.MaxInt32), boundedInt32(math.MaxInt64))
}

// ── GetRunFindings ──────────────────────────────────────────────────────────

type stubRunContext struct {
	prev    *MissionRunSummary
	history []*MissionRunSummary
	err     error
}

func (s *stubRunContext) GetContext(context.Context) (*MissionExecutionContext, error) {
	return &MissionExecutionContext{}, nil
}
func (s *stubRunContext) GetRunHistory(context.Context) ([]*MissionRunSummary, error) {
	return s.history, s.err
}
func (s *stubRunContext) GetPreviousRun(context.Context) (*MissionRunSummary, error) {
	return s.prev, s.err
}
func (s *stubRunContext) IsResumedRun() bool { return false }

type stubFindingStore struct {
	byMission map[types.ID][]agent.Finding
	err       error
}

func (s *stubFindingStore) Store(context.Context, string, types.ID, agent.Finding) error { return nil }
func (s *stubFindingStore) Get(_ context.Context, _ string, missionID types.ID, _ FindingFilter) ([]agent.Finding, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.byMission[missionID], nil
}

func runFindingsHarness(t *testing.T, cp MissionContextProvider, fs FindingStore) *DefaultAgentHarness {
	t.Helper()
	h := knowledgeHarness(t, &stubQuerier{})
	h.contextProvider = cp
	h.findingStore = fs
	return h
}

func TestGetRunFindings_PreviousScope(t *testing.T) {
	prevID := types.NewID()
	h := runFindingsHarness(t,
		&stubRunContext{prev: &MissionRunSummary{MissionID: prevID, RunNumber: 1}},
		&stubFindingStore{byMission: map[types.ID][]agent.Finding{prevID: {{Title: "SQLi"}}}},
	)
	out, err := h.GetRunFindings(acmeCtx(), harnesspb.RunScope_RUN_SCOPE_PREVIOUS, FindingFilter{})
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, "SQLi", out[0].Title)
}

// TestGetRunFindings_NoPreviousRunIsEmptyNotAnError: a mission genuinely on its
// first run has no prior findings, and that is a real answer. Only an ABSENT
// SEAM is an error — collapsing the two in either direction is the defect.
func TestGetRunFindings_NoPreviousRunIsEmptyNotAnError(t *testing.T) {
	h := runFindingsHarness(t, &stubRunContext{prev: nil}, &stubFindingStore{})
	out, err := h.GetRunFindings(acmeCtx(), harnesspb.RunScope_RUN_SCOPE_PREVIOUS, FindingFilter{})
	require.NoError(t, err)
	assert.Empty(t, out)
}

func TestGetRunFindings_AllScopeSpansEveryRun(t *testing.T) {
	a, b := types.NewID(), types.NewID()
	h := runFindingsHarness(t,
		&stubRunContext{history: []*MissionRunSummary{{MissionID: a}, {MissionID: b}}},
		&stubFindingStore{byMission: map[types.ID][]agent.Finding{a: {{Title: "one"}}, b: {{Title: "two"}}}},
	)
	out, err := h.GetRunFindings(acmeCtx(), harnesspb.RunScope_RUN_SCOPE_ALL, FindingFilter{})
	require.NoError(t, err)
	assert.Len(t, out, 2)
}

// TestGetRunFindings_OneUnreadableRunFailsTheWholeRead: the previous
// implementation logged and skipped, returning a subset that looks complete. A
// partial history presented as whole is the same lie as an empty one.
func TestGetRunFindings_OneUnreadableRunFailsTheWholeRead(t *testing.T) {
	h := runFindingsHarness(t,
		&stubRunContext{history: []*MissionRunSummary{{MissionID: types.NewID()}}},
		&stubFindingStore{err: assert.AnError},
	)
	_, err := h.GetRunFindings(acmeCtx(), harnesspb.RunScope_RUN_SCOPE_ALL, FindingFilter{})
	require.Error(t, err)
}

func TestGetRunFindings_UnavailableWhenSeamsAbsent(t *testing.T) {
	noCtx := runFindingsHarness(t, nil, &stubFindingStore{})
	_, err := noCtx.GetRunFindings(acmeCtx(), harnesspb.RunScope_RUN_SCOPE_ALL, FindingFilter{})
	require.ErrorIs(t, err, ErrKnowledgeUnavailable)

	noStore := runFindingsHarness(t, &stubRunContext{}, nil)
	_, err = noStore.GetRunFindings(acmeCtx(), harnesspb.RunScope_RUN_SCOPE_ALL, FindingFilter{})
	require.ErrorIs(t, err, ErrKnowledgeUnavailable)
}

// TestGetRunFindings_UnspecifiedScopeIsRejected: the zero value must not quietly
// mean "previous". A caller that forgot to set a scope gets told.
func TestGetRunFindings_UnspecifiedScopeIsRejected(t *testing.T) {
	h := runFindingsHarness(t, &stubRunContext{}, &stubFindingStore{})
	_, err := h.GetRunFindings(acmeCtx(), harnesspb.RunScope_RUN_SCOPE_UNSPECIFIED, FindingFilter{})
	require.Error(t, err)
}

// ── the finding + history handlers and their conversions ────────────────────

func findingHandlerService(t *testing.T, cp MissionContextProvider, fs FindingStore, runs []MissionRunSummarySDK) (*HarnessCallbackService, *harnesspb.ContextInfo) {
	t.Helper()
	mid := types.NewID()
	h := &observeMockHarness{missionID: mid, tenantID: "acme", targetID: types.NewID()}
	h.tracer = noop.NewTracerProvider().Tracer("test")
	h.logger = slog.New(slog.DiscardHandler)
	h.contextProvider = cp
	h.findingStore = fs
	registry := NewCallbackHarnessRegistry()
	registry.Register(mid.String(), "recon-agent", &runHistoryHarness{observeMockHarness: h, runs: runs})
	svc := NewHarnessCallbackServiceWithRegistry(slog.New(slog.DiscardHandler), registry)
	return svc, &harnesspb.ContextInfo{MissionId: mid.String(), AgentName: "recon-agent"}
}

// runHistoryHarness overrides only GetMissionRunHistory. The daemon reads it
// from a mission store the mock does not have, and the handler under test only
// cares that whatever the harness returns reaches the wire.
type runHistoryHarness struct {
	*observeMockHarness
	runs []MissionRunSummarySDK
}

func (r *runHistoryHarness) GetMissionRunHistory(context.Context) ([]MissionRunSummarySDK, error) {
	return r.runs, nil
}

func TestGetFindings(t *testing.T) {
	mid := types.NewID()
	svc, cinfo := findingHandlerService(t,
		&stubRunContext{},
		&stubFindingStore{byMission: map[types.ID][]agent.Finding{mid: {{Title: "XSS"}}}},
		nil)
	resp, err := svc.GetFindings(acmeCtx(), &harnesspb.GetFindingsRequest{Context: cinfo})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGetRunFindings(t *testing.T) {
	prevID := types.NewID()
	svc, cinfo := findingHandlerService(t,
		&stubRunContext{prev: &MissionRunSummary{MissionID: prevID}},
		&stubFindingStore{byMission: map[types.ID][]agent.Finding{prevID: {{Title: "SQLi"}}}},
		nil)
	resp, err := svc.GetRunFindings(acmeCtx(), &harnesspb.GetRunFindingsRequest{
		Context: cinfo, Scope: harnesspb.RunScope_RUN_SCOPE_PREVIOUS,
	})
	require.NoError(t, err)
	require.Len(t, resp.Findings, 1)
	assert.Equal(t, "SQLi", resp.Findings[0].Title)
}

func TestGetRunFindings_UnavailableSurfacesAsUnavailable(t *testing.T) {
	svc, cinfo := findingHandlerService(t, nil, nil, nil)
	_, err := svc.GetRunFindings(acmeCtx(), &harnesspb.GetRunFindingsRequest{
		Context: cinfo, Scope: harnesspb.RunScope_RUN_SCOPE_ALL,
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err),
		"an absent seam must reach the agent as Unavailable, not as an empty list")
}

func TestGetMissionRunHistory(t *testing.T) {
	svc, cinfo := findingHandlerService(t, &stubRunContext{}, &stubFindingStore{},
		[]MissionRunSummarySDK{{MissionID: "m-1", RunNumber: 1, Status: "completed"}})
	resp, err := svc.GetMissionRunHistory(acmeCtx(), &harnesspb.GetMissionRunHistoryRequest{Context: cinfo})
	require.NoError(t, err)
	require.Len(t, resp.Runs, 1)
	assert.Equal(t, "m-1", resp.Runs[0].MissionId)
}

func TestFindingFilterFromProto(t *testing.T) {
	assert.Nil(t, findingFilterFromProto(nil).Severity)
	f := findingFilterFromProto(&harnesspb.FindingFilter{Severity: typespb.FindingSeverity_FINDING_SEVERITY_HIGH})
	require.NotNil(t, f.Severity)
	assert.Equal(t, agent.SeverityHigh, *f.Severity)
}

func TestAgentFindingToProto(t *testing.T) {
	assert.Nil(t, agentFindingToProto(nil))
	target := types.NewID()
	pf := agentFindingToProto(&agent.Finding{
		ID: types.NewID(), Title: "XSS", Severity: agent.SeverityHigh, TargetID: &target,
	})
	require.NotNil(t, pf)
	assert.Equal(t, "XSS", pf.Title)
	assert.Equal(t, typespb.FindingSeverity_FINDING_SEVERITY_HIGH, pf.Severity)
	assert.Equal(t, target.String(), pf.TargetId)
}

func TestAgentSeverityToProto(t *testing.T) {
	for in, want := range map[agent.FindingSeverity]typespb.FindingSeverity{
		agent.SeverityCritical:            typespb.FindingSeverity_FINDING_SEVERITY_CRITICAL,
		agent.SeverityHigh:                typespb.FindingSeverity_FINDING_SEVERITY_HIGH,
		agent.SeverityMedium:              typespb.FindingSeverity_FINDING_SEVERITY_MEDIUM,
		agent.SeverityLow:                 typespb.FindingSeverity_FINDING_SEVERITY_LOW,
		agent.SeverityInfo:                typespb.FindingSeverity_FINDING_SEVERITY_INFO,
		agent.FindingSeverity("nonsense"): typespb.FindingSeverity_FINDING_SEVERITY_UNSPECIFIED,
	} {
		assert.Equal(t, want, agentSeverityToProto(in), "severity %q", in)
	}
}

// ── the embeddable default, and the error paths ─────────────────────────────

// TestUnimplementedKnowledgeReader: every method reports unavailable. A stub
// embedding this says "I cannot answer", never "there is nothing to find" — the
// distinction the whole surface is built around.
func TestUnimplementedKnowledgeReader(t *testing.T) {
	var u UnimplementedKnowledgeReader
	ctx := context.Background()

	checks := map[string]func() error{
		"GetFindings":          func() error { _, err := u.GetFindings(ctx, FindingFilter{}); return err },
		"GetMissionRunHistory": func() error { _, err := u.GetMissionRunHistory(ctx); return err },
		"GetRunFindings": func() error {
			_, err := u.GetRunFindings(ctx, harnesspb.RunScope_RUN_SCOPE_ALL, FindingFilter{})
			return err
		},
		"QueryNodes":          func() error { _, err := u.QueryNodes(ctx, nil); return err },
		"FindSimilarAttacks":  func() error { _, err := u.FindSimilarAttacks(ctx, "x", 1); return err },
		"GetAttackChains":     func() error { _, err := u.GetAttackChains(ctx, "T1", 1); return err },
		"FindSimilarFindings": func() error { _, err := u.FindSimilarFindings(ctx, "f", 1); return err },
		"GetRelatedFindings":  func() error { _, err := u.GetRelatedFindings(ctx, "f"); return err },
	}
	for name, call := range checks {
		require.ErrorIs(t, call(), ErrKnowledgeUnavailable, "%s must report unavailable", name)
	}
}

// TestResolveGraphRAG: an unset provider yields no querier rather than panicking.
// The provider exists because the daemon wires the querier after the harness
// factory is built; a factory constructed before any wiring must still work.
func TestResolveGraphRAG(t *testing.T) {
	assert.Nil(t, resolveGraphRAG(nil))
	q := &stubQuerier{}
	assert.NotNil(t, resolveGraphRAG(func() component.GraphRAGQuerier { return q }))
}

// TestKnowledgeErr: only an unavailable seam becomes codes.Unavailable. Every
// other failure stays Internal, so "the daemon is misconfigured" and "the query
// blew up" remain distinguishable to the caller.
func TestKnowledgeErr(t *testing.T) {
	assert.Equal(t, codes.Unavailable, status.Code(knowledgeErr(ErrKnowledgeUnavailable)))
	assert.Equal(t, codes.Unavailable,
		status.Code(knowledgeErr(fmt.Errorf("wrapped: %w", ErrKnowledgeUnavailable))))
	assert.Equal(t, codes.Internal, status.Code(knowledgeErr(assert.AnError)))
}

// TestKnowledgeHandlers_RejectUnknownMission: getHarness refuses a mission this
// daemon is not running, so a caller cannot read another mission's knowledge by
// naming it.
func TestKnowledgeHandlers_RejectUnknownMission(t *testing.T) {
	svc, _ := knowledgeService(t, &stubQuerier{})
	stranger := &harnesspb.ContextInfo{MissionId: types.NewID().String(), AgentName: "recon-agent"}

	_, err := svc.GetFindings(acmeCtx(), &harnesspb.GetFindingsRequest{Context: stranger})
	require.Error(t, err)

	_, err = svc.GetMissionRunHistory(acmeCtx(), &harnesspb.GetMissionRunHistoryRequest{Context: stranger})
	require.Error(t, err)

	_, err = svc.QueryNodes(acmeCtx(), &harnesspb.QueryNodesRequest{Context: stranger})
	require.Error(t, err)
}

func TestDefaultAgentHarness_GetMissionRunHistory(t *testing.T) {
	h := runFindingsHarness(t,
		&stubRunContext{history: []*MissionRunSummary{{MissionID: types.NewID(), RunNumber: 1, Status: "completed"}}},
		&stubFindingStore{})
	runs, err := h.GetMissionRunHistory(acmeCtx())
	require.NoError(t, err)
	require.Len(t, runs, 1)
	assert.Equal(t, 1, runs[0].RunNumber)
}

// TestDefaultAgentHarness_GetMissionRunHistoryUnavailable: an absent provider is
// not "this mission has never run". It used to answer an empty history, which an
// agent cannot tell from a genuine first run.
func TestDefaultAgentHarness_GetMissionRunHistoryUnavailable(t *testing.T) {
	h := runFindingsHarness(t, nil, &stubFindingStore{})
	_, err := h.GetMissionRunHistory(acmeCtx())
	require.ErrorIs(t, err, ErrKnowledgeUnavailable)
}

func TestDefaultAgentHarness_GetMissionRunHistoryPropagatesErrors(t *testing.T) {
	h := runFindingsHarness(t, &stubRunContext{err: assert.AnError}, &stubFindingStore{})
	_, err := h.GetMissionRunHistory(acmeCtx())
	require.Error(t, err)
}

// TestKnowledgeHandlers_AllRejectUnknownMission covers the getHarness refusal on
// every handler: a caller cannot reach another mission's knowledge by naming it.
func TestKnowledgeHandlers_AllRejectUnknownMission(t *testing.T) {
	svc, _ := knowledgeService(t, &stubQuerier{})
	s := &harnesspb.ContextInfo{MissionId: types.NewID().String(), AgentName: "recon-agent"}
	ctx := acmeCtx()

	calls := map[string]func() error{
		"FindSimilarAttacks": func() error {
			_, err := svc.FindSimilarAttacks(ctx, &harnesspb.FindSimilarAttacksRequest{Context: s})
			return err
		},
		"GetAttackChains": func() error {
			_, err := svc.GetAttackChains(ctx, &harnesspb.GetAttackChainsRequest{Context: s})
			return err
		},
		"FindSimilarFindings": func() error {
			_, err := svc.FindSimilarFindings(ctx, &harnesspb.FindSimilarFindingsRequest{Context: s})
			return err
		},
		"GetRelatedFindings": func() error {
			_, err := svc.GetRelatedFindings(ctx, &harnesspb.GetRelatedFindingsRequest{Context: s})
			return err
		},
		"GetRunFindings": func() error {
			_, err := svc.GetRunFindings(ctx, &harnesspb.GetRunFindingsRequest{Context: s})
			return err
		},
	}
	for name, call := range calls {
		require.Error(t, call(), "%s must refuse a mission this daemon is not running", name)
	}
}

// TestMiddlewareHarness_KnowledgeForwardsErrors: the decorator is a passthrough
// for knowledge reads — it wraps behaviour, and a read that only leaves the
// process has none to wrap — but a failure must still arrive matchable. Wrapping
// that lost errors.Is would make ErrKnowledgeUnavailable undetectable behind any
// middleware, which is exactly where a caller stops being able to tell "could
// not read" from "nothing found".
func TestMiddlewareHarness_KnowledgeForwardsErrors(t *testing.T) {
	h := NewMiddlewareHarness(&noopInnerHarness{}, nil)
	ctx := context.Background()

	checks := map[string]func() error{
		"GetRunFindings": func() error {
			_, err := h.GetRunFindings(ctx, harnesspb.RunScope_RUN_SCOPE_ALL, FindingFilter{})
			return err
		},
		"QueryNodes":          func() error { _, err := h.QueryNodes(ctx, nil); return err },
		"FindSimilarAttacks":  func() error { _, err := h.FindSimilarAttacks(ctx, "x", 1); return err },
		"GetAttackChains":     func() error { _, err := h.GetAttackChains(ctx, "T1", 1); return err },
		"FindSimilarFindings": func() error { _, err := h.FindSimilarFindings(ctx, "f", 1); return err },
		"GetRelatedFindings":  func() error { _, err := h.GetRelatedFindings(ctx, "f"); return err },
		"ApplicationFindings": func() error {
			_, err := h.ApplicationFindings(ctx, "customer-portal", nil, 10)
			return err
		},
	}
	for name, call := range checks {
		err := call()
		require.Error(t, err, "%s must surface the inner failure", name)
		require.ErrorIs(t, err, ErrKnowledgeUnavailable,
			"%s must stay matchable through the decorator", name)
	}
}

// TestDefaultAgentHarness_QueryNodesPropagatesQuerierErrors covers the wrap on
// the direct querier call: a graph failure is reported, not swallowed into an
// empty result set.
func TestDefaultAgentHarness_QueryNodesPropagatesQuerierErrors(t *testing.T) {
	h := knowledgeHarness(t, &stubQuerier{queryErr: assert.AnError})
	_, err := h.QueryNodes(acmeCtx(), &graphragpb.GraphQuery{Text: "x"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query nodes")
}

// ApplicationFindings is the read a lifecycle agent cannot work without
// (gibson#1669). Its failure mode is the one ErrKnowledgeUnavailable exists for:
// an agent that reads "unavailable" as "nothing open" ranks a whole backlog as
// harmless, so an unanswered question must never look like an empty answer.

func TestDefaultAgentHarness_ApplicationFindings_ReturnsTheQuerierPayload(t *testing.T) {
	payload := mustJSON(t, []map[string]any{{"finding_id": "f1", "reachable": true}})
	h := knowledgeHarness(t, &stubQuerier{appFinds: payload})

	got, err := h.ApplicationFindings(acmeCtx(), "customer-portal", []string{"open"}, 50)
	require.NoError(t, err)
	assert.JSONEq(t, string(payload), string(got))
}

func TestDefaultAgentHarness_ApplicationFindings_NoQuerierIsUnavailableNotEmpty(t *testing.T) {
	h := knowledgeHarness(t, nil)

	got, err := h.ApplicationFindings(acmeCtx(), "customer-portal", nil, 50)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrKnowledgeUnavailable)
	assert.Nil(t, got, "an unavailable graph must not answer with rows")
}

func TestDefaultAgentHarness_ApplicationFindings_AQuerierErrorSurfaces(t *testing.T) {
	h := knowledgeHarness(t, &stubQuerier{queryErr: errors.New("neo4j is down")})

	got, err := h.ApplicationFindings(acmeCtx(), "customer-portal", nil, 50)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "neo4j is down")
	assert.Nil(t, got, "a failed read must not answer with rows")
}

func TestDefaultAgentHarness_ApplicationFindings_WithoutATenantTheReadRefuses(t *testing.T) {
	// Tenant comes from the call context, never a payload. Without one there is
	// no graph to read, and guessing one would cross a tenant boundary.
	h := knowledgeHarness(t, &stubQuerier{appFinds: mustJSON(t, []map[string]any{})})

	got, err := h.ApplicationFindings(context.Background(), "customer-portal", nil, 50)
	require.Error(t, err)
	assert.Nil(t, got)
}

// The ApplicationFindings HANDLER, as opposed to the harness method beside it.
// It is the only route a sandboxed agent has to this read — it reaches gibson
// through the callback service and nothing else — so the wire mapping is worth
// pinning directly rather than inferring from the harness tests.

func TestCallbackApplicationFindings_MapsEveryFieldOntoTheWire(t *testing.T) {
	svc, cinfo := knowledgeService(t, &stubQuerier{appFinds: mustJSON(t, []map[string]any{{
		"finding_id":       "f1",
		"status":           "open",
		"severity":         "critical",
		"vulnerability_id": "CVE-2025-1234",
		"place_label":      "Package",
		"place_key":        "npm:lodash@4.17.20",
		"reachable":        true,
		"exposed":          true,
		"deployment_key":   "customer-portal/prod",
		"image_key":        "sha256:abc",
	}})})

	resp, err := svc.ApplicationFindings(acmeCtx(), &harnesspb.ApplicationFindingsRequest{
		Context: cinfo, Application: "customer-portal", Statuses: []string{"open"}, Limit: 50,
	})
	require.NoError(t, err)
	require.Len(t, resp.GetFindings(), 1)

	got := resp.GetFindings()[0]
	assert.Equal(t, "f1", got.GetFindingId())
	assert.Equal(t, "open", got.GetStatus())
	assert.Equal(t, "critical", got.GetSeverity())
	assert.Equal(t, "CVE-2025-1234", got.GetVulnerabilityId())
	assert.Equal(t, "Package", got.GetPlaceLabel())
	assert.Equal(t, "npm:lodash@4.17.20", got.GetPlaceKey())
	assert.True(t, got.GetReachable())
	assert.True(t, got.GetExposed())
	assert.Equal(t, "customer-portal/prod", got.GetDeploymentKey())
	assert.Equal(t, "sha256:abc", got.GetImageKey())
}

func TestCallbackApplicationFindings_NothingOpenIsAnEmptyListNotAFailure(t *testing.T) {
	// An Application with nothing open is a real answer. It must not arrive as
	// an error, and it must not arrive as nil — a caller distinguishing "clean"
	// from "could not look" is the entire point of this read.
	svc, cinfo := knowledgeService(t, &stubQuerier{appFinds: mustJSON(t, []map[string]any{})})

	resp, err := svc.ApplicationFindings(acmeCtx(), &harnesspb.ApplicationFindingsRequest{
		Context: cinfo, Application: "customer-portal",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp.GetFindings())
	assert.Empty(t, resp.GetFindings())
}

func TestCallbackApplicationFindings_AnUnavailableGraphIsAnError(t *testing.T) {
	svc, cinfo := knowledgeService(t, nil)

	resp, err := svc.ApplicationFindings(acmeCtx(), &harnesspb.ApplicationFindingsRequest{
		Context: cinfo, Application: "customer-portal",
	})
	require.Error(t, err)
	assert.Nil(t, resp, "an unavailable graph must not answer with findings")
}

func TestApplicationFindingsToProto_UndecodableAnswerIsReportedNotSwallowed(t *testing.T) {
	// If the harness ever answers with something that is not the agreed shape,
	// that is a defect to surface. Returning an empty list would look to a
	// triage pass exactly like an Application with nothing wrong with it.
	got, err := applicationFindingsToProto([]byte("{not json"))
	require.Error(t, err)
	assert.Nil(t, got)

	// An absent answer is not the same as a malformed one: no bytes is an empty
	// list, which is what a querier returns for an Application it found nothing on.
	empty, err := applicationFindingsToProto(nil)
	require.NoError(t, err)
	assert.NotNil(t, empty)
	assert.Empty(t, empty)
}

func TestCallbackApplicationFindings_AFailedReadIsReportedNotEmptied(t *testing.T) {
	// The two ways this handler can fail after the harness resolves: the read
	// itself errors, or it answers with something that will not decode. Both
	// must surface. An empty list would tell a triage pass the Application is
	// clean, which is the one wrong answer this read exists to prevent.
	for _, tc := range []struct {
		name string
		stub *stubQuerier
	}{
		{"the read fails", &stubQuerier{queryErr: errors.New("neo4j is down")}},
		{"the answer will not decode", &stubQuerier{appFinds: []byte("{not json")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, cinfo := knowledgeService(t, tc.stub)

			resp, err := svc.ApplicationFindings(acmeCtx(), &harnesspb.ApplicationFindingsRequest{
				Context: cinfo, Application: "customer-portal",
			})
			require.Error(t, err)
			assert.Nil(t, resp, "a failed read must not answer with findings")
		})
	}
}

// TestApplicationFindingsToProto_CarriesThePriorityTriple pins the three states
// the triple has to stay distinguishable in (gibson#1684, SDK v0.175.0).
//
// The two failure modes are both silent. Substituting a default for an unranked
// Finding makes it look ranked, so the rule that keeps a previous priority when
// EPSS or KEV is unavailable keeps a value nobody decided and that Finding is
// never triaged. Dropping a ranking that arrived without a sentence lets a model
// outage erase decisions a rule table computed without a model at all.
func TestApplicationFindingsToProto_CarriesThePriorityTriple(t *testing.T) {
	raw := []byte(`[
	  {"finding_id":"unranked","status":"open"},
	  {"finding_id":"ranked-unexplained","status":"open","priority":"P1","priority_rule":"R01"},
	  {"finding_id":"fully-ranked","status":"open","priority":"P2","priority_rule":"R04","priority_reason":"reachable and exposed"}
	]`)

	got, err := applicationFindingsToProto(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 findings, got %d", len(got))
	}
	byID := map[string]int{}
	for i, f := range got {
		byID[f.GetFindingId()] = i
	}

	unranked := got[byID["unranked"]]
	if unranked.GetPriority() != "" || unranked.GetPriorityRule() != "" || unranked.GetPriorityReason() != "" {
		t.Errorf("an unranked Finding must stay empty on the wire, got priority=%q rule=%q reason=%q; a default here is indistinguishable from a ranking somebody made",
			unranked.GetPriority(), unranked.GetPriorityRule(), unranked.GetPriorityReason())
	}

	partial := got[byID["ranked-unexplained"]]
	if partial.GetPriority() != "P1" || partial.GetPriorityRule() != "R01" {
		t.Errorf("a ranked Finding must keep its ranking without a reason, got priority=%q rule=%q",
			partial.GetPriority(), partial.GetPriorityRule())
	}
	if partial.GetPriorityReason() != "" {
		t.Errorf("an absent reason must stay absent, got %q", partial.GetPriorityReason())
	}

	full := got[byID["fully-ranked"]]
	if full.GetPriority() != "P2" || full.GetPriorityRule() != "R04" || full.GetPriorityReason() != "reachable and exposed" {
		t.Errorf("the full triple did not survive: priority=%q rule=%q reason=%q",
			full.GetPriority(), full.GetPriorityRule(), full.GetPriorityReason())
	}
}
