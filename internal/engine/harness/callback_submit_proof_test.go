// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/settlement"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"github.com/zeroroot-ai/sdk/codegen/workspace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// submitProofMockHarness is an AgentHarness stub carrying the one server-side
// fact SubmitProof reads besides tenant: the mission id / tenant, mirroring
// placeBetMockHarness (callback_place_bet_test.go). Target is left at its
// embedded zero value: SubmitProof tolerates an empty ScopeID (unlike
// Observe's observationAttribution, a bet is not identified by (ScopeID,
// Address)).
type submitProofMockHarness struct {
	DefaultAgentHarness
	missionID types.ID
	tenantID  string
}

func (m *submitProofMockHarness) Mission() MissionContext {
	return MissionContext{ID: m.missionID, TenantID: m.tenantID}
}

func (m *submitProofMockHarness) Workspace() workspace.Workspace { return nil }
func (m *submitProofMockHarness) Workspaces() map[string]workspace.Workspace {
	return map[string]workspace.Workspace{}
}

// testProofSettlementEngine is a minimal brain.ProofSettlementEngine backed by
// a real *brain.Engine (so SettleBetTrue exercises real Timeline-fold
// behavior, not a fake) and a plain predicate-name -> CEL-expression map
// standing in for a tenant's enabled Domain Packs.
type testProofSettlementEngine struct {
	engine     *brain.Engine
	tenant     string
	predicates map[string]string
}

func newTestProofSettlementEngine(t *testing.T, tenant string, predicates map[string]string) *testProofSettlementEngine {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &testProofSettlementEngine{
		engine:     brain.NewRegistry(ctx).For(tenant),
		tenant:     tenant,
		predicates: predicates,
	}
}

func (e *testProofSettlementEngine) DomainPackPredicate(_ context.Context, predicateName string) (expr string, ok bool, err error) {
	expr, ok = e.predicates[predicateName]
	return expr, ok, nil
}

// SettleBetTrue mirrors tenantRoutedProofSettlement.SettleBetTrue's ADR-0132
// wiring (proof_settlement_adapter.go): when the caller (the SubmitProof
// handler) leaves authorize nil for a destructive request, the real tenant
// routing wires in that tenant's own DestructiveAuthorizationQueue.Verify.
// This fake does the same, so a SubmitProof test that requests and decides
// authorization through e.engine.DestructiveAuthorizationQueue() exercises
// the exact verification path production uses.
func (e *testProofSettlementEngine) SettleBetTrue(
	ctx context.Context, registry *settlement.Registry, authorize brain.DestructiveProofAuthorizer, req brain.BetSettlementRequest,
) (bool, error) {
	if req.Destructive && authorize == nil {
		authorize = e.engine.DestructiveAuthorizationQueue().Verify
	}
	settled, err := e.engine.SettleBetTrue(ctx, registry, authorize, req)
	if err != nil {
		return settled, fmt.Errorf("settle bet true: %w", err)
	}
	return settled, nil
}

// RequestDestructiveAuthorization mirrors
// tenantRoutedProofSettlement.RequestDestructiveAuthorization: enqueue
// against the SAME engine's DestructiveAuthorizationQueue that SettleBetTrue
// above verifies against, so a test can Request+Decide and then observe
// SubmitProof settle.
func (e *testProofSettlementEngine) RequestDestructiveAuthorization(
	_ context.Context, req brain.DestructiveAuthorizationRequest,
) (string, error) {
	id, err := e.engine.DestructiveAuthorizationQueue().Request(e.tenant, req)
	if err != nil {
		return "", fmt.Errorf("request destructive authorization: %w", err)
	}
	return id, nil
}

var _ brain.ProofSettlementEngine = (*testProofSettlementEngine)(nil)

// newSubmitProofService wires a HarnessCallbackService for SubmitProof
// tests, mirroring newPlaceBetService. Either dependency may be nil to
// exercise the not-wired path.
func newSubmitProofService(
	t *testing.T, h *submitProofMockHarness, agentName string, substrate brain.BeliefSubstrate, engine brain.ProofSettlementEngine,
) *HarnessCallbackService {
	t.Helper()
	registry := NewCallbackHarnessRegistry()
	registry.Register(h.missionID.String(), agentName, h)
	var opts []CallbackServiceOption
	if substrate != nil {
		opts = append(opts, WithBeliefSubstrate(substrate))
	}
	if engine != nil {
		opts = append(opts, WithProofSettlement(engine))
	}
	return NewHarnessCallbackServiceWithRegistry(slog.New(slog.DiscardHandler), registry, opts...)
}

func submitProofRequest(missionID, agentName, hypothesisID, technique, predicateName string, destructive bool, evidence ...*typespb.Evidence) *harnesspb.SubmitProofRequest {
	return &harnesspb.SubmitProofRequest{
		Context:       &harnesspb.ContextInfo{MissionId: missionID, AgentName: agentName},
		HypothesisId:  hypothesisID,
		Technique:     technique,
		PredicateName: predicateName,
		Evidence:      evidence,
		Destructive:   destructive,
	}
}

func awaitProofSettlements(t *testing.T, e *brain.Engine, want int) []brain.BetSettlementSnapshot {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var got []brain.BetSettlementSnapshot
	for time.Now().Before(deadline) {
		got = e.BetSettlements()
		if len(got) == want {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("want %d settlements, got %d: %+v", want, len(got), got)
	return nil
}

// TestSubmitProof_NotWired_Unavailable proves SubmitProof degrades the same
// way PlaceBet does when its dependency was never wired (staged-wiring
// default, ADR-0003: no graceful-nil in the request path, an explicit
// Unavailable instead).
func TestSubmitProof_NotWired_Unavailable(t *testing.T) {
	h := &submitProofMockHarness{missionID: "mission-A", tenantID: "acme"}
	svc := newSubmitProofService(t, h, "recon-agent", nil, nil)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	resp, err := svc.SubmitProof(ctx, submitProofRequest("mission-A", "recon-agent", "hyp-1", "T1190", "T1190", false))
	require.Nil(t, resp)
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

// TestSubmitProof_MissingFields_InvalidArgument proves each required field is
// checked independently of protovalidate (defense in depth, mirroring
// PlaceBet's validateBet).
func TestSubmitProof_MissingFields_InvalidArgument(t *testing.T) {
	h := &submitProofMockHarness{missionID: "mission-A", tenantID: "acme"}
	engine := newTestProofSettlementEngine(t, "acme", map[string]string{"T1190": `true`})
	svc := newSubmitProofService(t, h, "recon-agent", newFakeBeliefSubstrate(), engine)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	tests := []struct {
		name          string
		hypothesisID  string
		technique     string
		predicateName string
	}{
		{"empty hypothesis id", "", "T1190", "T1190"},
		{"empty technique", "hyp-1", "", "T1190"},
		{"empty predicate name", "hyp-1", "T1190", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.SubmitProof(ctx, submitProofRequest("mission-A", "recon-agent", tt.hypothesisID, tt.technique, tt.predicateName, false))
			require.Nil(t, resp)
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

// TestSubmitProof_UnknownPredicate_FailsClosed proves an unenabled-pack or
// unknown-predicate name fails closed in-band (ADR-0131), never settling and
// never reporting a gRPC-level error (the RPC itself is well-formed).
func TestSubmitProof_UnknownPredicate_FailsClosed(t *testing.T) {
	h := &submitProofMockHarness{missionID: "mission-A", tenantID: "acme"}
	engine := newTestProofSettlementEngine(t, "acme", map[string]string{ /* nothing enabled */ })
	svc := newSubmitProofService(t, h, "recon-agent", newFakeBeliefSubstrate(), engine)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	resp, err := svc.SubmitProof(ctx, submitProofRequest("mission-A", "recon-agent", "hyp-1", "T1190", "T1190", false))
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.GetError())
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_NOT_FOUND, resp.GetError().GetCode())
	assert.Equal(t, harnesspb.SettlementOutcome_SETTLEMENT_OUTCOME_UNSPECIFIED, resp.GetOutcome())
	assert.Empty(t, engine.engine.BetSettlements())
}

// TestSubmitProof_Destructive_ReturnsPendingAuthorization proves a
// destructive proof with no recorded authorization decision at all reports
// PENDING_AUTHORIZATION and never settles (ADR-0132): SettleBetTrue's
// verification refuses before the predicate ever evaluates.
func TestSubmitProof_Destructive_ReturnsPendingAuthorization(t *testing.T) {
	h := &submitProofMockHarness{missionID: "mission-A", tenantID: "acme"}
	engine := newTestProofSettlementEngine(t, "acme", map[string]string{"T1190": `markerPresent(evidence, "tok")`})
	substrate := newFakeBeliefSubstrate()
	require.NoError(t, substrate.SetBelief(context.Background(), claimNodeRef("acme", "hyp-1"), brain.NodeBelief{Belief: brain.Belief{Exploitable: 0.6}}))
	svc := newSubmitProofService(t, h, "recon-agent", substrate, engine)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	evidence := &typespb.Evidence{Type: typespb.EvidenceType_EVIDENCE_TYPE_LOG, Title: "proof", Content: "tok observed"}
	resp, err := svc.SubmitProof(ctx, submitProofRequest("mission-A", "recon-agent", "hyp-1", "T1190", "T1190", true, evidence))
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Nil(t, resp.GetError())
	assert.Equal(t, harnesspb.SettlementOutcome_SETTLEMENT_OUTCOME_PENDING_AUTHORIZATION, resp.GetOutcome())
	assert.Empty(t, engine.engine.BetSettlements(), "a destructive proof must never settle synchronously")
}

// awaitDestructivePending polls engine's DestructiveActionSnapshot until
// hypothesisID's request has folded (the async Submit->fold path,
// ADR-0101), or fails the test after 2s. Decide requires the request to have
// already landed, so a Request immediately followed by Decide must wait here
// first to avoid racing the fold.
func awaitDestructivePending(t *testing.T, e *brain.Engine, hypothesisID string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, a := range e.DestructiveActionSnapshot() {
			if a.HypothesisID == hypothesisID {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("destructive action %q was not recorded within the deadline", hypothesisID)
}

// awaitDestructiveDecided polls engine's DestructiveActionSnapshot until
// hypothesisID shows Decided=true (the async Submit->fold path, ADR-0101),
// or fails the test after 2s. Mirrors brain's own private test helper of the
// same shape (destructive_authz_test.go), reimplemented here since it is
// unexported across packages.
func awaitDestructiveDecided(t *testing.T, e *brain.Engine, hypothesisID string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, a := range e.DestructiveActionSnapshot() {
			if a.HypothesisID == hypothesisID && a.Decided {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("destructive action %q was not decided within the deadline", hypothesisID)
}

// TestSubmitProof_DestructiveApproved_SettlesTrue proves the ADR-0132
// end-to-end path this file exists for: once a human approves a hypothesis's
// destructive authorization request (RequestDestructiveAuthorization +
// Decide, both reading/writing the same DestructiveAuthorizationQueue
// SettleBetTrue's authorizer verifies), a subsequent SubmitProof whose
// evidence satisfies the predicate settles the bet true — the same as any
// non-destructive proof, once authorized.
func TestSubmitProof_DestructiveApproved_SettlesTrue(t *testing.T) {
	h := &submitProofMockHarness{missionID: "mission-A", tenantID: "acme"}
	engine := newTestProofSettlementEngine(t, "acme", map[string]string{
		"T1190": `markerPresent(evidence, "proof-token-9f3a")`,
	})
	substrate := newFakeBeliefSubstrate()
	require.NoError(t, substrate.SetBelief(context.Background(), claimNodeRef("acme", "hyp-1"), brain.NodeBelief{Belief: brain.Belief{Exploitable: 0.8}}))
	svc := newSubmitProofService(t, h, "recon-agent", substrate, engine)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	// The agent asks BEFORE performing the destructive act (ADR-0132),
	// a human approves, and only then does the agent submit the
	// proof of having performed it.
	_, err := engine.RequestDestructiveAuthorization(ctx, brain.DestructiveAuthorizationRequest{
		HypothesisID: "hyp-1", Technique: "T1190", PredicateType: "T1190",
	})
	require.NoError(t, err)
	awaitDestructivePending(t, engine.engine, "hyp-1")
	require.NoError(t, engine.engine.DestructiveAuthorizationQueue().Decide("hyp-1", "reviewer-1", true))
	awaitDestructiveDecided(t, engine.engine, "hyp-1")

	evidence := &typespb.Evidence{
		Type:    typespb.EvidenceType_EVIDENCE_TYPE_RESPONSE,
		Title:   "destructive demonstration",
		Content: "HTTP/1.1 200 OK\nproof-token-9f3a\n",
	}
	resp, err := svc.SubmitProof(ctx, submitProofRequest("mission-A", "recon-agent", "hyp-1", "T1190", "T1190", true, evidence))
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Nil(t, resp.GetError())
	assert.Equal(t, harnesspb.SettlementOutcome_SETTLEMENT_OUTCOME_SETTLED_TRUE, resp.GetOutcome())

	got := awaitProofSettlements(t, engine.engine, 1)
	assert.Equal(t, "hyp-1", got[0].HypothesisID)
	assert.Equal(t, brain.SettlementVerdictTrue, got[0].Verdict)
	assert.InDelta(t, 0.8, got[0].PredictedProbability, 1e-9)
}

// TestSubmitProof_DestructiveDenied_PermissionDenied proves a destructive
// proof for a hypothesis whose authorization was explicitly denied is
// reported in-band as a terminal failure — never PENDING_AUTHORIZATION
// (which would wrongly imply retrying could still succeed) and never
// settled.
func TestSubmitProof_DestructiveDenied_PermissionDenied(t *testing.T) {
	h := &submitProofMockHarness{missionID: "mission-A", tenantID: "acme"}
	engine := newTestProofSettlementEngine(t, "acme", map[string]string{
		"T1190": `markerPresent(evidence, "proof-token-9f3a")`,
	})
	substrate := newFakeBeliefSubstrate()
	require.NoError(t, substrate.SetBelief(context.Background(), claimNodeRef("acme", "hyp-1"), brain.NodeBelief{Belief: brain.Belief{Exploitable: 0.8}}))
	svc := newSubmitProofService(t, h, "recon-agent", substrate, engine)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	_, err := engine.RequestDestructiveAuthorization(ctx, brain.DestructiveAuthorizationRequest{
		HypothesisID: "hyp-1", Technique: "T1190", PredicateType: "T1190",
	})
	require.NoError(t, err)
	awaitDestructivePending(t, engine.engine, "hyp-1")
	require.NoError(t, engine.engine.DestructiveAuthorizationQueue().Decide("hyp-1", "reviewer-1", false))
	awaitDestructiveDecided(t, engine.engine, "hyp-1")

	evidence := &typespb.Evidence{
		Type:    typespb.EvidenceType_EVIDENCE_TYPE_RESPONSE,
		Title:   "destructive demonstration",
		Content: "HTTP/1.1 200 OK\nproof-token-9f3a\n",
	}
	resp, err := svc.SubmitProof(ctx, submitProofRequest("mission-A", "recon-agent", "hyp-1", "T1190", "T1190", true, evidence))
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.GetError())
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, resp.GetError().GetCode())
	assert.Equal(t, harnesspb.SettlementOutcome_SETTLEMENT_OUTCOME_UNSPECIFIED, resp.GetOutcome())
	assert.Empty(t, engine.engine.BetSettlements())
}

// TestSubmitProof_PredicateFires_SettlesTrue proves the full non-destructive
// path (ADR-0131): a pack CEL predicate evaluated over the raw
// evidence the agent posted fires true, and Engine.SettleBetTrue folds
// BetSettledTrue for real (this exercises the actual Timeline, not a mock).
func TestSubmitProof_PredicateFires_SettlesTrue(t *testing.T) {
	h := &submitProofMockHarness{missionID: "mission-A", tenantID: "acme"}
	engine := newTestProofSettlementEngine(t, "acme", map[string]string{
		"T1190": `markerPresent(evidence, "proof-token-9f3a")`,
	})
	substrate := newFakeBeliefSubstrate()
	require.NoError(t, substrate.SetBelief(context.Background(), claimNodeRef("acme", "hyp-1"), brain.NodeBelief{Belief: brain.Belief{Exploitable: 0.75}}))
	svc := newSubmitProofService(t, h, "recon-agent", substrate, engine)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	evidence := &typespb.Evidence{
		Type:    typespb.EvidenceType_EVIDENCE_TYPE_RESPONSE,
		Title:   "unauthenticated admin panel",
		Content: "HTTP/1.1 200 OK\nproof-token-9f3a\n",
	}
	resp, err := svc.SubmitProof(ctx, submitProofRequest("mission-A", "recon-agent", "hyp-1", "T1190", "T1190", false, evidence))
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Nil(t, resp.GetError())
	assert.Equal(t, "hyp-1", resp.GetHypothesisId())
	assert.Equal(t, harnesspb.SettlementOutcome_SETTLEMENT_OUTCOME_SETTLED_TRUE, resp.GetOutcome())

	got := awaitProofSettlements(t, engine.engine, 1)
	assert.Equal(t, "hyp-1", got[0].HypothesisID)
	assert.Equal(t, brain.SettlementVerdictTrue, got[0].Verdict)
	assert.Equal(t, brain.SettlementMethodPredicate, got[0].Method)
	assert.InDelta(t, 0.75, got[0].PredictedProbability, 1e-9)
}

// TestSubmitProof_PredicateDoesNotFire_NotSettled proves an unproven claim
// stays open: raw evidence that does not satisfy the predicate never settles
// the bet, whatever confidence was staked.
func TestSubmitProof_PredicateDoesNotFire_NotSettled(t *testing.T) {
	h := &submitProofMockHarness{missionID: "mission-A", tenantID: "acme"}
	engine := newTestProofSettlementEngine(t, "acme", map[string]string{
		"T1190": `markerPresent(evidence, "proof-token-9f3a")`,
	})
	substrate := newFakeBeliefSubstrate()
	require.NoError(t, substrate.SetBelief(context.Background(), claimNodeRef("acme", "hyp-1"), brain.NodeBelief{Belief: brain.Belief{Exploitable: 0.75}}))
	svc := newSubmitProofService(t, h, "recon-agent", substrate, engine)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	evidence := &typespb.Evidence{Type: typespb.EvidenceType_EVIDENCE_TYPE_RESPONSE, Title: "no proof", Content: "HTTP/1.1 403 Forbidden"}
	resp, err := svc.SubmitProof(ctx, submitProofRequest("mission-A", "recon-agent", "hyp-1", "T1190", "T1190", false, evidence))
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Nil(t, resp.GetError())
	assert.Equal(t, harnesspb.SettlementOutcome_SETTLEMENT_OUTCOME_NOT_SETTLED, resp.GetOutcome())
	assert.Empty(t, engine.engine.BetSettlements())
}

// TestSubmitProof_NoStakedBet_FailsClosed proves a proof for a hypothesis
// nobody ever placed a bet on is refused in-band rather than settling with a
// fabricated confidence.
func TestSubmitProof_NoStakedBet_FailsClosed(t *testing.T) {
	h := &submitProofMockHarness{missionID: "mission-A", tenantID: "acme"}
	engine := newTestProofSettlementEngine(t, "acme", map[string]string{
		"T1190": `markerPresent(evidence, "tok")`,
	})
	svc := newSubmitProofService(t, h, "recon-agent", newFakeBeliefSubstrate(), engine)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	evidence := &typespb.Evidence{Type: typespb.EvidenceType_EVIDENCE_TYPE_LOG, Content: "tok"}
	resp, err := svc.SubmitProof(ctx, submitProofRequest("mission-A", "recon-agent", "hyp-never-staked", "T1190", "T1190", false, evidence))
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.GetError())
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_NOT_FOUND, resp.GetError().GetCode())
	assert.Equal(t, harnesspb.SettlementOutcome_SETTLEMENT_OUTCOME_UNSPECIFIED, resp.GetOutcome())
	assert.Empty(t, engine.engine.BetSettlements())
}

// TestSubmitProof_PredicateDoesNotCompile_FailsClosed proves a pack predicate
// that is well-formed text but not valid CEL against the gibson-owned
// environment (ADR-0131) is refused in-band rather than crashing the RPC.
func TestSubmitProof_PredicateDoesNotCompile_FailsClosed(t *testing.T) {
	h := &submitProofMockHarness{missionID: "mission-A", tenantID: "acme"}
	engine := newTestProofSettlementEngine(t, "acme", map[string]string{
		"T1190": `evidence.thisFunctionDoesNotExist()`,
	})
	substrate := newFakeBeliefSubstrate()
	require.NoError(t, substrate.SetBelief(context.Background(), claimNodeRef("acme", "hyp-1"), brain.NodeBelief{Belief: brain.Belief{Exploitable: 0.5}}))
	svc := newSubmitProofService(t, h, "recon-agent", substrate, engine)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	resp, err := svc.SubmitProof(ctx, submitProofRequest("mission-A", "recon-agent", "hyp-1", "T1190", "T1190", false))
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.GetError())
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_INTERNAL, resp.GetError().GetCode())
	assert.Equal(t, harnesspb.SettlementOutcome_SETTLEMENT_OUTCOME_UNSPECIFIED, resp.GetOutcome())
}
