// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
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
	predicates map[string]string
}

func newTestProofSettlementEngine(t *testing.T, tenant string, predicates map[string]string) *testProofSettlementEngine {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &testProofSettlementEngine{
		engine:     brain.NewRegistry(ctx).For(tenant),
		predicates: predicates,
	}
}

func (e *testProofSettlementEngine) DomainPackPredicate(_ context.Context, predicateName string) (string, bool, error) {
	expr, ok := e.predicates[predicateName]
	return expr, ok, nil
}

func (e *testProofSettlementEngine) SettleBetTrue(
	ctx context.Context, registry *settlement.Registry, authorize brain.DestructiveProofAuthorizer, req brain.BetSettlementRequest,
) (bool, error) {
	return e.engine.SettleBetTrue(ctx, registry, authorize, req)
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
// unknown-predicate name fails closed in-band (ADR-0030), never settling and
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

// TestSubmitProof_Destructive_ReturnsPendingAuthorization proves a destructive
// proof never evaluates or settles (gibson#390 builds the real gate); it
// reports PENDING_AUTHORIZATION once the named predicate is confirmed real.
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

// TestSubmitProof_PredicateFires_SettlesTrue proves the full non-destructive
// path (ADR-0030, ADR-0031): a pack CEL predicate evaluated over the raw
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
// environment (ADR-0031) is refused in-band rather than crashing the RPC.
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
