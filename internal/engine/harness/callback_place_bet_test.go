// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"github.com/zeroroot-ai/sdk/codegen/workspace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// placeBetMockHarness is an AgentHarness stub carrying the one server-side
// fact PlaceBet reads: the mission's tenant (via getHarness's tenant-mismatch
// guard, shared with Observe).
type placeBetMockHarness struct {
	DefaultAgentHarness
	missionID types.ID
	tenantID  string
}

func (m *placeBetMockHarness) Mission() MissionContext {
	return MissionContext{ID: m.missionID, TenantID: m.tenantID}
}

func (m *placeBetMockHarness) Workspace() workspace.Workspace { return nil }
func (m *placeBetMockHarness) Workspaces() map[string]workspace.Workspace {
	return map[string]workspace.Workspace{}
}

// fakeBeliefSubstrate is a minimal, in-memory brain.BeliefSubstrate used only
// to prove PlaceBet's write path; it is not the production implementation
// (see callback_place_bet.go's package doc).
type fakeBeliefSubstrate struct {
	mu      sync.Mutex
	beliefs map[brain.NodeRef]brain.NodeBelief
	setErr  error
	lastCtx context.Context //nolint:containedctx // captured only for test assertion, never used to make a call
}

func newFakeBeliefSubstrate() *fakeBeliefSubstrate {
	return &fakeBeliefSubstrate{beliefs: make(map[brain.NodeRef]brain.NodeBelief)}
}

func (f *fakeBeliefSubstrate) Belief(_ context.Context, ref brain.NodeRef) (brain.NodeBelief, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	nb, ok := f.beliefs[ref]
	return nb, ok, nil
}

func (f *fakeBeliefSubstrate) SetBelief(ctx context.Context, ref brain.NodeRef, nb brain.NodeBelief) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastCtx = ctx
	if f.setErr != nil {
		return f.setErr
	}
	f.beliefs[ref] = nb
	return nil
}

var _ brain.BeliefSubstrate = (*fakeBeliefSubstrate)(nil)

// newPlaceBetService registers h under (h.missionID, agentName) and returns a
// service wired to substrate (which may be nil to test the unwired path).
func newPlaceBetService(t *testing.T, h *placeBetMockHarness, agentName string, substrate brain.BeliefSubstrate) *HarnessCallbackService {
	t.Helper()
	registry := NewCallbackHarnessRegistry()
	registry.Register(h.missionID.String(), agentName, h)
	opts := []CallbackServiceOption{}
	if substrate != nil {
		opts = append(opts, WithBeliefSubstrate(substrate))
	}
	return NewHarnessCallbackServiceWithRegistry(slog.New(slog.DiscardHandler), registry, opts...)
}

func placeBetRequest(missionID, agentName, hypothesisID, stakingAgent string, confidence float64, technique string) *harnesspb.PlaceBetRequest {
	return &harnesspb.PlaceBetRequest{
		Context: &harnesspb.ContextInfo{MissionId: missionID, AgentName: agentName},
		Bet: &harnesspb.Bet{
			HypothesisId: hypothesisID,
			StakingAgent: stakingAgent,
			Confidence:   confidence,
			Technique:    technique,
		},
	}
}

// TestPlaceBet_Success proves a well-formed bet is persisted as belief on its
// hypothesis's tenant-scoped claim-node (ADR-0122, ADR-0129), and that
// placing the identical bet twice writes the identical belief both times
// (SetBelief's exact-overwrite contract, and PlaceBet's own determinism).
func TestPlaceBet_Success(t *testing.T) {
	h := &placeBetMockHarness{missionID: "mission-A", tenantID: "acme"}
	substrate := newFakeBeliefSubstrate()
	svc := newPlaceBetService(t, h, "recon-agent", substrate)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	req := placeBetRequest("mission-A", "recon-agent", "hyp-1", "recon-agent", 0.82, "T1190")

	resp, err := svc.PlaceBet(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Nil(t, resp.Error)

	ref := brain.NodeRef{Kind: brain.NodeKindClaim, ID: "acme/hyp-1"}
	nb, ok, berr := substrate.Belief(ctx, ref)
	require.NoError(t, berr)
	require.True(t, ok, "belief must be recorded under the tenant-scoped claim ref")
	assert.InDelta(t, 0.82, nb.Belief.Exploitable, 1e-9, "confidence is recorded as P(claim valid)")
	assert.Equal(t, betConfidenceModelTag, nb.Belief.Model)
	assert.NotEmpty(t, nb.EvidenceDigest)

	// Same bet again -> identical belief (deterministic, exact overwrite).
	resp2, err := svc.PlaceBet(ctx, req)
	require.NoError(t, err)
	require.Nil(t, resp2.Error)
	nb2, ok, berr := substrate.Belief(ctx, ref)
	require.NoError(t, berr)
	require.True(t, ok)
	assert.Equal(t, nb, nb2, "an identical bet must reproduce an identical belief write")
}

// TestPlaceBet_SubstrateContextCarriesTheValidatedTenant proves the ctx
// PlaceBet passes to beliefSubstrate.SetBelief carries a tenant readable via
// auth.TenantFromContext — the same mechanism world_service.go's engine(ctx)
// uses. A daemon-supplied BeliefSubstrate is one field shared across every
// tenant's PlaceBet calls, so it needs this to route a call to the right
// tenant's own belief store. PlaceBet itself does no tenant derivation for
// this: getHarness (called above) already required ctx to carry a tenant and
// validated it equals the mission's own tenant, so the same ctx flows
// through unchanged — this test pins that flow-through, not a new stamp.
func TestPlaceBet_SubstrateContextCarriesTheValidatedTenant(t *testing.T) {
	h := &placeBetMockHarness{missionID: "mission-A", tenantID: "acme"}
	substrate := newFakeBeliefSubstrate()
	svc := newPlaceBetService(t, h, "recon-agent", substrate)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	_, err := svc.PlaceBet(ctx, placeBetRequest("mission-A", "recon-agent", "hyp-1", "recon-agent", 0.7, "T1190"))
	require.NoError(t, err)

	require.NotNil(t, substrate.lastCtx, "SetBelief must have been called")
	got, ok := auth.TenantFromContext(substrate.lastCtx)
	require.True(t, ok, "substrate ctx must carry a tenant")
	assert.Equal(t, "acme", got.String())
}

// TestPlaceBet_TenantScopesTheClaimNode proves two tenants proposing a
// hypothesis with the same id land on two distinct claim-nodes, never one.
func TestPlaceBet_TenantScopesTheClaimNode(t *testing.T) {
	substrate := newFakeBeliefSubstrate()

	acme := &placeBetMockHarness{missionID: "mission-A", tenantID: "acme"}
	svcAcme := newPlaceBetService(t, acme, "recon-agent", substrate)
	ctxAcme := auth.ContextWithTenantString(context.Background(), "acme")
	_, err := svcAcme.PlaceBet(ctxAcme, placeBetRequest("mission-A", "recon-agent", "hyp-1", "recon-agent", 0.9, "T1190"))
	require.NoError(t, err)

	globex := &placeBetMockHarness{missionID: "mission-B", tenantID: "globex"}
	svcGlobex := newPlaceBetService(t, globex, "recon-agent", substrate)
	ctxGlobex := auth.ContextWithTenantString(context.Background(), "globex")
	_, err = svcGlobex.PlaceBet(ctxGlobex, placeBetRequest("mission-B", "recon-agent", "hyp-1", "recon-agent", 0.1, "T1190"))
	require.NoError(t, err)

	acmeNb, ok, _ := substrate.Belief(ctxAcme, brain.NodeRef{Kind: brain.NodeKindClaim, ID: "acme/hyp-1"})
	require.True(t, ok)
	globexNb, ok, _ := substrate.Belief(ctxGlobex, brain.NodeRef{Kind: brain.NodeKindClaim, ID: "globex/hyp-1"})
	require.True(t, ok)

	assert.InDelta(t, 0.9, acmeNb.Belief.Exploitable, 1e-9)
	assert.InDelta(t, 0.1, globexNb.Belief.Exploitable, 1e-9)
}

// TestPlaceBet_NilRequest_Rejected proves a nil request is a protocol-level
// error, mirroring Observe's req == nil check.
func TestPlaceBet_NilRequest_Rejected(t *testing.T) {
	h := &placeBetMockHarness{missionID: "mission-A", tenantID: "acme"}
	svc := newPlaceBetService(t, h, "recon-agent", newFakeBeliefSubstrate())

	_, err := svc.PlaceBet(context.Background(), nil)
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestPlaceBet_MissingBet_Rejected proves a request with no Bet payload is
// refused before any harness lookup or substrate write is attempted.
func TestPlaceBet_MissingBet_Rejected(t *testing.T) {
	h := &placeBetMockHarness{missionID: "mission-A", tenantID: "acme"}
	svc := newPlaceBetService(t, h, "recon-agent", newFakeBeliefSubstrate())
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	_, err := svc.PlaceBet(ctx, &harnesspb.PlaceBetRequest{
		Context: &harnesspb.ContextInfo{MissionId: "mission-A", AgentName: "recon-agent"},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestPlaceBet_UnwiredSubstrate_Unavailable proves a daemon that has not
// wired a belief substrate refuses PlaceBet outright, the same convention
// sessionContextStore/componentRegistry use elsewhere in this package.
func TestPlaceBet_UnwiredSubstrate_Unavailable(t *testing.T) {
	h := &placeBetMockHarness{missionID: "mission-A", tenantID: "acme"}
	svc := newPlaceBetService(t, h, "recon-agent", nil)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	_, err := svc.PlaceBet(ctx, placeBetRequest("mission-A", "recon-agent", "hyp-1", "recon-agent", 0.5, "T1190"))
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

// TestPlaceBet_ForeignTenant_Rejected proves PlaceBet goes through the same
// tenant-isolation guard as every other callback (getHarness), so an agent
// cannot stake a bet against another tenant's mission.
func TestPlaceBet_ForeignTenant_Rejected(t *testing.T) {
	h := &placeBetMockHarness{missionID: "mission-A", tenantID: "acme"}
	svc := newPlaceBetService(t, h, "recon-agent", newFakeBeliefSubstrate())
	ctx := auth.ContextWithTenantString(context.Background(), "some-other-tenant")

	_, err := svc.PlaceBet(ctx, placeBetRequest("mission-A", "recon-agent", "hyp-1", "recon-agent", 0.5, "T1190"))
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestPlaceBet_UnknownMission_Rejected proves an agent name/mission pair with
// no registered harness is a NotFound, not a silent no-op write.
func TestPlaceBet_UnknownMission_Rejected(t *testing.T) {
	h := &placeBetMockHarness{missionID: "mission-A", tenantID: "acme"}
	svc := newPlaceBetService(t, h, "recon-agent", newFakeBeliefSubstrate())
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	_, err := svc.PlaceBet(ctx, placeBetRequest("mission-does-not-exist", "recon-agent", "hyp-1", "recon-agent", 0.5, "T1190"))
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// TestPlaceBet_InvalidBet_ReportsInBand covers every field-level validation
// rule as an in-band PlaceBetResponse.Error rather than a gRPC error, since
// the RPC itself reached a resolvable mission successfully.
func TestPlaceBet_InvalidBet_ReportsInBand(t *testing.T) {
	tests := []struct {
		name         string
		hypothesisID string
		stakingAgent string
		confidence   float64
		technique    string
	}{
		{name: "empty hypothesis id", hypothesisID: "", stakingAgent: "recon-agent", confidence: 0.5, technique: "T1190"},
		{name: "empty staking agent", hypothesisID: "hyp-1", stakingAgent: "", confidence: 0.5, technique: "T1190"},
		{name: "empty technique", hypothesisID: "hyp-1", stakingAgent: "recon-agent", confidence: 0.5, technique: ""},
		{name: "confidence below zero", hypothesisID: "hyp-1", stakingAgent: "recon-agent", confidence: -0.1, technique: "T1190"},
		{name: "confidence above one", hypothesisID: "hyp-1", stakingAgent: "recon-agent", confidence: 1.1, technique: "T1190"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := &placeBetMockHarness{missionID: "mission-A", tenantID: "acme"}
			substrate := newFakeBeliefSubstrate()
			svc := newPlaceBetService(t, h, "recon-agent", substrate)
			ctx := auth.ContextWithTenantString(context.Background(), "acme")

			resp, err := svc.PlaceBet(ctx, placeBetRequest("mission-A", "recon-agent", tc.hypothesisID, tc.stakingAgent, tc.confidence, tc.technique))
			require.NoError(t, err, "an invalid bet is an in-band error, not a gRPC error")
			require.NotNil(t, resp)
			require.NotNil(t, resp.Error)
			assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, resp.Error.Code)
			assert.NotEmpty(t, resp.Error.Message)

			assert.Empty(t, substrate.beliefs, "an invalid bet must never reach the substrate")
		})
	}
}

// TestPlaceBet_SubstrateFailure_ReportsInBand proves a SetBelief failure is
// surfaced as an in-band internal error, not silently dropped or panicked.
func TestPlaceBet_SubstrateFailure_ReportsInBand(t *testing.T) {
	h := &placeBetMockHarness{missionID: "mission-A", tenantID: "acme"}
	substrate := newFakeBeliefSubstrate()
	substrate.setErr = assertErr{"boom"}
	svc := newPlaceBetService(t, h, "recon-agent", substrate)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	resp, err := svc.PlaceBet(ctx, placeBetRequest("mission-A", "recon-agent", "hyp-1", "recon-agent", 0.5, "T1190"))
	require.NoError(t, err)
	require.NotNil(t, resp.Error)
	assert.Equal(t, commonpb.ErrorCode_ERROR_CODE_INTERNAL, resp.Error.Code)
}

// assertErr is a trivial error value for TestPlaceBet_SubstrateFailure_ReportsInBand.
type assertErr struct{ msg string }

func (e assertErr) Error() string { return e.msg }
