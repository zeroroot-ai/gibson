// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// requestDestructiveAuthorizationRequest builds a well-formed
// RequestDestructiveAuthorizationRequest, mirroring submitProofRequest's
// shape (callback_submit_proof_test.go).
func requestDestructiveAuthorizationRequest(missionID, agentName, hypothesisID, technique, predicateName, actionDescription string) *harnesspb.RequestDestructiveAuthorizationRequest {
	return &harnesspb.RequestDestructiveAuthorizationRequest{
		Context:           &harnesspb.ContextInfo{MissionId: missionID, AgentName: agentName},
		HypothesisId:      hypothesisID,
		Technique:         technique,
		PredicateName:     predicateName,
		ActionDescription: actionDescription,
	}
}

// TestRequestDestructiveAuthorization_NotWired_Unavailable proves the RPC
// degrades the same way SubmitProof/PlaceBet do when proof settlement was
// never wired (staged-wiring default, ADR-0003: no graceful-nil in the
// request path, an explicit Unavailable instead).
func TestRequestDestructiveAuthorization_NotWired_Unavailable(t *testing.T) {
	h := &submitProofMockHarness{missionID: "mission-A", tenantID: "acme"}
	svc := newSubmitProofService(t, h, "recon-agent", nil, nil)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	resp, err := svc.RequestDestructiveAuthorization(ctx, requestDestructiveAuthorizationRequest(
		"mission-A", "recon-agent", "hyp-1", "T1490", "T1490", "delete the production database"))
	require.Nil(t, resp)
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

// TestRequestDestructiveAuthorization_MissingFields_InvalidArgument proves
// each required field (the proto's own min_len:1 fields) is checked
// independently of protovalidate, mirroring SubmitProof's own field checks.
func TestRequestDestructiveAuthorization_MissingFields_InvalidArgument(t *testing.T) {
	h := &submitProofMockHarness{missionID: "mission-A", tenantID: "acme"}
	engine := newTestProofSettlementEngine(t, "acme", nil)
	svc := newSubmitProofService(t, h, "recon-agent", newFakeBeliefSubstrate(), engine)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	tests := []struct {
		name              string
		hypothesisID      string
		predicateName     string
		actionDescription string
	}{
		{"empty hypothesis id", "", "T1490", "delete the production database"},
		{"empty predicate name", "hyp-1", "", "delete the production database"},
		{"empty action description", "hyp-1", "T1490", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.RequestDestructiveAuthorization(ctx, requestDestructiveAuthorizationRequest(
				"mission-A", "recon-agent", tt.hypothesisID, "T1490", tt.predicateName, tt.actionDescription))
			require.Nil(t, resp)
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

// TestRequestDestructiveAuthorization_Success_EnqueuesAndReturnsImmediately
// proves the ADR-0032 decision 1 contract: the call enqueues a pending
// destructive action on the caller's tenant's DestructiveAuthorizationQueue
// and returns immediately with an authorization_request_id — never blocking
// on a human decision, and never settling anything (this RPC never touches
// SettleBetTrue at all).
func TestRequestDestructiveAuthorization_Success_EnqueuesAndReturnsImmediately(t *testing.T) {
	h := &submitProofMockHarness{missionID: "mission-A", tenantID: "acme"}
	engine := newTestProofSettlementEngine(t, "acme", nil)
	svc := newSubmitProofService(t, h, "recon-agent", newFakeBeliefSubstrate(), engine)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	resp, err := svc.RequestDestructiveAuthorization(ctx, requestDestructiveAuthorizationRequest(
		"mission-A", "recon-agent", "hyp-1", "T1490", "T1490", "delete the production database"))
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "hyp-1", resp.GetAuthorizationRequestId())
	assert.Nil(t, resp.GetError())

	awaitDestructivePending(t, engine.engine, "hyp-1")
	got := engine.engine.DestructiveActionSnapshot()
	require.Len(t, got, 1)
	assert.Equal(t, "hyp-1", got[0].HypothesisID)
	assert.Equal(t, "T1490", got[0].Technique)
	assert.Equal(t, "T1490", got[0].PredicateType)
	assert.False(t, got[0].Decided, "a freshly requested action must not already be decided")

	// SettleBetTrue's verification must find it pending (no decision), never
	// approved — that is exactly the point of asking before acting.
	approved, verr := engine.engine.DestructiveAuthorizationQueue().Verify(context.Background(), "acme", brain.BetSettlementRequest{HypothesisID: "hyp-1"})
	assert.False(t, approved)
	require.Error(t, verr)
}

// TestRequestDestructiveAuthorization_HarnessLookupFailure proves an
// unresolvable mission/agent context is refused as a gRPC error, the same
// getHarness split every other harness callback in this package uses.
func TestRequestDestructiveAuthorization_HarnessLookupFailure(t *testing.T) {
	h := &submitProofMockHarness{missionID: "mission-A", tenantID: "acme"}
	engine := newTestProofSettlementEngine(t, "acme", nil)
	svc := newSubmitProofService(t, h, "recon-agent", newFakeBeliefSubstrate(), engine)
	ctx := auth.ContextWithTenantString(context.Background(), "acme")

	resp, err := svc.RequestDestructiveAuthorization(ctx, requestDestructiveAuthorizationRequest(
		"mission-does-not-exist", "recon-agent", "hyp-1", "T1490", "T1490", "delete the production database"))
	require.Nil(t, resp)
	require.Error(t, err)
}
