// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

// callback_request_destructive_authorization.go implements
// RequestDestructiveAuthorization (ADR-0032, gibson#390): an agent asks a
// human to approve an irreversible demonstration BEFORE it performs the act.
// The daemon enqueues the request on the caller's tenant's
// DestructiveAuthorizationQueue (ADR-0028, gibson#336/#342, via
// brain.ProofSettlementEngine's tenant-routing adapter,
// proof_settlement_adapter.go) and returns immediately with the pending
// request's id — the fleet keeps working while the decision is pending
// (ADR-0028). The agent performs the destructive act only after it reads
// back an approval (the dashboard's ListPendingDestructiveActions/decision
// surface), then calls SubmitProof with the SAME hypothesis_id
// (callback_submit_proof.go), whose SettleBetTrue verifies that recorded
// decision before ever evaluating the predicate.
//
// This RPC never blocks on the human decision (ADR-0032 decision 1): its
// only failure modes are structural — proof settlement not wired, a
// malformed request, or an unresolvable harness/mission — the same split
// SubmitProof uses.

import (
	"context"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// RequestDestructiveAuthorization implements
// harnesspb.HarnessCallbackServiceServer.RequestDestructiveAuthorization
// (ADR-0032 decision 1, gibson#390).
//
// Malformed requests (nil request, empty hypothesis_id/predicate_name/
// action_description — the proto's own min_len:1 fields) are refused as
// gRPC errors, the same defense-in-depth split every other harness callback
// in this package uses ahead of protovalidate. technique, blast_radius, and
// reversibility are not required: the proto marks only the three fields
// above as mandatory, and blast_radius/reversibility are not yet persisted
// anywhere (the dashboard's PendingDestructiveAction already documents this
// as a deliberate non-goal until a Domain Pack risk-tier signal exists —
// destructive_authz_service.go's toPendingDestructiveActionPB).
func (s *HarnessCallbackService) RequestDestructiveAuthorization(
	ctx context.Context, req *harnesspb.RequestDestructiveAuthorizationRequest,
) (*harnesspb.RequestDestructiveAuthorizationResponse, error) {
	if s.proofSettlement == nil {
		return nil, status.Error(codes.Unavailable, "RequestDestructiveAuthorization: proof settlement is not wired on this daemon")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "missing request destructive authorization request")
	}

	hypothesisID := req.GetHypothesisId()
	predicateName := req.GetPredicateName()
	actionDescription := req.GetActionDescription()
	if hypothesisID == "" {
		return nil, status.Error(codes.InvalidArgument, "hypothesis_id must not be empty")
	}
	if predicateName == "" {
		return nil, status.Error(codes.InvalidArgument, "predicate_name must not be empty")
	}
	if actionDescription == "" {
		return nil, status.Error(codes.InvalidArgument, "action_description must not be empty")
	}

	h, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	mission := h.Mission()
	target := h.Target()

	id, err := s.proofSettlement.RequestDestructiveAuthorization(ctx, brain.DestructiveAuthorizationRequest{
		HypothesisID:  hypothesisID,
		ScopeID:       target.ID.String(),
		MissionID:     mission.ID.String(),
		Technique:     req.GetTechnique(),
		PredicateType: predicateName,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "RequestDestructiveAuthorization: enqueue hypothesis %q: %v", hypothesisID, err)
	}

	return &harnesspb.RequestDestructiveAuthorizationResponse{
		AuthorizationRequestId: id,
	}, nil
}
