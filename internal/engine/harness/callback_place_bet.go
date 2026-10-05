// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

// callback_place_bet.go implements PlaceBet (ADR-0122, gibson#273/#278): an
// agent stakes a calibrated confidence on a Hypothesis. This IS the bet
// store — placing a bet is modeled as a write of belief on a claim-node
// (ADR-0129: "a hypothesis/bet is belief on a claim-node"), so the market
// is a VIEW over the same belief substrate Lane B's brain package publishes
// (brain.BeliefSubstrate, gibson#276) rather than a bespoke store of its own.
//
// brain.Belief is currently shaped for its original Host use (Juicy /
// Exploitable / Reachable). ADR-0129 generalizes belief to any
// node kind but has not yet grown a Claim-specific shape, so until it does,
// this file makes one explicit, documented choice: for a
// brain.NodeKindClaim node, Belief.Exploitable holds P(claim valid) — the
// bet's staked confidence — and Juicy/Reachable are left at their zero
// value. Model records the market's own provenance tag (betConfidenceModelTag),
// not a PRM model version.
//
// Placing a bet never requires the Hypothesis to already exist elsewhere on
// the graph: the hypothesis-fold that turns an emitted HypothesisObservation
// into a durable node is a separate, still-blocked slice (gibson#265).
// SetBelief's upsert semantics mean a bet placed first and folded into the
// graph later still lands on the same claim-node.
//
// A concrete brain.BeliefSubstrate is deliberately not wired into the daemon
// by this file (s.beliefSubstrate defaults to nil, and PlaceBet returns
// Unavailable) — the same staged-wiring pattern this package already uses
// for sessionContextStore and componentRegistry: the seam lands first, a
// later slice supplies and reaches the production implementation.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// betConfidenceModelTag is the Belief.Model provenance tag PlaceBet writes,
// distinguishing a market-view belief write from a PRM-scored one.
const betConfidenceModelTag = "bet:v1"

// PlaceBet implements harnesspb.HarnessCallbackServiceServer.PlaceBet
// (ADR-0122): an agent stakes a calibrated confidence on a Hypothesis. The
// stake is persisted as belief on the hypothesis's claim-node, tenant-scoped
// so two tenants' hypotheses never collide in the substrate's (Kind, ID)
// keyspace even if they happen to reuse the same hypothesis id.
//
// Malformed requests (nil request, nil bet) and an unresolvable/foreign-tenant
// mission are refused as gRPC errors — the same split every other callback in
// this file uses. A structurally valid but invalid bet (empty fields, an
// out-of-range confidence) is reported in-band via PlaceBetResponse.Error,
// mirroring Observe's bounds-rejection style, since the RPC itself succeeded.
func (s *HarnessCallbackService) PlaceBet(ctx context.Context, req *harnesspb.PlaceBetRequest) (*harnesspb.PlaceBetResponse, error) {
	if s.beliefSubstrate == nil {
		return nil, status.Error(codes.Unavailable, "PlaceBet: betting is not wired on this daemon")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "missing place bet request")
	}
	bet := req.GetBet()
	if bet == nil {
		return nil, status.Error(codes.InvalidArgument, "missing bet")
	}

	if verr := validateBet(bet); verr != nil {
		return &harnesspb.PlaceBetResponse{ //nolint:nilerr // an invalid bet is surfaced in the response body, not as a gRPC error
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: verr.Error(),
			},
		}, nil
	}

	h, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	tenant := h.Mission().TenantID

	// A daemon-supplied brain.BeliefSubstrate is shared across every
	// tenant's PlaceBet calls (one field on HarnessCallbackService), so it
	// must be able to route each call to the right tenant's own belief
	// store. It does that the same way world_service.go's engine(ctx) does
	// — reading the tenant from ctx via auth.TenantFromContext. ctx already
	// carries it here: getHarness above already required and validated
	// (auth.TenantStringFromContext(ctx) == harness.Mission().TenantID)
	// before returning h, so it is redundant, not merely unnecessary, to
	// re-derive or re-stamp tenant onto ctx from tenant/h.Mission() again.
	ref := claimNodeRef(tenant, bet.GetHypothesisId())
	nb := brain.NodeBelief{
		Belief: brain.Belief{
			Exploitable: bet.GetConfidence(),
			Model:       betConfidenceModelTag,
		},
		EvidenceDigest: betEvidenceDigest(bet),
	}

	if err := s.beliefSubstrate.SetBelief(ctx, ref, nb); err != nil {
		s.logger.Error("PlaceBet: SetBelief failed",
			"mission_id", req.GetContext().GetMissionId(),
			"hypothesis_id", bet.GetHypothesisId(),
			"error", err)
		return &harnesspb.PlaceBetResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	return &harnesspb.PlaceBetResponse{}, nil
}

// validateBet checks the wire-level shape of a Bet before it is persisted.
// Confidence is a calibrated probability, and must be a valid one.
func validateBet(bet *harnesspb.Bet) error {
	if bet.GetHypothesisId() == "" {
		return errors.New("bet.hypothesis_id must not be empty")
	}
	if bet.GetStakingAgent() == "" {
		return errors.New("bet.staking_agent must not be empty")
	}
	if bet.GetTechnique() == "" {
		return errors.New("bet.technique must not be empty")
	}
	if bet.GetConfidence() < 0 || bet.GetConfidence() > 1 {
		return fmt.Errorf("bet.confidence must be in [0,1], got %v", bet.GetConfidence())
	}
	return nil
}

// claimNodeRef addresses the claim-node a Hypothesis's bets accumulate on.
// The id is tenant-scoped: brain.BeliefSubstrate keys purely on (Kind, ID),
// so without this prefix two tenants proposing a hypothesis with the same id
// would collide on one belief record.
func claimNodeRef(tenant, hypothesisID string) brain.NodeRef {
	return brain.NodeRef{Kind: brain.NodeKindClaim, ID: tenant + "/" + hypothesisID}
}

// marketEvidence is the canonical, JSON-native shape PlaceBet fingerprints
// for a bet's EvidenceDigest. Field order matches encoding/json's struct
// field order, which is stable across processes.
type marketEvidence struct {
	HypothesisID string  `json:"hypothesis_id"`
	StakingAgent string  `json:"staking_agent"`
	Confidence   float64 `json:"confidence"`
	Technique    string  `json:"technique"`
}

// betEvidenceDigest fingerprints the placed bet itself: for the market view,
// the bet IS the evidence the belief was written from — there is no separate
// evidence document the way a Host's open ports are (belief.go's
// evidenceDigest). Same bet content -> same digest, so a replayed PlaceBet
// call is reproducible.
func betEvidenceDigest(bet *harnesspb.Bet) string {
	// marketEvidence holds only ordered, JSON-native fields, so Marshal
	// cannot fail and its encoding is canonical.
	b, _ := json.Marshal(marketEvidence{
		HypothesisID: bet.GetHypothesisId(),
		StakingAgent: bet.GetStakingAgent(),
		Confidence:   bet.GetConfidence(),
		Technique:    bet.GetTechnique(),
	})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
