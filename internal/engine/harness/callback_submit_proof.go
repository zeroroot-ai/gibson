// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

// callback_submit_proof.go implements SubmitProof (ADR-0131,
// gibson#389, epic #376): an agent names the hypothesis and (technique,
// predicate) it settles, and the tool calls that prove it — never a verdict.
// The daemon resolves the named predicate from the caller's tenant's
// currently enabled Domain Packs, compiles and evaluates it as CEL over its
// OWN records of those tool calls (internal/engine/settlement/celenv,
// gibson#388), and on a true result reaches Engine.SettleBetTrue to fold
// BetSettledTrue. A proof that carries only text the agent typed goes to a
// human review and settles nothing here. This clears
// the deadcode baseline for SettleBetTrue / settlement.NewRegistry: before
// this file, nothing in the live daemon ever reached either.
//
// Predicates are pack data, never gibson code (ADR-0131):
// ontology.DomainPack.Predicates is keyed by a technique-shaped identifier,
// and predicate_name is that identifier from the agent's perspective —
// resolution is fail-closed (ADR-0131) for a predicate name no currently
// enabled pack binds, mirroring ADR-0131's anti-gaming stance
// that an unregistered predicate never evaluates to true. technique is what
// BetSettlement records for reputation (ADR-0122's technique x environment
// key). A pack binds one CEL predicate to one technique, so the two names are
// the same value, and a request where they differ is refused. Without the
// refusal a proof could settle under one technique on the predicate of
// another.
//
// Engine.SettleBetTrue still speaks the older
// internal/engine/settlement.Registry/Predicate/Evaluator shapes (ADR-0131),
// which ADR-0131 explicitly does not extend with new per-technique Go
// evaluators. This file bridges the two without adding one: it builds a
// fresh, single-use Registry per call and registers one Evaluator
// (evaluateDomainPackCEL) that itself compiles and evaluates the resolved
// pack CEL expression — so Engine.SettleBetTrue's own internal
// registry.Evaluate call re-runs the SAME deterministic celenv check
// SubmitProof already ran, rather than a registry entry that merely returns
// a value decided elsewhere. Nothing here alters Registry, Predicate, or
// Engine.SettleBetTrue.
//
// Destructive proofs (ADR-0132, gibson#390) go through the SAME
// compile/stake/evaluate path as a non-destructive proof. The enabled pack
// states whether the named predicate is destructive, and a predicate the
// pack does not name as non-destructive is destructive. The handler never
// reads SubmitProofRequest.destructive: the agent that submits a proof does
// not decide how the daemon treats it. Engine.SettleBetTrue's
// authorizer (wired in by the daemon-side tenant-routing adapter,
// proof_settlement_adapter.go, as brain.DestructiveAuthorizationQueue.Verify)
// then refuses to even evaluate the predicate unless a human already
// approved this hypothesis_id via RequestDestructiveAuthorization +
// the dashboard's decision surface (callback_request_destructive_authorization.go):
//
//   - No decision recorded yet (or none ever requested): SubmitProof reports
//     SETTLEMENT_OUTCOME_PENDING_AUTHORIZATION — a routine, expected state
//     while a human decision is outstanding, never a gRPC-level error. The
//     bet stays open; the caller (or a later SubmitProof retry) checks back.
//   - The recorded decision denied authorization: SubmitProof reports it
//     in-band as a PERMISSION_DENIED HarnessError, the same
//     in-band-failure pattern every other SubmitProof failure in this file
//     uses — terminal, never retried into a different answer.
//   - The recorded decision approved: evaluation proceeds exactly like a
//     non-destructive proof, so the predicate still decides the verdict —
//     an approval to attempt the demonstration is not a verdict that it
//     succeeded.
//
// The named predicate is still resolved first in every case, so
// a destructive proof for an unknown predicate name fails closed the same
// way a non-destructive one does, rather than reporting PENDING_AUTHORIZATION
// for a predicate that could never settle.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/engine/settlement"
	"github.com/zeroroot-ai/gibson/internal/engine/settlement/celenv"
)

// domainPackCELPredicateType is the settlement.PredicateType every SubmitProof
// call registers on its own single-use Registry (see evaluateDomainPackCEL).
// It never varies per technique — the pack CEL expression itself is what
// varies, carried as the Predicate's Params, not the type name.
const domainPackCELPredicateType settlement.PredicateType = "domain_pack_cel"

// SubmitProof implements harnesspb.HarnessCallbackServiceServer.SubmitProof
// (ADR-0131): an agent triggers settlement and names recorded tool calls; the
// daemon decides via a deterministic pack CEL predicate, never the agent's
// own verdict.
//
// Malformed requests (nil request, empty hypothesis_id/technique/
// predicate_name) are refused as gRPC errors, the same split PlaceBet uses.
// A structurally valid request whose predicate cannot be resolved, or whose
// resolved expression fails to compile, is reported in-band via
// SubmitProofResponse.Error with SETTLEMENT_OUTCOME_UNSPECIFIED — the RPC
// itself succeeded, the proof did not.
func (s *HarnessCallbackService) SubmitProof(ctx context.Context, req *harnesspb.SubmitProofRequest) (*harnesspb.SubmitProofResponse, error) {
	if s.proofSettlement == nil {
		return nil, status.Error(codes.Unavailable, "SubmitProof: proof settlement is not wired on this daemon")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "missing submit proof request")
	}

	hypothesisID := req.GetHypothesisId()
	technique := req.GetTechnique()
	predicateName := req.GetPredicateName()
	if hypothesisID == "" {
		return nil, status.Error(codes.InvalidArgument, "hypothesis_id must not be empty")
	}
	if technique == "" {
		return nil, status.Error(codes.InvalidArgument, "technique must not be empty")
	}
	if predicateName == "" {
		return nil, status.Error(codes.InvalidArgument, "predicate_name must not be empty")
	}
	if technique != predicateName {
		return nil, status.Errorf(codes.InvalidArgument,
			"technique %q does not match predicate_name %q: a pack binds one predicate to one technique", technique, predicateName)
	}

	h, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	mission := h.Mission()
	target := h.Target()

	expr, destructive, ok, err := s.proofSettlement.DomainPackPredicate(ctx, predicateName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "SubmitProof: resolve predicate %q: %v", predicateName, err)
	}
	if !ok {
		return &harnesspb.SubmitProofResponse{
			HypothesisId: hypothesisID,
			Outcome:      harnesspb.SettlementOutcome_SETTLEMENT_OUTCOME_UNSPECIFIED,
			Error: &harnesspb.HarnessError{
				Code: commonpb.ErrorCode_ERROR_CODE_NOT_FOUND,
				Message: fmt.Sprintf(
					"SubmitProof: predicate %q is not bound by any Domain Pack enabled for this tenant", predicateName),
			},
		}, nil
	}

	if _, compileErr := celenv.Compile(expr); compileErr != nil {
		return &harnesspb.SubmitProofResponse{
			HypothesisId: hypothesisID,
			Outcome:      harnesspb.SettlementOutcome_SETTLEMENT_OUTCOME_UNSPECIFIED,
			Error: &harnesspb.HarnessError{
				Code: commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: fmt.Sprintf(
					"SubmitProof: predicate %q does not compile: %v", predicateName, compileErr),
			},
		}, nil
	}

	predictedProbability, err := s.stakedConfidence(ctx, mission.TenantID, hypothesisID)
	if err != nil {
		// Deliberate in-band error: the missing-stake failure is surfaced to the
		// agent in the response's HarnessError, and the gRPC error is intentionally
		// nil (same contract as the compileErr branch above).
		return &harnesspb.SubmitProofResponse{ //nolint:nilerr // in-band error via HarnessError; gRPC error intentionally nil
			HypothesisId: hypothesisID,
			Outcome:      harnesspb.SettlementOutcome_SETTLEMENT_OUTCOME_UNSPECIFIED,
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_NOT_FOUND,
				Message: err.Error(),
			},
		}, nil
	}

	// Two forms of proof (ADR-0131). A proof that names recorded tool calls
	// settles on the daemon's own record of those calls. A proof that carries
	// only text the agent typed settles nothing here: the daemon cannot tell
	// where the text came from, so a human reviews it.
	toolCallIDs := req.GetToolCallIds()
	if len(toolCallIDs) == 0 {
		return s.submitProofForReview(ctx, req, mission.ID.String(), target.ID.String())
	}
	if len(toolCallIDs) > brain.MaxProofToolCallIDs {
		return nil, status.Errorf(codes.InvalidArgument,
			"tool_call_ids names %d calls, over the limit of %d", len(toolCallIDs), brain.MaxProofToolCallIDs)
	}
	calls, missing, err := s.proofSettlement.RecordedToolCalls(ctx, mission.ID.String(), toolCallIDs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "SubmitProof: read recorded tool calls: %v", err)
	}
	if len(missing) > 0 {
		return &harnesspb.SubmitProofResponse{
			HypothesisId: hypothesisID,
			Outcome:      harnesspb.SettlementOutcome_SETTLEMENT_OUTCOME_UNSPECIFIED,
			Error: &harnesspb.HarnessError{
				Code: commonpb.ErrorCode_ERROR_CODE_NOT_FOUND,
				Message: fmt.Sprintf(
					"SubmitProof: the daemon holds no record of tool call %q for this mission", missing[0]),
			},
		}, nil
	}

	registry := settlement.NewRegistry()
	if regErr := registry.Register(settlement.TechniqueID(technique), domainPackCELPredicateType, evaluateDomainPackCEL); regErr != nil {
		return nil, status.Errorf(codes.Internal, "SubmitProof: register predicate: %v", regErr)
	}

	rawExpr, marshalErr := json.Marshal(expr)
	if marshalErr != nil {
		return nil, status.Errorf(codes.Internal, "SubmitProof: encode predicate params: %v", marshalErr)
	}

	settled, err := s.proofSettlement.SettleBetTrue(ctx, registry, nil, brain.BetSettlementRequest{
		HypothesisID:         hypothesisID,
		ScopeID:              target.ID.String(),
		MissionID:            mission.ID.String(),
		Technique:            settlement.TechniqueID(technique),
		PredicateType:        domainPackCELPredicateType,
		PredicateParams:      json.RawMessage(rawExpr),
		Evidence:             recordedToolCallEvidence(calls),
		Destructive:          destructive,
		PredictedProbability: predictedProbability,
	})
	if err != nil {
		switch {
		case errors.Is(err, brain.ErrDestructiveActionPending):
			return &harnesspb.SubmitProofResponse{
				HypothesisId: hypothesisID,
				Outcome:      harnesspb.SettlementOutcome_SETTLEMENT_OUTCOME_PENDING_AUTHORIZATION,
			}, nil
		case errors.Is(err, brain.ErrDestructiveActionDenied):
			return &harnesspb.SubmitProofResponse{
				HypothesisId: hypothesisID,
				Outcome:      harnesspb.SettlementOutcome_SETTLEMENT_OUTCOME_UNSPECIFIED,
				Error: &harnesspb.HarnessError{
					Code:    commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED,
					Message: fmt.Sprintf("SubmitProof: destructive proof for hypothesis %q was denied authorization", hypothesisID),
				},
			}, nil
		default:
			return nil, status.Errorf(codes.Internal, "SubmitProof: settle hypothesis %q: %v", hypothesisID, err)
		}
	}

	outcome := harnesspb.SettlementOutcome_SETTLEMENT_OUTCOME_NOT_SETTLED
	if settled {
		outcome = harnesspb.SettlementOutcome_SETTLEMENT_OUTCOME_SETTLED_TRUE
	}
	return &harnesspb.SubmitProofResponse{
		HypothesisId: hypothesisID,
		Outcome:      outcome,
	}, nil
}

// stakedConfidence reads the confidence the fleet staked on hypothesisID via
// PlaceBet (ADR-0122): for a NodeKindClaim node, Belief.Exploitable holds
// P(claim valid), the same convention callback_place_bet.go established.
// SettleBetTrue requires a PredictedProbability in [0,1] to score the
// settlement under a proper scoring rule (bet_scoring.go) — reusing the
// staked value here, rather than asking the agent to resupply it on
// SubmitProof, keeps that number the fleet's own calibrated stake rather
// than something the proof's submitter could pick to flatter its own score.
//
// Returns an error (never ok=false silently) when no bet was ever staked on
// hypothesisID: a proof with nothing staked to score is a caller mistake,
// not a system state SubmitProof degrades through.
func (s *HarnessCallbackService) stakedConfidence(ctx context.Context, tenant, hypothesisID string) (float64, error) {
	if s.beliefSubstrate == nil {
		return 0, fmt.Errorf("SubmitProof: no bet was staked on hypothesis %q: betting is not wired on this daemon", hypothesisID)
	}
	nb, ok, err := s.beliefSubstrate.Belief(ctx, claimNodeRef(tenant, hypothesisID))
	if err != nil {
		return 0, fmt.Errorf("SubmitProof: read staked confidence for hypothesis %q: %w", hypothesisID, err)
	}
	if !ok {
		return 0, fmt.Errorf("SubmitProof: no bet was staked on hypothesis %q; place a bet before submitting proof", hypothesisID)
	}
	return nb.Belief.Exploitable, nil
}

// evaluateDomainPackCEL is the settlement.Evaluator every SubmitProof call
// registers for its resolved (technique, domainPackCELPredicateType) pair. It
// decodes the pack's CEL expression text carried in params and evaluates it
// against evidence via celenv (gibson#388) — the same deterministic primitive
// SubmitProof itself already ran once to decide whether to reach this point,
// so Engine.SettleBetTrue's internal re-check can never diverge from that
// answer on the same evidence, never a shortcut that merely returns a value
// decided elsewhere.
func evaluateDomainPackCEL(params json.RawMessage, evidence []finding.EnhancedEvidence) (bool, error) {
	var expr string
	if err := json.Unmarshal(params, &expr); err != nil {
		return false, fmt.Errorf("submitproof: decode %s params: %w", domainPackCELPredicateType, err)
	}
	compiled, err := celenv.Compile(expr)
	if err != nil {
		return false, fmt.Errorf("submitproof: compile domain pack predicate: %w", err)
	}
	ok, err := compiled.Evaluate(context.Background(), evidence)
	if err != nil {
		return false, fmt.Errorf("submitproof: evaluate domain pack predicate: %w", err)
	}
	return ok, nil
}

// submitProofForReview records a proof that carries only agent-typed
// evidence and reports SETTLEMENT_OUTCOME_PENDING_REVIEW. The bet stays open
// until a human settles it. A proof with no tool call and no evidence is
// refused: there is nothing to evaluate and nothing to review.
func (s *HarnessCallbackService) submitProofForReview(
	ctx context.Context, req *harnesspb.SubmitProofRequest, missionID, scopeID string,
) (*harnesspb.SubmitProofResponse, error) {
	typed := req.GetEvidence()
	if len(typed) == 0 {
		return nil, status.Error(codes.InvalidArgument,
			"a proof must name recorded tool calls (tool_call_ids) or carry evidence")
	}
	evidence := make([]brain.ProofReviewEvidence, len(typed))
	for i, e := range typed {
		evidence[i] = brain.ProofReviewEvidence{
			Type:    e.GetType().String(),
			Title:   e.GetTitle(),
			Content: e.GetContent(),
		}
	}
	if err := s.proofSettlement.SubmitProofForReview(ctx, brain.ProofReviewRequest{
		HypothesisID:        req.GetHypothesisId(),
		MissionID:           missionID,
		ScopeID:             scopeID,
		Technique:           req.GetTechnique(),
		Evidence:            evidence,
		SubmittedAtUnixNano: time.Now().UnixNano(),
	}); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "SubmitProof: %v", err)
	}
	return &harnesspb.SubmitProofResponse{
		HypothesisId: req.GetHypothesisId(),
		Outcome:      harnesspb.SettlementOutcome_SETTLEMENT_OUTCOME_PENDING_REVIEW,
	}, nil
}

// recordedToolCallEvidence turns the daemon's own records of tool calls into
// the evidence a pack predicate evaluates. Content is the result the tool
// returned, as the flight recorder stored it (ADR-0120), and Timestamp is
// when the daemon observed the call. Nothing here comes from the proof
// request except the ids that selected the records.
func recordedToolCallEvidence(calls []brain.AgentToolCallSnapshot) []finding.EnhancedEvidence {
	out := make([]finding.EnhancedEvidence, len(calls))
	for i, c := range calls {
		out[i] = finding.EnhancedEvidence{
			Type:      finding.EvidenceLog,
			Title:     fmt.Sprintf("tool call %s (%s)", c.ToolName, c.ToolCallID),
			Content:   c.Result,
			Timestamp: time.Unix(0, c.RecordedAtUnixNano),
		}
	}
	return out
}
