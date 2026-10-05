// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	worldpb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/world/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// betLabelTargetID mirrors bet_settlement.go's unexported helper of the same
// name: the Label TargetID a bet's hypothesis is labelled under, prefixed so
// it can never collide with a Finding id or a surprise-host id sharing the
// same Label namespace. Duplicated rather than imported because
// bet_settlement.go does not export it (gibson#339: reference, don't rewrite
// that file).
func betLabelTargetID(hypothesisID string) string {
	return "bet-" + hypothesisID
}

// ListOpenBets returns the tenant's placed-but-unsettled bets (gibson#339):
// a Hypothesis that carries a bettable HypothesisID (an agent set
// HypothesisObservation.hypothesis_id, sdk#89) with no matching
// BetSettlement. Backend for dashboard#97's HITL-settle review queue.
//
// A Hypothesis with no HypothesisID is never listed: it was never entered
// into the betting system (no agent named it in a Bet), so it is not a bet,
// open or otherwise, even though it is a perfectly good Hypothesis. This is
// the practical join gibson#339's identity reconciliation
// (hypothesis.go: HypothesisID) makes possible; there is no separate
// "a Bet was placed" event to check against (PlaceBet writes belief on a
// claim-node, not a Timeline event — internal/engine/harness/callback_place_bet.go),
// so a HypothesisID's presence is read as "bettable", not as proof a Bet call
// actually happened.
//
// confidence in the response is the claim's own self-reported confidence
// (Hypothesis.Confidence), not a reconciled market stake read back from
// BeliefSubstrate — that reconciliation is a pre-existing, tracked gap
// (gibson#273) this RPC does not close.
func (s *worldServer) ListOpenBets(ctx context.Context, _ *worldpb.ListOpenBetsRequest) (*worldpb.ListOpenBetsResponse, error) {
	e, err := s.engine(ctx)
	if err != nil {
		return nil, err
	}

	settled := make(map[string]bool)
	for _, st := range e.BetSettlements() {
		settled[st.HypothesisID] = true
	}

	resp := &worldpb.ListOpenBetsResponse{}
	for _, h := range e.Hypotheses() {
		if h.HypothesisID == "" || settled[h.HypothesisID] {
			continue
		}
		evidence := make([]*worldpb.ReferencedEntityView, 0, len(h.References))
		for _, r := range h.References {
			evidence = append(evidence, &worldpb.ReferencedEntityView{
				Label: r.Label, IdProperties: r.IDProperties,
			})
		}
		resp.Bets = append(resp.Bets, &worldpb.OpenBet{
			HypothesisId: h.HypothesisID,
			Claim:        h.Claim,
			Proposer:     h.Proposer,
			Confidence:   h.Confidence,
			Evidence:     evidence,
			RunId:        h.RunID,
		})
	}
	return resp, nil
}

// SettleBetByHITL records a human review verdict on a bet (gibson#280,
// ADR-0123). true_positive/false_positive settle the bet through
// Engine.SettleBetByHITL. dismiss is label-only/no-settle: it applies the
// ordinary label (the same channel SubmitLabel writes to) rather than
// attempting settlement, matching Engine.SettleBetByHITL's own refusal
// semantics — a bet's binary settlement has no "not actionable" outcome the
// way a surfaced surprise does (bet_settlement.go's hitlSettlementVerdict).
//
// The reviewing user is resolved server-side from the caller's identity,
// never taken from the request — the same rule SubmitLabel already follows,
// so a caller can never attribute a settlement to another user. Unlike
// SubmitLabel, a missing acting user is refused rather than recorded as an
// empty string: a HITL verdict is the accountability record for a bet's
// settlement (ADR-0106 provenance, ADR-0132's class of destructive/
// consequential action), so an unattributable verdict must fail closed, not
// flow through as a zero-value identity.
func (s *worldServer) SettleBetByHITL(ctx context.Context, req *worldpb.SettleBetByHITLRequest) (*worldpb.SettleBetByHITLResponse, error) {
	e, err := s.engine(ctx)
	if err != nil {
		return nil, err
	}
	hypothesisID := req.GetHypothesisId()
	if hypothesisID == "" {
		return nil, status.Error(codes.InvalidArgument, "hypothesis_id is required")
	}
	verdict := brain.LabelVerdict(req.GetVerdict())
	if !brain.ValidVerdict(verdict) {
		return nil, status.Errorf(codes.InvalidArgument,
			"unknown verdict %q (want true_positive|false_positive|dismiss)", req.GetVerdict())
	}
	userID, ok := auth.ActingUserFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated,
			"SettleBetByHITL requires an authenticated acting user; the bet was not settled")
	}

	if verdict == brain.VerdictDismiss {
		e.Submit(brain.LabelApplied{
			TargetID: betLabelTargetID(hypothesisID),
			Verdict:  verdict,
			UserID:   userID,
		})
		return &worldpb.SettleBetByHITLResponse{Settled: false}, nil
	}

	settled, err := e.SettleBetByHITL(ctx, brain.BetHITLRequest{
		HypothesisID: hypothesisID,
		Verdict:      verdict,
		UserID:       userID,
	})
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "settle bet: %v", err)
	}
	return &worldpb.SettleBetByHITLResponse{Settled: settled}, nil
}
