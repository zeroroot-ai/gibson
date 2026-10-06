// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"sort"

	"github.com/zeroroot-ai/gibson/internal/engine/brain/beliefvi"
)

// belief_quality.go is the measure of the quality gate of the belief artifact
// versions (ADR-0106, gibson#789). The daemon scores a new version and the
// current version on the settled bets of the tenant, and the new version
// becomes current only when its score is not worse.
//
// The score is the mean Brier score (bet_scoring.go) of P(exploitable) on the
// host that each settled bet names. The gate uses the score to accept or
// reject a version. It is never a training input: no training read returns
// it, and no fit reads it.

// BetCase is one settled bet as the quality gate scores it: the belief
// evidence of the host that the bet names, and the verdict as 1 (TRUE) or 0
// (FALSE).
//
// The evidence leaves out ExploitDemonstrated. A TRUE settlement sets that
// evidence on its own host, so a model that reads it would score the bet
// with its own answer.
type BetCase struct {
	Evidence BeliefEvidence
	Outcome  float64
}

// SettledBetCases returns one BetCase for each settled bet and each host
// that its hypothesis names, in a stable order. A bet whose hypothesis names
// no host of the World gives no case. The join is the one
// demonstratedExploitByHost uses: settlement -> hypothesis -> a reference
// whose id-property value is the address of a host in the scope of the
// hypothesis.
func (w *World) SettledBetCases() []BetCase {
	evidence := map[string]BeliefEvidence{}
	forEachHostEvidence(w, func(h *Host, ev BeliefEvidence) {
		ev.ExploitDemonstrated = false
		evidence[hostEvidenceKey(h.ScopeID, h.Address)] = ev
	})
	hypByID := map[string]HypothesisSnapshot{}
	for _, h := range w.HypothesisSnapshot() {
		if h.HypothesisID != "" {
			hypByID[h.HypothesisID] = h
		}
	}

	var out []BetCase
	for _, s := range w.BetSettlementSnapshot() {
		hyp, ok := hypByID[s.HypothesisID]
		if !ok {
			continue
		}
		keys := map[string]struct{}{}
		for _, ref := range hyp.References {
			for _, v := range ref.IDProperties {
				if v == "" {
					continue
				}
				if _, ok := evidence[hostEvidenceKey(hyp.ScopeID, v)]; ok {
					keys[hostEvidenceKey(hyp.ScopeID, v)] = struct{}{}
				}
			}
		}
		sorted := make([]string, 0, len(keys))
		for k := range keys {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		for _, k := range sorted {
			out = append(out, BetCase{Evidence: evidence[k], Outcome: settlementOutcome(s.Verdict)})
		}
	}
	return out
}

// BrierOnBets returns the mean Brier score of P(exploitable) that model gives
// for each case, and the number of cases it scored. A case that the model
// cannot score (impossible evidence) counts as the worst forecast, 1. With no
// case the score is 0.
func BrierOnBets(model *beliefvi.BeliefModel, cases []BetCase) (score float64, scored int) {
	if len(cases) == 0 {
		return 0, 0
	}
	var sum float64
	for _, c := range cases {
		res, err := model.Score(beliefvi.Evidence{
			OpenPorts:       c.Evidence.OpenPorts,
			Services:        c.Evidence.Services,
			Reachable:       c.Evidence.Reachable,
			FindingCritical: c.Evidence.FindingCritical,
			FindingHigh:     c.Evidence.FindingHigh,
		}, nil)
		if err != nil {
			sum++
			continue
		}
		sum += brierScore(res.Exploitable, c.Outcome)
	}
	return sum / float64(len(cases)), len(cases)
}
