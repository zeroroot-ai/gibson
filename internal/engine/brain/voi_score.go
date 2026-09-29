// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "math"

// voi_score.go is the ONE-STEP-EXACT value-of-information scorer ADR-0026 §3
// describes: value = (goal-relative info gain + surprise) / (resource cost +
// risk cost) × reputation × stake — for a SINGLE candidate move, computed
// exactly (no sampling), never a multi-step lookahead.
//
// ADR-0026 §4 calls for full multi-step BAMCP (Bayes-Adaptive Monte Carlo
// Planning, Thompson-sampled, fully Bayesian, no UCB) because exact
// enumeration of a multi-step plan tree is intractable. This package does NOT
// implement that tree search: it computes each candidate's value exactly for
// the CURRENT belief state, and "sequential planning" is achieved by
// recomputing it every cycle as evidence changes (voi_plan.go's gate/worker,
// mirroring decider.go's own off-tick re-evaluation loop) — a receding
// one-step horizon rather than an internal search tree. This is a deliberate
// scope decision, not an oversight: a genuine BAMCP implementation needs a
// generative belief-network simulator and a consumable Dirichlet-over-CPT
// posterior from braintrain, neither of which exists as data the Go daemon
// can read yet. VoIScorer is the seam a future planner (or Jev, ADR-0026's own
// "not yet" note) plugs into without disturbing the gate/worker around it.

// Tunable constants. Costs and priors are simple, documented placeholders
// pending real integration with BudgetSystem (resource cost) and a RoE/
// blast-radius model (risk cost) — neither exists as a consumable cost
// function in this codebase yet. Reputation and stake priors are the
// "optimism under uncertainty" ADR-0026 §6 calls for: no data yet means
// "do not penalize", not "assume the worst" — VoI must be able to DRIVE a
// fleet's first bet on a hypothesis, not merely re-rank already-staked ones.
const (
	// DefaultVoITopK is the default number of top-ranked candidates VoIPlan
	// keeps (ADR-0026 §1: "VoI gates to top-k").
	DefaultVoITopK = 10

	voiEvidenceMoveResourceCost   = 1.0 // an evidence move is the cheapest action
	voiHypothesisTestResourceCost = 2.0 // pursuing a hypothesis is an active probe/bet
	voiEvidenceMoveRiskCost       = 0.5
	voiHypothesisTestRiskCost     = 1.0

	// voiNeutralReputationPrior is used when a candidate names no resolvable
	// technique×environment key yet (every candidate, today — see voi_plan.go).
	voiNeutralReputationPrior = 1.0
	// voiNeutralStakePrior is used for a hypothesis nobody has bet on yet.
	voiNeutralStakePrior = 1.0
	// voiUnstakedConfidence is the entropy input for an unstaked hypothesis:
	// maximal uncertainty (no bet has narrowed it at all).
	voiUnstakedConfidence = 0.5
)

// VoICandidateKind distinguishes the two candidate shapes ADR-0026 §2 names.
// Both are scored on one scale; they are not costed identically.
type VoICandidateKind string

const (
	// VoICandidateHypothesis is an open hypothesis to test. Pursuing it IS
	// placing/raising a bet on it (ADR-0022/ADR-0029 §3).
	VoICandidateHypothesis VoICandidateKind = "hypothesis"
	// VoICandidateEvidence is an evidence move on a high-uncertainty node.
	// Places no bet.
	VoICandidateEvidence VoICandidateKind = "evidence"
)

// VoIScoreInput is everything ExactVoIScorer needs for one candidate, resolved
// by the caller (voi_plan.go) so the scorer itself stays a pure function with
// no World/Engine/BeliefSubstrate access — easy to test, easy to replace.
type VoIScoreInput struct {
	Kind  VoICandidateKind
	RefID string // the Hypothesis id or Host id this candidate names (stringified)

	// Confidence is the belief this candidate's outcome is "juicy"/valid — the
	// entropy input. For a Host evidence-move, Host.Belief.Juicy. For a
	// hypothesis, its claim-node's staked confidence if HasStake, else
	// voiUnstakedConfidence.
	Confidence float64
	// Connectivity is the candidate's degree in the current attack graph
	// (DeriveAttackGraph, gibson#286) — ADR-0026 §3's "juiciness ×
	// connectivity". 0 is a valid, common value (today's live graph has no
	// cross-host edges yet), not a sentinel for "unknown".
	Connectivity int
	// Surprised mirrors Host.Surprise != "" (attention.go) — the anomaly
	// channel that must never be curated away.
	Surprised bool
	// HasStake reports whether a bet already exists for this candidate
	// (always false for VoICandidateEvidence, which places no bet).
	HasStake bool
	// Reputation is the caller-resolved technique×environment belief
	// (ADR-0029 §3), or voiNeutralReputationPrior when no technique×
	// environment key is resolvable yet.
	Reputation float64
}

// VoICandidate is one scored candidate with its full value breakdown recorded
// — never just the final number — so a plan is auditable and its ranking is
// reproducible from the same recorded inputs (ADR-0026 §3/§4: "exact,
// deterministic... recorded and replayable").
type VoICandidate struct {
	Kind         VoICandidateKind
	RefID        string
	InfoGain     float64
	Surprise     float64
	ResourceCost float64
	RiskCost     float64
	Reputation   float64
	Stake        float64
	Value        float64

	// Technique names the taxonomy technique (a taxonomy.TechniqueID, kept as
	// a plain string the same way Hypothesis.Technique is) this candidate
	// exercises, when known: carried from the source Hypothesis for a
	// VoICandidateHypothesis candidate, and always empty for a
	// VoICandidateEvidence candidate — a bare evidence move names no
	// technique (the same convention voi_plan.go's resolveReputation already
	// uses). PlanVoI sets it; VoIScorer never reads or sets it, since it is a
	// dispatch-gating input, not a value input.
	Technique string
	// CoveringCapabilities is VoI dispatch gating's technique -> capability
	// bridge resolved for this candidate (ADR-0035 decision 4, gibson#387):
	// the (Kind, Name) refs of every capability from the plan's Capabilities
	// catalog whose declared Coverage includes Technique itself or the
	// category it rolls up to (CapabilitiesForTechnique, voi_dispatch.go —
	// refs, not full Capability values: see CapabilityRef's own doc comment
	// for why). Nil means either the candidate names no technique, or nothing
	// in the catalog covers it — both are the explicit "no covering
	// capability" case, never an error; the caller (VoI dispatch gating,
	// gibson#396/#397) decides what an uncovered candidate means.
	CoveringCapabilities []CapabilityRef
}

// VoIScorer computes one candidate's VoICandidate (Value filled in) from its
// VoIScoreInput. The seam ADR-0026's own "no Jev yet" note names for a future
// fast typed model or in-search evaluator; ExactVoIScorer is the only
// implementation this package ships.
type VoIScorer interface {
	Score(in VoIScoreInput) VoICandidate
}

// exactVoIScorer is the one-step-exact scorer (see file doc comment).
type exactVoIScorer struct{}

// ExactVoIScorer returns the deterministic, exact-arithmetic VoIScorer this
// package ships (ADR-0026: "One-step-exact per node").
func ExactVoIScorer() VoIScorer { return exactVoIScorer{} }

func (exactVoIScorer) Score(in VoIScoreInput) VoICandidate {
	infoGain := binaryEntropy(in.Confidence) * float64(1+in.Connectivity)
	surprise := 0.0
	if in.Surprised {
		surprise = surpriseBoost
	}
	resourceCost, riskCost := voiCosts(in.Kind)
	stake := voiNeutralStakePrior
	if in.HasStake {
		stake = in.Confidence
	}
	// Reputation is taken as given: the caller (voi_plan.go) resolves it,
	// supplying voiNeutralReputationPrior when no technique×environment key
	// is known yet. A zero here is trusted as a genuine "never works here",
	// not silently replaced — masking it would hide a real, informative belief.
	value := (infoGain + surprise) / (resourceCost + riskCost) * in.Reputation * stake
	return VoICandidate{
		Kind:         in.Kind,
		RefID:        in.RefID,
		InfoGain:     infoGain,
		Surprise:     surprise,
		ResourceCost: resourceCost,
		RiskCost:     riskCost,
		Reputation:   in.Reputation,
		Stake:        stake,
		Value:        value,
	}
}

// voiCosts returns kind's (resourceCost, riskCost) — a simple, documented
// placeholder pending real BudgetSystem / RoE integration (see file doc
// comment). Both are always strictly positive, so Score never divides by zero.
func voiCosts(kind VoICandidateKind) (resourceCost, riskCost float64) {
	if kind == VoICandidateHypothesis {
		return voiHypothesisTestResourceCost, voiHypothesisTestRiskCost
	}
	return voiEvidenceMoveResourceCost, voiEvidenceMoveRiskCost
}

// binaryEntropy is the Shannon entropy (bits) of a Bernoulli(p) variable: 0 at
// p=0 or p=1 (certain), 1 at p=0.5 (maximally uncertain). p outside [0,1] is
// treated as certain (entropy 0) rather than producing NaN — a defensive
// floor, not a modeling claim; every caller in this package supplies a belief
// probability, which is always in range by construction.
func binaryEntropy(p float64) float64 {
	if p <= 0 || p >= 1 {
		return 0
	}
	return -(p*math.Log2(p) + (1-p)*math.Log2(1-p))
}
