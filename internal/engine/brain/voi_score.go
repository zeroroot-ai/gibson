// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "math"

// voi_score.go is the ONE-STEP-EXACT value-of-information scorer ADR-0126
// describes: value = (goal-relative info gain + surprise) / (resource cost +
// risk cost) × reputation × stake — for a SINGLE candidate move, computed
// exactly (no sampling), never a multi-step lookahead.
//
// The multi-step part is the BAMCP planner in bamcp.go. It starts from the
// one-step values of this file and grows a search tree over them. VoIScorer is
// the seam a different scorer plugs into without a change to the gate or the
// worker around it.
//
// The two costs come from the mission (gibson#695, ADR-0126):
//
//   - The resource cost scales with the budget that the mission has left. A
//     mission with its full budget pays the base cost. A mission that spent a
//     part of its budget pays the base cost divided by the part that is left.
//   - The risk cost is higher for a candidate that the code marks as
//     destructive: a hypothesis whose technique has a destructive predicate in
//     an enabled Domain Pack (ADR-0132).

// Tunable constants. Reputation and stake priors are the "optimism under
// uncertainty" ADR-0126 calls for: no data yet means "do not penalize", not
// "assume the worst" — VoI must be able to DRIVE a fleet's first bet on a
// hypothesis, not merely re-rank already-staked ones.
const (
	// DefaultVoITopK is the default number of top-ranked candidates VoIPlan
	// keeps (ADR-0126: "VoI gates to top-k").
	DefaultVoITopK = 10

	// The base costs are the costs of a mission with its full budget and a
	// candidate with no destructive mark.
	voiEvidenceMoveResourceCost   = 1.0 // an evidence move is the cheapest action
	voiHypothesisTestResourceCost = 2.0 // pursuing a hypothesis is an active probe/bet
	voiEvidenceMoveRiskCost       = 0.5
	voiHypothesisTestRiskCost     = 1.0

	// voiDestructiveRiskMultiplier scales the risk cost of a candidate with
	// the destructive mark. 4 puts the risk of a destructive test above its
	// resource cost at a full budget, so the planner prefers a test with no
	// mark unless the destructive one gives clearly more information.
	voiDestructiveRiskMultiplier = 4.0

	// voiMaxBudgetSpent caps the spent part of the budget that the resource
	// cost uses. The resource cost is the base cost divided by the part that
	// is left, so the cap keeps the cost finite: at most 20 times the base.
	// BudgetSystem stops a mission that passes its budget. The planner only
	// prices the approach to that limit.
	voiMaxBudgetSpent = 0.95

	// voiNeutralReputationPrior is used when a candidate names no resolvable
	// technique×environment key yet (every candidate, today — see voi_plan.go).
	voiNeutralReputationPrior = 1.0
	// voiNeutralStakePrior is used for a hypothesis nobody has bet on yet.
	voiNeutralStakePrior = 1.0
	// voiUnstakedConfidence is the entropy input for an unstaked hypothesis:
	// maximal uncertainty (no bet has narrowed it at all).
	voiUnstakedConfidence = 0.5
)

// VoIBudget is the budget state of one mission, as the planner costs against
// it. The limits come from Mission.Budget and the use comes from the World:
// the dispatch attempts of the mission's work and its token count, the same
// two numbers that BudgetSystem enforces (budget.go). A zero limit means that
// the mission has no limit on that dimension.
type VoIBudget struct {
	MaxExecutions int
	Executions    int
	MaxTokens     int64
	TokensUsed    int64
}

// SpentFraction returns the spent part of the budget, in [0, 1]. It is the
// larger of the two dimensions, because the mission stops when either limit is
// reached. A mission with no limit has spent 0.
func (b VoIBudget) SpentFraction() float64 {
	spent := 0.0
	if b.MaxExecutions > 0 {
		spent = math.Max(spent, float64(b.Executions)/float64(b.MaxExecutions))
	}
	if b.MaxTokens > 0 {
		spent = math.Max(spent, float64(b.TokensUsed)/float64(b.MaxTokens))
	}
	return math.Min(math.Max(spent, 0), 1)
}

// VoICandidateKind distinguishes the two candidate shapes ADR-0126 names.
// Both are scored on one scale; they are not costed identically.
type VoICandidateKind string

const (
	// VoICandidateHypothesis is an open hypothesis to test. Pursuing it IS
	// placing/raising a bet on it (ADR-0122/ADR-0129).
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
	// (DeriveAttackGraph, gibson#286) — ADR-0126's "juiciness ×
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
	// (ADR-0129), or voiNeutralReputationPrior when no technique×
	// environment key is resolvable yet.
	Reputation float64
	// BudgetSpent is the spent part of the mission budget, in [0, 1]
	// (VoIBudget.SpentFraction). 0 means a full budget or no limit.
	BudgetSpent float64
	// Destructive reports that the code marks this candidate as destructive:
	// a hypothesis whose technique has a destructive predicate in an enabled
	// Domain Pack. Always false for an evidence move.
	Destructive bool
}

// VoICandidate is one scored candidate with its full value breakdown recorded
// — never just the final number — so a plan is auditable and its ranking is
// reproducible from the same recorded inputs (ADR-0126: "exact,
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
	// Destructive records the destructive mark that RiskCost was computed
	// with, so the plan shows why the risk cost of this candidate is higher.
	Destructive bool

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
	// bridge resolved for this candidate (ADR-0135, gibson#387):
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
// VoIScoreInput. The seam ADR-0126's own "no Jev yet" note names for a future
// fast typed model or in-search evaluator; ExactVoIScorer is the only
// implementation this package ships.
type VoIScorer interface {
	Score(in VoIScoreInput) VoICandidate
}

// exactVoIScorer is the one-step-exact scorer (see file doc comment).
type exactVoIScorer struct{}

// ExactVoIScorer returns the deterministic, exact-arithmetic VoIScorer this
// package ships (ADR-0126: "One-step-exact per node").
func ExactVoIScorer() VoIScorer { return exactVoIScorer{} }

func (exactVoIScorer) Score(in VoIScoreInput) VoICandidate {
	infoGain := binaryEntropy(in.Confidence) * float64(1+in.Connectivity)
	surprise := 0.0
	if in.Surprised {
		surprise = surpriseBoost
	}
	resourceCost, riskCost := voiCosts(in.Kind, in.BudgetSpent, in.Destructive)
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
		Destructive:  in.Destructive,
	}
}

// voiCosts returns the resource cost and the risk cost of one candidate.
//
// The resource cost is the base cost of the kind, divided by the part of the
// mission budget that is left. budgetSpent is the spent part, capped at
// voiMaxBudgetSpent. The risk cost is the base risk of the kind, times
// voiDestructiveRiskMultiplier for a candidate with the destructive mark.
// Both are always strictly positive, so Score never divides by zero.
func voiCosts(kind VoICandidateKind, budgetSpent float64, destructive bool) (resourceCost, riskCost float64) {
	resourceCost, riskCost = voiEvidenceMoveResourceCost, voiEvidenceMoveRiskCost
	if kind == VoICandidateHypothesis {
		resourceCost, riskCost = voiHypothesisTestResourceCost, voiHypothesisTestRiskCost
	}
	spent := math.Min(math.Max(budgetSpent, 0), voiMaxBudgetSpent)
	resourceCost /= 1 - spent
	if destructive {
		riskCost *= voiDestructiveRiskMultiplier
	}
	return resourceCost, riskCost
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
