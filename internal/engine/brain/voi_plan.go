// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"fmt"
	"sort"
	"strconv"

	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// voi_plan.go gathers candidates (ADR-0126: an open hypothesis to test, or
// an evidence move on a high-uncertainty node — both bounded to the ambient
// slice), resolves each one's VoIScoreInput from the belief substrate, scores
// them (voi_score.go), and ranks/truncates to the top-k. PlanVoI is a pure
// function of its inputs (aside from substrate reads): no World/Engine access
// of its own, so it is directly testable and does not care whether its
// caller is a live worker (voi_planner.go) or a test.
//
// Reputation (ADR-0126, ADR-0129's technique×environment view) is wired
// end to end (gibson#267): resolveReputation reads NodeKindTechniqueEnvironment
// belief through the SAME BeliefSubstrate the market view uses, keyed by each
// hypothesis's own Technique × ScopeID (TechniqueEnvironmentRef) — the key the
// reputation write loop (reputation_worker.go) updates when a bet settles. It
// feeds BOTH places ADR-0122 names: a new hypothesis's prior P(claim valid)
// starts from its technique's track record (ReadReputation, AC3), and pursuit
// priority is multiplied by that reputation (resolveReputation, AC4). A
// hypothesis that names no technique, and a bare evidence move, both resolve to
// the neutral prior exactly as before, so untracked candidates are unchanged.
//
// The technique -> capability bridge (ADR-0135, gibson#387) IS
// wired here: each candidate's Technique (carried from Hypothesis.Technique,
// gibson#353/sdk#88 — empty for an evidence move, which names none) is
// resolved against in.Capabilities via CapabilitiesForTechnique
// (voi_dispatch.go), which rolls the technique up to its taxonomy category
// through in.Hierarchy (gibson#379's TechniqueHierarchy.CategoryOf) rather
// than through any separate reconciliation table (ADR-0135). This
// only RESOLVES the covering capabilities onto VoICandidate.
// CoveringCapabilities — it does not gate or refuse a dispatch itself. Ranking
// candidates by a deep multi-step plan is gibson#396's BAMCP planner
// (bamcp.go); turning the resolved coverage into an actual dispatch refusal is
// gibson#397's hard top-k enforcement (decider.go's voiGatedDispatch), both
// built on this file.

// VoIPlanInput bundles what PlanVoI needs for one mission's candidate set,
// gathered once by the caller (voi_planner.go's worker, or a test).
type VoIPlanInput struct {
	// Hosts should already be ambient-projected (AmbientHosts) — bounded to
	// the ambient slice, per ADR-0126.
	Hosts []HostSnapshot
	// Hypotheses is the candidate hypothesis set — typically scope-filtered
	// by the caller to the mission's own scope.
	Hypotheses []HypothesisSnapshot
	// Graph is the current attack graph (DeriveAttackGraph, gibson#286),
	// used only for each candidate's Connectivity.
	Graph AttackGraph
	// Tenant scopes a hypothesis's claim-node lookup exactly the way
	// harness.claimNodeRef scopes a placed bet's write.
	Tenant string
	// Capabilities is the mission's enrolled capability catalog (the same
	// shape decider.go's MissionContext.Capabilities carries) — the set
	// CapabilitiesForTechnique resolves each candidate's covering
	// capabilities against. Nil means no catalog was supplied: every
	// candidate's CoveringCapabilities resolves to nil, the same "nothing to
	// gate against" shape an empty catalog would produce.
	Capabilities []Capability
	// Hierarchy is the taxonomy technique hierarchy (gibson#379) used to roll
	// a candidate's Technique up to its category (ADR-0135). Nil
	// means no hierarchy was supplied: CapabilitiesForTechnique then resolves
	// no covering capabilities at all for any candidate (see its own doc
	// comment) — it still never panics.
	Hierarchy *taxonomy.TechniqueHierarchy
	// Budget is the budget state of the mission. The resource cost of each
	// candidate scales with the part that is left (voi_score.go). The zero
	// value is a mission with no limit.
	Budget VoIBudget
	// DestructiveTechniques names each technique whose predicate an enabled
	// Domain Pack marks as destructive (ADR-0132). A hypothesis candidate
	// with one of these techniques gets the higher risk cost. Nil means that
	// no technique has the mark.
	DestructiveTechniques map[string]bool
}

// PlanVoI scores every candidate in in (evidence moves from Hosts, test moves
// from Hypotheses), ranks them by descending Value (ties broken by Kind then
// RefID — the same stable-id tiebreak gibson#286/#287 use), and truncates to
// the topK highest. topK <= 0 means "no bound", matching AmbientProjection's
// own budget convention.
func PlanVoI(ctx context.Context, in VoIPlanInput, substrate BeliefSubstrate, scorer VoIScorer, topK int) ([]VoICandidate, error) {
	degree := attackGraphDegree(in.Graph)
	budgetSpent := in.Budget.SpentFraction()

	candidates := make([]VoICandidate, 0, len(in.Hosts)+len(in.Hypotheses))

	for _, h := range in.Hosts {
		id := HostNodeID(h.ID)
		// "" : a bare evidence move names no technique — see resolveReputation.
		reputation, err := resolveReputation(ctx, substrate, "")
		if err != nil {
			return nil, err
		}
		// An evidence move names no technique (see the "" above), so it has
		// nothing for CapabilitiesForTechnique to resolve — Technique and
		// CoveringCapabilities stay at their zero value (empty/nil).
		candidates = append(candidates, scorer.Score(VoIScoreInput{
			Kind:         VoICandidateEvidence,
			RefID:        id,
			Confidence:   h.Belief.Juicy,
			Connectivity: degree[id],
			Surprised:    h.Surprise != "",
			Reputation:   reputation,
			BudgetSpent:  budgetSpent,
		}))
	}

	for _, hyp := range in.Hypotheses {
		id := strconv.FormatUint(hyp.ID, 10)
		ref := hypothesisClaimRef(in.Tenant, id)
		nb, ok, err := substrate.Belief(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("voi plan: read claim belief for hypothesis %s: %w", id, err)
		}
		// A new hypothesis of a technique with a track record starts from that
		// technique×environment reputation as its prior P(claim valid), rather
		// than the flat max-uncertainty default — "reputation raises the prior
		// on new hypotheses of that technique" (gibson#267 AC3). ReadReputation
		// returns DefaultReputationPrior (== voiUnstakedConfidence) when the
		// technique has no track record, so an untracked or technique-less
		// hypothesis keeps exactly today's behavior. A placed bet's own staked
		// confidence (ok) still overrides this prior — the market has spoken for
		// THIS hypothesis.
		unstakedPrior := voiUnstakedConfidence
		reputationKey := ""
		if hyp.Technique != "" {
			reputationKey = TechniqueEnvironmentRef(in.Tenant, hyp.Technique, hyp.ScopeID).ID
			prior, _, rerr := ReadReputation(ctx, in.Tenant, hyp.Technique, hyp.ScopeID, substrate)
			if rerr != nil {
				return nil, rerr
			}
			unstakedPrior = prior
		}
		confidence := unstakedPrior
		if ok {
			confidence = nb.Belief.Exploitable
		}
		// Pursuit priority reflects the technique×environment reputation
		// (gibson#267 AC4): a hypothesis of a higher-reputation technique
		// outranks a lower-reputation one, all else equal. An empty key (a
		// hypothesis naming no technique) resolves to the neutral prior, exactly
		// as before.
		reputation, err := resolveReputation(ctx, substrate, reputationKey)
		if err != nil {
			return nil, err
		}
		c := scorer.Score(VoIScoreInput{
			Kind:         VoICandidateHypothesis,
			RefID:        id,
			Confidence:   confidence,
			Connectivity: len(hyp.References),
			HasStake:     ok,
			Reputation:   reputation,
			BudgetSpent:  budgetSpent,
			Destructive:  hyp.Technique != "" && in.DestructiveTechniques[hyp.Technique],
		})
		// VoI dispatch gating's technique -> capability bridge (ADR-0135,
		// gibson#387): resolve this candidate's covering
		// capabilities from its source Hypothesis's technique. hyp.Technique
		// is "" when the proposing agent never set one, which
		// CapabilitiesForTechnique already treats as "nothing to resolve".
		c.Technique = hyp.Technique
		c.CoveringCapabilities = capabilityRefs(CapabilitiesForTechnique(in.Hierarchy, hyp.Technique, in.Capabilities))
		candidates = append(candidates, c)
	}

	sortVoICandidates(candidates)
	if topK > 0 && len(candidates) > topK {
		candidates = candidates[:topK]
	}
	return candidates, nil
}

// hypothesisClaimRef addresses a hypothesis's claim-node — MUST match
// harness.claimNodeRef's convention exactly (tenant + "/" + hypothesis id),
// since both read/write the same BeliefSubstrate entry. Duplicated here
// rather than imported: claimNodeRef is unexported in a different package
// (internal/engine/harness), and brain must not depend on harness.
func hypothesisClaimRef(tenant, hypothesisID string) NodeRef {
	return NodeRef{Kind: NodeKindClaim, ID: tenant + "/" + hypothesisID}
}

// resolveReputation reads technique×environment belief (ADR-0129:
// "P(technique works here)", the same Belief.Exploitable convention
// harness.PlaceBet uses for a claim-node's P(claim valid)) through substrate,
// as the pursuit-priority multiplier (gibson#267 AC4). An empty key or no
// recorded belief both resolve to the neutral optimism-under-uncertainty prior
// (ADR-0126): a technique with a track record is weighted by it, while one
// without is neither rewarded nor penalized.
func resolveReputation(ctx context.Context, substrate BeliefSubstrate, techniqueEnvKey string) (float64, error) {
	if techniqueEnvKey == "" {
		return voiNeutralReputationPrior, nil
	}
	nb, ok, err := substrate.Belief(ctx, NodeRef{Kind: NodeKindTechniqueEnvironment, ID: techniqueEnvKey})
	if err != nil {
		return 0, fmt.Errorf("voi plan: read reputation for %s: %w", techniqueEnvKey, err)
	}
	if !ok {
		return voiNeutralReputationPrior, nil
	}
	return nb.Belief.Exploitable, nil
}

// sortVoICandidates ranks candidates by descending Value, ties broken by
// (Kind, RefID) — a total order, so the ranking never depends on input order.
func sortVoICandidates(c []VoICandidate) {
	sort.SliceStable(c, func(i, j int) bool {
		if c[i].Value != c[j].Value {
			return c[i].Value > c[j].Value
		}
		if c[i].Kind != c[j].Kind {
			return c[i].Kind < c[j].Kind
		}
		return c[i].RefID < c[j].RefID
	})
}

// attackGraphDegree returns every node's degree (in + out) in g — ADR-0126's
// "connectivity" input. A node absent from g has degree 0, the common
// case for a host that no relationship of the World links to a second host.
func attackGraphDegree(g AttackGraph) map[string]int {
	degree := make(map[string]int, len(g.Nodes))
	for _, e := range g.Edges {
		degree[e.From]++
		degree[e.To]++
	}
	return degree
}
