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

// voi_plan.go gathers candidates (ADR-0026 §2: an open hypothesis to test, or
// an evidence move on a high-uncertainty node — both bounded to the ambient
// slice), resolves each one's VoIScoreInput from the belief substrate, scores
// them (voi_score.go), and ranks/truncates to the top-k. PlanVoI is a pure
// function of its inputs (aside from substrate reads): no World/Engine access
// of its own, so it is directly testable and does not care whether its
// caller is a live worker (voi_planner.go) or a test.
//
// Reputation (ADR-0026 §3, ADR-0029 §3's technique×environment view) is
// genuinely wired — resolveReputation reads NodeKindTechniqueEnvironment
// belief through the SAME BeliefSubstrate the market view uses — and is
// called live from PlanVoI (the whole-program deadcode gate confirms it:
// wired at epic->main via wireBrainRegistry/WireVoIPlanner). Every candidate
// this file produces still resolves reputation to the neutral prior today,
// though: resolveReputation's technique×environment key stays "" (see its own
// doc comment) — that is a SEPARATE resolution from the technique ->
// capability bridge below, and gibson#347/reputation-by-technique remains
// future work, tracked independently of this file's own #387 scope.
//
// The technique -> capability bridge (ADR-0035 decision 4, gibson#387) IS
// wired here: each candidate's Technique (carried from Hypothesis.Technique,
// gibson#353/sdk#88 — empty for an evidence move, which names none) is
// resolved against in.Capabilities via CapabilitiesForTechnique
// (voi_dispatch.go), which rolls the technique up to its taxonomy category
// through in.Hierarchy (gibson#379's TechniqueHierarchy.CategoryOf) rather
// than through any separate reconciliation table (ADR-0035 decision 2). This
// only RESOLVES the covering capabilities onto VoICandidate.
// CoveringCapabilities — it does not gate or refuse a dispatch itself; that is
// gibson#396's (BAMCP planner) and gibson#397's (hard top-k enforcement) job,
// both blocked on this file.

// VoIPlanInput bundles what PlanVoI needs for one mission's candidate set,
// gathered once by the caller (voi_planner.go's worker, or a test).
type VoIPlanInput struct {
	// Hosts should already be ambient-projected (AmbientHosts) — bounded to
	// the ambient slice, per ADR-0026 §2.
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
	// a candidate's Technique up to its category (ADR-0035 decision 4). Nil
	// means no hierarchy was supplied: CapabilitiesForTechnique then resolves
	// no covering capabilities at all for any candidate (see its own doc
	// comment) — it still never panics.
	Hierarchy *taxonomy.TechniqueHierarchy
}

// PlanVoI scores every candidate in in (evidence moves from Hosts, test moves
// from Hypotheses), ranks them by descending Value (ties broken by Kind then
// RefID — the same stable-id tiebreak gibson#286/#287 use), and truncates to
// the topK highest. topK <= 0 means "no bound", matching AmbientProjection's
// own budget convention.
func PlanVoI(ctx context.Context, in VoIPlanInput, substrate BeliefSubstrate, scorer VoIScorer, topK int) ([]VoICandidate, error) {
	degree := attackGraphDegree(in.Graph)

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
		}))
	}

	for _, hyp := range in.Hypotheses {
		id := strconv.FormatUint(hyp.ID, 10)
		ref := hypothesisClaimRef(in.Tenant, id)
		nb, ok, err := substrate.Belief(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("voi plan: read claim belief for hypothesis %s: %w", id, err)
		}
		confidence := voiUnstakedConfidence
		if ok {
			confidence = nb.Belief.Exploitable
		}
		// "" : no technique×environment key is resolvable from a Hypothesis
		// yet — see file doc comment.
		reputation, err := resolveReputation(ctx, substrate, "")
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
		})
		// VoI dispatch gating's technique -> capability bridge (ADR-0035
		// decision 4, gibson#387): resolve this candidate's covering
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

// resolveReputation reads technique×environment belief (ADR-0029 §3:
// "P(technique works here)", the same Belief.Exploitable convention
// harness.PlaceBet uses for a claim-node's P(claim valid)) through substrate.
// An empty key or no recorded belief both resolve to the neutral
// optimism-under-uncertainty prior (ADR-0026 §6) — not yet reachable from
// PlanVoI today (see file doc comment) but kept as its own function so the
// day a candidate DOES carry a technique×environment key, wiring it in is a
// one-line change here, not a new lookup to invent.
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

// attackGraphDegree returns every node's degree (in + out) in g — ADR-0026
// §3's "connectivity" input. A node absent from g has degree 0, the common
// case while HostsToInfraGraph (gibson#275) still produces an edgeless graph.
func attackGraphDegree(g AttackGraph) map[string]int {
	degree := make(map[string]int, len(g.Nodes))
	for _, e := range g.Edges {
		degree[e.From]++
		degree[e.To]++
	}
	return degree
}
