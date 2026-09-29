// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"sort"
	"strconv"

	"gonum.org/v1/gonum/stat/distuv"

	"github.com/zeroroot-ai/gibson/internal/engine/brain/beliefvi"
	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

// bamcp.go is gibson#396 (ADR-0026 decision 4/5/6, ADR-0037 decision 4): the
// native Go BAMCP (Bayes-Adaptive Monte Carlo Planning) implementation
// voi_score.go's own doc comment named as future work -- "a genuine BAMCP
// implementation needs a generative belief-network simulator and a
// consumable Dirichlet/Beta posterior from braintrain, neither of which
// exists as data the Go daemon can read yet." This file builds the
// generative simulator (below); the posterior is EdgeStrengthPosterior,
// defaulting to the same uninformative Beta(1,1) prior
// UninformativePriorStrength's mean already stands in for
// (belief_slice_native.go) until braintrain (gibson#395, still open) fits a
// real one -- the day it does, only the EdgeStrengthPosteriorProvider passed
// to NewBAMCPPlanner changes, never this file's rollout/sampling code.
//
// ADR-0026 decision 4 calls for full multi-step sequential planning "off-tick
// ... it plans over the belief network as the simulator, samples promising
// trajectories deep." PlanVoI (voi_plan.go) already computes the one-step-
// exact candidate set VoI dispatch gating gates on (decision 1); BAMCPPlanner
// refines that set's ranking Value into a genuine multi-step, model-
// uncertainty-aware estimate:
//
//  1. Ground the mission's AttackGraph slice into the same noisy-OR structure
//     belief_slice_native.go grounds for exact inference (bamcpGround) --
//     but keep each cross-node cause's edge TYPE, so its strength can be
//     Thompson-sampled from the right posterior instead of read as a fixed
//     number.
//  2. For each candidate, run Config.Simulations independent rollouts: each
//     draws a fresh Thompson sample of every enablement edge's Beta
//     posterior (ADR-0037 decision 4 -- "BAMCP Thompson-samples the full
//     posterior for model-uncertainty planning"), ancestrally samples one
//     entire possible world from the resulting noisy-OR network
//     (bamcpSampleWorld -- the generative simulator), then walks a fixed,
//     Value-ranked sequence of candidates starting from the one under
//     evaluation, accumulating discounted reward (ADR-0026 decision 6:
//     heavily-weighted info-gain shaping plus a terminal bonus for a
//     demonstrated finding).
//  3. Average the Config.Simulations returns into the candidate's
//     PlannedValue, re-rank by it, and truncate to topK -- ADR-0026 decision
//     1's "the planner computes the top-k" is this step.
//
// "Fully Bayesian, no UCB" (ADR-0026): action selection never uses a UCB1
// exploration bonus. Instead every simulation samples ONE full model
// instantiation from the posterior and acts w.r.t. it (bamcpSampleWorld) --
// that IS Thompson sampling, applied at the model-uncertainty layer instead
// of at a tree-policy layer, which is exactly what ADR-0037 decision 4 asks
// the planner to do with the learned posterior.
//
// Determinism (this issue's hard acceptance criterion): every random draw in
// this file flows through the one *rand.Rand a caller passes into Plan,
// built from an explicit seed (never rand/v2's package-level functions,
// never map iteration order -- every map this file builds is walked through
// a sorted key list before it drives a decision). The same (VoIPlanInput,
// seed) pair therefore always produces the exact same rollouts and the same
// final ranking; see bamcp_test.go's determinism tests.

// Named, justified rollout constants (never a bare literal in the rollout
// loop itself -- every one is a BAMCPConfig field with a documented default
// below).
const (
	// DefaultBAMCPSimulations is the number of Monte Carlo rollouts averaged
	// per root candidate. BAMCP's model uncertainty comes entirely from the
	// Thompson-sampled edge posteriors (there is no UCB bonus to smooth
	// noise, ADR-0026), so enough rollouts must run to average that sampling
	// noise out; a few hundred is the range Bayes-Adaptive MCP literature
	// reports for a branching factor this small (the ambient-bounded slice,
	// at most a few dozen candidates) converging comfortably, while staying
	// cheap enough that VoIWorker's off-tick ticker (voi_planner.go) never
	// falls behind the next evidence change.
	DefaultBAMCPSimulations = 200

	// DefaultBAMCPDepth bounds how many candidates one rollout resolves
	// after (and including) its root action -- the planning horizon ADR-0026
	// decision 4 calls "a receding horizon." 3 matches the depth of the
	// seed belief chain this codebase grounds today (Host's
	// reachable -> exploitable -> juicy is 3 variables deep,
	// belief_slice_native.go) -- deep enough for a rollout to see a root
	// action's consequence propagate through a full chain, without paying
	// for a horizon that will already be stale by the next evidence-driven
	// re-plan (VoIGateSystem re-fires on every changed evidence cursor).
	DefaultBAMCPDepth = 3

	// DefaultBAMCPDiscount is the per-step reward discount (gamma).
	// ADR-0026 decision 6 asks for "a long horizon" balanced against
	// "it commits" -- 0.9 keeps a reward 3 steps out (DefaultBAMCPDepth)
	// worth 0.9^3 ~= 73% of an immediate one: distant reward still counts
	// for a lot, without letting an arbitrarily deep hypothetical step
	// dominate the root comparison over a real, immediate one.
	DefaultBAMCPDiscount = 0.9

	// DefaultBAMCPTerminalReward is the bonus a rollout step earns when its
	// candidate's simulated outcome resolves true -- ADR-0026 decision 6's
	// "terminal reward for a demonstrated finding" (ADR-0027 proof-of-
	// demonstration, gibson repo numbering). It is set well above a typical
	// one-step VoICandidate.Value (an entropy-bits-per-cost ratio, small and
	// bounded in practice) so a rollout that actually resolves a finding
	// outranks one that only ever accrues shaping reward -- "exploration-
	// dominant but it commits."
	DefaultBAMCPTerminalReward = 10.0

	// DefaultBAMCPInfoGainWeight heavily weights the one-step VoICandidate
	// value (info gain + surprise, voi_score.go) as the rollout's per-step
	// shaping reward -- ADR-0026 decision 6's "heavily-weighted info-gain /
	// novelty shaping." Paired with DefaultBAMCPTerminalReward so that
	// resolving two or three above-average candidates in a row can rival one
	// terminal bonus: exploration is rewarded richly at every step, but a
	// path that reaches a demonstrated finding still wins the ranking.
	DefaultBAMCPInfoGainWeight = 5.0

	// uninformativeBetaAlpha/uninformativeBetaBeta are the cold-start Beta
	// prior parameters BAMCP Thompson-samples for an enablement-edge type
	// braintrain (gibson#395, not yet built) has no fitted posterior for.
	// ADR-0037 decision 3 names Beta(1,1) (uniform) or Jeffreys Beta(1/2,1/2)
	// as the two defensible uninformative choices, both mean 0.5 -- the same
	// mean UninformativePriorStrength already encodes for exact inference
	// (belief_slice_native.go). Beta(1,1) is picked over Jeffreys here
	// specifically because BAMCP SAMPLES this prior on every rollout rather
	// than only reading its mean: Jeffreys is U-shaped (density concentrates
	// near 0 and 1), which would make an untrained edge type's sampled
	// strength swing to the extremes far more often than the flat uniform
	// prior -- the same "no data yet, do not overclaim" caution ADR-0037
	// applies to the mean, extended to the SHAPE of what gets sampled.
	uninformativeBetaAlpha = 1.0
	uninformativeBetaBeta  = 1.0
)

// EdgeStrengthPosterior is the Beta(Alpha, Beta) posterior BAMCP Thompson-
// samples for one enablement-edge TYPE's noisy-OR strength (ADR-0037
// decision 4). Its mean (Alpha/(Alpha+Beta)) is what exact inference
// consumes today via UninformativePriorStrength; BAMCP consumes the whole
// distribution, which is exactly ADR-0037 decision 4's "one output, two
// uses."
type EdgeStrengthPosterior struct {
	Alpha float64
	Beta  float64
}

// sample draws one Thompson sample of p's strength via rng. rng MUST be the
// caller's own explicitly-seeded *rand.Rand -- it is passed as distuv.Beta's
// Src verbatim, never left nil (which would fall back to a global,
// non-reproducible source), so a fixed seed reproduces the exact same drawn
// strength on every call.
func (p EdgeStrengthPosterior) sample(rng *rand.Rand) float64 {
	return distuv.Beta{Alpha: p.Alpha, Beta: p.Beta, Src: rng}.Rand()
}

// EdgeStrengthPosteriorProvider supplies BAMCP's per-edge-type Beta
// posterior. UninformativeEdgePosteriors is the only implementation this
// package ships until braintrain (gibson#395) fits real per-type posteriors
// from recorded outcomes -- see this file's own doc comment for why swapping
// it in later touches only NewBAMCPPlanner's caller, never the rollout code.
type EdgeStrengthPosteriorProvider interface {
	Posterior(edgeType string) EdgeStrengthPosterior
}

// UninformativeEdgePosteriors is the cold-start EdgeStrengthPosteriorProvider:
// every edge type, known or not, gets the same uninformative Beta(1,1) prior
// (ADR-0037 decision 3).
type UninformativeEdgePosteriors struct{}

// Posterior implements EdgeStrengthPosteriorProvider.
func (UninformativeEdgePosteriors) Posterior(string) EdgeStrengthPosterior {
	return EdgeStrengthPosterior{Alpha: uninformativeBetaAlpha, Beta: uninformativeBetaBeta}
}

// BAMCPConfig names every tunable of a BAMCP rollout (ADR-0026 decisions 4
// and 6). See the Default* constants above for each field's justification;
// DefaultBAMCPConfig returns the values this package ships wired with
// (internal/server/daemon/belief_provider.go).
type BAMCPConfig struct {
	// Simulations is the number of Monte Carlo rollouts averaged per root
	// candidate.
	Simulations int
	// Depth bounds how many candidates one rollout resolves, including its
	// root action -- the planning horizon.
	Depth int
	// Discount is the per-step reward discount (gamma), in (0, 1].
	Discount float64
	// TerminalReward is the bonus a rollout step earns when its candidate's
	// simulated outcome resolves true.
	TerminalReward float64
	// InfoGainWeight scales the one-step VoICandidate.Value used as the
	// rollout's per-step shaping reward.
	InfoGainWeight float64
}

// DefaultBAMCPConfig returns the package's documented default tuning.
func DefaultBAMCPConfig() BAMCPConfig {
	return BAMCPConfig{
		Simulations:    DefaultBAMCPSimulations,
		Depth:          DefaultBAMCPDepth,
		Discount:       DefaultBAMCPDiscount,
		TerminalReward: DefaultBAMCPTerminalReward,
		InfoGainWeight: DefaultBAMCPInfoGainWeight,
	}
}

// sanitized returns cfg with every non-positive/out-of-range field replaced
// by its Default* constant -- defensive against a caller building a
// BAMCPConfig{} zero value directly instead of through DefaultBAMCPConfig,
// the same nil-default discipline NewVoIWorker already applies to its own
// optional catalog/hierarchy parameters.
func (cfg BAMCPConfig) sanitized() BAMCPConfig {
	if cfg.Simulations <= 0 {
		cfg.Simulations = DefaultBAMCPSimulations
	}
	if cfg.Depth <= 0 {
		cfg.Depth = DefaultBAMCPDepth
	}
	if cfg.Discount <= 0 || cfg.Discount > 1 {
		cfg.Discount = DefaultBAMCPDiscount
	}
	if cfg.TerminalReward <= 0 {
		cfg.TerminalReward = DefaultBAMCPTerminalReward
	}
	if cfg.InfoGainWeight <= 0 {
		cfg.InfoGainWeight = DefaultBAMCPInfoGainWeight
	}
	return cfg
}

// BAMCPPlanner is the native Go BAMCP implementation (ADR-0026 decision 4):
// it refines PlanVoI's one-step-exact candidate ranking into a multi-step,
// model-uncertainty-aware one. gibson#396's scope is the planner itself,
// seeded and deterministic; refusing dispatch outside its ranked top-k output
// is gibson#397's hard top-k enforcement (decider.go's voiGatedDispatch,
// reading the VoIPlanState this planner's output is folded into — voi_planner.go),
// not built here.
type BAMCPPlanner struct {
	Registry   *ontology.BeliefSchemaRegistry
	Posteriors EdgeStrengthPosteriorProvider
	Config     BAMCPConfig
}

// NewBAMCPPlanner builds a planner. registry must not be nil -- it is the
// same belief-PRM schema belief_slice_native.go grounds against, and BAMCP
// needs it to know which enablement edges feed which target variable.
// posteriors nil defaults to UninformativeEdgePosteriors (the cold start
// every edge type gets until braintrain, gibson#395, fits real ones).
func NewBAMCPPlanner(registry *ontology.BeliefSchemaRegistry, posteriors EdgeStrengthPosteriorProvider, cfg BAMCPConfig) *BAMCPPlanner {
	if posteriors == nil {
		posteriors = UninformativeEdgePosteriors{}
	}
	return &BAMCPPlanner{Registry: registry, Posteriors: posteriors, Config: cfg.sanitized()}
}

// BAMCPSeed derives the RNG seed for one mission's planning round from its
// MissionID and evidence Cursor -- both already durable, replayable facts
// (VoIPlanRequested/VoIPlanState, voi_planner.go), so this seed is always
// exactly reproducible from state the Timeline already records without a new
// persisted field: the same (missionID, cursor) pair -- whether recomputed
// during a live re-plan, in a test, or while replaying a mission's history --
// always yields the same seed, and Plan is otherwise a pure function of its
// inputs (see bamcp_test.go's determinism tests), so the same seed always
// reproduces the exact same rollouts. FNV-1a is used only as a stable,
// dependency-free string hash, never as a cryptographic property.
func BAMCPSeed(missionID string, cursor int) uint64 {
	h := fnv.New64a()
	_, _ = fmt.Fprintf(h, "%s#%d", missionID, cursor)
	return h.Sum64()
}

// Plan computes in's one-step candidate set (PlanVoI, unbounded) and refines
// each candidate's ranking Value into a BAMCP multi-step estimate, seeded
// from seed so the same (in, seed) pair always reproduces the identical
// rollouts and therefore an identical ranking. It returns the same
// []VoICandidate shape voi_planner.go already Submits as VoIPlanned --
// re-ranked and truncated to topK, which IS ADR-0026 decision 1's "the
// planner computes the top-k" now that this planner exists.
func (p *BAMCPPlanner) Plan(ctx context.Context, in VoIPlanInput, substrate BeliefSubstrate, scorer VoIScorer, topK int, seed uint64) ([]VoICandidate, error) {
	candidates, err := PlanVoI(ctx, in, substrate, scorer, 0)
	if err != nil {
		return nil, fmt.Errorf("bamcp: one-step candidate set: %w", err)
	}
	if len(candidates) == 0 {
		return candidates, nil
	}

	hypothesisOutcomeProb, err := p.hypothesisOutcomeProbs(ctx, in, substrate)
	if err != nil {
		return nil, err
	}

	nodeKind := make(map[string]string, len(in.Graph.Nodes))
	for _, n := range in.Graph.Nodes {
		nodeKind[n.ID] = n.Kind
	}

	vars := bamcpGround(in.Graph, p.Registry)
	order := bamcpTopoOrder(vars)

	cfg := p.Config.sanitized()
	depth := cfg.Depth
	if depth > len(candidates) {
		depth = len(candidates)
	}

	rng := rand.New(rand.NewPCG(seed, seed)) //nolint:gosec // deterministic seeded PRNG is required for reproducible BAMCP rollouts, not security-sensitive

	out := make([]VoICandidate, len(candidates))
	copy(out, candidates)
	for root := range candidates {
		seq := bamcpRolloutSequence(candidates, root, depth)
		var total float64
		for range cfg.Simulations {
			realized := bamcpSampleWorld(vars, order, p.Posteriors, rng)
			total += bamcpRolloutReturn(cfg, seq, candidates, nodeKind, hypothesisOutcomeProb, p.Registry, realized, rng)
		}
		out[root].Value = total / float64(cfg.Simulations)
	}

	sortVoICandidates(out)
	if topK > 0 && len(out) > topK {
		out = out[:topK]
	}
	return out, nil
}

// hypothesisOutcomeProbs resolves every candidate hypothesis's current claim
// confidence ONCE (not per-simulation, to keep the substrate off the hot
// rollout loop) -- the exact same resolution PlanVoI's own hypothesis loop
// performs (voi_plan.go), duplicated here rather than threaded through
// VoICandidate because a rollout needs the raw confidence (a Bernoulli
// success probability) as its generative outcome model, not the info-gain
// value PlanVoI derives from it.
func (p *BAMCPPlanner) hypothesisOutcomeProbs(ctx context.Context, in VoIPlanInput, substrate BeliefSubstrate) (map[string]float64, error) {
	out := make(map[string]float64, len(in.Hypotheses))
	for _, hyp := range in.Hypotheses {
		id := strconv.FormatUint(hyp.ID, 10)
		confidence := voiUnstakedConfidence
		nb, ok, err := substrate.Belief(ctx, hypothesisClaimRef(in.Tenant, id))
		if err != nil {
			return nil, fmt.Errorf("bamcp: read claim belief for hypothesis %s: %w", id, err)
		}
		if ok {
			confidence = nb.Belief.Exploitable
		}
		out[id] = confidence
	}
	return out, nil
}

// bamcpRolloutSequence is the rollout/default policy for one root candidate:
// itself first, then every other candidate in PlanVoI's own stable one-step
// ranking order (candidates is already sorted by descending Value --
// sortVoICandidates, called inside PlanVoI), truncated to depth. Fixing the
// policy this way (rather than re-scoring it per simulation) is a deliberate,
// documented simplification (see bamcp.go's file doc comment): the
// stochastic element BAMCP needs -- model uncertainty -- lives entirely in
// bamcpSampleWorld's Thompson-sampled world, not in the policy that walks it.
func bamcpRolloutSequence(candidates []VoICandidate, root, depth int) []int {
	seq := make([]int, 0, depth)
	seq = append(seq, root)
	for i := range candidates {
		if len(seq) >= depth {
			break
		}
		if i == root {
			continue
		}
		seq = append(seq, i)
	}
	return seq
}

// bamcpRolloutReturn walks seq (bamcpRolloutSequence's fixed policy) over one
// already-sampled possible world (realized, from bamcpSampleWorld), summing
// discounted reward: InfoGainWeight * the candidate's one-step VoICandidate
// value (ADR-0026 decision 6's heavily-weighted shaping term) plus
// TerminalReward when this rollout's sampled outcome for that candidate
// resolves true (the terminal, demonstrated-finding bonus).
func bamcpRolloutReturn(
	cfg BAMCPConfig,
	seq []int,
	candidates []VoICandidate,
	nodeKind map[string]string,
	hypothesisOutcomeProb map[string]float64,
	registry *ontology.BeliefSchemaRegistry,
	realized map[string]bool,
	rng *rand.Rand,
) float64 {
	var total float64
	discount := 1.0
	for _, idx := range seq {
		c := candidates[idx]
		reward := cfg.InfoGainWeight * c.Value
		if bamcpOutcome(c, nodeKind, hypothesisOutcomeProb, registry, realized, rng) {
			reward += cfg.TerminalReward
		}
		total += discount * reward
		discount *= cfg.Discount
	}
	return total
}

// bamcpOutcome reports whether candidate c's move "resolves true" in this
// rollout's sampled world: for an evidence move, whether any of its node's
// terminal belief variables (terminalVariables, belief_slice_native.go) was
// ancestrally sampled true; for a hypothesis, a fresh Bernoulli draw against
// its pre-resolved claim confidence (hypothesisOutcomeProbs) -- a hypothesis
// names no node in the grounded AttackGraph, so it has nothing for
// bamcpSampleWorld to have realized, and is resolved directly instead.
func bamcpOutcome(
	c VoICandidate,
	nodeKind map[string]string,
	hypothesisOutcomeProb map[string]float64,
	registry *ontology.BeliefSchemaRegistry,
	realized map[string]bool,
	rng *rand.Rand,
) bool {
	switch c.Kind {
	case VoICandidateEvidence:
		kind := nodeKind[c.RefID]
		for _, v := range terminalVariables(registry, kind) {
			gname, err := beliefvi.GroundName(c.RefID, v)
			if err != nil {
				continue
			}
			if realized[gname] {
				return true
			}
		}
		return false
	case VoICandidateHypothesis:
		return rng.Float64() < hypothesisOutcomeProb[c.RefID]
	default:
		return false
	}
}

// bamcpVar is one grounded belief variable, ready for ancestral (generative)
// sampling: its ground name, its fixed-strength intra-node causes (ADR-0037
// scopes the learned posterior to ENABLEMENT edges only, so an intra-node
// DependsOn parent keeps UninformativePriorStrength here exactly as
// groundAttackGraph already gives it for exact inference), and its cross-node
// enablement causes, each still carrying its edge TYPE so bamcpSampleWorld
// can Thompson-sample the right posterior for it.
type bamcpVar struct {
	Name        string
	Leak        float64
	IntraCauses []bamcpIntraCause
	EdgeCauses  []bamcpEdgeCause
}

// bamcpIntraCause is one intra-node noisy-OR cause: ground parent name plus
// its fixed structural strength.
type bamcpIntraCause struct {
	Parent   string
	Strength float64
}

// bamcpEdgeCause is one cross-node enablement cause: ground parent name plus
// the edge TYPE whose Beta posterior bamcpSampleWorld Thompson-samples for
// its strength on every rollout.
type bamcpEdgeCause struct {
	Parent   string
	EdgeType string
}

// bamcpGround mirrors groundAttackGraph (belief_slice_native.go) exactly in
// structure -- same nodes, same intra-node DependsOn chains, same "From
// node's own terminal variable(s) cause the declared target variable"
// enablement-edge semantics -- except it keeps each enablement cause's edge
// TYPE instead of collapsing it to a fixed Strength number, since BAMCP needs
// the type to Thompson-sample a posterior per rollout rather than read one
// fixed value. An edge whose target variable the destination node does not
// declare, or whose type the registry does not flag as an enablement edge, is
// skipped -- the same graceful-degradation groundAttackGraph already
// documents, deliberately duplicated rather than shared: sharing would mean
// changing EnablementCause's own shape (beliefvi) to carry a type it has no
// other use for.
func bamcpGround(graph AttackGraph, registry *ontology.BeliefSchemaRegistry) []bamcpVar {
	nodeVariables := make(map[string]map[string]struct{}, len(graph.Nodes))
	nodeKind := make(map[string]string, len(graph.Nodes))
	byName := make(map[string]*bamcpVar)

	for _, n := range graph.Nodes {
		names := make(map[string]struct{}, len(n.Variables))
		for _, v := range n.Variables {
			names[v.Name] = struct{}{}
		}
		nodeVariables[n.ID] = names
		nodeKind[n.ID] = n.Kind

		for _, v := range n.Variables {
			gname, err := beliefvi.GroundName(n.ID, v.Name)
			if err != nil {
				continue
			}
			bv := &bamcpVar{Name: gname, Leak: UninformativePriorStrength}
			for _, parent := range v.DependsOn {
				pname, err := beliefvi.GroundName(n.ID, parent)
				if err != nil {
					continue
				}
				bv.IntraCauses = append(bv.IntraCauses, bamcpIntraCause{Parent: pname, Strength: UninformativePriorStrength})
			}
			byName[gname] = bv
		}
	}

	for _, e := range graph.Edges {
		targetVar, ok := registry.EnablementEdgeTargetVariable(e.Type)
		if !ok {
			continue
		}
		if _, declared := nodeVariables[e.To][targetVar]; !declared {
			continue
		}
		tgname, err := beliefvi.GroundName(e.To, targetVar)
		if err != nil {
			continue
		}
		bv, ok := byName[tgname]
		if !ok {
			continue
		}
		for _, sourceVar := range terminalVariables(registry, nodeKind[e.From]) {
			sgname, err := beliefvi.GroundName(e.From, sourceVar)
			if err != nil {
				continue
			}
			bv.EdgeCauses = append(bv.EdgeCauses, bamcpEdgeCause{Parent: sgname, EdgeType: e.Type})
		}
	}

	out := make([]bamcpVar, 0, len(byName))
	for _, bv := range byName {
		sort.Slice(bv.IntraCauses, func(i, j int) bool { return bv.IntraCauses[i].Parent < bv.IntraCauses[j].Parent })
		sort.Slice(bv.EdgeCauses, func(i, j int) bool { return bv.EdgeCauses[i].Parent < bv.EdgeCauses[j].Parent })
		out = append(out, *bv)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// bamcpTopoOrder returns vars' ground names in a deterministic topological
// order (parents before children, over both IntraCauses and EdgeCauses),
// breaking every tie by the lexicographically smallest ready name -- so the
// order depends only on the grounded structure, never on map iteration or
// slice insertion order (this file's determinism discipline). A slice this
// package derives an AttackGraph from is already guaranteed acyclic
// (DeriveAttackGraph, belief_attack_graph.go, breaks cycles deterministically
// before grounding ever sees it); if a future caller ever handed this
// function a cyclic input anyway, the vars a cycle strands are appended,
// sorted, at the end, so every var is still sampled exactly once rather than
// panicking or looping forever.
func bamcpTopoOrder(vars []bamcpVar) []string {
	remaining := make(map[string]int, len(vars))
	names := make([]string, 0, len(vars))
	for _, v := range vars {
		remaining[v.Name] = len(v.IntraCauses) + len(v.EdgeCauses)
		names = append(names, v.Name)
	}
	sort.Strings(names)

	children := make(map[string][]string, len(vars))
	for _, v := range vars {
		for _, c := range v.IntraCauses {
			children[c.Parent] = append(children[c.Parent], v.Name)
		}
		for _, c := range v.EdgeCauses {
			children[c.Parent] = append(children[c.Parent], v.Name)
		}
	}
	for parent := range children {
		sort.Strings(children[parent])
	}

	done := make(map[string]bool, len(names))
	order := make([]string, 0, len(names))
	for len(order) < len(names) {
		progressed := false
		for _, name := range names {
			if done[name] || remaining[name] > 0 {
				continue
			}
			order = append(order, name)
			done[name] = true
			progressed = true
			for _, child := range children[name] {
				remaining[child]--
			}
		}
		if !progressed {
			break
		}
	}
	if len(order) < len(names) {
		for _, name := range names {
			if !done[name] {
				order = append(order, name)
			}
		}
	}
	return order
}

// bamcpSampleWorld draws one Thompson-sampled possible world (ADR-0026
// decision 4/5, ADR-0037 decision 4): every edge cause's strength is drawn
// fresh from posteriors (model uncertainty); every intra-node cause keeps its
// fixed structural strength (see bamcpVar's doc comment). Each variable is
// then sampled by the exact generative process noisy-OR factorizes into
// (beliefvi/noisyor.go's own doc comment): the leak fires independently with
// probability Leak, and each ACTIVE cause independently fires with
// probability its strength; the variable is true iff any of those
// independent draws fires. rng drives every draw in topological order (order,
// from bamcpTopoOrder) so a fixed seed reproduces the exact same world.
func bamcpSampleWorld(vars []bamcpVar, order []string, posteriors EdgeStrengthPosteriorProvider, rng *rand.Rand) map[string]bool {
	byName := make(map[string]bamcpVar, len(vars))
	for _, v := range vars {
		byName[v.Name] = v
	}
	realized := make(map[string]bool, len(vars))
	for _, name := range order {
		v, ok := byName[name]
		if !ok {
			continue
		}
		realized[name] = bamcpSampleVar(v, posteriors, realized, rng)
	}
	return realized
}

// bamcpSampleVar draws one variable's realized boolean state given its
// already-realized parents (realized) -- see bamcpSampleWorld's doc comment
// for the generative process.
func bamcpSampleVar(v bamcpVar, posteriors EdgeStrengthPosteriorProvider, realized map[string]bool, rng *rand.Rand) bool {
	if rng.Float64() < v.Leak {
		return true
	}
	for _, c := range v.IntraCauses {
		if realized[c.Parent] && rng.Float64() < c.Strength {
			return true
		}
	}
	for _, c := range v.EdgeCauses {
		if !realized[c.Parent] {
			continue
		}
		strength := posteriors.Posterior(c.EdgeType).sample(rng)
		if rng.Float64() < strength {
			return true
		}
	}
	return false
}
