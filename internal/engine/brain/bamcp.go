// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"fmt"
	"hash/fnv"
	"math"
	"math/rand/v2"
	"sort"
	"strconv"

	"gonum.org/v1/gonum/stat/distuv"

	"github.com/zeroroot-ai/gibson/internal/engine/brain/beliefvi"
	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

// bamcp.go is gibson#396 (ADR-0126, ADR-0137): the
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
// ADR-0126 calls for multi-step sequential planning off the tick. PlanVoI
// (voi_plan.go) computes the one-step-exact candidate set. BAMCPPlanner turns
// the one-step Value of each candidate into a multi-step estimate that covers
// the uncertainty about the model. It is UCT with root sampling, as the BAMCP
// paper describes (Guez, Silver and Dayan, 2012):
//
//  1. Ground the mission's AttackGraph slice into the same noisy-OR structure
//     belief_slice_native.go grounds for exact inference (bamcpGround) --
//     but keep each cross-node cause's edge TYPE, so its strength can be
//     Thompson-sampled from the right posterior instead of read as a fixed
//     number.
//  2. Run the simulations. Each simulation samples one world at the root: a
//     fresh Thompson sample of every enablement edge's Beta posterior
//     (ADR-0137), one ancestral sample of the noisy-OR network
//     (bamcpSampleWorld), and one outcome for each hypothesis. The world
//     stays fixed for the whole simulation.
//  3. Inside that world, descend the search tree. A tree node is the sequence
//     of candidates taken so far. At a node with an untried candidate, the
//     simulation expands one child. At a node with no untried candidate, it
//     selects the child with the highest UCB1 score. After the expansion it
//     finishes with the rollout policy: the candidates not yet taken, in the
//     order of their one-step Value.
//  4. Back the discounted return up the path. The reward of one step is
//     ADR-0126's info-gain shaping plus a terminal bonus for a demonstrated
//     finding.
//  5. The Value of a candidate is the mean return of the simulations that took
//     it as the first move. Re-rank by it and truncate to topK -- ADR-0126's
//     "the planner computes the top-k" is this step.
//
// The order of the moves matters, and that is why a tree is necessary. A host
// that an enablement edge points at gives its terminal bonus only when the
// trajectory already took one of the hosts that enable it (bamcpTree.unlocked):
// an attack path reaches a host through the host before it. So the best first
// move can be a host with a low one-step Value that opens a host with a high
// one. The one-step rank cannot see that, and the tree can.
//
// The planner is Bayesian about the MODEL and uses UCB1 only for the choice of
// a move inside one sampled world (ADR-0126). The model uncertainty comes from
// the root sample, never from the tree policy.
//
// Determinism (a hard acceptance criterion): every random draw in this file
// flows through the one *rand.Rand that Plan builds from an explicit seed
// (never rand/v2's package-level functions, never map iteration order -- every
// map this file builds is walked through a sorted key list before it drives a
// decision). The tree itself draws nothing: it breaks each tie by the lower
// candidate index. The same (VoIPlanInput, seed) pair therefore always
// produces the exact same simulations and the same final ranking; see
// bamcp_test.go's determinism tests.

// Named, justified rollout constants (never a bare literal in the rollout
// loop itself -- every one is a BAMCPConfig field with a documented default
// below).
const (
	// DefaultBAMCPSimulations is the number of simulations for each root
	// candidate. One planning round runs this number times the number of
	// candidates, and the tree decides which first move each simulation
	// takes. BAMCP's model uncertainty comes from the Thompson-sampled edge
	// posteriors, so enough simulations must run to average that sampling
	// noise out; a few hundred is the range Bayes-Adaptive MCP literature
	// reports for a branching factor this small (the ambient-bounded slice,
	// at most a few dozen candidates) converging comfortably, while staying
	// cheap enough that VoIWorker's off-tick ticker (voi_planner.go) never
	// falls behind the next evidence change.
	DefaultBAMCPSimulations = 200

	// DefaultBAMCPDepth bounds how many candidates one rollout resolves
	// after (and including) its root action -- the planning horizon ADR-0126
	// calls "a receding horizon." 3 matches the depth of the
	// seed belief chain this codebase grounds today (Host's
	// reachable -> exploitable -> juicy is 3 variables deep,
	// belief_slice_native.go) -- deep enough for a rollout to see a root
	// action's consequence propagate through a full chain, without paying
	// for a horizon that will already be stale by the next evidence-driven
	// re-plan (VoIGateSystem re-fires on every changed evidence cursor).
	DefaultBAMCPDepth = 3

	// DefaultBAMCPDiscount is the per-step reward discount (gamma).
	// ADR-0126 asks for "a long horizon" balanced against
	// "it commits" -- 0.9 keeps a reward 3 steps out (DefaultBAMCPDepth)
	// worth 0.9^3 ~= 73% of an immediate one: distant reward still counts
	// for a lot, without letting an arbitrarily deep hypothetical step
	// dominate the root comparison over a real, immediate one.
	DefaultBAMCPDiscount = 0.9

	// DefaultBAMCPTerminalReward is the bonus a rollout step earns when its
	// candidate's simulated outcome resolves true -- ADR-0126's
	// "terminal reward for a demonstrated finding" (ADR-0131 proof-of-
	// demonstration, gibson repo numbering). It is set well above a typical
	// one-step VoICandidate.Value (an entropy-bits-per-cost ratio, small and
	// bounded in practice) so a rollout that actually resolves a finding
	// outranks one that only ever accrues shaping reward -- "exploration-
	// dominant but it commits."
	DefaultBAMCPTerminalReward = 10.0

	// DefaultBAMCPInfoGainWeight heavily weights the one-step VoICandidate
	// value (info gain + surprise, voi_score.go) as the rollout's per-step
	// shaping reward -- ADR-0126's "heavily-weighted info-gain /
	// novelty shaping." Paired with DefaultBAMCPTerminalReward so that
	// resolving two or three above-average candidates in a row can rival one
	// terminal bonus: exploration is rewarded richly at every step, but a
	// path that reaches a demonstrated finding still wins the ranking.
	DefaultBAMCPInfoGainWeight = 5.0

	// DefaultBAMCPExploration is the UCB1 exploration constant c: a child's
	// score is its mean return plus c * sqrt(ln(parent visits) / child
	// visits). UCB1 assumes a return in [0, 1]. A return here is a sum of
	// step rewards, and one step reward is of the size of one terminal
	// reward, so the default equals DefaultBAMCPTerminalReward. A smaller
	// value commits to the first good move sooner. A larger value spends
	// more simulations on moves that look worse.
	DefaultBAMCPExploration = 10.0

	// uninformativeBetaAlpha/uninformativeBetaBeta are the cold-start Beta
	// prior parameters BAMCP Thompson-samples for an enablement-edge type
	// braintrain (gibson#395, not yet built) has no fitted posterior for.
	// ADR-0137 names Beta(1,1) (uniform) or Jeffreys Beta(1/2,1/2)
	// as the two defensible uninformative choices, both mean 0.5 -- the same
	// mean UninformativePriorStrength already encodes for exact inference
	// (belief_slice_native.go). Beta(1,1) is picked over Jeffreys here
	// specifically because BAMCP SAMPLES this prior on every rollout rather
	// than only reading its mean: Jeffreys is U-shaped (density concentrates
	// near 0 and 1), which would make an untrained edge type's sampled
	// strength swing to the extremes far more often than the flat uniform
	// prior -- the same "no data yet, do not overclaim" caution ADR-0137
	// applies to the mean, extended to the SHAPE of what gets sampled.
	uninformativeBetaAlpha = 1.0
	uninformativeBetaBeta  = 1.0
)

// EdgeStrengthPosterior is the Beta(Alpha, Beta) posterior BAMCP Thompson-
// samples for one enablement-edge TYPE's noisy-OR strength (ADR-0137).
// Its mean (Alpha/(Alpha+Beta)) is what exact inference
// consumes today via UninformativePriorStrength; BAMCP consumes the whole
// distribution, which is exactly ADR-0137's "one output, two
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

// Mean returns the posterior's mean, Alpha/(Alpha+Beta) -- the noisy-OR
// strength EXACT inference consumes (belief_slice_native.go's
// groundAttackGraph), the other of ADR-0137's "one output, two
// uses" (sample is the Thompson-sampling use BAMCP's rollouts need). Both
// methods read the SAME posterior; braintrain (gibson#395) fits the one
// artifact both consume.
func (p EdgeStrengthPosterior) Mean() float64 {
	return p.Alpha / (p.Alpha + p.Beta)
}

// EdgeStrengthPosteriorProvider supplies BAMCP's per-edge-type Beta
// posterior. UninformativeEdgePosteriors is the cold-start implementation;
// braintrain.EdgePosteriorArtifact.Provider() (gibson#395) is the fitted one,
// built offline from recorded outcomes -- see this file's own doc comment for
// why swapping it in touches only NewBAMCPPlanner's caller, never the
// rollout code.
type EdgeStrengthPosteriorProvider interface {
	Posterior(edgeType string) EdgeStrengthPosterior
}

// PinnedEdgeStrengthPosteriorProvider is an EdgeStrengthPosteriorProvider
// fitted from a versioned artifact (ADR-0137, gibson#395):
// braintrain's per-tenant edge-posterior artifact, versioned exactly like the
// belief-CPT model (braintrain.NextVersion / braintrain.NextEdgePosteriorVersion).
// NativeSliceBeliefProvider (belief_slice_native.go) accepts this richer
// interface, not the plain EdgeStrengthPosteriorProvider BAMCP uses, because
// it stamps Version() onto every scored node's Belief.Model -- ADR-0134's
// "it is a RECORD, not a selector" discipline, applied to the slice belief
// path: a mission's recorded Timeline events, not a re-loaded file, are what
// replay reproduces from. UninformativeEdgePosteriors does not implement
// this: the cold-start prior has no fitted artifact version to report, which
// is exactly why a nil/absent provider means "no posterior pinned."
type PinnedEdgeStrengthPosteriorProvider interface {
	EdgeStrengthPosteriorProvider
	// Version identifies the fitted artifact this provider's posteriors came
	// from (e.g. "tenant-acme-edges-v3").
	Version() string
}

// UninformativeEdgePosteriors is the cold-start EdgeStrengthPosteriorProvider:
// every edge type, known or not, gets the same uninformative Beta(1,1) prior
// (ADR-0137).
type UninformativeEdgePosteriors struct{}

// Posterior implements EdgeStrengthPosteriorProvider.
func (UninformativeEdgePosteriors) Posterior(string) EdgeStrengthPosterior {
	return EdgeStrengthPosterior{Alpha: uninformativeBetaAlpha, Beta: uninformativeBetaBeta}
}

// BAMCPConfig names every tunable of a BAMCP rollout (ADR-0126
// and 6). See the Default* constants above for each field's justification;
// DefaultBAMCPConfig returns the values this package ships wired with
// (internal/server/daemon/belief_provider.go).
type BAMCPConfig struct {
	// Simulations is the number of simulations for each root candidate. One
	// planning round runs Simulations times the number of candidates.
	Simulations int
	// Depth bounds how many candidates one simulation takes, including its
	// first move -- the planning horizon.
	Depth int
	// Discount is the per-step reward discount (gamma), in (0, 1].
	Discount float64
	// TerminalReward is the bonus a rollout step earns when its candidate's
	// simulated outcome resolves true.
	TerminalReward float64
	// InfoGainWeight scales the one-step VoICandidate.Value used as the
	// rollout's per-step shaping reward.
	InfoGainWeight float64
	// Exploration is the UCB1 exploration constant of the tree policy.
	Exploration float64
}

// DefaultBAMCPConfig returns the package's documented default tuning.
func DefaultBAMCPConfig() BAMCPConfig {
	return BAMCPConfig{
		Simulations:    DefaultBAMCPSimulations,
		Depth:          DefaultBAMCPDepth,
		Discount:       DefaultBAMCPDiscount,
		TerminalReward: DefaultBAMCPTerminalReward,
		InfoGainWeight: DefaultBAMCPInfoGainWeight,
		Exploration:    DefaultBAMCPExploration,
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
	if cfg.Exploration <= 0 {
		cfg.Exploration = DefaultBAMCPExploration
	}
	return cfg
}

// BAMCPPlanner is the native Go BAMCP implementation (ADR-0126):
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
// each candidate's ranking Value into a BAMCP multi-step estimate: the mean
// return of the tree simulations that took the candidate as the first move.
// seed makes the round reproducible: the same (in, seed) pair always gives
// the identical simulations and therefore an identical ranking. It returns the
// same []VoICandidate shape voi_planner.go already Submits as VoIPlanned --
// re-ranked and truncated to topK, which IS ADR-0126's "the planner computes
// the top-k".
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

	vars := bamcpGround(in.Graph, p.Registry)
	order := bamcpTopoOrder(vars)

	cfg := p.Config.sanitized()
	tree := newBAMCPTree(cfg, candidates, in.Graph, p.Registry, hypothesisOutcomeProb)

	rng := rand.New(rand.NewPCG(seed, seed)) //nolint:gosec // deterministic seeded PRNG is required for reproducible BAMCP rollouts, not security-sensitive

	for range cfg.Simulations * len(candidates) {
		// Root sampling: one world for the whole simulation.
		realized := bamcpSampleWorld(vars, order, p.Posteriors, rng)
		tree.sampleOutcomes(realized, rng)
		tree.simulate(tree.root, 0)
	}

	out := make([]VoICandidate, len(candidates))
	copy(out, candidates)
	for i := range out {
		out[i].Value = tree.root.mean(i)
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

// bamcpNode is one node of the search tree: the sequence of candidates that
// the path from the root took. Each slice has one entry for each candidate,
// so the tree needs no map and no iteration order.
type bamcpNode struct {
	visits   int          // simulations that passed through this node
	count    []int        // simulations that took candidate i from this node
	total    []float64    // sum of the returns of those simulations, from this node on
	children []*bamcpNode // the node after candidate i, made when i is taken a second time
}

func newBAMCPNode(candidates int) *bamcpNode {
	return &bamcpNode{
		count:    make([]int, candidates),
		total:    make([]float64, candidates),
		children: make([]*bamcpNode, candidates),
	}
}

// mean returns the mean return of the simulations that took candidate i from
// this node, or 0 when none did.
func (n *bamcpNode) mean(i int) float64 {
	if n.count[i] == 0 {
		return 0
	}
	return n.total[i] / float64(n.count[i])
}

// bamcpTree is the UCT search tree of one planning round, with the state of
// the simulation in progress. candidates is in the order of the one-step
// Value (PlanVoI sorts it), and that order is the rollout policy.
type bamcpTree struct {
	cfg        BAMCPConfig
	candidates []VoICandidate
	depth      int // moves in one simulation: cfg.Depth, or fewer when there are fewer candidates
	root       *bamcpNode

	// terminals[i] holds the ground names of the terminal belief variables of
	// evidence candidate i. The candidate resolves true when one of them is
	// true in the sampled world. Empty for a hypothesis.
	terminals [][]string
	// outcomeProb[i] is the claim confidence of hypothesis candidate i: the
	// probability that its sampled outcome is true. Unused for evidence.
	outcomeProb []float64
	// enablers[i] holds the candidates whose node has an enablement edge to
	// the node of evidence candidate i. See unlocked.
	enablers [][]int

	// The state of the simulation in progress.
	outcome []bool // the root sample: does candidate i resolve true in this world
	taken   []bool // the candidates on the current trajectory
	marked  []int  // scratch of rollout: the candidates that it took
}

func newBAMCPTree(
	cfg BAMCPConfig,
	candidates []VoICandidate,
	graph AttackGraph,
	registry *ontology.BeliefSchemaRegistry,
	hypothesisOutcomeProb map[string]float64,
) *bamcpTree {
	n := len(candidates)
	t := &bamcpTree{
		cfg:         cfg,
		candidates:  candidates,
		depth:       min(cfg.Depth, n),
		root:        newBAMCPNode(n),
		terminals:   make([][]string, n),
		outcomeProb: make([]float64, n),
		enablers:    make([][]int, n),
		outcome:     make([]bool, n),
		taken:       make([]bool, n),
	}

	nodeKind := make(map[string]string, len(graph.Nodes))
	nodeVariables := make(map[string]map[string]struct{}, len(graph.Nodes))
	for _, node := range graph.Nodes {
		nodeKind[node.ID] = node.Kind
		names := make(map[string]struct{}, len(node.Variables))
		for _, v := range node.Variables {
			names[v.Name] = struct{}{}
		}
		nodeVariables[node.ID] = names
	}

	evidenceIndex := make(map[string]int, n)
	for i, c := range candidates {
		switch c.Kind {
		case VoICandidateEvidence:
			evidenceIndex[c.RefID] = i
			for _, v := range terminalVariables(registry, nodeKind[c.RefID]) {
				if gname, err := beliefvi.GroundName(c.RefID, v); err == nil {
					t.terminals[i] = append(t.terminals[i], gname)
				}
			}
		case VoICandidateHypothesis:
			t.outcomeProb[i] = hypothesisOutcomeProb[c.RefID]
		}
	}

	// An edge enables its target under the same two conditions as bamcpGround:
	// the registry names the edge type as an enablement edge, and the target
	// node declares the variable that the edge feeds. graph.Edges is a slice,
	// so the order of each enablers list is the order of the graph.
	for _, e := range graph.Edges {
		targetVar, ok := registry.EnablementEdgeTargetVariable(e.Type)
		if !ok {
			continue
		}
		if _, declared := nodeVariables[e.To][targetVar]; !declared {
			continue
		}
		from, fromIsCandidate := evidenceIndex[e.From]
		to, toIsCandidate := evidenceIndex[e.To]
		if fromIsCandidate && toIsCandidate && from != to {
			t.enablers[to] = append(t.enablers[to], from)
		}
	}
	return t
}

// sampleOutcomes completes the root sample of one simulation: for each
// candidate, does its move resolve true in this world. An evidence move
// resolves true when one of the terminal variables of its node is true in
// realized. A hypothesis names no node in the grounded graph, so its outcome
// is one Bernoulli draw against its claim confidence. The draws run in
// candidate order, so a fixed seed gives the same outcomes.
func (t *bamcpTree) sampleOutcomes(realized map[string]bool, rng *rand.Rand) {
	for i, c := range t.candidates {
		switch c.Kind {
		case VoICandidateEvidence:
			t.outcome[i] = false
			for _, gname := range t.terminals[i] {
				if realized[gname] {
					t.outcome[i] = true
					break
				}
			}
		case VoICandidateHypothesis:
			t.outcome[i] = rng.Float64() < t.outcomeProb[i]
		default:
			t.outcome[i] = false
		}
	}
}

// unlocked reports whether candidate i can give its terminal reward at this
// point of the trajectory. A candidate with no enabler is always unlocked. A
// candidate with enablers is unlocked after the trajectory took one of them:
// an attack path reaches a host through a host that enables it. An enabler
// that is not a candidate does not count, because the planner cannot take it.
func (t *bamcpTree) unlocked(i int) bool {
	if len(t.enablers[i]) == 0 {
		return true
	}
	for _, e := range t.enablers[i] {
		if t.taken[e] {
			return true
		}
	}
	return false
}

// reward is the reward of taking candidate i at this point of the trajectory:
// InfoGainWeight times the one-step Value (ADR-0126's shaping term), plus
// TerminalReward when the candidate resolves true in the sampled world and is
// unlocked (the bonus for a demonstrated finding).
func (t *bamcpTree) reward(i int) float64 {
	r := t.cfg.InfoGainWeight * t.candidates[i].Value
	if t.outcome[i] && t.unlocked(i) {
		r += t.cfg.TerminalReward
	}
	return r
}

// simulate runs one simulation from node, with step moves already taken, and
// returns the discounted return from node on. It takes one move by the tree
// policy (selectMove). The first time a move is taken from a node, the
// simulation leaves the tree and finishes with the rollout policy. The next
// time, it descends into the child of that move, which it makes if necessary:
// each simulation expands the tree by at most one node.
func (t *bamcpTree) simulate(node *bamcpNode, step int) float64 {
	if step >= t.depth {
		return 0
	}
	move := t.selectMove(node)
	firstVisit := node.count[move] == 0

	reward := t.reward(move)
	t.taken[move] = true
	var future float64
	if firstVisit {
		future = t.rollout(step + 1)
	} else {
		if node.children[move] == nil {
			node.children[move] = newBAMCPNode(len(t.candidates))
		}
		future = t.simulate(node.children[move], step+1)
	}
	t.taken[move] = false

	ret := reward + t.cfg.Discount*future
	node.visits++
	node.count[move]++
	node.total[move] += ret
	return ret
}

// selectMove is the tree policy. It returns the first untried candidate in
// the order of the one-step Value. When each candidate that is still free was
// tried, it returns the one with the highest UCB1 score:
//
//	mean return + Exploration * sqrt(ln(node visits) / move visits)
//
// A tie goes to the lower index, so the choice needs no random draw. The
// caller makes sure that one candidate is free (step < depth <= candidates).
func (t *bamcpTree) selectMove(node *bamcpNode) int {
	for i := range t.candidates {
		if !t.taken[i] && node.count[i] == 0 {
			return i
		}
	}
	best, bestScore := -1, 0.0
	logVisits := math.Log(float64(node.visits))
	for i := range t.candidates {
		if t.taken[i] {
			continue
		}
		score := node.mean(i) + t.cfg.Exploration*math.Sqrt(logVisits/float64(node.count[i]))
		if best == -1 || score > bestScore {
			best, bestScore = i, score
		}
	}
	return best
}

// rollout is the rollout policy: from step on, take the candidates that are
// still free in the order of their one-step Value, up to the depth. It returns
// the discounted return and leaves the trajectory as it found it.
func (t *bamcpTree) rollout(step int) float64 {
	var total float64
	discount := 1.0
	marked := t.marked[:0]
	for i := range t.candidates {
		if step >= t.depth {
			break
		}
		if t.taken[i] {
			continue
		}
		total += discount * t.reward(i)
		discount *= t.cfg.Discount
		t.taken[i] = true
		marked = append(marked, i)
		step++
	}
	for _, i := range marked {
		t.taken[i] = false
	}
	t.marked = marked
	return total
}

// bamcpVar is one grounded belief variable, ready for ancestral (generative)
// sampling: its ground name, its fixed-strength intra-node causes (ADR-0137
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

// bamcpSampleWorld draws one Thompson-sampled possible world (ADR-0126,
// ADR-0137): every edge cause's strength is drawn
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
