// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/mlange-42/ark/ecs"
	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// voi_planner.go is gibson#283's gate/worker layer: it makes voi_plan.go's
// PlanVoI LIVE against a running Engine, off the ~50ms tick, exactly mirroring
// decider.go's own gate/worker split (DeciderGateSystem/DeciderWorker) —
// ADR-0126's "off-tick", "recorded and replayable" requirements.
//
//   - VoIGateSystem (mechanical, in-tick, quiescent) emits a VoIPlanRequested
//     for a running goal mission when new evidence has landed and no plan is
//     already in flight for it — the same "one in-flight episode per mission,
//     re-fire only on a changed evidence cursor" discipline DeciderGateSystem
//     uses, applied to planning instead of dispatch.
//   - VoIWorker (off-tick) consumes VoIPlanRequested via a live tap, builds a
//     VoIPlanInput from the engine's live ambient hosts + hypotheses + attack
//     graph, calls PlanVoI, and Submits the ranked result as VoIPlanned.
//
// "Sequential planning via the closed loop" (ADR-0126, and the overseer's
// explicit scope: "one-step-exact per node, sequence via the closed loop") is
// this gate/worker cycle itself: every evidence change re-triggers a fresh
// one-step-exact plan, rather than an internal multi-step search tree.
//
// What this file deliberately does NOT do (see voi_score.go/voi_plan.go for
// the rest of the scope ledger): it does not dispatch anything. VoIPlanState
// records the ranked top-k candidates for a mission — the "choice" AC3 asks
// to be "recorded and replayable" — and each candidate now also carries its
// resolved CoveringCapabilities (ADR-0135, gibson#387's
// technique -> capability bridge, wired through catalog/hierarchy below), the
// mapping from a VoICandidate to the dispatchable capabilities that can
// address it. Refining that ranking into a multi-step plan is gibson#396's
// BAMCP planner (bamcp.go); refusing a DeciderDispatch outside the VoI top-k
// is gibson#397's hard top-k enforcement (decider.go's voiGatedDispatch),
// which reads the VoIPlanState this file folds — not this file's own job; this
// one makes the ranked, capability-resolved plan a first-class, replayable
// fact on the World, which is the seam #397's gate reads from.

// VoIPlanState is the per-mission VoI planning record: whether a plan is
// currently being computed (in flight), the evidence cursor it was requested
// against, and the last completed plan's ranked, top-k candidates. It is a
// standalone component (like DecisionRecord), never a field on Mission —
// Mission is shared state every lane's Systems touch, and VoI planning is
// this slice's own concern.
type VoIPlanState struct {
	MissionID  string
	InFlight   bool
	Cursor     int // evidence cursor (terminalWorkCount) this plan answers for
	Candidates []VoICandidate
}

// VoIPlanRequested asks for a VoI plan on a goal mission. The reducer marks
// the mission's plan in flight and records the evidence cursor at request
// time — mirrors DecisionRequested exactly.
type VoIPlanRequested struct {
	MissionID string
	Cursor    int
}

// Kind identifies the voi.plan.requested brain event.
func (VoIPlanRequested) Kind() string { return "voi.plan.requested" }

// VoIPlanned records a completed VoI planning round: the ranked, top-k
// candidates PlanVoI produced (nil if the round failed — see VoIWorker.plan).
// Recording the full candidate breakdown, not just a chosen id, is what makes
// the plan auditable and its ranking reproducible from the same recorded
// event on replay (ADR-0126).
type VoIPlanned struct {
	MissionID  string
	Cursor     int
	Candidates []VoICandidate
}

// Kind identifies the voi.plan.completed brain event.
func (VoIPlanned) Kind() string { return "voi.plan.completed" }

// findVoIPlanState returns the mission's VoIPlanState entity, if one has been
// created yet (the gate creates it lazily on first request — a mission with
// no evidence yet has no VoI planning history).
func findVoIPlanState(w *World, missionID string) (ecs.Entity, bool) {
	q := ecs.NewFilter1[VoIPlanState](w.ecs).Query()
	for q.Next() {
		if q.Get().MissionID == missionID {
			e := q.Entity()
			q.Close()
			return e, true
		}
	}
	return ecs.Entity{}, false
}

func applyVoIPlanRequested(w *World, e VoIPlanRequested) {
	ent, ok := findVoIPlanState(w, e.MissionID)
	if !ok {
		ent = w.voiPlans.NewEntity(&VoIPlanState{MissionID: e.MissionID})
	}
	st := w.voiPlans.Get(ent)
	st.InFlight = true
	st.Cursor = e.Cursor
}

func applyVoIPlanned(w *World, e VoIPlanned) {
	ent, ok := findVoIPlanState(w, e.MissionID)
	if !ok {
		// Defensive: a plan for a mission the gate never requested (should not
		// happen in practice — VoIWorker only plans missions it Tapped a
		// request for). Recorded anyway so the completed round is never lost.
		ent = w.voiPlans.NewEntity(&VoIPlanState{MissionID: e.MissionID})
	}
	st := w.voiPlans.Get(ent)
	st.InFlight = false
	st.Candidates = e.Candidates
}

// VoIPlanSnapshot is a stable, comparable view of a VoIPlanState.
type VoIPlanSnapshot struct {
	MissionID  string
	InFlight   bool
	Cursor     int
	Candidates []VoICandidate
}

// VoIPlanSnapshot returns every mission's current VoI plan state in
// deterministic (MissionID) order.
func (w *World) VoIPlanSnapshot() []VoIPlanSnapshot {
	var out []VoIPlanSnapshot
	q := ecs.NewFilter1[VoIPlanState](w.ecs).Query()
	for q.Next() {
		st := q.Get()
		out = append(out, VoIPlanSnapshot{
			MissionID:  st.MissionID,
			InFlight:   st.InFlight,
			Cursor:     st.Cursor,
			Candidates: append([]VoICandidate(nil), st.Candidates...),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MissionID < out[j].MissionID })
	return out
}

// VoIGateSystem requests a VoI plan for each running goal mission that has new
// evidence and no plan already in flight. Quiescent, mirroring
// DeciderGateSystem: once VoIPlanRequested is applied (in flight), it will not
// re-fire until the worker clears it (VoIPlanned) and new evidence (a changed
// terminal-work count) appears.
func VoIGateSystem(w *World) []Event {
	work := w.WorkSnapshot()
	states := make(map[string]VoIPlanSnapshot, len(work))
	for _, st := range w.VoIPlanSnapshot() {
		states[st.MissionID] = st
	}

	var out []Event
	for _, m := range w.MissionSnapshot() {
		if m.Status != MissionRunning || m.Goal == "" {
			continue
		}
		st, ok := states[m.ID]
		if ok && st.InFlight {
			continue
		}
		terminal := terminalWorkCount(work, m.ID)
		if !ok || terminal != st.Cursor {
			out = append(out, VoIPlanRequested{MissionID: m.ID, Cursor: terminal})
		}
	}
	return out
}

// VoIWorker drives off-tick VoI planning: Tap buffers VoIPlanRequested (live,
// no I/O); Drain reads the World's live ambient state, calls PlanVoI, and
// Submits the ranked result.
type VoIWorker struct {
	eng       *Engine
	substrate BeliefSubstrate
	registry  *ontology.BeliefSchemaRegistry
	scorer    VoIScorer
	topK      int
	// catalog returns the mission's enrolled capability catalog (the same
	// shape ExecutorDeps.Catalog supplies to DeciderWorker) — the set VoI
	// dispatch gating's technique -> capability bridge resolves each
	// candidate's CoveringCapabilities against (ADR-0135,
	// gibson#387). Never nil (NewVoIWorker defaults it).
	catalog func(missionID string) []Capability
	// hierarchy is the taxonomy technique hierarchy a candidate's Technique
	// rolls up through (gibson#379's TechniqueHierarchy.CategoryOf). Never
	// nil (NewVoIWorker defaults it to taxonomy.GlobalTechniques, the same
	// default brainExecutor.agentCoverage uses to validate a capability's own
	// declared coverage).
	hierarchy *taxonomy.TechniqueHierarchy
	// bamcp is the native BAMCP planner (ADR-0126, gibson#396)
	// that refines PlanVoI's one-step candidate ranking into a multi-step,
	// model-uncertainty-aware one before it is Submitted. Never nil
	// (NewVoIWorker defaults it via NewBAMCPPlanner) — ADR-0126 names BAMCP
	// as the planner, not an optional refinement, so there is no "off" path.
	bamcp *BAMCPPlanner

	mu      sync.Mutex
	pending []string // mission ids awaiting a plan
}

// NewVoIWorker builds a worker. substrate is typically a WorldBeliefSubstrate
// bound to the same eng (reputation/stake reads must see the live belief
// field); scorer is typically ExactVoIScorer(); topK is typically
// DefaultVoITopK. catalog may be nil (no capabilities offered, matching
// NewDeciderWorker's own convention) — VoI dispatch gating then resolves no
// covering capabilities for any candidate. hierarchy may be nil, which
// defaults to taxonomy.GlobalTechniques. bamcp may be nil, which defaults to
// NewBAMCPPlanner(registry, nil, DefaultBAMCPConfig()) — the same
// uninformative-prior cold start belief_slice_native.go uses until braintrain
// (gibson#395) fits real per-edge-type posteriors.
func NewVoIWorker(
	eng *Engine,
	substrate BeliefSubstrate,
	registry *ontology.BeliefSchemaRegistry,
	scorer VoIScorer,
	topK int,
	catalog func(missionID string) []Capability,
	hierarchy *taxonomy.TechniqueHierarchy,
	bamcp *BAMCPPlanner,
) *VoIWorker {
	if catalog == nil {
		catalog = func(string) []Capability { return nil }
	}
	if hierarchy == nil {
		hierarchy = taxonomy.GlobalTechniques
	}
	if bamcp == nil {
		bamcp = NewBAMCPPlanner(registry, nil, DefaultBAMCPConfig())
	}
	return &VoIWorker{
		eng: eng, substrate: substrate, registry: registry, scorer: scorer, topK: topK,
		catalog: catalog, hierarchy: hierarchy, bamcp: bamcp,
	}
}

// Tap is the engine subscriber (in-tick, no I/O): buffer the mission id.
func (vw *VoIWorker) Tap(ev Event) {
	if r, ok := ev.(VoIPlanRequested); ok {
		vw.mu.Lock()
		vw.pending = append(vw.pending, r.MissionID)
		vw.mu.Unlock()
	}
}

// Drain processes all buffered plan requests off the tick. Returns the count
// processed.
func (vw *VoIWorker) Drain(ctx context.Context) int {
	vw.mu.Lock()
	ids := vw.pending
	vw.pending = nil
	vw.mu.Unlock()

	for _, missionID := range ids {
		vw.plan(ctx, missionID)
	}
	return len(ids)
}

func (vw *VoIWorker) plan(ctx context.Context, missionID string) {
	in := vw.buildInput(missionID)
	seed := BAMCPSeed(missionID, voiPlanCursor(vw.eng.World, missionID))
	candidates, err := vw.bamcp.Plan(ctx, in, vw.substrate, vw.scorer, vw.topK, seed)
	if err != nil {
		// A failed plan does not kill the mission; clear in-flight (with no
		// candidates) and let the gate retry on the next evidence change —
		// the same failure handling DeciderWorker.decide uses for a failed
		// LLM call.
		candidates = nil
	}
	vw.eng.Submit(VoIPlanned{MissionID: missionID, Candidates: candidates})
}

// voiPlanCursor returns missionID's current in-flight evidence cursor from
// w's VoI plan state (set by applyVoIPlanRequested, the same cursor
// VoIGateSystem stamped into the VoIPlanRequested that triggered this round)
// — 0 if the mission has no VoI plan state yet, which should not happen in
// practice (VoIWorker only ever plans a mission it Tapped a request for) but
// is never a panic. This is BAMCPSeed's other input alongside missionID: both
// are already durable, replayable facts, so the seed a live planning round
// uses is always exactly reproducible from state the Timeline already
// records.
func voiPlanCursor(w *World, missionID string) int {
	for _, st := range w.VoIPlanSnapshot() {
		if st.MissionID == missionID {
			return st.Cursor
		}
	}
	return 0
}

// buildInput gathers the mission's ambient-bounded candidate set (ADR-0126):
// the ambient host slice (the same budget/curation the Decider itself
// reads, deciderHostBudget), every hypothesis (mirroring DeciderWorker's own
// Findings() precedent — tenant-wide, since Mission carries no ScopeID to
// filter by), and the current attack graph (DeriveAttackGraph over
// HostsToInfraGraph, gibson#275/#286's live-wiring machinery, reused
// unchanged) — plus the mission's capability catalog and the technique
// hierarchy (vw.catalog/vw.hierarchy), so PlanVoI can resolve each
// candidate's CoveringCapabilities (ADR-0135, gibson#387).
func (vw *VoIWorker) buildInput(missionID string) VoIPlanInput {
	hosts, _ := vw.eng.AmbientHosts(deciderHostBudget)
	nodes := HostsToInfraGraph(hosts)
	graph := DeriveAttackGraph(nodes, nil, vw.registry)
	return VoIPlanInput{
		Hosts:        hosts,
		Hypotheses:   vw.eng.Hypotheses(),
		Graph:        graph,
		Tenant:       vw.eng.World.Tenant,
		Capabilities: vw.catalog(missionID),
		Hierarchy:    vw.hierarchy,
	}
}

// WireVoIPlanner installs VoI planning against eng: VoIGateSystem must already
// be registered as a System (ExecutorSystems, or a test's own AddSystem) —
// this function only starts the off-tick worker and its drain loop, mirroring
// WireExecutor/WireSliceBelief's ticker pattern exactly. interval <= 0 uses
// TickInterval. catalog, hierarchy and bamcp are forwarded to NewVoIWorker
// verbatim (all three may be nil; see its own doc comment).
func WireVoIPlanner(
	ctx context.Context,
	eng *Engine,
	registry *ontology.BeliefSchemaRegistry,
	scorer VoIScorer,
	topK int,
	interval time.Duration,
	catalog func(missionID string) []Capability,
	hierarchy *taxonomy.TechniqueHierarchy,
	bamcp *BAMCPPlanner,
) *VoIWorker {
	if interval <= 0 {
		interval = TickInterval
	}
	substrate := NewWorldBeliefSubstrate(eng)
	worker := NewVoIWorker(eng, substrate, registry, scorer, topK, catalog, hierarchy, bamcp)
	eng.Subscribe(worker.Tap)

	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				// context.WithoutCancel: this final drain must still run after
				// ctx is done (the same shutdown-drain the caller asked for),
				// but it must not inherit ctx's own already-fired
				// cancellation, or the drain's own substrate/PlanVoI calls
				// would fail immediately on ctx.Err() (contextcheck).
				worker.Drain(context.WithoutCancel(ctx))
				return
			case <-t.C:
				worker.Drain(ctx)
			}
		}
	}()

	return worker
}
