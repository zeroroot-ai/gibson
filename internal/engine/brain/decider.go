package brain

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/mlange-42/ark/ecs"
)

// decider.go is the LLM decision loop (ADR-0001/0004, CONTEXT.md). It fits a slow
// LLM call to the ~50ms tick by the async-by-observation pattern:
//
//   - DeciderGateSystem (mechanical, in-tick, quiescent) emits a DecisionRequested
//     for a goal mission when new evidence has landed and no decision is in flight
//     (one in-flight decision per mission).
//   - DeciderWorker (off-tick, like the dispatch handler) consumes DecisionRequested
//     via a live tap, serializes the own-mission slice + capability catalog, calls
//     the DeciderLLM, and Submits the resulting decisions as events.
//
// The brain stays LLM-client-free: DeciderLLM is an interface; the concrete
// tenant-provider binding is daemon-side (wired at the cutover, gibson#851).

// Capability is a catalog entry the Decider may dispatch (CONTEXT.md: capability
// vs execution). Supplied by the daemon from the enrolled component registry.
type Capability struct {
	Kind        string // agent | tool | plugin
	Name        string
	Description string
	InputSchema string // for tools/plugins (gibson#848); empty for agents
}

// DeciderSlot names the LLM the Decider runs on (gibson#850): the mission-level
// slot, distinct from worker node slots. Empty fields mean "use the tenant's
// dashboard-default provider/model" — the concrete DeciderLLM resolves it.
type DeciderSlot struct {
	Provider string
	Model    string
}

// MissionContext is the serialized own-mission slice the Decider reasons over
// (gibson#847: own mission only; no belief #750, no ambient #749, no siblings).
type MissionContext struct {
	MissionID    string
	Goal         string
	Work         []WorkSnapshot
	Findings     []FindingSnapshot
	Hosts        []HostSnapshot // ambient-projected: top-attention + anomalies (gibson#749)
	OmittedHosts int            // lower-relevance hosts summarized away (LOD periphery)
	Capabilities []Capability
	DeciderSlot  DeciderSlot // which LLM to decide with (gibson#850)
}

// quiescent reports whether the mission has no work still running or dispatchable.
func (mc MissionContext) quiescent() bool {
	for _, wi := range mc.Work {
		if wi.State == WorkRunning || wi.State == WorkPending {
			return false
		}
	}
	return true
}

// DeciderDispatch is one re-invocation the Decider chose. Input is a free-text
// task goal for an agent, or **structured JSON** for a tool/plugin (gibson#848):
// the tool's input shaped to its schema, or {"method":...,"params":{...}} for a
// plugin. Structured inputs are validated before dispatch (see validateDispatch);
// proto-conformance + LLM repair is the concrete DeciderLLM's job (daemon-side).
type DeciderDispatch struct {
	Kind   string // agent | tool | plugin
	Target string // capability name
	Input  string // task goal (agent) or structured JSON (tool/plugin)
}

// DeciderComplete ends the mission. Outcome "failed" → MissionFailed, else completed.
type DeciderComplete struct {
	Outcome string
	Reason  string
}

// DeciderOutput is the Decider's decision for one invocation.
type DeciderOutput struct {
	Dispatches []DeciderDispatch
	Complete   *DeciderComplete
}

// DeciderLLM turns a MissionContext into a decision. Implementations call the
// tenant's provider; the brain depends only on this interface.
type DeciderLLM interface {
	Decide(ctx context.Context, mc MissionContext) (DeciderOutput, error)
}

// DecisionRequested asks for a Decider decision on a goal mission. The reducer
// marks the mission's decision in flight (one at a time) and records the evidence
// cursor at request time.
type DecisionRequested struct {
	MissionID string
	Cursor    int
}

func (DecisionRequested) Kind() string { return "decision.requested" }

// DecisionCompleted clears the in-flight decision once the worker has Submitted
// its resulting events.
type DecisionCompleted struct {
	MissionID string
}

func (DecisionCompleted) Kind() string { return "decision.completed" }

// Decision is a folded record of one Decider decision episode for a goal mission
// (gibson#1062) — the read-only projection the mission-run World frame surfaces as
// "what the brain chose to do next, and why" (PRD #1059 M2, user story #8). It is
// opened by a DecisionRequested event (the gate asked for a decision given the
// evidence so far) and closed by a DecisionCompleted event once the off-tick
// Decider worker has Submitted its choices. Between the two, the work the Decider
// dispatched is recorded as Dispatches, and a decision that ends the mission
// carries the completion reason as Rationale. It introduces no new event kind —
// it is a projection over the existing decision / dispatch / mission-done events,
// so the read-only-projection invariant (ADR-0001) holds.
type DecisionRecord struct {
	ID         string // deterministic per mission: "<MissionID>#d<ordinal>"
	MissionID  string
	Cursor     int                // evidence cursor at request time (its position in the run)
	Status     string             // "pending" (in flight) | "completed"
	Dispatches []DecisionDispatch // the work the Decider chose to dispatch in this episode
	Outcome    string             // mission outcome if the decision ended the mission ("" otherwise)
	Rationale  string             // the completion reason, where present
}

// DecisionDispatch is one action a Decider decision chose: the WorkItem it
// dispatched. The matching WorkItem carries its own lifecycle; this is the
// decision→work linkage.
type DecisionDispatch struct {
	WorkID string
	Kind   string
	Target string
}

const (
	decisionPending   = "pending"
	decisionCompleted = "completed"
)

// findOpenDecision returns the mission's currently-open (pending) decision, if any.
// The gate enforces one in-flight decision per mission, so there is at most one.
func findOpenDecision(w *World, missionID string) (ecs.Entity, bool) {
	q := ecs.NewFilter1[DecisionRecord](w.ecs).Query()
	for q.Next() {
		d := q.Get()
		if d.MissionID == missionID && d.Status == decisionPending {
			e := q.Entity()
			q.Close()
			return e, true
		}
	}
	return ecs.Entity{}, false
}

// countMissionDecisions returns how many decisions the mission already has folded,
// so a new episode gets a stable, replay-deterministic ordinal in its id.
func countMissionDecisions(w *World, missionID string) int {
	n := 0
	q := ecs.NewFilter1[DecisionRecord](w.ecs).Query()
	for q.Next() {
		if q.Get().MissionID == missionID {
			n++
		}
	}
	return n
}

// recordDecisionDispatch links a dispatched WorkItem to the mission's open
// decision, if one is in flight (gibson#1062) — the Decider's chosen action. A
// CUE/scheduler dispatch with no decision in flight is a no-op.
func recordDecisionDispatch(w *World, missionID string, d DecisionDispatch) {
	if missionID == "" {
		return
	}
	if ent, ok := findOpenDecision(w, missionID); ok {
		dec := w.decisions.Get(ent)
		dec.Dispatches = append(dec.Dispatches, d)
	}
}

func applyDecisionRequested(w *World, e DecisionRequested) {
	if ent, ok := findMission(w, e.MissionID); ok {
		m := w.missions.Get(ent)
		m.DecisionInFlight = true
		m.DecisionCursor = e.Cursor
	}
	// Open a decision episode (gibson#1062). The gate guarantees no decision is
	// already in flight for this mission, so this always starts a fresh one.
	ordinal := countMissionDecisions(w, e.MissionID) + 1
	w.decisions.NewEntity(&DecisionRecord{
		ID:        fmt.Sprintf("%s#d%d", e.MissionID, ordinal),
		MissionID: e.MissionID,
		Cursor:    e.Cursor,
		Status:    decisionPending,
	})
}

func applyDecisionCompleted(w *World, e DecisionCompleted) {
	if ent, ok := findMission(w, e.MissionID); ok {
		w.missions.Get(ent).DecisionInFlight = false
	}
	if ent, ok := findOpenDecision(w, e.MissionID); ok {
		w.decisions.Get(ent).Status = decisionCompleted
	}
}

// DecisionSnapshot is a stable, comparable view of a Decision.
type DecisionSnapshot struct {
	ID         string
	MissionID  string
	Cursor     int
	Status     string
	Dispatches []DecisionDispatch
	Outcome    string
	Rationale  string
}

// DecisionSnapshot returns the folded Decider decisions in deterministic (id)
// order (gibson#1062).
func (w *World) DecisionSnapshot() []DecisionSnapshot {
	var out []DecisionSnapshot
	q := ecs.NewFilter1[DecisionRecord](w.ecs).Query()
	for q.Next() {
		d := q.Get()
		out = append(out, DecisionSnapshot{
			ID:         d.ID,
			MissionID:  d.MissionID,
			Cursor:     d.Cursor,
			Status:     d.Status,
			Dispatches: append([]DecisionDispatch(nil), d.Dispatches...),
			Outcome:    d.Outcome,
			Rationale:  d.Rationale,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// terminalWorkCount returns the number of terminal (done/failed/skipped) work
// items for a mission — the evidence cursor.
func terminalWorkCount(work []WorkSnapshot, missionID string) int {
	n := 0
	for _, wi := range work {
		if wi.MissionID != missionID {
			continue
		}
		switch wi.State {
		case WorkDone, WorkFailed, WorkSkipped:
			n++
		}
	}
	return n
}

// DeciderGateSystem requests a decision for each goal mission that has new
// evidence and no decision in flight. Quiescent: once DecisionRequested is
// applied (in flight), it won't re-fire until the worker clears it and new
// evidence (a changed terminal-work count) appears.
func DeciderGateSystem(w *World) []Event {
	work := w.WorkSnapshot()
	var out []Event
	for _, m := range w.MissionSnapshot() {
		if m.Status != MissionRunning || m.Goal == "" || m.DecisionInFlight {
			continue
		}
		terminal := terminalWorkCount(work, m.ID)
		if m.DecisionCursor == -1 || terminal != m.DecisionCursor {
			out = append(out, DecisionRequested{MissionID: m.ID, Cursor: terminal})
		}
	}
	return out
}

// DeciderWorker drives the off-tick LLM decision. Tap buffers DecisionRequested
// (live); Drain reads the World, calls the LLM, and Submits the decisions.
type DeciderWorker struct {
	eng     *Engine
	llm     DeciderLLM
	catalog func() []Capability // enrolled capabilities (daemon-supplied)

	mu      sync.Mutex
	pending []string // mission ids awaiting a decision
	seq     int      // monotonic id suffix for dispatched executions
}

// NewDeciderWorker builds a worker. catalog may be nil (no capabilities offered).
func NewDeciderWorker(eng *Engine, llm DeciderLLM, catalog func() []Capability) *DeciderWorker {
	if catalog == nil {
		catalog = func() []Capability { return nil }
	}
	return &DeciderWorker{eng: eng, llm: llm, catalog: catalog}
}

// Tap is the engine subscriber (in-tick, no I/O): buffer the mission id.
func (dw *DeciderWorker) Tap(ev Event) {
	if r, ok := ev.(DecisionRequested); ok {
		dw.mu.Lock()
		dw.pending = append(dw.pending, r.MissionID)
		dw.mu.Unlock()
	}
}

// Drain processes all buffered decision requests off the tick. Returns the count
// processed.
func (dw *DeciderWorker) Drain(ctx context.Context) int {
	dw.mu.Lock()
	ids := dw.pending
	dw.pending = nil
	dw.mu.Unlock()

	for _, missionID := range ids {
		dw.decide(ctx, missionID)
	}
	return len(ids)
}

func (dw *DeciderWorker) decide(ctx context.Context, missionID string) {
	mc := dw.buildContext(missionID)

	out, err := dw.llm.Decide(ctx, mc)
	// Validate/filter dispatches against the catalog before acting: an agent/tool/
	// plugin the Decider hallucinated, or a tool/plugin with non-JSON structured
	// input, is dropped so garbage never reaches dispatch (gibson#848).
	var valid []DeciderDispatch
	if err == nil {
		for _, d := range out.Dispatches {
			if validateDispatch(d, mc.Capabilities) {
				valid = append(valid, d)
			}
		}
	}

	var evs []Event
	switch {
	case err != nil:
		// A failed decision does not kill the mission; clear in-flight and let the
		// gate retry on the next evidence change. (A persistent failure is bounded
		// by the budget System, gibson#849.)
	case out.Complete != nil:
		evs = append(evs, missionDoneFrom(missionID, *out.Complete))
	case len(valid) > 0:
		for _, d := range valid {
			evs = append(evs, dw.dispatchEvent(missionID, d))
		}
	default:
		// No actionable dispatch (empty, or all rejected). On a quiescent mission
		// (nothing left running/pending), that is terminal — the Decider has nothing
		// more to do (CONTEXT.md).
		if mc.quiescent() {
			evs = append(evs, MissionDone{ID: missionID, Outcome: MissionCompleted, Reason: "decider: goal resolved, nothing left to do"})
		}
	}
	evs = append(evs, DecisionCompleted{MissionID: missionID})
	for _, e := range evs {
		dw.eng.Submit(e)
	}
}

// validateDispatch rejects a dispatch the brain can't safely actuate: an unknown
// capability (kind+name not in the catalog), or a tool/plugin whose structured
// Input is not valid JSON. Agents take free-text input, so only catalog
// membership is checked. (Full proto-schema conformance + LLM repair is the
// concrete DeciderLLM's responsibility, daemon-side.)
func validateDispatch(d DeciderDispatch, catalog []Capability) bool {
	known := false
	for _, c := range catalog {
		if c.Kind == d.Kind && c.Name == d.Target {
			known = true
			break
		}
	}
	if !known {
		return false
	}
	if d.Kind == "tool" || d.Kind == "plugin" {
		return json.Valid([]byte(d.Input))
	}
	return true
}

func (dw *DeciderWorker) dispatchEvent(missionID string, d DeciderDispatch) Event {
	dw.mu.Lock()
	dw.seq++
	id := fmt.Sprintf("%s-dec-%d", missionID, dw.seq)
	dw.mu.Unlock()
	return WorkDispatched{ID: id, MissionID: missionID, ItemKind: d.Kind, Target: d.Target, Input: d.Input}
}

func missionDoneFrom(missionID string, c DeciderComplete) MissionDone {
	outcome := MissionCompleted
	if c.Outcome == "failed" {
		outcome = MissionFailed
	}
	reason := c.Reason
	if reason == "" {
		reason = "decider"
	}
	return MissionDone{ID: missionID, Outcome: outcome, Reason: reason}
}

// buildContext reads the own-mission slice off the tick (engine read-locked).
func (dw *DeciderWorker) buildContext(missionID string) MissionContext {
	mc := MissionContext{MissionID: missionID, Capabilities: dw.catalog()}
	for _, m := range dw.eng.Missions() {
		if m.ID == missionID {
			mc.Goal = m.Goal
			mc.DeciderSlot = m.DeciderSlot
			break
		}
	}
	for _, wi := range dw.eng.Work() {
		if wi.MissionID == missionID {
			mc.Work = append(mc.Work, wi)
		}
	}
	mc.Findings = dw.eng.Findings()
	// Ambient projection (gibson#749): curate the relevant host slice to the
	// context budget — top-attention + the anomaly channel; periphery summarized.
	mc.Hosts, mc.OmittedHosts = dw.eng.AmbientHosts(deciderHostBudget)
	return mc
}
