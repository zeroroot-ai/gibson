package brain

import (
	"sort"

	"github.com/mlange-42/ark/ecs"
)

// MissionStatus is the lifecycle state of a mission.
type MissionStatus string

const (
	MissionRunning   MissionStatus = "running"
	MissionCompleted MissionStatus = "completed"
	MissionFailed    MissionStatus = "failed"
)

// Budget is the per-mission resource ceiling carried from CUE MissionConstraints
// (ADR-0004). It is recorded here at projection; the budget/limit System that
// enforces it (forcing MissionDone{budget_exceeded}) is gibson#849. Zero in any
// field means "unlimited" for that dimension.
type Budget struct {
	MaxExecutions int   // cap on dispatched WorkItems (the runaway guard)
	MaxTokens     int64 // cumulative LLM token budget
}

// Mission is the root work-graph for a launched mission (ADR-0001): the unit of
// identity/goal/accounting. A CUE mission projects into this at launch
// (MissionProjected); a bare MissionStarted seeds the minimal form. A mission
// with an empty Goal is a **no-goal** mission: it runs its scripted graph to
// quiescence and completes mechanically, never invoking the Decider.
type Mission struct {
	ID     string
	Goal   string
	Status MissionStatus
	Reason string // why it completed
	Budget Budget
	// Decider bookkeeping (gibson#847). DecisionInFlight enforces one in-flight
	// decision per mission; DecisionCursor is the count of terminal work items at
	// the last decision request (-1 = never decided) — the gate fires again only
	// when new evidence has landed.
	DecisionInFlight bool
	DecisionCursor   int
	// TokensUsed is the cumulative LLM token spend reported for this mission
	// (TokenUsed events); the budget System (gibson#849) aborts when it exceeds
	// Budget.MaxTokens.
	TokensUsed int64
	// DeciderSlot is the mission-level LLM the Decider runs on (gibson#850); empty
	// → tenant dashboard default.
	DeciderSlot DeciderSlot
}

// MissionStarted launches a mission. (CUE-mission projection lands later; this is
// the minimal launch event.)
type MissionStarted struct {
	ID   string
	Goal string
}

func (MissionStarted) Kind() string { return "mission.started" }

// MissionDone marks a mission terminal with an outcome and reason. Outcome
// defaults to MissionCompleted when empty (back-compat with the minimal launch
// path); the Scheduler emits MissionFailed when the scripted graph stalls on a
// failed node, and the budget System (gibson#849) emits a budget-exceeded stop.
type MissionDone struct {
	ID      string
	Reason  string
	Outcome MissionStatus
}

func (MissionDone) Kind() string { return "mission.done" }

func findMission(w *World, id string) (ecs.Entity, bool) {
	q := ecs.NewFilter1[Mission](w.ecs).Query()
	for q.Next() {
		if q.Get().ID == id {
			e := q.Entity()
			q.Close()
			return e, true
		}
	}
	return ecs.Entity{}, false
}

func applyMissionStarted(w *World, e MissionStarted) {
	if _, ok := findMission(w, e.ID); ok {
		return
	}
	w.missions.NewEntity(&Mission{ID: e.ID, Goal: e.Goal, Status: MissionRunning, DecisionCursor: -1})
}

func applyMissionDone(w *World, e MissionDone) {
	if ent, ok := findMission(w, e.ID); ok {
		m := w.missions.Get(ent)
		if m.Status != MissionRunning {
			return // already terminal — idempotent
		}
		outcome := e.Outcome
		if outcome == "" {
			outcome = MissionCompleted
		}
		m.Status = outcome
		m.Reason = e.Reason
	}
}

// DecisionAction is what the Decider chose to do.
type DecisionAction string

const (
	DecideDispatch DecisionAction = "dispatch"
	DecideComplete DecisionAction = "complete"
)

// Decision is a single orchestration choice (ADR-0001). The Decider produces
// these from the World; the Orchestrator translates them into events. There are
// **no hand-authored decision rules** — a Decider is the policy (the LLM plugs in
// here later); the Orchestrator is the mechanism.
type Decision struct {
	Action     DecisionAction
	MissionID  string
	WorkID     string // dispatch
	WorkKind   string // dispatch: tool|agent|plugin
	WorkTarget string // dispatch
	Reason     string // complete
}

// Decider reasons over the World and returns the next decisions. Implementations
// MUST be quiescent (return nothing when the World already reflects their intent)
// so a tick settles. The LLM-backed Decider is a later slice; the loop is here.
type Decider interface {
	Decide(w *World) []Decision
}

// Orchestrator is the thin per-mission Decider role (ADR-0001): single-shot
// decisions over the World, dispatching work and completing missions. It is a
// System on the engine.
type Orchestrator struct {
	Decider Decider
}

// System returns the engine System for this Orchestrator: it asks the Decider for
// decisions and maps them to events.
func (o Orchestrator) System() System {
	return func(w *World) []Event {
		var out []Event
		for _, d := range o.Decider.Decide(w) {
			switch d.Action {
			case DecideDispatch:
				out = append(out, WorkDispatched{ID: d.WorkID, ItemKind: d.WorkKind, Target: d.WorkTarget})
			case DecideComplete:
				out = append(out, MissionDone{ID: d.MissionID, Reason: d.Reason})
			}
		}
		return out
	}
}

// MissionSnapshot is a stable, comparable view of a Mission.
type MissionSnapshot struct {
	ID               string
	Goal             string
	Status           MissionStatus
	Reason           string
	Budget           Budget
	DecisionInFlight bool
	DecisionCursor   int
	TokensUsed       int64
	DeciderSlot      DeciderSlot
}

// MissionSnapshot returns the current missions in deterministic (ID) order.
func (w *World) MissionSnapshot() []MissionSnapshot {
	var out []MissionSnapshot
	q := ecs.NewFilter1[Mission](w.ecs).Query()
	for q.Next() {
		m := q.Get()
		out = append(out, MissionSnapshot{
			ID:               m.ID,
			Goal:             m.Goal,
			Status:           m.Status,
			Reason:           m.Reason,
			Budget:           m.Budget,
			DecisionInFlight: m.DecisionInFlight,
			DecisionCursor:   m.DecisionCursor,
			TokensUsed:       m.TokensUsed,
			DeciderSlot:      m.DeciderSlot,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
