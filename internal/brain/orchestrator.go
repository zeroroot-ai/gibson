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
)

// Mission is the root work-graph for a launched mission (ADR-0001): the unit of
// identity/goal/accounting. A CUE mission projects into this at launch; here a
// MissionStarted event seeds it.
type Mission struct {
	ID     string
	Goal   string
	Status MissionStatus
	Reason string // why it completed
}

// MissionStarted launches a mission. (CUE-mission projection lands later; this is
// the minimal launch event.)
type MissionStarted struct {
	ID   string
	Goal string
}

func (MissionStarted) Kind() string { return "mission.started" }

// MissionDone marks a mission complete with a reason.
type MissionDone struct {
	ID     string
	Reason string
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
	w.missions.NewEntity(&Mission{ID: e.ID, Goal: e.Goal, Status: MissionRunning})
}

func applyMissionDone(w *World, e MissionDone) {
	if ent, ok := findMission(w, e.ID); ok {
		m := w.missions.Get(ent)
		m.Status = MissionCompleted
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
	ID     string
	Goal   string
	Status MissionStatus
	Reason string
}

// MissionSnapshot returns the current missions in deterministic (ID) order.
func (w *World) MissionSnapshot() []MissionSnapshot {
	var out []MissionSnapshot
	q := ecs.NewFilter1[Mission](w.ecs).Query()
	for q.Next() {
		m := q.Get()
		out = append(out, MissionSnapshot{ID: m.ID, Goal: m.Goal, Status: m.Status, Reason: m.Reason})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
