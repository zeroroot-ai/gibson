package brain

import (
	"sort"

	"github.com/mlange-42/ark/ecs"
)

// WorkState is the lifecycle state of a unit of work.
type WorkState string

const (
	// WorkPending: projected into the World (e.g. from a CUE node) but not yet
	// dispatched — the Scheduler dispatches it once its DependsOn are all done.
	WorkPending WorkState = "pending"
	WorkRunning WorkState = "running"
	WorkDone    WorkState = "done"
	WorkFailed  WorkState = "failed"
)

// WorkItem is a unit of work tracked as an entity — a tool call, agent run, or
// plugin invocation (ADR-0004: capability vs. execution; this is the execution
// side, e.g. a ToolExecution). Modeling work as an entity is what lets
// long-running operations be async: the engine never blocks on them; their
// completion arrives as an event whenever it lands (decided-by-observation — no
// duration is declared or tracked; a 3-second tool and a 3-day callback are the
// same path).
//
// A WorkItem may be born `pending` (projected from a CUE mission node, with its
// DependsOn ordering, by the Scheduler's deferred-ordering model) or born
// `running` (dispatched directly). DependsOn references other WorkItem IDs that
// must reach `done` before this one is dispatchable.
type WorkItem struct {
	ID        string
	MissionID string   // owning mission (empty for free-standing work)
	Kind      string   // "tool" | "agent" | "plugin"
	Target    string   // the capability being executed
	Input     string   // opaque dispatch input (e.g. the CUE node config), carried for dispatch
	DependsOn []string // WorkItem IDs that must be `done` before this is dispatchable
	State     WorkState
	Result    string
	Err       string
}

// WorkDispatched records that a unit of work was launched. It does not block;
// the work runs out-of-process and reports back via WorkCompleted.
type WorkDispatched struct {
	ID       string
	ItemKind string // tool | agent | plugin
	Target   string
}

func (WorkDispatched) Kind() string { return "work.dispatched" }

// WorkCompleted records that a previously-dispatched unit of work finished —
// whenever that is. Err non-empty means failure.
type WorkCompleted struct {
	ID     string
	Result string
	Err    string
}

func (WorkCompleted) Kind() string { return "work.completed" }

// findWork returns the entity for the work item with the given ID, if present.
func findWork(w *World, id string) (ecs.Entity, bool) {
	q := ecs.NewFilter1[WorkItem](w.ecs).Query()
	for q.Next() {
		if q.Get().ID == id {
			e := q.Entity()
			q.Close()
			return e, true
		}
	}
	return ecs.Entity{}, false
}

func applyWorkDispatched(w *World, e WorkDispatched) {
	if ent, ok := findWork(w, e.ID); ok { // idempotent re-dispatch
		w.work.Get(ent).State = WorkRunning
		return
	}
	w.work.NewEntity(&WorkItem{ID: e.ID, Kind: e.ItemKind, Target: e.Target, State: WorkRunning})
}

func applyWorkCompleted(w *World, e WorkCompleted) {
	ent, ok := findWork(w, e.ID)
	if !ok {
		return // completion for unknown work: ignore (out-of-order/duplicate)
	}
	wi := w.work.Get(ent)
	if e.Err != "" {
		wi.State, wi.Err = WorkFailed, e.Err
		return
	}
	wi.State, wi.Result = WorkDone, e.Result
}

// WorkSnapshot is a stable, comparable view of a WorkItem.
type WorkSnapshot struct {
	ID        string
	MissionID string
	Kind      string
	Target    string
	Input     string
	DependsOn []string
	State     WorkState
	Result    string
	Err       string
}

// WorkSnapshot returns the current work items in deterministic (ID) order.
func (w *World) WorkSnapshot() []WorkSnapshot {
	var out []WorkSnapshot
	q := ecs.NewFilter1[WorkItem](w.ecs).Query()
	for q.Next() {
		wi := q.Get()
		out = append(out, WorkSnapshot{
			ID:        wi.ID,
			MissionID: wi.MissionID,
			Kind:      wi.Kind,
			Target:    wi.Target,
			Input:     wi.Input,
			DependsOn: append([]string(nil), wi.DependsOn...),
			State:     wi.State,
			Result:    wi.Result,
			Err:       wi.Err,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
