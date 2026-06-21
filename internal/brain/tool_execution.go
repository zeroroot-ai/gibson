package brain

import "sort"

// tool_execution.go is the capability-vs-execution view of async tool/plugin work
// (ADR-0004, gibson#747). A dispatched tool/plugin call is tracked as a WorkItem —
// the *execution* (born on dispatch, has a lifecycle, carries its result). This
// view surfaces those executions as ToolExecution entities distinct from the
// static capability catalog the Decider chooses from.
//
// The async behaviour the entity exists to support is already live in the engine:
// a dispatched WorkItem never blocks the tick; its completion arrives as a
// WorkCompleted event whenever it lands (a 3-second tool and a 3-day callback are
// the same path), and the Decider re-engages from the World on the new evidence.
// Duration is never declared or tracked — quick vs slow is decided by observation.
// (Cross-restart survival additionally needs durable Timeline persistence, a
// separate follow-up; the in-memory Timeline replays within a process.)

// ToolExecutionState mirrors the WorkItem lifecycle for executions.
type ToolExecutionState = WorkState

// ToolExecutionSnapshot is one dispatched tool/plugin execution (the execution
// side of capability-vs-execution).
type ToolExecutionSnapshot struct {
	ID         string // the WorkItem id (stable execution key)
	MissionID  string // owning mission
	Kind       string // "tool" | "plugin"
	Capability string // the capability (tool/plugin name) this is an execution of
	Input      string // dispatch input
	State      ToolExecutionState
	Result     string
	Err        string
	Attempts   int
}

// ToolExecutions returns the current tool/plugin executions (engine read path).
func (e *Engine) ToolExecutions() []ToolExecutionSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.ToolExecutionSnapshot()
}

// ToolExecutionSnapshot derives the tool/plugin executions from the World's work
// items in deterministic (ID) order.
func (w *World) ToolExecutionSnapshot() []ToolExecutionSnapshot {
	var out []ToolExecutionSnapshot
	for _, wi := range w.WorkSnapshot() {
		if wi.Kind != "tool" && wi.Kind != "plugin" {
			continue
		}
		out = append(out, ToolExecutionSnapshot{
			ID:         wi.ID,
			MissionID:  wi.MissionID,
			Kind:       wi.Kind,
			Capability: wi.Target,
			Input:      wi.Input,
			State:      wi.State,
			Result:     wi.Result,
			Err:        wi.Err,
			Attempts:   wi.Attempts,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
