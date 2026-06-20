package brain

// scheduler.go is the mechanical execution of the scripted work-graph (ADR-0001,
// CONTEXT.md: "CUE declares dependencies, not a schedule"). Two Systems, both
// quiescent so a tick settles:
//
//   - SchedulerSystem dispatches any `pending` WorkItem whose DependsOn are all
//     `done`. No LLM — this is the deterministic scheduler that honors the CUE
//     graph's deferred ordering.
//   - MissionCompletionSystem completes a **no-goal** mission mechanically once
//     no further progress is possible (nothing running, nothing dispatchable).
//     Goal missions complete via the Decider (gibson#847), not here.

// SchedulerSystem dispatches pending work whose dependencies are satisfied.
func SchedulerSystem(w *World) []Event {
	work := w.WorkSnapshot()
	state := workStateIndex(work)
	var out []Event
	for _, wi := range work {
		if wi.State != WorkPending {
			continue
		}
		if depsAllDone(wi.DependsOn, state) {
			out = append(out, WorkDispatched{ID: wi.ID, ItemKind: wi.Kind, Target: wi.Target})
		}
	}
	return out
}

// MissionCompletionSystem mechanically completes no-goal missions at quiescence.
// A no-goal mission is done when none of its work is running and none of its
// pending work is dispatchable (i.e. every remaining pending node is dead —
// blocked by a failed dependency). Outcome is MissionFailed if any node failed,
// else MissionCompleted.
func MissionCompletionSystem(w *World) []Event {
	work := w.WorkSnapshot()
	state := workStateIndex(work)
	byMission := map[string][]WorkSnapshot{}
	for _, wi := range work {
		if wi.MissionID != "" {
			byMission[wi.MissionID] = append(byMission[wi.MissionID], wi)
		}
	}

	var out []Event
	for _, m := range w.MissionSnapshot() {
		if m.Status != MissionRunning || m.Goal != "" {
			continue // only running no-goal missions complete mechanically
		}
		running, ready, anyFailed := false, false, false
		for _, wi := range byMission[m.ID] {
			switch wi.State {
			case WorkRunning:
				running = true
			case WorkFailed:
				anyFailed = true
			case WorkPending:
				if depsAllDone(wi.DependsOn, state) {
					ready = true
				}
			}
		}
		if running || ready {
			continue // progress still possible
		}
		outcome, reason := MissionCompleted, "all work complete"
		if anyFailed {
			outcome, reason = MissionFailed, "a work item failed"
		}
		out = append(out, MissionDone{ID: m.ID, Outcome: outcome, Reason: reason})
	}
	return out
}

func workStateIndex(work []WorkSnapshot) map[string]WorkState {
	idx := make(map[string]WorkState, len(work))
	for _, wi := range work {
		idx[wi.ID] = wi.State
	}
	return idx
}

func depsAllDone(deps []string, state map[string]WorkState) bool {
	for _, d := range deps {
		if state[d] != WorkDone {
			return false
		}
	}
	return true
}
