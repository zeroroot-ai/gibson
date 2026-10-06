// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

// scheduler.go is the mechanical execution of the scripted work-graph (ADR-0101,
// CONTEXT.md: "CUE declares dependencies, not a schedule"). Two Systems, both
// quiescent so a tick settles:
//
//   - SchedulerSystem dispatches any `pending` WorkItem whose DependsOn are all
//     satisfied. No LLM — this is the deterministic scheduler that honors the CUE
//     graph's deferred ordering.
//   - MissionCompletionSystem completes a **no-goal** mission mechanically once
//     no further progress is possible (nothing running, nothing dispatchable).
//     Goal missions complete via the Decider (gibson#847), not here.

// pausedMissions returns the set of mission ids that are not currently RUNNING
// (paused or terminal) — the executor must not dispatch/retry their work.
func pausedMissions(w *World) map[string]bool {
	notRunning := map[string]bool{}
	for _, m := range w.MissionSnapshot() {
		if m.Status != MissionRunning {
			notRunning[m.ID] = true
		}
	}
	return notRunning
}

// SchedulerSystem dispatches pending work whose dependencies are satisfied,
// under each group's concurrency ceiling (gibson#538): a group with Limit N
// has at most N members running at once, counting the ones already running
// and the ones this pass dispatches. The walk is in id order, so which
// members go first is deterministic and replay folds the same way.
func SchedulerSystem(w *World) []Event {
	work := w.WorkSnapshot()
	idx := workIndex(work)
	halted := pausedMissions(w)
	running := runningPerGroup(work)
	var out []Event
	for _, wi := range work {
		if wi.State != WorkPending {
			continue
		}
		if wi.Kind == "condition" || wi.Kind == "join" {
			continue // resolved in-brain by ConditionSystem / JoinSystem, not dispatched to infra
		}
		if wi.MissionID != "" && halted[wi.MissionID] {
			continue // mission paused/terminal — do not dispatch its work
		}
		if !depsSatisfied(wi.DependsOn, idx) {
			continue
		}
		if key, ok := groupKey(wi); ok {
			if running[key] >= wi.Limit {
				continue // the ceiling is reached; a completion frees the slot
			}
			running[key]++
		}
		out = append(out, WorkDispatched{
			ID:         wi.ID,
			MissionID:  wi.MissionID,
			ItemKind:   wi.Kind,
			Target:     wi.Target,
			Input:      wi.Input,
			Timeout:    wi.Timeout,
			Group:      wi.Group,
			Limit:      wi.Limit,
			Network:    wi.Network,
			StartsFrom: wi.StartsFrom,
			Forkable:   wi.Forkable,
		})
	}
	return out
}

// groupKey is the ceiling an item is counted under: its group, scoped to its
// mission so two missions that both name a container "scan" never share a
// ceiling. False when the item has no ceiling.
func groupKey(wi WorkSnapshot) (string, bool) {
	if wi.Group == "" || wi.Limit <= 0 {
		return "", false
	}
	return wi.MissionID + "/" + wi.Group, true
}

// runningPerGroup counts the members of each group that are dispatched and
// not yet completed.
func runningPerGroup(work []WorkSnapshot) map[string]int {
	out := map[string]int{}
	for _, wi := range work {
		if wi.State != WorkRunning {
			continue
		}
		if key, ok := groupKey(wi); ok {
			out[key]++
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
	idx := workIndex(work)
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
				if depsSatisfied(wi.DependsOn, idx) {
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

func workIndex(work []WorkSnapshot) map[string]WorkSnapshot {
	idx := make(map[string]WorkSnapshot, len(work))
	for _, wi := range work {
		idx[wi.ID] = wi
	}
	return idx
}

// depsSatisfied reports whether every dependency of an item has reached a state
// that lets the item run.
//
// `done` satisfies a dependency, as it always has. A dependency that failed
// satisfies it only when the dependency says so — DependentsRunOnFailure, which
// a for_each instance sets and an ordinary node does not — and only when that
// failure is terminal. A failure with retries left is re-armed by RetrySystem in
// the same tick cycle, so treating it as settled would release the dependents
// one tick before the retry it is still owed (gibson#527).
//
// An unknown dependency id is not satisfied. The zero WorkSnapshot has no state,
// so a dependency on work that does not exist blocks rather than passing, which
// is the fail-closed reading.
func depsSatisfied(deps []string, idx map[string]WorkSnapshot) bool {
	for _, d := range deps {
		dep, ok := idx[d]
		if !ok {
			return false
		}
		if dep.State == WorkDone {
			continue
		}
		if dep.State == WorkFailed && dep.DependentsRunOnFailure && dep.Attempts > dep.MaxRetries {
			continue
		}
		return false
	}
	return true
}
