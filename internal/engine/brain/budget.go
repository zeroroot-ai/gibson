// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"fmt"
	"sort"
)

// budget.go is the per-mission resource ceiling — both the cumulative-cost cap and
// the runaway-Decider guard (CONTEXT.md, replacing the legacy spawn_cycle_guard).
// An unbounded LLM Decider could dispatch forever; BudgetSystem hard-stops a
// mission that exceeds its Budget, regardless of goal. Limits are sourced into the
// Budget at projection (CUE MissionConstraints merged with the Entitlements
// provider — the merge is daemon-side; the brain enforces what it is given).

// TokenUsed reports LLM token spend attributed to a mission (emitted by the
// dispatch/LLM layer, daemon-side). The reducer accumulates it; BudgetSystem
// enforces Budget.MaxTokens against the total.
type TokenUsed struct {
	MissionID string
	Tokens    int64
	// CallID names the model call that the tokens belong to. When it is set, the
	// reducer counts the tokens of one call one time: a second event with the
	// same CallID for the same mission changes nothing. The gateway trace path
	// sets it, because the collector can deliver a span again. An event with no
	// CallID counts every time, as before.
	CallID string `json:",omitempty"`
}

func (TokenUsed) Kind() string { return "token.used" }

func applyTokenUsed(w *World, e TokenUsed) {
	ent, ok := findMission(w, e.MissionID)
	if !ok {
		return
	}
	if e.CallID != "" {
		counted := w.countedTokenCalls[e.MissionID]
		if _, seen := counted[e.CallID]; seen {
			return
		}
		if counted == nil {
			counted = make(map[string]struct{})
			w.countedTokenCalls[e.MissionID] = counted
		}
		counted[e.CallID] = struct{}{}
	}
	w.missions.Get(ent).TokensUsed += e.Tokens
}

// BudgetSystem aborts any running mission that has exceeded its Budget. It runs
// before the gate/scheduler so an over-budget mission dispatches no further work.
// Executions are counted as the sum of dispatch attempts across the mission's
// work (so Decider re-dispatches and retries all count) — the runaway metric.
func BudgetSystem(w *World) []Event {
	work := w.WorkSnapshot()
	execByMission := map[string]int{}
	for _, wi := range work {
		execByMission[wi.MissionID] += wi.Attempts
	}

	var out []Event
	for _, m := range w.MissionSnapshot() {
		if !m.Status.IsActive() {
			continue
		}
		if m.Budget.MaxExecutions > 0 && execByMission[m.ID] > m.Budget.MaxExecutions {
			out = append(out, MissionDone{
				ID:      m.ID,
				Outcome: MissionFailed,
				Reason:  fmt.Sprintf("budget exceeded: %d executions > max %d", execByMission[m.ID], m.Budget.MaxExecutions),
			})
			continue
		}
		if m.Budget.MaxTokens > 0 && m.TokensUsed > m.Budget.MaxTokens {
			out = append(out, MissionDone{
				ID:      m.ID,
				Outcome: MissionFailed,
				Reason:  fmt.Sprintf("budget exceeded: %d tokens > max %d", m.TokensUsed, m.Budget.MaxTokens),
			})
		}
	}
	return out
}

// countedTokenCallsSnapshot returns the counted call IDs of each mission, sorted.
func (w *World) countedTokenCallsSnapshot() map[string][]string {
	if len(w.countedTokenCalls) == 0 {
		return nil
	}
	out := make(map[string][]string, len(w.countedTokenCalls))
	for id, set := range w.countedTokenCalls {
		calls := make([]string, 0, len(set))
		for c := range set {
			calls = append(calls, c)
		}
		sort.Strings(calls)
		out[id] = calls
	}
	return out
}
