package brain

import "fmt"

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
}

func (TokenUsed) Kind() string { return "token.used" }

func applyTokenUsed(w *World, e TokenUsed) {
	if ent, ok := findMission(w, e.MissionID); ok {
		w.missions.Get(ent).TokensUsed += e.Tokens
	}
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
		if m.Status != MissionRunning {
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
