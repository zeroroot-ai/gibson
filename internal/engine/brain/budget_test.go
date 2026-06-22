package brain

import (
	"context"
	"strings"
	"testing"
)

// budgetEngine wires BudgetSystem FIRST (so an over-budget mission dispatches no
// further work), then the full goal loop.
func budgetEngine(llm DeciderLLM, catalog func() []Capability) (*Engine, *DeciderWorker) {
	e := NewEngine("t1")
	dw := NewDeciderWorker(e, llm, catalog)
	e.AddSystem(BudgetSystem)
	e.AddSystem(SchedulerSystem)
	e.AddSystem(DeciderGateSystem)
	e.AddSystem(fakeDispatcher(nil))
	e.AddSystem(RetrySystem)
	e.AddSystem(MissionCompletionSystem)
	e.Subscribe(dw.Tap)
	return e, dw
}

func TestBudget_ExecutionRunawayGuardAborts(t *testing.T) {
	// A Decider that always dispatches another agent and never completes — the
	// runaway case. MaxExecutions=3 must hard-stop it.
	llm := llmFunc(func(_ context.Context, _ MissionContext) (DeciderOutput, error) {
		return DeciderOutput{Dispatches: []DeciderDispatch{{Kind: "agent", Target: "loop", Input: "again"}}}, nil
	})
	e, dw := budgetEngine(llm, func() []Capability { return []Capability{{Kind: "agent", Name: "loop"}} })

	e.Submit(MissionProjected{ID: "m1", Goal: "endless", Budget: Budget{MaxExecutions: 3}})
	runRounds(e, dw, 20)

	m := e.Missions()[0]
	if m.Status != MissionFailed {
		t.Fatalf("runaway mission want failed, got %s", m.Status)
	}
	if !strings.Contains(m.Reason, "budget exceeded") {
		t.Errorf("reason should mention budget, got %q", m.Reason)
	}
	// executions were actually capped near the limit, not unbounded.
	exec := 0
	for _, wi := range e.Work() {
		exec += wi.Attempts
	}
	if exec > 6 { // 3 allowed + a little slack for the round it trips on
		t.Errorf("executions not capped: %d", exec)
	}
}

func TestBudget_TokenBudgetAborts(t *testing.T) {
	e := NewEngine("t1")
	e.AddSystem(BudgetSystem)
	e.Submit(MissionProjected{ID: "m1", Goal: "g", Budget: Budget{MaxTokens: 100}})
	e.Submit(TokenUsed{MissionID: "m1", Tokens: 150})
	e.Tick()

	m := e.Missions()[0]
	if m.Status != MissionFailed || !strings.Contains(m.Reason, "tokens") {
		t.Fatalf("token-over-budget want failed/tokens, got %s / %q", m.Status, m.Reason)
	}
}

func TestBudget_WithinBudgetCompletesNormally(t *testing.T) {
	llm := &scriptedLLM{outputs: []DeciderOutput{{Complete: &DeciderComplete{Outcome: "success"}}}}
	e, dw := budgetEngine(llm, func() []Capability { return nil })
	e.Submit(MissionProjected{ID: "m1", Goal: "quick", Budget: Budget{MaxExecutions: 10, MaxTokens: 1000}})
	e.Submit(TokenUsed{MissionID: "m1", Tokens: 50})
	runRounds(e, dw, 5)

	if got := e.Missions()[0].Status; got != MissionCompleted {
		t.Fatalf("within-budget mission want completed, got %s", got)
	}
}

func TestBudget_ZeroMeansUnlimited(t *testing.T) {
	e := NewEngine("t1")
	e.AddSystem(BudgetSystem)
	e.Submit(MissionProjected{ID: "m1", Goal: "g"}) // Budget zero-value
	e.Submit(TokenUsed{MissionID: "m1", Tokens: 1_000_000})
	e.Tick()
	if got := e.Missions()[0].Status; got != MissionRunning {
		t.Fatalf("zero budget = unlimited; mission should stay running, got %s", got)
	}
}
