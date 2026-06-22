package brain

import (
	"testing"
)

// richCatalogEngine offers an agent, a tool, and a plugin in the catalog.
func richCatalogEngine(llm DeciderLLM) (*Engine, *DeciderWorker) {
	e := NewEngine("t1")
	dw := NewDeciderWorker(e, llm, func() []Capability {
		return []Capability{
			{Kind: "agent", Name: "exploit"},
			{Kind: "tool", Name: "nmap", InputSchema: `{"type":"object"}`},
			{Kind: "plugin", Name: "gitleaks"},
		}
	})
	e.AddSystem(SchedulerSystem)
	e.AddSystem(DeciderGateSystem)
	e.AddSystem(fakeDispatcher(nil))
	e.AddSystem(RetrySystem)
	e.AddSystem(MissionCompletionSystem)
	e.Subscribe(dw.Tap)
	return e, dw
}

func dispatchedTargets(e *Engine) map[string]WorkState {
	m := map[string]WorkState{}
	for _, wi := range e.Work() {
		m[wi.Target] = wi.State
	}
	return m
}

func TestRedispatch_ToolWithValidStructuredInput(t *testing.T) {
	llm := &scriptedLLM{outputs: []DeciderOutput{
		{Dispatches: []DeciderDispatch{{Kind: "tool", Target: "nmap", Input: `{"target":"10.0.0.5"}`}}},
		{Complete: &DeciderComplete{Outcome: "success"}},
	}}
	e, dw := richCatalogEngine(llm)
	e.Submit(MissionProjected{ID: "m1", Goal: "scan"})
	runRounds(e, dw, 8)

	if got := dispatchedTargets(e)["nmap"]; got != WorkDone {
		t.Fatalf("tool nmap want done, got %q (work=%+v)", got, e.Work())
	}
	// the structured input is carried on the WorkItem for the dispatch layer.
	for _, wi := range e.Work() {
		if wi.Target == "nmap" && wi.Input != `{"target":"10.0.0.5"}` {
			t.Errorf("tool input not carried: %q", wi.Input)
		}
	}
}

func TestRedispatch_PluginWithMethodParams(t *testing.T) {
	llm := &scriptedLLM{outputs: []DeciderOutput{
		{Dispatches: []DeciderDispatch{{Kind: "plugin", Target: "gitleaks", Input: `{"method":"scan","params":{"repo":"x"}}`}}},
		{Complete: &DeciderComplete{Outcome: "success"}},
	}}
	e, dw := richCatalogEngine(llm)
	e.Submit(MissionProjected{ID: "m1", Goal: "secrets"})
	runRounds(e, dw, 8)

	if got := dispatchedTargets(e)["gitleaks"]; got != WorkDone {
		t.Fatalf("plugin gitleaks want done, got %q", got)
	}
}

func TestRedispatch_InvalidJSONToolInputRejected(t *testing.T) {
	llm := &scriptedLLM{outputs: []DeciderOutput{
		{Dispatches: []DeciderDispatch{{Kind: "tool", Target: "nmap", Input: `{not json`}}}, // garbage
		{Complete: &DeciderComplete{Outcome: "success"}},
	}}
	e, dw := richCatalogEngine(llm)
	e.Submit(MissionProjected{ID: "m1", Goal: "scan"})
	runRounds(e, dw, 8)

	if _, ok := dispatchedTargets(e)["nmap"]; ok {
		t.Fatalf("malformed tool input must NOT be dispatched; work=%+v", e.Work())
	}
}

func TestRedispatch_UnknownCapabilityRejected(t *testing.T) {
	llm := &scriptedLLM{outputs: []DeciderOutput{
		{Dispatches: []DeciderDispatch{{Kind: "tool", Target: "metasploit", Input: `{}`}}}, // not in catalog
		{Complete: &DeciderComplete{Outcome: "success"}},
	}}
	e, dw := richCatalogEngine(llm)
	e.Submit(MissionProjected{ID: "m1", Goal: "scan"})
	runRounds(e, dw, 8)

	if _, ok := dispatchedTargets(e)["metasploit"]; ok {
		t.Fatalf("unknown capability must NOT be dispatched; work=%+v", e.Work())
	}
}

func TestValidateDispatch_AgentTakesFreeText(t *testing.T) {
	cat := []Capability{{Kind: "agent", Name: "exploit"}}
	if !validateDispatch(DeciderDispatch{Kind: "agent", Target: "exploit", Input: "just do it"}, cat) {
		t.Error("agent with free-text input should validate")
	}
	if validateDispatch(DeciderDispatch{Kind: "agent", Target: "ghost", Input: "x"}, cat) {
		t.Error("unknown agent should be rejected")
	}
}
