package brain

import "testing"

// A tool/plugin dispatch surfaces as a ToolExecution; an agent does not (agents
// are AgentRuns, not tool executions). The async lifecycle is the WorkItem's.
func TestToolExecutions_ViewOverToolPluginWork(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, MissionProjected{ID: "m1", Nodes: []WorkNode{
		{ID: "scan", Kind: "tool", Target: "nmap", Input: `{"target":"10.0.0.5"}`},
		{ID: "leak", Kind: "plugin", Target: "gitleaks"},
		{ID: "exploit", Kind: "agent", Target: "exploit-agent"},
	}})
	Reduce(w, WorkDispatched{ID: "scan", MissionID: "m1", ItemKind: "tool", Target: "nmap"})
	Reduce(w, WorkCompleted{ID: "scan", Result: "22/ssh,80/http"})

	tes := w.ToolExecutionSnapshot()
	if len(tes) != 2 { // tool + plugin, not the agent
		t.Fatalf("want 2 tool/plugin executions, got %d (%+v)", len(tes), tes)
	}
	byID := map[string]ToolExecutionSnapshot{}
	for _, te := range tes {
		byID[te.ID] = te
	}
	scan := byID["scan"]
	if scan.Kind != "tool" || scan.Capability != "nmap" || scan.State != WorkDone || scan.Result != "22/ssh,80/http" {
		t.Errorf("scan execution wrong: %+v", scan)
	}
	if scan.Attempts != 1 {
		t.Errorf("scan attempts: want 1, got %d", scan.Attempts)
	}
	if byID["leak"].Kind != "plugin" || byID["leak"].State != WorkPending {
		t.Errorf("leak execution wrong: %+v", byID["leak"])
	}
	if _, ok := byID["exploit"]; ok {
		t.Errorf("agent should not appear as a tool execution")
	}
}

func TestToolExecutions_EngineAccessor(t *testing.T) {
	e := NewEngine("t1")
	e.Submit(MissionProjected{ID: "m1", Nodes: []WorkNode{{ID: "a", Kind: "tool", Target: "nmap"}}})
	e.Tick()
	if got := len(e.ToolExecutions()); got != 1 {
		t.Fatalf("engine ToolExecutions: want 1, got %d", got)
	}
}
