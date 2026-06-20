package daemon

import (
	"sort"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/brain"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

func agentNode(name string, deps ...string) *missionpb.MissionNode {
	return &missionpb.MissionNode{
		Type:         missionpb.NodeType_NODE_TYPE_AGENT,
		Config:       &missionpb.MissionNode_AgentConfig{AgentConfig: &missionpb.AgentNodeConfig{AgentName: name}},
		Dependencies: deps,
	}
}

func toolNode(name string, deps ...string) *missionpb.MissionNode {
	return &missionpb.MissionNode{
		Type:         missionpb.NodeType_NODE_TYPE_TOOL,
		Config:       &missionpb.MissionNode_ToolConfig{ToolConfig: &missionpb.ToolNodeConfig{ToolName: name}},
		Dependencies: deps,
	}
}

func TestMissionDefinitionToProjected_NodesEdgesConstraints(t *testing.T) {
	def := &missionpb.MissionDefinition{
		Id: "m1",
		Nodes: map[string]*missionpb.MissionNode{
			"a": toolNode("recon"),
			"b": agentNode("scan", "a"),                  // dep via field
			"c": toolNode("report"),                       // dep via edge below
		},
		Edges: []*missionpb.MissionEdge{
			{From: "b", To: "c"},
		},
		Constraints: &missionpb.MissionConstraints{MaxTokens: 1000},
	}

	got, err := missionDefinitionToProjected(def, "")
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if got.ID != "m1" || got.Goal != "" {
		t.Errorf("id/goal: got %q/%q", got.ID, got.Goal)
	}
	if got.Budget.MaxTokens != 1000 {
		t.Errorf("budget tokens: got %d", got.Budget.MaxTokens)
	}
	byID := map[string]brain.WorkNode{}
	for _, n := range got.Nodes {
		byID[n.ID] = n
	}
	if byID["a"].Kind != "tool" || byID["a"].Target != "recon" {
		t.Errorf("node a: %+v", byID["a"])
	}
	if byID["b"].Kind != "agent" || byID["b"].Target != "scan" {
		t.Errorf("node b: %+v", byID["b"])
	}
	if !eqStrs(byID["b"].DependsOn, []string{"a"}) {
		t.Errorf("b deps: got %v want [a]", byID["b"].DependsOn)
	}
	if !eqStrs(byID["c"].DependsOn, []string{"b"}) { // from the edge
		t.Errorf("c deps: got %v want [b]", byID["c"].DependsOn)
	}
}

func TestMissionDefinitionToProjected_RejectsControlFlowNodes(t *testing.T) {
	def := &missionpb.MissionDefinition{
		Id:    "m1",
		Nodes: map[string]*missionpb.MissionNode{"x": {Type: missionpb.NodeType_NODE_TYPE_PARALLEL}},
	}
	if _, err := missionDefinitionToProjected(def, ""); err == nil {
		t.Fatal("expected error for parallel node (gibson#846), got nil")
	}
}

// End-to-end: translate a proto definition and run it through a brain engine with
// a fake dispatcher (proves the projection drives real scheduling/completion).
func TestMissionDefinitionToProjected_RunsThroughEngine(t *testing.T) {
	def := &missionpb.MissionDefinition{
		Id: "m1",
		Nodes: map[string]*missionpb.MissionNode{
			"a": toolNode("recon"),
			"b": agentNode("scan", "a"),
		},
	}
	proj, err := missionDefinitionToProjected(def, "") // no-goal
	if err != nil {
		t.Fatalf("translate: %v", err)
	}

	e := brain.NewEngine("t1")
	e.AddSystem(brain.SchedulerSystem)
	e.AddSystem(func(w *brain.World) []brain.Event { // fake dispatcher
		var out []brain.Event
		for _, wi := range w.WorkSnapshot() {
			if wi.State == brain.WorkRunning {
				out = append(out, brain.WorkCompleted{ID: wi.ID, Result: "ok"})
			}
		}
		return out
	})
	e.AddSystem(brain.MissionCompletionSystem)

	e.Submit(proj)
	e.Tick()

	ms := e.Missions()
	if len(ms) != 1 || ms[0].Status != brain.MissionCompleted {
		t.Fatalf("mission want completed, got %+v", ms)
	}
	for _, wi := range e.Work() {
		if wi.State != brain.WorkDone {
			t.Errorf("work %q want done, got %s", wi.ID, wi.State)
		}
	}
}

func eqStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
