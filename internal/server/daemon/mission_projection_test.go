package daemon

import (
	"sort"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
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
			"b": agentNode("scan", "a"), // dep via field
			"c": toolNode("report"),     // dep via edge below
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

func conditionNode(expr string, trueBranch, falseBranch []string, deps ...string) *missionpb.MissionNode {
	return &missionpb.MissionNode{
		Type:         missionpb.NodeType_NODE_TYPE_CONDITION,
		Config:       &missionpb.MissionNode_ConditionConfig{ConditionConfig: &missionpb.ConditionNodeConfig{Expression: expr, TrueBranch: trueBranch, FalseBranch: falseBranch}},
		Dependencies: deps,
	}
}

func TestMissionDefinitionToProjected_DeciderSlot(t *testing.T) {
	def := &missionpb.MissionDefinition{
		Id:          "m1",
		Nodes:       map[string]*missionpb.MissionNode{"a": toolNode("ta")},
		DeciderSlot: &missionpb.LLMSlotConfig{Provider: "anthropic", Model: "claude-opus-4-8"},
	}
	got, err := missionDefinitionToProjected(def, "find flag")
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if got.DeciderSlot.Provider != "anthropic" || got.DeciderSlot.Model != "claude-opus-4-8" {
		t.Fatalf("decider slot: got %+v", got.DeciderSlot)
	}

	// Absent decider_slot → empty (tenant default).
	def.DeciderSlot = nil
	got, _ = missionDefinitionToProjected(def, "")
	if (got.DeciderSlot != brain.DeciderSlot{}) {
		t.Errorf("absent slot should be empty, got %+v", got.DeciderSlot)
	}
}

func TestMissionDefinitionToProjected_JoinCollapsesToDeps(t *testing.T) {
	// a, b run; join j waits for both; c depends on j → c should depend on {a,b}.
	def := &missionpb.MissionDefinition{
		Id: "m1",
		Nodes: map[string]*missionpb.MissionNode{
			"a": toolNode("ta"),
			"b": toolNode("tb"),
			"j": {Type: missionpb.NodeType_NODE_TYPE_JOIN, Config: &missionpb.MissionNode_JoinConfig{JoinConfig: &missionpb.JoinNodeConfig{WaitFor: []string{"a", "b"}}}},
			"c": toolNode("tc", "j"),
		},
	}
	got, err := missionDefinitionToProjected(def, "")
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	byID := map[string]brain.WorkNode{}
	for _, n := range got.Nodes {
		byID[n.ID] = n
	}
	if _, ok := byID["j"]; ok {
		t.Error("join node should not appear as a WorkNode")
	}
	if !eqStrs(byID["c"].DependsOn, []string{"a", "b"}) {
		t.Errorf("c deps: got %v want [a b]", byID["c"].DependsOn)
	}
}

func TestMissionDefinitionToProjected_ParallelFlattensSubNodes(t *testing.T) {
	// p (depends on a) contains sub-nodes s1, s2; d depends on p → d depends on {s1,s2}.
	def := &missionpb.MissionDefinition{
		Id: "m1",
		Nodes: map[string]*missionpb.MissionNode{
			"a": toolNode("ta"),
			"p": {
				Type:         missionpb.NodeType_NODE_TYPE_PARALLEL,
				Dependencies: []string{"a"},
				Config: &missionpb.MissionNode_ParallelConfig{ParallelConfig: &missionpb.ParallelNodeConfig{SubNodes: []*missionpb.MissionNode{
					func() *missionpb.MissionNode { n := toolNode("ts1"); n.Id = "s1"; return n }(),
					func() *missionpb.MissionNode { n := toolNode("ts2"); n.Id = "s2"; return n }(),
				}}},
			},
			"d": toolNode("td", "p"),
		},
	}
	got, err := missionDefinitionToProjected(def, "")
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	byID := map[string]brain.WorkNode{}
	for _, n := range got.Nodes {
		byID[n.ID] = n
	}
	if _, ok := byID["p"]; ok {
		t.Error("parallel node should not appear as a WorkNode")
	}
	// sub-nodes are real nodes, both depending on a (the parallel's dep).
	if !eqStrs(byID["s1"].DependsOn, []string{"a"}) || !eqStrs(byID["s2"].DependsOn, []string{"a"}) {
		t.Errorf("sub-node deps: s1=%v s2=%v want [a]", byID["s1"].DependsOn, byID["s2"].DependsOn)
	}
	// d depends on the parallel → its sub-nodes.
	if !eqStrs(byID["d"].DependsOn, []string{"s1", "s2"}) {
		t.Errorf("d deps: got %v want [s1 s2]", byID["d"].DependsOn)
	}
}

func TestMissionDefinitionToProjected_ConditionGatesBranches(t *testing.T) {
	def := &missionpb.MissionDefinition{
		Id: "m1",
		Nodes: map[string]*missionpb.MissionNode{
			"a":    toolNode("ta"),
			"cond": conditionNode("nodes['a'] == 'vuln'", []string{"yes"}, []string{"no"}, "a"),
			"yes":  toolNode("ty"),
			"no":   toolNode("tn"),
		},
	}
	got, err := missionDefinitionToProjected(def, "")
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	byID := map[string]brain.WorkNode{}
	for _, n := range got.Nodes {
		byID[n.ID] = n
	}
	if byID["cond"].Kind != "condition" {
		t.Errorf("cond kind: got %q want condition", byID["cond"].Kind)
	}
	if !eqStrs(byID["cond"].DependsOn, []string{"a"}) {
		t.Errorf("cond deps: got %v want [a]", byID["cond"].DependsOn)
	}
	// branch nodes are gated on the condition.
	if !eqStrs(byID["yes"].DependsOn, []string{"cond"}) || !eqStrs(byID["no"].DependsOn, []string{"cond"}) {
		t.Errorf("branch deps: yes=%v no=%v want [cond]", byID["yes"].DependsOn, byID["no"].DependsOn)
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
