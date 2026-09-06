// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	agentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	"google.golang.org/protobuf/encoding/protojson"
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

func TestNodeKindTargetInput_CarriesToolInput(t *testing.T) {
	// The node's declared input is the whole point of a tool node. Dropping it
	// dispatched the tool with no parameters, which for anything that requires
	// one is an immediate failure with a confusing reason (gibson#1196).
	n := &missionpb.MissionNode{
		Type: missionpb.NodeType_NODE_TYPE_TOOL,
		Config: &missionpb.MissionNode_ToolConfig{ToolConfig: &missionpb.ToolNodeConfig{
			ToolName: "zerocool-http",
			Input:    map[string]string{"url": "https://google.com"},
		}},
	}
	kind, target, input, err := nodeKindTargetInput(n)
	if err != nil {
		t.Fatalf("nodeKindTargetInput: %v", err)
	}
	if kind != "tool" || target != "zerocool-http" {
		t.Fatalf("kind/target = %q/%q", kind, target)
	}
	if input != `{"url":"https://google.com"}` {
		t.Errorf("input = %q, want the node input as JSON", input)
	}
}

func TestNodeKindTargetInput_ToolWithNoInputProjectsEmpty(t *testing.T) {
	// A parameterless tool and a tool whose parameters were lost must not look
	// identical downstream; empty stays empty rather than becoming "{}".
	_, _, input, err := nodeKindTargetInput(toolNode("ping"))
	if err != nil {
		t.Fatalf("nodeKindTargetInput: %v", err)
	}
	if input != "" {
		t.Errorf("input = %q, want empty", input)
	}
}

func TestNodeKindTargetInput_CarriesAgentGoal(t *testing.T) {
	// The dispatcher builds agent.Task{Goal: input}; without the goal the agent
	// is asked to do nothing in particular.
	n := &missionpb.MissionNode{
		Type: missionpb.NodeType_NODE_TYPE_AGENT,
		Config: &missionpb.MissionNode_AgentConfig{AgentConfig: &missionpb.AgentNodeConfig{
			AgentName: "zerocool",
			Task:      &agentpb.Task{Goal: "Fetch https://google.com and report the status code."},
		}},
	}
	kind, target, input, err := nodeKindTargetInput(n)
	if err != nil {
		t.Fatalf("nodeKindTargetInput: %v", err)
	}
	if kind != "agent" || target != "zerocool" {
		t.Fatalf("kind/target = %q/%q", kind, target)
	}
	if input != "Fetch https://google.com and report the status code." {
		t.Errorf("input = %q, want the task goal", input)
	}
}

// TestToolInputJSON_CarriesArraysAndObjects: MissionNode tool input is
// map<string,string>, but a tool contract is plain JSON and not every parameter
// is a string. nmap's `args` is []string; marshalling the map verbatim sent
// {"args":"-sV -vv"} where the tool required ["-sV","-vv"], so the sandbox
// exited 1 and the node failed for a reason invisible from the schema.
func TestToolInputJSON_CarriesArraysAndObjects(t *testing.T) {
	got, err := toolInputJSON(map[string]string{
		"target": "scanme.nmap.org",
		"ports":  "80",
		"args":   `["-sV","-vv"]`,
		"opts":   `{"deep":true}`,
		"broken": "[not json",
	})
	if err != nil {
		t.Fatalf("toolInputJSON: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("result is not valid JSON: %v (%s)", err, got)
	}
	args, ok := out["args"].([]any)
	if !ok || len(args) != 2 || args[0] != "-sV" {
		t.Errorf("args = %#v; want the JSON array [-sV -vv]", out["args"])
	}
	if _, ok := out["opts"].(map[string]any); !ok {
		t.Errorf("opts = %#v; want a JSON object", out["opts"])
	}
	// "80" must stay a string: the tool reads it from a string-typed options
	// map, and the number 80 would not survive that.
	if v, ok := out["ports"].(string); !ok || v != "80" {
		t.Errorf("ports = %#v; want the string \"80\"", out["ports"])
	}
	if v, ok := out["target"].(string); !ok || v != "scanme.nmap.org" {
		t.Errorf("target = %#v; want a string", out["target"])
	}
	// Something that only looks like JSON stays the string it was.
	if v, ok := out["broken"].(string); !ok || v != "[not json" {
		t.Errorf("broken = %#v; want the original string", out["broken"])
	}
}

// TestNodeKindTargetInput_JobNodeCarriesItsBankAndSpec asserts a job node
// projects to the "job" kind with the bank as target and the whole config as
// protojson input, and that a node with no bank or no goal is refused.
func TestNodeKindTargetInput_JobNodeCarriesItsBankAndSpec(t *testing.T) {
	n := &missionpb.MissionNode{Id: "fix", Type: missionpb.NodeType_NODE_TYPE_JOB, Config: &missionpb.MissionNode_JobConfig{
		JobConfig: &missionpb.JobNodeConfig{BankRef: "bank-1", Spec: &jobpb.JobSpec{Goal: "fix the build"}},
	}}
	kind, target, input, err := nodeKindTargetInput(n)
	if err != nil || kind != "job" || target != "bank-1" {
		t.Fatalf("got %q %q %v", kind, target, err)
	}
	cfg := &missionpb.JobNodeConfig{}
	if err := protojson.Unmarshal([]byte(input), cfg); err != nil || cfg.GetSpec().GetGoal() != "fix the build" {
		t.Fatalf("input = %s, %v", input, err)
	}
	n.GetJobConfig().Spec.Goal = ""
	if _, _, _, err := nodeKindTargetInput(n); err == nil {
		t.Error("a job node with no goal must be refused")
	}
	n.GetJobConfig().BankRef = ""
	if _, _, _, err := nodeKindTargetInput(n); err == nil {
		t.Error("a job node with no bank must be refused")
	}
}
