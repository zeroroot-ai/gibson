// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package missioncatalog

import (
	"context"
	"slices"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
)

// agentLookup answers for a name: the tasks that the agent declares, and whether
// the catalog holds the agent.
type agentLookup func(name string) (tasks []string, ok bool)

func catalogAgents(name string) ([]string, bool) {
	e, ok := componentcatalog.LookupAgent(name)
	return e.Tasks, ok
}

// agentProblems returns, for each agent node of the mission, why the node cannot
// run: the catalog does not hold the agent, or the agent declares tasks and the
// task of the node is not one of them. The result is sorted.
func agentProblems(def *missionv1.MissionDefinition, lookup agentLookup) []string {
	var out []string
	for id, n := range def.GetNodes() {
		if n.GetType() != missionv1.NodeType_NODE_TYPE_AGENT {
			continue
		}
		name := n.GetAgentConfig().GetAgentName()
		tasks, ok := lookup(name)
		switch {
		case !ok:
			out = append(out, "node "+id+" names agent "+name+", which the catalog does not hold")
		case len(tasks) > 0 && !slices.Contains(tasks, n.GetAgentConfig().GetTask().GetId()):
			out = append(out, "node "+id+" names task "+n.GetAgentConfig().GetTask().GetId()+" that agent "+name+" does not declare")
		}
	}
	slices.Sort(out)
	return out
}

// Each agent node of each mission names an agent that the component catalog
// holds, and a task that the agent declares when it declares any. A mission
// that does not meet this cannot run, so it must not ship (ADR-0027, review M12).
func TestRender_EachMissionNamesAnAgentOfTheCatalog(t *testing.T) {
	for _, name := range Names() {
		def, err := Render(context.Background(), name, paramsFor(t, name))
		if err != nil {
			t.Fatalf("Render(%s): %v", name, err)
		}
		if problems := agentProblems(def, catalogAgents); len(problems) != 0 {
			t.Errorf("mission %s cannot run: %v", name, problems)
		}
	}
}

func agentNode(agent, task string) *missionv1.MissionNode {
	return &missionv1.MissionNode{
		Type: missionv1.NodeType_NODE_TYPE_AGENT,
		Config: &missionv1.MissionNode_AgentConfig{AgentConfig: &missionv1.AgentNodeConfig{
			AgentName: agent, Task: &typespb.Task{Id: task},
		}},
	}
}

// The failing fixtures of the guard above. The live catalog does not hold the
// red agent (gibson#1511), so a node that names it is reported. A stub agent
// that declares tasks reports a node with another task.
func TestAgentProblems_ReportsAnAgentOrATaskThatCannotRun(t *testing.T) {
	def := &missionv1.MissionDefinition{Nodes: map[string]*missionv1.MissionNode{
		"attack": agentNode("red-agent", "attack"),
	}}
	got := agentProblems(def, catalogAgents)
	if len(got) != 1 {
		t.Fatalf("problems = %v, want one for red-agent", got)
	}

	stub := func(name string) ([]string, bool) { return []string{"contain", "cause"}, name == "responder" }
	def = &missionv1.MissionDefinition{Nodes: map[string]*missionv1.MissionNode{
		"ok":   agentNode("responder", "contain"),
		"bad":  agentNode("responder", "triage"),
		"gone": agentNode("nobody", "contain"),
	}}
	if got := agentProblems(def, stub); len(got) != 2 {
		t.Fatalf("problems = %v, want the task of bad and the agent of gone", got)
	}
	// An agent that declares no tasks is not checked for the task.
	none := func(string) ([]string, bool) { return nil, true }
	if got := agentProblems(def, none); len(got) != 0 {
		t.Fatalf("problems = %v, want none for an agent with no declared tasks", got)
	}
}
