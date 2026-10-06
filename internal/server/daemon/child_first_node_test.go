// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"errors"
	"testing"

	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// A fork becomes the source of the one entry node of the child mission, so
// the child must start at exactly one agent node (gibson#803, ADR-0169).
func TestFirstNodeOfDefinition(t *testing.T) {
	one := &missionpb.MissionDefinition{Id: "child", Nodes: map[string]*missionpb.MissionNode{
		"recon":  agentNode("recon"),
		"report": agentNode("report", "recon"),
	}}
	n, err := firstNodeOfDefinition(one, "", nil)
	if err != nil {
		t.Fatalf("one entry node: %v", err)
	}
	if n.ID != "recon" || n.Kind != "agent" || n.Target != "recon" {
		t.Errorf("entry node = %+v, want the recon agent node", n)
	}

	for name, def := range map[string]*missionpb.MissionDefinition{
		"two entry nodes": {Id: "child", Nodes: map[string]*missionpb.MissionNode{
			"a": agentNode("a"), "b": agentNode("b"),
		}},
		"a tool entry node": {Id: "child", Nodes: map[string]*missionpb.MissionNode{
			"scan": toolNode("nmap"), "triage": agentNode("triage", "scan"),
		}},
		"no node": {Id: "child"},
	} {
		if _, err := firstNodeOfDefinition(def, "", nil); !errors.Is(err, errNoSingleEntryNode) {
			t.Errorf("%s: err = %v, want errNoSingleEntryNode", name, err)
		}
	}

	bad := &missionpb.MissionDefinition{Id: "child", Nodes: map[string]*missionpb.MissionNode{
		"a": agentNode("a", "b"), "b": agentNode("b", "a"),
	}}
	if _, err := firstNodeOfDefinition(bad, "", nil); err == nil {
		t.Error("a cycle with no entry node was accepted")
	}
}
