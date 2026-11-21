// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/tests/e2e/helpers"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

const (
	// skillScriptTool is the tool that runs a script of an Agent Skill. The
	// daemon places the files of the Agent Skill in its sandbox for each call
	// (gibson#1373).
	skillScriptTool = "skill-script"
	// skillScriptRef is the SetCatalogEnabled component_ref of the tool.
	skillScriptRef = "tool/" + skillScriptTool
)

// createSkillScriptMissionDefinition creates a mission of two nodes and returns
// its id. The first node is the held agent. The second node is a TOOL node that
// runs the script of an Agent Skill with the skill-script tool. The test holds
// the first node open, grants the Agent Skill to the mission, and then releases
// the node, so the tool node starts after the grant exists. The input names the
// script as "<Agent Skill>/<path>".
func createSkillScriptMissionDefinition(
	t *testing.T, ctx context.Context, daemon daemonpb.DaemonServiceClient, name, agent, script string,
) string {
	t.Helper()
	resp, err := daemon.CreateMissionDefinition(ctx, &daemonpb.CreateMissionDefinitionRequest{
		Definition: &missionpb.MissionDefinition{
			Name:        helpers.RunName(t, name),
			Description: "a script of an Agent Skill runs in the sandbox of the call (gibson#1373)",
			Nodes: map[string]*missionpb.MissionNode{
				"agent": {
					Id: "agent", Name: "Agent", Description: "An outside agent that the test holds open",
					Type: missionpb.NodeType_NODE_TYPE_AGENT,
					Config: &missionpb.MissionNode_AgentConfig{
						AgentConfig: &missionpb.AgentNodeConfig{AgentName: agent},
					},
				},
				"script": {
					Id: "script", Name: "Script", Description: "Runs a script of an Agent Skill in a sandbox",
					Type: missionpb.NodeType_NODE_TYPE_TOOL,
					Config: &missionpb.MissionNode_ToolConfig{
						ToolConfig: &missionpb.ToolNodeConfig{
							ToolName: skillScriptTool,
							Input:    map[string]string{"target": script},
						},
					},
				},
			},
			Edges:       []*missionpb.MissionEdge{{From: "agent", To: "script"}},
			EntryPoints: []string{"agent"},
		},
	})
	require.NoError(t, err, "CreateMissionDefinition(%s)", name)
	require.NotEmpty(t, resp.GetMissionDefinitionId(), "CreateMissionDefinition(%s) gave no id", name)
	return resp.GetMissionDefinitionId()
}
