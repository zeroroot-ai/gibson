// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// mission_projection_slots_test.go tests nodeSlotPins: the LLM slot pins of an
// agent node (AgentNodeConfig.llm_slots) that the projection puts on the
// node's work (gibson#539, gibson#1203).
package daemon

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// makeAgentNodeProto produces a minimal AGENT node with the given llm_slots.
func makeAgentNodeProto(agentName string, slots []*missionpb.LLMSlotConfig) *missionpb.MissionNode {
	return &missionpb.MissionNode{
		Id:   "node-1",
		Type: missionpb.NodeType_NODE_TYPE_AGENT,
		Config: &missionpb.MissionNode_AgentConfig{
			AgentConfig: &missionpb.AgentNodeConfig{
				AgentName: agentName,
				LlmSlots:  slots,
			},
		},
	}
}

func TestNodeSlotPins_EachSlotKeepsItsProviderAndModel(t *testing.T) {
	pins := nodeSlotPins(makeAgentNodeProto("my-agent", []*missionpb.LLMSlotConfig{
		{Slot: "primary", Provider: "anthropic", Model: "claude-3-5-sonnet"},
		{Slot: "fast", Provider: "openai", Model: "gpt-4o-mini"},
	}))
	assert.Equal(t, map[string]agent.SlotConfig{
		"primary": {Provider: "anthropic", Model: "claude-3-5-sonnet"},
		"fast":    {Provider: "openai", Model: "gpt-4o-mini"},
	}, pins)
}

// An entry with no provider, or with no slot name, pins nothing.
func TestNodeSlotPins_AnEntryWithNoProviderIsLeftOut(t *testing.T) {
	pins := nodeSlotPins(makeAgentNodeProto("my-agent", []*missionpb.LLMSlotConfig{
		{Slot: "primary", Provider: ""},
		{Slot: "", Provider: "openai"},
		{Slot: "fast", Provider: "openai", Model: "gpt-4o-mini"},
	}))
	assert.Equal(t, map[string]agent.SlotConfig{"fast": {Provider: "openai", Model: "gpt-4o-mini"}}, pins)
}

// A node with no pin, and a node that is not an agent, give nil.
func TestNodeSlotPins_NoPinIsNil(t *testing.T) {
	assert.Nil(t, nodeSlotPins(makeAgentNodeProto("my-agent", nil)))
	assert.Nil(t, nodeSlotPins(makeAgentNodeProto("my-agent", []*missionpb.LLMSlotConfig{{Slot: "fast"}})))
	assert.Nil(t, nodeSlotPins(&missionpb.MissionNode{Type: missionpb.NodeType_NODE_TYPE_TOOL}))
}
