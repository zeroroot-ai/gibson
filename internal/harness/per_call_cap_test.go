package harness

import (
	"testing"

	daemonv1 "github.com/zero-day-ai/sdk/api/gen/gibson/daemon/v1"
	missionv1 "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
)

func ptr32(v int32) *int32 { return &v }

func agentNode(cap *int32) *missionv1.MissionNode {
	return &missionv1.MissionNode{
		Type: missionv1.NodeType_NODE_TYPE_AGENT,
		Config: &missionv1.MissionNode_AgentConfig{
			AgentConfig: &missionv1.AgentNodeConfig{
				AgentName:        "a",
				MaxTokensPerCall: cap,
			},
		},
	}
}

func toolNode(cap *int32) *missionv1.MissionNode {
	return &missionv1.MissionNode{
		Type: missionv1.NodeType_NODE_TYPE_TOOL,
		Config: &missionv1.MissionNode_ToolConfig{
			ToolConfig: &missionv1.ToolNodeConfig{
				ToolName:         "t",
				MaxTokensPerCall: cap,
			},
		},
	}
}

func pluginNode(cap *int32) *missionv1.MissionNode {
	return &missionv1.MissionNode{
		Type: missionv1.NodeType_NODE_TYPE_PLUGIN,
		Config: &missionv1.MissionNode_PluginConfig{
			PluginConfig: &missionv1.PluginNodeConfig{
				PluginName:       "p",
				Method:           "do",
				MaxTokensPerCall: cap,
			},
		},
	}
}

func TestEffectivePerCallCap_node_override_wins(t *testing.T) {
	cs := &daemonv1.MissionConstraints{MaxTokensPerCall: 1000}
	got := EffectivePerCallCap(agentNode(ptr32(2048)), cs)
	if got != 2048 {
		t.Errorf("got=%d want=2048 (per-node override)", got)
	}
}

func TestEffectivePerCallCap_zero_node_override_disables_cap(t *testing.T) {
	cs := &daemonv1.MissionConstraints{MaxTokensPerCall: 1000}
	got := EffectivePerCallCap(agentNode(ptr32(0)), cs)
	if got != 0 {
		t.Errorf("got=%d want=0 (explicit 0 shadows mission cap)", got)
	}
}

func TestEffectivePerCallCap_unset_node_falls_back_to_mission(t *testing.T) {
	cs := &daemonv1.MissionConstraints{MaxTokensPerCall: 1000}
	got := EffectivePerCallCap(agentNode(nil), cs)
	if got != 1000 {
		t.Errorf("got=%d want=1000 (mission default)", got)
	}
}

func TestEffectivePerCallCap_no_constraints_no_node(t *testing.T) {
	got := EffectivePerCallCap(agentNode(nil), nil)
	if got != 0 {
		t.Errorf("got=%d want=0", got)
	}
}

func TestEffectivePerCallCap_tool_override(t *testing.T) {
	cs := &daemonv1.MissionConstraints{MaxTokensPerCall: 100}
	got := EffectivePerCallCap(toolNode(ptr32(500)), cs)
	if got != 500 {
		t.Errorf("got=%d want=500", got)
	}
}

func TestEffectivePerCallCap_plugin_override(t *testing.T) {
	cs := &daemonv1.MissionConstraints{MaxTokensPerCall: 100}
	got := EffectivePerCallCap(pluginNode(ptr32(300)), cs)
	if got != 300 {
		t.Errorf("got=%d want=300", got)
	}
}

func TestEffectivePerCallCap_nil_node(t *testing.T) {
	cs := &daemonv1.MissionConstraints{MaxTokensPerCall: 750}
	got := EffectivePerCallCap(nil, cs)
	if got != 750 {
		t.Errorf("got=%d want=750", got)
	}
}

func TestEffectivePerCallCap_zero_mission_no_cap(t *testing.T) {
	cs := &daemonv1.MissionConstraints{MaxTokensPerCall: 0}
	got := EffectivePerCallCap(agentNode(nil), cs)
	if got != 0 {
		t.Errorf("got=%d want=0", got)
	}
}

func TestEffectivePerCallCap_condition_node_no_overhead(t *testing.T) {
	// CONDITION nodes don't carry max_tokens_per_call; should
	// always fall through to mission-level.
	node := &missionv1.MissionNode{
		Type: missionv1.NodeType_NODE_TYPE_CONDITION,
		Config: &missionv1.MissionNode_ConditionConfig{
			ConditionConfig: &missionv1.ConditionNodeConfig{Expression: "true"},
		},
	}
	cs := &daemonv1.MissionConstraints{MaxTokensPerCall: 600}
	got := EffectivePerCallCap(node, cs)
	if got != 600 {
		t.Errorf("got=%d want=600 (CONDITION → mission cap)", got)
	}
}
