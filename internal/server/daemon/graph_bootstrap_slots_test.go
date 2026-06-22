// graph_bootstrap_slots_test.go tests that convertToSchemaNode correctly
// serialises AgentNodeConfig.llm_slots into the "__llm_slots" sentinel key
// inside TaskConfig.  This is the first seam in the per-node-slot-override
// pipeline (gibson#539).
package daemon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// makeAgentNode is a helper that produces a minimal proto MissionNode of type
// AGENT carrying the given llm_slots bindings.
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

func TestConvertToSchemaNode_LLMSlotsSerialised(t *testing.T) {
	missionID := types.NewID()
	nodeDef := makeAgentNodeProto("my-agent", []*missionpb.LLMSlotConfig{
		{Slot: "primary", Provider: "anthropic", Model: "claude-3-5-sonnet"},
		{Slot: "fast", Provider: "openai", Model: "gpt-4o-mini"},
	})

	node := convertToSchemaNode(missionID, nodeDef, false)
	require.NotNil(t, node)

	rawSlots, ok := node.TaskConfig["__llm_slots"]
	require.True(t, ok, "expected __llm_slots key in TaskConfig")

	entries, ok := rawSlots.([]map[string]string)
	require.True(t, ok, "expected __llm_slots to be []map[string]string")
	require.Len(t, entries, 2)

	// Use a stable sort check: both entries must appear (order is proto-slice order)
	bySlot := make(map[string]map[string]string)
	for _, e := range entries {
		bySlot[e["slot"]] = e
	}
	assert.Equal(t, "anthropic", bySlot["primary"]["provider"])
	assert.Equal(t, "claude-3-5-sonnet", bySlot["primary"]["model"])
	assert.Equal(t, "openai", bySlot["fast"]["provider"])
	assert.Equal(t, "gpt-4o-mini", bySlot["fast"]["model"])
}

func TestConvertToSchemaNode_EmptyProviderSkipped(t *testing.T) {
	missionID := types.NewID()
	nodeDef := makeAgentNodeProto("my-agent", []*missionpb.LLMSlotConfig{
		{Slot: "primary", Provider: "", Model: ""}, // empty provider — must be skipped
		{Slot: "fast", Provider: "openai", Model: "gpt-4o-mini"},
	})

	node := convertToSchemaNode(missionID, nodeDef, false)
	require.NotNil(t, node)

	rawSlots, ok := node.TaskConfig["__llm_slots"]
	require.True(t, ok, "expected __llm_slots key (at least one valid entry)")

	entries, ok := rawSlots.([]map[string]string)
	require.True(t, ok)
	require.Len(t, entries, 1, "empty-provider entry must be omitted")
	assert.Equal(t, "fast", entries[0]["slot"])
}

func TestConvertToSchemaNode_NoSlotsNoKey(t *testing.T) {
	missionID := types.NewID()
	nodeDef := makeAgentNodeProto("my-agent", nil) // no llm_slots at all

	node := convertToSchemaNode(missionID, nodeDef, false)
	require.NotNil(t, node)

	_, ok := node.TaskConfig["__llm_slots"]
	assert.False(t, ok, "__llm_slots key must be absent when there are no slot bindings")
}

func TestConvertToSchemaNode_AllEmptyProvidersNoKey(t *testing.T) {
	missionID := types.NewID()
	nodeDef := makeAgentNodeProto("my-agent", []*missionpb.LLMSlotConfig{
		{Slot: "primary", Provider: ""},
		{Slot: "fast", Provider: ""},
	})

	node := convertToSchemaNode(missionID, nodeDef, false)
	require.NotNil(t, node)

	_, ok := node.TaskConfig["__llm_slots"]
	assert.False(t, ok, "__llm_slots key must be absent when all providers are empty")
}
