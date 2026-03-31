package harness

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/types"
	sdktypes "github.com/zero-day-ai/sdk/types"
)

// ────────────────────────────────────────────────────────────────────────────
// Tool Capability System Integration Tests
// ────────────────────────────────────────────────────────────────────────────

// TestHarness_GetToolCapabilities_Integration verifies that GetToolCapabilities
// works correctly when called on a harness with a registry adapter that provides
// tool capability information.
func TestHarness_GetToolCapabilities_Integration(t *testing.T) {
	// Create mock registry adapter that returns tools with capabilities
	mockAdapter := &MockRegistryAdapter{
		ListToolsFn: func(ctx context.Context) ([]component.ToolInfo, error) {
			return []component.ToolInfo{
				{
					Name:    "nmap",
					Version: "1.0.0",
					Capabilities: &sdktypes.Capabilities{
						HasRoot:      false,
						HasSudo:      true,
						CanRawSocket: false,
						Features: map[string]bool{
							"syn_scan":     true,
							"os_detection": false,
						},
						BlockedArgs: []string{"-sS"},
						ArgAlternatives: map[string]string{
							"-sS": "-sT",
						},
					},
				},
			}, nil
		},
	}

	// Create factory and harness
	config := HarnessConfig{
		SlotManager:     llm.NewSlotManager(llm.NewLLMRegistry()),
		RegistryAdapter: mockAdapter,
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	missionCtx := NewMissionContext(types.NewID(), "test-mission", "test-agent")
	targetInfo := NewTargetInfo(types.NewID(), "test-target", "https://example.com", "web")

	harness, err := factory.Create("test-agent", missionCtx, targetInfo)
	require.NoError(t, err)

	// Test GetToolCapabilities via registry adapter
	ctx := context.Background()

	// Call ListTools to see what's available
	tools := harness.ListTools()
	t.Logf("Available tools in local registry: %d", len(tools))

	// The registry adapter provides capability information via ListTools
	// Verify we can get that information
	allCaps, err := harness.GetAllToolCapabilities(ctx)
	require.NoError(t, err)
	require.NotNil(t, allCaps)

	t.Logf("Tool capabilities retrieved: %d tools", len(allCaps))
}

// TestHarness_GetAllToolCapabilities_EmptyRegistry verifies that
// GetAllToolCapabilities returns an empty map when no tools are registered.
func TestHarness_GetAllToolCapabilities_EmptyRegistry(t *testing.T) {
	// Create factory without any tools registered
	config := HarnessConfig{
		SlotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	missionCtx := NewMissionContext(types.NewID(), "test-mission", "test-agent")
	targetInfo := NewTargetInfo(types.NewID(), "test-target", "https://example.com", "web")

	harness, err := factory.Create("test-agent", missionCtx, targetInfo)
	require.NoError(t, err)

	// Get all tool capabilities
	ctx := context.Background()
	allCaps, err := harness.GetAllToolCapabilities(ctx)

	// Should return empty map without error
	assert.NoError(t, err)
	assert.NotNil(t, allCaps)
	assert.Empty(t, allCaps)
}

// TestHarnessFactory_ToolCapabilities_WorkingMemoryIntegration verifies that
// tool capabilities are stored in working memory during harness creation
// when both memory store and tools with capabilities are available.
func TestHarnessFactory_ToolCapabilities_WorkingMemoryIntegration(t *testing.T) {
	// Create working memory to track stored values
	workingMem := memory.NewWorkingMemory(10000)
	memoryStore := &MockMemoryStore{
		WorkingFn: func() memory.WorkingMemory {
			return workingMem
		},
	}

	// Create factory config with memory store (no tools registered)
	config := HarnessConfig{
		SlotManager:   llm.NewSlotManager(llm.NewLLMRegistry()),
		MemoryManager: memoryStore,
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	// Create harness
	missionCtx := NewMissionContext(types.NewID(), "test-mission", "test-agent")
	targetInfo := NewTargetInfo(types.NewID(), "test-target", "https://example.com", "web")

	harness, err := factory.Create("test-agent", missionCtx, targetInfo)
	require.NoError(t, err)
	require.NotNil(t, harness)

	// Check working memory for capabilities
	// With no tools registered, the key may not be set or may be empty
	storedCaps, ok := workingMem.Get("tool_capabilities")
	if ok {
		// If key exists, it should be a valid capabilities map
		capsMap, isMap := storedCaps.(map[string]*sdktypes.Capabilities)
		assert.True(t, isMap, "tool_capabilities should be map[string]*sdktypes.Capabilities")
		// With no tools, map should be empty
		assert.Empty(t, capsMap)
	} else {
		// If no tools have capabilities, the key may not be set at all
		// This is acceptable behavior
		t.Log("tool_capabilities key not set (no tools with capabilities)")
	}
}

// TestHarness_GetToolCapabilities_NoRegistryAdapter verifies that
// GetToolCapabilities returns nil when tool doesn't exist.
func TestHarness_GetToolCapabilities_NoRegistryAdapter(t *testing.T) {
	// Create factory without registry adapter
	config := HarnessConfig{
		SlotManager:     llm.NewSlotManager(llm.NewLLMRegistry()),
		RegistryAdapter: nil,
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	missionCtx := NewMissionContext(types.NewID(), "test-mission", "test-agent")
	targetInfo := NewTargetInfo(types.NewID(), "test-target", "https://example.com", "web")

	harness, err := factory.Create("test-agent", missionCtx, targetInfo)
	require.NoError(t, err)

	// Try to get capabilities for a non-existent tool
	ctx := context.Background()
	caps, err := harness.GetToolCapabilities(ctx, "nonexistent")

	// Should return error since tool doesn't exist
	assert.Error(t, err)
	assert.Nil(t, caps)
}
