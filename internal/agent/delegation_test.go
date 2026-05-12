package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/tool"
	"github.com/zero-day-ai/gibson/internal/types"
	"google.golang.org/protobuf/proto"
)

// mockComponentDiscovery implements ComponentDiscovery for testing.
//
// Note: post plugin-runtime Spec 2 Phase 7, ComponentDiscovery only carries
// DiscoverTool — plugin discovery moved to the daemon-side
// PluginInvokeService. Tests for plugin behaviour now exercise the
// "DelegationHarness has no plugin dispatch path" error contract directly.
type mockComponentDiscovery struct {
	discoverToolFunc func(ctx context.Context, name string) (tool.Tool, error)
}

func (m *mockComponentDiscovery) DiscoverTool(ctx context.Context, name string) (tool.Tool, error) {
	if m.discoverToolFunc != nil {
		return m.discoverToolFunc(ctx, name)
	}
	return nil, errors.New("tool not found")
}

// mockTool implements tool.Tool for testing
type mockTool struct {
	name              string
	version           string
	description       string
	tags              []string
	inputMessageType  string
	outputMessageType string
	executeProtoFunc  func(ctx context.Context, input proto.Message) (proto.Message, error)
	healthFunc        func(ctx context.Context) types.HealthStatus
}

func (m *mockTool) Name() string              { return m.name }
func (m *mockTool) Version() string           { return m.version }
func (m *mockTool) Description() string       { return m.description }
func (m *mockTool) Tags() []string            { return m.tags }
func (m *mockTool) InputMessageType() string  { return m.inputMessageType }
func (m *mockTool) OutputMessageType() string { return m.outputMessageType }

func (m *mockTool) ExecuteProto(ctx context.Context, input proto.Message) (proto.Message, error) {
	if m.executeProtoFunc != nil {
		return m.executeProtoFunc(ctx, input)
	}
	return nil, nil
}

func (m *mockTool) Health(ctx context.Context) types.HealthStatus {
	if m.healthFunc != nil {
		return m.healthFunc(ctx)
	}
	return types.Healthy("")
}

// TestRegistryToolExecutor tests the registryToolExecutor implementation
func TestRegistryToolExecutor(t *testing.T) {
	tests := []struct {
		name          string
		toolName      string
		input         map[string]any
		discoverFunc  func(ctx context.Context, name string) (tool.Tool, error)
		expectError   bool
		errorContains string
	}{
		{
			name:     "successful tool discovery",
			toolName: "test-tool",
			input:    map[string]any{"key": "value"},
			discoverFunc: func(ctx context.Context, name string) (tool.Tool, error) {
				return &mockTool{
					name:    "test-tool",
					version: "1.0.0",
				}, nil
			},
			// Proto-to-map conversion IS implemented (see delegation.go's
			// ExecuteTool), but a tool that doesn't declare its input
			// proto type (mockTool with empty inputMessageType) is
			// rejected before the conversion runs.
			expectError:   true,
			errorContains: "has no InputMessageType",
		},
		{
			name:     "tool not found",
			toolName: "nonexistent-tool",
			input:    map[string]any{"key": "value"},
			discoverFunc: func(ctx context.Context, name string) (tool.Tool, error) {
				return nil, errors.New("tool not found in registry")
			},
			expectError:   true,
			errorContains: "failed to discover tool",
		},
		{
			name:     "registry unavailable",
			toolName: "test-tool",
			input:    map[string]any{"key": "value"},
			discoverFunc: func(ctx context.Context, name string) (tool.Tool, error) {
				return nil, errors.New("registry connection failed")
			},
			expectError:   true,
			errorContains: "failed to discover tool",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			discovery := &mockComponentDiscovery{
				discoverToolFunc: tt.discoverFunc,
			}

			executor := &registryToolExecutor{
				discovery: discovery,
			}

			ctx := context.Background()
			result, err := executor.ExecuteTool(ctx, tt.toolName, tt.input)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

// TestRegistryPluginExecutor verifies that the DelegationHarness's plugin
// executor returns a structured error directing callers to the live harness's
// PluginInvokeService dispatch path. Pre-Phase-7 behaviour (in-process
// Plugin.Query) is no longer supported.
func TestRegistryPluginExecutor(t *testing.T) {
	discovery := &mockComponentDiscovery{}
	executor := &registryPluginExecutor{discovery: discovery}

	ctx := context.Background()
	result, err := executor.QueryPlugin(ctx, "any-plugin", "any-method", map[string]any{"k": "v"})
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "DelegationHarness has no plugin dispatch path")
}

// TestDelegationHarnessWithRegistryExecutors tests the integration of registry executors in DelegationHarness
func TestDelegationHarnessWithRegistryExecutors(t *testing.T) {
	t.Run("ExecuteTool with registry executor", func(t *testing.T) {
		discovery := &mockComponentDiscovery{
			discoverToolFunc: func(ctx context.Context, name string) (tool.Tool, error) {
				return &mockTool{
					name:    "test-tool",
					version: "1.0.0",
				}, nil
			},
		}

		harness := NewDelegationHarness(nil, discovery)
		ctx := context.Background()

		// Discovers the tool but rejects it because mockTool does not
		// declare an InputMessageType (proto conversion now works for
		// tools that declare it; this fixture intentionally does not).
		result, err := harness.ExecuteTool(ctx, "test-tool", map[string]any{"key": "value"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "has no InputMessageType")
		assert.Nil(t, result)
	})

	t.Run("QueryPlugin returns the no-dispatch error", func(t *testing.T) {
		discovery := &mockComponentDiscovery{}
		harness := NewDelegationHarness(nil, discovery)
		ctx := context.Background()

		result, err := harness.QueryPlugin(ctx, "any-plugin", "status", nil)
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "DelegationHarness has no plugin dispatch path")
	})

	t.Run("ExecuteTool discovery failure", func(t *testing.T) {
		discovery := &mockComponentDiscovery{
			discoverToolFunc: func(ctx context.Context, name string) (tool.Tool, error) {
				return nil, errors.New("tool not found")
			},
		}

		harness := NewDelegationHarness(nil, discovery)
		ctx := context.Background()

		result, err := harness.ExecuteTool(ctx, "missing-tool", map[string]any{"key": "value"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to discover tool")
		assert.Nil(t, result)
	})
}

// TestWithToolExecutor tests the WithToolExecutor builder method
func TestWithToolExecutor(t *testing.T) {
	customExecutor := &registryToolExecutor{
		discovery: &mockComponentDiscovery{},
	}

	harness := NewDelegationHarness(nil, &mockComponentDiscovery{})
	harness = harness.WithToolExecutor(customExecutor)

	assert.Equal(t, customExecutor, harness.toolExec)
}

// TestWithPluginExecutor tests the WithPluginExecutor builder method
func TestWithPluginExecutor(t *testing.T) {
	customExecutor := &registryPluginExecutor{
		discovery: &mockComponentDiscovery{},
	}

	harness := NewDelegationHarness(nil, &mockComponentDiscovery{})
	harness = harness.WithPluginExecutor(customExecutor)

	assert.Equal(t, customExecutor, harness.pluginExec)
}
