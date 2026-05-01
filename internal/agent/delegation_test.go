package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/plugin"
	"github.com/zero-day-ai/gibson/internal/tool"
	"github.com/zero-day-ai/gibson/internal/types"
	"google.golang.org/protobuf/proto"
)

// mockComponentDiscovery implements ComponentDiscovery for testing
type mockComponentDiscovery struct {
	discoverToolFunc   func(ctx context.Context, name string) (tool.Tool, error)
	discoverPluginFunc func(ctx context.Context, name string) (plugin.Plugin, error)
}

func (m *mockComponentDiscovery) DiscoverTool(ctx context.Context, name string) (tool.Tool, error) {
	if m.discoverToolFunc != nil {
		return m.discoverToolFunc(ctx, name)
	}
	return nil, errors.New("tool not found")
}

func (m *mockComponentDiscovery) DiscoverPlugin(ctx context.Context, name string) (plugin.Plugin, error) {
	if m.discoverPluginFunc != nil {
		return m.discoverPluginFunc(ctx, name)
	}
	return nil, errors.New("plugin not found")
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

// mockPlugin implements plugin.Plugin for testing
type mockPlugin struct {
	name        string
	version     string
	queryFunc   func(ctx context.Context, method string, params map[string]any) (any, error)
	methodsFunc func() []plugin.MethodDescriptor
}

func (m *mockPlugin) Name() string        { return m.name }
func (m *mockPlugin) Version() string     { return m.version }
func (m *mockPlugin) Description() string { return "" }

func (m *mockPlugin) Initialize(ctx context.Context, config map[string]any) error {
	return nil
}

func (m *mockPlugin) Shutdown(ctx context.Context) error {
	return nil
}

func (m *mockPlugin) Query(ctx context.Context, method string, params map[string]any) (any, error) {
	if m.queryFunc != nil {
		return m.queryFunc(ctx, method, params)
	}
	return nil, nil
}

func (m *mockPlugin) Methods() []plugin.MethodDescriptor {
	if m.methodsFunc != nil {
		return m.methodsFunc()
	}
	return nil
}

func (m *mockPlugin) Health(ctx context.Context) types.HealthStatus {
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
			expectError:   true, // proto-to-map conversion not implemented yet
			errorContains: "proto-to-map conversion not yet implemented",
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

// TestRegistryPluginExecutor tests the registryPluginExecutor implementation
func TestRegistryPluginExecutor(t *testing.T) {
	tests := []struct {
		name           string
		pluginName     string
		method         string
		params         map[string]any
		discoverFunc   func(ctx context.Context, name string) (plugin.Plugin, error)
		expectedResult any
		expectError    bool
		errorContains  string
	}{
		{
			name:       "successful plugin query",
			pluginName: "test-plugin",
			method:     "search",
			params:     map[string]any{"query": "test"},
			discoverFunc: func(ctx context.Context, name string) (plugin.Plugin, error) {
				return &mockPlugin{
					name:    "test-plugin",
					version: "1.0.0",
					queryFunc: func(ctx context.Context, method string, params map[string]any) (any, error) {
						return map[string]any{"results": []string{"result1", "result2"}}, nil
					},
				}, nil
			},
			expectedResult: map[string]any{"results": []string{"result1", "result2"}},
			expectError:    false,
		},
		{
			name:       "plugin not found",
			pluginName: "nonexistent-plugin",
			method:     "search",
			params:     map[string]any{"query": "test"},
			discoverFunc: func(ctx context.Context, name string) (plugin.Plugin, error) {
				return nil, errors.New("plugin not found in registry")
			},
			expectError:   true,
			errorContains: "failed to discover plugin",
		},
		{
			name:       "plugin query failure",
			pluginName: "test-plugin",
			method:     "invalid-method",
			params:     map[string]any{"query": "test"},
			discoverFunc: func(ctx context.Context, name string) (plugin.Plugin, error) {
				return &mockPlugin{
					name:    "test-plugin",
					version: "1.0.0",
					queryFunc: func(ctx context.Context, method string, params map[string]any) (any, error) {
						return nil, errors.New("method not supported")
					},
				}, nil
			},
			expectError:   true,
			errorContains: "plugin test-plugin query failed",
		},
		{
			name:       "registry unavailable",
			pluginName: "test-plugin",
			method:     "search",
			params:     map[string]any{"query": "test"},
			discoverFunc: func(ctx context.Context, name string) (plugin.Plugin, error) {
				return nil, errors.New("registry connection failed")
			},
			expectError:   true,
			errorContains: "failed to discover plugin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			discovery := &mockComponentDiscovery{
				discoverPluginFunc: tt.discoverFunc,
			}

			executor := &registryPluginExecutor{
				discovery: discovery,
			}

			ctx := context.Background()
			result, err := executor.QueryPlugin(ctx, tt.pluginName, tt.method, tt.params)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedResult, result)
			}
		})
	}
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

		// Should discover tool but fail on proto conversion
		result, err := harness.ExecuteTool(ctx, "test-tool", map[string]any{"key": "value"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "proto-to-map conversion not yet implemented")
		assert.Nil(t, result)
	})

	t.Run("QueryPlugin with registry executor", func(t *testing.T) {
		discovery := &mockComponentDiscovery{
			discoverPluginFunc: func(ctx context.Context, name string) (plugin.Plugin, error) {
				return &mockPlugin{
					name:    "test-plugin",
					version: "1.0.0",
					queryFunc: func(ctx context.Context, method string, params map[string]any) (any, error) {
						return map[string]any{"status": "success"}, nil
					},
				}, nil
			},
		}

		harness := NewDelegationHarness(nil, discovery)
		ctx := context.Background()

		// Should discover plugin and execute query successfully
		result, err := harness.QueryPlugin(ctx, "test-plugin", "status", nil)
		require.NoError(t, err)
		assert.Equal(t, map[string]any{"status": "success"}, result)
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

	t.Run("QueryPlugin discovery failure", func(t *testing.T) {
		discovery := &mockComponentDiscovery{
			discoverPluginFunc: func(ctx context.Context, name string) (plugin.Plugin, error) {
				return nil, errors.New("plugin not found")
			},
		}

		harness := NewDelegationHarness(nil, discovery)
		ctx := context.Background()

		result, err := harness.QueryPlugin(ctx, "missing-plugin", "method", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to discover plugin")
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
