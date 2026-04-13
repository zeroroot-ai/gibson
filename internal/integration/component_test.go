package integration

// Component Registration Flow Integration Tests (Stage 2 - Task 7.1)
//
// This test suite validates the complete lifecycle and integration of Gibson's
// component system, including tools, plugins, and agents. It tests both internal
// (native Go) and external (gRPC) implementations.
//
// Test Coverage:
//  - TestToolLifecycle: Complete tool registration, execution, metrics, health, and unregistration
//  - TestPluginLifecycle: Plugin initialization, querying, method listing, and shutdown
//  - TestAgentLifecycle: Agent factory registration, instance creation, task execution, and cleanup
//  - TestMixedComponents: Integration of internal and external components
//  - TestConcurrentComponentOperations: Thread-safety under concurrent load
//  - TestComponentInteraction: Cross-component integration (tools, plugins, agents working together)
//
// Mock Implementations:
//  - mockTool/mockExternalTool: Implements Tool interface with schema validation
//  - mockPlugin/mockExternalPlugin: Implements Plugin interface with lifecycle management
//  - mockAgent/mockExternalAgent: Implements Agent interface with full capabilities
//  - mockToolExecutor/mockPluginExecutor: Bridge components for integration testing
//
// This test suite ensures that all Stage 2 packages (schema, component, tool, plugin, agent)
// work together correctly and provides confidence in the component architecture before
// moving to Stage 3 (techniques and missions).

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/plugin"
	"github.com/zero-day-ai/gibson/internal/schema"
	"github.com/zero-day-ai/gibson/internal/tool"
	"github.com/zero-day-ai/gibson/internal/types"
)

// TestToolLifecycle tests the complete tool registration lifecycle
func TestToolLifecycle(t *testing.T) {
	ctx := context.Background()
	registry := tool.NewToolRegistry()

	// Step 1: Register a tool
	t.Run("RegisterTool", func(t *testing.T) {
		mockTool := newMockTool("echo", "1.0.0")
		err := registry.RegisterInternal(mockTool)
		require.NoError(t, err, "should register tool successfully")

		// Verify tool is registered
		tools := registry.List()
		assert.Len(t, tools, 1, "should have 1 tool registered")
		assert.Equal(t, "echo", tools[0].Name, "tool name should match")
		assert.False(t, tools[0].IsExternal, "should be internal tool")

		t.Logf("Registered tool: %s v%s", tools[0].Name, tools[0].Version)
	})

	// Step 2: Execute the tool
	t.Run("ExecuteTool", func(t *testing.T) {
		input := map[string]any{"message": "Hello, Gibson!"}
		output, err := registry.Execute(ctx, "echo", input)
		require.NoError(t, err, "tool execution should succeed")
		require.NotNil(t, output, "output should not be nil")

		assert.Equal(t, "Hello, Gibson!", output["message"], "output should match input")
		assert.Contains(t, output, "timestamp", "output should include timestamp")

		t.Logf("Tool executed successfully: %v", output)
	})

	// Step 3: Check metrics
	t.Run("CheckMetrics", func(t *testing.T) {
		metrics, err := registry.Metrics("echo")
		require.NoError(t, err, "should retrieve metrics")

		assert.Equal(t, int64(1), metrics.TotalCalls, "should have 1 total call")
		assert.Equal(t, int64(1), metrics.SuccessCalls, "should have 1 success call")
		assert.Equal(t, int64(0), metrics.FailedCalls, "should have 0 failed calls")
		assert.Greater(t, metrics.AvgDuration, time.Duration(0), "should have non-zero duration")

		t.Logf("Metrics: %d calls, %.2f%% success, avg duration: %v",
			metrics.TotalCalls, metrics.SuccessRate()*100, metrics.AvgDuration)
	})

	// Step 4: Health check
	t.Run("HealthCheck", func(t *testing.T) {
		health := registry.Health(ctx)
		assert.True(t, health.IsHealthy(), "registry should be healthy")
		assert.Equal(t, types.HealthStateHealthy, health.State, "health state should be healthy")

		toolHealth := registry.ToolHealth(ctx, "echo")
		assert.True(t, toolHealth.IsHealthy(), "tool should be healthy")

		t.Logf("Health: %s - %s", health.State, health.Message)
	})

	// Step 5: Unregister the tool
	t.Run("UnregisterTool", func(t *testing.T) {
		err := registry.Unregister("echo")
		require.NoError(t, err, "should unregister tool successfully")

		// Verify tool is removed
		tools := registry.List()
		assert.Len(t, tools, 0, "should have 0 tools registered")

		// Try to execute unregistered tool
		_, err = registry.Execute(ctx, "echo", map[string]any{})
		assert.Error(t, err, "should fail to execute unregistered tool")

		t.Logf("Tool unregistered successfully")
	})
}

// TestPluginLifecycle tests the complete plugin registration lifecycle
func TestPluginLifecycle(t *testing.T) {
	ctx := context.Background()
	registry := plugin.NewPluginRegistry(nil)

	// Step 1: Register a plugin
	t.Run("RegisterPlugin", func(t *testing.T) {
		mockPlugin := newMockPlugin("database", "1.0.0")
		cfg := plugin.PluginConfig{
			Name:       "database",
			Settings:   map[string]any{"connection": "mock://localhost"},
			Timeout:    30 * time.Second,
			RetryCount: 3,
		}

		err := registry.Register(mockPlugin, cfg)
		require.NoError(t, err, "should register plugin successfully")

		// Verify plugin is registered
		plugins := registry.List()
		assert.Len(t, plugins, 1, "should have 1 plugin registered")
		assert.Equal(t, "database", plugins[0].Name, "plugin name should match")
		assert.Equal(t, plugin.PluginStatusRunning, plugins[0].Status, "plugin should be running")
		assert.False(t, plugins[0].IsExternal, "should be internal plugin")

		t.Logf("Registered plugin: %s v%s (status: %s)", plugins[0].Name, plugins[0].Version, plugins[0].Status)
	})

	// Step 2: Initialize check (already done during registration)
	t.Run("VerifyInitialized", func(t *testing.T) {
		p, err := registry.Get("database")
		require.NoError(t, err, "should get plugin")
		require.NotNil(t, p, "plugin should not be nil")

		// Plugin should be running after registration
		health := p.Health(ctx)
		assert.True(t, health.IsHealthy(), "plugin should be healthy after initialization")

		t.Logf("Plugin initialized and healthy")
	})

	// Step 3: Query the plugin
	t.Run("QueryPlugin", func(t *testing.T) {
		result, err := registry.Query(ctx, "database", "query", map[string]any{
			"sql": "SELECT * FROM users",
		})
		require.NoError(t, err, "query should succeed")
		require.NotNil(t, result, "result should not be nil")

		resultMap, ok := result.(map[string]any)
		require.True(t, ok, "result should be a map")
		assert.Equal(t, "query executed", resultMap["status"], "status should match")

		t.Logf("Plugin query executed: %v", result)
	})

	// Step 4: List methods
	t.Run("ListMethods", func(t *testing.T) {
		methods, err := registry.Methods("database")
		require.NoError(t, err, "should list methods")
		assert.Len(t, methods, 2, "should have 2 methods")

		methodNames := make([]string, len(methods))
		for i, m := range methods {
			methodNames[i] = m.Name
		}
		assert.Contains(t, methodNames, "query", "should have query method")
		assert.Contains(t, methodNames, "execute", "should have execute method")

		t.Logf("Plugin methods: %v", methodNames)
	})

	// Step 5: Health check
	t.Run("HealthCheck", func(t *testing.T) {
		health := registry.Health(ctx)
		assert.True(t, health.IsHealthy(), "registry should be healthy")

		t.Logf("Health: %s - %s", health.State, health.Message)
	})

	// Step 6: Shutdown (unregister)
	t.Run("ShutdownPlugin", func(t *testing.T) {
		err := registry.Unregister("database")
		require.NoError(t, err, "should unregister plugin successfully")

		// Verify plugin is removed
		plugins := registry.List()
		assert.Len(t, plugins, 0, "should have 0 plugins registered")

		// Try to query unregistered plugin
		_, err = registry.Query(ctx, "database", "query", map[string]any{})
		assert.Error(t, err, "should fail to query unregistered plugin")

		t.Logf("Plugin unregistered successfully")
	})
}

// TestAgentLifecycle tests the complete agent registration lifecycle
func TestAgentLifecycle(t *testing.T) {
	t.Skip("Legacy AgentRegistry removed - use registry.ComponentDiscovery instead")

	/*
		// This test is disabled - legacy code preserved below for reference
		ctx := context.Background()
		registry := agent.NewAgentRegistry()

		// Step 1: Register an agent
		t.Run("RegisterAgent", func(t *testing.T) {
			factory := func(cfg agent.AgentConfig) (agent.Agent, error) {
				return newMockAgent("recon", "1.0.0"), nil
			}

			err := registry.RegisterInternal("recon", factory)
			require.NoError(t, err, "should register agent successfully")

			// Verify agent is registered
			agents := registry.List()
			assert.Len(t, agents, 1, "should have 1 agent registered")
			assert.Equal(t, "recon", agents[0].Name, "agent name should match")
			assert.False(t, agents[0].IsExternal, "should be internal agent")

			t.Logf("Registered agent: %s v%s", agents[0].Name, agents[0].Version)
		})

		// Step 2: Create agent instance
		t.Run("CreateInstance", func(t *testing.T) {
			cfg := agent.NewAgentConfig("recon").
				WithSetting("max_depth", 5).
				WithTimeout(10 * time.Minute)

			agentInstance, err := registry.Create("recon", cfg)
			require.NoError(t, err, "should create agent instance")
			require.NotNil(t, agentInstance, "agent instance should not be nil")

			// Initialize the agent
			err = agentInstance.Initialize(ctx, cfg)
			require.NoError(t, err, "should initialize agent")

			// Check capabilities
			caps := agentInstance.Capabilities()
			assert.NotEmpty(t, caps, "agent should have capabilities")
			assert.Contains(t, caps, "reconnaissance", "should have reconnaissance capability")

			t.Logf("Created agent instance with capabilities: %v", caps)
		})

		// Step 3: Execute task
		t.Run("ExecuteTask", func(t *testing.T) {
			task := agent.NewTask(
				"scan-target",
				"Scan the target for vulnerabilities",
				map[string]any{"target": "https://example.com"},
			).WithTimeout(5 * time.Minute)

			// Create harness for task execution
			harness := agent.NewDelegationHarness(registry, registry)

			// Execute via delegation
			result, err := registry.DelegateToAgent(ctx, "recon", task, harness)
			require.NoError(t, err, "task execution should succeed")
			assert.Equal(t, agent.ResultStatusCompleted, result.Status, "task should be completed")
			assert.NotEmpty(t, result.Output, "should have output")

			// Check findings
			assert.Greater(t, len(result.Findings), 0, "should have at least one finding")
			assert.Equal(t, agent.SeverityInfo, result.Findings[0].Severity, "first finding should be info")

			t.Logf("Task executed: status=%s, findings=%d, duration=%v",
				result.Status, len(result.Findings), result.Metrics.Duration)
		})

		// Step 4: Check descriptor
		t.Run("GetDescriptor", func(t *testing.T) {
			desc, err := registry.GetDescriptor("recon")
			require.NoError(t, err, "should get descriptor")

			assert.Equal(t, "recon", desc.Name, "name should match")
			assert.Contains(t, desc.TargetTypes, component.TargetTypeLLMAPI, "should support LLM API targets")
			assert.Contains(t, desc.TechniqueTypes, component.TechniqueReconnaissance, "should support reconnaissance")
			assert.NotEmpty(t, desc.Slots, "should have LLM slots")

			t.Logf("Descriptor: %d capabilities, %d target types, %d technique types, %d slots",
				len(desc.Capabilities), len(desc.TargetTypes), len(desc.TechniqueTypes), len(desc.Slots))
		})

		// Step 5: Unregister agent
		t.Run("UnregisterAgent", func(t *testing.T) {
			err := registry.Unregister("recon")
			require.NoError(t, err, "should unregister agent successfully")

			// Verify agent is removed
			agents := registry.List()
			assert.Len(t, agents, 0, "should have 0 agents registered")

			t.Logf("Agent unregistered successfully")
		})
	*/
}

// TestMixedComponents tests integration of internal and external components
func TestMixedComponents(t *testing.T) {
	t.Skip("Legacy AgentRegistry removed - use registry.ComponentDiscovery instead")

	/*
		// This test is disabled - legacy code preserved below for reference
		ctx := context.Background()

		t.Run("MixedTools", func(t *testing.T) {
			registry := tool.NewToolRegistry()

			// Register internal tool
			internalTool := newMockTool("internal-tool", "1.0.0")
			err := registry.RegisterInternal(internalTool)
			require.NoError(t, err, "should register internal tool")

			// Register external tool
			externalTool := newMockExternalTool("external-tool", "2.0.0")
			err = registry.RegisterExternal("external-tool", externalTool)
			require.NoError(t, err, "should register external tool")

			// List all tools
			tools := registry.List()
			assert.Len(t, tools, 2, "should have 2 tools")

			// Count internal vs external
			internalCount := 0
			externalCount := 0
			for _, tool := range tools {
				if tool.IsExternal {
					externalCount++
				} else {
					internalCount++
				}
			}
			assert.Equal(t, 1, internalCount, "should have 1 internal tool")
			assert.Equal(t, 1, externalCount, "should have 1 external tool")

			// Execute both tools
			_, err = registry.Execute(ctx, "internal-tool", map[string]any{"message": "internal"})
			require.NoError(t, err, "internal tool should execute")

			_, err = registry.Execute(ctx, "external-tool", map[string]any{"message": "external"})
			require.NoError(t, err, "external tool should execute")

			t.Logf("Mixed tools test passed: %d internal, %d external", internalCount, externalCount)
		})

		t.Run("MixedPlugins", func(t *testing.T) {
			registry := plugin.NewPluginRegistry(nil)

			// Register internal plugin
			internalPlugin := newMockPlugin("internal-db", "1.0.0")
			err := registry.Register(internalPlugin, plugin.PluginConfig{Name: "internal-db"})
			require.NoError(t, err, "should register internal plugin")

			// Register external plugin
			externalPlugin := newMockExternalPlugin("external-api", "2.0.0")
			err = registry.RegisterExternal("external-api", externalPlugin, plugin.PluginConfig{Name: "external-api"})
			require.NoError(t, err, "should register external plugin")

			// List all plugins
			plugins := registry.List()
			assert.Len(t, plugins, 2, "should have 2 plugins")

			// Verify both are running
			for _, p := range plugins {
				assert.Equal(t, plugin.PluginStatusRunning, p.Status, "plugin should be running")
			}

			t.Logf("Mixed plugins test passed: %d plugins running", len(plugins))
		})

		t.Run("MixedAgents", func(t *testing.T) {
			// registry := agent.NewAgentRegistry()

			// Register internal agent
			internalFactory := func(cfg agent.AgentConfig) (agent.Agent, error) {
				return newMockAgent("internal-agent", "1.0.0"), nil
			}
			err := registry.RegisterInternal("internal-agent", internalFactory)
			require.NoError(t, err, "should register internal agent")

			// Register external agent
			externalAgent := newMockExternalAgent("external-agent", "2.0.0")
			err = registry.RegisterExternal("external-agent", externalAgent)
			require.NoError(t, err, "should register external agent")

			// List all agents
			agents := registry.List()
			assert.Len(t, agents, 2, "should have 2 agents")

			// Verify internal vs external flags
			for _, a := range agents {
				if a.Name == "internal-agent" {
					assert.False(t, a.IsExternal, "internal-agent should not be external")
				} else if a.Name == "external-agent" {
					assert.True(t, a.IsExternal, "external-agent should be external")
				}
			}

			t.Logf("Mixed agents test passed: %d agents registered", len(agents))
		})
	*/
}

// TestConcurrentComponentOperations tests thread-safety with concurrent operations
func TestConcurrentComponentOperations(t *testing.T) {
	t.Skip("Legacy AgentRegistry removed - use registry.ComponentDiscovery instead")

	/*
		// This test is disabled - legacy code preserved below for reference
		ctx := context.Background()

		t.Run("ConcurrentToolOps", func(t *testing.T) {
			registry := tool.NewToolRegistry()

			// Register initial tools
			for i := 0; i < 5; i++ {
				mockTool := newMockTool(fmt.Sprintf("tool-%d", i), "1.0.0")
				err := registry.RegisterInternal(mockTool)
				require.NoError(t, err)
			}

			var wg sync.WaitGroup
			concurrency := 20

			// Concurrent executions
			wg.Add(concurrency)
			for i := 0; i < concurrency; i++ {
				go func(idx int) {
					defer wg.Done()
					toolName := fmt.Sprintf("tool-%d", idx%5)
					_, err := registry.Execute(ctx, toolName, map[string]any{"message": fmt.Sprintf("concurrent-%d", idx)})
					assert.NoError(t, err, "concurrent execution should succeed")
				}(i)
			}
			wg.Wait()

			// Verify metrics
			for i := 0; i < 5; i++ {
				metrics, err := registry.Metrics(fmt.Sprintf("tool-%d", i))
				require.NoError(t, err)
				assert.Greater(t, metrics.TotalCalls, int64(0), "should have executed calls")
			}

			t.Logf("Concurrent tool operations test passed with %d goroutines", concurrency)
		})

		t.Run("ConcurrentPluginOps", func(t *testing.T) {
			registry := plugin.NewPluginRegistry(nil)

			// Register plugin
			mockPlugin := newMockPlugin("concurrent-db", "1.0.0")
			err := registry.Register(mockPlugin, plugin.PluginConfig{Name: "concurrent-db"})
			require.NoError(t, err)

			var wg sync.WaitGroup
			concurrency := 20

			// Concurrent queries
			wg.Add(concurrency)
			for i := 0; i < concurrency; i++ {
				go func(idx int) {
					defer wg.Done()
					_, err := registry.Query(ctx, "concurrent-db", "query", map[string]any{"id": idx})
					assert.NoError(t, err, "concurrent query should succeed")
				}(i)
			}
			wg.Wait()

			// Verify plugin is still healthy
			health := registry.Health(ctx)
			assert.True(t, health.IsHealthy(), "registry should still be healthy")

			t.Logf("Concurrent plugin operations test passed with %d goroutines", concurrency)
		})

		t.Run("ConcurrentAgentOps", func(t *testing.T) {
			// registry := agent.NewAgentRegistry()

			// Register agent
			factory := func(cfg agent.AgentConfig) (agent.Agent, error) {
				return newMockAgent("concurrent-agent", "1.0.0"), nil
			}
			err := registry.RegisterInternal("concurrent-agent", factory)
			require.NoError(t, err)

			var wg sync.WaitGroup
			concurrency := 10

			// Concurrent task executions
			wg.Add(concurrency)
			for i := 0; i < concurrency; i++ {
				go func(idx int) {
					defer wg.Done()
					task := agent.NewTask(
						fmt.Sprintf("task-%d", idx),
						"Concurrent test task",
						map[string]any{"id": idx},
					)
					harness := agent.NewDelegationHarness(registry, registry)
					_, err := registry.DelegateToAgent(ctx, "concurrent-agent", task, harness)
					assert.NoError(t, err, "concurrent task should succeed")
				}(i)
			}
			wg.Wait()

			t.Logf("Concurrent agent operations test passed with %d goroutines", concurrency)
		})
	*/
}

// TestComponentInteraction tests that all component types work together
func TestComponentInteraction(t *testing.T) {
	t.Skip("Legacy AgentRegistry removed - use registry.ComponentDiscovery instead")

	/*
		// This test is disabled - legacy code preserved below for reference
		ctx := context.Background()

		// Create all registries
		toolRegistry := tool.NewToolRegistry()
		pluginRegistry := plugin.NewPluginRegistry(nil)
		agentRegistry := agent.NewAgentRegistry()

		// Register components
		t.Run("Setup", func(t *testing.T) {
			// Register tool
			mockTool := newMockTool("validator", "1.0.0")
			err := toolRegistry.RegisterInternal(mockTool)
			require.NoError(t, err)

			// Register plugin
			mockPlugin := newMockPlugin("data-source", "1.0.0")
			err = pluginRegistry.Register(mockPlugin, plugin.PluginConfig{Name: "data-source"})
			require.NoError(t, err)

			// Register agent
			factory := func(cfg agent.AgentConfig) (agent.Agent, error) {
				return newMockAgent("orchestrator", "1.0.0"), nil
			}
			err = agentRegistry.RegisterInternal("orchestrator", factory)
			require.NoError(t, err)

			t.Logf("All components registered")
		})

		// Test component interaction
		t.Run("Integration", func(t *testing.T) {
			// Create harness with tool and plugin executors
			harness := agent.NewDelegationHarness(agentRegistry, agentRegistry).
				WithToolExecutor(&mockToolExecutor{registry: toolRegistry}).
				WithPluginExecutor(&mockPluginExecutor{registry: pluginRegistry})

			// Execute task that uses tools and plugins
			task := agent.NewTask(
				"integrated-task",
				"Task that uses tools and plugins",
				map[string]any{"complexity": "high"},
			)

			result, err := agentRegistry.DelegateToAgent(ctx, "orchestrator", task, harness)
			require.NoError(t, err, "integrated task should succeed")
			assert.Equal(t, agent.ResultStatusCompleted, result.Status, "task should complete")

			t.Logf("Integration test passed: task completed successfully")
		})

		// Test health across all components
		t.Run("OverallHealth", func(t *testing.T) {
			toolHealth := toolRegistry.Health(ctx)
			pluginHealth := pluginRegistry.Health(ctx)
			agentHealth := agentRegistry.Health(ctx)

			assert.True(t, toolHealth.IsHealthy(), "tools should be healthy")
			assert.True(t, pluginHealth.IsHealthy(), "plugins should be healthy")
			assert.True(t, agentHealth.IsHealthy(), "agents should be healthy")

			t.Logf("Overall health check passed")
		})

		// Cleanup
		t.Run("Cleanup", func(t *testing.T) {
			err := toolRegistry.Unregister("validator")
			require.NoError(t, err)

			err = pluginRegistry.Shutdown(ctx)
			require.NoError(t, err)

			err = agentRegistry.Unregister("orchestrator")
			require.NoError(t, err)

			t.Logf("All components cleaned up")
		})
	*/
}

// =============================================================================
// Mock Implementations
// =============================================================================

// mockTool implements the Tool interface for testing
type mockTool struct {
	name        string
	version     string
	description string
	tags        []string
}

func newMockTool(name, version string) *mockTool {
	return &mockTool{
		name:        name,
		version:     version,
		description: fmt.Sprintf("Mock tool: %s", name),
		tags:        []string{"test", "mock"},
	}
}

func (t *mockTool) Name() string        { return t.name }
func (t *mockTool) Description() string { return t.description }
func (t *mockTool) Version() string     { return t.version }
func (t *mockTool) Tags() []string      { return t.tags }

func (t *mockTool) InputSchema() schema.JSONSchema {
	return schema.NewObjectSchema(
		map[string]schema.SchemaField{
			"message": schema.NewStringField("Message to echo"),
		},
		[]string{"message"},
	)
}

func (t *mockTool) OutputSchema() schema.JSONSchema {
	return schema.NewObjectSchema(
		map[string]schema.SchemaField{
			"message":   schema.NewStringField("Echoed message"),
			"timestamp": schema.NewStringField("Execution timestamp"),
		},
		[]string{"message", "timestamp"},
	)
}

func (t *mockTool) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	message, ok := input["message"]
	if !ok {
		return nil, fmt.Errorf("missing required field: message")
	}

	return map[string]any{
		"message":   message,
		"timestamp": time.Now().Format(time.RFC3339),
	}, nil
}

func (t *mockTool) Health(ctx context.Context) types.HealthStatus {
	return types.Healthy("mock tool is healthy")
}

func (t *mockTool) InputMessageType() string  { return "" }
func (t *mockTool) OutputMessageType() string { return "" }
func (t *mockTool) ExecuteProto(ctx context.Context, input proto.Message) (proto.Message, error) {
	return nil, fmt.Errorf("mockTool: proto execution not supported; use Execute instead")
}

// mockExternalTool implements ExternalToolClient for testing
type mockExternalTool struct {
	*mockTool
}

func newMockExternalTool(name, version string) *mockExternalTool {
	return &mockExternalTool{
		mockTool: newMockTool(name, version),
	}
}

// mockPlugin implements the Plugin interface for testing
type mockPlugin struct {
	name        string
	version     string
	initialized bool
	mu          sync.Mutex
}

func newMockPlugin(name, version string) *mockPlugin {
	return &mockPlugin{
		name:    name,
		version: version,
	}
}

func (p *mockPlugin) Name() string    { return p.name }
func (p *mockPlugin) Version() string { return p.version }

func (p *mockPlugin) Initialize(ctx context.Context, cfg plugin.PluginConfig) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.initialized = true
	return nil
}

func (p *mockPlugin) Shutdown(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.initialized = false
	return nil
}

func (p *mockPlugin) Query(ctx context.Context, method string, params map[string]any) (any, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.initialized {
		return nil, fmt.Errorf("plugin not initialized")
	}

	return map[string]any{
		"status": method + " executed",
		"params": params,
	}, nil
}

func (p *mockPlugin) Methods() []plugin.MethodDescriptor {
	return []plugin.MethodDescriptor{
		{
			Name:        "query",
			Description: "Execute a query",
			InputSchema: schema.NewObjectSchema(
				map[string]schema.SchemaField{
					"sql": schema.NewStringField("SQL query"),
				},
				[]string{"sql"},
			),
			OutputSchema: schema.NewObjectSchema(
				map[string]schema.SchemaField{
					"rows": schema.NewIntegerField("Number of rows"),
				},
				[]string{"rows"},
			),
		},
		{
			Name:        "execute",
			Description: "Execute a command",
			InputSchema: schema.NewObjectSchema(
				map[string]schema.SchemaField{
					"command": schema.NewStringField("Command to execute"),
				},
				[]string{"command"},
			),
			OutputSchema: schema.NewObjectSchema(
				map[string]schema.SchemaField{
					"status": schema.NewStringField("Execution status"),
				},
				[]string{"status"},
			),
		},
	}
}

func (p *mockPlugin) Health(ctx context.Context) types.HealthStatus {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.initialized {
		return types.Unhealthy("plugin not initialized")
	}
	return types.Healthy("mock plugin is healthy")
}

// mockExternalPlugin implements ExternalPluginClient for testing
type mockExternalPlugin struct {
	*mockPlugin
}

func newMockExternalPlugin(name, version string) *mockExternalPlugin {
	return &mockExternalPlugin{
		mockPlugin: newMockPlugin(name, version),
	}
}

// mockAgent implements the Agent interface for testing
type mockAgent struct {
	name        string
	version     string
	description string
	initialized bool
	mu          sync.Mutex
}

func newMockAgent(name, version string) *mockAgent {
	return &mockAgent{
		name:        name,
		version:     version,
		description: fmt.Sprintf("Mock agent: %s", name),
	}
}

func (a *mockAgent) Name() string        { return a.name }
func (a *mockAgent) Version() string     { return a.version }
func (a *mockAgent) Description() string { return a.description }

func (a *mockAgent) Capabilities() []string {
	return []string{"reconnaissance", "scanning", "analysis"}
}

func (a *mockAgent) TargetTypes() []component.TargetType {
	return []component.TargetType{
		component.TargetTypeLLMAPI,
		component.TargetTypeLLMChat,
		component.TargetTypeRAG,
	}
}

func (a *mockAgent) TechniqueTypes() []component.TechniqueType {
	return []component.TechniqueType{
		component.TechniqueReconnaissance,
		component.TechniquePromptInjection,
	}
}

func (a *mockAgent) LLMSlots() []agent.SlotDefinition {
	return []agent.SlotDefinition{
		agent.NewSlotDefinition("primary", "Primary LLM for reasoning", true),
		agent.NewSlotDefinition("fallback", "Fallback LLM for errors", false),
	}
}

func (a *mockAgent) Initialize(ctx context.Context, cfg agent.AgentConfig) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.initialized = true
	return nil
}

func (a *mockAgent) Shutdown(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.initialized = false
	return nil
}

func (a *mockAgent) Execute(ctx context.Context, task agent.Task, harness agent.AgentHarness) (agent.Result, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.initialized {
		return agent.Result{}, fmt.Errorf("agent not initialized")
	}

	result := agent.NewResult(task.ID)
	result.Start()

	// Simulate work
	time.Sleep(10 * time.Millisecond)

	// Create a finding
	finding := agent.NewFinding(
		"Mock Finding",
		"This is a test finding from the mock agent",
		agent.SeverityInfo,
	).WithCategory("test")
	result.AddFinding(finding)

	// Complete with output
	result.Complete(map[string]any{
		"status":    "completed",
		"task_name": task.Name,
		"findings":  1,
	})

	return result, nil
}

func (a *mockAgent) Health(ctx context.Context) types.HealthStatus {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.initialized {
		return types.Unhealthy("agent not initialized")
	}
	return types.Healthy("mock agent is healthy")
}

// mockExternalAgent implements ExternalAgentClient for testing
type mockExternalAgent struct {
	*mockAgent
}

func newMockExternalAgent(name, version string) *mockExternalAgent {
	return &mockExternalAgent{
		mockAgent: newMockAgent(name, version),
	}
}

// mockToolExecutor implements ToolExecutor for integration testing
type mockToolExecutor struct {
	registry *tool.DefaultToolRegistry
}

func (e *mockToolExecutor) ExecuteTool(ctx context.Context, name string, input map[string]any) (map[string]any, error) {
	return e.registry.Execute(ctx, name, input)
}

// mockPluginExecutor implements PluginExecutor for integration testing
type mockPluginExecutor struct {
	registry *plugin.DefaultPluginRegistry
}

func (e *mockPluginExecutor) QueryPlugin(ctx context.Context, pluginName, method string, params map[string]any) (any, error) {
	return e.registry.Query(ctx, pluginName, method, params)
}
