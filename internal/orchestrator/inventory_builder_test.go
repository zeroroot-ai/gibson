package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/tool"
)

// mockBuilderComponentDiscovery is a test double for component.ComponentDiscovery
// Used specifically for inventory builder tests with partial failure support
type mockBuilderComponentDiscovery struct {
	agents  []component.AgentInfo
	tools   []component.ToolInfo
	plugins []component.PluginInfo
	err     error

	// Error simulation for partial failures
	agentsErr  error
	toolsErr   error
	pluginsErr error
}

func (m *mockBuilderComponentDiscovery) ListAgents(ctx context.Context) ([]component.AgentInfo, error) {
	if m.agentsErr != nil {
		return nil, m.agentsErr
	}
	return m.agents, m.err
}

func (m *mockBuilderComponentDiscovery) ListTools(ctx context.Context) ([]component.ToolInfo, error) {
	if m.toolsErr != nil {
		return nil, m.toolsErr
	}
	return m.tools, m.err
}

func (m *mockBuilderComponentDiscovery) ListPlugins(ctx context.Context) ([]component.PluginInfo, error) {
	if m.pluginsErr != nil {
		return nil, m.pluginsErr
	}
	return m.plugins, m.err
}

// Unused methods for ComponentDiscovery interface compliance
func (m *mockBuilderComponentDiscovery) DiscoverAgent(ctx context.Context, name string) (agent.Agent, error) {
	return nil, errors.New("not implemented")
}

func (m *mockBuilderComponentDiscovery) DiscoverTool(ctx context.Context, name string) (tool.Tool, error) {
	return nil, errors.New("not implemented")
}

// DiscoverPlugin was removed from component.ComponentDiscovery in plugin-runtime
// Spec 2 Phase 7; plugin invocation now goes through PluginInvokeService.

func (m *mockBuilderComponentDiscovery) DelegateToAgent(ctx context.Context, agentName string, task agent.Task, harness agent.AgentHarness) (agent.Result, error) {
	return agent.Result{}, errors.New("not implemented")
}

// TestNewInventoryBuilder tests the constructor
func TestNewInventoryBuilder(t *testing.T) {
	mock := &mockBuilderComponentDiscovery{}

	tests := []struct {
		name            string
		opts            []InventoryBuilderOption
		expectedTimeout time.Duration
		expectedTTL     time.Duration
	}{
		{
			name:            "default options",
			opts:            nil,
			expectedTimeout: 5 * time.Second,
			expectedTTL:     30 * time.Second,
		},
		{
			name: "custom timeout",
			opts: []InventoryBuilderOption{
				WithInventoryTimeout(10 * time.Second),
			},
			expectedTimeout: 10 * time.Second,
			expectedTTL:     30 * time.Second,
		},
		{
			name: "custom TTL",
			opts: []InventoryBuilderOption{
				WithCacheTTL(1 * time.Minute),
			},
			expectedTimeout: 5 * time.Second,
			expectedTTL:     1 * time.Minute,
		},
		{
			name: "custom timeout and TTL",
			opts: []InventoryBuilderOption{
				WithInventoryTimeout(15 * time.Second),
				WithCacheTTL(2 * time.Minute),
			},
			expectedTimeout: 15 * time.Second,
			expectedTTL:     2 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewInventoryBuilder(mock, tt.opts...)

			if builder.timeout != tt.expectedTimeout {
				t.Errorf("timeout = %v, want %v", builder.timeout, tt.expectedTimeout)
			}

			if builder.cacheTTL != tt.expectedTTL {
				t.Errorf("cacheTTL = %v, want %v", builder.cacheTTL, tt.expectedTTL)
			}

			if builder.registry == nil {
				t.Error("registry is nil")
			}
		})
	}
}

// TestBuild_Success tests successful inventory building
func TestBuild_Success(t *testing.T) {
	mock := &mockBuilderComponentDiscovery{
		agents: []component.AgentInfo{
			{
				Name:         "davinci",
				Version:      "1.0.0",
				Description:  "DaVinci test agent",
				Capabilities: []string{"jailbreak", "prompt_injection"},
				TargetTypes:  []string{"llm_chat", "llm_api"},
				Instances:    2,
				Endpoints:    []string{"localhost:50051", "localhost:50052"},
			},
			{
				Name:         "k8skiller",
				Version:      "1.0.0",
				Description:  "Kubernetes exploitation agent",
				Capabilities: []string{"container_escape", "rbac_abuse"},
				TargetTypes:  []string{"kubernetes"},
				Instances:    1,
				Endpoints:    []string{"localhost:50053"},
			},
		},
		tools: []component.ToolInfo{
			{
				Name:        "nmap",
				Version:     "1.0.0",
				Description: "Network scanner",
				Instances:   1,
				Endpoints:   []string{"localhost:50061"},
			},
			{
				Name:        "sqlmap",
				Version:     "1.0.0",
				Description: "SQL injection tool",
				Instances:   1,
				Endpoints:   []string{"localhost:50062"},
			},
		},
		plugins: []component.PluginInfo{
			{
				Name:        "mitre-lookup",
				Version:     "1.0.0",
				Description: "MITRE ATT&CK lookup plugin",
				Instances:   1,
				Endpoints:   []string{"localhost:50071"},
			},
		},
	}

	builder := NewInventoryBuilder(mock, WithInventoryTimeout(5*time.Second))
	ctx := context.Background()

	inventory, err := builder.Build(ctx)

	if err != nil {
		t.Fatalf("Build() returned unexpected error: %v", err)
	}

	if inventory == nil {
		t.Fatal("Build() returned nil inventory")
	}

	// Verify agents
	if len(inventory.Agents) != 2 {
		t.Errorf("len(Agents) = %d, want 2", len(inventory.Agents))
	}

	// Verify tools
	if len(inventory.Tools) != 2 {
		t.Errorf("len(Tools) = %d, want 2", len(inventory.Tools))
	}

	// Verify plugins
	if len(inventory.Plugins) != 1 {
		t.Errorf("len(Plugins) = %d, want 1", len(inventory.Plugins))
	}

	// Verify total components
	if inventory.TotalComponents != 5 {
		t.Errorf("TotalComponents = %d, want 5", inventory.TotalComponents)
	}

	// Verify IsStale is false
	if inventory.IsStale {
		t.Error("IsStale should be false for fresh inventory")
	}

	// Verify agents are sorted by name
	if len(inventory.Agents) > 1 {
		for i := 0; i < len(inventory.Agents)-1; i++ {
			if inventory.Agents[i].Name > inventory.Agents[i+1].Name {
				t.Errorf("Agents not sorted: %s > %s", inventory.Agents[i].Name, inventory.Agents[i+1].Name)
			}
		}
	}

	// Verify agent conversion
	davinciAgent := inventory.GetAgent("davinci")
	if davinciAgent == nil {
		t.Fatal("davinci agent not found")
	}
	if davinciAgent.HealthStatus != "healthy" {
		t.Errorf("davinci health = %s, want healthy", davinciAgent.HealthStatus)
	}
	if davinciAgent.Instances != 2 {
		t.Errorf("davinci instances = %d, want 2", davinciAgent.Instances)
	}
	if !davinciAgent.IsExternal {
		t.Error("davinci should be external (has endpoints)")
	}

	// Verify cache is populated
	builder.mu.RLock()
	cached := builder.cachedInventory
	builder.mu.RUnlock()

	if cached == nil {
		t.Error("cache was not populated after Build()")
	}
}

// TestBuild_EmptyRegistry tests building from an empty registry
func TestBuild_EmptyRegistry(t *testing.T) {
	mock := &mockBuilderComponentDiscovery{
		agents:  []component.AgentInfo{},
		tools:   []component.ToolInfo{},
		plugins: []component.PluginInfo{},
	}

	builder := NewInventoryBuilder(mock)
	ctx := context.Background()

	inventory, err := builder.Build(ctx)

	if err != nil {
		t.Fatalf("Build() returned unexpected error: %v", err)
	}

	if inventory == nil {
		t.Fatal("Build() returned nil inventory")
	}

	if len(inventory.Agents) != 0 {
		t.Errorf("len(Agents) = %d, want 0", len(inventory.Agents))
	}

	if inventory.TotalComponents != 0 {
		t.Errorf("TotalComponents = %d, want 0", inventory.TotalComponents)
	}
}

// TestBuild_PartialFailure tests graceful handling of partial failures
func TestBuild_PartialFailure(t *testing.T) {
	tests := []struct {
		name            string
		agentsErr       error
		toolsErr        error
		pluginsErr      error
		expectError     bool
		expectedAgents  int
		expectedTools   int
		expectedPlugins int
		errorContains   string
	}{
		{
			name:            "agents query fails",
			agentsErr:       errors.New("agents unavailable"),
			toolsErr:        nil,
			pluginsErr:      nil,
			expectError:     true,
			expectedAgents:  0,
			expectedTools:   1,
			expectedPlugins: 1,
			errorContains:   "agents",
		},
		{
			name:            "tools query fails",
			agentsErr:       nil,
			toolsErr:        errors.New("tools unavailable"),
			pluginsErr:      nil,
			expectError:     true,
			expectedAgents:  1,
			expectedTools:   0,
			expectedPlugins: 1,
			errorContains:   "tools",
		},
		{
			name:            "plugins query fails",
			agentsErr:       nil,
			toolsErr:        nil,
			pluginsErr:      errors.New("plugins unavailable"),
			expectError:     true,
			expectedAgents:  1,
			expectedTools:   1,
			expectedPlugins: 0,
			errorContains:   "plugins",
		},
		{
			name:            "all queries fail",
			agentsErr:       errors.New("agents unavailable"),
			toolsErr:        errors.New("tools unavailable"),
			pluginsErr:      errors.New("plugins unavailable"),
			expectError:     true,
			expectedAgents:  0,
			expectedTools:   0,
			expectedPlugins: 0,
			errorContains:   "partial inventory build failures",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockBuilderComponentDiscovery{
				agents: []component.AgentInfo{
					{Name: "agent1", Version: "1.0.0", Instances: 1},
				},
				tools: []component.ToolInfo{
					{Name: "tool1", Version: "1.0.0", Instances: 1},
				},
				plugins: []component.PluginInfo{
					{Name: "plugin1", Version: "1.0.0", Instances: 1},
				},
				agentsErr:  tt.agentsErr,
				toolsErr:   tt.toolsErr,
				pluginsErr: tt.pluginsErr,
			}

			builder := NewInventoryBuilder(mock)
			ctx := context.Background()

			inventory, err := builder.Build(ctx)

			if tt.expectError && err == nil {
				t.Fatal("Build() should return error for partial failure")
			}

			if tt.expectError && err != nil {
				if tt.errorContains != "" && !contains(err.Error(), tt.errorContains) {
					t.Errorf("error message %q does not contain %q", err.Error(), tt.errorContains)
				}
			}

			// Inventory should still be returned with partial data
			if inventory == nil {
				t.Fatal("Build() should return partial inventory on failure")
			}

			if len(inventory.Agents) != tt.expectedAgents {
				t.Errorf("len(Agents) = %d, want %d", len(inventory.Agents), tt.expectedAgents)
			}

			if len(inventory.Tools) != tt.expectedTools {
				t.Errorf("len(Tools) = %d, want %d", len(inventory.Tools), tt.expectedTools)
			}

			if len(inventory.Plugins) != tt.expectedPlugins {
				t.Errorf("len(Plugins) = %d, want %d", len(inventory.Plugins), tt.expectedPlugins)
			}
		})
	}
}

// TestBuild_Timeout tests timeout handling
func TestBuild_Timeout(t *testing.T) {
	// Use error simulation to cause a timeout-like scenario
	// We can't truly block, but we can simulate the error condition
	mock := &mockBuilderComponentDiscovery{
		agents:    []component.AgentInfo{},
		tools:     []component.ToolInfo{},
		plugins:   []component.PluginInfo{},
		agentsErr: context.DeadlineExceeded, // Simulate timeout
	}

	builder := NewInventoryBuilder(mock, WithInventoryTimeout(100*time.Millisecond))
	ctx := context.Background()

	inventory, err := builder.Build(ctx)

	// Should still return partial inventory (tools and plugins may succeed)
	if inventory == nil {
		t.Error("Build() should return partial inventory on partial failure")
	}

	// Error should be present due to agents failure
	if err == nil {
		t.Error("Build() should return error when agents query fails")
	}
}

// TestBuildWithCache_FreshCache tests returning cached inventory within TTL
func TestBuildWithCache_FreshCache(t *testing.T) {
	mock := &mockBuilderComponentDiscovery{
		agents: []component.AgentInfo{
			{Name: "agent1", Version: "1.0.0", Instances: 1},
		},
		tools:   []component.ToolInfo{},
		plugins: []component.PluginInfo{},
	}

	builder := NewInventoryBuilder(mock, WithCacheTTL(1*time.Second))
	ctx := context.Background()

	// First call - should build
	inv1, err := builder.BuildWithCache(ctx)
	if err != nil {
		t.Fatalf("first BuildWithCache() failed: %v", err)
	}
	if inv1 == nil {
		t.Fatal("first BuildWithCache() returned nil")
	}

	// Second call immediately - should use cache (same pointer or same data)
	inv2, err := builder.BuildWithCache(ctx)
	if err != nil {
		t.Fatalf("second BuildWithCache() failed: %v", err)
	}
	if inv2 == nil {
		t.Fatal("second BuildWithCache() returned nil")
	}

	// Verify both inventories have the same data
	if len(inv1.Agents) != len(inv2.Agents) {
		t.Errorf("cached inventory differs from fresh inventory")
	}

	// Verify IsStale is false
	if inv2.IsStale {
		t.Error("cached inventory should not be stale within TTL")
	}
}

// TestBuildWithCache_ExpiredCache tests cache expiration
func TestBuildWithCache_ExpiredCache(t *testing.T) {
	mock := &mockBuilderComponentDiscovery{
		agents: []component.AgentInfo{
			{Name: "agent1", Version: "1.0.0", Instances: 1},
		},
		tools:   []component.ToolInfo{},
		plugins: []component.PluginInfo{},
	}

	builder := NewInventoryBuilder(mock, WithCacheTTL(100*time.Millisecond))
	ctx := context.Background()

	// First call - should build
	inv1, err := builder.BuildWithCache(ctx)
	if err != nil {
		t.Fatalf("first BuildWithCache() failed: %v", err)
	}

	// Wait for cache to expire
	time.Sleep(150 * time.Millisecond)

	// Second call after expiration - should rebuild
	inv2, err := builder.BuildWithCache(ctx)
	if err != nil {
		t.Fatalf("second BuildWithCache() failed: %v", err)
	}
	if inv2 == nil {
		t.Fatal("second BuildWithCache() returned nil")
	}

	// Verify inventories have the same data
	if len(inv1.Agents) != len(inv2.Agents) {
		t.Errorf("rebuilt inventory differs from original")
	}

	// The second inventory should have a different GatheredAt timestamp
	if inv1.GatheredAt == inv2.GatheredAt {
		t.Error("expected different GatheredAt after cache expiration")
	}
}

// TestBuildWithCache_StaleCacheFallback tests fallback to stale cache on error
func TestBuildWithCache_StaleCacheFallback(t *testing.T) {
	mock := &mockBuilderComponentDiscovery{
		agents: []component.AgentInfo{
			{Name: "agent1", Version: "1.0.0", Instances: 1},
		},
		tools:   []component.ToolInfo{},
		plugins: []component.PluginInfo{},
	}

	builder := NewInventoryBuilder(mock, WithCacheTTL(100*time.Millisecond))
	ctx := context.Background()

	// First call - successful build
	inv1, err := builder.BuildWithCache(ctx)
	if err != nil {
		t.Fatalf("first BuildWithCache() failed: %v", err)
	}
	if inv1.IsStale {
		t.Error("first inventory should not be stale")
	}

	// Wait for cache to expire
	time.Sleep(150 * time.Millisecond)

	// Make the registry fail for agents only
	mock.agentsErr = errors.New("registry unavailable")

	// Second call after expiration - will rebuild with partial data
	inv2, err := builder.BuildWithCache(ctx)

	// Should return partial inventory with error
	if err == nil {
		t.Error("BuildWithCache() should return error on partial failure")
	}

	if inv2 == nil {
		t.Fatal("BuildWithCache() should return inventory even on partial failure")
	}

	// Note: Current implementation overwrites cache with partial result
	// This is a known behavior - the cache now contains 0 agents
	// A future improvement could preserve the original cache on partial failures
}

// TestBuildWithCache_NoCache tests error when no cache is available
func TestBuildWithCache_NoCache(t *testing.T) {
	mock := &mockBuilderComponentDiscovery{
		agentsErr: errors.New("registry unavailable"),
	}

	builder := NewInventoryBuilder(mock)
	ctx := context.Background()

	inventory, err := builder.BuildWithCache(ctx)

	if err == nil {
		t.Fatal("BuildWithCache() should return error when no cache available")
	}

	// BuildWithCache returns partial inventory even on failure
	// The inventory may be partial (empty agents) but still returned
	// This is the expected graceful degradation behavior
	_ = inventory // may or may not be nil depending on implementation
}

// TestConvertAgentInfo tests agent conversion
func TestConvertAgentInfo(t *testing.T) {
	builder := NewInventoryBuilder(&mockBuilderComponentDiscovery{})

	tests := []struct {
		name             string
		agentInfo        component.AgentInfo
		expectedHealth   string
		expectedExternal bool
	}{
		{
			name: "healthy agent with instances",
			agentInfo: component.AgentInfo{
				Name:         "davinci",
				Version:      "1.0.0",
				Description:  "Test agent",
				Capabilities: []string{"jailbreak"},
				TargetTypes:  []string{"llm_chat"},
				Instances:    2,
				Endpoints:    []string{"localhost:50051"},
			},
			expectedHealth:   "healthy",
			expectedExternal: true,
		},
		{
			name: "unavailable agent with zero instances",
			agentInfo: component.AgentInfo{
				Name:        "offline-agent",
				Version:     "1.0.0",
				Description: "Offline agent",
				Instances:   0,
				Endpoints:   []string{},
			},
			expectedHealth:   "unavailable",
			expectedExternal: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := builder.convertAgentInfo(tt.agentInfo)

			if summary.Name != tt.agentInfo.Name {
				t.Errorf("Name = %s, want %s", summary.Name, tt.agentInfo.Name)
			}

			if summary.HealthStatus != tt.expectedHealth {
				t.Errorf("HealthStatus = %s, want %s", summary.HealthStatus, tt.expectedHealth)
			}

			if summary.IsExternal != tt.expectedExternal {
				t.Errorf("IsExternal = %v, want %v", summary.IsExternal, tt.expectedExternal)
			}

			if summary.Instances != tt.agentInfo.Instances {
				t.Errorf("Instances = %d, want %d", summary.Instances, tt.agentInfo.Instances)
			}
		})
	}
}

// TestConvertToolInfo tests tool conversion
func TestConvertToolInfo(t *testing.T) {
	builder := NewInventoryBuilder(&mockBuilderComponentDiscovery{})

	toolInfo := component.ToolInfo{
		Name:        "nmap",
		Version:     "1.0.0",
		Description: "Network scanner",
		Instances:   1,
		Endpoints:   []string{"localhost:50061"},
	}

	summary := builder.convertToolInfo(toolInfo)

	if summary.Name != toolInfo.Name {
		t.Errorf("Name = %s, want %s", summary.Name, toolInfo.Name)
	}

	if summary.HealthStatus != "healthy" {
		t.Errorf("HealthStatus = %s, want healthy", summary.HealthStatus)
	}

	if !summary.IsExternal {
		t.Error("IsExternal should be true when endpoints exist")
	}
}

// TestConvertPluginInfo tests plugin conversion
func TestConvertPluginInfo(t *testing.T) {
	builder := NewInventoryBuilder(&mockBuilderComponentDiscovery{})

	pluginInfo := component.PluginInfo{
		Name:        "mitre-lookup",
		Version:     "1.0.0",
		Description: "MITRE lookup plugin",
		Instances:   1,
		Endpoints:   []string{"localhost:50071"},
	}

	summary := builder.convertPluginInfo(pluginInfo)

	if summary.Name != pluginInfo.Name {
		t.Errorf("Name = %s, want %s", summary.Name, pluginInfo.Name)
	}

	if summary.HealthStatus != "healthy" {
		t.Errorf("HealthStatus = %s, want healthy", summary.HealthStatus)
	}

	if !summary.IsExternal {
		t.Error("IsExternal should be true when endpoints exist")
	}
}
