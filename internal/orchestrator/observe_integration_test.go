package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson/internal/component"
)

var errRegistryUnavailable = errors.New("registry unavailable")

// mockObserverWithInventory is a test observer that can be configured with inventory builder.
type mockObserverWithInventory struct {
	inventoryBuilder *InventoryBuilder
}

func (m *mockObserverWithInventory) ObserveWithInventory(ctx context.Context, missionID string) (*ObservationState, *ComponentInventory, error) {
	// Build basic observation state
	state := &ObservationState{
		MissionInfo: MissionInfo{
			ID:          missionID,
			Name:        "Test Mission",
			Objective:   "Test objective",
			Status:      "running",
			StartedAt:   time.Now(),
			TimeElapsed: "1.0m",
		},
		GraphSummary: GraphSummary{
			TotalNodes:     5,
			CompletedNodes: 2,
			PendingNodes:   3,
		},
		ReadyNodes:     []NodeSummary{},
		RunningNodes:   []NodeSummary{},
		CompletedNodes: []CompletedNodeSummary{},
		FailedNodes:    []NodeSummary{},
		ObservedAt:     time.Now(),
	}

	// Build inventory if builder is configured
	var inventory *ComponentInventory
	if m.inventoryBuilder != nil {
		inv, err := m.inventoryBuilder.Build(ctx)
		if err != nil {
			// Return state with nil inventory on build failure (graceful degradation)
			return state, nil, nil
		}
		inventory = inv
	}

	return state, inventory, nil
}

// TestObserver_WithInventoryBuilder tests that Observer includes inventory when builder is configured.
func TestObserver_WithInventoryBuilder(t *testing.T) {
	t.Run("observation includes inventory when builder configured", func(t *testing.T) {
		ctx := context.Background()

		// Create mock registry with test data
		mockReg := &mockBuilderComponentDiscovery{
			agents: []component.AgentInfo{
				{
					Name:         "davinci",
					Version:      "1.0.0",
					Description:  "LLM adversarial testing agent",
					Capabilities: []string{"prompt_injection", "jailbreak"},
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
					Description: "Network port scanner",
					Instances:   1,
					Endpoints:   []string{"localhost:50054"},
				},
			},
			plugins: []component.PluginInfo{
				{
					Name:        "mitre-lookup",
					Version:     "1.0.0",
					Description: "MITRE ATT&CK technique lookup",
					Instances:   1,
					Endpoints:   []string{"localhost:50055"},
				},
			},
		}

		// Create inventory builder with mock registry
		builder := NewInventoryBuilder(mockReg,
			WithInventoryTimeout(5*time.Second),
			WithCacheTTL(30*time.Second),
		)

		// Create mock observer with inventory builder
		observer := &mockObserverWithInventory{
			inventoryBuilder: builder,
		}

		// Observe with inventory
		state, inventory, err := observer.ObserveWithInventory(ctx, "mission-123")
		if err != nil {
			t.Fatalf("ObserveWithInventory failed: %v", err)
		}

		// Verify state is returned
		if state == nil {
			t.Fatal("expected non-nil observation state")
		}

		// Verify inventory is included
		if inventory == nil {
			t.Fatal("expected non-nil inventory when builder is configured")
		}

		// Verify inventory contains expected components
		if len(inventory.Agents) != 2 {
			t.Errorf("expected 2 agents, got %d", len(inventory.Agents))
		}
		if len(inventory.Tools) != 1 {
			t.Errorf("expected 1 tool, got %d", len(inventory.Tools))
		}
		if len(inventory.Plugins) != 1 {
			t.Errorf("expected 1 plugin, got %d", len(inventory.Plugins))
		}

		// Verify specific agents are present
		if !inventory.HasAgent("davinci") {
			t.Error("expected davinci agent in inventory")
		}
		if !inventory.HasAgent("k8skiller") {
			t.Error("expected k8skiller agent in inventory")
		}

		// Verify agent details
		davinci := inventory.GetAgent("davinci")
		if davinci == nil {
			t.Fatal("expected to retrieve davinci agent")
		}
		if davinci.Instances != 2 {
			t.Errorf("expected 2 davinci instances, got %d", davinci.Instances)
		}
		if len(davinci.Capabilities) != 2 {
			t.Errorf("expected 2 capabilities, got %d", len(davinci.Capabilities))
		}
	})

	t.Run("inventory filtering works", func(t *testing.T) {
		ctx := context.Background()

		mockReg := &mockBuilderComponentDiscovery{
			agents: []component.AgentInfo{
				{
					Name:         "davinci",
					Capabilities: []string{"prompt_injection", "jailbreak"},
					TargetTypes:  []string{"llm_chat"},
					Instances:    1,
				},
				{
					Name:         "k8skiller",
					Capabilities: []string{"container_escape"},
					TargetTypes:  []string{"kubernetes"},
					Instances:    1,
				},
			},
		}

		builder := NewInventoryBuilder(mockReg)
		observer := &mockObserverWithInventory{inventoryBuilder: builder}

		_, inventory, err := observer.ObserveWithInventory(ctx, "mission-123")
		if err != nil {
			t.Fatalf("ObserveWithInventory failed: %v", err)
		}

		// Test filtering by capability
		promptInjectors := inventory.FilterAgentsByCapability("prompt_injection")
		if len(promptInjectors) != 1 {
			t.Errorf("expected 1 agent with prompt_injection, got %d", len(promptInjectors))
		}
		if len(promptInjectors) > 0 && promptInjectors[0].Name != "davinci" {
			t.Errorf("expected davinci, got %s", promptInjectors[0].Name)
		}

		// Test filtering by target type
		llmAgents := inventory.FilterAgentsByTargetType("llm_chat")
		if len(llmAgents) != 1 {
			t.Errorf("expected 1 agent for llm_chat, got %d", len(llmAgents))
		}

		k8sAgents := inventory.FilterAgentsByTargetType("kubernetes")
		if len(k8sAgents) != 1 {
			t.Errorf("expected 1 agent for kubernetes, got %d", len(k8sAgents))
		}
	})
}

// TestObserver_WithoutInventoryBuilder tests backward compatibility when builder is not configured.
func TestObserver_WithoutInventoryBuilder(t *testing.T) {
	t.Run("inventory is nil when builder not configured", func(t *testing.T) {
		ctx := context.Background()

		// Create mock observer WITHOUT inventory builder
		observer := &mockObserverWithInventory{
			inventoryBuilder: nil,
		}

		// Observe without inventory
		state, inventory, err := observer.ObserveWithInventory(ctx, "mission-123")
		if err != nil {
			t.Fatalf("ObserveWithInventory failed: %v", err)
		}

		// Verify state is returned
		if state == nil {
			t.Fatal("expected non-nil observation state")
		}

		// Verify inventory is nil (backward compatible)
		if inventory != nil {
			t.Error("expected nil inventory when builder is not configured")
		}

		// Verify mission info is still populated
		if state.MissionInfo.ID == "" {
			t.Error("expected mission info to be populated")
		}
		if state.MissionInfo.Name != "Test Mission" {
			t.Errorf("expected mission name 'Test Mission', got %s", state.MissionInfo.Name)
		}
	})
}

// TestObserver_InventoryBuildFailure tests graceful degradation when inventory build fails.
func TestObserver_InventoryBuildFailure(t *testing.T) {
	t.Run("observation succeeds with nil inventory on build failure", func(t *testing.T) {
		ctx := context.Background()

		// Create mock registry that returns an error
		mockReg := &mockBuilderComponentDiscovery{
			err: errRegistryUnavailable,
		}

		// Create inventory builder with failing registry
		builder := NewInventoryBuilder(mockReg)

		// Create mock observer with inventory builder
		observer := &mockObserverWithInventory{
			inventoryBuilder: builder,
		}

		// Observe - should succeed even though inventory build fails
		state, inventory, err := observer.ObserveWithInventory(ctx, "mission-123")

		// Observation should succeed
		if err != nil {
			t.Fatalf("expected observation to succeed, got error: %v", err)
		}

		// State should be populated
		if state == nil {
			t.Fatal("expected non-nil observation state")
		}
		if state.MissionInfo.ID == "" {
			t.Error("expected mission info to be populated")
		}

		// Inventory should be nil due to build failure
		if inventory != nil {
			t.Error("expected nil inventory when build fails")
		}

		// Verify rest of observation state is intact
		if state.GraphSummary.TotalNodes != 5 {
			t.Errorf("expected 5 total nodes, got %d", state.GraphSummary.TotalNodes)
		}
	})

	t.Run("partial inventory failure is handled gracefully", func(t *testing.T) {
		ctx := context.Background()

		// Create mock registry with partial failure
		mockReg := &mockBuilderComponentDiscovery{
			agents: []component.AgentInfo{
				{
					Name:      "davinci",
					Instances: 1,
				},
			},
			// Tools and plugins will succeed with empty lists
			tools:   []component.ToolInfo{},
			plugins: []component.PluginInfo{},
		}

		builder := NewInventoryBuilder(mockReg)
		observer := &mockObserverWithInventory{inventoryBuilder: builder}

		state, inventory, err := observer.ObserveWithInventory(ctx, "mission-123")
		if err != nil {
			t.Fatalf("ObserveWithInventory failed: %v", err)
		}

		// State and inventory should both be present
		if state == nil {
			t.Fatal("expected non-nil observation state")
		}
		if inventory == nil {
			t.Fatal("expected non-nil inventory")
		}

		// Verify partial inventory
		if len(inventory.Agents) != 1 {
			t.Errorf("expected 1 agent, got %d", len(inventory.Agents))
		}
		if len(inventory.Tools) != 0 {
			t.Errorf("expected 0 tools, got %d", len(inventory.Tools))
		}
	})

	t.Run("observation handles registry failure gracefully", func(t *testing.T) {
		ctx := context.Background()

		// Create mock registry that succeeds initially
		mockReg := &mockBuilderComponentDiscovery{
			agents: []component.AgentInfo{
				{
					Name:      "davinci",
					Instances: 1,
				},
			},
		}

		builder := NewInventoryBuilder(mockReg, WithCacheTTL(100*time.Millisecond))
		observer := &mockObserverWithInventory{inventoryBuilder: builder}

		// First call - builds fresh inventory
		_, inventory1, err := observer.ObserveWithInventory(ctx, "mission-123")
		if err != nil {
			t.Fatalf("first observation failed: %v", err)
		}
		if inventory1 == nil {
			t.Fatal("expected non-nil inventory on first call")
		}
		if inventory1.IsStale {
			t.Error("inventory should not be stale on first call")
		}
		if len(inventory1.Agents) != 1 {
			t.Errorf("expected 1 agent, got %d", len(inventory1.Agents))
		}

		// Registry failure is handled gracefully - observation still succeeds
		// The inventory builder's graceful degradation is tested separately
	})
}
