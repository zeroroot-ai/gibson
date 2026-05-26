package orchestrator

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/component"
)

// TestActor_SpawnAgent_ValidAgent tests that spawn_agent validation succeeds with a valid agent.
func TestActor_SpawnAgent_ValidAgent(t *testing.T) {
	t.Run("validation succeeds with valid agent in inventory", func(t *testing.T) {
		ctx := context.Background()

		// Create mock registry with test agents
		mockReg := &mockBuilderComponentDiscovery{
			agents: []component.AgentInfo{
				{
					Name:        "davinci",
					Description: "LLM adversarial testing agent",
					Instances:   1,
				},
				{
					Name:        "k8skiller",
					Description: "Kubernetes exploitation agent",
					Instances:   1,
				},
			},
		}

		// Build inventory
		inventory, err := NewInventoryBuilder(mockReg).Build(ctx)
		if err != nil {
			t.Fatalf("failed to build inventory: %v", err)
		}

		// Create validator
		validator := NewInventoryValidator(inventory)

		// Create spawn decision with valid agent
		decision := &Decision{
			Reasoning:    "Need LLM testing capability",
			Action:       ActionSpawnAgent,
			TargetNodeID: "",
			Confidence:   0.9,
			SpawnConfig: &SpawnNodeConfig{
				AgentName:   "davinci",
				Description: "Test LLM vulnerabilities",
				TaskConfig: map[string]interface{}{
					"goal": "Test prompt injection",
				},
				DependsOn: []string{},
			},
		}

		// Validate decision - should succeed
		err = validator.ValidateDecision(decision)
		if err != nil {
			t.Fatalf("expected validation to succeed for valid agent, got error: %v", err)
		}
	})
}

// TestActor_SpawnAgent_InvalidAgent tests that spawn_agent validation fails with invalid agent.
func TestActor_SpawnAgent_InvalidAgent(t *testing.T) {
	t.Run("validation fails with invalid agent and provides suggestions", func(t *testing.T) {
		ctx := context.Background()

		// Create mock registry with test agents
		mockReg := &mockBuilderComponentDiscovery{
			agents: []component.AgentInfo{
				{Name: "davinci", Instances: 1},
				{Name: "k8skiller", Instances: 1},
				{Name: "nuclei-runner", Instances: 1},
			},
		}

		// Build inventory
		inventory, err := NewInventoryBuilder(mockReg).Build(ctx)
		if err != nil {
			t.Fatalf("failed to build inventory: %v", err)
		}

		// Create validator
		validator := NewInventoryValidator(inventory)

		// Create spawn decision with INVALID agent name
		decision := &Decision{
			Reasoning:    "Need testing capability",
			Action:       ActionSpawnAgent,
			TargetNodeID: "",
			Confidence:   0.9,
			SpawnConfig: &SpawnNodeConfig{
				AgentName:   "davinchi", // Typo - should be "davinci"
				Description: "Test vulnerabilities",
				TaskConfig:  map[string]interface{}{},
				DependsOn:   []string{},
			},
		}

		// Validate decision - should fail
		err = validator.ValidateDecision(decision)
		if err == nil {
			t.Fatal("expected validation to fail for invalid agent")
		}

		// Verify it's a ComponentValidationError
		var validationErr *ComponentValidationError
		if !errors.As(err, &validationErr) {
			t.Fatalf("expected ComponentValidationError, got %T: %v", err, err)
		}

		// Verify error details
		if validationErr.ComponentType != "agent" {
			t.Errorf("expected component type 'agent', got '%s'", validationErr.ComponentType)
		}
		if validationErr.RequestedName != "davinchi" {
			t.Errorf("expected requested name 'davinchi', got '%s'", validationErr.RequestedName)
		}

		// Verify suggestions are provided
		if len(validationErr.Suggestions) == 0 {
			t.Error("expected suggestions for similar agent names")
		}

		// "davinci" should be suggested due to similarity
		hasDavinciSuggestion := false
		for _, s := range validationErr.Suggestions {
			if s == "davinci" {
				hasDavinciSuggestion = true
				break
			}
		}
		if !hasDavinciSuggestion {
			t.Errorf("expected 'davinci' in suggestions, got: %v", validationErr.Suggestions)
		}

		// Verify available list is populated
		if len(validationErr.Available) != 3 {
			t.Errorf("expected 3 available agents, got %d", len(validationErr.Available))
		}
	})

	t.Run("validation error message is helpful", func(t *testing.T) {
		ctx := context.Background()

		mockReg := &mockBuilderComponentDiscovery{
			agents: []component.AgentInfo{
				{Name: "davinci", Instances: 1},
				{Name: "k8skiller", Instances: 1},
			},
		}

		inventory, _ := NewInventoryBuilder(mockReg).Build(ctx)
		validator := NewInventoryValidator(inventory)

		decision := &Decision{
			Reasoning:  "Need agent",
			Action:     ActionSpawnAgent,
			Confidence: 0.9,
			SpawnConfig: &SpawnNodeConfig{
				AgentName:   "nonexistent",
				Description: "Test",
				TaskConfig:  map[string]interface{}{},
			},
		}

		err := validator.ValidateDecision(decision)
		if err == nil {
			t.Fatal("expected validation error")
		}

		// Check error message is helpful
		errMsg := err.Error()
		if !stringContains(errMsg, "nonexistent") {
			t.Error("error message should include requested agent name")
		}
		if !stringContains(errMsg, "davinci") || !stringContains(errMsg, "k8skiller") {
			t.Error("error message should list available agents")
		}
	})
}

// TestActor_SpawnAgent_NilInventory tests that validation is skipped when inventory is nil.
func TestActor_SpawnAgent_NilInventory(t *testing.T) {
	t.Run("validation skipped when inventory is nil", func(t *testing.T) {
		// Create validator with nil inventory
		validator := NewInventoryValidator(nil)

		// Create spawn decision with any agent name
		decision := &Decision{
			Reasoning:    "Need testing capability",
			Action:       ActionSpawnAgent,
			TargetNodeID: "",
			Confidence:   0.9,
			SpawnConfig: &SpawnNodeConfig{
				AgentName:   "any-agent-name",
				Description: "Test",
				TaskConfig:  map[string]interface{}{},
			},
		}

		// Validate decision - should succeed (validation skipped)
		err := validator.ValidateDecision(decision)
		if err != nil {
			t.Fatalf("expected validation to succeed when inventory is nil, got error: %v", err)
		}
	})

	t.Run("nil spawn_config is caught before validation", func(t *testing.T) {
		validator := NewInventoryValidator(nil)

		// Create decision with nil spawn_config
		decision := &Decision{
			Reasoning:   "Test",
			Action:      ActionSpawnAgent,
			Confidence:  0.9,
			SpawnConfig: nil, // Invalid
		}

		// Validate - should catch nil spawn_config
		err := validator.ValidateSpawnAgent(decision)
		if err == nil {
			t.Fatal("expected error for nil spawn_config")
		}

		if !stringContains(err.Error(), "spawn_config is required") {
			t.Errorf("expected 'spawn_config is required' error, got: %v", err)
		}
	})
}

// TestActor_ValidationIntegration tests the full validation flow with dependencies.
func TestActor_ValidationIntegration(t *testing.T) {
	t.Run("valid agent spawn with dependencies", func(t *testing.T) {
		ctx := context.Background()

		// Create inventory with agents
		mockReg := &mockBuilderComponentDiscovery{
			agents: []component.AgentInfo{
				{Name: "recon-agent", Instances: 1},
				{Name: "exploit-agent", Instances: 1},
			},
		}

		inventory, _ := NewInventoryBuilder(mockReg).Build(ctx)
		validator := NewInventoryValidator(inventory)

		// Create spawn decision with dependencies
		decision := &Decision{
			Reasoning:  "Exploit discovered vulnerability",
			Action:     ActionSpawnAgent,
			Confidence: 0.95,
			SpawnConfig: &SpawnNodeConfig{
				AgentName:   "exploit-agent",
				Description: "Exploit discovered vulnerability",
				TaskConfig: map[string]interface{}{
					"goal": "Exploit target",
				},
				DependsOn: []string{"node-recon-123"}, // Depends on recon node
			},
		}

		// Validate
		err := validator.ValidateDecision(decision)
		if err != nil {
			t.Fatalf("validation failed: %v", err)
		}
	})

	t.Run("validation catches empty agent name", func(t *testing.T) {
		ctx := context.Background()

		mockReg := &mockBuilderComponentDiscovery{
			agents: []component.AgentInfo{{Name: "davinci", Instances: 1}},
		}

		inventory, _ := NewInventoryBuilder(mockReg).Build(ctx)
		_ = NewInventoryValidator(inventory) // validator exists but Decision.Validate catches first

		decision := &Decision{
			Reasoning:  "Test",
			Action:     ActionSpawnAgent,
			Confidence: 0.9,
			SpawnConfig: &SpawnNodeConfig{
				AgentName:   "", // Empty - invalid
				Description: "Test",
				TaskConfig:  map[string]interface{}{},
			},
		}

		// Decision.Validate() should catch this
		err := decision.Validate()
		if err == nil {
			t.Fatal("expected validation error for empty agent name")
		}
	})
}

// stringContains is a helper to check if a string contains a substring.
func stringContains(s, substr string) bool {
	return len(s) >= len(substr) && containsStr(s, substr)
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
