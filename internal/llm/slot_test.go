package llm

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/types"
)

func TestNewSlotManager(t *testing.T) {
	registry := NewLLMRegistry()
	manager := NewSlotManager(registry)

	if manager == nil {
		t.Fatal("NewSlotManager returned nil")
	}

	if manager.registry == nil {
		t.Error("slot manager registry is nil")
	}
}

func TestResolveSlot_Success(t *testing.T) {
	// Setup
	registry := NewLLMRegistry()
	provider := newMockProvider("test-provider", true)
	if err := registry.RegisterProvider(provider); err != nil {
		t.Fatalf("failed to register provider: %v", err)
	}

	manager := NewSlotManager(registry)
	ctx := context.Background()

	// Create a slot definition
	slot := agent.NewSlotDefinition("test-slot", "Test slot", true)
	slot = slot.WithDefault(agent.SlotConfig{
		Provider:    "test-provider",
		Model:       "test-provider-model-1",
		Temperature: 0.7,
		MaxTokens:   4096,
	})
	slot = slot.WithConstraints(agent.SlotConstraints{
		MinContextWindow: 4096,
		RequiredFeatures: []string{agent.FeatureToolUse},
	})

	// Resolve the slot
	resolvedProvider, modelInfo, err := manager.ResolveSlot(ctx, slot, nil)
	if err != nil {
		t.Fatalf("failed to resolve slot: %v", err)
	}

	// Verify provider
	if resolvedProvider.Name() != "test-provider" {
		t.Errorf("expected provider %q, got %q", "test-provider", resolvedProvider.Name())
	}

	// Verify model info
	if modelInfo.Name != "test-provider-model-1" {
		t.Errorf("expected model %q, got %q", "test-provider-model-1", modelInfo.Name)
	}
	if modelInfo.ContextWindow != 8192 {
		t.Errorf("expected context window 8192, got %d", modelInfo.ContextWindow)
	}
}

func TestResolveSlot_WithOverride(t *testing.T) {
	// Setup
	registry := NewLLMRegistry()
	provider := newMockProvider("test-provider", true)
	if err := registry.RegisterProvider(provider); err != nil {
		t.Fatalf("failed to register provider: %v", err)
	}

	manager := NewSlotManager(registry)
	ctx := context.Background()

	// Create a slot definition with default config
	slot := agent.NewSlotDefinition("test-slot", "Test slot", true)
	slot = slot.WithDefault(agent.SlotConfig{
		Provider:    "test-provider",
		Model:       "test-provider-model-1",
		Temperature: 0.7,
		MaxTokens:   4096,
	})
	slot = slot.WithConstraints(agent.SlotConstraints{
		MinContextWindow: 4096,
		RequiredFeatures: []string{agent.FeatureToolUse},
	})

	// Override with a different model
	override := &agent.SlotConfig{
		Model: "test-provider-model-2",
	}

	// Resolve the slot with override
	resolvedProvider, modelInfo, err := manager.ResolveSlot(ctx, slot, override)
	if err != nil {
		t.Fatalf("failed to resolve slot: %v", err)
	}

	// Verify the override was applied
	if modelInfo.Name != "test-provider-model-2" {
		t.Errorf("expected model %q, got %q", "test-provider-model-2", modelInfo.Name)
	}

	// Verify provider remains the same
	if resolvedProvider.Name() != "test-provider" {
		t.Errorf("expected provider %q, got %q", "test-provider", resolvedProvider.Name())
	}
}

func TestResolveSlot_ProviderNotFound(t *testing.T) {
	registry := NewLLMRegistry()
	manager := NewSlotManager(registry)
	ctx := context.Background()

	slot := agent.NewSlotDefinition("test-slot", "Test slot", true)
	slot = slot.WithDefault(agent.SlotConfig{
		Provider:    "nonexistent-provider",
		Model:       "some-model",
		Temperature: 0.7,
		MaxTokens:   4096,
	})

	_, _, err := manager.ResolveSlot(ctx, slot, nil)
	if err == nil {
		t.Fatal("expected error for nonexistent provider, got nil")
	}

	var gibsonErr *types.GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatalf("expected GibsonError, got %T", err)
	}
	if gibsonErr.Code != ErrNoMatchingProvider {
		t.Errorf("expected error code %q, got %q", ErrNoMatchingProvider, gibsonErr.Code)
	}
}

func TestResolveSlot_ModelNotFound(t *testing.T) {
	registry := NewLLMRegistry()
	provider := newMockProvider("test-provider", true)
	if err := registry.RegisterProvider(provider); err != nil {
		t.Fatalf("failed to register provider: %v", err)
	}

	manager := NewSlotManager(registry)
	ctx := context.Background()

	slot := agent.NewSlotDefinition("test-slot", "Test slot", true)
	slot = slot.WithDefault(agent.SlotConfig{
		Provider:    "test-provider",
		Model:       "nonexistent-model",
		Temperature: 0.7,
		MaxTokens:   4096,
	})

	_, _, err := manager.ResolveSlot(ctx, slot, nil)
	if err == nil {
		t.Fatal("expected error for nonexistent model, got nil")
	}

	var gibsonErr *types.GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatalf("expected GibsonError, got %T", err)
	}
	if gibsonErr.Code != ErrNoMatchingProvider {
		t.Errorf("expected error code %q, got %q", ErrNoMatchingProvider, gibsonErr.Code)
	}
}

func TestResolveSlot_EmptyProvider(t *testing.T) {
	registry := NewLLMRegistry()
	manager := NewSlotManager(registry)
	ctx := context.Background()

	slot := agent.NewSlotDefinition("test-slot", "Test slot", true)
	slot = slot.WithDefault(agent.SlotConfig{
		Provider:    "",
		Model:       "some-model",
		Temperature: 0.7,
		MaxTokens:   4096,
	})

	_, _, err := manager.ResolveSlot(ctx, slot, nil)
	if err == nil {
		t.Fatal("expected error for empty provider, got nil")
	}

	var gibsonErr *types.GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatalf("expected GibsonError, got %T", err)
	}
	if gibsonErr.Code != ErrInvalidSlotConfig {
		t.Errorf("expected error code %q, got %q", ErrInvalidSlotConfig, gibsonErr.Code)
	}
}

func TestResolveSlot_EmptyModel(t *testing.T) {
	registry := NewLLMRegistry()
	manager := NewSlotManager(registry)
	ctx := context.Background()

	slot := agent.NewSlotDefinition("test-slot", "Test slot", true)
	slot = slot.WithDefault(agent.SlotConfig{
		Provider:    "test-provider",
		Model:       "",
		Temperature: 0.7,
		MaxTokens:   4096,
	})

	_, _, err := manager.ResolveSlot(ctx, slot, nil)
	if err == nil {
		t.Fatal("expected error for empty model, got nil")
	}

	var gibsonErr *types.GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatalf("expected GibsonError, got %T", err)
	}
	if gibsonErr.Code != ErrInvalidSlotConfig {
		t.Errorf("expected error code %q, got %q", ErrInvalidSlotConfig, gibsonErr.Code)
	}
}

func TestResolveSlot_ContextWindowConstraint(t *testing.T) {
	registry := NewLLMRegistry()
	provider := newMockProvider("test-provider", true)
	if err := registry.RegisterProvider(provider); err != nil {
		t.Fatalf("failed to register provider: %v", err)
	}

	manager := NewSlotManager(registry)
	ctx := context.Background()

	// Create a slot with MinContextWindow larger than available (8192)
	slot := agent.NewSlotDefinition("test-slot", "Test slot", true)
	slot = slot.WithDefault(agent.SlotConfig{
		Provider:    "test-provider",
		Model:       "test-provider-model-1",
		Temperature: 0.7,
		MaxTokens:   4096,
	})
	slot = slot.WithConstraints(agent.SlotConstraints{
		MinContextWindow: 32000, // Greater than model's 8192
		RequiredFeatures: []string{},
	})

	_, _, err := manager.ResolveSlot(ctx, slot, nil)
	if err == nil {
		t.Fatal("expected error for insufficient context window, got nil")
	}

	var gibsonErr *types.GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatalf("expected GibsonError, got %T", err)
	}
	if gibsonErr.Code != ErrNoMatchingProvider {
		t.Errorf("expected error code %q, got %q", ErrNoMatchingProvider, gibsonErr.Code)
	}
}

func TestResolveSlot_RequiredFeaturesConstraint(t *testing.T) {
	registry := NewLLMRegistry()
	provider := newMockProvider("test-provider", true)
	if err := registry.RegisterProvider(provider); err != nil {
		t.Fatalf("failed to register provider: %v", err)
	}

	manager := NewSlotManager(registry)
	ctx := context.Background()

	// model-1 has: tool_use, streaming
	// Request vision which is not available
	slot := agent.NewSlotDefinition("test-slot", "Test slot", true)
	slot = slot.WithDefault(agent.SlotConfig{
		Provider:    "test-provider",
		Model:       "test-provider-model-1",
		Temperature: 0.7,
		MaxTokens:   4096,
	})
	slot = slot.WithConstraints(agent.SlotConstraints{
		MinContextWindow: 4096,
		RequiredFeatures: []string{agent.FeatureVision}, // Not available in model-1
	})

	_, _, err := manager.ResolveSlot(ctx, slot, nil)
	if err == nil {
		t.Fatal("expected error for missing required feature, got nil")
	}

	var gibsonErr *types.GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatalf("expected GibsonError, got %T", err)
	}
	if gibsonErr.Code != ErrNoMatchingProvider {
		t.Errorf("expected error code %q, got %q", ErrNoMatchingProvider, gibsonErr.Code)
	}
}

func TestResolveSlot_AllConstraintsMet(t *testing.T) {
	registry := NewLLMRegistry()
	provider := newMockProvider("test-provider", true)
	if err := registry.RegisterProvider(provider); err != nil {
		t.Fatalf("failed to register provider: %v", err)
	}

	manager := NewSlotManager(registry)
	ctx := context.Background()

	// model-2 has: tool_use, vision, streaming with 16384 context window
	slot := agent.NewSlotDefinition("test-slot", "Test slot", true)
	slot = slot.WithDefault(agent.SlotConfig{
		Provider:    "test-provider",
		Model:       "test-provider-model-2",
		Temperature: 0.7,
		MaxTokens:   4096,
	})
	slot = slot.WithConstraints(agent.SlotConstraints{
		MinContextWindow: 8192,
		RequiredFeatures: []string{agent.FeatureToolUse, agent.FeatureVision},
	})

	_, modelInfo, err := manager.ResolveSlot(ctx, slot, nil)
	if err != nil {
		t.Fatalf("failed to resolve slot: %v", err)
	}

	if modelInfo.Name != "test-provider-model-2" {
		t.Errorf("expected model %q, got %q", "test-provider-model-2", modelInfo.Name)
	}
}

func TestValidateSlot_Success(t *testing.T) {
	registry := NewLLMRegistry()
	provider := newMockProvider("test-provider", true)
	if err := registry.RegisterProvider(provider); err != nil {
		t.Fatalf("failed to register provider: %v", err)
	}

	manager := NewSlotManager(registry)
	ctx := context.Background()

	slot := agent.NewSlotDefinition("test-slot", "Test slot", true)
	slot = slot.WithDefault(agent.SlotConfig{
		Provider:    "test-provider",
		Model:       "test-provider-model-1",
		Temperature: 0.7,
		MaxTokens:   4096,
	})
	slot = slot.WithConstraints(agent.SlotConstraints{
		MinContextWindow: 4096,
		RequiredFeatures: []string{agent.FeatureToolUse},
	})

	err := manager.ValidateSlot(ctx, slot)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
}

func TestValidateSlot_Failure(t *testing.T) {
	registry := NewLLMRegistry()
	provider := newMockProvider("test-provider", true)
	if err := registry.RegisterProvider(provider); err != nil {
		t.Fatalf("failed to register provider: %v", err)
	}

	manager := NewSlotManager(registry)
	ctx := context.Background()

	// Invalid slot with nonexistent model
	slot := agent.NewSlotDefinition("test-slot", "Test slot", true)
	slot = slot.WithDefault(agent.SlotConfig{
		Provider:    "test-provider",
		Model:       "nonexistent-model",
		Temperature: 0.7,
		MaxTokens:   4096,
	})

	err := manager.ValidateSlot(ctx, slot)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
}

func TestValidateConstraints_ContextWindow(t *testing.T) {
	manager := NewSlotManager(nil)

	tests := []struct {
		name               string
		minContextWindow   int
		modelContextWindow int
		expectError        bool
	}{
		{
			name:               "sufficient context window",
			minContextWindow:   4096,
			modelContextWindow: 8192,
			expectError:        false,
		},
		{
			name:               "exact context window",
			minContextWindow:   8192,
			modelContextWindow: 8192,
			expectError:        false,
		},
		{
			name:               "insufficient context window",
			minContextWindow:   16384,
			modelContextWindow: 8192,
			expectError:        true,
		},
		{
			name:               "no constraint (0)",
			minContextWindow:   0,
			modelContextWindow: 8192,
			expectError:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slot := agent.SlotDefinition{
				Constraints: agent.SlotConstraints{
					MinContextWindow: tt.minContextWindow,
					RequiredFeatures: []string{},
				},
			}

			model := ModelInfo{
				Name:          "test-model",
				ContextWindow: tt.modelContextWindow,
				Features:      []string{},
			}

			err := manager.validateConstraints(slot, model)
			if tt.expectError && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateConstraints_RequiredFeatures(t *testing.T) {
	manager := NewSlotManager(nil)

	tests := []struct {
		name             string
		requiredFeatures []string
		modelFeatures    []string
		expectError      bool
	}{
		{
			name:             "all features present",
			requiredFeatures: []string{"tool_use", "streaming"},
			modelFeatures:    []string{"tool_use", "streaming", "vision"},
			expectError:      false,
		},
		{
			name:             "exact features match",
			requiredFeatures: []string{"tool_use"},
			modelFeatures:    []string{"tool_use"},
			expectError:      false,
		},
		{
			name:             "missing one feature",
			requiredFeatures: []string{"tool_use", "vision"},
			modelFeatures:    []string{"tool_use"},
			expectError:      true,
		},
		{
			name:             "missing all features",
			requiredFeatures: []string{"tool_use", "vision"},
			modelFeatures:    []string{},
			expectError:      true,
		},
		{
			name:             "no required features",
			requiredFeatures: []string{},
			modelFeatures:    []string{"tool_use", "vision"},
			expectError:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slot := agent.SlotDefinition{
				Constraints: agent.SlotConstraints{
					MinContextWindow: 0,
					RequiredFeatures: tt.requiredFeatures,
				},
			}

			model := ModelInfo{
				Name:          "test-model",
				ContextWindow: 8192,
				Features:      tt.modelFeatures,
			}

			err := manager.validateConstraints(slot, model)
			if tt.expectError && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestConvertAgentFeatureToModelFeature(t *testing.T) {
	tests := []struct {
		agentFeature string
		expected     string
	}{
		{agent.FeatureToolUse, "tool_use"},
		{agent.FeatureVision, "vision"},
		{agent.FeatureStreaming, "streaming"},
		{agent.FeatureJSONMode, "json_mode"},
	}

	for _, tt := range tests {
		t.Run(tt.agentFeature, func(t *testing.T) {
			result := convertAgentFeatureToModelFeature(tt.agentFeature)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestSlotManager_MultipleProviders(t *testing.T) {
	registry := NewLLMRegistry()

	// Register multiple providers
	provider1 := newMockProvider("provider1", true)
	provider2 := newMockProvider("provider2", true)

	if err := registry.RegisterProvider(provider1); err != nil {
		t.Fatalf("failed to register provider1: %v", err)
	}
	if err := registry.RegisterProvider(provider2); err != nil {
		t.Fatalf("failed to register provider2: %v", err)
	}

	manager := NewSlotManager(registry)
	ctx := context.Background()

	// Test resolving with provider1
	slot1 := agent.NewSlotDefinition("slot1", "Slot 1", true)
	slot1 = slot1.WithDefault(agent.SlotConfig{
		Provider:    "provider1",
		Model:       "provider1-model-1",
		Temperature: 0.7,
		MaxTokens:   4096,
	})

	provider, model, err := manager.ResolveSlot(ctx, slot1, nil)
	if err != nil {
		t.Fatalf("failed to resolve slot1: %v", err)
	}
	if provider.Name() != "provider1" {
		t.Errorf("expected provider1, got %q", provider.Name())
	}
	if model.Name != "provider1-model-1" {
		t.Errorf("expected provider1-model-1, got %q", model.Name)
	}

	// Test resolving with provider2
	slot2 := agent.NewSlotDefinition("slot2", "Slot 2", true)
	slot2 = slot2.WithDefault(agent.SlotConfig{
		Provider:    "provider2",
		Model:       "provider2-model-2",
		Temperature: 0.7,
		MaxTokens:   4096,
	})

	provider, model, err = manager.ResolveSlot(ctx, slot2, nil)
	if err != nil {
		t.Fatalf("failed to resolve slot2: %v", err)
	}
	if provider.Name() != "provider2" {
		t.Errorf("expected provider2, got %q", provider.Name())
	}
	if model.Name != "provider2-model-2" {
		t.Errorf("expected provider2-model-2, got %q", model.Name)
	}
}

func TestResolveSlot_JSONModeFeatureValidation(t *testing.T) {
	registry := NewLLMRegistry()
	provider := newMockProvider("test-provider", true)
	if err := registry.RegisterProvider(provider); err != nil {
		t.Fatalf("failed to register provider: %v", err)
	}

	manager := NewSlotManager(registry)
	ctx := context.Background()

	tests := []struct {
		name         string
		model        string
		requireJSON  bool
		expectError  bool
		errorMessage string
	}{
		{
			name:        "model without json_mode - no requirement",
			model:       "test-provider-model-1", // has: tool_use, streaming
			requireJSON: false,
			expectError: false,
		},
		{
			name:         "model without json_mode - with requirement",
			model:        "test-provider-model-1", // has: tool_use, streaming
			requireJSON:  true,
			expectError:  true,
			errorMessage: "json_mode",
		},
		{
			name:        "model with json_mode - with requirement",
			model:       "test-provider-model-3", // has: tool_use, streaming, json_mode
			requireJSON: true,
			expectError: false,
		},
		{
			name:        "model with json_mode - no requirement",
			model:       "test-provider-model-3", // has: tool_use, streaming, json_mode
			requireJSON: false,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build required features list
			requiredFeatures := []string{}
			if tt.requireJSON {
				requiredFeatures = append(requiredFeatures, agent.FeatureJSONMode)
			}

			// Create slot definition
			slot := agent.NewSlotDefinition("structured-output-slot", "Slot requiring structured output", true)
			slot = slot.WithDefault(agent.SlotConfig{
				Provider:    "test-provider",
				Model:       tt.model,
				Temperature: 0.7,
				MaxTokens:   4096,
			})
			slot = slot.WithConstraints(agent.SlotConstraints{
				MinContextWindow: 4096,
				RequiredFeatures: requiredFeatures,
			})

			// Attempt to resolve the slot
			_, modelInfo, err := manager.ResolveSlot(ctx, slot, nil)

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error for missing json_mode feature, got nil")
				}

				var gibsonErr *types.GibsonError
				if !errors.As(err, &gibsonErr) {
					t.Fatalf("expected GibsonError, got %T", err)
				}
				if gibsonErr.Code != ErrNoMatchingProvider {
					t.Errorf("expected error code %q, got %q", ErrNoMatchingProvider, gibsonErr.Code)
				}

				// Verify error message mentions the missing feature
				if tt.errorMessage != "" {
					errMsg := err.Error()
					if !contains(errMsg, tt.errorMessage) {
						t.Errorf("expected error message to contain %q, got: %s", tt.errorMessage, errMsg)
					}
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				// Verify model was resolved correctly
				if modelInfo.Name != tt.model {
					t.Errorf("expected model %q, got %q", tt.model, modelInfo.Name)
				}

				// If json_mode was required, verify the model supports it
				if tt.requireJSON && !modelInfo.SupportsJSONMode() {
					t.Error("model should support json_mode but SupportsJSONMode() returned false")
				}
			}
		})
	}
}
