package daemon

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// mockLLMProvider is a test implementation of llm.LLMProvider
type mockLLMProvider struct {
	name   string
	models []llm.ModelInfo
	health types.HealthStatus
}

func (m *mockLLMProvider) Name() string {
	return m.name
}

func (m *mockLLMProvider) Models(ctx context.Context) ([]llm.ModelInfo, error) {
	return m.models, nil
}

func (m *mockLLMProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	return nil, types.NewError("NOT_IMPLEMENTED", "mock provider does not implement Complete")
}

func (m *mockLLMProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	return nil, types.NewError("NOT_IMPLEMENTED", "mock provider does not implement CompleteWithTools")
}

func (m *mockLLMProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	return nil, types.NewError("NOT_IMPLEMENTED", "mock provider does not implement Stream")
}

func (m *mockLLMProvider) Health(ctx context.Context) types.HealthStatus {
	return m.health
}

// Test helper to create a mock Anthropic provider
func createMockAnthropicProvider() *mockLLMProvider {
	return &mockLLMProvider{
		name: "anthropic",
		models: []llm.ModelInfo{
			{
				Name:          "claude-3-5-sonnet-20241022",
				ContextWindow: 200000,
				Features:      []string{"tool_use", "vision", "streaming"},
				MaxOutput:     8192,
			},
			{
				Name:          "claude-3-opus-20240229",
				ContextWindow: 200000,
				Features:      []string{"tool_use", "vision", "streaming"},
				MaxOutput:     4096,
			},
			{
				Name:          "claude-3-sonnet-20240229",
				ContextWindow: 200000,
				Features:      []string{"tool_use", "streaming"},
				MaxOutput:     4096,
			},
			{
				Name:          "claude-3-haiku-20240307",
				ContextWindow: 200000,
				Features:      []string{"tool_use", "streaming"},
				MaxOutput:     4096,
			},
		},
		health: types.Healthy("mock provider healthy"),
	}
}

// Test helper to create a mock OpenAI provider
func createMockOpenAIProvider() *mockLLMProvider {
	return &mockLLMProvider{
		name: "openai",
		models: []llm.ModelInfo{
			{
				Name:          "gpt-4-turbo",
				ContextWindow: 128000,
				Features:      []string{"tool_use", "vision", "streaming", "json_mode"},
				MaxOutput:     4096,
			},
			{
				Name:          "gpt-4",
				ContextWindow: 8192,
				Features:      []string{"tool_use", "streaming"},
				MaxOutput:     4096,
			},
			{
				Name:          "gpt-3.5-turbo",
				ContextWindow: 16384,
				Features:      []string{"tool_use", "streaming"},
				MaxOutput:     4096,
			},
		},
		health: types.Healthy("mock provider healthy"),
	}
}

func TestDaemonSlotManager_ResolveSlot_PrimarySlot(t *testing.T) {
	ctx := context.Background()

	// Create registry with mock provider
	registry := llm.NewLLMRegistry()
	mockProvider := createMockAnthropicProvider()
	require.NoError(t, registry.RegisterProvider(mockProvider))

	// Create slot manager
	manager := NewDaemonSlotManager(registry, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Create a "primary" slot definition without explicit config
	slot := agent.SlotDefinition{
		Name:        "primary",
		Description: "Primary LLM for agent reasoning",
		Required:    true,
		Constraints: agent.SlotConstraints{
			MinContextWindow: 100000,
			RequiredFeatures: []string{agent.FeatureToolUse},
		},
	}

	// Resolve slot
	provider, model, err := manager.ResolveSlot(ctx, slot, nil)
	require.NoError(t, err)
	assert.NotNil(t, provider)
	assert.Equal(t, "anthropic", provider.Name())

	// Should resolve to Claude 3.5 Sonnet (highest capability)
	assert.Equal(t, "claude-3-5-sonnet-20241022", model.Name)
	assert.GreaterOrEqual(t, model.ContextWindow, 100000)
	assert.True(t, model.SupportsFeature(agent.FeatureToolUse))
}

func TestDaemonSlotManager_ResolveSlot_FastSlot(t *testing.T) {
	ctx := context.Background()

	registry := llm.NewLLMRegistry()
	mockProvider := createMockAnthropicProvider()
	require.NoError(t, registry.RegisterProvider(mockProvider))

	manager := NewDaemonSlotManager(registry, slog.New(slog.NewTextHandler(io.Discard, nil)))

	slot := agent.SlotDefinition{
		Name:        "fast",
		Description: "Fast LLM for quick operations",
		Required:    false,
	}

	provider, model, err := manager.ResolveSlot(ctx, slot, nil)
	require.NoError(t, err)
	assert.NotNil(t, provider)

	// Should resolve to a model meeting the 8k context window constraint
	assert.GreaterOrEqual(t, model.ContextWindow, 8192)
}

func TestDaemonSlotManager_ResolveSlot_VisionSlot(t *testing.T) {
	ctx := context.Background()

	registry := llm.NewLLMRegistry()
	mockProvider := createMockAnthropicProvider()
	require.NoError(t, registry.RegisterProvider(mockProvider))

	manager := NewDaemonSlotManager(registry, slog.New(slog.NewTextHandler(io.Discard, nil)))

	slot := agent.SlotDefinition{
		Name:        "vision",
		Description: "LLM with vision capabilities",
		Required:    true,
	}

	provider, model, err := manager.ResolveSlot(ctx, slot, nil)
	require.NoError(t, err)
	assert.NotNil(t, provider)

	// Should resolve to a model with vision support
	assert.True(t, model.SupportsFeature(agent.FeatureVision))
	assert.Contains(t, []string{"claude-3-5-sonnet-20241022", "claude-3-opus-20240229"}, model.Name)
}

func TestDaemonSlotManager_ResolveSlot_ReasoningSlot(t *testing.T) {
	ctx := context.Background()

	registry := llm.NewLLMRegistry()
	mockProvider := createMockAnthropicProvider()
	require.NoError(t, registry.RegisterProvider(mockProvider))

	manager := NewDaemonSlotManager(registry, slog.New(slog.NewTextHandler(io.Discard, nil)))

	slot := agent.SlotDefinition{
		Name:        "reasoning",
		Description: "High context window LLM for complex reasoning",
		Required:    true,
	}

	provider, model, err := manager.ResolveSlot(ctx, slot, nil)
	require.NoError(t, err)
	assert.NotNil(t, provider)

	// Should resolve to a model meeting the 150k context window constraint
	assert.GreaterOrEqual(t, model.ContextWindow, 150000)
}

func TestDaemonSlotManager_ResolveSlot_ExplicitConfig(t *testing.T) {
	ctx := context.Background()

	registry := llm.NewLLMRegistry()
	require.NoError(t, registry.RegisterProvider(createMockAnthropicProvider()))
	require.NoError(t, registry.RegisterProvider(createMockOpenAIProvider()))

	manager := NewDaemonSlotManager(registry, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Slot with explicit provider and model
	slot := agent.SlotDefinition{
		Name:        "custom",
		Description: "Custom slot",
		Default: agent.SlotConfig{
			Provider:    "openai",
			Model:       "gpt-4-turbo",
			Temperature: 0.8,
			MaxTokens:   2048,
		},
		Constraints: agent.SlotConstraints{
			MinContextWindow: 100000,
		},
	}

	provider, model, err := manager.ResolveSlot(ctx, slot, nil)
	require.NoError(t, err)
	assert.Equal(t, "openai", provider.Name())
	assert.Equal(t, "gpt-4-turbo", model.Name)
	assert.GreaterOrEqual(t, model.ContextWindow, 100000)
}

func TestDaemonSlotManager_ResolveSlot_WithOverride(t *testing.T) {
	ctx := context.Background()

	registry := llm.NewLLMRegistry()
	require.NoError(t, registry.RegisterProvider(createMockAnthropicProvider()))
	require.NoError(t, registry.RegisterProvider(createMockOpenAIProvider()))

	manager := NewDaemonSlotManager(registry, slog.New(slog.NewTextHandler(io.Discard, nil)))

	slot := agent.SlotDefinition{
		Name: "primary",
		Default: agent.SlotConfig{
			Provider: "anthropic",
			Model:    "claude-3-sonnet-20240229",
		},
	}

	// Override to use OpenAI
	override := &agent.SlotConfig{
		Provider: "openai",
		Model:    "gpt-4",
	}

	provider, model, err := manager.ResolveSlot(ctx, slot, override)
	require.NoError(t, err)
	assert.Equal(t, "openai", provider.Name())
	assert.Equal(t, "gpt-4", model.Name)
}

func TestDaemonSlotManager_ResolveSlot_ConstraintValidation_ContextWindow(t *testing.T) {
	ctx := context.Background()

	registry := llm.NewLLMRegistry()
	require.NoError(t, registry.RegisterProvider(createMockOpenAIProvider()))

	manager := NewDaemonSlotManager(registry, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Slot requiring very large context window
	slot := agent.SlotDefinition{
		Name: "large-context",
		Default: agent.SlotConfig{
			Provider: "openai",
			Model:    "gpt-4", // Only has 8192 context
		},
		Constraints: agent.SlotConstraints{
			MinContextWindow: 100000, // Requires 100k+
		},
	}

	_, _, err := manager.ResolveSlot(ctx, slot, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context window")
}

func TestDaemonSlotManager_ResolveSlot_ConstraintValidation_Features(t *testing.T) {
	ctx := context.Background()

	registry := llm.NewLLMRegistry()
	require.NoError(t, registry.RegisterProvider(createMockAnthropicProvider()))

	manager := NewDaemonSlotManager(registry, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Slot requiring vision but selecting a model without it
	slot := agent.SlotDefinition{
		Name: "vision-test",
		Default: agent.SlotConfig{
			Provider: "anthropic",
			Model:    "claude-3-haiku-20240307", // No vision support
		},
		Constraints: agent.SlotConstraints{
			RequiredFeatures: []string{agent.FeatureVision},
		},
	}

	_, _, err := manager.ResolveSlot(ctx, slot, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing required features")
}

func TestDaemonSlotManager_ResolveSlot_NoProvidersRegistered(t *testing.T) {
	ctx := context.Background()

	// Empty registry
	registry := llm.NewLLMRegistry()
	manager := NewDaemonSlotManager(registry, slog.New(slog.NewTextHandler(io.Discard, nil)))

	slot := agent.SlotDefinition{
		Name: "primary",
	}

	_, _, err := manager.ResolveSlot(ctx, slot, nil)
	require.Error(t, err)
	// Per-tenant world (gibson#528): the error points to the dashboard, not
	// env-var/config single-tenant setup.
	assert.Contains(t, err.Error(), "no LLM provider configured for this tenant")
	assert.Contains(t, err.Error(), "Settings → Providers")
}

func TestDaemonSlotManager_ResolveSlot_ProviderNotFound(t *testing.T) {
	ctx := context.Background()

	registry := llm.NewLLMRegistry()
	require.NoError(t, registry.RegisterProvider(createMockAnthropicProvider()))

	manager := NewDaemonSlotManager(registry, slog.New(slog.NewTextHandler(io.Discard, nil)))

	slot := agent.SlotDefinition{
		Name: "custom",
		Default: agent.SlotConfig{
			Provider: "nonexistent",
			Model:    "some-model",
		},
	}

	_, _, err := manager.ResolveSlot(ctx, slot, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestDaemonSlotManager_ResolveSlot_ModelNotFound(t *testing.T) {
	ctx := context.Background()

	registry := llm.NewLLMRegistry()
	require.NoError(t, registry.RegisterProvider(createMockAnthropicProvider()))

	manager := NewDaemonSlotManager(registry, slog.New(slog.NewTextHandler(io.Discard, nil)))

	slot := agent.SlotDefinition{
		Name: "custom",
		Default: agent.SlotConfig{
			Provider: "anthropic",
			Model:    "nonexistent-model",
		},
	}

	_, _, err := manager.ResolveSlot(ctx, slot, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestDaemonSlotManager_ResolveSlot_FallbackToAlternativeProvider(t *testing.T) {
	ctx := context.Background()

	// Only register OpenAI (not preferred Anthropic)
	registry := llm.NewLLMRegistry()
	require.NoError(t, registry.RegisterProvider(createMockOpenAIProvider()))

	manager := NewDaemonSlotManager(registry, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Primary slot defaults to Anthropic, but should fall back to OpenAI
	slot := agent.SlotDefinition{
		Name: "primary",
		Constraints: agent.SlotConstraints{
			MinContextWindow: 100000,
			RequiredFeatures: []string{agent.FeatureToolUse},
		},
	}

	provider, model, err := manager.ResolveSlot(ctx, slot, nil)
	require.NoError(t, err)

	// Should fall back to OpenAI GPT-4 Turbo (meets constraints)
	assert.Equal(t, "openai", provider.Name())
	assert.Equal(t, "gpt-4-turbo", model.Name)
	assert.GreaterOrEqual(t, model.ContextWindow, 100000)
	assert.True(t, model.SupportsFeature(agent.FeatureToolUse))
}

func TestDaemonSlotManager_ValidateSlot_Valid(t *testing.T) {
	ctx := context.Background()

	registry := llm.NewLLMRegistry()
	require.NoError(t, registry.RegisterProvider(createMockAnthropicProvider()))

	manager := NewDaemonSlotManager(registry, slog.New(slog.NewTextHandler(io.Discard, nil)))

	slot := agent.SlotDefinition{
		Name: "primary",
		Default: agent.SlotConfig{
			Provider: "anthropic",
			Model:    "claude-3-5-sonnet-20241022",
		},
		Constraints: agent.SlotConstraints{
			MinContextWindow: 100000,
		},
	}

	err := manager.ValidateSlot(ctx, slot)
	assert.NoError(t, err)
}

func TestDaemonSlotManager_ValidateSlot_Invalid(t *testing.T) {
	ctx := context.Background()

	registry := llm.NewLLMRegistry()
	require.NoError(t, registry.RegisterProvider(createMockOpenAIProvider()))

	manager := NewDaemonSlotManager(registry, slog.New(slog.NewTextHandler(io.Discard, nil)))

	slot := agent.SlotDefinition{
		Name: "invalid",
		Default: agent.SlotConfig{
			Provider: "openai",
			Model:    "gpt-4", // 8k context
		},
		Constraints: agent.SlotConstraints{
			MinContextWindow: 500000, // Impossible requirement
		},
	}

	err := manager.ValidateSlot(ctx, slot)
	assert.Error(t, err)
}

func TestDaemonSlotManager_ConcurrentAccess(t *testing.T) {
	ctx := context.Background()

	registry := llm.NewLLMRegistry()
	require.NoError(t, registry.RegisterProvider(createMockAnthropicProvider()))
	require.NoError(t, registry.RegisterProvider(createMockOpenAIProvider()))

	manager := NewDaemonSlotManager(registry, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Test concurrent slot resolution
	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()

			slotName := "primary"
			if id%2 == 0 {
				slotName = "fast"
			}

			slot := agent.SlotDefinition{
				Name: slotName,
			}

			_, _, err := manager.ResolveSlot(ctx, slot, nil)
			assert.NoError(t, err)
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

func TestDaemonSlotManager_ApplySlotNameDefaults_UnknownSlot(t *testing.T) {
	ctx := context.Background()

	registry := llm.NewLLMRegistry()
	require.NoError(t, registry.RegisterProvider(createMockAnthropicProvider()))

	manager := NewDaemonSlotManager(registry, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Unknown slot name should use constraint-based search
	slot := agent.SlotDefinition{
		Name: "unknown-slot",
	}

	provider, model, err := manager.ResolveSlot(ctx, slot, nil)
	require.NoError(t, err)
	assert.NotNil(t, provider)

	// Should resolve to any available model from Anthropic (constraint-based search)
	assert.Equal(t, "anthropic", provider.Name())
	// Should pick a model with highest context window (3.5 Sonnet or Opus)
	assert.Contains(t, []string{"claude-3-5-sonnet-20241022", "claude-3-opus-20240229", "claude-3-sonnet-20240229", "claude-3-haiku-20240307"}, model.Name)
}

func TestDaemonSlotManager_ResolveSlot_MultipleFeatures(t *testing.T) {
	ctx := context.Background()

	registry := llm.NewLLMRegistry()
	require.NoError(t, registry.RegisterProvider(createMockAnthropicProvider()))

	manager := NewDaemonSlotManager(registry, slog.New(slog.NewTextHandler(io.Discard, nil)))

	slot := agent.SlotDefinition{
		Name: "multi-feature",
		Constraints: agent.SlotConstraints{
			MinContextWindow: 150000,
			RequiredFeatures: []string{
				agent.FeatureToolUse,
				agent.FeatureVision,
				agent.FeatureStreaming,
			},
		},
	}

	provider, model, err := manager.ResolveSlot(ctx, slot, nil)
	require.NoError(t, err)
	assert.NotNil(t, provider)

	// Should resolve to a model with all features
	assert.True(t, model.SupportsFeature(agent.FeatureToolUse))
	assert.True(t, model.SupportsFeature(agent.FeatureVision))
	assert.True(t, model.SupportsFeature(agent.FeatureStreaming))
	assert.GreaterOrEqual(t, model.ContextWindow, 150000)
}

func TestApplySlotNameDefaults_OnlyConstraints(t *testing.T) {
	registry := llm.NewLLMRegistry()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := NewDaemonSlotManager(registry, logger)

	tests := []struct {
		name                string
		slotName            string
		expectedMinContext  int
		expectVisionFeature bool
	}{
		{"primary", "primary", 100000, false},
		{"fast", "fast", 8192, false},
		{"vision", "vision", 50000, true},
		{"reasoning", "reasoning", 150000, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create slot without any constraints (MinContextWindow = 0)
			// so that applySlotNameDefaults can set them
			slot := agent.SlotDefinition{
				Name:        tt.slotName,
				Description: "test",
				Required:    true,
				Default: agent.SlotConfig{
					Provider:    "",
					Model:       "",
					Temperature: 0.7,
					MaxTokens:   4096,
				},
				Constraints: agent.SlotConstraints{
					MinContextWindow: 0, // Not set, so defaults will apply
					RequiredFeatures: []string{},
				},
			}

			result := mgr.applySlotNameDefaults(slot)

			// Should NOT set provider/model
			assert.Equal(t, "", result.Default.Provider, "Provider should remain empty")
			assert.Equal(t, "", result.Default.Model, "Model should remain empty")

			// Should set constraints
			assert.Equal(t, tt.expectedMinContext, result.Constraints.MinContextWindow)

			if tt.expectVisionFeature {
				assert.Contains(t, result.Constraints.RequiredFeatures, agent.FeatureVision)
			}
		})
	}
}

func TestApplySlotNameDefaults_UnknownSlot(t *testing.T) {
	registry := llm.NewLLMRegistry()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := NewDaemonSlotManager(registry, logger)

	slot := agent.NewSlotDefinition("unknown-slot-name", "test", true)
	result := mgr.applySlotNameDefaults(slot)

	// Should NOT set provider/model
	assert.Equal(t, "", result.Default.Provider, "Provider should remain empty")
	assert.Equal(t, "", result.Default.Model, "Model should remain empty")

	// Should keep original constraints (from NewSlotDefinition defaults)
	assert.Equal(t, 8192, result.Constraints.MinContextWindow, "Should keep NewSlotDefinition default")
	assert.Empty(t, result.Constraints.RequiredFeatures, "RequiredFeatures should remain empty")
}

func TestApplySlotNameDefaults_ExplicitConfigPreserved(t *testing.T) {
	registry := llm.NewLLMRegistry()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := NewDaemonSlotManager(registry, logger)

	// Create a "primary" slot with explicit provider/model config
	slot := agent.NewSlotDefinition("primary", "test", true)
	slot = slot.WithDefault(agent.SlotConfig{
		Provider:    "openai",
		Model:       "gpt-4",
		Temperature: 0.8,
		MaxTokens:   2048,
	})

	result := mgr.applySlotNameDefaults(slot)

	// Should preserve explicit provider/model
	assert.Equal(t, "openai", result.Default.Provider, "Explicit provider should be preserved")
	assert.Equal(t, "gpt-4", result.Default.Model, "Explicit model should be preserved")
	assert.Equal(t, 0.8, result.Default.Temperature)
	assert.Equal(t, 2048, result.Default.MaxTokens)
}

func TestResolveByConstraints_NoPreferenceOrder(t *testing.T) {
	registry := llm.NewLLMRegistry()

	// Register providers in a specific order - NOT alphabetical
	// "zebra" provider first, then "alpha"
	zebraProvider := &mockLLMProvider{
		name: "zebra",
		models: []llm.ModelInfo{
			{
				Name:          "zebra-model-1",
				ContextWindow: 100000,
				Features:      []string{agent.FeatureToolUse},
				MaxOutput:     4096,
			},
		},
		health: types.Healthy("mock provider healthy"),
	}
	require.NoError(t, registry.RegisterProvider(zebraProvider))

	alphaProvider := &mockLLMProvider{
		name: "alpha",
		models: []llm.ModelInfo{
			{
				Name:          "alpha-model-1",
				ContextWindow: 100000,
				Features:      []string{agent.FeatureToolUse},
				MaxOutput:     4096,
			},
		},
		health: types.Healthy("mock provider healthy"),
	}
	require.NoError(t, registry.RegisterProvider(alphaProvider))

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := NewDaemonSlotManager(registry, logger)

	slot := agent.NewSlotDefinition("test", "test slot", true)
	provider, model, err := mgr.ResolveSlot(context.Background(), slot, nil)

	require.NoError(t, err)
	// With no explicit/default provider, the fallback scan is deterministic
	// (sorted) — never a hardcoded preference and never map-iteration-order
	// dependent (gibson#531). "alpha" sorts before "zebra".
	assert.Equal(t, "alpha", provider.Name())
	assert.Equal(t, "alpha-model-1", model.Name)
}
