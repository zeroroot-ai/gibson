// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
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
	// saved is the default model the tenant saved for the provider.
	saved string
	// listCalls counts Models calls. A mission must make none.
	listCalls atomic.Int32
}

// DefaultModel returns the saved default model of the mock.
func (m *mockLLMProvider) DefaultModel() string { return m.saved }

func (m *mockLLMProvider) Name() string {
	return m.name
}

func (m *mockLLMProvider) Models(ctx context.Context) ([]llm.ModelInfo, error) {
	m.listCalls.Add(1)
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
		name:  "anthropic",
		saved: "claude-3-5-sonnet-20241022",
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
		name:  "openai",
		saved: "gpt-4-turbo",
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
		},
	}

	// Resolve slot
	provider, model, err := manager.ResolveSlot(ctx, slot, nil)
	require.NoError(t, err)
	assert.NotNil(t, provider)
	assert.Equal(t, "anthropic", provider.Name())

	// The model is the default that the tenant saved. A mission never lists
	// models, and the window and features of the model are unknown.
	assert.Equal(t, "claude-3-5-sonnet-20241022", model.Name)
	assert.True(t, model.ContextWindowUnreported)
	assert.Zero(t, mockProvider.listCalls.Load(), "a mission must not call Models")
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

	assert.Equal(t, "claude-3-5-sonnet-20241022", model.Name)
	assert.Zero(t, mockProvider.listCalls.Load())
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

	// The feature set of the saved model is unknown, so the vision slot passes.
	assert.Equal(t, "claude-3-5-sonnet-20241022", model.Name)
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

	assert.Equal(t, "claude-3-5-sonnet-20241022", model.Name)
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

// openAIWithoutWindows mimics a live OpenAI list: no context window and no
// feature set is reported for any model.
func openAIWithoutWindows() *mockLLMProvider {
	return &mockLLMProvider{
		name:   "openai",
		saved:  "gpt-5",
		models: []llm.ModelInfo{{Name: "gpt-5", ContextWindowUnreported: true}},
		health: types.Healthy("mock provider healthy"),
	}
}

func TestDaemonSlotManager_UnknownWindowAndFeaturesPassEveryDefaultSlot(t *testing.T) {
	for _, slotName := range []string{"primary", "fast", "vision", "reasoning"} {
		t.Run(slotName, func(t *testing.T) {
			registry := llm.NewLLMRegistry()
			p := openAIWithoutWindows()
			require.NoError(t, registry.RegisterProvider(p))
			manager := NewDaemonSlotManager(registry, slog.New(slog.DiscardHandler))

			provider, model, err := manager.ResolveSlot(context.Background(), agent.SlotDefinition{Name: slotName}, nil)
			require.NoError(t, err)
			assert.Equal(t, "openai", provider.Name())
			assert.Equal(t, "gpt-5", model.Name)
			assert.Zero(t, p.listCalls.Load(), "a mission must not call Models")
		})
	}
}

func TestDaemonSlotManager_ExplicitModelNeedsNoList(t *testing.T) {
	registry := llm.NewLLMRegistry()
	p := openAIWithoutWindows()
	require.NoError(t, registry.RegisterProvider(p))
	manager := NewDaemonSlotManager(registry, slog.New(slog.NewTextHandler(io.Discard, nil)))

	slot := agent.SlotDefinition{
		Name:    "primary",
		Default: agent.SlotConfig{Provider: "openai", Model: "any-typed-model"},
	}
	_, model, err := manager.ResolveSlot(context.Background(), slot, nil)
	require.NoError(t, err)
	assert.Equal(t, "any-typed-model", model.Name, "the saved choice is used as given")
	assert.Zero(t, p.listCalls.Load())
}

func TestDaemonSlotManager_ValidateConstraints_ReportedWindowStillFails(t *testing.T) {
	manager := NewDaemonSlotManager(llm.NewLLMRegistry(), slog.New(slog.DiscardHandler))
	slot := agent.SlotDefinition{Name: "primary", Constraints: agent.SlotConstraints{MinContextWindow: 100000}}

	// A model that reports a window below the minimum fails.
	err := manager.validateConstraints(slot, llm.ModelInfo{Name: "claude-small", ContextWindow: 8192})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context window")

	// Reported and large enough passes. Unreported passes. A reported zero fails.
	require.NoError(t, manager.validateConstraints(slot, llm.ModelInfo{Name: "ok", ContextWindow: 200000}))
	require.NoError(t, manager.validateConstraints(slot, llm.ModelInfo{Name: "gpt", ContextWindowUnreported: true}))
	require.Error(t, manager.validateConstraints(slot, llm.ModelInfo{Name: "zero"}))
}

// The vision slot name sets a context floor and no feature requirement: no
// provider reports a complete feature set, so a feature check could not fail.
func TestApplySlotNameDefaults_VisionHasNoFeatureRequirement(t *testing.T) {
	mgr := NewDaemonSlotManager(llm.NewLLMRegistry(), slog.New(slog.DiscardHandler))
	result := mgr.applySlotNameDefaults(agent.SlotDefinition{Name: "vision"})
	assert.Equal(t, 50000, result.Constraints.MinContextWindow)
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

func TestDaemonSlotManager_ResolveSlot_NoSavedModelFailsClearly(t *testing.T) {
	registry := llm.NewLLMRegistry()
	require.NoError(t, registry.RegisterProvider(&mockLLMProvider{name: "anthropic", health: types.Healthy("ok")}))
	manager := NewDaemonSlotManager(registry, slog.New(slog.NewTextHandler(io.Discard, nil)))

	_, _, err := manager.ResolveSlot(context.Background(), agent.SlotDefinition{Name: "primary"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no saved default model")
	assert.Contains(t, err.Error(), "Settings → Providers")
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
		},
	}

	provider, model, err := manager.ResolveSlot(ctx, slot, nil)
	require.NoError(t, err)

	// Should fall back to OpenAI GPT-4 Turbo (meets constraints)
	assert.Equal(t, "openai", provider.Name())
	assert.Equal(t, "gpt-4-turbo", model.Name)
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

	// A slot that names a provider the tenant has not configured is invalid.
	slot := agent.SlotDefinition{
		Name: "invalid",
		Default: agent.SlotConfig{
			Provider: "ghost",
			Model:    "gpt-4",
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
	assert.Equal(t, "claude-3-5-sonnet-20241022", model.Name, "the saved default model")
}

func TestApplySlotNameDefaults_OnlyConstraints(t *testing.T) {
	registry := llm.NewLLMRegistry()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := NewDaemonSlotManager(registry, logger)

	tests := []struct {
		name               string
		slotName           string
		expectedMinContext int
	}{
		{"primary", "primary", 100000},
		{"fast", "fast", 8192},
		{"vision", "vision", 50000},
		{"reasoning", "reasoning", 150000},
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
				},
			}

			result := mgr.applySlotNameDefaults(slot)

			// Should NOT set provider/model
			assert.Equal(t, "", result.Default.Provider, "Provider should remain empty")
			assert.Equal(t, "", result.Default.Model, "Model should remain empty")

			// Should set constraints
			assert.Equal(t, tt.expectedMinContext, result.Constraints.MinContextWindow)

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
		name:  "zebra",
		saved: "zebra-model-1",
		models: []llm.ModelInfo{
			{
				Name:          "zebra-model-1",
				ContextWindow: 100000,
				Features:      []string{"tool_use"},
				MaxOutput:     4096,
			},
		},
		health: types.Healthy("mock provider healthy"),
	}
	require.NoError(t, registry.RegisterProvider(zebraProvider))

	alphaProvider := &mockLLMProvider{
		name:  "alpha",
		saved: "alpha-model-1",
		models: []llm.ModelInfo{
			{
				Name:          "alpha-model-1",
				ContextWindow: 100000,
				Features:      []string{"tool_use"},
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
