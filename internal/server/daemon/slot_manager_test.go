// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
)

// slotTestLogger returns a logger that writes nothing.
func slotTestLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// newSlotManager builds a slot manager over the given provider records.
func newSlotManager(providers ...SlotProvider) *DaemonSlotManager {
	return NewDaemonSlotManager(providers, slotTestLogger())
}

// provWithModel is a provider that has a saved default model with a 200k window.
func provWithModel(name, model string) SlotProvider {
	return SlotProvider{Name: name, DefaultModel: model, ContextWindow: 200000}
}

// anthropicProvider is a provider record with a saved default model.
func anthropicProvider() SlotProvider {
	return SlotProvider{Name: "anthropic", DefaultModel: "claude-3-5-sonnet-20241022", ContextWindow: 200000}
}

// openAIProvider is a provider record with a saved default model.
func openAIProvider() SlotProvider {
	return SlotProvider{Name: "openai", DefaultModel: "gpt-4-turbo", ContextWindow: 128000}
}

// openAIWithoutWindow mimics a record that stores no context window.
func openAIWithoutWindow() SlotProvider {
	return SlotProvider{Name: "openai", DefaultModel: "gpt-5"}
}

func TestDaemonSlotManager_ResolveSlot_PrimarySlot(t *testing.T) {
	manager := newSlotManager(anthropicProvider())
	slot := agent.SlotDefinition{
		Name:        "primary",
		Description: "Primary LLM for agent reasoning",
		Required:    true,
		Constraints: agent.SlotConstraints{MinContextWindow: 100000},
	}

	picked, err := manager.ResolveSlot(context.Background(), slot, nil)
	require.NoError(t, err)

	// The model is the default that the tenant saved. The window is the one
	// that was stored with it.
	assert.Equal(t, harness.SlotModel{
		Provider: "anthropic", Model: "claude-3-5-sonnet-20241022", ContextWindow: 200000,
	}, picked)
}

func TestDaemonSlotManager_ResolveSlot_DefaultSlotNames(t *testing.T) {
	for _, name := range []string{"fast", "vision", "reasoning"} {
		t.Run(name, func(t *testing.T) {
			manager := newSlotManager(anthropicProvider())
			picked, err := manager.ResolveSlot(context.Background(), agent.SlotDefinition{Name: name, Required: true}, nil)
			require.NoError(t, err)
			assert.Equal(t, "anthropic", picked.Provider)
			assert.Equal(t, "claude-3-5-sonnet-20241022", picked.Model)
		})
	}
}

func TestDaemonSlotManager_ResolveSlot_ExplicitConfig(t *testing.T) {
	manager := newSlotManager(anthropicProvider(), openAIProvider())
	slot := agent.SlotDefinition{
		Name:        "custom",
		Description: "Custom slot",
		Default: agent.SlotConfig{
			Provider: "openai", Model: "gpt-4-turbo", Temperature: 0.8, MaxTokens: 2048,
		},
		Constraints: agent.SlotConstraints{MinContextWindow: 100000},
	}

	picked, err := manager.ResolveSlot(context.Background(), slot, nil)
	require.NoError(t, err)
	assert.Equal(t, "openai", picked.Provider)
	assert.Equal(t, "gpt-4-turbo", picked.Model)
	assert.Equal(t, 128000, picked.ContextWindow, "the saved default model keeps its stored window")
}

func TestDaemonSlotManager_ResolveSlot_WithOverride(t *testing.T) {
	manager := newSlotManager(anthropicProvider(), openAIProvider())
	slot := agent.SlotDefinition{
		Name:    "primary",
		Default: agent.SlotConfig{Provider: "anthropic", Model: "claude-3-sonnet-20240229"},
	}
	override := &agent.SlotConfig{Provider: "openai", Model: "gpt-4"}

	picked, err := manager.ResolveSlot(context.Background(), slot, override)
	require.NoError(t, err)
	assert.Equal(t, "openai", picked.Provider)
	assert.Equal(t, "gpt-4", picked.Model)
	assert.Zero(t, picked.ContextWindow, "a model that is not the saved default has an unknown window")
}

func TestDaemonSlotManager_UnknownWindowPassesEveryDefaultSlot(t *testing.T) {
	for _, slotName := range []string{"primary", "fast", "vision", "reasoning"} {
		t.Run(slotName, func(t *testing.T) {
			manager := newSlotManager(openAIWithoutWindow())

			picked, err := manager.ResolveSlot(context.Background(), agent.SlotDefinition{Name: slotName}, nil)
			require.NoError(t, err)
			assert.Equal(t, "openai", picked.Provider)
			assert.Equal(t, "gpt-5", picked.Model)
			assert.Zero(t, picked.ContextWindow)
		})
	}
}

func TestDaemonSlotManager_ExplicitModelNeedsNoList(t *testing.T) {
	manager := newSlotManager(openAIWithoutWindow())
	slot := agent.SlotDefinition{
		Name:    "primary",
		Default: agent.SlotConfig{Provider: "openai", Model: "any-typed-model"},
	}

	picked, err := manager.ResolveSlot(context.Background(), slot, nil)
	require.NoError(t, err)
	assert.Equal(t, "any-typed-model", picked.Model, "the saved choice is used as given")
}

func TestDaemonSlotManager_ValidateConstraints(t *testing.T) {
	manager := newSlotManager()
	slot := agent.SlotDefinition{Name: "primary", Constraints: agent.SlotConstraints{MinContextWindow: 100000}}

	// A known window below the minimum fails.
	err := manager.validateConstraints(slot, harness.SlotModel{Model: "claude-small", ContextWindow: 8192})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context window")

	// A known window that is large enough passes. An unknown window passes.
	require.NoError(t, manager.validateConstraints(slot, harness.SlotModel{Model: "ok", ContextWindow: 200000}))
	require.NoError(t, manager.validateConstraints(slot, harness.SlotModel{Model: "gpt"}))
}

func TestDaemonSlotManager_AKnownSmallWindowFailsTheSlot(t *testing.T) {
	manager := newSlotManager(SlotProvider{Name: "small", DefaultModel: "tiny", ContextWindow: 4096})

	_, err := manager.ResolveSlot(context.Background(), agent.SlotDefinition{Name: "primary"}, nil)
	require.Error(t, err)
	assert.ErrorContains(t, err, "context window")
}

// The vision slot name sets a context floor and no feature requirement.
func TestApplySlotNameDefaults_VisionHasNoFeatureRequirement(t *testing.T) {
	result := newSlotManager().applySlotNameDefaults(agent.SlotDefinition{Name: "vision"})
	assert.Equal(t, 50000, result.Constraints.MinContextWindow)
}

func TestDaemonSlotManager_ResolveSlot_NoProvidersRegistered(t *testing.T) {
	manager := newSlotManager()

	_, err := manager.ResolveSlot(context.Background(), agent.SlotDefinition{Name: "primary"}, nil)
	require.Error(t, err)
	// Per-tenant world (gibson#528): the error points to the dashboard.
	assert.Contains(t, err.Error(), "no LLM provider configured for this tenant")
	assert.Contains(t, err.Error(), "Settings → Providers")
}

func TestDaemonSlotManager_ResolveSlot_ProviderNotFound(t *testing.T) {
	manager := newSlotManager(anthropicProvider())
	slot := agent.SlotDefinition{
		Name:    "custom",
		Default: agent.SlotConfig{Provider: "nonexistent", Model: "some-model"},
	}

	_, err := manager.ResolveSlot(context.Background(), slot, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestDaemonSlotManager_ResolveSlot_NoSavedModelFailsClearly(t *testing.T) {
	manager := newSlotManager(SlotProvider{Name: "anthropic"})

	_, err := manager.ResolveSlot(context.Background(), agent.SlotDefinition{Name: "primary"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no saved default model")
	assert.Contains(t, err.Error(), "Settings → Providers")
}

func TestDaemonSlotManager_ResolveSlot_FallbackToAlternativeProvider(t *testing.T) {
	manager := newSlotManager(openAIProvider())
	slot := agent.SlotDefinition{
		Name:        "primary",
		Constraints: agent.SlotConstraints{MinContextWindow: 100000},
	}

	picked, err := manager.ResolveSlot(context.Background(), slot, nil)
	require.NoError(t, err)
	assert.Equal(t, "openai", picked.Provider)
	assert.Equal(t, "gpt-4-turbo", picked.Model)
}

func TestDaemonSlotManager_ValidateSlot_Valid(t *testing.T) {
	manager := newSlotManager(anthropicProvider())
	slot := agent.SlotDefinition{
		Name:        "primary",
		Default:     agent.SlotConfig{Provider: "anthropic", Model: "claude-3-5-sonnet-20241022"},
		Constraints: agent.SlotConstraints{MinContextWindow: 100000},
	}

	assert.NoError(t, manager.ValidateSlot(context.Background(), slot))
}

func TestDaemonSlotManager_ValidateSlot_Invalid(t *testing.T) {
	manager := newSlotManager(openAIProvider())
	// A slot that names a provider the tenant has not configured is invalid.
	slot := agent.SlotDefinition{
		Name:    "invalid",
		Default: agent.SlotConfig{Provider: "ghost", Model: "gpt-4"},
	}

	assert.Error(t, manager.ValidateSlot(context.Background(), slot))
}

func TestDaemonSlotManager_ConcurrentAccess(t *testing.T) {
	manager := newSlotManager(anthropicProvider(), openAIProvider())

	const numGoroutines = 10
	done := make(chan bool, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()
			slotName := "primary"
			if id%2 == 0 {
				slotName = "fast"
			}
			_, err := manager.ResolveSlot(context.Background(), agent.SlotDefinition{Name: slotName}, nil)
			assert.NoError(t, err)
		}(i)
	}
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

func TestDaemonSlotManager_ApplySlotNameDefaults_UnknownSlot(t *testing.T) {
	manager := newSlotManager(anthropicProvider())

	picked, err := manager.ResolveSlot(context.Background(), agent.SlotDefinition{Name: "unknown-slot"}, nil)
	require.NoError(t, err)
	assert.Equal(t, "anthropic", picked.Provider)
	assert.Equal(t, "claude-3-5-sonnet-20241022", picked.Model, "the saved default model")
}

func TestApplySlotNameDefaults_OnlyConstraints(t *testing.T) {
	mgr := newSlotManager()

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
			// The slot has no constraints, so the defaults apply.
			slot := agent.SlotDefinition{
				Name:        tt.slotName,
				Description: "test",
				Required:    true,
				Default:     agent.SlotConfig{Temperature: 0.7, MaxTokens: 4096},
			}

			result := mgr.applySlotNameDefaults(slot)

			assert.Equal(t, "", result.Default.Provider, "Provider should remain empty")
			assert.Equal(t, "", result.Default.Model, "Model should remain empty")
			assert.Equal(t, tt.expectedMinContext, result.Constraints.MinContextWindow)
		})
	}
}

func TestApplySlotNameDefaults_UnknownSlot(t *testing.T) {
	mgr := newSlotManager()

	result := mgr.applySlotNameDefaults(agent.NewSlotDefinition("unknown-slot-name", "test", true))

	assert.Equal(t, "", result.Default.Provider, "Provider should remain empty")
	assert.Equal(t, "", result.Default.Model, "Model should remain empty")
	assert.Equal(t, 8192, result.Constraints.MinContextWindow, "Should keep NewSlotDefinition default")
}

func TestApplySlotNameDefaults_ExplicitConfigPreserved(t *testing.T) {
	mgr := newSlotManager()
	slot := agent.NewSlotDefinition("primary", "test", true).WithDefault(agent.SlotConfig{
		Provider: "openai", Model: "gpt-4", Temperature: 0.8, MaxTokens: 2048,
	})

	result := mgr.applySlotNameDefaults(slot)

	assert.Equal(t, "openai", result.Default.Provider, "Explicit provider should be preserved")
	assert.Equal(t, "gpt-4", result.Default.Model, "Explicit model should be preserved")
	assert.Equal(t, 0.8, result.Default.Temperature)
	assert.Equal(t, 2048, result.Default.MaxTokens)
}

func TestResolveByConstraints_NoPreferenceOrder(t *testing.T) {
	// The records come in a fixed order that is not alphabetical.
	mgr := newSlotManager(
		SlotProvider{Name: "zebra", DefaultModel: "zebra-model-1", ContextWindow: 100000},
		SlotProvider{Name: "alpha", DefaultModel: "alpha-model-1", ContextWindow: 100000},
	)

	picked, err := mgr.ResolveSlot(context.Background(), agent.NewSlotDefinition("test", "test slot", true), nil)
	require.NoError(t, err)
	// With no explicit or default provider, the fallback scan is sorted. It
	// never depends on a hardcoded preference or on map order (gibson#531).
	assert.Equal(t, "alpha", picked.Provider)
	assert.Equal(t, "alpha-model-1", picked.Model)
}

// A pin names one provider. When the pinned provider cannot serve the slot,
// the pin fails and never falls back to another provider (gibson#1203).
func TestResolveSlot_APinNeverFallsBack(t *testing.T) {
	mgr := newSlotManager(anthropicProvider(), SlotProvider{Name: "nomodel"})
	slot := agent.NewSlotDefinition("primary", "primary", true)

	_, err := mgr.ResolveSlot(context.Background(), slot, &agent.SlotConfig{Provider: "nomodel"})
	require.Error(t, err)
	assert.ErrorContains(t, err, "no saved default model")

	_, err = mgr.ResolveSlot(context.Background(), slot, &agent.SlotConfig{Provider: "ghost"})
	require.Error(t, err)
	assert.ErrorContains(t, err, "not found")

	picked, err := mgr.ResolveSlot(context.Background(), slot, &agent.SlotConfig{Provider: "anthropic"})
	require.NoError(t, err)
	assert.Equal(t, "claude-3-5-sonnet-20241022", picked.Model, "a pin with no model takes the saved default")
}

func TestSlotProvidersFromRecords(t *testing.T) {
	recs := []*providerconfig.ProviderConfig{
		{Name: "chat", DefaultModel: "m1", DefaultModelContextWindow: 64000, Enabled: true},
		{Name: "default-chat", DefaultModel: "m2", Enabled: true, IsDefault: true,
			Capabilities: []string{providerconfig.CapabilityChat}},
		{Name: "off", DefaultModel: "m3", Enabled: false},
		{Name: "embed-only", DefaultModel: "m4", Enabled: true,
			Capabilities: []string{providerconfig.CapabilityEmbedding}},
		nil,
	}

	got, defaultName := SlotProvidersFromRecords(recs)

	assert.Equal(t, []SlotProvider{
		{Name: "chat", DefaultModel: "m1", ContextWindow: 64000},
		{Name: "default-chat", DefaultModel: "m2"},
	}, got, "a disabled record and an embedding only record are left out")
	assert.Equal(t, "default-chat", defaultName)
}
