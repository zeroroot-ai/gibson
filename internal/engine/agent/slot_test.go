package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSlotDefinition_NoHardcodedDefaults(t *testing.T) {
	slot := NewSlotDefinition("test-slot", "A test slot", true)

	// Provider and Model should be empty (resolved at runtime)
	assert.Equal(t, "", slot.Default.Provider, "Provider should be empty")
	assert.Equal(t, "", slot.Default.Model, "Model should be empty")

	// Temperature and MaxTokens should have sensible defaults
	assert.Equal(t, 0.7, slot.Default.Temperature, "Temperature should default to 0.7")
	assert.Equal(t, 4096, slot.Default.MaxTokens, "MaxTokens should default to 4096")

	// Constraints should have minimal defaults
	assert.Equal(t, 8192, slot.Constraints.MinContextWindow, "MinContextWindow should default to 8192")
	assert.Empty(t, slot.Constraints.RequiredFeatures, "RequiredFeatures should be empty")
}

func TestNewSlotDefinition_Properties(t *testing.T) {
	slot := NewSlotDefinition("my-slot", "My description", true)

	assert.Equal(t, "my-slot", slot.Name)
	assert.Equal(t, "My description", slot.Description)
	assert.True(t, slot.Required)
}

func TestSlotDefinition_WithDefault(t *testing.T) {
	slot := NewSlotDefinition("test-slot", "Test slot", false)

	customConfig := SlotConfig{
		Provider:    "anthropic",
		Model:       "claude-3-opus-20240229",
		Temperature: 0.9,
		MaxTokens:   8000,
	}

	slot = slot.WithDefault(customConfig)

	assert.Equal(t, "anthropic", slot.Default.Provider)
	assert.Equal(t, "claude-3-opus-20240229", slot.Default.Model)
	assert.Equal(t, 0.9, slot.Default.Temperature)
	assert.Equal(t, 8000, slot.Default.MaxTokens)
}

func TestSlotDefinition_WithConstraints(t *testing.T) {
	slot := NewSlotDefinition("test-slot", "Test slot", false)

	customConstraints := SlotConstraints{
		MinContextWindow: 100000,
		RequiredFeatures: []string{FeatureToolUse, FeatureVision},
	}

	slot = slot.WithConstraints(customConstraints)

	assert.Equal(t, 100000, slot.Constraints.MinContextWindow)
	assert.Contains(t, slot.Constraints.RequiredFeatures, FeatureToolUse)
	assert.Contains(t, slot.Constraints.RequiredFeatures, FeatureVision)
	assert.Len(t, slot.Constraints.RequiredFeatures, 2)
}

func TestSlotDefinition_MergeConfig_NoOverride(t *testing.T) {
	slot := NewSlotDefinition("test-slot", "Test slot", true)
	slot = slot.WithDefault(SlotConfig{
		Provider:    "anthropic",
		Model:       "claude-3-opus",
		Temperature: 0.8,
		MaxTokens:   5000,
	})

	result := slot.MergeConfig(nil)

	assert.Equal(t, "anthropic", result.Provider)
	assert.Equal(t, "claude-3-opus", result.Model)
	assert.Equal(t, 0.8, result.Temperature)
	assert.Equal(t, 5000, result.MaxTokens)
}

func TestSlotDefinition_MergeConfig_WithOverride(t *testing.T) {
	slot := NewSlotDefinition("test-slot", "Test slot", true)
	slot = slot.WithDefault(SlotConfig{
		Provider:    "anthropic",
		Model:       "claude-3-opus",
		Temperature: 0.8,
		MaxTokens:   5000,
	})

	override := &SlotConfig{
		Model:       "claude-3-sonnet",
		Temperature: 0.5,
	}

	result := slot.MergeConfig(override)

	// Provider should remain from default (not overridden)
	assert.Equal(t, "anthropic", result.Provider)
	// Model and Temperature should be overridden
	assert.Equal(t, "claude-3-sonnet", result.Model)
	assert.Equal(t, 0.5, result.Temperature)
	// MaxTokens should remain from default
	assert.Equal(t, 5000, result.MaxTokens)
}

func TestSlotDefinition_MergeConfig_PartialOverride(t *testing.T) {
	slot := NewSlotDefinition("test-slot", "Test slot", true)
	slot = slot.WithDefault(SlotConfig{
		Provider:    "openai",
		Model:       "gpt-4",
		Temperature: 0.7,
		MaxTokens:   4096,
	})

	override := &SlotConfig{
		Provider: "anthropic",
	}

	result := slot.MergeConfig(override)

	// Only Provider should be overridden
	assert.Equal(t, "anthropic", result.Provider)
	// Everything else should remain from default
	assert.Equal(t, "gpt-4", result.Model)
	assert.Equal(t, 0.7, result.Temperature)
	assert.Equal(t, 4096, result.MaxTokens)
}
