package harness

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// mockClassifier is a mock implementation of CategoryClassifier for testing.
type mockClassifier struct {
	// classifyFunc allows customizing the behavior per test
	classifyFunc func(ctx context.Context, proposed, description string) (string, error)
}

func (m *mockClassifier) Classify(ctx context.Context, proposed, description string) (string, error) {
	if m.classifyFunc != nil {
		return m.classifyFunc(ctx, proposed, description)
	}
	// Default behavior: return proposed category unchanged
	return proposed, nil
}

// TestSubmitFinding_ClassifierDisabled tests that findings are submitted unchanged
// when the classifier is not configured.
func TestSubmitFinding_ClassifierDisabled(t *testing.T) {
	// Create a minimal harness config with no classifier
	config := HarnessConfig{
		SlotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
	}
	config.ApplyDefaults()

	// Create factory
	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	// Create mission context
	missionID := types.NewID()
	missionCtx := MissionContext{
		ID:   missionID,
		Name: "test-mission",
	}

	// Create harness
	harness, err := factory.Create("test-agent", missionCtx, TargetInfo{})
	require.NoError(t, err)

	// Cast to DefaultAgentHarness to access internal state
	defaultHarness, ok := harness.(*DefaultAgentHarness)
	require.True(t, ok)

	// Create a finding with a custom category
	finding := agent.NewFinding("Test Finding", "This is a test finding", agent.SeverityCritical)
	finding.Category = "custom_category"

	// Submit the finding
	err = defaultHarness.SubmitFinding(context.Background(), finding)
	require.NoError(t, err)

	// Retrieve findings
	filter := NewFindingFilter()
	findings, err := defaultHarness.GetFindings(context.Background(), *filter)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	// Verify category was not changed
	assert.Equal(t, "custom_category", findings[0].Category)
	// Verify no metadata was added
	assert.Nil(t, findings[0].Metadata["original_category"])
}

// TestSubmitFinding_ClassifierNormalizes tests that the classifier normalizes
// categories when enabled.
func TestSubmitFinding_ClassifierNormalizes(t *testing.T) {
	// Create a mock classifier that normalizes categories
	mockCls := &mockClassifier{
		classifyFunc: func(ctx context.Context, proposed, description string) (string, error) {
			// Normalize "jailbreaking" to "jailbreak"
			if proposed == "jailbreaking" {
				return "jailbreak", nil
			}
			// Return proposed for other categories
			return proposed, nil
		},
	}

	// Create harness config with classifier enabled
	config := HarnessConfig{
		SlotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
		ClassifierConfig: &ClassifierConfig{
			Enabled:      true,
			Threshold:    0.85,
			AutoRegister: true,
		},
		CategoryClassifier: mockCls,
	}
	config.ApplyDefaults()

	// Create factory
	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	// Create mission context
	missionID := types.NewID()
	missionCtx := MissionContext{
		ID:   missionID,
		Name: "test-mission",
	}

	// Create harness
	harness, err := factory.Create("test-agent", missionCtx, TargetInfo{})
	require.NoError(t, err)

	// Cast to DefaultAgentHarness
	defaultHarness, ok := harness.(*DefaultAgentHarness)
	require.True(t, ok)

	// Create a finding with category "jailbreaking"
	finding := agent.NewFinding("Jailbreak Attempt", "LLM jailbreak vulnerability", agent.SeverityHigh)
	finding.Category = "jailbreaking"

	// Submit the finding
	err = defaultHarness.SubmitFinding(context.Background(), finding)
	require.NoError(t, err)

	// Retrieve findings
	filter := NewFindingFilter()
	findings, err := defaultHarness.GetFindings(context.Background(), *filter)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	// Verify category was normalized to "jailbreak"
	assert.Equal(t, "jailbreak", findings[0].Category)
	// Verify original_category metadata was set
	assert.Equal(t, "jailbreaking", findings[0].Metadata["original_category"])
}

// TestSubmitFinding_ClassifierUnchanged tests that when the classifier returns
// the same category, metadata is still added.
func TestSubmitFinding_ClassifierUnchanged(t *testing.T) {
	// Create a mock classifier that returns categories unchanged
	mockCls := &mockClassifier{
		classifyFunc: func(ctx context.Context, proposed, description string) (string, error) {
			return proposed, nil
		},
	}

	// Create harness config with classifier enabled
	config := HarnessConfig{
		SlotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
		ClassifierConfig: &ClassifierConfig{
			Enabled:      true,
			Threshold:    0.85,
			AutoRegister: true,
		},
		CategoryClassifier: mockCls,
	}
	config.ApplyDefaults()

	// Create factory
	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	// Create mission context
	missionID := types.NewID()
	missionCtx := MissionContext{
		ID:   missionID,
		Name: "test-mission",
	}

	// Create harness
	harness, err := factory.Create("test-agent", missionCtx, TargetInfo{})
	require.NoError(t, err)

	// Cast to DefaultAgentHarness
	defaultHarness, ok := harness.(*DefaultAgentHarness)
	require.True(t, ok)

	// Create a finding
	finding := agent.NewFinding("SQL Injection", "SQL injection found", agent.SeverityCritical)
	finding.Category = "sql_injection"

	// Submit the finding
	err = defaultHarness.SubmitFinding(context.Background(), finding)
	require.NoError(t, err)

	// Retrieve findings
	filter := NewFindingFilter()
	findings, err := defaultHarness.GetFindings(context.Background(), *filter)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	// Verify category was not changed
	assert.Equal(t, "sql_injection", findings[0].Category)
	// Verify original_category metadata was set (even though unchanged)
	assert.Equal(t, "sql_injection", findings[0].Metadata["original_category"])
}

// TestSubmitFinding_ClassifierGracefulDegradation tests that the harness
// gracefully degrades when the classifier returns an error.
func TestSubmitFinding_ClassifierGracefulDegradation(t *testing.T) {
	// Create a mock classifier that always fails
	mockCls := &mockClassifier{
		classifyFunc: func(ctx context.Context, proposed, description string) (string, error) {
			return "", fmt.Errorf("classifier unavailable")
		},
	}

	// Create harness config with classifier enabled
	config := HarnessConfig{
		SlotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
		ClassifierConfig: &ClassifierConfig{
			Enabled:      true,
			Threshold:    0.85,
			AutoRegister: true,
		},
		CategoryClassifier: mockCls,
	}
	config.ApplyDefaults()

	// Create factory
	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	// Create mission context
	missionID := types.NewID()
	missionCtx := MissionContext{
		ID:   missionID,
		Name: "test-mission",
	}

	// Create harness
	harness, err := factory.Create("test-agent", missionCtx, TargetInfo{})
	require.NoError(t, err)

	// Cast to DefaultAgentHarness
	defaultHarness, ok := harness.(*DefaultAgentHarness)
	require.True(t, ok)

	// Create a finding
	finding := agent.NewFinding("XSS Vulnerability", "Cross-site scripting found", agent.SeverityHigh)
	finding.Category = "xss"

	// Submit the finding - should succeed despite classifier error
	err = defaultHarness.SubmitFinding(context.Background(), finding)
	require.NoError(t, err)

	// Retrieve findings
	filter := NewFindingFilter()
	findings, err := defaultHarness.GetFindings(context.Background(), *filter)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	// Verify category was not changed (graceful degradation)
	assert.Equal(t, "xss", findings[0].Category)
	// Verify no metadata was added (classification failed)
	assert.Nil(t, findings[0].Metadata["original_category"])
}

// TestSubmitFinding_ClassifierEnabledButNotProvided tests that the harness
// handles the case where classifier config is enabled but no classifier is provided.
func TestSubmitFinding_ClassifierEnabledButNotProvided(t *testing.T) {
	// Create harness config with classifier enabled but no classifier instance
	config := HarnessConfig{
		SlotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
		ClassifierConfig: &ClassifierConfig{
			Enabled:      true,
			Threshold:    0.85,
			AutoRegister: true,
		},
		CategoryClassifier: nil, // No classifier provided
	}
	config.ApplyDefaults()

	// Create factory
	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	// Create mission context
	missionID := types.NewID()
	missionCtx := MissionContext{
		ID:   missionID,
		Name: "test-mission",
	}

	// Create harness
	harness, err := factory.Create("test-agent", missionCtx, TargetInfo{})
	require.NoError(t, err)

	// Cast to DefaultAgentHarness
	defaultHarness, ok := harness.(*DefaultAgentHarness)
	require.True(t, ok)

	// Create a finding
	finding := agent.NewFinding("CSRF Vulnerability", "Cross-site request forgery found", agent.SeverityMedium)
	finding.Category = "csrf"

	// Submit the finding - should succeed (classifier is nil, so no classification)
	err = defaultHarness.SubmitFinding(context.Background(), finding)
	require.NoError(t, err)

	// Retrieve findings
	filter := NewFindingFilter()
	findings, err := defaultHarness.GetFindings(context.Background(), *filter)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	// Verify category was not changed
	assert.Equal(t, "csrf", findings[0].Category)
	// Verify no metadata was added
	assert.Nil(t, findings[0].Metadata["original_category"])
}

// TestDefaultClassifierConfig tests that the default config has sensible values.
func TestDefaultClassifierConfig(t *testing.T) {
	config := DefaultClassifierConfig()
	require.NotNil(t, config)

	// Verify defaults
	assert.False(t, config.Enabled, "classifier should be disabled by default for backward compatibility")
	assert.Equal(t, 0.85, config.Threshold, "threshold should default to 0.85")
	assert.True(t, config.AutoRegister, "auto-register should default to true")
}

// TestClassifierConfig_ApplyDefaults tests that ApplyDefaults sets classifier config.
func TestClassifierConfig_ApplyDefaults(t *testing.T) {
	config := HarnessConfig{
		SlotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
		// ClassifierConfig not set
	}

	config.ApplyDefaults()

	// Verify default classifier config was applied
	require.NotNil(t, config.ClassifierConfig)
	assert.False(t, config.ClassifierConfig.Enabled)
	assert.Equal(t, 0.85, config.ClassifierConfig.Threshold)
	assert.True(t, config.ClassifierConfig.AutoRegister)
}
