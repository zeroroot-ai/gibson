package agent

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// mockAgent implements Agent for testing
type mockAgent struct {
	name           string
	version        string
	description    string
	capabilities   []string
	targetTypes    []types.TargetType
	techniqueTypes []types.TechniqueType
	slots          []SlotDefinition
	initialized    bool
	shutdownCalled bool
	executeFunc    func(ctx context.Context, task Task, harness AgentHarness) (Result, error)
}

func newMockAgent(name string) *mockAgent {
	return &mockAgent{
		name:           name,
		version:        "1.0.0",
		description:    "Mock agent for testing",
		capabilities:   []string{"test"},
		targetTypes:    []types.TargetType{types.TargetTypeLLMChat},
		techniqueTypes: []types.TechniqueType{types.TechniqueReconnaissance},
		slots: []SlotDefinition{
			NewSlotDefinition("main", "Main LLM slot", true),
		},
	}
}

func (m *mockAgent) Name() string                          { return m.name }
func (m *mockAgent) Version() string                       { return m.version }
func (m *mockAgent) Description() string                   { return m.description }
func (m *mockAgent) Capabilities() []string                { return m.capabilities }
func (m *mockAgent) TargetTypes() []types.TargetType       { return m.targetTypes }
func (m *mockAgent) TechniqueTypes() []types.TechniqueType { return m.techniqueTypes }
func (m *mockAgent) LLMSlots() []SlotDefinition            { return m.slots }

func (m *mockAgent) Execute(ctx context.Context, task Task, harness AgentHarness) (Result, error) {
	if m.executeFunc != nil {
		return m.executeFunc(ctx, task, harness)
	}
	result := NewResult(task.ID)
	result.Complete(map[string]any{"status": "success"})
	return result, nil
}

func (m *mockAgent) Initialize(ctx context.Context, cfg AgentConfig) error {
	m.initialized = true
	return nil
}

func (m *mockAgent) Shutdown(ctx context.Context) error {
	m.shutdownCalled = true
	return nil
}

func (m *mockAgent) Health(ctx context.Context) types.HealthStatus {
	return types.Healthy("Mock agent is healthy")
}

// TestSlotDefinition tests slot definition creation and manipulation
func TestSlotDefinition(t *testing.T) {
	t.Run("NewSlotDefinition", func(t *testing.T) {
		slot := NewSlotDefinition("test", "Test slot", true)
		assert.Equal(t, "test", slot.Name)
		assert.Equal(t, "Test slot", slot.Description)
		assert.True(t, slot.Required)
		// Provider and Model are empty by default (resolved at runtime by SlotManager)
		assert.Equal(t, "", slot.Default.Provider)
		assert.Equal(t, "", slot.Default.Model)
		assert.Equal(t, 0.7, slot.Default.Temperature)
		assert.Equal(t, 4096, slot.Default.MaxTokens)
		assert.Equal(t, 8192, slot.Constraints.MinContextWindow)
	})

	t.Run("WithDefault", func(t *testing.T) {
		slot := NewSlotDefinition("test", "Test slot", true).
			WithDefault(SlotConfig{
				Provider:    "openai",
				Model:       "gpt-4",
				Temperature: 0.5,
				MaxTokens:   2048,
			})
		assert.Equal(t, "openai", slot.Default.Provider)
		assert.Equal(t, "gpt-4", slot.Default.Model)
		assert.Equal(t, 0.5, slot.Default.Temperature)
		assert.Equal(t, 2048, slot.Default.MaxTokens)
	})

	t.Run("WithConstraints", func(t *testing.T) {
		slot := NewSlotDefinition("test", "Test slot", true).
			WithConstraints(SlotConstraints{
				MinContextWindow: 32000,
				RequiredFeatures: []string{FeatureToolUse, FeatureVision},
			})
		assert.Equal(t, 32000, slot.Constraints.MinContextWindow)
		assert.Contains(t, slot.Constraints.RequiredFeatures, FeatureToolUse)
		assert.Contains(t, slot.Constraints.RequiredFeatures, FeatureVision)
	})

	t.Run("MergeConfig", func(t *testing.T) {
		// Create a slot with explicit defaults set
		slot := NewSlotDefinition("test", "Test slot", true).
			WithDefault(SlotConfig{
				Provider:    "anthropic",
				Model:       "claude-3-sonnet-20240229",
				Temperature: 0.7,
				MaxTokens:   4096,
			})

		// Test with nil override (should return default)
		merged := slot.MergeConfig(nil)
		assert.Equal(t, slot.Default, merged)

		// Test with partial override
		override := &SlotConfig{
			Model: "gpt-4-turbo",
		}
		merged = slot.MergeConfig(override)
		assert.Equal(t, "anthropic", merged.Provider) // From default
		assert.Equal(t, "gpt-4-turbo", merged.Model)  // From override
	})
}

// TestTask tests task creation and manipulation
func TestTask(t *testing.T) {
	t.Run("NewTask", func(t *testing.T) {
		input := map[string]any{"key": "value"}
		task := NewTask("test-task", "Test description", input)

		assert.NotEmpty(t, task.ID)
		assert.Equal(t, "test-task", task.Name)
		assert.Equal(t, "Test description", task.Description)
		assert.Equal(t, input, task.Input)
		assert.Equal(t, 30*time.Minute, task.Timeout)
		assert.Equal(t, 0, task.Priority)
	})

	t.Run("WithMission", func(t *testing.T) {
		missionID := types.NewID()
		task := NewTask("test", "test", nil).WithMission(missionID)
		require.NotNil(t, task.MissionID)
		assert.Equal(t, missionID, *task.MissionID)
	})

	t.Run("WithParent", func(t *testing.T) {
		parentID := types.NewID()
		task := NewTask("test", "test", nil).WithParent(parentID)
		require.NotNil(t, task.ParentTaskID)
		assert.Equal(t, parentID, *task.ParentTaskID)
	})

	t.Run("WithTarget", func(t *testing.T) {
		targetID := types.NewID()
		task := NewTask("test", "test", nil).WithTarget(targetID)
		require.NotNil(t, task.TargetID)
		assert.Equal(t, targetID, *task.TargetID)
	})

	t.Run("WithTimeout", func(t *testing.T) {
		task := NewTask("test", "test", nil).WithTimeout(1 * time.Hour)
		assert.Equal(t, 1*time.Hour, task.Timeout)
	})

	t.Run("WithPriority", func(t *testing.T) {
		task := NewTask("test", "test", nil).WithPriority(10)
		assert.Equal(t, 10, task.Priority)
	})

	t.Run("WithTags", func(t *testing.T) {
		task := NewTask("test", "test", nil).WithTags("tag1", "tag2")
		assert.Equal(t, []string{"tag1", "tag2"}, task.Tags)
	})
}

// TestResult tests result creation and state transitions
func TestResult(t *testing.T) {
	taskID := types.NewID()

	t.Run("NewResult", func(t *testing.T) {
		result := NewResult(taskID)
		assert.Equal(t, taskID, result.TaskID)
		assert.Equal(t, ResultStatusPending, result.Status)
		assert.Empty(t, result.Findings)
		assert.Nil(t, result.Error)
	})

	t.Run("Start", func(t *testing.T) {
		result := NewResult(taskID)
		result.Start()
		assert.Equal(t, ResultStatusRunning, result.Status)
		assert.False(t, result.StartedAt.IsZero())
	})

	t.Run("Complete", func(t *testing.T) {
		result := NewResult(taskID)
		result.Start()
		time.Sleep(10 * time.Millisecond)

		output := map[string]any{"key": "value"}
		result.Complete(output)

		assert.Equal(t, ResultStatusCompleted, result.Status)
		assert.Equal(t, output, result.Output)
		assert.False(t, result.CompletedAt.IsZero())
		assert.Greater(t, result.Metrics.Duration, time.Duration(0))
	})

	t.Run("Fail", func(t *testing.T) {
		result := NewResult(taskID)
		result.Start()

		err := assert.AnError
		result.Fail(err)

		assert.Equal(t, ResultStatusFailed, result.Status)
		require.NotNil(t, result.Error)
		assert.Equal(t, err.Error(), result.Error.Message)
		assert.False(t, result.CompletedAt.IsZero())
	})

	t.Run("Cancel", func(t *testing.T) {
		result := NewResult(taskID)
		result.Start()
		result.Cancel()

		assert.Equal(t, ResultStatusCancelled, result.Status)
		assert.False(t, result.CompletedAt.IsZero())
	})

	t.Run("AddFinding", func(t *testing.T) {
		result := NewResult(taskID)
		finding := NewFinding("Test", "Test finding", SeverityHigh)

		result.AddFinding(finding)

		assert.Len(t, result.Findings, 1)
		assert.Equal(t, finding, result.Findings[0])
	})
}

// TestFinding tests finding creation and manipulation
func TestFinding(t *testing.T) {
	t.Run("NewFinding", func(t *testing.T) {
		finding := NewFinding("XSS Vulnerability", "Cross-site scripting found", SeverityHigh)

		assert.NotEmpty(t, finding.ID)
		assert.Equal(t, "XSS Vulnerability", finding.Title)
		assert.Equal(t, "Cross-site scripting found", finding.Description)
		assert.Equal(t, SeverityHigh, finding.Severity)
		assert.Equal(t, 1.0, finding.Confidence)
		assert.Empty(t, finding.Evidence)
	})

	t.Run("WithConfidence", func(t *testing.T) {
		finding := NewFinding("Test", "Test", SeverityLow).WithConfidence(0.7)
		assert.Equal(t, 0.7, finding.Confidence)
	})

	t.Run("WithCategory", func(t *testing.T) {
		finding := NewFinding("Test", "Test", SeverityLow).WithCategory("injection")
		assert.Equal(t, "injection", finding.Category)
	})

	t.Run("WithEvidence", func(t *testing.T) {
		evidence := NewEvidence("http-response", "Response contained script tag", map[string]any{
			"status": 200,
		})
		finding := NewFinding("Test", "Test", SeverityLow).WithEvidence(evidence)

		assert.Len(t, finding.Evidence, 1)
		assert.Equal(t, evidence, finding.Evidence[0])
	})

	t.Run("WithCWE", func(t *testing.T) {
		finding := NewFinding("Test", "Test", SeverityLow).WithCWE("CWE-79", "CWE-80")
		assert.Equal(t, []string{"CWE-79", "CWE-80"}, finding.CWE)
	})

	t.Run("WithTarget", func(t *testing.T) {
		targetID := types.NewID()
		finding := NewFinding("Test", "Test", SeverityLow).WithTarget(targetID)
		require.NotNil(t, finding.TargetID)
		assert.Equal(t, targetID, *finding.TargetID)
	})
}

// TestAgentConfig tests agent configuration
func TestAgentConfig(t *testing.T) {
	t.Run("NewAgentConfig", func(t *testing.T) {
		cfg := NewAgentConfig("test-agent")
		assert.Equal(t, "test-agent", cfg.Name)
		assert.NotNil(t, cfg.Settings)
		assert.NotNil(t, cfg.SlotOverrides)
		assert.Equal(t, 30*time.Minute, cfg.Timeout)
	})

	t.Run("WithSetting", func(t *testing.T) {
		cfg := NewAgentConfig("test").WithSetting("key", "value")
		assert.Equal(t, "value", cfg.Settings["key"])
	})

	t.Run("WithSlotOverride", func(t *testing.T) {
		slotCfg := SlotConfig{Provider: "openai", Model: "gpt-4"}
		cfg := NewAgentConfig("test").WithSlotOverride("main", slotCfg)
		assert.Equal(t, slotCfg, cfg.SlotOverrides["main"])
	})

	t.Run("WithTimeout", func(t *testing.T) {
		cfg := NewAgentConfig("test").WithTimeout(1 * time.Hour)
		assert.Equal(t, 1*time.Hour, cfg.Timeout)
	})

	t.Run("GetSetting", func(t *testing.T) {
		cfg := NewAgentConfig("test").WithSetting("key", "value")
		assert.Equal(t, "value", cfg.GetSetting("key", "default"))
		assert.Equal(t, "default", cfg.GetSetting("missing", "default"))
	})

	t.Run("GetStringSetting", func(t *testing.T) {
		cfg := NewAgentConfig("test").WithSetting("str", "text")
		assert.Equal(t, "text", cfg.GetStringSetting("str", "default"))
		assert.Equal(t, "default", cfg.GetStringSetting("missing", "default"))
	})

	t.Run("GetIntSetting", func(t *testing.T) {
		cfg := NewAgentConfig("test").
			WithSetting("int", 42).
			WithSetting("int64", int64(100)).
			WithSetting("float", 3.14)

		assert.Equal(t, 42, cfg.GetIntSetting("int", 0))
		assert.Equal(t, 100, cfg.GetIntSetting("int64", 0))
		assert.Equal(t, 3, cfg.GetIntSetting("float", 0))
		assert.Equal(t, 99, cfg.GetIntSetting("missing", 99))
	})

	t.Run("GetBoolSetting", func(t *testing.T) {
		cfg := NewAgentConfig("test").WithSetting("bool", true)
		assert.True(t, cfg.GetBoolSetting("bool", false))
		assert.False(t, cfg.GetBoolSetting("missing", false))
	})
}

// TestAgentDescriptor tests agent descriptor
func TestAgentDescriptor(t *testing.T) {
	t.Run("NewAgentDescriptor", func(t *testing.T) {
		agent := newMockAgent("test-agent")
		desc := NewAgentDescriptor(agent)

		assert.Equal(t, "test-agent", desc.Name)
		assert.Equal(t, "1.0.0", desc.Version)
		assert.Equal(t, "Mock agent for testing", desc.Description)
		assert.Contains(t, desc.Capabilities, "test")
		assert.False(t, desc.IsExternal)
	})

	t.Run("NewExternalAgentDescriptor", func(t *testing.T) {
		desc := NewExternalAgentDescriptor("external", "2.0.0", "External agent")
		assert.Equal(t, "external", desc.Name)
		assert.Equal(t, "2.0.0", desc.Version)
		assert.True(t, desc.IsExternal)
	})

	t.Run("RequiresSlot", func(t *testing.T) {
		agent := newMockAgent("test")
		desc := NewAgentDescriptor(agent)
		assert.True(t, desc.RequiresSlot("main"))
		assert.False(t, desc.RequiresSlot("nonexistent"))
	})

	t.Run("GetSlot", func(t *testing.T) {
		agent := newMockAgent("test")
		desc := NewAgentDescriptor(agent)

		slot := desc.GetSlot("main")
		require.NotNil(t, slot)
		assert.Equal(t, "main", slot.Name)

		slot = desc.GetSlot("nonexistent")
		assert.Nil(t, slot)
	})
}

// TestAgentRuntime tests agent runtime tracking
func TestAgentRuntime(t *testing.T) {
	taskID := types.NewID()

	t.Run("NewAgentRuntime", func(t *testing.T) {
		runtime := NewAgentRuntime("test-agent", taskID)

		assert.NotEmpty(t, runtime.ID)
		assert.Equal(t, "test-agent", runtime.AgentName)
		assert.Equal(t, taskID, runtime.TaskID)
		assert.Equal(t, "running", runtime.Status)
		assert.False(t, runtime.StartedAt.IsZero())
	})

	t.Run("Complete", func(t *testing.T) {
		runtime := NewAgentRuntime("test-agent", taskID)
		runtime.Complete()
		assert.Equal(t, "completed", runtime.Status)
	})

	t.Run("Fail", func(t *testing.T) {
		runtime := NewAgentRuntime("test-agent", taskID)
		runtime.Fail()
		assert.Equal(t, "failed", runtime.Status)
	})

	t.Run("Cancel", func(t *testing.T) {
		runtime := NewAgentRuntime("test-agent", taskID)
		runtime.Cancel()
		assert.Equal(t, "cancelled", runtime.Status)
	})

	t.Run("Duration", func(t *testing.T) {
		runtime := NewAgentRuntime("test-agent", taskID)
		time.Sleep(10 * time.Millisecond)
		duration := runtime.Duration()
		assert.Greater(t, duration, time.Duration(0))
	})
}

// TestSlotValidate tests slot validation (currently a no-op)
func TestSlotValidate(t *testing.T) {
	slot := NewSlotDefinition("test", "Test slot", true)
	cfg := SlotConfig{Provider: "openai", Model: "gpt-4"}
	err := slot.Validate(cfg)
	assert.NoError(t, err)
}

// TestNewEvidence tests evidence creation
func TestNewEvidence(t *testing.T) {
	data := map[string]any{"key": "value"}
	evidence := NewEvidence("test-type", "Test description", data)
	assert.Equal(t, "test-type", evidence.Type)
	assert.Equal(t, "Test description", evidence.Description)
	assert.Equal(t, data, evidence.Data)
	assert.False(t, evidence.Timestamp.IsZero())
}

// TestSlotMergeConfig_AllFields tests all merge paths
func TestSlotMergeConfig_AllFields(t *testing.T) {
	slot := NewSlotDefinition("test", "Test", true).
		WithDefault(SlotConfig{
			Provider:    "anthropic",
			Model:       "claude",
			Temperature: 0.7,
			MaxTokens:   1000,
		})

	t.Run("FullOverride", func(t *testing.T) {
		override := &SlotConfig{
			Provider:    "openai",
			Model:       "gpt-4",
			Temperature: 0.5,
			MaxTokens:   2000,
		}
		merged := slot.MergeConfig(override)
		assert.Equal(t, "openai", merged.Provider)
		assert.Equal(t, "gpt-4", merged.Model)
		assert.Equal(t, 0.5, merged.Temperature)
		assert.Equal(t, 2000, merged.MaxTokens)
	})

	t.Run("PartialOverride_Model", func(t *testing.T) {
		override := &SlotConfig{
			Model: "gpt-4",
		}
		merged := slot.MergeConfig(override)
		assert.Equal(t, "anthropic", merged.Provider)
		assert.Equal(t, "gpt-4", merged.Model)
		assert.Equal(t, 0.7, merged.Temperature)
		assert.Equal(t, 1000, merged.MaxTokens)
	})
}
