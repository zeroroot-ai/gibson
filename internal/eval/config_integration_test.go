package eval

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfigIntegration_FullMission tests the complete mission:
// 1. Load YAML config from file
// 2. Validate configuration
// 3. Convert to EvalOptions
// 4. Build scorer instances
func TestConfigIntegration_FullMission(t *testing.T) {
	// Create a temporary config file
	yaml := `
scorers:
  - name: tool_correctness
    enabled: true
    options:
      order_matters: true
      numeric_tolerance: 0.001
  - name: trajectory
    enabled: true
    options:
      mode: ordered_subset
      penalize_extra: 0.05
  - name: finding_accuracy
    enabled: false
thresholds:
  warning: 0.6
  critical: 0.3
export:
  langfuse: true
  otel: false
  jsonl: "./results.jsonl"
ground_truth: "./testdata/ground_truth.json"
expected_tools: "./testdata/expected_tools.json"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "eval.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(yaml), 0644))

	// Step 1: Load configuration
	config, err := LoadEvalConfig(configPath)
	require.NoError(t, err, "LoadEvalConfig should succeed")
	require.NotNil(t, config)

	// Step 2: Configuration should already be validated
	// Verify key fields
	assert.Len(t, config.Scorers, 3)
	assert.InDelta(t, 0.6, config.Thresholds.Warning, 0.0001)
	assert.InDelta(t, 0.3, config.Thresholds.Critical, 0.0001)
	assert.Equal(t, "./testdata/ground_truth.json", config.GroundTruth)

	// Step 3: Convert to EvalOptions
	opts := config.ToOptions()
	require.NotNil(t, opts)

	assert.True(t, opts.Enabled, "Evaluation should be enabled")
	assert.Equal(t, "./testdata/ground_truth.json", opts.GroundTruthPath)
	assert.Equal(t, "./testdata/expected_tools.json", opts.ExpectedToolsPath)
	assert.InDelta(t, 0.6, opts.WarningThreshold, 0.0001)
	assert.InDelta(t, 0.3, opts.CriticalThreshold, 0.0001)
	assert.True(t, opts.ExportLangfuse)
	assert.False(t, opts.ExportOTel)
	assert.Equal(t, "./results.jsonl", opts.OutputPath)

	// Only enabled scorers should be in the list
	require.Len(t, opts.Scorers, 2)
	assert.Contains(t, opts.Scorers, "tool_correctness")
	assert.Contains(t, opts.Scorers, "trajectory")
	assert.NotContains(t, opts.Scorers, "finding_accuracy")

	// Step 4: Build scorer instances
	scorers, err := config.BuildScorers()
	require.NoError(t, err, "BuildScorers should succeed")
	require.Len(t, scorers, 2, "Should only build enabled scorers")

	// Verify scorer names
	scorerNames := []string{scorers[0].Name(), scorers[1].Name()}
	assert.Contains(t, scorerNames, "tool_correctness")
	assert.Contains(t, scorerNames, "trajectory")

	// Verify scorers support streaming
	for _, scorer := range scorers {
		assert.True(t, scorer.SupportsStreaming(),
			"Scorer %s should support streaming", scorer.Name())
	}
}

// TestConfigIntegration_MinimalConfig tests a minimal valid configuration
func TestConfigIntegration_MinimalConfig(t *testing.T) {
	yaml := `
scorers:
  - name: tool_correctness
    enabled: true
thresholds:
  warning: 0.5
  critical: 0.2
export:
  langfuse: false
  otel: false
ground_truth: "./ground_truth.json"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "eval.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(yaml), 0644))

	// Load and validate
	config, err := LoadEvalConfig(configPath)
	require.NoError(t, err)
	require.NotNil(t, config)

	// Convert to options
	opts := config.ToOptions()
	require.NotNil(t, opts)
	assert.True(t, opts.Enabled)
	assert.Equal(t, "./ground_truth.json", opts.GroundTruthPath)
	assert.Empty(t, opts.ExpectedToolsPath)
	assert.Empty(t, opts.OutputPath) // JSONL export disabled

	// Build scorers
	scorers, err := config.BuildScorers()
	require.NoError(t, err)
	require.Len(t, scorers, 1)
	assert.Equal(t, "tool_correctness", scorers[0].Name())
}

// TestConfigIntegration_AllScorersDisabled tests config with all scorers disabled
func TestConfigIntegration_AllScorersDisabled(t *testing.T) {
	yaml := `
scorers:
  - name: tool_correctness
    enabled: false
  - name: trajectory
    enabled: false
thresholds:
  warning: 0.5
  critical: 0.2
export:
  langfuse: false
ground_truth: "./ground_truth.json"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "eval.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(yaml), 0644))

	config, err := LoadEvalConfig(configPath)
	require.NoError(t, err)

	// ToOptions should return empty scorer list
	opts := config.ToOptions()
	assert.Empty(t, opts.Scorers)

	// BuildScorers should return empty list (no enabled scorers)
	scorers, err := config.BuildScorers()
	require.NoError(t, err)
	assert.Empty(t, scorers)
}

// TestConfigIntegration_RealExample tests loading the example config file
func TestConfigIntegration_RealExample(t *testing.T) {
	// Check if example config exists
	examplePath := "../../testdata/eval_config_example.yaml"
	if _, err := os.Stat(examplePath); os.IsNotExist(err) {
		t.Skip("Example config file not found, skipping test")
	}

	// Load the real example
	config, err := LoadEvalConfig(examplePath)
	require.NoError(t, err, "Should load example config successfully")
	require.NotNil(t, config)

	// Verify it has all three scorers
	assert.Len(t, config.Scorers, 3)

	// Verify scorers can be built
	scorers, err := config.BuildScorers()
	require.NoError(t, err)
	// All three scorers should be enabled in the example
	assert.Len(t, scorers, 3)

	// Verify options conversion works
	opts := config.ToOptions()
	require.NotNil(t, opts)
	assert.True(t, opts.Enabled)
	assert.Len(t, opts.Scorers, 3)
}

// TestConfigIntegration_ErrorHandling tests various error scenarios
func TestConfigIntegration_ErrorHandling(t *testing.T) {
	testCases := []struct {
		name        string
		yaml        string
		expectError string
	}{
		{
			name: "invalid YAML syntax",
			yaml: `
scorers: [invalid yaml syntax
`,
			expectError: "CONFIG_PARSE_FAILED",
		},
		{
			name: "missing ground truth",
			yaml: `
scorers:
  - name: tool_correctness
    enabled: true
thresholds:
  warning: 0.5
  critical: 0.2
export:
  langfuse: false
`,
			expectError: "ground_truth path is required",
		},
		{
			name: "invalid threshold values",
			yaml: `
scorers:
  - name: tool_correctness
    enabled: true
thresholds:
  warning: 1.5
  critical: 0.2
export:
  langfuse: false
ground_truth: "./ground_truth.json"
`,
			expectError: "warning threshold must be between 0.0 and 1.0",
		},
		{
			name: "unknown scorer type",
			yaml: `
scorers:
  - name: unknown_scorer
    enabled: true
thresholds:
  warning: 0.5
  critical: 0.2
export:
  langfuse: false
ground_truth: "./ground_truth.json"
`,
			expectError: "invalid scorer name",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "eval.yaml")
			require.NoError(t, os.WriteFile(configPath, []byte(tc.yaml), 0644))

			config, err := LoadEvalConfig(configPath)
			assert.Error(t, err)
			assert.Nil(t, config)
			assert.Contains(t, err.Error(), tc.expectError)
		})
	}
}
