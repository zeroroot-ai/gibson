package eval

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdkeval "github.com/zeroroot-ai/sdk/eval"
)

func TestLoadEvalConfig_Success(t *testing.T) {
	// Create temporary YAML config
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
    options:
      match_by_severity: true
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
	configPath := filepath.Join(tmpDir, "eval_config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(yaml), 0644))

	// Load config
	config, err := LoadEvalConfig(configPath)
	require.NoError(t, err)
	require.NotNil(t, config)

	// Verify scorers
	assert.Len(t, config.Scorers, 3)

	// Tool correctness scorer
	assert.Equal(t, "tool_correctness", config.Scorers[0].Name)
	assert.True(t, config.Scorers[0].Enabled)
	assert.Equal(t, true, config.Scorers[0].Options["order_matters"])
	assert.InDelta(t, 0.001, config.Scorers[0].Options["numeric_tolerance"], 0.0001)

	// Trajectory scorer
	assert.Equal(t, "trajectory", config.Scorers[1].Name)
	assert.True(t, config.Scorers[1].Enabled)
	assert.Equal(t, "ordered_subset", config.Scorers[1].Options["mode"])
	assert.InDelta(t, 0.05, config.Scorers[1].Options["penalize_extra"], 0.0001)

	// Finding accuracy scorer (disabled)
	assert.Equal(t, "finding_accuracy", config.Scorers[2].Name)
	assert.False(t, config.Scorers[2].Enabled)

	// Verify thresholds
	assert.InDelta(t, 0.6, config.Thresholds.Warning, 0.0001)
	assert.InDelta(t, 0.3, config.Thresholds.Critical, 0.0001)

	// Verify export
	assert.True(t, config.Export.Langfuse)
	assert.False(t, config.Export.OTel)
	assert.Equal(t, "./results.jsonl", config.Export.JSONL)

	// Verify paths
	assert.Equal(t, "./testdata/ground_truth.json", config.GroundTruth)
	assert.Equal(t, "./testdata/expected_tools.json", config.ExpectedTools)
}

func TestLoadEvalConfig_FileNotFound(t *testing.T) {
	config, err := LoadEvalConfig("/nonexistent/path/config.yaml")
	assert.Error(t, err)
	assert.Nil(t, config)
	assert.Contains(t, err.Error(), "CONFIG_NOT_FOUND")
}

func TestLoadEvalConfig_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("invalid: yaml: content: ["), 0644))

	config, err := LoadEvalConfig(configPath)
	assert.Error(t, err)
	assert.Nil(t, config)
	assert.Contains(t, err.Error(), "CONFIG_PARSE_FAILED")
}

func TestLoadEvalConfig_ValidationFails(t *testing.T) {
	testCases := []struct {
		name   string
		yaml   string
		errMsg string
	}{
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
			errMsg: "ground_truth path is required",
		},
		{
			name: "invalid warning threshold",
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
			errMsg: "warning threshold must be between 0.0 and 1.0",
		},
		{
			name: "critical > warning",
			yaml: `
scorers:
  - name: tool_correctness
    enabled: true
thresholds:
  warning: 0.3
  critical: 0.5
export:
  langfuse: false
ground_truth: "./ground_truth.json"
`,
			errMsg: "critical threshold",
		},
		{
			name: "invalid scorer name",
			yaml: `
scorers:
  - name: invalid_scorer
    enabled: true
thresholds:
  warning: 0.5
  critical: 0.2
export:
  langfuse: false
ground_truth: "./ground_truth.json"
`,
			errMsg: "invalid scorer name",
		},
		{
			name: "scorer missing name",
			yaml: `
scorers:
  - enabled: true
thresholds:
  warning: 0.5
  critical: 0.2
export:
  langfuse: false
ground_truth: "./ground_truth.json"
`,
			errMsg: "scorer at index 0 is missing name",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.yaml")
			require.NoError(t, os.WriteFile(configPath, []byte(tc.yaml), 0644))

			config, err := LoadEvalConfig(configPath)
			assert.Error(t, err)
			assert.Nil(t, config)
			assert.Contains(t, err.Error(), tc.errMsg)
		})
	}
}

func TestEvalConfig_ToOptions(t *testing.T) {
	config := &EvalConfig{
		Scorers: []ScorerConfig{
			{Name: "tool_correctness", Enabled: true},
			{Name: "trajectory", Enabled: true},
			{Name: "finding_accuracy", Enabled: false},
		},
		Thresholds: ThresholdsConfig{
			Warning:  0.6,
			Critical: 0.3,
		},
		Export: ExportConfig{
			Langfuse: true,
			OTel:     false,
			JSONL:    "./results.jsonl",
		},
		GroundTruth:   "./ground_truth.json",
		ExpectedTools: "./expected_tools.json",
	}

	opts := config.ToOptions()
	require.NotNil(t, opts)

	// Verify basic options
	assert.True(t, opts.Enabled)
	assert.Equal(t, "./ground_truth.json", opts.GroundTruthPath)
	assert.Equal(t, "./expected_tools.json", opts.ExpectedToolsPath)

	// Verify thresholds
	assert.InDelta(t, 0.6, opts.WarningThreshold, 0.0001)
	assert.InDelta(t, 0.3, opts.CriticalThreshold, 0.0001)

	// Verify export options
	assert.True(t, opts.ExportLangfuse)
	assert.False(t, opts.ExportOTel)
	assert.Equal(t, "./results.jsonl", opts.OutputPath)

	// Verify scorers (only enabled ones)
	assert.Len(t, opts.Scorers, 2)
	assert.Contains(t, opts.Scorers, "tool_correctness")
	assert.Contains(t, opts.Scorers, "trajectory")
	assert.NotContains(t, opts.Scorers, "finding_accuracy")
}

func TestEvalConfig_ToOptions_DefaultThresholds(t *testing.T) {
	config := &EvalConfig{
		Scorers: []ScorerConfig{
			{Name: "tool_correctness", Enabled: true},
		},
		Thresholds: ThresholdsConfig{
			Warning:  0.0, // Not set
			Critical: 0.0, // Not set
		},
		Export: ExportConfig{
			Langfuse: false,
			OTel:     false,
		},
		GroundTruth: "./ground_truth.json",
	}

	opts := config.ToOptions()
	require.NotNil(t, opts)

	// Should use defaults from NewEvalOptions
	assert.InDelta(t, 0.5, opts.WarningThreshold, 0.0001)
	assert.InDelta(t, 0.2, opts.CriticalThreshold, 0.0001)
}

func TestEvalConfig_BuildScorers(t *testing.T) {
	config := &EvalConfig{
		Scorers: []ScorerConfig{
			{
				Name:    "tool_correctness",
				Enabled: true,
				Options: map[string]any{
					"order_matters":     true,
					"numeric_tolerance": 0.001,
				},
			},
			{
				Name:    "trajectory",
				Enabled: true,
				Options: map[string]any{
					"mode":           "exact_match",
					"penalize_extra": 0.05,
				},
			},
			{
				Name:    "finding_accuracy",
				Enabled: false, // This should be skipped
				Options: map[string]any{
					"match_by_severity": true,
				},
			},
		},
		Thresholds: ThresholdsConfig{
			Warning:  0.5,
			Critical: 0.2,
		},
		Export: ExportConfig{
			Langfuse: false,
			OTel:     false,
		},
		GroundTruth: "./ground_truth.json",
	}

	scorers, err := config.BuildScorers()
	require.NoError(t, err)
	require.Len(t, scorers, 2) // Only enabled scorers

	// Verify scorer types
	assert.Equal(t, "tool_correctness", scorers[0].Name())
	assert.Equal(t, "trajectory", scorers[1].Name())

	// Verify they support streaming
	assert.True(t, scorers[0].SupportsStreaming())
	assert.True(t, scorers[1].SupportsStreaming())
}

func TestEvalConfig_BuildScorers_AllTypes(t *testing.T) {
	testCases := []struct {
		name        string
		scorerName  string
		options     map[string]any
		expectError bool
		errorMsg    string
	}{
		{
			name:       "tool_correctness with valid options",
			scorerName: "tool_correctness",
			options: map[string]any{
				"order_matters":     true,
				"numeric_tolerance": 0.001,
			},
			expectError: false,
		},
		{
			name:       "tool_correctness with invalid order_matters type",
			scorerName: "tool_correctness",
			options: map[string]any{
				"order_matters": "invalid",
			},
			expectError: true,
			errorMsg:    "must be boolean",
		},
		{
			name:       "trajectory with valid mode",
			scorerName: "trajectory",
			options: map[string]any{
				"mode":           "subset_match",
				"penalize_extra": 0.1,
			},
			expectError: false,
		},
		{
			name:       "trajectory with invalid mode",
			scorerName: "trajectory",
			options: map[string]any{
				"mode": "invalid_mode",
			},
			expectError: true,
			errorMsg:    "invalid trajectory mode",
		},
		{
			name:       "finding_accuracy with valid options",
			scorerName: "finding_accuracy",
			options: map[string]any{
				"match_by_severity":     true,
				"match_by_category":     false,
				"fuzzy_title_threshold": 0.85,
			},
			expectError: false,
		},
		{
			name:       "finding_accuracy with invalid fuzzy_title_threshold type",
			scorerName: "finding_accuracy",
			options: map[string]any{
				"fuzzy_title_threshold": "invalid",
			},
			expectError: true,
			errorMsg:    "must be number",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &EvalConfig{
				Scorers: []ScorerConfig{
					{
						Name:    tc.scorerName,
						Enabled: true,
						Options: tc.options,
					},
				},
				Thresholds: ThresholdsConfig{
					Warning:  0.5,
					Critical: 0.2,
				},
				Export: ExportConfig{
					Langfuse: false,
					OTel:     false,
				},
				GroundTruth: "./ground_truth.json",
			}

			scorers, err := config.BuildScorers()

			if tc.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
			} else {
				require.NoError(t, err)
				require.Len(t, scorers, 1)
				assert.Equal(t, tc.scorerName, scorers[0].Name())
			}
		})
	}
}

func TestEvalConfig_BuildScorers_TrajectoryModes(t *testing.T) {
	testCases := []struct {
		mode         string
		expectedMode sdkeval.TrajectoryMode
	}{
		{"exact_match", sdkeval.TrajectoryExactMatch},
		{"subset_match", sdkeval.TrajectorySubsetMatch},
		{"ordered_subset", sdkeval.TrajectoryOrderedSubset},
	}

	for _, tc := range testCases {
		t.Run(tc.mode, func(t *testing.T) {
			config := &EvalConfig{
				Scorers: []ScorerConfig{
					{
						Name:    "trajectory",
						Enabled: true,
						Options: map[string]any{
							"mode": tc.mode,
						},
					},
				},
				Thresholds: ThresholdsConfig{
					Warning:  0.5,
					Critical: 0.2,
				},
				Export: ExportConfig{
					Langfuse: false,
					OTel:     false,
				},
				GroundTruth: "./ground_truth.json",
			}

			scorers, err := config.BuildScorers()
			require.NoError(t, err)
			require.Len(t, scorers, 1)

			// The scorer should be created successfully with the correct mode
			// We can't directly inspect the mode, but we can verify the scorer was created
			assert.Equal(t, "trajectory", scorers[0].Name())
		})
	}
}

func TestEvalConfig_BuildScorers_NumericTypeConversion(t *testing.T) {
	// Test that both int and float64 work for numeric options
	config := &EvalConfig{
		Scorers: []ScorerConfig{
			{
				Name:    "tool_correctness",
				Enabled: true,
				Options: map[string]any{
					"numeric_tolerance": 1, // int instead of float64
				},
			},
			{
				Name:    "trajectory",
				Enabled: true,
				Options: map[string]any{
					"penalize_extra": 5, // int instead of float64
				},
			},
		},
		Thresholds: ThresholdsConfig{
			Warning:  0.5,
			Critical: 0.2,
		},
		Export: ExportConfig{
			Langfuse: false,
			OTel:     false,
		},
		GroundTruth: "./ground_truth.json",
	}

	scorers, err := config.BuildScorers()
	require.NoError(t, err)
	require.Len(t, scorers, 2)
}

func TestEvalConfig_BuildScorers_EmptyOptions(t *testing.T) {
	// Test that scorers can be created with no options (using defaults)
	config := &EvalConfig{
		Scorers: []ScorerConfig{
			{
				Name:    "tool_correctness",
				Enabled: true,
				// No options - should use defaults
			},
			{
				Name:    "finding_accuracy",
				Enabled: true,
				// No options - should use defaults
			},
		},
		Thresholds: ThresholdsConfig{
			Warning:  0.5,
			Critical: 0.2,
		},
		Export: ExportConfig{
			Langfuse: false,
			OTel:     false,
		},
		GroundTruth: "./ground_truth.json",
	}

	scorers, err := config.BuildScorers()
	require.NoError(t, err)
	require.Len(t, scorers, 2)
}

func TestEvalConfig_Validate_EdgeCases(t *testing.T) {
	testCases := []struct {
		name    string
		config  EvalConfig
		wantErr bool
	}{
		{
			name: "valid config with all fields",
			config: EvalConfig{
				Scorers: []ScorerConfig{
					{Name: "tool_correctness", Enabled: true},
				},
				Thresholds: ThresholdsConfig{
					Warning:  0.5,
					Critical: 0.2,
				},
				Export: ExportConfig{
					Langfuse: true,
				},
				GroundTruth:   "./ground_truth.json",
				ExpectedTools: "./expected_tools.json",
			},
			wantErr: false,
		},
		{
			name: "valid config with threshold = 0",
			config: EvalConfig{
				Scorers: []ScorerConfig{
					{Name: "tool_correctness", Enabled: true},
				},
				Thresholds: ThresholdsConfig{
					Warning:  0.0,
					Critical: 0.0,
				},
				Export: ExportConfig{
					Langfuse: false,
				},
				GroundTruth: "./ground_truth.json",
			},
			wantErr: false,
		},
		{
			name: "valid config with threshold = 1",
			config: EvalConfig{
				Scorers: []ScorerConfig{
					{Name: "tool_correctness", Enabled: true},
				},
				Thresholds: ThresholdsConfig{
					Warning:  1.0,
					Critical: 1.0,
				},
				Export: ExportConfig{
					Langfuse: false,
				},
				GroundTruth: "./ground_truth.json",
			},
			wantErr: false,
		},
		{
			name: "empty scorers list",
			config: EvalConfig{
				Scorers: []ScorerConfig{},
				Thresholds: ThresholdsConfig{
					Warning:  0.5,
					Critical: 0.2,
				},
				Export: ExportConfig{
					Langfuse: false,
				},
				GroundTruth: "./ground_truth.json",
			},
			wantErr: false, // Empty scorers is valid
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
