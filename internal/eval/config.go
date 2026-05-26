package eval

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/zeroroot-ai/gibson/internal/types"
	sdkeval "github.com/zeroroot-ai/sdk/eval"
)

// EvalConfig represents the YAML configuration for evaluation settings.
// This structure defines scorers, thresholds, export options, and ground truth paths.
type EvalConfig struct {
	// Scorers is an array of scorer configurations defining which scorers to apply
	// and their specific options.
	Scorers []ScorerConfig `yaml:"scorers" json:"scorers"`

	// Thresholds defines warning and critical score thresholds for evaluation.
	Thresholds ThresholdsConfig `yaml:"thresholds" json:"thresholds"`

	// Export controls where evaluation results are exported.
	Export ExportConfig `yaml:"export" json:"export"`

	// GroundTruth is the path to the ground truth data file containing expected outputs.
	// Required for evaluation. Format: JSON with task_id -> expected_output mappings.
	GroundTruth string `yaml:"ground_truth" json:"ground_truth"`

	// ExpectedTools is the path to expected tool call sequences file.
	// Optional. Format: JSON with task_id -> []ToolCall mappings.
	ExpectedTools string `yaml:"expected_tools" json:"expected_tools"`
}

// ScorerConfig defines configuration for a single scorer.
type ScorerConfig struct {
	// Name identifies the scorer type.
	// Valid values: "tool_correctness", "trajectory", "finding_accuracy"
	Name string `yaml:"name" json:"name"`

	// Enabled controls whether this scorer is active.
	// Disabled scorers are skipped during evaluation.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Options contains scorer-specific configuration as key-value pairs.
	// The structure depends on the scorer type:
	//   - tool_correctness: OrderMatters (bool), NumericTolerance (float64)
	//   - trajectory: Mode (string), PenalizeExtra (float64)
	//   - finding_accuracy: MatchBySeverity (bool), MatchByCategory (bool), FuzzyTitleThreshold (float64)
	Options map[string]any `yaml:"options,omitempty" json:"options,omitempty"`
}

// ThresholdsConfig defines score thresholds for evaluation warnings and failures.
type ThresholdsConfig struct {
	// Warning is the minimum score (0.0 - 1.0) before a warning is issued.
	// Default: 0.5
	Warning float64 `yaml:"warning" json:"warning"`

	// Critical is the minimum score (0.0 - 1.0) before evaluation fails.
	// Default: 0.2
	Critical float64 `yaml:"critical" json:"critical"`
}

// ExportConfig controls where evaluation results are exported.
type ExportConfig struct {
	// Langfuse enables export to Langfuse observability platform.
	Langfuse bool `yaml:"langfuse" json:"langfuse"`

	// OTel enables export via OpenTelemetry.
	OTel bool `yaml:"otel" json:"otel"`

	// JSONL is the path to a JSONL file for exporting results.
	// If empty, JSONL export is disabled.
	JSONL string `yaml:"jsonl" json:"jsonl"`
}

// LoadEvalConfig loads and parses an evaluation configuration from a YAML file.
// It validates the file exists, parses the YAML content, and performs basic validation.
//
// Example YAML structure:
//
//	scorers:
//	  - name: tool_correctness
//	    enabled: true
//	    options:
//	      order_matters: true
//	      numeric_tolerance: 0.001
//	  - name: trajectory
//	    enabled: true
//	    options:
//	      mode: ordered_subset
//	      penalize_extra: 0.05
//	thresholds:
//	  warning: 0.5
//	  critical: 0.2
//	export:
//	  langfuse: true
//	  otel: false
//	  jsonl: "./eval_results.jsonl"
//	ground_truth: "./testdata/ground_truth.json"
//	expected_tools: "./testdata/expected_tools.json"
func LoadEvalConfig(path string) (*EvalConfig, error) {
	// Read file contents
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, types.NewError(types.CONFIG_NOT_FOUND,
				fmt.Sprintf("evaluation config file not found: %s", path))
		}
		return nil, types.WrapError(types.CONFIG_LOAD_FAILED,
			fmt.Sprintf("failed to read evaluation config file: %s", path), err)
	}

	// Parse YAML
	var config EvalConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, types.WrapError(types.CONFIG_PARSE_FAILED,
			fmt.Sprintf("failed to parse evaluation config YAML: %s", path), err)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, types.WrapError(types.CONFIG_VALIDATION_FAILED,
			"evaluation config validation failed", err)
	}

	return &config, nil
}

// Validate performs validation on the EvalConfig structure.
// It checks for required fields, valid threshold values, and scorer configurations.
func (c *EvalConfig) Validate() error {
	// Validate thresholds
	if c.Thresholds.Warning < 0.0 || c.Thresholds.Warning > 1.0 {
		return fmt.Errorf("warning threshold must be between 0.0 and 1.0, got %f", c.Thresholds.Warning)
	}

	if c.Thresholds.Critical < 0.0 || c.Thresholds.Critical > 1.0 {
		return fmt.Errorf("critical threshold must be between 0.0 and 1.0, got %f", c.Thresholds.Critical)
	}

	if c.Thresholds.Critical > c.Thresholds.Warning {
		return fmt.Errorf("critical threshold (%f) must be less than or equal to warning threshold (%f)",
			c.Thresholds.Critical, c.Thresholds.Warning)
	}

	// Ground truth is required
	if c.GroundTruth == "" {
		return fmt.Errorf("ground_truth path is required")
	}

	// Validate each scorer configuration
	validScorerNames := map[string]bool{
		"tool_correctness": true,
		"trajectory":       true,
		"finding_accuracy": true,
	}

	for i, scorer := range c.Scorers {
		if scorer.Name == "" {
			return fmt.Errorf("scorer at index %d is missing name", i)
		}

		if !validScorerNames[scorer.Name] {
			return fmt.Errorf("invalid scorer name '%s' at index %d, must be one of: tool_correctness, trajectory, finding_accuracy",
				scorer.Name, i)
		}
	}

	return nil
}

// ToOptions converts an EvalConfig to EvalOptions.
// This bridges the gap between YAML configuration and runtime options.
// Default values are applied for thresholds if not specified.
func (c *EvalConfig) ToOptions() *EvalOptions {
	opts := NewEvalOptions()

	// Set basic options
	opts.Enabled = true // If we loaded a config, evaluation is enabled
	opts.GroundTruthPath = c.GroundTruth
	opts.ExpectedToolsPath = c.ExpectedTools

	// Set thresholds with defaults
	if c.Thresholds.Warning > 0.0 {
		opts.WarningThreshold = c.Thresholds.Warning
	}
	if c.Thresholds.Critical > 0.0 {
		opts.CriticalThreshold = c.Thresholds.Critical
	}

	// Set export options
	opts.ExportLangfuse = c.Export.Langfuse
	opts.ExportOTel = c.Export.OTel
	if c.Export.JSONL != "" {
		opts.OutputPath = c.Export.JSONL
	}

	// Collect enabled scorer names
	scorerNames := []string{}
	for _, scorer := range c.Scorers {
		if scorer.Enabled {
			scorerNames = append(scorerNames, scorer.Name)
		}
	}
	opts.Scorers = scorerNames

	return opts
}

// BuildScorers instantiates StreamingScorer instances from the configuration.
// It creates scorer objects with their specific options based on the YAML config.
// Only enabled scorers are instantiated.
func (c *EvalConfig) BuildScorers() ([]sdkeval.StreamingScorer, error) {
	scorers := []sdkeval.StreamingScorer{}

	for i, scorerCfg := range c.Scorers {
		// Skip disabled scorers
		if !scorerCfg.Enabled {
			continue
		}

		// Build scorer based on type
		scorer, err := c.buildScorer(scorerCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to build scorer at index %d (%s): %w", i, scorerCfg.Name, err)
		}

		scorers = append(scorers, scorer)
	}

	return scorers, nil
}

// buildScorer creates a single StreamingScorer instance from a ScorerConfig.
func (c *EvalConfig) buildScorer(cfg ScorerConfig) (sdkeval.StreamingScorer, error) {
	switch cfg.Name {
	case "tool_correctness":
		return c.buildToolCorrectnessScorer(cfg)
	case "trajectory":
		return c.buildTrajectoryScorer(cfg)
	case "finding_accuracy":
		return c.buildFindingAccuracyScorer(cfg)
	default:
		return nil, fmt.Errorf("unknown scorer type: %s", cfg.Name)
	}
}

// buildToolCorrectnessScorer creates a tool correctness scorer from config.
func (c *EvalConfig) buildToolCorrectnessScorer(cfg ScorerConfig) (sdkeval.StreamingScorer, error) {
	opts := sdkeval.ToolCorrectnessOptions{}

	// Parse options
	if cfg.Options != nil {
		// OrderMatters
		if val, ok := cfg.Options["order_matters"]; ok {
			if boolVal, ok := val.(bool); ok {
				opts.OrderMatters = boolVal
			} else {
				return nil, fmt.Errorf("tool_correctness option 'order_matters' must be boolean, got %T", val)
			}
		}

		// NumericTolerance
		if val, ok := cfg.Options["numeric_tolerance"]; ok {
			switch v := val.(type) {
			case float64:
				opts.NumericTolerance = v
			case int:
				opts.NumericTolerance = float64(v)
			default:
				return nil, fmt.Errorf("tool_correctness option 'numeric_tolerance' must be number, got %T", val)
			}
		}
	}

	return sdkeval.NewStreamingToolCorrectnessScorer(opts), nil
}

// buildTrajectoryScorer creates a trajectory scorer from config.
func (c *EvalConfig) buildTrajectoryScorer(cfg ScorerConfig) (sdkeval.StreamingScorer, error) {
	opts := sdkeval.TrajectoryOptions{
		Mode: sdkeval.TrajectoryOrderedSubset, // Default mode
	}

	// Parse options
	if cfg.Options != nil {
		// Mode
		if val, ok := cfg.Options["mode"]; ok {
			modeStr, ok := val.(string)
			if !ok {
				return nil, fmt.Errorf("trajectory option 'mode' must be string, got %T", val)
			}

			switch modeStr {
			case "exact_match":
				opts.Mode = sdkeval.TrajectoryExactMatch
			case "subset_match":
				opts.Mode = sdkeval.TrajectorySubsetMatch
			case "ordered_subset":
				opts.Mode = sdkeval.TrajectoryOrderedSubset
			default:
				return nil, fmt.Errorf("invalid trajectory mode '%s', must be one of: exact_match, subset_match, ordered_subset", modeStr)
			}
		}

		// PenalizeExtra
		if val, ok := cfg.Options["penalize_extra"]; ok {
			switch v := val.(type) {
			case float64:
				opts.PenalizeExtra = v
			case int:
				opts.PenalizeExtra = float64(v)
			default:
				return nil, fmt.Errorf("trajectory option 'penalize_extra' must be number, got %T", val)
			}
		}
	}

	return sdkeval.NewStreamingTrajectoryScorer(opts), nil
}

// buildFindingAccuracyScorer creates a finding accuracy scorer from config.
func (c *EvalConfig) buildFindingAccuracyScorer(cfg ScorerConfig) (sdkeval.StreamingScorer, error) {
	opts := sdkeval.FindingAccuracyOptions{
		FuzzyTitleThreshold: 0.8, // Default
	}

	// Parse options
	if cfg.Options != nil {
		// MatchBySeverity
		if val, ok := cfg.Options["match_by_severity"]; ok {
			if boolVal, ok := val.(bool); ok {
				opts.MatchBySeverity = boolVal
			} else {
				return nil, fmt.Errorf("finding_accuracy option 'match_by_severity' must be boolean, got %T", val)
			}
		}

		// MatchByCategory
		if val, ok := cfg.Options["match_by_category"]; ok {
			if boolVal, ok := val.(bool); ok {
				opts.MatchByCategory = boolVal
			} else {
				return nil, fmt.Errorf("finding_accuracy option 'match_by_category' must be boolean, got %T", val)
			}
		}

		// FuzzyTitleThreshold
		if val, ok := cfg.Options["fuzzy_title_threshold"]; ok {
			switch v := val.(type) {
			case float64:
				opts.FuzzyTitleThreshold = v
			case int:
				opts.FuzzyTitleThreshold = float64(v)
			default:
				return nil, fmt.Errorf("finding_accuracy option 'fuzzy_title_threshold' must be number, got %T", val)
			}
		}
	}

	return sdkeval.NewStreamingFindingAccuracyScorer(opts), nil
}
