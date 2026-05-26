package eval

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// EvalOptions contains configuration for the evaluation system.
// This structure controls how agent executions are evaluated against ground truth
// and expected behavior, with optional export to Langfuse and OpenTelemetry.
type EvalOptions struct {
	// Enabled controls whether evaluation is active for this mission.
	// When false, all evaluation logic is bypassed.
	Enabled bool `mapstructure:"enabled" yaml:"enabled" json:"enabled"`

	// FeedbackEnabled controls whether interactive feedback collection is enabled.
	// When true, users will be prompted to provide feedback on agent outputs.
	FeedbackEnabled bool `mapstructure:"feedback_enabled" yaml:"feedback_enabled" json:"feedback_enabled"`

	// OutputPath specifies where evaluation results are written.
	// If empty, results are written to stdout only.
	OutputPath string `mapstructure:"output_path" yaml:"output_path" json:"output_path"`

	// ConfigPath points to the evaluation configuration file containing scorer definitions
	// and thresholds. If empty, uses default scoring configuration.
	ConfigPath string `mapstructure:"config_path" yaml:"config_path" json:"config_path"`

	// Scorers is a list of scorer names to apply during evaluation.
	// Valid values: "exact_match", "semantic_similarity", "tool_correctness", "custom"
	// If empty, all available scorers are applied.
	Scorers []string `mapstructure:"scorers" yaml:"scorers" json:"scorers"`

	// GroundTruthPath points to a file containing expected outputs for validation.
	// Required when Enabled is true. Format: JSON with task_id -> expected_output mappings.
	GroundTruthPath string `mapstructure:"ground_truth_path" yaml:"ground_truth_path" json:"ground_truth_path"`

	// ExpectedToolsPath points to a file containing expected tool call sequences.
	// Optional. Format: JSON with task_id -> []ToolCall mappings.
	ExpectedToolsPath string `mapstructure:"expected_tools_path" yaml:"expected_tools_path" json:"expected_tools_path"`

	// WarningThreshold is the minimum score (0.0 - 1.0) before a warning is issued.
	// Scores below this threshold trigger warning-level alerts but don't fail the mission.
	// Default: 0.5
	WarningThreshold float64 `mapstructure:"warning_threshold" yaml:"warning_threshold" json:"warning_threshold"`

	// CriticalThreshold is the minimum score (0.0 - 1.0) before evaluation fails.
	// Scores below this threshold cause mission failure.
	// Default: 0.2
	CriticalThreshold float64 `mapstructure:"critical_threshold" yaml:"critical_threshold" json:"critical_threshold"`

	// ExportLangfuse controls whether evaluation results are exported to Langfuse.
	// Requires Langfuse configuration in observability settings.
	ExportLangfuse bool `mapstructure:"export_langfuse" yaml:"export_langfuse" json:"export_langfuse"`

	// ExportOTel controls whether evaluation results are exported via OpenTelemetry.
	// Requires OpenTelemetry configuration in tracing settings.
	ExportOTel bool `mapstructure:"export_otel" yaml:"export_otel" json:"export_otel"`
}

// NewEvalOptions creates a new EvalOptions with sensible defaults.
// By default, evaluation is disabled to avoid breaking existing missions.
func NewEvalOptions() *EvalOptions {
	return &EvalOptions{
		Enabled:           false,
		FeedbackEnabled:   false,
		OutputPath:        "",
		ConfigPath:        "",
		Scorers:           []string{},
		GroundTruthPath:   "",
		ExpectedToolsPath: "",
		WarningThreshold:  0.5,
		CriticalThreshold: 0.2,
		ExportLangfuse:    false,
		ExportOTel:        false,
	}
}

// Validate performs validation on EvalOptions.
// It checks for conflicting options, invalid thresholds, and missing required files.
func (o *EvalOptions) Validate() error {
	// If evaluation is disabled, skip validation
	if !o.Enabled {
		return nil
	}

	// Validate thresholds are in valid range [0.0, 1.0]
	if o.WarningThreshold < 0.0 || o.WarningThreshold > 1.0 {
		return types.NewError(types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("warning_threshold must be between 0.0 and 1.0, got %f", o.WarningThreshold))
	}

	if o.CriticalThreshold < 0.0 || o.CriticalThreshold > 1.0 {
		return types.NewError(types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("critical_threshold must be between 0.0 and 1.0, got %f", o.CriticalThreshold))
	}

	// Critical threshold must be less than or equal to warning threshold
	if o.CriticalThreshold > o.WarningThreshold {
		return types.NewError(types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("critical_threshold (%f) must be less than or equal to warning_threshold (%f)",
				o.CriticalThreshold, o.WarningThreshold))
	}

	// Ground truth path is required when evaluation is enabled
	if o.GroundTruthPath == "" {
		return types.NewError(types.CONFIG_VALIDATION_FAILED,
			"ground_truth_path is required when evaluation is enabled")
	}

	// Validate ground truth file exists
	if err := o.validateFilePath(o.GroundTruthPath, "ground_truth_path"); err != nil {
		return err
	}

	// Validate expected tools path if provided
	if o.ExpectedToolsPath != "" {
		if err := o.validateFilePath(o.ExpectedToolsPath, "expected_tools_path"); err != nil {
			return err
		}
	}

	// Validate config path if provided
	if o.ConfigPath != "" {
		if err := o.validateFilePath(o.ConfigPath, "config_path"); err != nil {
			return err
		}
	}

	// Validate output path directory exists if provided
	if o.OutputPath != "" {
		outputDir := filepath.Dir(o.OutputPath)
		if err := o.validateDirectoryPath(outputDir, "output_path directory"); err != nil {
			return err
		}
	}

	// Validate scorer names
	validScorers := map[string]bool{
		"exact_match":         true,
		"semantic_similarity": true,
		"tool_correctness":    true,
		"custom":              true,
	}

	for _, scorer := range o.Scorers {
		if !validScorers[scorer] {
			return types.NewError(types.CONFIG_VALIDATION_FAILED,
				fmt.Sprintf("invalid scorer '%s', must be one of: exact_match, semantic_similarity, tool_correctness, custom", scorer))
		}
	}

	// Warn about conflicting export options (allow both, but it's unusual)
	// This is informational - not a validation failure

	return nil
}

// validateFilePath checks if a file exists and is readable.
func (o *EvalOptions) validateFilePath(path, fieldName string) error {
	// Expand path to absolute
	absPath, err := filepath.Abs(path)
	if err != nil {
		return types.WrapError(types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("failed to resolve %s", fieldName), err)
	}

	// Check if file exists
	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return types.NewError(types.CONFIG_VALIDATION_FAILED,
				fmt.Sprintf("%s does not exist: %s", fieldName, absPath))
		}
		return types.WrapError(types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("failed to stat %s", fieldName), err)
	}

	// Check if it's a regular file
	if info.IsDir() {
		return types.NewError(types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("%s must be a file, not a directory: %s", fieldName, absPath))
	}

	return nil
}

// validateDirectoryPath checks if a directory exists and is writable.
func (o *EvalOptions) validateDirectoryPath(path, fieldName string) error {
	// Expand path to absolute
	absPath, err := filepath.Abs(path)
	if err != nil {
		return types.WrapError(types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("failed to resolve %s", fieldName), err)
	}

	// Check if directory exists
	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return types.NewError(types.CONFIG_VALIDATION_FAILED,
				fmt.Sprintf("%s does not exist: %s", fieldName, absPath))
		}
		return types.WrapError(types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("failed to stat %s", fieldName), err)
	}

	// Check if it's a directory
	if !info.IsDir() {
		return types.NewError(types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("%s must be a directory: %s", fieldName, absPath))
	}

	return nil
}

// ApplyDefaults applies default values to unset fields.
// This is called after configuration loading to ensure all fields have valid values.
func (o *EvalOptions) ApplyDefaults() {
	if o.WarningThreshold == 0.0 {
		o.WarningThreshold = 0.5
	}
	if o.CriticalThreshold == 0.0 {
		o.CriticalThreshold = 0.2
	}
}
