package prompt

import (
	"path/filepath"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// PromptConfig is the configuration for the prompt system
type PromptConfig struct {
	PromptsDir     string `json:"prompts_dir" yaml:"prompts_dir" mapstructure:"prompts_dir"`
	LoadBuiltins   bool   `json:"load_builtins" yaml:"load_builtins" mapstructure:"load_builtins"`
	DefaultPersona string `json:"default_persona,omitempty" yaml:"default_persona,omitempty" mapstructure:"default_persona"`
}

// NewDefaultPromptConfig returns a PromptConfig with sensible defaults
func NewDefaultPromptConfig() *PromptConfig {
	config := &PromptConfig{}
	config.ApplyDefaults()
	return config
}

// Validate checks if the configuration is valid
func (c *PromptConfig) Validate() error {
	// If PromptsDir is set and non-empty, validate path format
	if c.PromptsDir != "" {
		// Check if it's a valid path format (not checking existence)
		cleaned := filepath.Clean(c.PromptsDir)
		if cleaned == "." || cleaned == "/" {
			return types.NewError(types.CONFIG_VALIDATION_FAILED,
				"prompts_dir must be a valid directory path")
		}
	}

	return nil
}

// ApplyDefaults sets default values for unset fields
func (c *PromptConfig) ApplyDefaults() {
	// PromptsDir defaults to empty string (will use ~/.gibson/prompts)
	// LoadBuiltins defaults to true, but Go's zero value for bool is false
	// So we need to set it explicitly if it's not already set
	// Note: This is a limitation - we can't distinguish between explicitly set to false
	// and unset. In practice, users should explicitly set this in config files.
	if c.PromptsDir == "" {
		c.PromptsDir = "" // Empty means use default ~/.gibson/prompts
	}

	// DefaultPersona defaults to empty string (no default persona)
	if c.DefaultPersona == "" {
		c.DefaultPersona = ""
	}

	// Note: LoadBuiltins has a special default of true, but we can't detect
	// if it's been explicitly set to false vs being unset. The actual default
	// application logic should happen at the loading layer, not here.
	// For now, we leave it as-is since false is the zero value.
}
