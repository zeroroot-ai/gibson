package agent

// SlotDefinition defines an LLM slot requirement for an agent.
// Slots allow agents to declare their LLM needs, which can be satisfied
// by different providers and models based on runtime configuration.
type SlotDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Required    bool            `json:"required"`
	Default     SlotConfig      `json:"default"`
	Constraints SlotConstraints `json:"constraints"`
}

// SlotConfig defines LLM configuration for a slot.
// This specifies which model to use and how to configure it.
type SlotConfig struct {
	Provider    string  `json:"provider"`    // e.g., "anthropic", "openai", "local"
	Model       string  `json:"model"`       // e.g., "claude-3-opus", "gpt-4"
	Temperature float64 `json:"temperature"` // 0.0 - 1.0
	MaxTokens   int     `json:"max_tokens"`  // Maximum tokens to generate
}

// SlotConstraints defines requirements for a slot.
// These constraints ensure the assigned LLM meets the agent's needs.
type SlotConstraints struct {
	MinContextWindow int      `json:"min_context_window"` // Minimum context window size
	RequiredFeatures []string `json:"required_features"`  // Required LLM features
}

// Feature constants define capabilities that LLMs may support
const (
	FeatureToolUse   = "tool_use"  // Function/tool calling
	FeatureVision    = "vision"    // Image understanding
	FeatureStreaming = "streaming" // Streaming responses
	FeatureJSONMode  = "json_mode" // Structured JSON output
)

// NewSlotDefinition creates a new slot definition with basic properties
func NewSlotDefinition(name, description string, required bool) SlotDefinition {
	return SlotDefinition{
		Name:        name,
		Description: description,
		Required:    required,
		Default: SlotConfig{
			Provider:    "", // Resolved at runtime based on available providers
			Model:       "", // Resolved at runtime based on available providers
			Temperature: 0.7,
			MaxTokens:   4096,
		},
		Constraints: SlotConstraints{
			MinContextWindow: 8192,
			RequiredFeatures: []string{},
		},
	}
}

// WithDefault sets the default configuration for this slot
func (s SlotDefinition) WithDefault(cfg SlotConfig) SlotDefinition {
	s.Default = cfg
	return s
}

// WithConstraints sets the constraints for this slot
func (s SlotDefinition) WithConstraints(c SlotConstraints) SlotDefinition {
	s.Constraints = c
	return s
}

// Validate checks if a slot configuration meets the constraints
func (s SlotDefinition) Validate(cfg SlotConfig) error {
	// Validation will be implemented when we add LLM providers in Stage 5
	return nil
}

// MergeConfig merges a slot override with the default configuration
func (s SlotDefinition) MergeConfig(override *SlotConfig) SlotConfig {
	if override == nil {
		return s.Default
	}

	result := s.Default

	if override.Provider != "" {
		result.Provider = override.Provider
	}
	if override.Model != "" {
		result.Model = override.Model
	}
	if override.Temperature != 0 {
		result.Temperature = override.Temperature
	}
	if override.MaxTokens != 0 {
		result.MaxTokens = override.MaxTokens
	}

	return result
}
