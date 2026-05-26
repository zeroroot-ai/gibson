package prompt

import (
	"github.com/zeroroot-ai/gibson/internal/types"
)

// Prompt error codes
const (
	PROMPT_INVALID_POSITION  types.ErrorCode = "PROMPT_INVALID_POSITION"
	PROMPT_EMPTY_ID          types.ErrorCode = "PROMPT_EMPTY_ID"
	PROMPT_EMPTY_CONTENT     types.ErrorCode = "PROMPT_EMPTY_CONTENT"
	PROMPT_VAR_NOT_FOUND     types.ErrorCode = "PROMPT_VAR_NOT_FOUND"
	PROMPT_VAR_REQUIRED      types.ErrorCode = "PROMPT_VAR_REQUIRED"
	PROMPT_CONDITION_INVALID types.ErrorCode = "PROMPT_CONDITION_INVALID"
)

// VariableDef, Condition, and Example are defined in their respective files:
// - variable.go: VariableDef implementation
// - condition.go: Condition implementation
// - example.go: Example implementation

// Prompt represents a structured prompt with metadata, variables, and conditions.
// Prompts are positioned in a specific location in the message sequence and can
// contain dynamic variables that are resolved at runtime.
type Prompt struct {
	// ID is the unique identifier for this prompt (required)
	ID string `json:"id" yaml:"id"`

	// Name is a human-readable name for this prompt
	Name string `json:"name" yaml:"name"`

	// Description provides context about what this prompt does
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// Position determines where this prompt appears in the message sequence (required)
	Position Position `json:"position" yaml:"position"`

	// Content is the actual prompt text, which may contain variable placeholders (required)
	Content string `json:"content" yaml:"content"`

	// Variables defines the variables that can be used in this prompt's content
	Variables []VariableDef `json:"variables,omitempty" yaml:"variables,omitempty"`

	// Conditions determines when this prompt should be included in the final message
	Conditions []Condition `json:"conditions,omitempty" yaml:"conditions,omitempty"`

	// Examples provides few-shot learning examples for this prompt
	Examples []Example `json:"examples,omitempty" yaml:"examples,omitempty"`

	// Priority determines the order of prompts within the same position (higher = earlier)
	// When multiple prompts share the same position, they are sorted by priority descending
	Priority int `json:"priority,omitempty" yaml:"priority,omitempty"`

	// Metadata stores arbitrary key-value pairs for extensibility
	Metadata map[string]any `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// Validate checks if the Prompt has all required fields and valid values.
// Returns a GibsonError if validation fails.
//
// Validation rules:
//   - ID must not be empty
//   - Position must be a valid position constant
//   - Content must not be empty
func (p *Prompt) Validate() error {
	// Check ID is not empty
	if p.ID == "" {
		return types.NewError(
			PROMPT_EMPTY_ID,
			"prompt ID cannot be empty",
		)
	}

	// Check Position is valid
	if !p.Position.IsValid() {
		return types.NewError(
			PROMPT_INVALID_POSITION,
			"invalid prompt position: "+string(p.Position),
		)
	}

	// Check Content is not empty
	if p.Content == "" {
		return types.NewError(
			PROMPT_EMPTY_CONTENT,
			"prompt content cannot be empty",
		)
	}

	return nil
}
