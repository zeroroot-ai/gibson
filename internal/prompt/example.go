package prompt

import (
	"fmt"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// Example represents a few-shot example for the model.
// Few-shot learning provides the LLM with examples of desired input-output pairs
// to guide its behavior and improve response quality.
type Example struct {
	// Description provides context about what this example demonstrates (optional)
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// Input is the example input text shown to the model
	Input string `json:"input" yaml:"input"`

	// Output is the expected output for the given input
	Output string `json:"output" yaml:"output"`
}

// Validate checks if the example is valid.
// Returns an error if required fields are missing or invalid.
func (e *Example) Validate() error {
	var validationErrors []string

	// Input is required
	if strings.TrimSpace(e.Input) == "" {
		validationErrors = append(validationErrors, "input is required")
	}

	// Output is required
	if strings.TrimSpace(e.Output) == "" {
		validationErrors = append(validationErrors, "output is required")
	}

	if len(validationErrors) > 0 {
		return &types.GibsonError{
			Code:    ErrCodeInvalidExample,
			Message: fmt.Sprintf("example validation failed: %s", strings.Join(validationErrors, ", ")),
		}
	}

	return nil
}

// String returns a formatted string representation of the example.
// This can be useful for debugging and logging.
func (e *Example) String() string {
	if e.Description != "" {
		return fmt.Sprintf("Example(%s): %s -> %s", e.Description, e.Input, e.Output)
	}
	return fmt.Sprintf("Example: %s -> %s", e.Input, e.Output)
}

// Examples is a collection of Example instances for few-shot learning.
type Examples []Example

// Validate checks if all examples in the collection are valid.
// Returns an error if any example is invalid.
func (exs Examples) Validate() error {
	for i, ex := range exs {
		if err := ex.Validate(); err != nil {
			return &types.GibsonError{
				Code:    ErrCodeInvalidExample,
				Message: fmt.Sprintf("example at index %d is invalid", i),
				Cause:   err,
			}
		}
	}
	return nil
}

// String returns a formatted string representation of all examples.
func (exs Examples) String() string {
	if len(exs) == 0 {
		return "Examples: []"
	}

	parts := make([]string, len(exs))
	for i, ex := range exs {
		parts[i] = fmt.Sprintf("[%d] %s", i, ex.String())
	}
	return fmt.Sprintf("Examples:\n  %s", strings.Join(parts, "\n  "))
}
