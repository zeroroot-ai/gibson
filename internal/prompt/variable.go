package prompt

import (
	"strings"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// VariableDef defines a variable that can be resolved from context data.
// Variables use dot-notation paths to reference nested values in the context map.
type VariableDef struct {
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Required    bool   `json:"required,omitempty" yaml:"required,omitempty"`
	Default     any    `json:"default,omitempty" yaml:"default,omitempty"`
	Source      string `json:"source,omitempty" yaml:"source,omitempty"` // e.g., "mission.target.url"
}

// ResolvePath resolves a dot-notation path in a nested map.
// For example, ResolvePath(ctx, "mission.target.url") will traverse:
//
//	ctx["mission"] -> ["target"] -> ["url"]
//
// Returns the resolved value and true if found, or nil and false if any part
// of the path doesn't exist or is not a map.
func ResolvePath(ctx map[string]any, path string) (any, bool) {
	if path == "" {
		return nil, false
	}

	parts := strings.Split(path, ".")
	current := any(ctx)

	for i, part := range parts {
		// Try to convert current to map[string]any
		currentMap, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}

		// Get the value at this part
		value, exists := currentMap[part]
		if !exists {
			return nil, false
		}

		// If this is the last part, return the value
		if i == len(parts)-1 {
			return value, true
		}

		// Otherwise, continue traversing
		current = value
	}

	return nil, false
}

// Resolve resolves the variable's value from the given context.
// It first checks if the variable name exists directly in the context.
// If not found and a Source is specified, it resolves the Source path.
// If still not found and the variable is Required, returns an error.
// If not found and a Default is set, returns the default value.
func (v *VariableDef) Resolve(ctx map[string]any) (any, error) {
	// First check if the variable name exists directly in context
	if value, exists := ctx[v.Name]; exists {
		return value, nil
	}

	// If Source is specified, try resolving the source path
	if v.Source != "" {
		if value, found := ResolvePath(ctx, v.Source); found {
			return value, nil
		}
	}

	// If required and not found, return error
	if v.Required {
		return nil, types.NewError(
			PROMPT_VAR_REQUIRED,
			"required variable '"+v.Name+"' not found in context",
		)
	}

	// Return default if set, otherwise nil
	return v.Default, nil
}
