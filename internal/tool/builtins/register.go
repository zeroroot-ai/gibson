// Package builtins provides built-in tools for Gibson agents.
// These tools are automatically registered when initializing the harness.
package builtins

import (
	"github.com/zero-day-ai/gibson/internal/payload"
	"github.com/zero-day-ai/gibson/internal/tool"
)

// BuiltinToolsConfig holds dependencies for creating builtin tools.
type BuiltinToolsConfig struct {
	// PayloadRegistry is required for payload_search tool.
	PayloadRegistry payload.PayloadRegistry

	// PayloadExecutor is required for payload_execute tool.
	PayloadExecutor payload.PayloadExecutor
}

// RegisterBuiltinTools registers all builtin tools with the provided registry.
// This function should be called during harness initialization.
//
// The following tools are registered:
//   - payload_search: Searches payloads using full-text search
//   - payload_execute: Executes a payload against a target
//
// Any tools that can't be created (due to missing dependencies) are skipped.
// Returns the first error encountered during registration.
func RegisterBuiltinTools(registry tool.ToolRegistry, cfg BuiltinToolsConfig) error {
	var errors []error

	// Register payload_search tool if PayloadRegistry is available
	if cfg.PayloadRegistry != nil {
		searchTool := NewPayloadSearchTool(cfg.PayloadRegistry)
		if err := registry.RegisterInternal(searchTool); err != nil {
			errors = append(errors, err)
		}
	}

	// Register payload_execute tool if PayloadExecutor is available
	if cfg.PayloadExecutor != nil {
		executeTool := NewPayloadExecuteTool(cfg.PayloadExecutor)
		if err := registry.RegisterInternal(executeTool); err != nil {
			errors = append(errors, err)
		}
	}

	// Return first error if any occurred
	if len(errors) > 0 {
		return errors[0]
	}

	return nil
}

// BuiltinToolNames returns the names of all builtin tools.
// This is useful for documentation and validation purposes.
func BuiltinToolNames() []string {
	return []string{
		"payload_search",
		"payload_execute",
	}
}
