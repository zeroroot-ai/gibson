package builtin

import (
	"context"
	"fmt"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/guardrail"
)

// ToolRestrictionConfig defines the configuration for tool access control.
type ToolRestrictionConfig struct {
	// AllowedTools is a whitelist of allowed tool names.
	// If empty, all tools are allowed unless blocked.
	AllowedTools []string

	// BlockedTools is a blacklist of blocked tools.
	// Takes precedence over AllowedTools.
	BlockedTools []string

	// AllowedTags allows tools with these tags.
	AllowedTags []string

	// BlockedTags blocks tools with these tags.
	// Takes precedence over AllowedTags.
	BlockedTags []string
}

// ToolRestriction enforces tool usage restrictions based on allow/block lists.
// It performs case-insensitive matching on tool names and tags.
type ToolRestriction struct {
	config      ToolRestrictionConfig
	name        string
	allowedSet  map[string]bool
	blockedSet  map[string]bool
	allowedTags map[string]bool
	blockedTags map[string]bool
}

// NewToolRestriction creates a new ToolRestriction guardrail with the given configuration.
// It pre-processes the configuration into hash sets for O(1) lookup performance.
func NewToolRestriction(config ToolRestrictionConfig) *ToolRestriction {
	tr := &ToolRestriction{
		config:      config,
		name:        "tool_restriction",
		allowedSet:  make(map[string]bool),
		blockedSet:  make(map[string]bool),
		allowedTags: make(map[string]bool),
		blockedTags: make(map[string]bool),
	}

	// Build sets for O(1) lookup with case-insensitive keys
	for _, tool := range config.AllowedTools {
		tr.allowedSet[strings.ToLower(tool)] = true
	}

	for _, tool := range config.BlockedTools {
		tr.blockedSet[strings.ToLower(tool)] = true
	}

	for _, tag := range config.AllowedTags {
		tr.allowedTags[strings.ToLower(tag)] = true
	}

	for _, tag := range config.BlockedTags {
		tr.blockedTags[strings.ToLower(tag)] = true
	}

	return tr
}

// Name returns the unique name of this guardrail instance.
func (t *ToolRestriction) Name() string {
	return t.name
}

// Type returns the guardrail type for tool restrictions.
func (t *ToolRestriction) Type() guardrail.GuardrailType {
	return guardrail.GuardrailTypeTool
}

// CheckInput inspects the tool name in the input and enforces restrictions.
// Returns a block result if the tool is not allowed, otherwise allows.
func (t *ToolRestriction) CheckInput(ctx context.Context, input guardrail.GuardrailInput) (guardrail.GuardrailResult, error) {
	// If no tool name is provided, allow (nothing to check)
	if input.ToolName == "" {
		return guardrail.NewAllowResult(), nil
	}

	toolName := strings.ToLower(input.ToolName)

	// Check if tool is explicitly blocked (takes precedence)
	if t.blockedSet[toolName] {
		return guardrail.NewBlockResult(fmt.Sprintf("tool '%s' is blocked", input.ToolName)), nil
	}

	// Check tags if provided in metadata
	if tags, ok := input.Metadata["tags"].([]string); ok {
		for _, tag := range tags {
			tagLower := strings.ToLower(tag)
			// Blocked tags take precedence
			if t.blockedTags[tagLower] {
				return guardrail.NewBlockResult(fmt.Sprintf("tool '%s' has blocked tag '%s'", input.ToolName, tag)), nil
			}
		}

		// If we have allowed tags configured, check if tool has at least one
		if len(t.allowedTags) > 0 {
			hasAllowedTag := false
			for _, tag := range tags {
				if t.allowedTags[strings.ToLower(tag)] {
					hasAllowedTag = true
					break
				}
			}
			if !hasAllowedTag {
				return guardrail.NewBlockResult(fmt.Sprintf("tool '%s' does not have any allowed tags", input.ToolName)), nil
			}
		}
	}

	// If AllowedTools is empty, allow all tools (except explicitly blocked)
	if len(t.allowedSet) == 0 {
		return guardrail.NewAllowResult(), nil
	}

	// Check if tool is in the allowed list
	if t.allowedSet[toolName] {
		return guardrail.NewAllowResult(), nil
	}

	// Tool not in allowed list, block it
	return guardrail.NewBlockResult(fmt.Sprintf("tool '%s' is not in allowed list", input.ToolName)), nil
}

// CheckOutput typically allows all output for tool restrictions.
// Tool restrictions are primarily enforced on input (tool invocation).
func (t *ToolRestriction) CheckOutput(ctx context.Context, output guardrail.GuardrailOutput) (guardrail.GuardrailResult, error) {
	return guardrail.NewAllowResult(), nil
}
