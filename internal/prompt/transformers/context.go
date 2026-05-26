package transformers

import (
	"fmt"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/prompt"
)

// ContextInjector adds parent agent context to delegated prompts.
// It prepends a context prompt at the system_prefix position to inform
// the sub-agent about the delegation context, task, and constraints.
type ContextInjector struct {
	// IncludeMemory determines whether to include memory context
	IncludeMemory bool

	// IncludeConstraints determines whether to include constraints
	IncludeConstraints bool

	// ContextTemplate is the template for the context prompt content.
	// If empty, uses the default template.
	ContextTemplate string
}

// NewContextInjector creates a new ContextInjector with default settings.
func NewContextInjector() *ContextInjector {
	return &ContextInjector{
		IncludeMemory:      true,
		IncludeConstraints: true,
		ContextTemplate:    "",
	}
}

// Name returns the transformer name for logging.
func (c *ContextInjector) Name() string {
	return "ContextInjector"
}

// Transform adds a context prompt at the beginning of the prompts list.
func (c *ContextInjector) Transform(ctx *prompt.RelayContext, prompts []prompt.Prompt) ([]prompt.Prompt, error) {
	contextContent := c.buildContextContent(ctx)

	// Create context prompt at system_prefix position with priority 1
	contextPrompt := prompt.Prompt{
		ID:          fmt.Sprintf("relay_context_%s_to_%s", ctx.SourceAgent, ctx.TargetAgent),
		Name:        "Delegation Context",
		Description: "Context information from parent agent delegation",
		Position:    prompt.PositionSystemPrefix,
		Content:     contextContent,
		Priority:    1,
		Metadata: map[string]any{
			"relay":        true,
			"source_agent": ctx.SourceAgent,
			"target_agent": ctx.TargetAgent,
		},
	}

	// Prepend context prompt to the list
	result := make([]prompt.Prompt, 0, len(prompts)+1)
	result = append(result, contextPrompt)
	result = append(result, prompts...)

	return result, nil
}

// buildContextContent constructs the context prompt content based on settings.
func (c *ContextInjector) buildContextContent(ctx *prompt.RelayContext) string {
	if c.ContextTemplate != "" {
		// Use custom template (simple string replacement for now)
		return c.applyTemplate(c.ContextTemplate, ctx)
	}

	// Build default context content
	var parts []string

	parts = append(parts, fmt.Sprintf("Delegated by: %s", ctx.SourceAgent))
	parts = append(parts, fmt.Sprintf("Task: %s", ctx.Task))

	if c.IncludeConstraints && len(ctx.Constraints) > 0 {
		constraintsList := make([]string, len(ctx.Constraints))
		for i, constraint := range ctx.Constraints {
			constraintsList[i] = fmt.Sprintf("  - %s", constraint)
		}
		parts = append(parts, "Constraints:")
		parts = append(parts, constraintsList...)
	}

	if c.IncludeMemory && len(ctx.Memory) > 0 {
		parts = append(parts, fmt.Sprintf("\nShared Context: %d items available", len(ctx.Memory)))
	}

	return strings.Join(parts, "\n")
}

// applyTemplate applies simple template substitution.
func (c *ContextInjector) applyTemplate(template string, ctx *prompt.RelayContext) string {
	result := template
	result = strings.ReplaceAll(result, "{SourceAgent}", ctx.SourceAgent)
	result = strings.ReplaceAll(result, "{TargetAgent}", ctx.TargetAgent)
	result = strings.ReplaceAll(result, "{Task}", ctx.Task)

	if len(ctx.Constraints) > 0 {
		result = strings.ReplaceAll(result, "{Constraints}", strings.Join(ctx.Constraints, ", "))
	} else {
		result = strings.ReplaceAll(result, "{Constraints}", "None")
	}

	return result
}
