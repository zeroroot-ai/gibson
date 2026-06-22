package builtin

import (
	"context"
	"fmt"
	"regexp"

	"github.com/zeroroot-ai/gibson/internal/engine/guardrail"
)

// ContentPattern defines a pattern to match and action to take
type ContentPattern struct {
	Pattern string                    // Regex pattern to match
	Action  guardrail.GuardrailAction // Action when matched (block, redact, warn)
	Replace string                    // Replacement text for redact action
}

// ContentFilterConfig configures the content filter guardrail
type ContentFilterConfig struct {
	Patterns      []ContentPattern          // Patterns to check
	DefaultAction guardrail.GuardrailAction // Default action if no action specified
}

// ContentFilter implements content-based guardrails using regex patterns
type ContentFilter struct {
	config   ContentFilterConfig
	name     string
	patterns []compiledPattern
}

type compiledPattern struct {
	regex   *regexp.Regexp
	action  guardrail.GuardrailAction
	replace string
}

// NewContentFilter creates a new content filter guardrail
func NewContentFilter(config ContentFilterConfig) (*ContentFilter, error) {
	cf := &ContentFilter{
		config:   config,
		name:     "content-filter",
		patterns: make([]compiledPattern, 0, len(config.Patterns)),
	}

	// Pre-compile all regex patterns
	for i, pattern := range config.Patterns {
		regex, err := regexp.Compile(pattern.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern at index %d: %w", i, err)
		}

		action := pattern.Action
		if action == "" {
			action = config.DefaultAction
		}
		if action == "" {
			action = guardrail.GuardrailActionAllow
		}

		cf.patterns = append(cf.patterns, compiledPattern{
			regex:   regex,
			action:  action,
			replace: pattern.Replace,
		})
	}

	return cf, nil
}

// Name returns the name of this guardrail
func (c *ContentFilter) Name() string {
	return c.name
}

// Type returns the type of guardrail
func (c *ContentFilter) Type() guardrail.GuardrailType {
	return guardrail.GuardrailTypeContent
}

// CheckInput checks input content against patterns
func (c *ContentFilter) CheckInput(ctx context.Context, input guardrail.GuardrailInput) (guardrail.GuardrailResult, error) {
	return c.checkContent(input.Content), nil
}

// CheckOutput checks output content against patterns
func (c *ContentFilter) CheckOutput(ctx context.Context, output guardrail.GuardrailOutput) (guardrail.GuardrailResult, error) {
	return c.checkContent(output.Content), nil
}

// checkContent applies all patterns and returns most restrictive result
func (c *ContentFilter) checkContent(content string) guardrail.GuardrailResult {
	// Empty patterns list means allow all
	if len(c.patterns) == 0 {
		return guardrail.NewAllowResult()
	}

	var matchedPatterns []string
	var mostRestrictiveAction guardrail.GuardrailAction = guardrail.GuardrailActionAllow
	var redactedContent = content

	// Apply all patterns
	for _, cp := range c.patterns {
		if cp.regex.MatchString(content) {
			matchedPatterns = append(matchedPatterns, cp.regex.String())

			// Track most restrictive action
			if actionPriority(cp.action) > actionPriority(mostRestrictiveAction) {
				mostRestrictiveAction = cp.action
			}

			// Apply redactions
			if cp.action == guardrail.GuardrailActionRedact {
				replacement := cp.replace
				if replacement == "" {
					replacement = "[REDACTED]"
				}
				redactedContent = cp.regex.ReplaceAllString(redactedContent, replacement)
			}
		}
	}

	// No matches, allow
	if len(matchedPatterns) == 0 {
		return guardrail.NewAllowResult()
	}

	// Build result based on most restrictive action
	var result guardrail.GuardrailResult
	reason := fmt.Sprintf("matched pattern(s): %v", matchedPatterns)

	switch mostRestrictiveAction {
	case guardrail.GuardrailActionBlock:
		result = guardrail.NewBlockResult(reason)
	case guardrail.GuardrailActionRedact:
		result = guardrail.NewRedactResult(reason, redactedContent)
	case guardrail.GuardrailActionWarn:
		result = guardrail.NewWarnResult(reason)
	default:
		result = guardrail.NewAllowResult()
	}

	// Add matched patterns to metadata
	if result.Metadata == nil {
		result.Metadata = make(map[string]any)
	}
	result.Metadata["matched_patterns"] = matchedPatterns

	return result
}

// actionPriority returns the priority level of an action for comparison
// Higher priority means more restrictive
func actionPriority(action guardrail.GuardrailAction) int {
	switch action {
	case guardrail.GuardrailActionBlock:
		return 4
	case guardrail.GuardrailActionRedact:
		return 3
	case guardrail.GuardrailActionWarn:
		return 2
	case guardrail.GuardrailActionAllow:
		return 1
	default:
		return 0
	}
}
