package builtin

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/guardrail"
)

// PIIPattern represents a predefined PII detection pattern type.
type PIIPattern string

const (
	PIIPatternSSN        PIIPattern = "ssn"
	PIIPatternEmail      PIIPattern = "email"
	PIIPatternPhone      PIIPattern = "phone"
	PIIPatternCreditCard PIIPattern = "credit_card"
	PIIPatternIPAddress  PIIPattern = "ip_address"
)

// PIIDetectorConfig configures PII detection behavior.
type PIIDetectorConfig struct {
	// Action to take when PII is detected (block, redact, or warn)
	Action guardrail.GuardrailAction

	// EnabledPatterns specifies which built-in patterns to detect
	EnabledPatterns []string

	// CustomPatterns allows custom regex patterns with names
	CustomPatterns map[string]string

	// AllowlistPatterns are regex patterns that should not be treated as PII
	AllowlistPatterns []string
}

// PIIDetector detects and handles personally identifiable information.
type PIIDetector struct {
	config           PIIDetectorConfig
	name             string
	patterns         map[PIIPattern]*regexp.Regexp
	customPatterns   map[string]*regexp.Regexp
	allowlistPattern *regexp.Regexp
}

// piiMatch represents a detected PII occurrence.
type piiMatch struct {
	Pattern PIIPattern
	Match   string
	Start   int
	End     int
}

// Predefined PII regex patterns
var piiPatterns = map[PIIPattern]string{
	PIIPatternSSN:        `\b\d{3}-\d{2}-\d{4}\b`,
	PIIPatternEmail:      `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,
	PIIPatternPhone:      `(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b`,
	PIIPatternCreditCard: `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`,
	PIIPatternIPAddress:  `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`,
}

// NewPIIDetector creates a new PII detector with the given configuration.
// Returns an error if custom patterns are invalid regex.
func NewPIIDetector(config PIIDetectorConfig) (*PIIDetector, error) {
	// Default action to redact if not specified
	if config.Action == "" {
		config.Action = guardrail.GuardrailActionRedact
	}

	detector := &PIIDetector{
		config:         config,
		name:           "pii_detector",
		patterns:       make(map[PIIPattern]*regexp.Regexp),
		customPatterns: make(map[string]*regexp.Regexp),
	}

	// Compile enabled built-in patterns
	if len(config.EnabledPatterns) == 0 {
		// If no patterns specified, enable all
		for pattern, regex := range piiPatterns {
			detector.patterns[pattern] = regexp.MustCompile(regex)
		}
	} else {
		for _, patternName := range config.EnabledPatterns {
			pattern := PIIPattern(patternName)
			if regex, ok := piiPatterns[pattern]; ok {
				detector.patterns[pattern] = regexp.MustCompile(regex)
			}
		}
	}

	// Compile custom patterns
	for name, pattern := range config.CustomPatterns {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid custom pattern '%s': %w", name, err)
		}
		detector.customPatterns[name] = compiled
	}

	// Compile allowlist pattern (combine all allowlist patterns)
	if len(config.AllowlistPatterns) > 0 {
		allowlistRegex := "(?:" + strings.Join(config.AllowlistPatterns, "|") + ")"
		var err error
		detector.allowlistPattern, err = regexp.Compile(allowlistRegex)
		if err != nil {
			return nil, fmt.Errorf("invalid allowlist pattern: %w", err)
		}
	}

	return detector, nil
}

// Name returns the unique name of this guardrail instance.
func (p *PIIDetector) Name() string {
	return p.name
}

// Type returns the guardrail type for PII detection.
func (p *PIIDetector) Type() guardrail.GuardrailType {
	return guardrail.GuardrailTypePII
}

// CheckInput inspects input content for PII and handles it based on the configured action.
func (p *PIIDetector) CheckInput(ctx context.Context, input guardrail.GuardrailInput) (guardrail.GuardrailResult, error) {
	return p.checkContent(input.Content)
}

// CheckOutput inspects output content for PII and handles it based on the configured action.
func (p *PIIDetector) CheckOutput(ctx context.Context, output guardrail.GuardrailOutput) (guardrail.GuardrailResult, error) {
	return p.checkContent(output.Content)
}

// checkContent performs PII detection on the given content.
func (p *PIIDetector) checkContent(content string) (guardrail.GuardrailResult, error) {
	if content == "" {
		return guardrail.NewAllowResult(), nil
	}

	// Detect PII
	matches := p.detectPII(content)
	if len(matches) == 0 {
		return guardrail.NewAllowResult(), nil
	}

	// Handle based on action
	switch p.config.Action {
	case guardrail.GuardrailActionBlock:
		reasons := make([]string, 0, len(matches))
		for _, match := range matches {
			reasons = append(reasons, fmt.Sprintf("%s detected", match.Pattern))
		}
		return guardrail.NewBlockResult(fmt.Sprintf("PII detected: %s", strings.Join(reasons, ", "))), nil

	case guardrail.GuardrailActionRedact:
		redacted := p.redactPII(content)
		return guardrail.NewRedactResult("PII redacted", redacted), nil

	case guardrail.GuardrailActionWarn:
		reasons := make([]string, 0, len(matches))
		for _, match := range matches {
			reasons = append(reasons, fmt.Sprintf("%s detected", match.Pattern))
		}
		return guardrail.NewWarnResult(fmt.Sprintf("PII detected: %s", strings.Join(reasons, ", "))), nil

	default:
		return guardrail.NewAllowResult(), nil
	}
}

// detectPII finds all PII in content and returns matches.
func (p *PIIDetector) detectPII(content string) []piiMatch {
	var matches []piiMatch

	// Check built-in patterns
	for pattern, regex := range p.patterns {
		allMatches := regex.FindAllStringIndex(content, -1)
		for _, match := range allMatches {
			matchStr := content[match[0]:match[1]]

			// Skip if in allowlist
			if p.allowlistPattern != nil && p.allowlistPattern.MatchString(matchStr) {
				continue
			}

			matches = append(matches, piiMatch{
				Pattern: pattern,
				Match:   matchStr,
				Start:   match[0],
				End:     match[1],
			})
		}
	}

	// Check custom patterns
	for name, regex := range p.customPatterns {
		allMatches := regex.FindAllStringIndex(content, -1)
		for _, match := range allMatches {
			matchStr := content[match[0]:match[1]]

			// Skip if in allowlist
			if p.allowlistPattern != nil && p.allowlistPattern.MatchString(matchStr) {
				continue
			}

			matches = append(matches, piiMatch{
				Pattern: PIIPattern(name),
				Match:   matchStr,
				Start:   match[0],
				End:     match[1],
			})
		}
	}

	return matches
}

// redactPII replaces PII with placeholders like [REDACTED-SSN].
func (p *PIIDetector) redactPII(content string) string {
	result := content

	// Redact built-in patterns
	for pattern, regex := range p.patterns {
		replacement := fmt.Sprintf("[REDACTED-%s]", strings.ToUpper(string(pattern)))
		result = regex.ReplaceAllStringFunc(result, func(match string) string {
			// Check allowlist
			if p.allowlistPattern != nil && p.allowlistPattern.MatchString(match) {
				return match
			}
			return replacement
		})
	}

	// Redact custom patterns
	for name, regex := range p.customPatterns {
		replacement := fmt.Sprintf("[REDACTED-%s]", strings.ToUpper(name))
		result = regex.ReplaceAllStringFunc(result, func(match string) string {
			// Check allowlist
			if p.allowlistPattern != nil && p.allowlistPattern.MatchString(match) {
				return match
			}
			return replacement
		})
	}

	return result
}
