package guardrail

import (
	"testing"
)

func TestGuardrailAction_Constants(t *testing.T) {
	tests := []struct {
		name     string
		action   GuardrailAction
		expected string
	}{
		{
			name:     "allow action",
			action:   GuardrailActionAllow,
			expected: "allow",
		},
		{
			name:     "block action",
			action:   GuardrailActionBlock,
			expected: "block",
		},
		{
			name:     "redact action",
			action:   GuardrailActionRedact,
			expected: "redact",
		},
		{
			name:     "warn action",
			action:   GuardrailActionWarn,
			expected: "warn",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.action) != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, tt.action)
			}
		})
	}
}

func TestGuardrailResult_IsBlocked(t *testing.T) {
	tests := []struct {
		name     string
		action   GuardrailAction
		expected bool
	}{
		{
			name:     "allow is not blocked",
			action:   GuardrailActionAllow,
			expected: false,
		},
		{
			name:     "block is blocked",
			action:   GuardrailActionBlock,
			expected: true,
		},
		{
			name:     "redact is not blocked",
			action:   GuardrailActionRedact,
			expected: false,
		},
		{
			name:     "warn is not blocked",
			action:   GuardrailActionWarn,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GuardrailResult{Action: tt.action}
			if result.IsBlocked() != tt.expected {
				t.Errorf("IsBlocked() = %v, expected %v", result.IsBlocked(), tt.expected)
			}
		})
	}
}

func TestGuardrailResult_IsRedact(t *testing.T) {
	tests := []struct {
		name     string
		action   GuardrailAction
		expected bool
	}{
		{
			name:     "allow is not redact",
			action:   GuardrailActionAllow,
			expected: false,
		},
		{
			name:     "block is not redact",
			action:   GuardrailActionBlock,
			expected: false,
		},
		{
			name:     "redact is redact",
			action:   GuardrailActionRedact,
			expected: true,
		},
		{
			name:     "warn is not redact",
			action:   GuardrailActionWarn,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GuardrailResult{Action: tt.action}
			if result.IsRedact() != tt.expected {
				t.Errorf("IsRedact() = %v, expected %v", result.IsRedact(), tt.expected)
			}
		})
	}
}

func TestGuardrailResult_AllowContinue(t *testing.T) {
	tests := []struct {
		name     string
		action   GuardrailAction
		expected bool
	}{
		{
			name:     "allow allows continue",
			action:   GuardrailActionAllow,
			expected: true,
		},
		{
			name:     "block does not allow continue",
			action:   GuardrailActionBlock,
			expected: false,
		},
		{
			name:     "redact does not allow continue",
			action:   GuardrailActionRedact,
			expected: false,
		},
		{
			name:     "warn allows continue",
			action:   GuardrailActionWarn,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GuardrailResult{Action: tt.action}
			if result.AllowContinue() != tt.expected {
				t.Errorf("AllowContinue() = %v, expected %v", result.AllowContinue(), tt.expected)
			}
		})
	}
}

func TestNewAllowResult(t *testing.T) {
	result := NewAllowResult()

	if result.Action != GuardrailActionAllow {
		t.Errorf("expected action to be allow, got %s", result.Action)
	}

	if result.Reason != "" {
		t.Errorf("expected reason to be empty, got %s", result.Reason)
	}

	if result.ModifiedContent != "" {
		t.Errorf("expected modified content to be empty, got %s", result.ModifiedContent)
	}

	if result.Metadata == nil {
		t.Error("expected metadata to be initialized")
	}

	if len(result.Metadata) != 0 {
		t.Errorf("expected metadata to be empty, got %d entries", len(result.Metadata))
	}
}

func TestNewBlockResult(t *testing.T) {
	tests := []struct {
		name   string
		reason string
	}{
		{
			name:   "block with reason",
			reason: "content violates policy",
		},
		{
			name:   "block with empty reason",
			reason: "",
		},
		{
			name:   "block with long reason",
			reason: "this is a very long reason that explains in detail why the operation was blocked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewBlockResult(tt.reason)

			if result.Action != GuardrailActionBlock {
				t.Errorf("expected action to be block, got %s", result.Action)
			}

			if result.Reason != tt.reason {
				t.Errorf("expected reason to be %s, got %s", tt.reason, result.Reason)
			}

			if result.ModifiedContent != "" {
				t.Errorf("expected modified content to be empty, got %s", result.ModifiedContent)
			}

			if result.Metadata == nil {
				t.Error("expected metadata to be initialized")
			}
		})
	}
}

func TestNewRedactResult(t *testing.T) {
	tests := []struct {
		name            string
		reason          string
		modifiedContent string
	}{
		{
			name:            "redact with content",
			reason:          "PII detected",
			modifiedContent: "Hello [REDACTED]",
		},
		{
			name:            "redact with empty content",
			reason:          "sensitive data",
			modifiedContent: "",
		},
		{
			name:            "redact with complex content",
			reason:          "multiple PII instances",
			modifiedContent: "Name: [REDACTED], SSN: [REDACTED], Email: [REDACTED]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewRedactResult(tt.reason, tt.modifiedContent)

			if result.Action != GuardrailActionRedact {
				t.Errorf("expected action to be redact, got %s", result.Action)
			}

			if result.Reason != tt.reason {
				t.Errorf("expected reason to be %s, got %s", tt.reason, result.Reason)
			}

			if result.ModifiedContent != tt.modifiedContent {
				t.Errorf("expected modified content to be %s, got %s", tt.modifiedContent, result.ModifiedContent)
			}

			if result.Metadata == nil {
				t.Error("expected metadata to be initialized")
			}
		})
	}
}

func TestNewWarnResult(t *testing.T) {
	tests := []struct {
		name   string
		reason string
	}{
		{
			name:   "warn with reason",
			reason: "potentially risky operation",
		},
		{
			name:   "warn with empty reason",
			reason: "",
		},
		{
			name:   "warn with detailed reason",
			reason: "operation is allowed but may have security implications",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewWarnResult(tt.reason)

			if result.Action != GuardrailActionWarn {
				t.Errorf("expected action to be warn, got %s", result.Action)
			}

			if result.Reason != tt.reason {
				t.Errorf("expected reason to be %s, got %s", tt.reason, result.Reason)
			}

			if result.ModifiedContent != "" {
				t.Errorf("expected modified content to be empty, got %s", result.ModifiedContent)
			}

			if result.Metadata == nil {
				t.Error("expected metadata to be initialized")
			}
		})
	}
}

func TestGuardrailBlockedError_Error(t *testing.T) {
	tests := []struct {
		name          string
		guardrailName string
		guardrailType GuardrailType
		reason        string
		expectedMsg   string
	}{
		{
			name:          "content guardrail blocked",
			guardrailName: "ContentFilter",
			guardrailType: GuardrailTypeContent,
			reason:        "inappropriate content detected",
			expectedMsg:   "guardrail 'ContentFilter' (content) blocked operation: inappropriate content detected",
		},
		{
			name:          "PII guardrail blocked",
			guardrailName: "PIIDetector",
			guardrailType: GuardrailTypePII,
			reason:        "social security number detected",
			expectedMsg:   "guardrail 'PIIDetector' (pii) blocked operation: social security number detected",
		},
		{
			name:          "scope guardrail blocked",
			guardrailName: "ScopeValidator",
			guardrailType: GuardrailTypeScope,
			reason:        "operation outside allowed scope",
			expectedMsg:   "guardrail 'ScopeValidator' (scope) blocked operation: operation outside allowed scope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewGuardrailBlockedError(tt.guardrailName, tt.guardrailType, tt.reason)

			if err.Error() != tt.expectedMsg {
				t.Errorf("expected error message %q, got %q", tt.expectedMsg, err.Error())
			}

			if err.GuardrailName != tt.guardrailName {
				t.Errorf("expected guardrail name %s, got %s", tt.guardrailName, err.GuardrailName)
			}

			if err.GuardrailType != tt.guardrailType {
				t.Errorf("expected guardrail type %s, got %s", tt.guardrailType, err.GuardrailType)
			}

			if err.Reason != tt.reason {
				t.Errorf("expected reason %s, got %s", tt.reason, err.Reason)
			}

			if err.Metadata == nil {
				t.Error("expected metadata to be initialized")
			}
		})
	}
}

func TestGuardrailBlockedError_Unwrap(t *testing.T) {
	err := NewGuardrailBlockedError("TestGuardrail", GuardrailTypeContent, "test reason")

	unwrapped := err.Unwrap()
	if unwrapped != nil {
		t.Errorf("expected Unwrap() to return nil, got %v", unwrapped)
	}
}

func TestGuardrailType_Constants(t *testing.T) {
	tests := []struct {
		name          string
		guardrailType GuardrailType
		expected      string
	}{
		{
			name:          "scope type",
			guardrailType: GuardrailTypeScope,
			expected:      "scope",
		},
		{
			name:          "content type",
			guardrailType: GuardrailTypeContent,
			expected:      "content",
		},
		{
			name:          "rate type",
			guardrailType: GuardrailTypeRate,
			expected:      "rate",
		},
		{
			name:          "tool type",
			guardrailType: GuardrailTypeTool,
			expected:      "tool",
		},
		{
			name:          "PII type",
			guardrailType: GuardrailTypePII,
			expected:      "pii",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.guardrailType) != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, tt.guardrailType)
			}
		})
	}
}
