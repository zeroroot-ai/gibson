package builtin

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/guardrail"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
)

func TestScopeValidator_ExactDomainMatch(t *testing.T) {
	validator := NewScopeValidator(ScopeValidatorConfig{
		AllowedDomains: []string{"example.com"},
	})

	tests := []struct {
		name     string
		url      string
		expected guardrail.GuardrailAction
	}{
		{
			name:     "exact match allowed",
			url:      "https://example.com/path",
			expected: guardrail.GuardrailActionAllow,
		},
		{
			name:     "subdomain not allowed without wildcard",
			url:      "https://api.example.com/path",
			expected: guardrail.GuardrailActionBlock,
		},
		{
			name:     "different domain blocked",
			url:      "https://other.com/path",
			expected: guardrail.GuardrailActionBlock,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := guardrail.GuardrailInput{
				TargetInfo: &harness.TargetInfo{
					URL: tt.url,
				},
			}

			result, err := validator.CheckInput(context.Background(), input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Action != tt.expected {
				t.Errorf("expected action %s, got %s (reason: %s)", tt.expected, result.Action, result.Reason)
			}
		})
	}
}

func TestScopeValidator_WildcardDomainMatch(t *testing.T) {
	validator := NewScopeValidator(ScopeValidatorConfig{
		AllowedDomains: []string{"*.example.com"},
	})

	tests := []struct {
		name     string
		url      string
		expected guardrail.GuardrailAction
	}{
		{
			name:     "subdomain matches wildcard",
			url:      "https://api.example.com/path",
			expected: guardrail.GuardrailActionAllow,
		},
		{
			name:     "nested subdomain matches wildcard",
			url:      "https://api.v2.example.com/path",
			expected: guardrail.GuardrailActionAllow,
		},
		{
			name:     "parent domain doesn't match wildcard",
			url:      "https://example.com/path",
			expected: guardrail.GuardrailActionBlock,
		},
		{
			name:     "different domain blocked",
			url:      "https://example.org/path",
			expected: guardrail.GuardrailActionBlock,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := guardrail.GuardrailInput{
				TargetInfo: &harness.TargetInfo{
					URL: tt.url,
				},
			}

			result, err := validator.CheckInput(context.Background(), input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Action != tt.expected {
				t.Errorf("expected action %s, got %s (reason: %s)", tt.expected, result.Action, result.Reason)
			}
		})
	}
}

func TestScopeValidator_BlockedPathExactMatch(t *testing.T) {
	validator := NewScopeValidator(ScopeValidatorConfig{
		BlockedPaths: []string{"/admin", "/internal"},
	})

	tests := []struct {
		name     string
		url      string
		expected guardrail.GuardrailAction
	}{
		{
			name:     "exact blocked path",
			url:      "https://example.com/admin",
			expected: guardrail.GuardrailActionBlock,
		},
		{
			name:     "different path allowed",
			url:      "https://example.com/public",
			expected: guardrail.GuardrailActionAllow,
		},
		{
			name:     "subpath of blocked path allowed (no wildcard)",
			url:      "https://example.com/admin/users",
			expected: guardrail.GuardrailActionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := guardrail.GuardrailInput{
				TargetInfo: &harness.TargetInfo{
					URL: tt.url,
				},
			}

			result, err := validator.CheckInput(context.Background(), input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Action != tt.expected {
				t.Errorf("expected action %s, got %s (reason: %s)", tt.expected, result.Action, result.Reason)
			}
		})
	}
}

func TestScopeValidator_BlockedPathWildcardMatch(t *testing.T) {
	validator := NewScopeValidator(ScopeValidatorConfig{
		BlockedPaths: []string{"/admin/*", "/internal/*"},
	})

	tests := []struct {
		name     string
		url      string
		expected guardrail.GuardrailAction
	}{
		{
			name:     "wildcard path match",
			url:      "https://example.com/admin/users",
			expected: guardrail.GuardrailActionBlock,
		},
		{
			name:     "wildcard path nested match",
			url:      "https://example.com/admin/users/123",
			expected: guardrail.GuardrailActionBlock,
		},
		{
			name:     "different path allowed",
			url:      "https://example.com/public/users",
			expected: guardrail.GuardrailActionAllow,
		},
		{
			name:     "admin prefix but different path",
			url:      "https://example.com/administrator",
			expected: guardrail.GuardrailActionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := guardrail.GuardrailInput{
				TargetInfo: &harness.TargetInfo{
					URL: tt.url,
				},
			}

			result, err := validator.CheckInput(context.Background(), input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Action != tt.expected {
				t.Errorf("expected action %s, got %s (reason: %s)", tt.expected, result.Action, result.Reason)
			}
		})
	}
}

func TestScopeValidator_EmptyAllowedDomains(t *testing.T) {
	validator := NewScopeValidator(ScopeValidatorConfig{
		AllowedDomains: []string{},
	})

	tests := []struct {
		name string
		url  string
	}{
		{
			name: "any domain allowed when list is empty",
			url:  "https://example.com/path",
		},
		{
			name: "another domain allowed",
			url:  "https://other.com/path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := guardrail.GuardrailInput{
				TargetInfo: &harness.TargetInfo{
					URL: tt.url,
				},
			}

			result, err := validator.CheckInput(context.Background(), input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Action != guardrail.GuardrailActionAllow {
				t.Errorf("expected allow, got %s (reason: %s)", result.Action, result.Reason)
			}
		})
	}
}

func TestScopeValidator_EmptyBlockedPaths(t *testing.T) {
	validator := NewScopeValidator(ScopeValidatorConfig{
		BlockedPaths: []string{},
	})

	tests := []struct {
		name string
		url  string
	}{
		{
			name: "any path allowed when list is empty",
			url:  "https://example.com/admin",
		},
		{
			name: "another path allowed",
			url:  "https://example.com/internal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := guardrail.GuardrailInput{
				TargetInfo: &harness.TargetInfo{
					URL: tt.url,
				},
			}

			result, err := validator.CheckInput(context.Background(), input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Action != guardrail.GuardrailActionAllow {
				t.Errorf("expected allow, got %s (reason: %s)", result.Action, result.Reason)
			}
		})
	}
}

func TestScopeValidator_InvalidURL(t *testing.T) {
	validator := NewScopeValidator(ScopeValidatorConfig{
		AllowedDomains: []string{"example.com"},
	})

	input := guardrail.GuardrailInput{
		TargetInfo: &harness.TargetInfo{
			URL: "://invalid-url",
		},
	}

	result, err := validator.CheckInput(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Action != guardrail.GuardrailActionBlock {
		t.Errorf("expected block for invalid URL, got %s", result.Action)
	}
}

func TestScopeValidator_MissingURL(t *testing.T) {
	validator := NewScopeValidator(ScopeValidatorConfig{
		AllowedDomains: []string{"example.com"},
	})

	input := guardrail.GuardrailInput{
		TargetInfo: &harness.TargetInfo{
			URL: "",
		},
	}

	result, err := validator.CheckInput(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Missing URL should allow (no URL to validate)
	if result.Action != guardrail.GuardrailActionAllow {
		t.Errorf("expected allow for missing URL, got %s", result.Action)
	}
}

func TestScopeValidator_CheckOutput(t *testing.T) {
	validator := NewScopeValidator(ScopeValidatorConfig{
		AllowedDomains: []string{"example.com"},
	})

	output := guardrail.GuardrailOutput{
		Content: "some response",
	}

	result, err := validator.CheckOutput(context.Background(), output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Output should always be allowed for scope validator
	if result.Action != guardrail.GuardrailActionAllow {
		t.Errorf("expected allow for output, got %s", result.Action)
	}
}

func TestScopeValidator_Combined(t *testing.T) {
	validator := NewScopeValidator(ScopeValidatorConfig{
		AllowedDomains: []string{"example.com", "*.api.example.com"},
		BlockedPaths:   []string{"/admin/*", "/internal"},
	})

	tests := []struct {
		name     string
		url      string
		expected guardrail.GuardrailAction
		reason   string
	}{
		{
			name:     "allowed domain and path",
			url:      "https://example.com/public",
			expected: guardrail.GuardrailActionAllow,
		},
		{
			name:     "allowed domain but blocked path",
			url:      "https://example.com/admin/users",
			expected: guardrail.GuardrailActionBlock,
			reason:   "blocked path should take precedence",
		},
		{
			name:     "wildcard domain with allowed path",
			url:      "https://v1.api.example.com/users",
			expected: guardrail.GuardrailActionAllow,
		},
		{
			name:     "wildcard domain with blocked path",
			url:      "https://v1.api.example.com/internal",
			expected: guardrail.GuardrailActionBlock,
			reason:   "blocked path should apply to wildcard domains",
		},
		{
			name:     "disallowed domain",
			url:      "https://evil.com/public",
			expected: guardrail.GuardrailActionBlock,
			reason:   "domain not in allowed list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := guardrail.GuardrailInput{
				TargetInfo: &harness.TargetInfo{
					URL: tt.url,
				},
			}

			result, err := validator.CheckInput(context.Background(), input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Action != tt.expected {
				t.Errorf("%s: expected action %s, got %s (reason: %s)", tt.reason, tt.expected, result.Action, result.Reason)
			}
		})
	}
}

func TestScopeValidator_Name(t *testing.T) {
	validator := NewScopeValidator(ScopeValidatorConfig{})

	if validator.Name() != "scope-validator" {
		t.Errorf("expected name 'scope-validator', got %s", validator.Name())
	}
}

func TestScopeValidator_Type(t *testing.T) {
	validator := NewScopeValidator(ScopeValidatorConfig{})

	if validator.Type() != guardrail.GuardrailTypeScope {
		t.Errorf("expected type %s, got %s", guardrail.GuardrailTypeScope, validator.Type())
	}
}
