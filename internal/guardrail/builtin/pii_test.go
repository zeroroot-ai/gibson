package builtin

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/guardrail"
)

func TestPIIDetector_Name(t *testing.T) {
	detector, err := NewPIIDetector(PIIDetectorConfig{})
	require.NoError(t, err)
	assert.Equal(t, "pii_detector", detector.Name())
}

func TestPIIDetector_Type(t *testing.T) {
	detector, err := NewPIIDetector(PIIDetectorConfig{})
	require.NoError(t, err)
	assert.Equal(t, guardrail.GuardrailTypePII, detector.Type())
}

func TestPIIDetector_SSN(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name         string
		action       guardrail.GuardrailAction
		content      string
		expectAction guardrail.GuardrailAction
		expectRedact string
	}{
		{
			name:         "SSN detection - block",
			action:       guardrail.GuardrailActionBlock,
			content:      "My SSN is 123-45-6789",
			expectAction: guardrail.GuardrailActionBlock,
		},
		{
			name:         "SSN detection - redact",
			action:       guardrail.GuardrailActionRedact,
			content:      "My SSN is 123-45-6789 and yours is 987-65-4321",
			expectAction: guardrail.GuardrailActionRedact,
			expectRedact: "My SSN is [REDACTED-SSN] and yours is [REDACTED-SSN]",
		},
		{
			name:         "SSN detection - warn",
			action:       guardrail.GuardrailActionWarn,
			content:      "Contact: 123-45-6789",
			expectAction: guardrail.GuardrailActionWarn,
		},
		{
			name:         "No SSN - allow",
			action:       guardrail.GuardrailActionBlock,
			content:      "No sensitive data here",
			expectAction: guardrail.GuardrailActionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := PIIDetectorConfig{
				Action:          tt.action,
				EnabledPatterns: []string{"ssn"},
			}
			detector, err := NewPIIDetector(config)
			require.NoError(t, err)

			result, err := detector.CheckInput(ctx, guardrail.GuardrailInput{
				Content: tt.content,
			})
			require.NoError(t, err)
			assert.Equal(t, tt.expectAction, result.Action)

			if tt.expectAction == guardrail.GuardrailActionRedact {
				assert.Equal(t, tt.expectRedact, result.ModifiedContent)
			}

			if tt.expectAction == guardrail.GuardrailActionBlock {
				assert.Contains(t, result.Reason, "ssn detected")
			}
		})
	}
}

func TestPIIDetector_Email(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name         string
		content      string
		expectAction guardrail.GuardrailAction
		expectRedact string
	}{
		{
			name:         "Email detection",
			content:      "Contact me at user@example.com",
			expectAction: guardrail.GuardrailActionRedact,
			expectRedact: "Contact me at [REDACTED-EMAIL]",
		},
		{
			name:         "Multiple emails",
			content:      "Email alice@test.com or bob@company.org",
			expectAction: guardrail.GuardrailActionRedact,
			expectRedact: "Email [REDACTED-EMAIL] or [REDACTED-EMAIL]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := PIIDetectorConfig{
				Action:          guardrail.GuardrailActionRedact,
				EnabledPatterns: []string{"email"},
			}
			detector, err := NewPIIDetector(config)
			require.NoError(t, err)

			result, err := detector.CheckInput(ctx, guardrail.GuardrailInput{
				Content: tt.content,
			})
			require.NoError(t, err)
			assert.Equal(t, tt.expectAction, result.Action)
			assert.Equal(t, tt.expectRedact, result.ModifiedContent)
		})
	}
}

func TestPIIDetector_Phone(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name         string
		content      string
		expectRedact string
	}{
		{
			name:         "Phone with parentheses",
			content:      "Call (555) 123-4567",
			expectRedact: "Call [REDACTED-PHONE]",
		},
		{
			name:         "Phone with country code",
			content:      "Dial +1-555-123-4567",
			expectRedact: "Dial [REDACTED-PHONE]",
		},
		{
			name:         "Phone with dots",
			content:      "Phone: 555.123.4567",
			expectRedact: "Phone: [REDACTED-PHONE]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := PIIDetectorConfig{
				Action:          guardrail.GuardrailActionRedact,
				EnabledPatterns: []string{"phone"},
			}
			detector, err := NewPIIDetector(config)
			require.NoError(t, err)

			result, err := detector.CheckInput(ctx, guardrail.GuardrailInput{
				Content: tt.content,
			})
			require.NoError(t, err)
			assert.Equal(t, guardrail.GuardrailActionRedact, result.Action)
			assert.Equal(t, tt.expectRedact, result.ModifiedContent)
		})
	}
}

func TestPIIDetector_CreditCard(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name         string
		content      string
		expectRedact string
	}{
		{
			name:         "Visa card",
			content:      "Card: 4111111111111111",
			expectRedact: "Card: [REDACTED-CREDIT_CARD]",
		},
		{
			name:         "Mastercard",
			content:      "Pay with 5500000000000004",
			expectRedact: "Pay with [REDACTED-CREDIT_CARD]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := PIIDetectorConfig{
				Action:          guardrail.GuardrailActionRedact,
				EnabledPatterns: []string{"credit_card"},
			}
			detector, err := NewPIIDetector(config)
			require.NoError(t, err)

			result, err := detector.CheckInput(ctx, guardrail.GuardrailInput{
				Content: tt.content,
			})
			require.NoError(t, err)
			assert.Equal(t, guardrail.GuardrailActionRedact, result.Action)
			assert.Equal(t, tt.expectRedact, result.ModifiedContent)
		})
	}
}

func TestPIIDetector_IPAddress(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name         string
		content      string
		expectRedact string
	}{
		{
			name:         "IPv4 address",
			content:      "Server at 192.168.1.1",
			expectRedact: "Server at [REDACTED-IP_ADDRESS]",
		},
		{
			name:         "Public IP",
			content:      "Connect to 8.8.8.8",
			expectRedact: "Connect to [REDACTED-IP_ADDRESS]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := PIIDetectorConfig{
				Action:          guardrail.GuardrailActionRedact,
				EnabledPatterns: []string{"ip_address"},
			}
			detector, err := NewPIIDetector(config)
			require.NoError(t, err)

			result, err := detector.CheckInput(ctx, guardrail.GuardrailInput{
				Content: tt.content,
			})
			require.NoError(t, err)
			assert.Equal(t, guardrail.GuardrailActionRedact, result.Action)
			assert.Equal(t, tt.expectRedact, result.ModifiedContent)
		})
	}
}

func TestPIIDetector_MultiplePIITypes(t *testing.T) {
	ctx := context.Background()

	config := PIIDetectorConfig{
		Action: guardrail.GuardrailActionRedact,
		// No enabled patterns means all are enabled
	}
	detector, err := NewPIIDetector(config)
	require.NoError(t, err)

	content := "Contact: user@example.com, SSN: 123-45-6789, Phone: (555) 123-4567"
	result, err := detector.CheckInput(ctx, guardrail.GuardrailInput{
		Content: content,
	})

	require.NoError(t, err)
	assert.Equal(t, guardrail.GuardrailActionRedact, result.Action)
	assert.Contains(t, result.ModifiedContent, "[REDACTED-EMAIL]")
	assert.Contains(t, result.ModifiedContent, "[REDACTED-SSN]")
	assert.Contains(t, result.ModifiedContent, "[REDACTED-PHONE]")
}

func TestPIIDetector_CustomPatterns(t *testing.T) {
	ctx := context.Background()

	config := PIIDetectorConfig{
		Action:          guardrail.GuardrailActionRedact,
		EnabledPatterns: []string{}, // Disable built-in patterns
		CustomPatterns: map[string]string{
			"employee_id": `EMP-\d{6}`,
		},
	}
	detector, err := NewPIIDetector(config)
	require.NoError(t, err)

	content := "Employee ID: EMP-123456"
	result, err := detector.CheckInput(ctx, guardrail.GuardrailInput{
		Content: content,
	})

	require.NoError(t, err)
	assert.Equal(t, guardrail.GuardrailActionRedact, result.Action)
	assert.Equal(t, "Employee ID: [REDACTED-EMPLOYEE_ID]", result.ModifiedContent)
}

func TestPIIDetector_InvalidCustomPattern(t *testing.T) {
	config := PIIDetectorConfig{
		Action: guardrail.GuardrailActionRedact,
		CustomPatterns: map[string]string{
			"invalid": "[invalid regex",
		},
	}
	_, err := NewPIIDetector(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid custom pattern")
}

func TestPIIDetector_Allowlist(t *testing.T) {
	ctx := context.Background()

	config := PIIDetectorConfig{
		Action:          guardrail.GuardrailActionRedact,
		EnabledPatterns: []string{"email"},
		AllowlistPatterns: []string{
			`noreply@example\.com`,
			`admin@example\.com`,
		},
	}
	detector, err := NewPIIDetector(config)
	require.NoError(t, err)

	content := "Contact noreply@example.com or user@test.com"
	result, err := detector.CheckInput(ctx, guardrail.GuardrailInput{
		Content: content,
	})

	require.NoError(t, err)
	assert.Equal(t, guardrail.GuardrailActionRedact, result.Action)
	// Allowlisted email should not be redacted
	assert.Contains(t, result.ModifiedContent, "noreply@example.com")
	// Non-allowlisted email should be redacted
	assert.Contains(t, result.ModifiedContent, "[REDACTED-EMAIL]")
}

func TestPIIDetector_BlockAction(t *testing.T) {
	ctx := context.Background()

	config := PIIDetectorConfig{
		Action:          guardrail.GuardrailActionBlock,
		EnabledPatterns: []string{"ssn"},
	}
	detector, err := NewPIIDetector(config)
	require.NoError(t, err)

	content := "SSN: 123-45-6789"
	result, err := detector.CheckInput(ctx, guardrail.GuardrailInput{
		Content: content,
	})

	require.NoError(t, err)
	assert.Equal(t, guardrail.GuardrailActionBlock, result.Action)
	assert.False(t, result.AllowContinue())
	assert.Contains(t, strings.ToLower(result.Reason), "pii detected")
}

func TestPIIDetector_WarnAction(t *testing.T) {
	ctx := context.Background()

	config := PIIDetectorConfig{
		Action:          guardrail.GuardrailActionWarn,
		EnabledPatterns: []string{"email"},
	}
	detector, err := NewPIIDetector(config)
	require.NoError(t, err)

	content := "Email: user@example.com"
	result, err := detector.CheckInput(ctx, guardrail.GuardrailInput{
		Content: content,
	})

	require.NoError(t, err)
	assert.Equal(t, guardrail.GuardrailActionWarn, result.Action)
	assert.True(t, result.AllowContinue())
	assert.Contains(t, strings.ToLower(result.Reason), "pii detected")
}

func TestPIIDetector_NoPII(t *testing.T) {
	ctx := context.Background()

	config := PIIDetectorConfig{
		Action: guardrail.GuardrailActionBlock,
	}
	detector, err := NewPIIDetector(config)
	require.NoError(t, err)

	content := "This is a clean message with no PII"
	result, err := detector.CheckInput(ctx, guardrail.GuardrailInput{
		Content: content,
	})

	require.NoError(t, err)
	assert.Equal(t, guardrail.GuardrailActionAllow, result.Action)
	assert.True(t, result.AllowContinue())
}

func TestPIIDetector_EmptyContent(t *testing.T) {
	ctx := context.Background()

	config := PIIDetectorConfig{
		Action: guardrail.GuardrailActionBlock,
	}
	detector, err := NewPIIDetector(config)
	require.NoError(t, err)

	result, err := detector.CheckInput(ctx, guardrail.GuardrailInput{
		Content: "",
	})

	require.NoError(t, err)
	assert.Equal(t, guardrail.GuardrailActionAllow, result.Action)
}

func TestPIIDetector_CheckOutput(t *testing.T) {
	ctx := context.Background()

	config := PIIDetectorConfig{
		Action:          guardrail.GuardrailActionRedact,
		EnabledPatterns: []string{"email"},
	}
	detector, err := NewPIIDetector(config)
	require.NoError(t, err)

	output := guardrail.GuardrailOutput{
		Content: "Results: user@example.com",
	}

	result, err := detector.CheckOutput(ctx, output)
	require.NoError(t, err)
	assert.Equal(t, guardrail.GuardrailActionRedact, result.Action)
	assert.Contains(t, result.ModifiedContent, "[REDACTED-EMAIL]")
}

func TestPIIDetector_DefaultAction(t *testing.T) {
	// Test that default action is redact when not specified
	config := PIIDetectorConfig{
		EnabledPatterns: []string{"ssn"},
	}
	detector, err := NewPIIDetector(config)
	require.NoError(t, err)

	ctx := context.Background()
	content := "SSN: 123-45-6789"
	result, err := detector.CheckInput(ctx, guardrail.GuardrailInput{
		Content: content,
	})

	require.NoError(t, err)
	assert.Equal(t, guardrail.GuardrailActionRedact, result.Action)
}
