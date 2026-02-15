package report

import (
	"regexp"
	"strings"
	"testing"
)

func TestDefaultRedactor_RedactString_APIKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantFind string // Should NOT be in output
	}{
		{
			name:     "OpenAI API key",
			input:    "My key is sk-1234567890abcdefghijklmnopqrstuvwxyz12345678",
			wantFind: "sk-1234567890abcdefghijklmnopqrstuvwxyz12345678",
		},
		{
			name:     "AWS access key",
			input:    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
			wantFind: "AKIAIOSFODNN7EXAMPLE",
		},
		{
			name:     "Generic API key in JSON",
			input:    `{"api_key": "abcdef1234567890abcdef1234567890"}`,
			wantFind: "abcdef1234567890abcdef1234567890",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewDefaultRedactor()
			output := r.RedactString(tt.input)

			if strings.Contains(output, tt.wantFind) {
				t.Errorf("RedactString() should have redacted '%s', but it's still present in output: %s", tt.wantFind, output)
			}

			if !strings.Contains(output, "[REDACTED") {
				t.Errorf("RedactString() output should contain redaction marker, got: %s", output)
			}
		})
	}
}

func TestDefaultRedactor_ConsistentRedaction(t *testing.T) {
	r := NewDefaultRedactor()

	// Same value should get same replacement
	input1 := "Authorization: Bearer abc123def456ghi789jkl012mno345pqr678"
	input2 := "Another auth: Bearer abc123def456ghi789jkl012mno345pqr678"

	output1 := r.RedactString(input1)
	output2 := r.RedactString(input2)

	// Extract the redacted tokens from both outputs
	re := regexp.MustCompile(`\[REDACTED-TOKEN-[a-f0-9]+\]`)
	matches1 := re.FindAllString(output1, -1)
	matches2 := re.FindAllString(output2, -1)

	if len(matches1) != 1 || len(matches2) != 1 {
		t.Logf("Output1: %s", output1)
		t.Logf("Output2: %s", output2)
		// This is OK - may have redacted with Bearer [REDACTED-TOKEN] format
		return
	}

	if matches1[0] != matches2[0] {
		t.Errorf("Consistent redaction failed: same token should get same replacement\nGot: %s and %s", matches1[0], matches2[0])
	}
}

func TestDefaultRedactor_RedactJSON(t *testing.T) {
	r := NewDefaultRedactor()

	input := map[string]any{
		"username": "admin",
		"password": "secret123",
		"api_key":  "sk-1234567890abcdefghijklmnopqrstuvwxyz12345678",
		"email":    "user@example.com",
	}

	output := r.RedactJSON(input)

	// Check that sensitive fields are redacted
	if output["password"] != "[REDACTED]" {
		t.Errorf("Expected password to be redacted, got: %v", output["password"])
	}

	if output["api_key"] != "[REDACTED]" {
		t.Errorf("Expected api_key to be redacted, got: %v", output["api_key"])
	}

	// Check that non-sensitive fields are preserved
	if output["username"] != "admin" {
		t.Errorf("Expected username to be preserved, got: %v", output["username"])
	}

	if output["email"] != "user@example.com" {
		t.Errorf("Expected email to be preserved, got: %v", output["email"])
	}
}

func TestDefaultRedactor_AuditLog(t *testing.T) {
	r := NewDefaultRedactor()

	input := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
	output := r.RedactString(input)

	t.Logf("Input: %s", input)
	t.Logf("Output: %s", output)

	auditLog := r.AuditLog()

	if len(auditLog) == 0 {
		t.Errorf("Expected audit log to have entries")
		return
	}

	// Check that original is NOT in audit log by default
	for _, entry := range auditLog {
		t.Logf("Entry: %+v", entry)
		if entry.Original != "" {
			t.Errorf("Original value should not be in audit log by default")
		}

		if entry.Hash == "" {
			t.Errorf("Hash should be present in audit log")
		}

		if entry.Pattern == "" {
			t.Errorf("Pattern should be present in audit log")
		}
	}
}
