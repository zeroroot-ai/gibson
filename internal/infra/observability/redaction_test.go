// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package observability

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedact(t *testing.T) {
	tests := []struct {
		name     string
		input    []any
		expected []any
	}{
		{
			name:     "nil args returns nil",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty args returns empty",
			input:    []any{},
			expected: []any{},
		},
		{
			name:     "odd length args returns unchanged",
			input:    []any{"key1", "value1", "key2"},
			expected: []any{"key1", "value1", "key2"},
		},
		{
			name:     "single pair no sensitive data",
			input:    []any{"user", "alice"},
			expected: []any{"user", "alice"},
		},
		{
			name:     "password field is redacted",
			input:    []any{"user", "alice", "password", "secret123"},
			expected: []any{"user", "alice", "password", "[REDACTED]"},
		},
		{
			name:     "password case insensitive",
			input:    []any{"PASSWORD", "secret123"},
			expected: []any{"PASSWORD", "[REDACTED]"},
		},
		{
			name:     "password mixed case",
			input:    []any{"PaSsWoRd", "secret123"},
			expected: []any{"PaSsWoRd", "[REDACTED]"},
		},
		{
			name:     "secret field is redacted",
			input:    []any{"secret", "my-secret-value"},
			expected: []any{"secret", "[REDACTED]"},
		},
		{
			name:     "token field is redacted",
			input:    []any{"token", "sk_live_abc123"},
			expected: []any{"token", "[REDACTED]"},
		},
		{
			name:     "apikey field is redacted",
			input:    []any{"apikey", "AKIAIOSFODNN7EXAMPLE"},
			expected: []any{"apikey", "[REDACTED]"},
		},
		{
			name:     "api_key with underscore is redacted",
			input:    []any{"api_key", "AKIAIOSFODNN7EXAMPLE"},
			expected: []any{"api_key", "[REDACTED]"},
		},
		{
			name:     "ApiKey mixed case with underscore normalization",
			input:    []any{"Api_Key", "AKIAIOSFODNN7EXAMPLE"},
			expected: []any{"Api_Key", "[REDACTED]"},
		},
		{
			name:     "credential field is redacted",
			input:    []any{"credential", "user:pass"},
			expected: []any{"credential", "[REDACTED]"},
		},
		{
			name:     "authorization field is redacted",
			input:    []any{"authorization", "Bearer token123"},
			expected: []any{"authorization", "[REDACTED]"},
		},
		{
			name:     "bearer field is redacted",
			input:    []any{"bearer", "token123"},
			expected: []any{"bearer", "[REDACTED]"},
		},
		{
			name:     "privatekey field is redacted",
			input:    []any{"privatekey", "-----BEGIN PRIVATE KEY-----"},
			expected: []any{"privatekey", "[REDACTED]"},
		},
		{
			name:     "private_key with underscore is redacted",
			input:    []any{"private_key", "-----BEGIN PRIVATE KEY-----"},
			expected: []any{"private_key", "[REDACTED]"},
		},
		{
			name:     "PrivateKey mixed case is redacted",
			input:    []any{"PrivateKey", "-----BEGIN PRIVATE KEY-----"},
			expected: []any{"PrivateKey", "[REDACTED]"},
		},
		{
			name:     "secretkey field is redacted",
			input:    []any{"secretkey", "my-secret-key"},
			expected: []any{"secretkey", "[REDACTED]"},
		},
		{
			name:     "multiple sensitive fields",
			input:    []any{"user", "alice", "password", "pass123", "apikey", "key456", "count", 42},
			expected: []any{"user", "alice", "password", "[REDACTED]", "apikey", "[REDACTED]", "count", 42},
		},
		{
			name:     "non-string key skipped",
			input:    []any{123, "value", "password", "secret"},
			expected: []any{123, "value", "password", "[REDACTED]"},
		},
		{
			name:     "non-string value not affected",
			input:    []any{"password", 12345, "apikey", true, "count", 42},
			expected: []any{"password", "[REDACTED]", "apikey", "[REDACTED]", "count", 42},
		},
		{
			name:     "similar but not sensitive field not redacted",
			input:    []any{"password_hash", "hashed_value", "user", "alice"},
			expected: []any{"password_hash", "hashed_value", "user", "alice"},
		},
		{
			name:     "empty string value is redacted for sensitive fields",
			input:    []any{"password", ""},
			expected: []any{"password", "[REDACTED]"},
		},
		{
			name:     "all sensitive fields in one test",
			input:    []any{"password", "p", "secret", "s", "token", "t", "apikey", "a", "credential", "c", "authorization", "au", "bearer", "b", "privatekey", "pk", "secretkey", "sk"},
			expected: []any{"password", "[REDACTED]", "secret", "[REDACTED]", "token", "[REDACTED]", "apikey", "[REDACTED]", "credential", "[REDACTED]", "authorization", "[REDACTED]", "bearer", "[REDACTED]", "privatekey", "[REDACTED]", "secretkey", "[REDACTED]"},
		},
		{
			name:     "original slice not modified",
			input:    []any{"password", "secret123"},
			expected: []any{"password", "[REDACTED]"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Keep original for mutation check
			original := make([]any, len(tt.input))
			copy(original, tt.input)

			result := Redact(tt.input)
			assert.Equal(t, tt.expected, result)

			// Verify original not modified (except for nil and empty cases)
			if tt.input != nil && len(tt.input) > 0 {
				assert.Equal(t, original, tt.input, "original slice should not be modified")
			}
		})
	}
}

func TestNormalizeFieldName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "lowercase unchanged",
			input:    "password",
			expected: "password",
		},
		{
			name:     "uppercase converted to lowercase",
			input:    "PASSWORD",
			expected: "password",
		},
		{
			name:     "mixed case converted to lowercase",
			input:    "PaSsWoRd",
			expected: "password",
		},
		{
			name:     "underscores removed",
			input:    "api_key",
			expected: "apikey",
		},
		{
			name:     "multiple underscores removed",
			input:    "private__key",
			expected: "privatekey",
		},
		{
			name:     "mixed case with underscores",
			input:    "Api_Key",
			expected: "apikey",
		},
		{
			name:     "leading and trailing underscores",
			input:    "_token_",
			expected: "token",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "only underscores",
			input:    "___",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeFieldName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Benchmark tests for performance validation
func BenchmarkRedact(b *testing.B) {
	args := []any{
		"user", "alice",
		"password", "secret123",
		"apikey", "key456",
		"count", 42,
		"url", "https://example.com",
		"token", "bearer-token",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Redact(args)
	}
}

func TestRedact_LLMProviderCredentialKeys(t *testing.T) {
	// Every credential key any provider consumes must be redacted by the
	// logger. This mirrors providers.redactCredentialKeys().
	secrets := []string{
		"aws_access_key_id", "aws_secret_access_key", "aws_session_token",
		"cloudflare_account_id", "cloudflare_api_token",
		"cohere_api_key",
		"ernie_access_key", "ernie_secret_key",
		"huggingface_api_token",
		"mistral_api_key",
		"maritaca_api_key",
		"watsonx_api_key", "watsonx_project_id",
	}
	for _, key := range secrets {
		t.Run(key, func(t *testing.T) {
			args := []any{key, "cred-value-xyz", "unrelated", "ok"}
			got := Redact(args)
			// Find the pair and assert value is redacted.
			for i := 0; i < len(got); i += 2 {
				if got[i] == key {
					if got[i+1] != "[REDACTED]" {
						t.Fatalf("expected redaction for %q, got %v", key, got[i+1])
					}
				}
			}
		})
	}
}
