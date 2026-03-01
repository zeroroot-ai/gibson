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

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{
			name:     "empty string returns empty",
			input:    "",
			maxLen:   10,
			expected: "",
		},
		{
			name:     "string shorter than maxLen unchanged",
			input:    "short",
			maxLen:   10,
			expected: "short",
		},
		{
			name:     "string equal to maxLen unchanged",
			input:    "exactly10c",
			maxLen:   10,
			expected: "exactly10c",
		},
		{
			name:     "string longer than maxLen truncated with ellipsis",
			input:    "very long string here",
			maxLen:   10,
			expected: "very lo...",
		},
		{
			name:     "maxLen 0 returns empty",
			input:    "test",
			maxLen:   0,
			expected: "",
		},
		{
			name:     "maxLen 1 truncates without ellipsis",
			input:    "test",
			maxLen:   1,
			expected: "t",
		},
		{
			name:     "maxLen 2 truncates without ellipsis",
			input:    "test",
			maxLen:   2,
			expected: "te",
		},
		{
			name:     "maxLen 3 truncates without ellipsis",
			input:    "test",
			maxLen:   3,
			expected: "tes",
		},
		{
			name:     "maxLen 4 adds ellipsis",
			input:    "testing",
			maxLen:   4,
			expected: "t...",
		},
		{
			name:     "maxLen 5 adds ellipsis",
			input:    "testing string",
			maxLen:   5,
			expected: "te...",
		},
		{
			name:     "long string with maxLen 20",
			input:    "this is a very long string that needs truncation",
			maxLen:   20,
			expected: "this is a very lo...",
		},
		{
			name:     "exactly maxLen+1 triggers truncation",
			input:    "12345678901",
			maxLen:   10,
			expected: "1234567...",
		},
		{
			name:     "unicode characters (byte slicing)",
			input:    "Hello World Test",
			maxLen:   10,
			expected: "Hello W...",
		},
		{
			name:     "single character string with maxLen 1",
			input:    "a",
			maxLen:   1,
			expected: "a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TruncateString(tt.input, tt.maxLen)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRedactToken(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string returns redacted",
			input:    "",
			expected: "[REDACTED]",
		},
		{
			name:     "very short token fully redacted",
			input:    "short",
			expected: "[REDACTED]",
		},
		{
			name:     "token length 9 fully redacted",
			input:    "123456789",
			expected: "[REDACTED]",
		},
		{
			name:     "token length 10 shows first 4 and last 4",
			input:    "1234567890",
			expected: "1234***7890",
		},
		{
			name:     "token length 11",
			input:    "12345678901",
			expected: "1234***8901",
		},
		{
			name:     "realistic API key",
			input:    "sk_live_abc123def456ghi789jkl",
			expected: "sk_l***9jkl",
		},
		{
			name:     "AWS-style key",
			input:    "AKIAIOSFODNN7EXAMPLE",
			expected: "AKIA***MPLE",
		},
		{
			name:     "long token",
			input:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
			expected: "eyJh***IyfQ",
		},
		{
			name:     "exactly 10 chars",
			input:    "abcdefghij",
			expected: "abcd***ghij",
		},
		{
			name:     "single character token",
			input:    "a",
			expected: "[REDACTED]",
		},
		{
			name:     "unicode token (byte slicing, not rune slicing)",
			input:    "abcd1234567890xyz",
			expected: "abcd***0xyz",
		},
		{
			name:     "token with special characters",
			input:    "sk-proj-1234567890abcdefghijk",
			expected: "sk-p***hijk",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RedactToken(tt.input)
			assert.Equal(t, tt.expected, result)
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

func BenchmarkTruncateString(b *testing.B) {
	s := "this is a very long string that needs truncation for logging purposes"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		TruncateString(s, 20)
	}
}

func BenchmarkRedactToken(b *testing.B) {
	token := "sk_live_abc123def456ghi789jkl012"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RedactToken(token)
	}
}
