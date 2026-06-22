package types

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestErrorCode_Constants(t *testing.T) {
	tests := []struct {
		name     string
		code     ErrorCode
		expected string
	}{
		// Configuration errors
		{"CONFIG_LOAD_FAILED", CONFIG_LOAD_FAILED, "CONFIG_LOAD_FAILED"},
		{"CONFIG_PARSE_FAILED", CONFIG_PARSE_FAILED, "CONFIG_PARSE_FAILED"},
		{"CONFIG_VALIDATION_FAILED", CONFIG_VALIDATION_FAILED, "CONFIG_VALIDATION_FAILED"},
		{"CONFIG_NOT_FOUND", CONFIG_NOT_FOUND, "CONFIG_NOT_FOUND"},

		// Database errors
		{"DB_OPEN_FAILED", DB_OPEN_FAILED, "DB_OPEN_FAILED"},
		{"DB_MIGRATION_FAILED", DB_MIGRATION_FAILED, "DB_MIGRATION_FAILED"},
		{"DB_QUERY_FAILED", DB_QUERY_FAILED, "DB_QUERY_FAILED"},
		{"DB_CONNECTION_LOST", DB_CONNECTION_LOST, "DB_CONNECTION_LOST"},

		// Cryptography errors
		{"CRYPTO_ENCRYPT_FAILED", CRYPTO_ENCRYPT_FAILED, "CRYPTO_ENCRYPT_FAILED"},
		{"CRYPTO_DECRYPT_FAILED", CRYPTO_DECRYPT_FAILED, "CRYPTO_DECRYPT_FAILED"},
		{"CRYPTO_KEY_GENERATION_FAILED", CRYPTO_KEY_GENERATION_FAILED, "CRYPTO_KEY_GENERATION_FAILED"},
		{"CRYPTO_KEY_NOT_FOUND", CRYPTO_KEY_NOT_FOUND, "CRYPTO_KEY_NOT_FOUND"},

		// Initialization errors
		{"INIT_DIRS_FAILED", INIT_DIRS_FAILED, "INIT_DIRS_FAILED"},
		{"INIT_CONFIG_FAILED", INIT_CONFIG_FAILED, "INIT_CONFIG_FAILED"},
		{"INIT_DB_FAILED", INIT_DB_FAILED, "INIT_DB_FAILED"},
		{"INIT_VALIDATION_FAILED", INIT_VALIDATION_FAILED, "INIT_VALIDATION_FAILED"},

		// Target errors
		{"TARGET_NOT_FOUND", TARGET_NOT_FOUND, "TARGET_NOT_FOUND"},
		{"TARGET_INVALID", TARGET_INVALID, "TARGET_INVALID"},
		{"TARGET_CONNECTION_FAILED", TARGET_CONNECTION_FAILED, "TARGET_CONNECTION_FAILED"},

		// Credential errors
		{"CREDENTIAL_NOT_FOUND", CREDENTIAL_NOT_FOUND, "CREDENTIAL_NOT_FOUND"},
		{"CREDENTIAL_INVALID", CREDENTIAL_INVALID, "CREDENTIAL_INVALID"},
		{"CREDENTIAL_EXPIRED", CREDENTIAL_EXPIRED, "CREDENTIAL_EXPIRED"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.code) != tt.expected {
				t.Errorf("ErrorCode = %v, want %v", tt.code, tt.expected)
			}
		})
	}
}

func TestGibsonError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *GibsonError
		contains []string
	}{
		{
			name: "simple error without cause",
			err:  NewError(CONFIG_LOAD_FAILED, "failed to load configuration"),
			contains: []string{
				"[CONFIG_LOAD_FAILED]",
				"failed to load configuration",
			},
		},
		{
			name: "error with cause",
			err:  WrapError(DB_QUERY_FAILED, "query execution failed", errors.New("connection timeout")),
			contains: []string{
				"[DB_QUERY_FAILED]",
				"query execution failed",
				"connection timeout",
			},
		},
		{
			name: "retryable error",
			err:  NewRetryableError(TARGET_CONNECTION_FAILED, "connection refused"),
			contains: []string{
				"[TARGET_CONNECTION_FAILED]",
				"connection refused",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errMsg := tt.err.Error()
			for _, substring := range tt.contains {
				if !strings.Contains(errMsg, substring) {
					t.Errorf("Error() = %v, want to contain %v", errMsg, substring)
				}
			}
		})
	}
}

func TestGibsonError_Unwrap(t *testing.T) {
	tests := []struct {
		name      string
		err       *GibsonError
		wantCause bool
	}{
		{
			name:      "error without cause",
			err:       NewError(CONFIG_PARSE_FAILED, "parse error"),
			wantCause: false,
		},
		{
			name:      "error with cause",
			err:       WrapError(CRYPTO_DECRYPT_FAILED, "decryption failed", errors.New("invalid key")),
			wantCause: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cause := tt.err.Unwrap()
			if tt.wantCause && cause == nil {
				t.Error("Unwrap() = nil, want non-nil cause")
			}
			if !tt.wantCause && cause != nil {
				t.Errorf("Unwrap() = %v, want nil", cause)
			}
		})
	}
}

func TestGibsonError_Is(t *testing.T) {
	baseErr := NewError(DB_CONNECTION_LOST, "connection lost")
	sameCodeErr := NewError(DB_CONNECTION_LOST, "different message")
	differentCodeErr := NewError(DB_QUERY_FAILED, "query failed")
	standardErr := errors.New("standard error")

	tests := []struct {
		name   string
		err    *GibsonError
		target error
		want   bool
	}{
		{
			name:   "same error code matches",
			err:    baseErr,
			target: sameCodeErr,
			want:   true,
		},
		{
			name:   "different error code does not match",
			err:    baseErr,
			target: differentCodeErr,
			want:   false,
		},
		{
			name:   "standard error does not match",
			err:    baseErr,
			target: standardErr,
			want:   false,
		},
		{
			name:   "wrapped error with same code matches",
			err:    WrapError(DB_CONNECTION_LOST, "wrapped", standardErr),
			target: baseErr,
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Is(tt.target); got != tt.want {
				t.Errorf("Is() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewError(t *testing.T) {
	err := NewError(INIT_DIRS_FAILED, "directory creation failed")

	if err.Code != INIT_DIRS_FAILED {
		t.Errorf("Code = %v, want %v", err.Code, INIT_DIRS_FAILED)
	}
	if err.Message != "directory creation failed" {
		t.Errorf("Message = %v, want %v", err.Message, "directory creation failed")
	}
	if err.Retryable {
		t.Error("Retryable = true, want false")
	}
	if err.Cause != nil {
		t.Errorf("Cause = %v, want nil", err.Cause)
	}
}

func TestNewRetryableError(t *testing.T) {
	err := NewRetryableError(TARGET_CONNECTION_FAILED, "network timeout")

	if err.Code != TARGET_CONNECTION_FAILED {
		t.Errorf("Code = %v, want %v", err.Code, TARGET_CONNECTION_FAILED)
	}
	if err.Message != "network timeout" {
		t.Errorf("Message = %v, want %v", err.Message, "network timeout")
	}
	if !err.Retryable {
		t.Error("Retryable = false, want true")
	}
	if err.Cause != nil {
		t.Errorf("Cause = %v, want nil", err.Cause)
	}
}

func TestWrapError(t *testing.T) {
	cause := fmt.Errorf("underlying error")
	err := WrapError(CRYPTO_KEY_NOT_FOUND, "key lookup failed", cause)

	if err.Code != CRYPTO_KEY_NOT_FOUND {
		t.Errorf("Code = %v, want %v", err.Code, CRYPTO_KEY_NOT_FOUND)
	}
	if err.Message != "key lookup failed" {
		t.Errorf("Message = %v, want %v", err.Message, "key lookup failed")
	}
	if err.Retryable {
		t.Error("Retryable = true, want false")
	}
	if err.Cause != cause {
		t.Errorf("Cause = %v, want %v", err.Cause, cause)
	}
}

func TestGibsonError_ErrorsIsCompatibility(t *testing.T) {
	// Test that GibsonError works correctly with errors.Is()
	originalErr := errors.New("original error")
	wrappedErr := WrapError(DB_QUERY_FAILED, "database query failed", originalErr)

	// Should be able to unwrap to original error
	if !errors.Is(wrappedErr, originalErr) {
		t.Error("errors.Is() should find wrapped original error")
	}

	// Should match by error code
	sameCodeErr := NewError(DB_QUERY_FAILED, "different message")
	if !errors.Is(wrappedErr, sameCodeErr) {
		t.Error("errors.Is() should match by error code")
	}

	// Should not match different code
	differentCodeErr := NewError(DB_OPEN_FAILED, "open failed")
	if errors.Is(wrappedErr, differentCodeErr) {
		t.Error("errors.Is() should not match different error code")
	}
}

func TestGibsonError_ErrorsAsCompatibility(t *testing.T) {
	// Test that GibsonError works correctly with errors.As()
	err := WrapError(CREDENTIAL_EXPIRED, "token expired", errors.New("jwt expired"))

	var gibsonErr *GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatal("errors.As() should extract GibsonError")
	}

	if gibsonErr.Code != CREDENTIAL_EXPIRED {
		t.Errorf("extracted Code = %v, want %v", gibsonErr.Code, CREDENTIAL_EXPIRED)
	}
	if gibsonErr.Message != "token expired" {
		t.Errorf("extracted Message = %v, want %v", gibsonErr.Message, "token expired")
	}
}

// Benchmark error creation
func BenchmarkNewError(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewError(CONFIG_LOAD_FAILED, "configuration load failed")
	}
}

func BenchmarkWrapError(b *testing.B) {
	cause := errors.New("underlying error")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = WrapError(DB_QUERY_FAILED, "query failed", cause)
	}
}

func BenchmarkError(b *testing.B) {
	err := WrapError(CRYPTO_DECRYPT_FAILED, "decryption failed", errors.New("invalid key"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = err.Error()
	}
}
