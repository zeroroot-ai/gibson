package llm

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zeroroot-ai/gibson/internal/types"
)

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "non-GibsonError",
			err:      errors.New("regular error"),
			expected: false,
		},
		{
			name:     "network error (retryable)",
			err:      NewNetworkError("connection failed", nil),
			expected: true,
		},
		{
			name:     "network timeout (retryable)",
			err:      &types.GibsonError{Code: ErrNetworkTimeout, Retryable: true},
			expected: true,
		},
		{
			name:     "rate limit (retryable)",
			err:      NewRateLimitError("test-provider"),
			expected: true,
		},
		{
			name:     "quota exceeded (retryable)",
			err:      &types.GibsonError{Code: ErrProviderQuotaExceeded, Retryable: true},
			expected: true,
		},
		{
			name:     "provider unavailable (retryable)",
			err:      NewProviderUnavailableError("test-provider", nil),
			expected: true,
		},
		{
			name:     "timeout (retryable)",
			err:      NewTimeoutError("request timeout"),
			expected: true,
		},
		{
			name:     "unauthorized (not retryable)",
			err:      &types.GibsonError{Code: ErrProviderUnauthorized},
			expected: false,
		},
		{
			name:     "invalid request (not retryable)",
			err:      NewInvalidRequestError("bad request"),
			expected: false,
		},
		{
			name:     "model not found (not retryable)",
			err:      NewModelNotFoundError("gpt-5"),
			expected: false,
		},
		{
			name:     "content filtered (not retryable)",
			err:      &types.GibsonError{Code: ErrContentFiltered},
			expected: false,
		},
		{
			name:     "context exceeded (not retryable)",
			err:      NewContextExceededError(10000, 8192),
			expected: false,
		},
		{
			name:     "context canceled (not retryable)",
			err:      &types.GibsonError{Code: ErrContextCanceled},
			expected: false,
		},
		{
			name:     "explicitly marked retryable",
			err:      &types.GibsonError{Code: ErrCompletionFailed, Retryable: true},
			expected: true,
		},
		{
			name:     "unknown error code (default not retryable)",
			err:      &types.GibsonError{Code: "UNKNOWN_CODE"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsRetryable(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewProviderNotFoundError(t *testing.T) {
	err := NewProviderNotFoundError("anthropic")

	assert.Equal(t, ErrProviderNotFound, err.Code)
	assert.Contains(t, err.Message, "anthropic")
	assert.False(t, err.Retryable)
}

func TestNewProviderUnavailableError(t *testing.T) {
	cause := errors.New("connection refused")
	err := NewProviderUnavailableError("openai", cause)

	assert.Equal(t, ErrProviderUnavailable, err.Code)
	assert.Contains(t, err.Message, "openai")
	assert.True(t, err.Retryable)
	assert.Equal(t, cause, err.Cause)
}

func TestNewRateLimitError(t *testing.T) {
	err := NewRateLimitError("anthropic")

	assert.Equal(t, ErrProviderRateLimited, err.Code)
	assert.Contains(t, err.Message, "anthropic")
	assert.True(t, err.Retryable)
}

func TestNewModelNotFoundError(t *testing.T) {
	err := NewModelNotFoundError("gpt-5-ultra")

	assert.Equal(t, ErrModelNotFound, err.Code)
	assert.Contains(t, err.Message, "gpt-5-ultra")
	assert.False(t, err.Retryable)
}

func TestNewContextExceededError(t *testing.T) {
	err := NewContextExceededError(10000, 8192)

	assert.Equal(t, ErrModelContextExceeded, err.Code)
	assert.Contains(t, err.Message, "10000")
	assert.Contains(t, err.Message, "8192")
	assert.False(t, err.Retryable)
}

func TestNewInvalidRequestError(t *testing.T) {
	err := NewInvalidRequestError("missing required field")

	assert.Equal(t, ErrInvalidRequest, err.Code)
	assert.Contains(t, err.Message, "missing required field")
	assert.False(t, err.Retryable)
}

func TestNewToolCallError(t *testing.T) {
	cause := errors.New("tool execution failed")
	err := NewToolCallError("get_weather", cause)

	assert.Equal(t, ErrToolCallFailed, err.Code)
	assert.Contains(t, err.Message, "get_weather")
	assert.Equal(t, cause, err.Cause)
	assert.False(t, err.Retryable)
}

func TestNewCompletionError(t *testing.T) {
	cause := errors.New("API error")
	err := NewCompletionError("failed to generate", cause)

	assert.Equal(t, ErrCompletionFailed, err.Code)
	assert.Contains(t, err.Message, "failed to generate")
	assert.Equal(t, cause, err.Cause)
	assert.False(t, err.Retryable)
}

func TestNewNetworkError(t *testing.T) {
	cause := errors.New("connection timeout")
	err := NewNetworkError("network unreachable", cause)

	assert.Equal(t, ErrNetworkFailed, err.Code)
	assert.Contains(t, err.Message, "network unreachable")
	assert.Equal(t, cause, err.Cause)
	assert.True(t, err.Retryable)
}

func TestNewTimeoutError(t *testing.T) {
	err := NewTimeoutError("request exceeded deadline")

	assert.Equal(t, ErrTimeoutExceeded, err.Code)
	assert.Contains(t, err.Message, "request exceeded deadline")
	assert.True(t, err.Retryable)
}

func TestErrorCodeConstants(t *testing.T) {
	// Verify error codes are properly namespaced with LLM_ prefix
	tests := []struct {
		name string
		code types.ErrorCode
	}{
		{"provider not found", ErrProviderNotFound},
		{"provider init failed", ErrProviderInitFailed},
		{"provider unavailable", ErrProviderUnavailable},
		{"provider unauthorized", ErrProviderUnauthorized},
		{"provider rate limited", ErrProviderRateLimited},
		{"provider quota exceeded", ErrProviderQuotaExceeded},
		{"model not found", ErrModelNotFound},
		{"model not supported", ErrModelNotSupported},
		{"model context exceeded", ErrModelContextExceeded},
		{"invalid request", ErrInvalidRequest},
		{"invalid message", ErrInvalidMessage},
		{"invalid temperature", ErrInvalidTemperature},
		{"invalid max tokens", ErrInvalidMaxTokens},
		{"invalid top p", ErrInvalidTopP},
		{"invalid tool", ErrInvalidTool},
		{"tool call failed", ErrToolCallFailed},
		{"tool not found", ErrToolNotFound},
		{"invalid tool args", ErrInvalidToolArgs},
		{"tool execution failed", ErrToolExecutionFailed},
		{"completion failed", ErrCompletionFailed},
		{"streaming failed", ErrStreamingFailed},
		{"content filtered", ErrContentFiltered},
		{"response truncated", ErrResponseTruncated},
		{"response parse failed", ErrResponseParseFailed},
		{"invalid response", ErrInvalidResponse},
		{"timeout exceeded", ErrTimeoutExceeded},
		{"context canceled", ErrContextCanceled},
		{"network failed", ErrNetworkFailed},
		{"network timeout", ErrNetworkTimeout},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify all codes start with LLM_
			assert.Contains(t, string(tt.code), "LLM_")
		})
	}
}

func TestErrorWrapping(t *testing.T) {
	cause := errors.New("underlying error")
	err := NewCompletionError("completion failed", cause)

	// Test error unwrapping
	assert.ErrorIs(t, err, cause)

	// Test error message includes cause
	assert.Contains(t, err.Error(), "underlying error")
}

func TestRetryableErrors(t *testing.T) {
	retryableErrors := []error{
		NewNetworkError("network error", nil),
		NewTimeoutError("timeout"),
		NewRateLimitError("test"),
		NewProviderUnavailableError("test", nil),
		&types.GibsonError{Code: ErrNetworkTimeout, Retryable: true},
		&types.GibsonError{Code: ErrProviderQuotaExceeded, Retryable: true},
	}

	for _, err := range retryableErrors {
		assert.True(t, IsRetryable(err), "expected %v to be retryable", err)
	}
}

func TestNonRetryableErrors(t *testing.T) {
	nonRetryableErrors := []error{
		NewProviderNotFoundError("test"),
		NewModelNotFoundError("test"),
		NewInvalidRequestError("test"),
		NewContextExceededError(100, 50),
		&types.GibsonError{Code: ErrProviderUnauthorized},
		&types.GibsonError{Code: ErrContentFiltered},
		&types.GibsonError{Code: ErrContextCanceled},
		&types.GibsonError{Code: ErrInvalidMessage},
		&types.GibsonError{Code: ErrInvalidTool},
	}

	for _, err := range nonRetryableErrors {
		assert.False(t, IsRetryable(err), "expected %v to not be retryable", err)
	}
}
