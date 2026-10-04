// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestComponentError_Error tests the Error method for ComponentError
func TestComponentError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ComponentError
		expected string
	}{
		{
			name: "WithoutCause",
			err: &ComponentError{
				Code:    ErrCodeComponentNotFound,
				Message: "component not found",
			},
			expected: "[COMPONENT_NOT_FOUND] component not found",
		},
		{
			name: "WithCause",
			err: &ComponentError{
				Code:    ErrCodeLoadFailed,
				Message: "failed to load",
				Cause:   errors.New("file not found"),
			},
			expected: "[LOAD_FAILED] failed to load: file not found",
		},
		{
			name: "WithComponent",
			err: &ComponentError{
				Code:      ErrCodeStartFailed,
				Message:   "failed to start",
				Component: "test-agent",
			},
			expected: "[START_FAILED] component=test-agent failed to start",
		},
		{
			name: "WithComponentAndCause",
			err: &ComponentError{
				Code:      ErrCodeExecutionFailed,
				Message:   "execution failed",
				Component: "test-tool",
				Cause:     errors.New("timeout"),
			},
			expected: "[EXECUTION_FAILED] component=test-tool execution failed: timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

// TestComponentError_Unwrap tests the Unwrap method for ComponentError
func TestComponentError_Unwrap(t *testing.T) {
	t.Run("WithCause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := &ComponentError{
			Code:    ErrCodeLoadFailed,
			Message: "failed",
			Cause:   cause,
		}
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("WithoutCause", func(t *testing.T) {
		err := &ComponentError{
			Code:    ErrCodeLoadFailed,
			Message: "failed",
		}
		assert.Nil(t, err.Unwrap())
	})
}

// TestComponentError_Is tests the Is method for ComponentError
func TestComponentError_Is(t *testing.T) {
	t.Run("SameCode", func(t *testing.T) {
		err1 := &ComponentError{Code: ErrCodeComponentNotFound}
		err2 := &ComponentError{Code: ErrCodeComponentNotFound}
		assert.True(t, err1.Is(err2))
	})

	t.Run("DifferentCode", func(t *testing.T) {
		err1 := &ComponentError{Code: ErrCodeComponentNotFound}
		err2 := &ComponentError{Code: ErrCodeLoadFailed}
		assert.False(t, err1.Is(err2))
	})

	t.Run("NotComponentError", func(t *testing.T) {
		err1 := &ComponentError{Code: ErrCodeComponentNotFound}
		err2 := errors.New("different error")
		assert.False(t, err1.Is(err2))
	})
}

// Should return same instance for chaining

// Should return same instance for chaining

// Should match by code

// Should not match different code

// Should match the wrapper's code

// Can also unwrap to find the base error
