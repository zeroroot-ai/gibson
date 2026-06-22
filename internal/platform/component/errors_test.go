package component

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// TestComponentError_WithContext tests the WithContext method
func TestComponentError_WithContext(t *testing.T) {
	err := &ComponentError{
		Code:    ErrCodeLoadFailed,
		Message: "failed",
	}

	result := err.WithContext("key", "value")
	assert.Same(t, err, result) // Should return same instance for chaining
	assert.NotNil(t, err.Context)
	assert.Equal(t, "value", err.Context["key"])
}

// TestComponentError_WithComponent tests the WithComponent method
func TestComponentError_WithComponent(t *testing.T) {
	err := &ComponentError{
		Code:    ErrCodeLoadFailed,
		Message: "failed",
	}

	result := err.WithComponent("test-agent")
	assert.Same(t, err, result) // Should return same instance for chaining
	assert.Equal(t, "test-agent", err.Component)
}

// TestNewComponentError tests the NewComponentError function
func TestNewComponentError(t *testing.T) {
	err := NewComponentError(ErrCodeComponentNotFound, "not found")
	assert.NotNil(t, err)
	assert.Equal(t, ErrCodeComponentNotFound, err.Code)
	assert.Equal(t, "not found", err.Message)
	assert.False(t, err.Retryable)
	assert.NotNil(t, err.Context)
}

// TestNewRetryableComponentError tests the NewRetryableComponentError function
func TestNewRetryableComponentError(t *testing.T) {
	err := NewRetryableComponentError(ErrCodeConnectionFailed, "connection failed")
	assert.NotNil(t, err)
	assert.Equal(t, ErrCodeConnectionFailed, err.Code)
	assert.Equal(t, "connection failed", err.Message)
	assert.True(t, err.Retryable)
	assert.NotNil(t, err.Context)
}

// TestWrapComponentError tests the WrapComponentError function
func TestWrapComponentError(t *testing.T) {
	cause := errors.New("underlying error")
	err := WrapComponentError(ErrCodeLoadFailed, "failed to load", cause)
	assert.NotNil(t, err)
	assert.Equal(t, ErrCodeLoadFailed, err.Code)
	assert.Equal(t, "failed to load", err.Message)
	assert.Equal(t, cause, err.Cause)
	assert.False(t, err.Retryable)
	assert.NotNil(t, err.Context)
}

// TestNewComponentNotFoundError tests the NewComponentNotFoundError function
func TestNewComponentNotFoundError(t *testing.T) {
	err := NewComponentNotFoundError("test-agent")
	assert.NotNil(t, err)
	assert.Equal(t, ErrCodeComponentNotFound, err.Code)
	assert.Contains(t, err.Message, "test-agent")
	assert.Equal(t, "test-agent", err.Component)
	assert.False(t, err.Retryable)
	assert.Equal(t, "test-agent", err.Context["component"])
}

// TestNewComponentExistsError tests the NewComponentExistsError function
func TestNewComponentExistsError(t *testing.T) {
	err := NewComponentExistsError("test-agent")
	assert.NotNil(t, err)
	assert.Equal(t, ErrCodeComponentExists, err.Code)
	assert.Contains(t, err.Message, "test-agent")
	assert.Equal(t, "test-agent", err.Component)
	assert.False(t, err.Retryable)
}

// TestNewInvalidManifestError tests the NewInvalidManifestError function
func TestNewInvalidManifestError(t *testing.T) {
	cause := errors.New("parse error")
	err := NewInvalidManifestError("invalid manifest", cause)
	assert.NotNil(t, err)
	assert.Equal(t, ErrCodeInvalidManifest, err.Code)
	assert.Equal(t, "invalid manifest", err.Message)
	assert.Equal(t, cause, err.Cause)
	assert.False(t, err.Retryable)
}

// TestNewManifestNotFoundError tests the NewManifestNotFoundError function
func TestNewManifestNotFoundError(t *testing.T) {
	err := NewManifestNotFoundError("/path/to/manifest.json")
	assert.NotNil(t, err)
	assert.Equal(t, ErrCodeManifestNotFound, err.Code)
	assert.Contains(t, err.Message, "/path/to/manifest.json")
	assert.False(t, err.Retryable)
}

// TestNewLoadFailedError tests the NewLoadFailedError function
func TestNewLoadFailedError(t *testing.T) {
	cause := errors.New("file error")

	t.Run("Retryable", func(t *testing.T) {
		err := NewLoadFailedError("test-agent", cause, true)
		assert.NotNil(t, err)
		assert.Equal(t, ErrCodeLoadFailed, err.Code)
		assert.Equal(t, "test-agent", err.Component)
		assert.Equal(t, cause, err.Cause)
		assert.True(t, err.Retryable)
	})

	t.Run("NonRetryable", func(t *testing.T) {
		err := NewLoadFailedError("test-agent", cause, false)
		assert.NotNil(t, err)
		assert.False(t, err.Retryable)
	})
}

// TestNewStartFailedError tests the NewStartFailedError function
func TestNewStartFailedError(t *testing.T) {
	cause := errors.New("start error")
	err := NewStartFailedError("test-agent", cause, true)
	assert.NotNil(t, err)
	assert.Equal(t, ErrCodeStartFailed, err.Code)
	assert.Equal(t, "test-agent", err.Component)
	assert.Equal(t, cause, err.Cause)
	assert.True(t, err.Retryable)
}

// TestNewStopFailedError tests the NewStopFailedError function
func TestNewStopFailedError(t *testing.T) {
	cause := errors.New("stop error")
	err := NewStopFailedError("test-agent", cause, false)
	assert.NotNil(t, err)
	assert.Equal(t, ErrCodeStopFailed, err.Code)
	assert.Equal(t, "test-agent", err.Component)
	assert.Equal(t, cause, err.Cause)
	assert.False(t, err.Retryable)
}

// TestNewValidationFailedError tests the NewValidationFailedError function
func TestNewValidationFailedError(t *testing.T) {
	cause := errors.New("validation error")
	err := NewValidationFailedError("validation failed", cause)
	assert.NotNil(t, err)
	assert.Equal(t, ErrCodeValidationFailed, err.Code)
	assert.Equal(t, cause, err.Cause)
	assert.False(t, err.Retryable)
}

// TestNewConnectionFailedError tests the NewConnectionFailedError function
func TestNewConnectionFailedError(t *testing.T) {
	cause := errors.New("network error")
	err := NewConnectionFailedError("test-agent", cause)
	assert.NotNil(t, err)
	assert.Equal(t, ErrCodeConnectionFailed, err.Code)
	assert.Equal(t, "test-agent", err.Component)
	assert.Equal(t, cause, err.Cause)
	assert.True(t, err.Retryable)
}

// TestNewExecutionFailedError tests the NewExecutionFailedError function
func TestNewExecutionFailedError(t *testing.T) {
	cause := errors.New("execution error")
	err := NewExecutionFailedError("test-agent", cause, true)
	assert.NotNil(t, err)
	assert.Equal(t, ErrCodeExecutionFailed, err.Code)
	assert.Equal(t, "test-agent", err.Component)
	assert.Equal(t, cause, err.Cause)
	assert.True(t, err.Retryable)
}

// TestNewInvalidKindError tests the NewInvalidKindError function
func TestNewInvalidKindError(t *testing.T) {
	err := NewInvalidKindError("")
	assert.NotNil(t, err)
	assert.Equal(t, ErrCodeInvalidKind, err.Code)
	assert.Contains(t, err.Message, "empty")
	assert.False(t, err.Retryable)
}

// TestNewInvalidSourceError tests the NewInvalidSourceError function
func TestNewInvalidSourceError(t *testing.T) {
	err := NewInvalidSourceError("invalid")
	assert.NotNil(t, err)
	assert.Equal(t, ErrCodeInvalidSource, err.Code)
	assert.Contains(t, err.Message, "invalid")
	assert.False(t, err.Retryable)
}

// TestNewInvalidStatusError tests the NewInvalidStatusError function
func TestNewInvalidStatusError(t *testing.T) {
	err := NewInvalidStatusError("invalid")
	assert.NotNil(t, err)
	assert.Equal(t, ErrCodeInvalidStatus, err.Code)
	assert.Contains(t, err.Message, "invalid")
	assert.False(t, err.Retryable)
}

// TestNewInvalidPathError tests the NewInvalidPathError function
func TestNewInvalidPathError(t *testing.T) {
	err := NewInvalidPathError("/invalid/path")
	assert.NotNil(t, err)
	assert.Equal(t, ErrCodeInvalidPath, err.Code)
	assert.Contains(t, err.Message, "/invalid/path")
	assert.False(t, err.Retryable)
}

// TestNewInvalidPortError tests the NewInvalidPortError function
func TestNewInvalidPortError(t *testing.T) {
	err := NewInvalidPortError(99999)
	assert.NotNil(t, err)
	assert.Equal(t, ErrCodeInvalidPort, err.Code)
	assert.Contains(t, err.Message, "99999")
	assert.False(t, err.Retryable)
}

// TestNewInvalidVersionError tests the NewInvalidVersionError function
func TestNewInvalidVersionError(t *testing.T) {
	err := NewInvalidVersionError("invalid")
	assert.NotNil(t, err)
	assert.Equal(t, ErrCodeInvalidVersion, err.Code)
	assert.Contains(t, err.Message, "invalid")
	assert.False(t, err.Retryable)
}

// TestNewDependencyFailedError tests the NewDependencyFailedError function
func TestNewDependencyFailedError(t *testing.T) {
	cause := errors.New("dependency error")
	err := NewDependencyFailedError("test-agent", "dep1", cause, true)
	assert.NotNil(t, err)
	assert.Equal(t, ErrCodeDependencyFailed, err.Code)
	assert.Equal(t, "test-agent", err.Component)
	assert.Equal(t, cause, err.Cause)
	assert.True(t, err.Retryable)
	assert.Equal(t, "dep1", err.Context["dependency"])
}

// TestNewIncompatibleVersionError tests the NewIncompatibleVersionError function
func TestNewIncompatibleVersionError(t *testing.T) {
	err := NewIncompatibleVersionError("test-agent", ">=2.0.0", "1.0.0")
	assert.NotNil(t, err)
	assert.Equal(t, ErrCodeIncompatibleVersion, err.Code)
	assert.Equal(t, "test-agent", err.Component)
	assert.Contains(t, err.Message, ">=2.0.0")
	assert.Contains(t, err.Message, "1.0.0")
	assert.False(t, err.Retryable)
}

// TestNewAlreadyRunningError tests the NewAlreadyRunningError function
func TestNewAlreadyRunningError(t *testing.T) {
	err := NewAlreadyRunningError("test-agent", 1234)
	assert.NotNil(t, err)
	assert.Equal(t, ErrCodeAlreadyRunning, err.Code)
	assert.Equal(t, "test-agent", err.Component)
	assert.Contains(t, err.Message, "1234")
	assert.False(t, err.Retryable)
}

// TestNewNotRunningError tests the NewNotRunningError function
func TestNewNotRunningError(t *testing.T) {
	err := NewNotRunningError("test-agent")
	assert.NotNil(t, err)
	assert.Equal(t, ErrCodeNotRunning, err.Code)
	assert.Equal(t, "test-agent", err.Component)
	assert.False(t, err.Retryable)
}

// TestNewTimeoutError tests the NewTimeoutError function
func TestNewTimeoutError(t *testing.T) {
	err := NewTimeoutError("test-agent", "start")
	assert.NotNil(t, err)
	assert.Equal(t, ErrCodeTimeout, err.Code)
	assert.Equal(t, "test-agent", err.Component)
	assert.Contains(t, err.Message, "start")
	assert.True(t, err.Retryable)
}

// TestNewPermissionDeniedError tests the NewPermissionDeniedError function
func TestNewPermissionDeniedError(t *testing.T) {
	err := NewPermissionDeniedError("test-agent", "execute")
	assert.NotNil(t, err)
	assert.Equal(t, ErrCodePermissionDenied, err.Code)
	assert.Equal(t, "test-agent", err.Component)
	assert.Contains(t, err.Message, "execute")
	assert.False(t, err.Retryable)
}

// TestNewUnsupportedOperationError tests the NewUnsupportedOperationError function
func TestNewUnsupportedOperationError(t *testing.T) {
	err := NewUnsupportedOperationError("test-agent", "restart")
	assert.NotNil(t, err)
	assert.Equal(t, ErrCodeUnsupportedOperation, err.Code)
	assert.Equal(t, "test-agent", err.Component)
	assert.Contains(t, err.Message, "restart")
	assert.False(t, err.Retryable)
}

// TestComponentError_ErrorChaining tests error chaining with errors.Is and errors.As
func TestComponentError_ErrorChaining(t *testing.T) {
	t.Run("ErrorsIs_DirectMatch", func(t *testing.T) {
		err := NewComponentNotFoundError("test")
		target := &ComponentError{Code: ErrCodeComponentNotFound}

		// Should match by code
		assert.True(t, errors.Is(err, target))
	})

	t.Run("ErrorsIs_NoMatch", func(t *testing.T) {
		err := NewComponentNotFoundError("test")
		target := &ComponentError{Code: ErrCodeLoadFailed}

		// Should not match different code
		assert.False(t, errors.Is(err, target))
	})

	t.Run("ErrorsIs_WrappedError", func(t *testing.T) {
		baseErr := NewComponentNotFoundError("test")
		wrappedErr := WrapComponentError(ErrCodeLoadFailed, "failed", baseErr)

		// Should match the wrapper's code
		assert.True(t, errors.Is(wrappedErr, &ComponentError{Code: ErrCodeLoadFailed}))

		// Can also unwrap to find the base error
		assert.True(t, errors.Is(wrappedErr, baseErr))
	})

	t.Run("ErrorsAs", func(t *testing.T) {
		baseErr := NewComponentNotFoundError("test")
		wrappedErr := WrapComponentError(ErrCodeLoadFailed, "failed", baseErr)

		var compErr *ComponentError
		require.True(t, errors.As(wrappedErr, &compErr))
		assert.Equal(t, ErrCodeLoadFailed, compErr.Code)
	})
}

// TestComponentError_MethodChaining tests method chaining
func TestComponentError_MethodChaining(t *testing.T) {
	err := NewComponentError(ErrCodeLoadFailed, "failed").
		WithComponent("test-agent").
		WithContext("path", "/test/path").
		WithContext("version", "1.0.0")

	assert.Equal(t, "test-agent", err.Component)
	assert.Equal(t, "/test/path", err.Context["path"])
	assert.Equal(t, "1.0.0", err.Context["version"])
}

// TestNewLogWriteError tests the NewLogWriteError function
func TestNewLogWriteError(t *testing.T) {
	cause := errors.New("disk full")
	err := NewLogWriteError("test-agent", cause)
	assert.NotNil(t, err)
	assert.Equal(t, ErrCodeLogWriteFailed, err.Code)
	assert.Equal(t, "test-agent", err.Component)
	assert.Equal(t, cause, err.Cause)
	assert.True(t, err.Retryable)
}

// TestNewLogRotationError tests the NewLogRotationError function
func TestNewLogRotationError(t *testing.T) {
	cause := errors.New("file locked")
	err := NewLogRotationError("test-tool", cause)
	assert.NotNil(t, err)
	assert.Equal(t, ErrCodeLogRotationFailed, err.Code)
	assert.Equal(t, "test-tool", err.Component)
	assert.Equal(t, cause, err.Cause)
	assert.True(t, err.Retryable)
}
