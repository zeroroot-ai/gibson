package state

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsNotFound(t *testing.T) {
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
			name:     "ErrNotFound",
			err:      ErrNotFound,
			expected: true,
		},
		{
			name:     "wrapped ErrNotFound",
			err:      errors.Join(ErrNotFound, errors.New("context")),
			expected: true,
		},
		{
			name:     "different error",
			err:      ErrConnectionFailed,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsNotFound(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestModuleError(t *testing.T) {
	underlyingErr := errors.New("module load failed")
	modErr := NewModuleError("search", underlyingErr)

	assert.NotNil(t, modErr)
	assert.Equal(t, "search", modErr.Module)
	assert.Equal(t, underlyingErr, modErr.Err)
	assert.Contains(t, modErr.Error(), "search")
	assert.Contains(t, modErr.Error(), "module load failed")

	// Test unwrap
	assert.Equal(t, underlyingErr, modErr.Unwrap())
	assert.True(t, errors.Is(modErr, underlyingErr))
}

func TestConnectionError(t *testing.T) {
	underlyingErr := errors.New("connection timeout")

	t.Run("with address", func(t *testing.T) {
		connErr := NewConnectionError("dial", "localhost:6379", underlyingErr)

		assert.NotNil(t, connErr)
		assert.Equal(t, "dial", connErr.Operation)
		assert.Equal(t, "localhost:6379", connErr.Addr)
		assert.Equal(t, underlyingErr, connErr.Err)
		assert.Contains(t, connErr.Error(), "dial")
		assert.Contains(t, connErr.Error(), "localhost:6379")
		assert.Contains(t, connErr.Error(), "connection timeout")

		// Test unwrap
		assert.Equal(t, underlyingErr, connErr.Unwrap())
		assert.True(t, errors.Is(connErr, underlyingErr))
	})

	t.Run("without address", func(t *testing.T) {
		connErr := NewConnectionError("ping", "", underlyingErr)

		assert.NotNil(t, connErr)
		assert.Equal(t, "ping", connErr.Operation)
		assert.Equal(t, "", connErr.Addr)
		assert.Contains(t, connErr.Error(), "ping")
		assert.NotContains(t, connErr.Error(), "to ")
	})
}

func TestErrorConstants(t *testing.T) {
	// Ensure error constants are defined and distinct
	assert.NotNil(t, ErrNotFound)
	assert.NotNil(t, ErrModuleNotAvailable)
	assert.NotNil(t, ErrConnectionFailed)

	assert.NotEqual(t, ErrNotFound, ErrModuleNotAvailable)
	assert.NotEqual(t, ErrNotFound, ErrConnectionFailed)
	assert.NotEqual(t, ErrModuleNotAvailable, ErrConnectionFailed)
}
