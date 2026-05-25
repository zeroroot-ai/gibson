package providerconfig

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func randomTestKEK(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	_, err := rand.Read(k)
	require.NoError(t, err)
	return k
}

func TestNewPostgresStore_InputValidation(t *testing.T) {
	kek := randomTestKEK(t)

	t.Run("nil pool returns error", func(t *testing.T) {
		_, err := NewPostgresStore(nil, kek)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "postgres pool cannot be nil")
	})

	t.Run("short KEK returns error", func(t *testing.T) {
		_, err := NewPostgresStore(nil, make([]byte, 16))
		require.Error(t, err)
		// Short KEK is caught first
		assert.Contains(t, err.Error(), "KEK must be 32 bytes")
	})
}

func TestSecretAAD_Consistency(t *testing.T) {
	k1 := rowKey("openai-prod")
	k2 := rowKey("openai-prod")
	assert.Equal(t, secretAAD(k1), secretAAD(k2), "same key must produce same AAD")

	k3 := rowKey("anthropic-prod")
	assert.NotEqual(t, secretAAD(k1), secretAAD(k3), "different names must produce different AAD")

	assert.NotEqual(t, secretAAD(providerDefaultKey), secretAAD(providerFallbackKey),
		"meta keys must produce distinct AAD")
}

func TestIsPgUniqueViolation(t *testing.T) {
	assert.False(t, isPgUniqueViolation(nil))
	assert.False(t, isPgUniqueViolation(ErrNotFound))
}

// Integration tests: require a real Postgres connection.
// Run with: go test -tags=integration -run TestPostgresStore_Integration
