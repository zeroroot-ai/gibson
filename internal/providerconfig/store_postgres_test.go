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

func TestProviderConfigAAD_Consistency(t *testing.T) {
	aad1 := providerConfigAAD("openai", "prod-key")
	aad2 := providerConfigAAD("openai", "prod-key")
	assert.Equal(t, aad1, aad2)

	aad3 := providerConfigAAD("anthropic", "prod-key")
	assert.NotEqual(t, aad1, aad3, "different providers must produce different AAD")

	aad4 := providerConfigAAD("openai", "staging-key")
	assert.NotEqual(t, aad1, aad4, "different names must produce different AAD")
}

func TestIsPgUniqueViolation(t *testing.T) {
	assert.False(t, isPgUniqueViolation(nil))
	assert.False(t, isPgUniqueViolation(ErrNotFound))
}

// Integration tests: require a real Postgres connection.
// Run with: go test -tags=integration -run TestPostgresStore_Integration
