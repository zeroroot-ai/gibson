package database

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// randomKEK returns a fresh random 32-byte KEK for each test.
func randomTestKEK(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	_, err := rand.Read(k)
	require.NoError(t, err)
	return k
}

// TestCredentialOps_UnitBehavior exercises CredentialOps business logic
// without a real Postgres connection by using a table-driven approach that
// validates error paths.
func TestCredentialOps_InputValidation(t *testing.T) {
	kek := randomTestKEK(t)
	// nil pg pool — operations that make it to the DB call will panic/error,
	// but we validate the pre-DB checks here.
	ops := NewCredentialOps(nil, kek)

	ctx := context.Background()

	t.Run("Put rejects empty name", func(t *testing.T) {
		err := ops.Put(ctx, "", []byte("secret"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "name must not be empty")
	})

	t.Run("Put rejects empty secret", func(t *testing.T) {
		err := ops.Put(ctx, "mykey", []byte{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "secret must not be empty")
	})

	t.Run("Get rejects empty name", func(t *testing.T) {
		_, err := ops.Get(ctx, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "name must not be empty")
	})

	t.Run("Delete rejects empty name", func(t *testing.T) {
		err := ops.Delete(ctx, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "name must not be empty")
	})
}

func TestIsCrossTenantCredentialError(t *testing.T) {
	t.Run("nil error returns false", func(t *testing.T) {
		assert.False(t, IsCrossTenantCredentialError(nil))
	})

	t.Run("unrelated error returns false", func(t *testing.T) {
		assert.False(t, IsCrossTenantCredentialError(ErrCredentialNotFound))
	})

	t.Run("cross-tenant sentinel returns true", func(t *testing.T) {
		err := &credentialDecryptError{name: "test", crossTenant: true}
		assert.True(t, IsCrossTenantCredentialError(err))
	})

	t.Run("non-cross-tenant decrypt error returns false", func(t *testing.T) {
		err := &credentialDecryptError{name: "test", crossTenant: false}
		assert.False(t, IsCrossTenantCredentialError(err))
	})
}

// TestCredentialOps_AADBinding verifies that the AAD construction is
// consistent (same name → same AAD bytes).
func TestCredentialOps_AADConsistency(t *testing.T) {
	aad1 := credentialAAD("my-openai-key")
	aad2 := credentialAAD("my-openai-key")
	assert.Equal(t, aad1, aad2)

	aad3 := credentialAAD("other-key")
	assert.NotEqual(t, aad1, aad3)
}

// TestCredentialOps_Integration is defined in credential_dao_postgres_integration_test.go.
