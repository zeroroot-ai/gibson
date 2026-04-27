package envelope

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// randomKEK returns a fresh random 32-byte KEK for each test.
func randomKEK(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	_, err := rand.Read(k)
	require.NoError(t, err)
	return k
}

func TestEncryptDecrypt_HappyRoundtrip(t *testing.T) {
	kek := randomKEK(t)
	plaintext := []byte("super-secret-api-key-value")
	aad := []byte("credential:my-openai-key")

	env, err := Encrypt(kek, plaintext, aad)
	require.NoError(t, err)
	require.NotNil(t, env)

	got, err := Decrypt(kek, env, aad)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

func TestEncryptDecrypt_EmptyAAD(t *testing.T) {
	kek := randomKEK(t)
	plaintext := []byte("secret")
	aad := []byte{}

	env, err := Encrypt(kek, plaintext, aad)
	require.NoError(t, err)

	got, err := Decrypt(kek, env, aad)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

func TestEncryptDecrypt_LargePayload(t *testing.T) {
	kek := randomKEK(t)
	plaintext := make([]byte, 4096)
	_, err := rand.Read(plaintext)
	require.NoError(t, err)
	aad := []byte("credential:large-payload")

	env, err := Encrypt(kek, plaintext, aad)
	require.NoError(t, err)

	got, err := Decrypt(kek, env, aad)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

// Encrypt should produce different envelopes on repeated calls (fresh DEK + nonce).
func TestEncrypt_NonDeterministic(t *testing.T) {
	kek := randomKEK(t)
	plaintext := []byte("secret")
	aad := []byte("credential:test")

	env1, err := Encrypt(kek, plaintext, aad)
	require.NoError(t, err)
	env2, err := Encrypt(kek, plaintext, aad)
	require.NoError(t, err)

	assert.False(t, bytes.Equal(env1, env2), "two Encrypt calls must produce different envelopes")
}

func TestDecrypt_CrossTenantKEK_FailsWithSentinel(t *testing.T) {
	tenantAKEK := randomKEK(t)
	tenantBKEK := randomKEK(t)

	plaintext := []byte("tenant-A-secret")
	aad := []byte("credential:tenant-A-key")

	// Encrypt under tenant A's KEK.
	env, err := Encrypt(tenantAKEK, plaintext, aad)
	require.NoError(t, err)

	// Attempt to decrypt under tenant B's KEK.
	_, err = Decrypt(tenantBKEK, env, aad)
	require.Error(t, err, "decryption with wrong KEK must fail")
	assert.True(t, IsCrossTenantDecryptError(err),
		"IsCrossTenantDecryptError must be true for cross-tenant KEK mismatch")
	assert.ErrorIs(t, err, ErrDecrypt,
		"error must also satisfy errors.Is(err, ErrDecrypt)")
}

func TestDecrypt_TamperedCiphertext_FailsAEAD(t *testing.T) {
	kek := randomKEK(t)
	plaintext := []byte("secret")
	aad := []byte("credential:test")

	env, err := Encrypt(kek, plaintext, aad)
	require.NoError(t, err)

	// Flip the last byte of the ciphertext (AEAD tag region).
	tampered := make([]byte, len(env))
	copy(tampered, env)
	tampered[len(tampered)-1] ^= 0x01

	_, err = Decrypt(kek, tampered, aad)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDecrypt)
	assert.False(t, IsCrossTenantDecryptError(err),
		"tampered ciphertext must not be flagged as cross-tenant error")
}

func TestDecrypt_TamperedAAD_FailsAEAD(t *testing.T) {
	kek := randomKEK(t)
	plaintext := []byte("secret")
	aad := []byte("credential:test")

	env, err := Encrypt(kek, plaintext, aad)
	require.NoError(t, err)

	// Present a different AAD at decrypt time.
	wrongAAD := []byte("credential:WRONG")

	_, err = Decrypt(kek, env, wrongAAD)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDecrypt)
}

func TestDecrypt_TamperedWrappedDEK_FailsUnwrap(t *testing.T) {
	kek := randomKEK(t)
	plaintext := []byte("secret")
	aad := []byte("credential:test")

	env, err := Encrypt(kek, plaintext, aad)
	require.NoError(t, err)

	// Flip a byte in the wrapped DEK region (first 40 bytes).
	tampered := make([]byte, len(env))
	copy(tampered, env)
	tampered[5] ^= 0xFF

	_, err = Decrypt(kek, tampered, aad)
	require.Error(t, err)
	// A tampered wrapped DEK will fail the AES-Unwrap integrity check,
	// which is indistinguishable from a wrong KEK at the unwrap layer;
	// IsCrossTenantDecryptError may be true here.
	assert.ErrorIs(t, err, ErrDecrypt)
}

func TestDecrypt_ShortEnvelope_ReturnsCleanError(t *testing.T) {
	kek := randomKEK(t)

	// Envelope shorter than minimum valid length.
	shortEnv := make([]byte, minEnvelopeLen-1)

	_, err := Decrypt(kek, shortEnv, nil)
	require.Error(t, err)
	// Must not be ErrDecrypt (it's a format error, not a crypto error).
	assert.False(t, errors.Is(err, ErrDecrypt), "short envelope should return format error, not ErrDecrypt")
}

func TestDecrypt_EmptyEnvelope_ReturnsCleanError(t *testing.T) {
	kek := randomKEK(t)

	_, err := Decrypt(kek, []byte{}, nil)
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrDecrypt))
}

func TestEncrypt_EmptyPlaintext_ReturnsError(t *testing.T) {
	kek := randomKEK(t)

	_, err := Encrypt(kek, []byte{}, []byte("aad"))
	require.Error(t, err)
}

func TestEncrypt_ShortKEK_ReturnsError(t *testing.T) {
	shortKEK := make([]byte, 16) // 128-bit, not 256-bit

	_, err := Encrypt(shortKEK, []byte("secret"), []byte("aad"))
	require.Error(t, err)
}

func TestIsCrossTenantDecryptError_NilErr(t *testing.T) {
	assert.False(t, IsCrossTenantDecryptError(nil))
}

func TestIsCrossTenantDecryptError_UnrelatedErr(t *testing.T) {
	assert.False(t, IsCrossTenantDecryptError(errors.New("some other error")))
}

func TestIsCrossTenantDecryptError_ErrDecrypt(t *testing.T) {
	// Plain ErrDecrypt (no sentinel wrapper) must NOT trigger cross-tenant flag.
	assert.False(t, IsCrossTenantDecryptError(ErrDecrypt))
}
