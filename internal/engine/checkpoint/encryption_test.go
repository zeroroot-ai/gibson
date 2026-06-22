package checkpoint

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockKeyProvider implements keyprovider.KeyProvider for testing.
type mockKeyProvider struct {
	key   []byte
	keyID string
	keys  map[string][]byte
}

func newMockKeyProvider(key []byte, keyID string) *mockKeyProvider {
	return &mockKeyProvider{
		key:   key,
		keyID: keyID,
		keys: map[string][]byte{
			keyID: key,
		},
	}
}

func (m *mockKeyProvider) GetKey(ctx context.Context) ([]byte, error) {
	return m.key, nil
}

func (m *mockKeyProvider) GetKeyByID(ctx context.Context, keyID string) ([]byte, error) {
	if key, ok := m.keys[keyID]; ok {
		return key, nil
	}
	return nil, assert.AnError
}

func (m *mockKeyProvider) CurrentKeyID() string {
	return m.keyID
}

func (m *mockKeyProvider) addKey(keyID string, key []byte) {
	m.keys[keyID] = key
}

// generateTestKey generates a random 32-byte AES-256 key for testing.
func generateTestKey() []byte {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return key
}

func TestEncryption_RoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	key := generateTestKey()
	provider := newMockKeyProvider(key, "test-key-1")
	service := NewAESGCMEncryptionService(provider)

	testData := []byte("Hello, World! This is sensitive checkpoint data.")

	// Encrypt
	payload, err := service.Encrypt(ctx, testData)
	require.NoError(t, err)
	require.NotNil(t, payload)

	// Verify payload structure
	assert.Equal(t, "test-key-1", payload.KeyID)
	assert.NotEmpty(t, payload.Nonce)
	assert.NotEmpty(t, payload.Ciphertext)
	assert.NotEqual(t, testData, payload.Ciphertext)

	// Decrypt
	decrypted, err := service.Decrypt(ctx, payload)
	require.NoError(t, err)
	assert.Equal(t, testData, decrypted)
}

func TestEncryption_DifferentNonces(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	key := generateTestKey()
	provider := newMockKeyProvider(key, "test-key-1")
	service := NewAESGCMEncryptionService(provider)

	testData := []byte("Same data encrypted twice")

	// Encrypt same data twice
	payload1, err := service.Encrypt(ctx, testData)
	require.NoError(t, err)

	payload2, err := service.Encrypt(ctx, testData)
	require.NoError(t, err)

	// Nonces should be different
	assert.NotEqual(t, payload1.Nonce, payload2.Nonce, "nonces should be unique")

	// Ciphertexts should be different (due to different nonces)
	assert.NotEqual(t, payload1.Ciphertext, payload2.Ciphertext, "ciphertexts should differ with different nonces")

	// Both should decrypt to same plaintext
	decrypted1, err := service.Decrypt(ctx, payload1)
	require.NoError(t, err)
	assert.Equal(t, testData, decrypted1)

	decrypted2, err := service.Decrypt(ctx, payload2)
	require.NoError(t, err)
	assert.Equal(t, testData, decrypted2)
}

func TestEncryption_KeyRotation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Create old key and encrypt data
	oldKey := generateTestKey()
	oldProvider := newMockKeyProvider(oldKey, "key-v1")
	oldService := NewAESGCMEncryptionService(oldProvider)

	testData := []byte("Data encrypted with old key")

	// Encrypt with old key
	payload, err := oldService.Encrypt(ctx, testData)
	require.NoError(t, err)
	assert.Equal(t, "key-v1", payload.KeyID)

	// Create new key provider with both keys
	newKey := generateTestKey()
	newProvider := newMockKeyProvider(newKey, "key-v2")
	newProvider.addKey("key-v1", oldKey) // Keep old key for decryption
	newService := NewAESGCMEncryptionService(newProvider)

	// Should be able to decrypt old data with new service
	decrypted, err := newService.Decrypt(ctx, payload)
	require.NoError(t, err)
	assert.Equal(t, testData, decrypted)

	// New encryptions should use new key
	newPayload, err := newService.Encrypt(ctx, []byte("New data"))
	require.NoError(t, err)
	assert.Equal(t, "key-v2", newPayload.KeyID)
}

func TestEncryption_InvalidKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("key too short", func(t *testing.T) {
		shortKey := make([]byte, 16) // AES-128, need AES-256
		provider := newMockKeyProvider(shortKey, "short-key")
		service := NewAESGCMEncryptionService(provider)

		testData := []byte("test data")

		_, err := service.Encrypt(ctx, testData)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid key length")
	})

	t.Run("key too long", func(t *testing.T) {
		longKey := make([]byte, 64)
		provider := newMockKeyProvider(longKey, "long-key")
		service := NewAESGCMEncryptionService(provider)

		testData := []byte("test data")

		_, err := service.Encrypt(ctx, testData)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid key length")
	})
}

func TestEncryption_CorruptedCiphertext(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	key := generateTestKey()
	provider := newMockKeyProvider(key, "test-key")
	service := NewAESGCMEncryptionService(provider)

	testData := []byte("Original data before corruption")

	// Encrypt
	payload, err := service.Encrypt(ctx, testData)
	require.NoError(t, err)

	t.Run("corrupted ciphertext", func(t *testing.T) {
		// Corrupt the ciphertext
		corruptedPayload := &EncryptedPayload{
			KeyID:      payload.KeyID,
			Nonce:      payload.Nonce,
			Ciphertext: make([]byte, len(payload.Ciphertext)),
		}
		copy(corruptedPayload.Ciphertext, payload.Ciphertext)
		corruptedPayload.Ciphertext[0] ^= 0xFF // Flip bits

		// Decryption should fail
		_, err := service.Decrypt(ctx, corruptedPayload)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt")
	})

	t.Run("corrupted nonce", func(t *testing.T) {
		// Corrupt the nonce
		corruptedPayload := &EncryptedPayload{
			KeyID:      payload.KeyID,
			Nonce:      make([]byte, len(payload.Nonce)),
			Ciphertext: payload.Ciphertext,
		}
		copy(corruptedPayload.Nonce, payload.Nonce)
		corruptedPayload.Nonce[0] ^= 0xFF // Flip bits

		// Decryption should fail
		_, err := service.Decrypt(ctx, corruptedPayload)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt")
	})
}

func TestEncryption_WrongKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Encrypt with one key
	key1 := generateTestKey()
	provider1 := newMockKeyProvider(key1, "key-1")
	service1 := NewAESGCMEncryptionService(provider1)

	testData := []byte("Secret data")
	payload, err := service1.Encrypt(ctx, testData)
	require.NoError(t, err)

	// Try to decrypt with different key
	key2 := generateTestKey()
	provider2 := newMockKeyProvider(key2, "key-1") // Same ID, different key
	service2 := NewAESGCMEncryptionService(provider2)

	_, err = service2.Decrypt(ctx, payload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt")
}

func TestEncryption_EmptyData(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	key := generateTestKey()
	provider := newMockKeyProvider(key, "test-key")
	service := NewAESGCMEncryptionService(provider)

	// Encrypt empty data
	emptyData := []byte{}
	payload, err := service.Encrypt(ctx, emptyData)
	require.NoError(t, err)
	require.NotNil(t, payload)

	// Should still have nonce and authentication tag
	assert.NotEmpty(t, payload.Nonce)
	assert.NotEmpty(t, payload.Ciphertext)

	// Decrypt should return empty data (may be nil or empty slice)
	decrypted, err := service.Decrypt(ctx, payload)
	require.NoError(t, err)
	assert.Empty(t, decrypted)
}

func TestEncryption_LargeData(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	key := generateTestKey()
	provider := newMockKeyProvider(key, "test-key")
	service := NewAESGCMEncryptionService(provider)

	// Create 10MB of random data
	largeData := make([]byte, 10*1024*1024)
	_, err := rand.Read(largeData)
	require.NoError(t, err)

	// Encrypt
	payload, err := service.Encrypt(ctx, largeData)
	require.NoError(t, err)
	require.NotNil(t, payload)

	// Decrypt
	decrypted, err := service.Decrypt(ctx, payload)
	require.NoError(t, err)
	assert.Equal(t, largeData, decrypted)
}

func TestEncryption_NilPayload(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	key := generateTestKey()
	provider := newMockKeyProvider(key, "test-key")
	service := NewAESGCMEncryptionService(provider)

	// Decrypt nil payload should fail
	_, err := service.Decrypt(ctx, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encrypted payload is nil")
}

func TestEncryption_InvalidPayload(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	key := generateTestKey()
	provider := newMockKeyProvider(key, "test-key")
	service := NewAESGCMEncryptionService(provider)

	tests := []struct {
		name    string
		payload *EncryptedPayload
		errMsg  string
	}{
		{
			name: "missing key ID",
			payload: &EncryptedPayload{
				KeyID:      "",
				Nonce:      []byte("12345678901234567890"),
				Ciphertext: []byte("encrypted"),
			},
			errMsg: "missing key ID",
		},
		{
			name: "missing nonce",
			payload: &EncryptedPayload{
				KeyID:      "test-key",
				Nonce:      []byte{},
				Ciphertext: []byte("encrypted"),
			},
			errMsg: "missing nonce",
		},
		{
			name: "missing ciphertext",
			payload: &EncryptedPayload{
				KeyID:      "test-key",
				Nonce:      []byte("12345678901234567890"),
				Ciphertext: []byte{},
			},
			errMsg: "missing ciphertext",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.Decrypt(ctx, tt.payload)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestEncryption_InvalidNonceSize(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	key := generateTestKey()
	provider := newMockKeyProvider(key, "test-key")
	service := NewAESGCMEncryptionService(provider)

	testData := []byte("test data")
	payload, err := service.Encrypt(ctx, testData)
	require.NoError(t, err)

	// Create payload with wrong nonce size
	invalidPayload := &EncryptedPayload{
		KeyID:      payload.KeyID,
		Nonce:      []byte("short"), // Too short
		Ciphertext: payload.Ciphertext,
	}

	_, err = service.Decrypt(ctx, invalidPayload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid nonce size")
}

func TestEncryption_UnknownKeyID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	key := generateTestKey()
	provider := newMockKeyProvider(key, "test-key")
	service := NewAESGCMEncryptionService(provider)

	testData := []byte("test data")
	payload, err := service.Encrypt(ctx, testData)
	require.NoError(t, err)

	// Change key ID to unknown value
	payload.KeyID = "unknown-key"

	_, err = service.Decrypt(ctx, payload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to retrieve encryption key")
}

func TestEncryption_MultipleMessages(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	key := generateTestKey()
	provider := newMockKeyProvider(key, "test-key")
	service := NewAESGCMEncryptionService(provider)

	messages := []string{
		"First message",
		"Second message with more data",
		"Third message",
		"",
		"Message with special chars: !@#$%^&*()",
	}

	// Encrypt all messages
	payloads := make([]*EncryptedPayload, len(messages))
	for i, msg := range messages {
		payload, err := service.Encrypt(ctx, []byte(msg))
		require.NoError(t, err)
		payloads[i] = payload
	}

	// Decrypt all messages
	for i, payload := range payloads {
		decrypted, err := service.Decrypt(ctx, payload)
		require.NoError(t, err)
		assert.Equal(t, messages[i], string(decrypted))
	}
}

// Benchmark tests
func BenchmarkEncryption_Encrypt(b *testing.B) {
	ctx := context.Background()
	key := generateTestKey()
	provider := newMockKeyProvider(key, "test-key")
	service := NewAESGCMEncryptionService(provider)

	testData := make([]byte, 1024*1024) // 1MB
	_, _ = rand.Read(testData)

	b.ResetTimer()
	b.SetBytes(int64(len(testData)))

	for i := 0; i < b.N; i++ {
		_, err := service.Encrypt(ctx, testData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryption_Decrypt(b *testing.B) {
	ctx := context.Background()
	key := generateTestKey()
	provider := newMockKeyProvider(key, "test-key")
	service := NewAESGCMEncryptionService(provider)

	testData := make([]byte, 1024*1024) // 1MB
	_, _ = rand.Read(testData)

	payload, err := service.Encrypt(ctx, testData)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.SetBytes(int64(len(testData)))

	for i := 0; i < b.N; i++ {
		_, err := service.Decrypt(ctx, payload)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryption_SmallData(b *testing.B) {
	ctx := context.Background()
	key := generateTestKey()
	provider := newMockKeyProvider(key, "test-key")
	service := NewAESGCMEncryptionService(provider)

	testData := []byte("Small checkpoint data")

	b.ResetTimer()
	b.SetBytes(int64(len(testData)))

	for i := 0; i < b.N; i++ {
		payload, err := service.Encrypt(ctx, testData)
		if err != nil {
			b.Fatal(err)
		}
		_, err = service.Decrypt(ctx, payload)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryption_LargeData(b *testing.B) {
	ctx := context.Background()
	key := generateTestKey()
	provider := newMockKeyProvider(key, "test-key")
	service := NewAESGCMEncryptionService(provider)

	testData := make([]byte, 10*1024*1024) // 10MB
	_, _ = rand.Read(testData)

	b.ResetTimer()
	b.SetBytes(int64(len(testData)))

	for i := 0; i < b.N; i++ {
		payload, err := service.Encrypt(ctx, testData)
		if err != nil {
			b.Fatal(err)
		}
		_, err = service.Decrypt(ctx, payload)
		if err != nil {
			b.Fatal(err)
		}
	}
}
