package crypto

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConstants verifies that cryptographic constants match OWASP recommendations
func TestConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant int
		expected int
		reason   string
	}{
		{
			name:     "KeySize",
			constant: KeySize,
			expected: 32,
			reason:   "AES-256 requires 32-byte keys",
		},
		{
			name:     "SaltSize",
			constant: SaltSize,
			expected: 32,
			reason:   "256-bit salt provides strong security",
		},
		{
			name:     "NonceSize",
			constant: NonceSize,
			expected: 12,
			reason:   "GCM standard nonce size",
		},
		{
			name:     "ScryptN",
			constant: ScryptN,
			expected: 32768,
			reason:   "OWASP recommended N=2^15",
		},
		{
			name:     "ScryptR",
			constant: ScryptR,
			expected: 8,
			reason:   "OWASP recommended r=8",
		},
		{
			name:     "ScryptP",
			constant: ScryptP,
			expected: 1,
			reason:   "OWASP recommended p=1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant, tt.reason)
		})
	}
}

// TestGenerateSalt tests salt generation
func TestGenerateSalt(t *testing.T) {
	t.Run("generates correct size", func(t *testing.T) {
		salt, err := GenerateSalt()
		require.NoError(t, err)
		assert.Len(t, salt, SaltSize)
	})

	t.Run("generates unique salts", func(t *testing.T) {
		salt1, err1 := GenerateSalt()
		require.NoError(t, err1)

		salt2, err2 := GenerateSalt()
		require.NoError(t, err2)

		salt3, err3 := GenerateSalt()
		require.NoError(t, err3)

		// All salts should be unique
		assert.NotEqual(t, salt1, salt2, "salt1 and salt2 should be unique")
		assert.NotEqual(t, salt2, salt3, "salt2 and salt3 should be unique")
		assert.NotEqual(t, salt1, salt3, "salt1 and salt3 should be unique")
	})

	t.Run("salts are not all zeros", func(t *testing.T) {
		salt, err := GenerateSalt()
		require.NoError(t, err)

		allZeros := true
		for _, b := range salt {
			if b != 0 {
				allZeros = false
				break
			}
		}
		assert.False(t, allZeros, "salt should not be all zeros")
	})
}

// TestScryptDeriver tests the scrypt key derivation implementation
func TestScryptDeriver(t *testing.T) {
	t.Run("NewScryptDeriver creates valid instance", func(t *testing.T) {
		deriver := NewScryptDeriver()
		require.NotNil(t, deriver)
		assert.Equal(t, ScryptN, deriver.n)
		assert.Equal(t, ScryptR, deriver.r)
		assert.Equal(t, ScryptP, deriver.p)
		assert.Equal(t, KeySize, deriver.keyLen)
	})

	t.Run("DeriveKey with valid inputs", func(t *testing.T) {
		deriver := NewScryptDeriver()
		masterKey := []byte("my-master-key")
		salt := make([]byte, SaltSize)
		for i := range salt {
			salt[i] = byte(i)
		}

		key, err := deriver.DeriveKey(masterKey, salt)
		require.NoError(t, err)
		assert.Len(t, key, KeySize)
	})

	t.Run("DeriveKey is deterministic", func(t *testing.T) {
		deriver := NewScryptDeriver()
		masterKey := []byte("test-password-determinism")
		salt := make([]byte, SaltSize)
		for i := range salt {
			salt[i] = byte(i % 256)
		}

		key1, err := deriver.DeriveKey(masterKey, salt)
		require.NoError(t, err)

		key2, err := deriver.DeriveKey(masterKey, salt)
		require.NoError(t, err)

		key3, err := deriver.DeriveKey(masterKey, salt)
		require.NoError(t, err)

		// All keys should be identical
		assert.Equal(t, key1, key2, "same inputs should produce same key")
		assert.Equal(t, key2, key3, "same inputs should produce same key")
	})

	t.Run("DeriveKey with different salts produces different keys", func(t *testing.T) {
		deriver := NewScryptDeriver()
		masterKey := []byte("same-password")

		salt1 := make([]byte, SaltSize)
		for i := range salt1 {
			salt1[i] = byte(i)
		}

		salt2 := make([]byte, SaltSize)
		for i := range salt2 {
			salt2[i] = byte(255 - i)
		}

		key1, err := deriver.DeriveKey(masterKey, salt1)
		require.NoError(t, err)

		key2, err := deriver.DeriveKey(masterKey, salt2)
		require.NoError(t, err)

		assert.NotEqual(t, key1, key2, "different salts should produce different keys")
	})

	t.Run("DeriveKey with empty master key fails", func(t *testing.T) {
		deriver := NewScryptDeriver()
		salt := make([]byte, SaltSize)

		key, err := deriver.DeriveKey([]byte{}, salt)
		assert.Error(t, err)
		assert.Nil(t, key)
		assert.Contains(t, err.Error(), "master key cannot be empty")
	})

	t.Run("DeriveKey with nil master key fails", func(t *testing.T) {
		deriver := NewScryptDeriver()
		salt := make([]byte, SaltSize)

		key, err := deriver.DeriveKey(nil, salt)
		assert.Error(t, err)
		assert.Nil(t, key)
		assert.Contains(t, err.Error(), "master key cannot be empty")
	})

	t.Run("DeriveKey with invalid salt size", func(t *testing.T) {
		deriver := NewScryptDeriver()
		masterKey := []byte("test-key")

		tests := []struct {
			name     string
			saltSize int
		}{
			{"too short", 16},
			{"too long", 64},
			{"empty", 0},
			{"one byte", 1},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				salt := make([]byte, tt.saltSize)
				key, err := deriver.DeriveKey(masterKey, salt)
				assert.Error(t, err)
				assert.Nil(t, key)
				assert.Contains(t, err.Error(), "invalid salt size")
			})
		}
	})
}

// TestScryptDeriverInterface verifies ScryptDeriver implements KeyDeriver
func TestScryptDeriverInterface(t *testing.T) {
	var _ KeyDeriver = (*ScryptDeriver)(nil)
}

// TestAESGCMEncryptorInterface verifies AESGCMEncryptor implements Encryptor
func TestAESGCMEncryptorInterface(t *testing.T) {
	var _ Encryptor = (*AESGCMEncryptor)(nil)
}

// TestEncryptionEdgeCases tests edge cases in encryption
func TestEncryptionEdgeCases(t *testing.T) {
	encryptor := NewAESGCMEncryptor()

	t.Run("encrypt with very long plaintext", func(t *testing.T) {
		plaintext := bytes.Repeat([]byte("A"), 1024*1024) // 1MB
		masterKey := []byte("test-key-for-large-data")

		ciphertext, iv, salt, err := encryptor.Encrypt(plaintext, masterKey)
		require.NoError(t, err)
		assert.NotNil(t, ciphertext)
		assert.Len(t, iv, NonceSize)
		assert.Len(t, salt, SaltSize)

		// Decrypt to verify
		decrypted, err := encryptor.Decrypt(ciphertext, iv, salt, masterKey)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("encrypt with single byte plaintext", func(t *testing.T) {
		plaintext := []byte("X")
		masterKey := []byte("test-key")

		ciphertext, iv, salt, err := encryptor.Encrypt(plaintext, masterKey)
		require.NoError(t, err)

		decrypted, err := encryptor.Decrypt(ciphertext, iv, salt, masterKey)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("encrypt with unicode", func(t *testing.T) {
		plaintext := []byte("Hello 世界 🌍 مرحبا שלום")
		masterKey := []byte("unicode-test-key")

		ciphertext, iv, salt, err := encryptor.Encrypt(plaintext, masterKey)
		require.NoError(t, err)

		decrypted, err := encryptor.Decrypt(ciphertext, iv, salt, masterKey)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("encrypt with different master keys", func(t *testing.T) {
		plaintext := []byte("test message")
		key1 := []byte("key-one")
		key2 := []byte("key-two")

		ct1, iv1, salt1, err := encryptor.Encrypt(plaintext, key1)
		require.NoError(t, err)

		ct2, iv2, salt2, err := encryptor.Encrypt(plaintext, key2)
		require.NoError(t, err)

		// Ciphertexts should be different
		assert.NotEqual(t, ct1, ct2)

		// Each should decrypt with its own key
		dec1, err := encryptor.Decrypt(ct1, iv1, salt1, key1)
		require.NoError(t, err)
		assert.Equal(t, plaintext, dec1)

		dec2, err := encryptor.Decrypt(ct2, iv2, salt2, key2)
		require.NoError(t, err)
		assert.Equal(t, plaintext, dec2)

		// Cross-decryption should fail
		_, err = encryptor.Decrypt(ct1, iv1, salt1, key2)
		assert.Error(t, err)

		_, err = encryptor.Decrypt(ct2, iv2, salt2, key1)
		assert.Error(t, err)
	})
}

// TestDecryptionFailureModes tests various decryption failure scenarios
func TestDecryptionFailureModes(t *testing.T) {
	encryptor := NewAESGCMEncryptor()

	t.Run("decrypt with tampered auth tag", func(t *testing.T) {
		plaintext := []byte("secret message")
		masterKey := []byte("test-key")

		ciphertext, iv, salt, err := encryptor.Encrypt(plaintext, masterKey)
		require.NoError(t, err)

		// Tamper with last byte (part of auth tag)
		tampered := make([]byte, len(ciphertext))
		copy(tampered, ciphertext)
		tampered[len(tampered)-1] ^= 0xFF

		_, err = encryptor.Decrypt(tampered, iv, salt, masterKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "decryption failed")
	})

	t.Run("decrypt with tampered ciphertext body", func(t *testing.T) {
		plaintext := []byte("secret message that is long enough")
		masterKey := []byte("test-key")

		ciphertext, iv, salt, err := encryptor.Encrypt(plaintext, masterKey)
		require.NoError(t, err)

		// Tamper with middle byte
		tampered := make([]byte, len(ciphertext))
		copy(tampered, ciphertext)
		tampered[len(tampered)/2] ^= 0x01

		_, err = encryptor.Decrypt(tampered, iv, salt, masterKey)
		assert.Error(t, err)
	})

	t.Run("decrypt with modified nonce", func(t *testing.T) {
		plaintext := []byte("secret message")
		masterKey := []byte("test-key")

		ciphertext, iv, salt, err := encryptor.Encrypt(plaintext, masterKey)
		require.NoError(t, err)

		// Modify nonce
		modifiedIV := make([]byte, len(iv))
		copy(modifiedIV, iv)
		modifiedIV[0] ^= 0xFF

		_, err = encryptor.Decrypt(ciphertext, modifiedIV, salt, masterKey)
		assert.Error(t, err)
	})

	t.Run("decrypt with modified salt", func(t *testing.T) {
		plaintext := []byte("secret message")
		masterKey := []byte("test-key")

		ciphertext, iv, salt, err := encryptor.Encrypt(plaintext, masterKey)
		require.NoError(t, err)

		// Modify salt
		modifiedSalt := make([]byte, len(salt))
		copy(modifiedSalt, salt)
		modifiedSalt[0] ^= 0xFF

		_, err = encryptor.Decrypt(ciphertext, iv, modifiedSalt, masterKey)
		assert.Error(t, err)
	})

	t.Run("decrypt with empty master key", func(t *testing.T) {
		ciphertext := []byte("fake-ciphertext-with-enough-length-for-gcm")
		iv := make([]byte, NonceSize)
		salt := make([]byte, SaltSize)

		_, err := encryptor.Decrypt(ciphertext, iv, salt, []byte{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "master key cannot be empty")
	})
}

// TestEncryptionNonDeterminism verifies encryption produces unique outputs
func TestEncryptionNonDeterminism(t *testing.T) {
	encryptor := NewAESGCMEncryptor()
	plaintext := []byte("same plaintext every time")
	masterKey := []byte("same-master-key")

	// Encrypt same data multiple times
	results := make([]struct {
		ciphertext []byte
		iv         []byte
		salt       []byte
	}, 10)

	for i := 0; i < 10; i++ {
		ct, iv, salt, err := encryptor.Encrypt(plaintext, masterKey)
		require.NoError(t, err)
		results[i].ciphertext = ct
		results[i].iv = iv
		results[i].salt = salt
	}

	// Verify all results are unique
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			assert.NotEqual(t, results[i].ciphertext, results[j].ciphertext,
				"ciphertexts should be unique due to random salt/nonce")
			assert.NotEqual(t, results[i].iv, results[j].iv,
				"nonces should be unique")
			assert.NotEqual(t, results[i].salt, results[j].salt,
				"salts should be unique")
		}
	}

	// But all should decrypt to same plaintext
	for i, result := range results {
		decrypted, err := encryptor.Decrypt(result.ciphertext, result.iv, result.salt, masterKey)
		require.NoError(t, err, "decryption %d failed", i)
		assert.Equal(t, plaintext, decrypted, "decryption %d mismatch", i)
	}
}

// Benchmarks

// BenchmarkGenerateSalt benchmarks salt generation
func BenchmarkGenerateSalt(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GenerateSalt()
	}
}

// BenchmarkScryptDeriveKey benchmarks scrypt key derivation
func BenchmarkScryptDeriveKey(b *testing.B) {
	deriver := NewScryptDeriver()
	masterKey := []byte("benchmark-master-key")
	salt := make([]byte, SaltSize)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = deriver.DeriveKey(masterKey, salt)
	}
}

// BenchmarkEncrypt benchmarks encryption performance
func BenchmarkEncrypt(b *testing.B) {
	encryptor := NewAESGCMEncryptor()
	plaintext := []byte("benchmark plaintext data for encryption testing")
	masterKey := []byte("benchmark-master-key-for-testing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = encryptor.Encrypt(plaintext, masterKey)
	}
}

// BenchmarkDecrypt benchmarks decryption performance
func BenchmarkDecrypt(b *testing.B) {
	encryptor := NewAESGCMEncryptor()
	plaintext := []byte("benchmark plaintext data for decryption testing")
	masterKey := []byte("benchmark-master-key-for-testing")
	ciphertext, iv, salt, _ := encryptor.Encrypt(plaintext, masterKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = encryptor.Decrypt(ciphertext, iv, salt, masterKey)
	}
}

// BenchmarkEncryptDecryptRoundTrip benchmarks full encryption and decryption
func BenchmarkEncryptDecryptRoundTrip(b *testing.B) {
	encryptor := NewAESGCMEncryptor()
	plaintext := []byte("benchmark plaintext for round trip testing")
	masterKey := []byte("benchmark-master-key")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ciphertext, iv, salt, _ := encryptor.Encrypt(plaintext, masterKey)
		_, _ = encryptor.Decrypt(ciphertext, iv, salt, masterKey)
	}
}

// BenchmarkEncryptLargeData benchmarks encryption of large data
func BenchmarkEncryptLargeData(b *testing.B) {
	encryptor := NewAESGCMEncryptor()
	plaintext := bytes.Repeat([]byte("A"), 1024*1024) // 1MB
	masterKey := []byte("benchmark-key")

	b.ResetTimer()
	b.SetBytes(int64(len(plaintext)))
	for i := 0; i < b.N; i++ {
		_, _, _, _ = encryptor.Encrypt(plaintext, masterKey)
	}
}

// BenchmarkDecryptLargeData benchmarks decryption of large data
func BenchmarkDecryptLargeData(b *testing.B) {
	encryptor := NewAESGCMEncryptor()
	plaintext := bytes.Repeat([]byte("A"), 1024*1024) // 1MB
	masterKey := []byte("benchmark-key")
	ciphertext, iv, salt, _ := encryptor.Encrypt(plaintext, masterKey)

	b.ResetTimer()
	b.SetBytes(int64(len(plaintext)))
	for i := 0; i < b.N; i++ {
		_, _ = encryptor.Decrypt(ciphertext, iv, salt, masterKey)
	}
}

// BenchmarkScryptDifferentSizes benchmarks scrypt with different key sizes
func BenchmarkScryptDifferentSizes(b *testing.B) {
	sizes := []int{16, 32, 64}

	for _, size := range sizes {
		b.Run(string(rune('0'+size)), func(b *testing.B) {
			deriver := &ScryptDeriver{
				n:      ScryptN,
				r:      ScryptR,
				p:      ScryptP,
				keyLen: size,
			}
			masterKey := []byte("test-key")
			salt := make([]byte, SaltSize)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = deriver.DeriveKey(masterKey, salt)
			}
		})
	}
}

// TestDecryptEmptyMasterKey tests decryption with nil master key
func TestDecryptEmptyMasterKey(t *testing.T) {
	encryptor := NewAESGCMEncryptor()

	ciphertext := make([]byte, 100)
	iv := make([]byte, NonceSize)
	salt := make([]byte, SaltSize)

	_, err := encryptor.Decrypt(ciphertext, iv, salt, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "master key cannot be empty")
}

// TestEncryptWithVariousKeySizes tests encryption with different master key sizes
func TestEncryptWithVariousKeySizes(t *testing.T) {
	encryptor := NewAESGCMEncryptor()
	plaintext := []byte("test plaintext")

	tests := []struct {
		name      string
		keySize   int
		shouldErr bool
	}{
		{"1 byte key", 1, false},
		{"8 byte key", 8, false},
		{"16 byte key", 16, false},
		{"32 byte key", 32, false},
		{"64 byte key", 64, false},
		{"128 byte key", 128, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			masterKey := make([]byte, tt.keySize)
			for i := range masterKey {
				masterKey[i] = byte(i)
			}

			ciphertext, iv, salt, err := encryptor.Encrypt(plaintext, masterKey)
			if tt.shouldErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, ciphertext)
				assert.Len(t, iv, NonceSize)
				assert.Len(t, salt, SaltSize)

				// Verify decryption works
				decrypted, err := encryptor.Decrypt(ciphertext, iv, salt, masterKey)
				require.NoError(t, err)
				assert.Equal(t, plaintext, decrypted)
			}
		})
	}
}


// TestEncryptionWithAllZeroPlaintext tests encrypting data that's all zeros
func TestEncryptionWithAllZeroPlaintext(t *testing.T) {
	encryptor := NewAESGCMEncryptor()
	plaintext := make([]byte, 1024)
	masterKey := []byte("test-key")

	ciphertext, iv, salt, err := encryptor.Encrypt(plaintext, masterKey)
	require.NoError(t, err)

	// Even all-zero plaintext should produce non-zero ciphertext
	allZeros := true
	for _, b := range ciphertext {
		if b != 0 {
			allZeros = false
			break
		}
	}
	assert.False(t, allZeros, "ciphertext should not be all zeros")

	// Verify decryption
	decrypted, err := encryptor.Decrypt(ciphertext, iv, salt, masterKey)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

// TestMultipleConcurrentEncryptions tests concurrent encryption operations
func TestMultipleConcurrentEncryptions(t *testing.T) {
	encryptor := NewAESGCMEncryptor()
	plaintext := []byte("concurrent test message")
	masterKey := []byte("concurrent-test-key")

	const numGoroutines = 50
	results := make(chan struct {
		ciphertext []byte
		iv         []byte
		salt       []byte
		err        error
	}, numGoroutines)

	// Encrypt concurrently
	for i := 0; i < numGoroutines; i++ {
		go func() {
			ct, iv, salt, err := encryptor.Encrypt(plaintext, masterKey)
			results <- struct {
				ciphertext []byte
				iv         []byte
				salt       []byte
				err        error
			}{ct, iv, salt, err}
		}()
	}

	// Collect and verify results
	uniqueCiphertexts := make(map[string]bool)
	for i := 0; i < numGoroutines; i++ {
		result := <-results
		require.NoError(t, result.err)

		// Verify decryption
		decrypted, err := encryptor.Decrypt(result.ciphertext, result.iv, result.salt, masterKey)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)

		// Track uniqueness
		uniqueCiphertexts[string(result.ciphertext)] = true
	}

	// All ciphertexts should be unique
	assert.Len(t, uniqueCiphertexts, numGoroutines, "all concurrent encryptions should produce unique results")
}

// TestSaltUniqueness verifies GenerateSalt produces unique values
func TestSaltUniqueness(t *testing.T) {
	const numSalts = 1000
	salts := make(map[string]bool)

	for i := 0; i < numSalts; i++ {
		salt, err := GenerateSalt()
		require.NoError(t, err)
		require.Len(t, salt, SaltSize)

		key := string(salt)
		assert.False(t, salts[key], "duplicate salt generated")
		salts[key] = true
	}

	assert.Len(t, salts, numSalts, "all generated salts should be unique")
}
