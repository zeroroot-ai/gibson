package crypto

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestNewAESGCMEncryptor(t *testing.T) {
	encryptor := NewAESGCMEncryptor()
	if encryptor == nil {
		t.Fatal("NewAESGCMEncryptor returned nil")
	}
	if encryptor.keyDeriver == nil {
		t.Fatal("keyDeriver is nil")
	}
}

func TestAESGCMEncryptor_Encrypt_Success(t *testing.T) {
	encryptor := NewAESGCMEncryptor()

	plaintext := []byte("This is a secret message that needs encryption")
	masterKey := []byte("my-super-secret-master-key-12345")

	ciphertext, iv, salt, err := encryptor.Encrypt(plaintext, masterKey)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify outputs are not nil
	if ciphertext == nil {
		t.Fatal("ciphertext is nil")
	}
	if iv == nil {
		t.Fatal("iv is nil")
	}
	if salt == nil {
		t.Fatal("salt is nil")
	}

	// Verify sizes
	if len(iv) != NonceSize {
		t.Errorf("nonce size = %d, want %d", len(iv), NonceSize)
	}
	if len(salt) != SaltSize {
		t.Errorf("salt size = %d, want %d", len(salt), SaltSize)
	}

	// Ciphertext should be longer than plaintext due to auth tag
	if len(ciphertext) <= len(plaintext) {
		t.Errorf("ciphertext length %d should be > plaintext length %d", len(ciphertext), len(plaintext))
	}

	// Ciphertext should not match plaintext
	if bytes.Equal(ciphertext[:len(plaintext)], plaintext) {
		t.Error("ciphertext matches plaintext (not encrypted)")
	}
}

func TestAESGCMEncryptor_EncryptDecrypt_RoundTrip(t *testing.T) {
	encryptor := NewAESGCMEncryptor()

	testCases := []struct {
		name      string
		plaintext []byte
		masterKey []byte
	}{
		{
			name:      "short message",
			plaintext: []byte("Hello, World!"),
			masterKey: []byte("my-secret-key-32-bytes-long!"),
		},
		{
			name:      "long message",
			plaintext: []byte("This is a much longer message that spans multiple AES blocks and should still encrypt and decrypt correctly without any issues whatsoever."),
			masterKey: []byte("another-master-key-for-testing"),
		},
		{
			name:      "binary data",
			plaintext: []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD, 0x10, 0x20, 0x30},
			masterKey: []byte("binary-data-encryption-key-123"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt
			ciphertext, iv, salt, err := encryptor.Encrypt(tc.plaintext, tc.masterKey)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			// Decrypt
			decrypted, err := encryptor.Decrypt(ciphertext, iv, salt, tc.masterKey)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			// Verify plaintext matches
			if !bytes.Equal(decrypted, tc.plaintext) {
				t.Errorf("decrypted = %q, want %q", decrypted, tc.plaintext)
			}
		})
	}
}

func TestAESGCMEncryptor_Encrypt_UniqueOutputs(t *testing.T) {
	encryptor := NewAESGCMEncryptor()

	plaintext := []byte("Same message encrypted multiple times")
	masterKey := []byte("same-master-key-every-time-12345")

	// Encrypt the same message 10 times
	var ciphertexts [][]byte
	var ivs [][]byte
	var salts [][]byte

	for i := 0; i < 10; i++ {
		ciphertext, iv, salt, err := encryptor.Encrypt(plaintext, masterKey)
		if err != nil {
			t.Fatalf("Encrypt iteration %d failed: %v", i, err)
		}
		ciphertexts = append(ciphertexts, ciphertext)
		ivs = append(ivs, iv)
		salts = append(salts, salt)
	}

	// Verify all ciphertexts are different (semantic security)
	for i := 0; i < len(ciphertexts); i++ {
		for j := i + 1; j < len(ciphertexts); j++ {
			if bytes.Equal(ciphertexts[i], ciphertexts[j]) {
				t.Errorf("ciphertexts[%d] == ciphertexts[%d] (should be unique)", i, j)
			}
		}
	}

	// Verify all nonces are different
	for i := 0; i < len(ivs); i++ {
		for j := i + 1; j < len(ivs); j++ {
			if bytes.Equal(ivs[i], ivs[j]) {
				t.Errorf("nonces[%d] == nonces[%d] (should be unique)", i, j)
			}
		}
	}

	// Verify all salts are different
	for i := 0; i < len(salts); i++ {
		for j := i + 1; j < len(salts); j++ {
			if bytes.Equal(salts[i], salts[j]) {
				t.Errorf("salts[%d] == salts[%d] (should be unique)", i, j)
			}
		}
	}
}

func TestAESGCMEncryptor_Encrypt_EmptyPlaintext(t *testing.T) {
	encryptor := NewAESGCMEncryptor()

	masterKey := []byte("master-key-for-empty-test-123456")

	_, _, _, err := encryptor.Encrypt([]byte{}, masterKey)
	if err == nil {
		t.Error("expected error for empty plaintext, got nil")
	}
}

func TestAESGCMEncryptor_Encrypt_EmptyMasterKey(t *testing.T) {
	encryptor := NewAESGCMEncryptor()

	plaintext := []byte("Some data to encrypt")

	_, _, _, err := encryptor.Encrypt(plaintext, []byte{})
	if err == nil {
		t.Error("expected error for empty master key, got nil")
	}
}

func TestAESGCMEncryptor_Decrypt_WrongKey(t *testing.T) {
	encryptor := NewAESGCMEncryptor()

	plaintext := []byte("Secret data")
	correctKey := []byte("correct-master-key-123456789012")
	wrongKey := []byte("wrong-master-key-0000000000000")

	// Encrypt with correct key
	ciphertext, iv, salt, err := encryptor.Encrypt(plaintext, correctKey)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Try to decrypt with wrong key
	_, err = encryptor.Decrypt(ciphertext, iv, salt, wrongKey)
	if err == nil {
		t.Error("expected error when decrypting with wrong key, got nil")
	}
}

func TestAESGCMEncryptor_Decrypt_TamperedCiphertext(t *testing.T) {
	encryptor := NewAESGCMEncryptor()

	plaintext := []byte("Important data that should not be tampered with")
	masterKey := []byte("master-key-for-tamper-test-12345")

	// Encrypt
	ciphertext, iv, salt, err := encryptor.Encrypt(plaintext, masterKey)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Tamper with ciphertext (flip a bit)
	tamperedCiphertext := make([]byte, len(ciphertext))
	copy(tamperedCiphertext, ciphertext)
	tamperedCiphertext[0] ^= 0x01

	// Try to decrypt tampered ciphertext
	_, err = encryptor.Decrypt(tamperedCiphertext, iv, salt, masterKey)
	if err == nil {
		t.Error("expected error when decrypting tampered ciphertext, got nil")
	}
}

func TestAESGCMEncryptor_Decrypt_TamperedNonce(t *testing.T) {
	encryptor := NewAESGCMEncryptor()

	plaintext := []byte("Data protected by authentication")
	masterKey := []byte("master-key-for-nonce-test-123456")

	// Encrypt
	ciphertext, iv, salt, err := encryptor.Encrypt(plaintext, masterKey)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Tamper with nonce
	tamperedIV := make([]byte, len(iv))
	copy(tamperedIV, iv)
	tamperedIV[0] ^= 0x01

	// Try to decrypt with tampered nonce
	_, err = encryptor.Decrypt(ciphertext, tamperedIV, salt, masterKey)
	if err == nil {
		t.Error("expected error when using tampered nonce, got nil")
	}
}

func TestAESGCMEncryptor_Decrypt_InvalidNonceSize(t *testing.T) {
	encryptor := NewAESGCMEncryptor()

	ciphertext := []byte("fake ciphertext")
	salt := make([]byte, SaltSize)
	masterKey := []byte("test-key-for-invalid-nonce-size")

	// Test with wrong nonce sizes
	testCases := []struct {
		name     string
		nonceLen int
	}{
		{"too short", 8},
		{"too long", 16},
		{"empty", 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			invalidNonce := make([]byte, tc.nonceLen)
			_, err := encryptor.Decrypt(ciphertext, invalidNonce, salt, masterKey)
			if err == nil {
				t.Errorf("expected error for nonce size %d, got nil", tc.nonceLen)
			}
		})
	}
}

func TestAESGCMEncryptor_Decrypt_InvalidSaltSize(t *testing.T) {
	encryptor := NewAESGCMEncryptor()

	ciphertext := []byte("fake ciphertext")
	nonce := make([]byte, NonceSize)
	masterKey := []byte("test-key-for-invalid-salt-size")

	// Test with wrong salt sizes
	testCases := []struct {
		name    string
		saltLen int
	}{
		{"too short", 16},
		{"too long", 64},
		{"empty", 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			invalidSalt := make([]byte, tc.saltLen)
			_, err := encryptor.Decrypt(ciphertext, nonce, invalidSalt, masterKey)
			if err == nil {
				t.Errorf("expected error for salt size %d, got nil", tc.saltLen)
			}
		})
	}
}

func TestAESGCMEncryptor_Decrypt_EmptyCiphertext(t *testing.T) {
	encryptor := NewAESGCMEncryptor()

	nonce := make([]byte, NonceSize)
	salt := make([]byte, SaltSize)
	masterKey := []byte("test-key-for-empty-ciphertext")

	_, err := encryptor.Decrypt([]byte{}, nonce, salt, masterKey)
	if err == nil {
		t.Error("expected error for empty ciphertext, got nil")
	}
}

// Benchmark encryption performance
func BenchmarkAESGCMEncryptor_Encrypt(b *testing.B) {
	encryptor := NewAESGCMEncryptor()
	plaintext := make([]byte, 1024) // 1KB
	masterKey := []byte("benchmark-master-key-32-bytes!!")

	// Fill with random data
	if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, err := encryptor.Encrypt(plaintext, masterKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark decryption performance
func BenchmarkAESGCMEncryptor_Decrypt(b *testing.B) {
	encryptor := NewAESGCMEncryptor()
	plaintext := make([]byte, 1024) // 1KB
	masterKey := []byte("benchmark-master-key-32-bytes!!")

	// Fill with random data and encrypt once
	if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
		b.Fatal(err)
	}

	ciphertext, iv, salt, err := encryptor.Encrypt(plaintext, masterKey)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := encryptor.Decrypt(ciphertext, iv, salt, masterKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark full round-trip
func BenchmarkAESGCMEncryptor_RoundTrip(b *testing.B) {
	encryptor := NewAESGCMEncryptor()
	plaintext := make([]byte, 1024) // 1KB
	masterKey := []byte("benchmark-master-key-32-bytes!!")

	// Fill with random data
	if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ciphertext, iv, salt, err := encryptor.Encrypt(plaintext, masterKey)
		if err != nil {
			b.Fatal(err)
		}

		_, err = encryptor.Decrypt(ciphertext, iv, salt, masterKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}
