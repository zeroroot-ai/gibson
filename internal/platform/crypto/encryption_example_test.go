package crypto_test

import (
	"fmt"
	"log"

	"github.com/zeroroot-ai/gibson/internal/platform/crypto"
)

// ExampleAESGCMEncryptor demonstrates basic usage of the AES-GCM encryptor
func ExampleAESGCMEncryptor() {
	// Create a new encryptor
	encryptor := crypto.NewAESGCMEncryptor()

	// Your master key (in production, this should come from secure storage)
	masterKey := []byte("my-super-secret-master-key-here!")

	// The sensitive data to encrypt
	plaintext := []byte("This is my secret message")

	// Encrypt the data
	// Note: Each encryption produces different output due to random salt and nonce
	ciphertext, iv, salt, err := encryptor.Encrypt(plaintext, masterKey)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}

	fmt.Printf("Encrypted successfully!\n")
	fmt.Printf("Ciphertext length: %d bytes\n", len(ciphertext))
	fmt.Printf("Nonce (IV) length: %d bytes\n", len(iv))
	fmt.Printf("Salt length: %d bytes\n", len(salt))

	// Decrypt the data
	// You must provide the same ciphertext, iv, salt, and master key
	decrypted, err := encryptor.Decrypt(ciphertext, iv, salt, masterKey)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}

	fmt.Printf("Decrypted successfully!\n")
	fmt.Printf("Original message: %s\n", string(decrypted))

	// Output:
	// Encrypted successfully!
	// Ciphertext length: 41 bytes
	// Nonce (IV) length: 12 bytes
	// Salt length: 32 bytes
	// Decrypted successfully!
	// Original message: This is my secret message
}

// ExampleAESGCMEncryptor_semanticSecurity demonstrates semantic security
func ExampleAESGCMEncryptor_semanticSecurity() {
	encryptor := crypto.NewAESGCMEncryptor()
	masterKey := []byte("my-secret-key-for-semantic-security")
	plaintext := []byte("Same message")

	// Encrypt the same message twice
	ciphertext1, _, _, _ := encryptor.Encrypt(plaintext, masterKey)
	ciphertext2, _, _, _ := encryptor.Encrypt(plaintext, masterKey)

	// The ciphertexts will be different despite encrypting the same message
	// This is semantic security - attackers cannot determine if two ciphertexts
	// encrypt the same plaintext
	if string(ciphertext1) == string(ciphertext2) {
		fmt.Println("Ciphertexts are the same (BAD - semantic security violation!)")
	} else {
		fmt.Println("Ciphertexts are different (GOOD - semantic security preserved!)")
	}

	// Output:
	// Ciphertexts are different (GOOD - semantic security preserved!)
}

// ExampleAESGCMEncryptor_authenticatedEncryption demonstrates tamper detection
func ExampleAESGCMEncryptor_authenticatedEncryption() {
	encryptor := crypto.NewAESGCMEncryptor()
	masterKey := []byte("my-secret-key-for-authentication")
	plaintext := []byte("Important data")

	// Encrypt the data
	ciphertext, iv, salt, _ := encryptor.Encrypt(plaintext, masterKey)

	// Try to tamper with the ciphertext (flip a bit)
	tamperedCiphertext := make([]byte, len(ciphertext))
	copy(tamperedCiphertext, ciphertext)
	tamperedCiphertext[0] ^= 0x01 // Flip one bit

	// Try to decrypt the tampered data
	_, err := encryptor.Decrypt(tamperedCiphertext, iv, salt, masterKey)
	if err != nil {
		fmt.Println("Tampered data detected! Decryption failed as expected.")
	} else {
		fmt.Println("Tampered data was NOT detected (BAD - security failure!)")
	}

	// Output:
	// Tampered data detected! Decryption failed as expected.
}
