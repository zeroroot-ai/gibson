package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/scrypt"
)

const (
	// KeySize is the size of encryption keys in bytes (256 bits for AES-256)
	KeySize = 32

	// NonceSize is the size of the AES-GCM nonce in bytes
	NonceSize = 12

	// SaltSize is the size of the salt in bytes
	// 32 bytes (256 bits) provides strong resistance against rainbow table attacks
	SaltSize = 32

	// ScryptN is the CPU/memory cost parameter (N)
	// 32768 provides strong security while remaining practical for server use
	ScryptN = 32768

	// ScryptR is the block size parameter (r)
	ScryptR = 8

	// ScryptP is the parallelization parameter (p)
	ScryptP = 1
)

// GenerateSalt generates a cryptographically secure random salt.
// The salt must be unique for each encryption operation to ensure that
// the same plaintext encrypted twice produces different ciphertexts.
// This prevents rainbow table attacks and ensures semantic security.
//
// Returns:
//   - Random salt of SaltSize bytes
//   - Error if random generation fails
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)

	// Read random bytes from the system's cryptographically secure PRNG
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate random salt: %w", err)
	}

	return salt, nil
}

// ScryptDeriver implements KeyDeriver using scrypt key derivation function.
// Scrypt is specifically designed to be memory-hard, making it resistant to
// hardware brute-force attacks (ASIC, GPU).
type ScryptDeriver struct {
	n      int // CPU/memory cost parameter
	r      int // Block size parameter
	p      int // Parallelization parameter
	keyLen int // Length of derived key
}

// NewScryptDeriver creates a new ScryptDeriver with secure default parameters.
// The default parameters (N=32768, r=8, p=1) provide strong security while
// remaining practical for server-side use. The derived key length is 32 bytes
// for AES-256 encryption.
func NewScryptDeriver() *ScryptDeriver {
	return &ScryptDeriver{
		n:      ScryptN,
		r:      ScryptR,
		p:      ScryptP,
		keyLen: KeySize, // 32 bytes for AES-256
	}
}

// DeriveKey derives a cryptographic key from a master key and salt using scrypt.
// The derivation is deterministic: the same inputs always produce the same output.
// This allows us to derive the same encryption key from the master key when needed.
//
// Parameters:
//   - masterKey: The master password/key to derive from
//   - salt: A unique random salt (must be SaltSize bytes)
//
// Returns:
//   - Derived key of length keyLen bytes
//   - Error if derivation fails or parameters are invalid
func (d *ScryptDeriver) DeriveKey(masterKey, salt []byte) ([]byte, error) {
	if len(masterKey) == 0 {
		return nil, fmt.Errorf("master key cannot be empty")
	}

	if len(salt) != SaltSize {
		return nil, fmt.Errorf("invalid salt size: expected %d bytes, got %d bytes", SaltSize, len(salt))
	}

	// Derive the key using scrypt
	// scrypt(password, salt, N, r, p, keyLen)
	key, err := scrypt.Key(masterKey, salt, d.n, d.r, d.p, d.keyLen)
	if err != nil {
		return nil, fmt.Errorf("scrypt key derivation failed: %w", err)
	}

	return key, nil
}

// Encryptor defines the interface for encryption and decryption operations.
// Implementations must provide authenticated encryption to ensure both
// confidentiality and integrity of the encrypted data.
type Encryptor interface {
	// Encrypt encrypts plaintext using the provided master key.
	// Returns the ciphertext, nonce (IV), salt, and any error encountered.
	// The nonce and salt must be stored alongside the ciphertext for decryption.
	Encrypt(plaintext, masterKey []byte) (ciphertext, iv, salt []byte, err error)

	// Decrypt decrypts ciphertext using the provided master key, nonce, and salt.
	// Returns the plaintext or an error if decryption fails or data has been tampered with.
	Decrypt(ciphertext, iv, salt, masterKey []byte) (plaintext []byte, err error)
}

// AESGCMEncryptor implements Encryptor using AES-256-GCM.
// GCM (Galois/Counter Mode) provides authenticated encryption, which means it
// ensures both confidentiality (encryption) and integrity (authentication).
// This prevents attackers from tampering with encrypted data.
type AESGCMEncryptor struct {
	keyDeriver KeyDeriver
}

// NewAESGCMEncryptor creates a new AESGCMEncryptor with ScryptDeriver.
// The encryptor uses scrypt for key derivation and AES-256-GCM for encryption.
// This combination provides strong security against both brute-force and
// tampering attacks.
func NewAESGCMEncryptor() *AESGCMEncryptor {
	return &AESGCMEncryptor{
		keyDeriver: NewScryptDeriver(),
	}
}

// Encrypt encrypts plaintext using AES-256-GCM with authenticated encryption.
// The encryption process:
// 1. Generate a unique random salt for key derivation
// 2. Derive an encryption key from the master key and salt using scrypt
// 3. Create an AES-256 cipher with the derived key
// 4. Create a GCM cipher mode for authenticated encryption
// 5. Generate a unique random nonce (never reuse!)
// 6. Encrypt the plaintext and compute authentication tag
//
// Parameters:
//   - plaintext: Data to encrypt (can be any length)
//   - masterKey: Master encryption key (must not be empty)
//
// Returns:
//   - ciphertext: Encrypted data with authentication tag appended
//   - iv: Nonce used for encryption (must be stored with ciphertext)
//   - salt: Salt used for key derivation (must be stored with ciphertext)
//   - err: Error if encryption fails
//
// SECURITY NOTES:
//   - The nonce MUST be unique for every encryption with the same key
//   - The salt MUST be unique for every encryption operation
//   - Never reuse a nonce with the same key (catastrophic security failure)
//   - The authentication tag in ciphertext prevents tampering
func (e *AESGCMEncryptor) Encrypt(plaintext, masterKey []byte) (ciphertext, iv, salt []byte, err error) {
	// Validate inputs
	if len(plaintext) == 0 {
		return nil, nil, nil, fmt.Errorf("plaintext cannot be empty")
	}

	if len(masterKey) == 0 {
		return nil, nil, nil, fmt.Errorf("master key cannot be empty")
	}

	// Step 1: Generate a unique random salt for key derivation
	// The salt prevents rainbow table attacks and ensures the same master key
	// produces different encryption keys for different encryptions
	salt, err = GenerateSalt()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Step 2: Derive encryption key from master key and salt
	// scrypt makes this computationally expensive to resist brute-force attacks
	derivedKey, err := e.keyDeriver.DeriveKey(masterKey, salt)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Step 3: Create AES cipher with the derived key
	// AES-256 requires a 32-byte key
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Step 4: Create GCM cipher mode
	// GCM provides authenticated encryption (confidentiality + integrity)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Verify nonce size matches GCM requirements
	if gcm.NonceSize() != NonceSize {
		return nil, nil, nil, fmt.Errorf("unexpected GCM nonce size: got %d, expected %d", gcm.NonceSize(), NonceSize)
	}

	// Step 5: Generate a unique random nonce (IV)
	// The nonce MUST be unique for every encryption with the same key
	// Nonce reuse with GCM is catastrophic and completely breaks security
	iv = make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Step 6: Encrypt plaintext with GCM
	// GCM.Seal encrypts the plaintext and appends an authentication tag
	// The authentication tag allows detection of any tampering with the ciphertext
	// nil as dst means a new slice is allocated
	// nil as additional data (could be used for authenticated but unencrypted data)
	ciphertext = gcm.Seal(nil, iv, plaintext, nil)

	return ciphertext, iv, salt, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM and verifies the authentication tag.
// The decryption process:
// 1. Derive the encryption key from master key and salt using scrypt
// 2. Create an AES-256 cipher with the derived key
// 3. Create a GCM cipher mode for authenticated decryption
// 4. Decrypt the ciphertext and verify the authentication tag
//
// Parameters:
//   - ciphertext: Encrypted data with authentication tag appended
//   - iv: Nonce used during encryption (must be exact same value)
//   - salt: Salt used during key derivation (must be exact same value)
//   - masterKey: Master encryption key (must be exact same key)
//
// Returns:
//   - plaintext: Decrypted data
//   - err: Error if decryption fails or authentication tag verification fails
//
// SECURITY NOTES:
//   - If the authentication tag is invalid, an error is returned
//   - Authentication failure indicates the data has been tampered with
//   - Never return partially decrypted data if authentication fails
//   - The error message intentionally does not distinguish between wrong key
//     and tampered data to avoid giving attackers information
func (e *AESGCMEncryptor) Decrypt(ciphertext, iv, salt, masterKey []byte) (plaintext []byte, err error) {
	// Validate inputs
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext cannot be empty")
	}

	if len(iv) != NonceSize {
		return nil, fmt.Errorf("invalid nonce size: expected %d bytes, got %d bytes", NonceSize, len(iv))
	}

	if len(salt) != SaltSize {
		return nil, fmt.Errorf("invalid salt size: expected %d bytes, got %d bytes", SaltSize, len(salt))
	}

	if len(masterKey) == 0 {
		return nil, fmt.Errorf("master key cannot be empty")
	}

	// Step 1: Derive the same encryption key from master key and salt
	// The same master key and salt will produce the exact same derived key
	derivedKey, err := e.keyDeriver.DeriveKey(masterKey, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Step 2: Create AES cipher with the derived key
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Step 3: Create GCM cipher mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Step 4: Decrypt and verify authentication tag
	// GCM.Open verifies the authentication tag and decrypts if valid
	// If the tag is invalid (data tampered with), this returns an error
	// nil as dst means a new slice is allocated
	// nil as additional data (must match what was used in Encrypt)
	plaintext, err = gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		// Intentionally generic error message to avoid leaking information
		// Could be: wrong key, tampered data, corrupted ciphertext, etc.
		return nil, fmt.Errorf("decryption failed: authentication verification failed or invalid key")
	}

	return plaintext, nil
}
