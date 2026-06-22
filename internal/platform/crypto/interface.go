package crypto

// KeyDeriver defines the interface for key derivation functions.
// Implementations must derive cryptographic keys from a master key and salt
// in a deterministic and computationally expensive manner to resist brute-force attacks.
type KeyDeriver interface {
	// DeriveKey derives a cryptographic key from a master key and salt.
	// The same inputs must always produce the same output (deterministic).
	// Returns the derived key or an error if derivation fails.
	DeriveKey(masterKey, salt []byte) ([]byte, error)
}
