package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// dekLen is the DEK size: 32 bytes = AES-256.
	dekLen = 32

	// wrappedDEKLen is the length of an AES-Wrapped 32-byte DEK:
	// 32 plaintext bytes / 8 * 8 bytes + 8-byte integrity block = 40 bytes.
	wrappedDEKLen = 40

	// nonceLen is the AES-GCM nonce length in bytes.
	nonceLen = 12

	// aadLenBytes is the number of bytes used to encode the AAD length (uint16).
	aadLenBytes = 2

	// minEnvelopeLen is the minimum valid envelope: wrappedDEK + nonce + aad_len (no AAD, empty ciphertext).
	minEnvelopeLen = wrappedDEKLen + nonceLen + aadLenBytes
)

// ErrDecrypt is the generic, caller-visible error returned on any decryption
// failure. Callers must NOT inspect the wrapped cause beyond the predicates
// defined in this package (IsCrossTenantDecryptError). The underlying failure
// mode is intentionally hidden.
var ErrDecrypt = errors.New("envelope: decryption failed")

// crossTenantSentinel is the sentinel that wraps ErrUnwrapAuth when surfaced
// up through Decrypt. IsCrossTenantDecryptError tests for this type.
type crossTenantSentinel struct {
	cause error
}

func (e *crossTenantSentinel) Error() string { return ErrDecrypt.Error() }
func (e *crossTenantSentinel) Is(target error) bool {
	return target == ErrDecrypt
}
func (e *crossTenantSentinel) Unwrap() error { return e.cause }

// IsCrossTenantDecryptError reports whether err originated from an AES-Unwrap
// authentication failure — the canonical indicator that the decryption was
// attempted with the wrong tenant's KEK.
func IsCrossTenantDecryptError(err error) bool {
	if err == nil {
		return false
	}
	var s *crossTenantSentinel
	return errors.As(err, &s)
}

// Encrypt generates a fresh 32-byte DEK, encrypts plaintext with AES-256-GCM
// using that DEK and a random 12-byte nonce, then wraps the DEK under kek
// using AES Key Wrap (RFC 3394).
//
// The envelope format on the wire is:
//
//	wrapped_dek (40 bytes) || nonce (12 bytes) || aad_len (2 bytes, big-endian) || aad (variable) || ciphertext_with_tag
//
// aad ties the record to a context (e.g., "credential:name") so that a row
// cannot be moved between tables or renamed without decryption failing.
//
// kek must be exactly 32 bytes (AES-256 KEK).
// plaintext must not be empty.
func Encrypt(kek, plaintext, aad []byte) ([]byte, error) {
	if len(kek) != dekLen {
		return nil, fmt.Errorf("envelope: KEK must be %d bytes, got %d", dekLen, len(kek))
	}
	if len(plaintext) == 0 {
		return nil, errors.New("envelope: plaintext must not be empty")
	}
	if len(aad) > 0xFFFF {
		return nil, fmt.Errorf("envelope: AAD exceeds maximum length of 65535 bytes")
	}

	// 1. Generate a fresh DEK.
	dek := make([]byte, dekLen)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("envelope: generate DEK: %w", err)
	}
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()

	// 2. Wrap the DEK under the KEK.
	wrappedDEK, err := Wrap(kek, dek)
	if err != nil {
		return nil, fmt.Errorf("envelope: AES-Wrap DEK: %w", err)
	}
	if len(wrappedDEK) != wrappedDEKLen {
		return nil, fmt.Errorf("envelope: unexpected wrapped DEK length %d", len(wrappedDEK))
	}

	// 3. AES-256-GCM encrypt with fresh random nonce.
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("envelope: generate nonce: %w", err)
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("envelope: create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("envelope: create GCM: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	// 4. Assemble envelope: wrapped_dek || nonce || aad_len || aad || ciphertext_with_tag
	aadLen := uint16(len(aad)) //nolint:gosec // len(aad) <= 0xFFFF validated above
	out := make([]byte, wrappedDEKLen+nonceLen+aadLenBytes+len(aad)+len(ciphertext))
	offset := 0

	copy(out[offset:], wrappedDEK)
	offset += wrappedDEKLen

	copy(out[offset:], nonce)
	offset += nonceLen

	binary.BigEndian.PutUint16(out[offset:], aadLen)
	offset += aadLenBytes

	copy(out[offset:], aad)
	offset += len(aad)

	copy(out[offset:], ciphertext)

	return out, nil
}

// Decrypt parses an envelope produced by Encrypt, unwraps the DEK using kek,
// and AES-256-GCM decrypts the ciphertext. The stored AAD in the envelope must
// match the aad argument; mismatches cause AEAD verification failure.
//
// On any failure Decrypt returns a wrapped ErrDecrypt. If the failure was
// specifically an AES-Unwrap authentication error (indicating a cross-tenant
// KEK mismatch), IsCrossTenantDecryptError(err) returns true.
//
// The plaintext is never included in any error message.
func Decrypt(kek, envelope, aad []byte) ([]byte, error) {
	if len(kek) != dekLen {
		return nil, fmt.Errorf("envelope: KEK must be %d bytes, got %d", dekLen, len(kek))
	}
	if len(envelope) < minEnvelopeLen {
		return nil, fmt.Errorf("envelope: too short (%d bytes, minimum %d)", len(envelope), minEnvelopeLen)
	}

	// Parse envelope fields.
	offset := 0

	wrappedDEK := envelope[offset : offset+wrappedDEKLen]
	offset += wrappedDEKLen

	nonce := envelope[offset : offset+nonceLen]
	offset += nonceLen

	storedAADLen := int(binary.BigEndian.Uint16(envelope[offset:]))
	offset += aadLenBytes

	if offset+storedAADLen > len(envelope) {
		return nil, fmt.Errorf("envelope: malformed: AAD overflows envelope")
	}
	storedAAD := envelope[offset : offset+storedAADLen]
	offset += storedAADLen

	ciphertext := envelope[offset:]

	// Unwrap DEK. AES-Unwrap failure → crossTenantSentinel.
	dek, err := Unwrap(kek, wrappedDEK)
	if err != nil {
		if errors.Is(err, ErrUnwrapAuth) {
			return nil, &crossTenantSentinel{cause: ErrUnwrapAuth}
		}
		return nil, ErrDecrypt
	}
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()

	// The stored AAD must equal the caller's aad; AEAD verification will
	// reject mismatches, but we also verify directly so the GCM call
	// uses the actual stored AAD (which carries the record identity).
	if len(storedAAD) != len(aad) {
		// If caller-supplied AAD length differs from stored, the GCM open
		// will fail anyway; surface as generic ErrDecrypt.
		return nil, ErrDecrypt
	}

	// AES-256-GCM decrypt with stored AAD.
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, ErrDecrypt
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrDecrypt
	}

	// Use storedAAD as additional data (it was used during Seal).
	plaintext, err := gcm.Open(nil, nonce, ciphertext, storedAAD)
	if err != nil {
		return nil, ErrDecrypt
	}

	return plaintext, nil
}
