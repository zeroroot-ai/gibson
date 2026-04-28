// Package envelope implements per-record encryption using AES Key Wrap (RFC 3394)
// and AES-256-GCM. Each record receives a fresh DEK; the DEK is wrapped under
// the per-tenant KEK so that decryption with any other tenant's KEK fails with
// an AEAD authentication error.
package envelope

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
)

// ErrUnwrapAuth is returned by Unwrap when the AES Key Wrap integrity check
// fails. This happens when the wrapping KEK does not match the one used at
// Wrap time — the canonical signal for a cross-tenant decryption attempt.
var ErrUnwrapAuth = errors.New("envelope: AES-Unwrap authentication failed")

// aesWrapIV is the RFC 3394 default initial value (§2.2.3.1).
var aesWrapIV = [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// Wrap implements AES Key Wrap per RFC 3394 §2.2.1.
//
// kek must be 16, 24, or 32 bytes (AES-128/192/256).
// plaintext must be a multiple of 8 bytes and at least 16 bytes.
// Output is len(plaintext)+8 bytes (one integrity block prepended).
func Wrap(kek, plaintext []byte) ([]byte, error) {
	if len(plaintext)%8 != 0 || len(plaintext) < 16 {
		return nil, errors.New("envelope: AES-Wrap plaintext must be a multiple of 8 bytes, minimum 16")
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := len(plaintext) / 8 // number of 64-bit blocks

	// A is the integrity check register (ICR), initialised to the IV.
	A := aesWrapIV

	// R is a working copy of the key material.
	R := make([][]byte, n)
	for i := range R {
		R[i] = make([]byte, 8)
		copy(R[i], plaintext[i*8:])
	}

	// 6 rounds of n steps each (RFC 3394 §2.2.1, step 2).
	buf := make([]byte, 16) // scratch buffer for AES block
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			// B = AES(KEK, A || R[i])
			copy(buf[:8], A[:])
			copy(buf[8:], R[i])
			block.Encrypt(buf, buf)

			// A = MSB(64, B) XOR t, where t = (n*j)+i+1
			copy(A[:], buf[:8])
			t := uint64(n*j + i + 1)
			tBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(tBytes, t)
			for k := 0; k < 8; k++ {
				A[k] ^= tBytes[k]
			}

			// R[i] = LSB(64, B)
			copy(R[i], buf[8:])
		}
	}

	// Output: A || R[0] || R[1] || ... || R[n-1]
	out := make([]byte, 8+len(plaintext))
	copy(out[:8], A[:])
	for i, r := range R {
		copy(out[8+i*8:], r)
	}
	return out, nil
}

// Unwrap implements AES Key Unwrap per RFC 3394 §2.2.2.
//
// kek must be 16, 24, or 32 bytes (AES-128/192/256).
// ciphertext must be a multiple of 8 bytes and at least 24 bytes (one integrity
// block + at least two payload blocks).
//
// Returns ErrUnwrapAuth when the integrity check fails — the caller-visible
// signal that the wrapping KEK did not match.
func Unwrap(kek, ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%8 != 0 || len(ciphertext) < 24 {
		return nil, errors.New("envelope: AES-Unwrap ciphertext must be a multiple of 8 bytes, minimum 24")
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := len(ciphertext)/8 - 1 // number of 64-bit payload blocks

	// A is the integrity check register.
	var A [8]byte
	copy(A[:], ciphertext[:8])

	// R is a working copy of the wrapped key material.
	R := make([][]byte, n)
	for i := range R {
		R[i] = make([]byte, 8)
		copy(R[i], ciphertext[8+i*8:])
	}

	// 6 rounds of n steps each (RFC 3394 §2.2.2, step 2), in reverse.
	buf := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			// t = (n*j)+i+1
			t := uint64(n*j + i + 1)
			tBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(tBytes, t)

			// A = A XOR t
			for k := 0; k < 8; k++ {
				A[k] ^= tBytes[k]
			}

			// B = AES-1(KEK, (A XOR t) || R[i])
			copy(buf[:8], A[:])
			copy(buf[8:], R[i])
			block.Decrypt(buf, buf)

			// A = MSB(64, B)
			copy(A[:], buf[:8])

			// R[i] = LSB(64, B)
			copy(R[i], buf[8:])
		}
	}

	// Verify integrity: A must equal the IV.
	if A != aesWrapIV {
		return nil, ErrUnwrapAuth
	}

	// Reconstruct plaintext.
	out := make([]byte, n*8)
	for i, r := range R {
		copy(out[i*8:], r)
	}
	return out, nil
}
