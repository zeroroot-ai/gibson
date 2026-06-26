// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package envelope implements client-side encryption for backup blobs.
//
// Wire format:
//
//	[ wrapped_dek (40 bytes) | nonce (12 bytes) | AES-256-GCM ciphertext ]
//
// The DEK is a fresh random 32-byte key generated per backup blob.
// The DEK is wrapped with the tenant KEK using RFC 3394 AES Key Wrap (AES-KW).
// The backup content is encrypted with AES-256-GCM using the DEK and a random
// 12-byte nonce. The GCM tag is appended by the standard library to the end of
// the ciphertext, so the total overhead is 40 + 12 + 16 = 68 bytes.
//
// KEK derivation is done outside this package (see internal/dataplane/kek.go in
// the tenant-operator module). The caller passes the derived 32-byte KEK.
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
	// DEKLen is the length of the per-blob data encryption key in bytes.
	DEKLen = 32

	// NonceLen is the AES-GCM nonce length in bytes.
	NonceLen = 12

	// WrappedDEKLen is the length of an RFC-3394-wrapped 32-byte key.
	// AES-KW adds an 8-byte integrity block, so: 32 + 8 = 40 bytes.
	WrappedDEKLen = 40

	// HeaderLen is the total number of bytes preceding the ciphertext:
	// wrapped DEK (40) + nonce (12).
	HeaderLen = WrappedDEKLen + NonceLen
)

// ErrInvalidKEKLength is returned when the KEK is not 16, 24, or 32 bytes.
var ErrInvalidKEKLength = errors.New("envelope: KEK must be 16, 24, or 32 bytes (AES-128/192/256)")

// Seal encrypts plaintext from src using the supplied KEK, writes the
// encrypted blob (header + ciphertext) to dst, and returns the number of
// bytes written and the SHA-256 hex digest of the written bytes.
//
// The caller should pass an io.Writer backed by a hash.Hash tee-writer if a
// concurrent SHA-256 is desired; alternatively the caller can wrap dst before
// calling Seal.
func Seal(dst io.Writer, src io.Reader, kek []byte) (int64, error) {
	if err := validateKEKLen(kek); err != nil {
		return 0, err
	}

	// Generate a fresh DEK.
	dek := make([]byte, DEKLen)
	if _, err := rand.Read(dek); err != nil {
		return 0, fmt.Errorf("envelope: generate DEK: %w", err)
	}
	defer zeroBytes(dek)

	// Wrap the DEK with the KEK using RFC 3394 AES-KW.
	wrappedDEK, err := aesKeyWrap(kek, dek)
	if err != nil {
		return 0, fmt.Errorf("envelope: wrap DEK: %w", err)
	}

	// Generate a random nonce.
	nonce := make([]byte, NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return 0, fmt.Errorf("envelope: generate nonce: %w", err)
	}

	// Read all plaintext. For large backups callers should ensure src is
	// already a streaming source (e.g., pg_dump piped directly); we buffer
	// here because GCM Seal requires all plaintext before producing output.
	// For very large databases, callers should switch to a chunked approach
	// (out of scope for v1).
	plaintext, err := io.ReadAll(src)
	if err != nil {
		return 0, fmt.Errorf("envelope: read plaintext: %w", err)
	}

	// Build the AES-256-GCM cipher.
	block, err := aes.NewCipher(dek)
	if err != nil {
		return 0, fmt.Errorf("envelope: AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0, fmt.Errorf("envelope: GCM: %w", err)
	}

	// Encrypt (appends 16-byte GCM tag to ciphertext).
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Write header: wrapped DEK || nonce.
	var written int64
	n, err := dst.Write(wrappedDEK)
	written += int64(n)
	if err != nil {
		return written, fmt.Errorf("envelope: write wrapped DEK: %w", err)
	}
	n, err = dst.Write(nonce)
	written += int64(n)
	if err != nil {
		return written, fmt.Errorf("envelope: write nonce: %w", err)
	}

	// Write ciphertext (includes GCM tag).
	n, err = dst.Write(ciphertext)
	written += int64(n)
	if err != nil {
		return written, fmt.Errorf("envelope: write ciphertext: %w", err)
	}

	return written, nil
}

// Open decrypts an encrypted blob produced by Seal. It reads the full blob
// from src, unwraps the DEK, decrypts the ciphertext, and writes plaintext
// to dst.
func Open(dst io.Writer, src io.Reader, kek []byte) error {
	if err := validateKEKLen(kek); err != nil {
		return err
	}

	blob, err := io.ReadAll(src)
	if err != nil {
		return fmt.Errorf("envelope: read blob: %w", err)
	}
	if len(blob) < HeaderLen+16 { // 16 == GCM tag minimum
		return fmt.Errorf("envelope: blob too short: %d bytes", len(blob))
	}

	wrappedDEK := blob[:WrappedDEKLen]
	nonce := blob[WrappedDEKLen:HeaderLen]
	ciphertext := blob[HeaderLen:]

	dek, err := aesKeyUnwrap(kek, wrappedDEK)
	if err != nil {
		return fmt.Errorf("envelope: unwrap DEK: %w", err)
	}
	defer zeroBytes(dek)

	block, err := aes.NewCipher(dek)
	if err != nil {
		return fmt.Errorf("envelope: AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("envelope: GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("envelope: GCM decrypt: %w", err)
	}

	if _, err := dst.Write(plaintext); err != nil {
		return fmt.Errorf("envelope: write plaintext: %w", err)
	}
	return nil
}

// validateKEKLen returns an error if kek is not a valid AES key length.
func validateKEKLen(kek []byte) error {
	switch len(kek) {
	case 16, 24, 32:
		return nil
	default:
		return ErrInvalidKEKLength
	}
}

// zeroBytes overwrites b with zeros to minimise key material residency.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// --- RFC 3394 AES Key Wrap / Unwrap ---
//
// The Go standard library does not include RFC 3394 (AESWRAP). We implement
// the wrap/unwrap here. The implementation follows RFC 3394 §2.2.1 and §2.2.2
// exactly, using the well-known default IV (0xA6A6A6A6A6A6A6A6).

// defaultIV is the RFC 3394 default initial value.
var defaultIV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// aesKeyWrap wraps keyData with the wrapping key kek.
// Returns the wrapped key of length len(keyData)+8.
func aesKeyWrap(kek, keyData []byte) ([]byte, error) {
	if len(keyData)%8 != 0 {
		return nil, errors.New("envelope/aeskw: key data length must be a multiple of 8")
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := len(keyData) / 8
	R := make([][]byte, n)
	for i := range R {
		R[i] = make([]byte, 8)
		copy(R[i], keyData[i*8:])
	}

	A := make([]byte, 8)
	copy(A, defaultIV)

	buf := make([]byte, 16)
	for j := 0; j <= 5; j++ {
		for i := range n {
			copy(buf[:8], A)
			copy(buf[8:], R[i])
			block.Encrypt(buf, buf)
			copy(A, buf[:8])
			t := uint64(n*j + i + 1)
			xorUint64(A, t)
			copy(R[i], buf[8:])
		}
	}

	out := make([]byte, (n+1)*8)
	copy(out, A)
	for i := range R {
		copy(out[(i+1)*8:], R[i])
	}
	return out, nil
}

// aesKeyUnwrap unwraps a key wrapped with aesKeyWrap.
// Returns the unwrapped key or an error if integrity check fails.
func aesKeyUnwrap(kek, wrappedKey []byte) ([]byte, error) {
	if len(wrappedKey) < 24 || (len(wrappedKey)-8)%8 != 0 {
		return nil, errors.New("envelope/aeskw: invalid wrapped key length")
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := (len(wrappedKey) / 8) - 1
	R := make([][]byte, n)
	A := make([]byte, 8)
	copy(A, wrappedKey[:8])
	for i := range R {
		R[i] = make([]byte, 8)
		copy(R[i], wrappedKey[(i+1)*8:])
	}

	buf := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			t := uint64(n*j + i + 1)
			xorUint64(A, t)
			copy(buf[:8], A)
			copy(buf[8:], R[i])
			block.Decrypt(buf, buf)
			copy(A, buf[:8])
			copy(R[i], buf[8:])
		}
	}

	// Verify the IV.
	for i := range defaultIV {
		if A[i] != defaultIV[i] {
			return nil, errors.New("envelope/aeskw: integrity check failed — wrong KEK or corrupt blob")
		}
	}

	out := make([]byte, n*8)
	for i := range R {
		copy(out[i*8:], R[i])
	}
	return out, nil
}

// xorUint64 XORs the big-endian representation of t into b in-place.
func xorUint64(b []byte, t uint64) {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], t)
	for i := range tmp {
		b[i] ^= tmp[i]
	}
}
