// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package envelope_test

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/tenant/cmd/gibson-backup/internal/envelope"
)

func randomKey(t *testing.T, n int) []byte {
	t.Helper()
	k := make([]byte, n)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return k
}

// TestSealOpenRoundtrip verifies that Seal followed by Open recovers the
// original plaintext for all valid AES key sizes.
func TestSealOpenRoundtrip(t *testing.T) {
	keySizes := []int{16, 24, 32}
	plaintext := []byte("the quick brown fox jumps over the lazy dog — tenant backup payload 🔐")

	for _, ks := range keySizes {
		t.Run(strings.ReplaceAll(strings.ReplaceAll(t.Name(), "=", "_"), "/", "_"), func(t *testing.T) {
			kek := randomKey(t, ks)

			var cipherBuf bytes.Buffer
			n, err := envelope.Seal(&cipherBuf, bytes.NewReader(plaintext), kek)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			if n == 0 {
				t.Fatal("Seal: wrote 0 bytes")
			}
			// Encrypted output must be larger than plaintext (header + tag overhead).
			if n <= int64(len(plaintext)) {
				t.Errorf("Seal: output %d bytes <= plaintext %d bytes", n, len(plaintext))
			}

			var plainBuf bytes.Buffer
			if err := envelope.Open(&plainBuf, bytes.NewReader(cipherBuf.Bytes()), kek); err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(plainBuf.Bytes(), plaintext) {
				t.Errorf("Open: got %q, want %q", plainBuf.Bytes(), plaintext)
			}
		})
	}
}

// TestSealOpenEmptyPlaintext verifies that empty content round-trips correctly.
func TestSealOpenEmptyPlaintext(t *testing.T) {
	kek := randomKey(t, 32)
	var cipherBuf bytes.Buffer
	if _, err := envelope.Seal(&cipherBuf, bytes.NewReader(nil), kek); err != nil {
		t.Fatalf("Seal empty: %v", err)
	}

	var plainBuf bytes.Buffer
	if err := envelope.Open(&plainBuf, bytes.NewReader(cipherBuf.Bytes()), kek); err != nil {
		t.Fatalf("Open empty: %v", err)
	}
	if plainBuf.Len() != 0 {
		t.Errorf("Open empty: expected 0 bytes, got %d", plainBuf.Len())
	}
}

// TestOpenWrongKEK verifies that decryption fails when the wrong KEK is used.
func TestOpenWrongKEK(t *testing.T) {
	kek1 := randomKey(t, 32)
	kek2 := randomKey(t, 32)

	var cipherBuf bytes.Buffer
	if _, err := envelope.Seal(&cipherBuf, bytes.NewReader([]byte("secret data")), kek1); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	var plainBuf bytes.Buffer
	err := envelope.Open(&plainBuf, bytes.NewReader(cipherBuf.Bytes()), kek2)
	if err == nil {
		t.Fatal("Open with wrong KEK should fail but returned nil")
	}
}

// TestSealInvalidKEK verifies that an invalid KEK length is rejected.
func TestSealInvalidKEK(t *testing.T) {
	badKEK := make([]byte, 10) // not 16/24/32
	_, err := envelope.Seal(bytes.NewBuffer(nil), bytes.NewReader([]byte("data")), badKEK)
	if err == nil {
		t.Fatal("expected error for invalid KEK length")
	}
}

// TestOpenInvalidKEK verifies that an invalid KEK length is rejected on open.
func TestOpenInvalidKEK(t *testing.T) {
	badKEK := make([]byte, 10)
	err := envelope.Open(bytes.NewBuffer(nil), bytes.NewReader([]byte("data")), badKEK)
	if err == nil {
		t.Fatal("expected error for invalid KEK length")
	}
}

// TestOpenTruncatedBlob verifies that a truncated blob produces an error.
func TestOpenTruncatedBlob(t *testing.T) {
	kek := randomKey(t, 32)
	var cipherBuf bytes.Buffer
	if _, err := envelope.Seal(&cipherBuf, bytes.NewReader([]byte("hello")), kek); err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Truncate the ciphertext to less than the minimum valid size.
	truncated := cipherBuf.Bytes()[:10]
	err := envelope.Open(bytes.NewBuffer(nil), bytes.NewReader(truncated), kek)
	if err == nil {
		t.Fatal("expected error for truncated blob")
	}
}

// TestSealOutputSize verifies that the output size matches the expected formula:
// HeaderLen (52) + len(plaintext) + 16 (GCM tag).
func TestSealOutputSize(t *testing.T) {
	kek := randomKey(t, 32)
	pt := []byte("exactly-16 bytes")
	var buf bytes.Buffer
	n, err := envelope.Seal(&buf, bytes.NewReader(pt), kek)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	want := int64(envelope.HeaderLen + len(pt) + 16)
	if n != want {
		t.Errorf("Seal output size: got %d, want %d", n, want)
	}
}
