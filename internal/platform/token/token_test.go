// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package token

import (
	"encoding/hex"
	"testing"
)

// TestGenerate_ShapeAndUniqueness pins the two properties every caller relies
// on: 256 bits of entropy, and a value that is not the thing that gets stored.
func TestGenerate_ShapeAndUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := range 128 {
		raw, hash, err := Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if len(raw) != tokenBytes*2 {
			t.Fatalf("raw length = %d hex chars, want %d (%d bytes)", len(raw), tokenBytes*2, tokenBytes)
		}
		if _, err := hex.DecodeString(raw); err != nil {
			t.Fatalf("raw is not hex: %v", err)
		}
		if hash == raw {
			t.Fatalf("hash equals the raw token; the stored value must not be the usable one")
		}
		if hash != Hash(raw) {
			t.Fatalf("Generate's hash disagrees with Hash(raw)")
		}
		if seen[raw] {
			t.Fatalf("Generate repeated a token after %d draws", i)
		}
		seen[raw] = true
	}
}

// TestHash_IsDeterministic — redemption looks a token up by its hash, so the
// same input must always land on the same row.
func TestHash_IsDeterministic(t *testing.T) {
	first := Hash("abc")
	second := Hash("abc")
	if first != second {
		t.Errorf("Hash is not deterministic")
	}
	if Hash("abc") == Hash("abd") {
		t.Errorf("distinct tokens collided")
	}
	if len(Hash("")) != 64 {
		t.Errorf("Hash length = %d, want 64 hex chars (sha256)", len(Hash("")))
	}
}
