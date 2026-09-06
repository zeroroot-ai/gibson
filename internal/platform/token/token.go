// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package token is the daemon's single primitive for bearer tokens that ride
// an emailed link.
//
// One shape, used everywhere: 32 bytes from crypto/rand, hex-encoded (256 bits
// of entropy), with only the sha256 hash persisted. The raw value exists in
// exactly two places — the response that hands it to the sender, and the link
// in the recipient's mailbox. It is never written to a database, never logged,
// and never returned by a lookup.
//
// Consumers: member invitations (internal/server/admin/invitation_store.go) and
// signup email verification (internal/server/daemon/api/signup_verification_store.go).
// Before this package the two grew their own copies; they now share one.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// tokenBytes is the raw entropy per token. 32 bytes = 256 bits, well past any
// feasible online or offline guessing budget for a value that also expires.
const tokenBytes = 32

// Generate returns a fresh random token and its sha256 hash.
//
// Persist hash. Send raw. Never the other way round: a store that holds the
// raw value turns a database read into an account takeover, which is the whole
// reason this package exists.
func Generate() (raw, hash string, err error) {
	buf := make([]byte, tokenBytes)
	if _, rerr := rand.Read(buf); rerr != nil {
		return "", "", fmt.Errorf("token: read random: %w", rerr)
	}
	raw = hex.EncodeToString(buf)
	return raw, Hash(raw), nil
}

// Hash returns the sha256 hash of a raw token, hex-encoded.
//
// This is the lookup key on redemption: the caller presents the raw token, the
// store searches by Hash(raw). A plain sha256 with no salt or stretching is
// correct here and would not be for a password — the input is 256 bits of
// uniform randomness, so there is no dictionary to attack and no work factor
// that would make a difference.
func Hash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
