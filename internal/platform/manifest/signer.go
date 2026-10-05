// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package manifest

import (
	"crypto/ed25519"
	"errors"
	"sync"
)

// SignerKey is one Ed25519 keypair the Signer can sign and/or verify
// with. The Public half is required; Private may be nil for keys the
// Signer has been given solely for rotation-window verification.
type SignerKey struct {
	Kid     string
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// ed25519Signer is the concrete Signer backed by crypto/ed25519.
// It holds a map of all known keys (active + any still-valid predecessors
// during rotation) and signs with the single key identified by activeKid.
type ed25519Signer struct {
	mu        sync.RWMutex
	keys      map[string]SignerKey // kid → key
	activeKid string
}

// Sentinel errors surfaced by Verify so callers can distinguish between
// a missing-key-for-kid problem (rotation miss) and a body-mismatch
// problem (tamper or corruption).
var (
	// ErrMissingSignature is returned when a manifest has no signature bytes.
	ErrMissingSignature = errors.New("manifest: signature missing")

	// ErrUnknownSigningKey is returned when manifest.signing_key_id names
	// a kid this Signer does not hold. Common during a rotation window
	// when a predecessor Signer hasn't yet been cycled out everywhere.
	ErrUnknownSigningKey = errors.New("manifest: unknown signing_key_id")

	// ErrBadSignature is returned when the signature verification fails.
	// Always treat this as a tamper signal — never retry.
	ErrBadSignature = errors.New("manifest: signature verification failed")
)
