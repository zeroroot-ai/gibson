// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package manifest

// SignerKey is one Ed25519 keypair the Signer can sign and/or verify
// with. The Public half is required; Private may be nil for keys the
// Signer has been given solely for rotation-window verification.
type SignerKey struct {
}
