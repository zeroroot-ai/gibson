// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package manifest

// WellKnownPath is the canonical HTTP path for the Agent Auth
// configuration document. Kept in sync with core/sdk/capabilitygrant/discovery.go's
// wellKnownPath constant.
const WellKnownPath = "/.well-known/agent-configuration"

// ManifestKeysDocument is the minimal shape consumers read to learn
// about the manifest signing keys. It is designed to be merged into
// the existing Agent Auth discovery document by decorator/composer
// patterns — consumers that only need the manifest keys hit this
// handler directly; production wires a top-level handler that combines
// this with the Agent Auth fields.
type ManifestKeysDocument struct {
	// ManifestSigningKeys lists public JWKs for every signing kid the
	// daemon will use. Active kid is always first; consumers may prefer
	// it for first-verification attempts during rotation windows.
	ManifestSigningKeys []SigningKeyJWK `json:"manifest_signing_keys"`
}
