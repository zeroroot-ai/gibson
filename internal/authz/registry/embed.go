// Package registry also embeds the generated registry.yaml so the daemon can
// serve the authz policy to ext-authz at runtime over its mTLS channel
// (deploy#852). This makes the daemon the single source of truth for the
// authz registry: ext-authz fetches the SAME bytes the daemon compiled in,
// eliminating the version-pinned OCI-artifact skew that silently default-
// denied newly-added RPCs (e.g. SetSignupProgress) when the published
// artifact lagged the deployed daemon.
//
// registry.go (the compiled-in Go map) and registry.yaml are generated
// together by `make authz-registry` from the same proto annotations at the
// same commit, so the embedded bytes can never disagree with the daemon's
// own enforcement view.
package registry

import _ "embed"

//go:embed registry.yaml
var yamlBytes []byte

// YAML returns the embedded, generated registry.yaml bytes verbatim. The
// daemon's authz-registry mTLS endpoint serves these to ext-authz; the bytes
// parse through ext-authz's fga.LoadRegistry unchanged (same generator).
func YAML() []byte {
	// Return a defensive copy so callers cannot mutate the embedded backing
	// array (which is process-global).
	out := make([]byte, len(yamlBytes))
	copy(out, yamlBytes)
	return out
}
