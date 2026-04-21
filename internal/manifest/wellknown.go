package manifest

import (
	"encoding/json"
	"net/http"
)

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

// ManifestKeysHandler returns an HTTP handler that serves the manifest
// signing keys portion of the /.well-known/agent-configuration document.
// Expected usage: the daemon's existing discovery handler builds its
// own DiscoveryDocument shape and merges this output into its JSON
// response. Dev setups that don't yet have a combined handler can mount
// this at WellKnownPath directly.
//
// The signer argument is required; handler returns 503 when nil at
// request time so a later wire-up is safe.
func ManifestKeysHandler(signer Signer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if signer == nil {
			http.Error(w, "manifest signing keys not configured", http.StatusServiceUnavailable)
			return
		}
		doc := ManifestKeysDocument{ManifestSigningKeys: signer.PublishedKeys()}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=60")
		_ = json.NewEncoder(w).Encode(doc)
	})
}

// MergeManifestKeys is a helper for discovery-document composers. Given
// an arbitrary JSON-encodable discovery document body and a Signer, it
// produces a merged map[string]any that includes manifest_signing_keys
// as a top-level field. Existing keys take precedence so callers can
// override — the helper is deliberately non-destructive.
func MergeManifestKeys(existing map[string]any, signer Signer) map[string]any {
	out := make(map[string]any, len(existing)+1)
	for k, v := range existing {
		out[k] = v
	}
	if _, alreadySet := out["manifest_signing_keys"]; !alreadySet && signer != nil {
		out["manifest_signing_keys"] = signer.PublishedKeys()
	}
	return out
}
