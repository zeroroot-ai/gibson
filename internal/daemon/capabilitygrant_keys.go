package daemon

import (
	"context"
	"net/http"
	"strings"
)

// Capability-Grant public-key endpoint (epic unified-cg-identity, ADR-0045,
// gibson#648 / ext-authz#103).
//
// GET /capabilitygrant/v1/keys/{kid} returns a single-key JWKS for the kid:
//   - the daemon CG signing key when kid is the Minter's KeyID (verifies
//     daemon-minted dispatch CG-JWTs);
//   - a registered agent's public key when kid is an agentID (verifies a
//     component's self-signed per-RPC agent+jwt, whose kid is its agentID).
//
// ext-authz's CG-JWT verifier fetches this per-kid (bounded — one key per
// request, no JWKS-wide enumeration). Served on the pre-auth :8085 listener;
// public keys are non-secret.

// capabilityGrantKeysPath is the per-kid key endpoint prefix; the kid is the
// trailing path segment.
const capabilityGrantKeysPath = "/capabilitygrant/v1/keys/"

// cgKeyMinter is the daemon CG Minter subset the key endpoint needs.
type cgKeyMinter interface {
	KeyID() string
	PublicKeyJWKS() ([]byte, error)
}

// cgAgentKeyLookup resolves a registered agent's public key as a single-key JWKS.
type cgAgentKeyLookup interface {
	AgentPublicKeyJWKS(ctx context.Context, kid string) ([]byte, error)
}

// capabilityGrantKeysHandler serves the per-kid key document. minter and lookup
// are required; when either is nil the endpoint reports 503.
func capabilityGrantKeysHandler(minter cgKeyMinter, lookup cgAgentKeyLookup) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if minter == nil || lookup == nil {
			http.Error(w, "capability-grant keys not configured", http.StatusServiceUnavailable)
			return
		}
		kid := strings.TrimPrefix(r.URL.Path, capabilityGrantKeysPath)
		if kid == "" || strings.Contains(kid, "/") {
			http.Error(w, "kid path segment required", http.StatusBadRequest)
			return
		}

		var (
			body []byte
			err  error
		)
		if kid == minter.KeyID() {
			body, err = minter.PublicKeyJWKS()
		} else {
			body, err = lookup.AgentPublicKeyJWKS(r.Context(), kid)
		}
		if err != nil {
			// Unknown kid / inactive agent / parse failure — do not echo detail.
			http.Error(w, "unknown key", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(body)
	}
}
