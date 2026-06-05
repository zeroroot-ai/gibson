package daemon

import (
	"context"
	"net/http"
	"strings"
)

// Capability-Grant public-key endpoint (epic unified-cg-identity, ADR-0045,
// gibson#648 / ext-authz#103).
//
// GET /capabilitygrant/v1/keys/{kid} returns a per-kid key document for the kid:
//   - the daemon CG signing key (bare JWKS) when kid is the Minter's KeyID
//     (verifies daemon-minted dispatch CG-JWTs, which carry their own claims);
//   - a registered agent's key DESCRIPTOR when kid is an agentID — a JWKS
//     superset that also carries the authoritative FGA principal + tenant
//     (ADR-0045). ext-authz verifies the component's self-signed agent+jwt
//     signature, then runs its per-method FGA check on the daemon-asserted
//     principal/tenant — it trusts no caller-asserted identity.
//
// ext-authz fetches this per-kid (bounded — one key per request, no JWKS-wide
// enumeration). Served on the pre-auth :8085 listener; public keys are
// non-secret.

// capabilityGrantKeysPath is the per-kid key endpoint prefix; the kid is the
// trailing path segment.
const capabilityGrantKeysPath = "/capabilitygrant/v1/keys/"

// cgKeyMinter is the daemon CG Minter subset the key endpoint needs.
type cgKeyMinter interface {
	KeyID() string
	PublicKeyJWKS() ([]byte, error)
}

// cgAgentKeyLookup resolves a registered agent's per-kid key descriptor (a JWKS
// superset carrying the authoritative FGA principal + tenant; ADR-0045).
type cgAgentKeyLookup interface {
	AgentKeyDescriptor(ctx context.Context, kid string) ([]byte, error)
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
			// The daemon's own dispatch key: bare JWKS (no component principal/
			// tenant — dispatch CG-JWTs carry their own claims). The descriptor's
			// `keys` field is JWKS-shaped, so ext-authz parses both uniformly.
			body, err = minter.PublicKeyJWKS()
		} else {
			body, err = lookup.AgentKeyDescriptor(r.Context(), kid)
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
