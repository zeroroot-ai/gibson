package daemon

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Capability-Grant registration discovery (epic unified-cg-identity, ADR-0045,
// gibson#648).
//
// External components (agent / tool / plugin) bootstrap their Capability Grant
// by fetching this document, then POSTing an Ed25519 host registration to the
// advertised register endpoint. The SDK's capabilitygrant.Discover reads exactly
// these fields (opensource/sdk/capabilitygrant/discovery.go). The document is
// non-secret and unauthenticated by design: a component holds no Capability
// Grant yet at discovery time. It is served on the same pre-auth listener as the
// native-login bootstrap and published through Envoy on an allow_missing route.
const (
	// agentConfigWellKnownPath is the discovery document path. Kept in sync with
	// the SDK's wellKnownPath constant.
	agentConfigWellKnownPath = "/.well-known/agent-configuration"

	// capabilityGrantRegisterPath is the host-registration endpoint advertised by
	// the discovery document (served by the register handler, gibson#648).
	capabilityGrantRegisterPath = "/capabilitygrant/v1/register"

	// capabilityGrantProtocolVersion is the Capability Grant Protocol version this
	// daemon implements. The SDK requires >= its MinProtocolVersion ("1.0").
	capabilityGrantProtocolVersion = "1.0"

	// daemonJWKSPath is the daemon's CG-JWT signing JWKS, already published
	// through Envoy (the /.well-known/jwks.json route).
	daemonJWKSPath = "/.well-known/jwks.json"
)

// capabilityGrantSupportedModes are the agent execution modes the platform
// accepts during registration.
var capabilityGrantSupportedModes = []string{"delegated", "autonomous"}

// agentConfigEndpoints mirrors the SDK DiscoveryDocument.Endpoints shape.
type agentConfigEndpoints struct {
	Register   string `json:"register"`
	Execute    string `json:"execute"`
	List       string `json:"list"`
	Status     string `json:"status"`
	Revoke     string `json:"revoke"`
	Introspect string `json:"introspect"`
}

// agentConfigDocument is the JSON body served at /.well-known/agent-configuration.
// Field names and shape must match opensource/sdk/capabilitygrant.DiscoveryDocument.
type agentConfigDocument struct {
	ProtocolVersion string               `json:"protocol_version"`
	ProviderName    string               `json:"provider_name"`
	Issuer          string               `json:"issuer"`
	DefaultLocation string               `json:"default_location"`
	SupportedModes  []string             `json:"supported_modes"`
	Endpoints       agentConfigEndpoints `json:"endpoints"`
	JWKSURI         string               `json:"jwks_uri"`
}

// buildAgentConfigDocument assembles the discovery document from the daemon's
// public base URL. All endpoint URLs are absolute (the SDK uses them verbatim),
// so they resolve through Envoy regardless of which daemon listener serves each.
func buildAgentConfigDocument(publicURL string) agentConfigDocument {
	base := strings.TrimRight(publicURL, "/")
	return agentConfigDocument{
		ProtocolVersion: capabilityGrantProtocolVersion,
		ProviderName:    "Gibson",
		Issuer:          base,
		DefaultLocation: "global",
		SupportedModes:  capabilityGrantSupportedModes,
		Endpoints: agentConfigEndpoints{
			Register: base + capabilityGrantRegisterPath,
		},
		JWKSURI: base + daemonJWKSPath,
	}
}

// agentConfigHandler serves the Capability-Grant discovery document. publicURL is
// the daemon's public base URL (GIBSON_PUBLIC_URL). Returns 503 when it is unset
// so misconfiguration is loud rather than handing back unusable empty URLs.
func agentConfigHandler(publicURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if strings.TrimSpace(publicURL) == "" {
			http.Error(w, "capability-grant registration not configured (GIBSON_PUBLIC_URL unset)", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_ = json.NewEncoder(w).Encode(buildAgentConfigDocument(publicURL))
	}
}
