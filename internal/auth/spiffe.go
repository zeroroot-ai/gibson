package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	sdkauth "github.com/zero-day-ai/sdk/auth"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// spiffeFGABypass is the hardcoded allowlist of SPIFFE IDs whose requests bypass
// OpenFGA authorization checks. Only infrastructure components that need
// system-wide access without per-resource FGA checks are listed here.
//
// Dashboard needs FGA bypass for system-level RPCs (signup, provisioning, etc.)
// that operate before a tenant or user context is established.
// Daemon needs FGA bypass for inter-service operations.
var spiffeFGABypass = map[string]bool{
	"spiffe://gibson.io/platform/dashboard": true,
	"spiffe://gibson.io/platform/daemon":    true,
}

// extractSPIFFEID extracts the SPIFFE ID from the TLS peer certificate SAN
// in the gRPC request context. Returns the SPIFFE URI string and true if
// a SPIFFE SAN is present, or empty string and false otherwise.
//
// This function never returns an error — an absent or non-SPIFFE peer cert
// simply returns ("", false), routing the request to token-based auth paths.
func extractSPIFFEID(ctx context.Context) (string, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return "", false
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return "", false
	}

	cert := tlsInfo.State.PeerCertificates[0]
	for _, uri := range cert.URIs {
		if uri.Scheme == "spiffe" {
			return uri.String(), true
		}
	}
	return "", false
}

// spiffeToIdentity maps a SPIFFE ID to a Gibson Identity with the appropriate role.
//
// Role mapping:
//   - spiffe://gibson.io/platform/dashboard → platform-service (FGA bypass; acts on behalf of users)
//   - spiffe://gibson.io/platform/daemon    → platform-operator (FGA bypass; cross-tenant)
//   - spiffe://gibson.io/tool/*             → component (FGA governed)
//   - spiffe://gibson.io/agent/*            → component (FGA governed)
//   - spiffe://gibson.io/plugin/*           → component (FGA governed)
//
// Unknown SPIFFE IDs (outside the gibson.io trust domain or unrecognised paths)
// are rejected with ErrUnknownSPIFFEID so the interceptor returns Unauthenticated.
func spiffeToIdentity(spiffeID string) (*Identity, error) {
	id := &Identity{
		Identity: sdkauth.Identity{
			Subject:         spiffeID,
			Issuer:          "spiffe",
			AuthenticatedAt: time.Now(),
			ExpiresAt:       time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		},
	}

	switch {
	case spiffeID == "spiffe://gibson.io/platform/dashboard":
		id.Roles = []string{"platform-service"}
	case spiffeID == "spiffe://gibson.io/platform/daemon":
		id.Roles = []string{"platform-operator"}
	case strings.HasPrefix(spiffeID, "spiffe://gibson.io/tool/"),
		strings.HasPrefix(spiffeID, "spiffe://gibson.io/agent/"),
		strings.HasPrefix(spiffeID, "spiffe://gibson.io/plugin/"):
		id.Roles = []string{"component"}
	default:
		return nil, ErrUnknownSPIFFEID(spiffeID)
	}

	return id, nil
}

// ErrUnknownSPIFFEID returns an authentication error for SPIFFE IDs that do
// not match any known Gibson workload. This rejects workloads that present
// a valid certificate from the gibson.io trust domain but have no registered
// identity in the daemon's SPIFFE ID mapping.
func ErrUnknownSPIFFEID(spiffeID string) error {
	return ErrInvalidToken(fmt.Errorf("unknown SPIFFE ID: %s", spiffeID))
}
