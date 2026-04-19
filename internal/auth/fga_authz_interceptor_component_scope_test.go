package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCatalogRelationToComponentGrant covers the mapping from owner-side
// catalog relations (can_read / can_configure / can_execute) to their
// component-scope grant counterparts that the FGA interceptor's R2 two-check
// path consults.
func TestCatalogRelationToComponentGrant(t *testing.T) {
	cases := []struct {
		owner         string
		wantGrant     string
		wantIsCatalog bool
	}{
		{"can_read", "component_read_enabled", true},
		{"can_configure", "component_write_enabled", true},
		{"can_execute", "component_execute_enabled", true},
		// Non-catalog relations — the second check is skipped entirely.
		{"member", "", false},
		{"admin", "", false},
		{"platform_operator", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := catalogRelationToComponentGrant(tc.owner)
		assert.Equalf(t, tc.wantGrant, got, "mapping for %q", tc.owner)
		assert.Equalf(t, tc.wantIsCatalog, ok, "isCatalog for %q", tc.owner)
	}
}

// TestAgentAuthIssuerConstant guards against an accidental rename of the
// agent-auth issuer constant. The FGA interceptor branches on Identity.Issuer
// == this value and the value is also emitted by agentClaimsToIdentity, so
// the two must stay in lockstep. A future rename breaks the R2 two-check
// silently (the interceptor would skip the component check for every agent),
// so this test catches it loudly.
func TestAgentAuthIssuerConstant(t *testing.T) {
	assert.Equal(t, "agent-auth", agentAuthIssuer)
}
