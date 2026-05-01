package registry_test

// spiffe_required_test.go asserts that the generated authz registry has
// exactly two unauthenticated: true entries — Connect and Ping — and that
// GetMyPermissions and ListMyMemberships are NOT in that set.
//
// This is a regression guard: if a future proto change accidentally marks
// another RPC as unauthenticated, or if the registry regeneration is skipped
// after a proto annotation change, this test fails loudly before a release.
//
// Spec: zero-trust-hardening Requirement 5.3 (Connect and Ping are the ONLY
// unauthenticated: true entries; GetMyPermissions and ListMyMemberships must
// require authenticated USER tokens).

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/zero-day-ai/gibson/internal/authz/registry"
)

// allowedUnauthenticated is the exact set of methods that are permitted to
// have Unauthenticated: true in the generated registry.
// DO NOT expand this set without a corresponding spec change.
var allowedUnauthenticated = map[string]bool{
	"/gibson.daemon.v1.DaemonService/Connect": true,
	"/gibson.daemon.v1.DaemonService/Ping":    true,
}

// TestOnlyConnectAndPingAreUnauthenticated walks the generated Registry map
// and asserts that every entry with Unauthenticated: true is in
// allowedUnauthenticated, and every entry in allowedUnauthenticated has
// Unauthenticated: true in the registry.
//
// This test reads the live registry.Registry var (generated code), so a
// `make authz-registry` regen immediately surfaces any proto annotation change.
func TestOnlyConnectAndPingAreUnauthenticated(t *testing.T) {
	// Collect methods marked unauthenticated in the generated registry.
	var foundUnauthenticated []string
	for method, entry := range registry.Registry {
		if entry.Unauthenticated {
			foundUnauthenticated = append(foundUnauthenticated, method)
		}
	}
	sort.Strings(foundUnauthenticated)

	// Assert no unexpected unauthenticated entries.
	var unexpected []string
	for _, method := range foundUnauthenticated {
		if !allowedUnauthenticated[method] {
			unexpected = append(unexpected, method)
		}
	}
	if len(unexpected) > 0 {
		t.Errorf(
			"REGRESSION (zero-trust-hardening Req 5.3): "+
				"the following methods are marked unauthenticated: true in the "+
				"generated registry but are NOT in the allowed set %v:\n  - %s\n\n"+
				"If this is intentional, update allowedUnauthenticated in this file "+
				"AND ensure the spec (zero-trust-hardening) approves the change.",
			sortedKeys(allowedUnauthenticated),
			strings.Join(unexpected, "\n  - "),
		)
	}

	// Assert all expected entries are actually present and unauthenticated.
	for method := range allowedUnauthenticated {
		entry, ok := registry.Registry[method]
		if !ok {
			t.Errorf("expected method %q to exist in registry but it is missing", method)
			continue
		}
		if !entry.Unauthenticated {
			t.Errorf(
				"expected method %q to have Unauthenticated: true (it is a required "+
					"pre-auth liveness check per zero-trust-hardening Req 5.3), "+
					"but the registry marks it as requiring authentication",
				method,
			)
		}
	}
}

// TestGetMyPermissionsAndListMyMembershipsAreAuthenticated explicitly asserts
// the two RPCs that were previously misconfigured as unauthenticated (per the
// zero-trust-hardening audit finding for Req 5 / 6 confused-deputy).
// They must have a relation, object_type, object_deriver, and allowed_identities
// that include the USER bit, and must NOT have Unauthenticated: true.
func TestGetMyPermissionsAndListMyMembershipsAreAuthenticated(t *testing.T) {
	targets := []string{
		"/gibson.daemon.v1.DaemonService/GetMyPermissions",
		"/gibson.daemon.v1.DaemonService/ListMyMemberships",
	}
	for _, method := range targets {
		t.Run(fmt.Sprintf("%s", method[strings.LastIndex(method, "/")+1:]), func(t *testing.T) {
			entry, ok := registry.Registry[method]
			if !ok {
				t.Fatalf("method %q is missing from the registry; re-run `make authz-registry`", method)
			}
			if entry.Unauthenticated {
				t.Errorf(
					"REGRESSION (zero-trust-hardening Req 5.1 / 5.2): "+
						"method %q must NOT have Unauthenticated: true — "+
						"it was previously a confused-deputy that allowed any caller to "+
						"enumerate permissions for an arbitrary subject. "+
						"Re-run `make authz-registry` after confirming the SDK proto "+
						"annotation for this RPC does NOT set unauthenticated: true.",
					method,
				)
			}
			if entry.Relation == "" {
				t.Errorf("method %q has empty Relation; expected 'tenant_member'", method)
			}
			if entry.ObjectType == "" {
				t.Errorf("method %q has empty ObjectType; expected 'tenant'", method)
			}
			// Must allow at least the USER identity class.
			if !entry.AllowedIdentities.Has(registry.IdentityUser) {
				t.Errorf(
					"method %q AllowedIdentities (%d) does not include USER bit (%d); "+
						"dashboard user sessions call these RPCs",
					method, entry.AllowedIdentities, registry.IdentityUser,
				)
			}
		})
	}
}

// sortedKeys returns the keys of a map[string]bool in sorted order.
func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
