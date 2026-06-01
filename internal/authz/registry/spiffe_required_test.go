package registry_test

// spiffe_required_test.go asserts the following invariants on the generated
// authz registry:
//
//  1. Connect and Ping are the ONLY unauthenticated: true entries (the set
//     must NOT grow — Req 4.5).
//  2. GetMyPermissions and ListMyMemberships carry the self-mode shape:
//     Self == true, AllowedIdentities includes USER, Unauthenticated == false,
//     Relation == "" (no FGA rule fields).
//  3. Every Self == true entry in the registry has the USER bit in
//     AllowedIdentities (USER-only by design for self-bootstrap RPCs).
//
// Spec: zero-trust-hardening Req 5.3 (Connect and Ping only unauthenticated);
//
//	self-mode-authz Req 4.4, 4.5 (self-mode shape + unauth set does not grow).
import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/authz/registry"
)

// allowedUnauthenticated is the exact set of methods that are permitted to
// have Unauthenticated: true in the generated registry.
// DO NOT expand this set without a corresponding spec change.
var allowedUnauthenticated = map[string]bool{
	"/gibson.daemon.v1.DaemonService/Connect": true,
	"/gibson.daemon.v1.DaemonService/Ping":    true,

	// GetReservedNames is intentionally unauthenticated on MembershipService.
	// It returns the chart-managed denylist for the signup form — a pre-auth
	// surface where no tenant JWT can be present. Spec: issue #395
	// (tenant-service-admin-handlers: GetReservedNames). ADR-0039: moved from
	// gibson.admin.v1.TenantAdminService to gibson.tenant.v1.MembershipService.
	"/gibson.tenant.v1.MembershipService/GetReservedNames": true,

	// GetSignupProgress is intentionally unauthenticated.
	// Polled by the browser during the signup flow (before the user has an account).
	// The attempt_id is an opaque UUID-v4 capability functioning as a single-use token;
	// the response carries only step names + error codes, never PII.
	// Spec: dashboard-no-backing-store-clients (Module 2 — Signup Progress RPC).
	// ADR-0039: promoted from daemon-local gibson.user.v1.UserService to
	// sdk gibson.tenant.v1.UserService; both appear in the registry until the
	// daemon-local proto is cleaned up in a follow-up (the old service is no
	// longer registered on the gRPC server).
	"/gibson.tenant.v1.UserService/GetSignupProgress": true,
	"/gibson.user.v1.UserService/GetSignupProgress":   true, // daemon-local proto retained for registry until cleanup
}

// TestOnlyConnectAndPingAreUnauthenticated walks the generated Registry map
// and asserts that every entry with Unauthenticated: true is in
// allowedUnauthenticated, and every entry in allowedUnauthenticated has
// Unauthenticated: true in the registry.
//
// Spec: zero-trust-hardening Req 5.3; self-mode-authz Req 4.5 (the set must
// NOT grow as a result of this spec).
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
			"REGRESSION (zero-trust-hardening Req 5.3 / self-mode-authz Req 4.5): "+
				"the following methods are marked unauthenticated: true in the "+
				"generated registry but are NOT in the allowed set %v:\n  - %s\n\n"+
				"If this is intentional, update allowedUnauthenticated in this file "+
				"AND ensure the spec (zero-trust-hardening or self-mode-authz) approves the change.",
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

// TestGetMyPermissionsAndListMyMembershipsAreAuthenticated asserts the
// self-mode shape on the two self-bootstrap RPCs. These were previously
// annotated as unauthenticated: true (hotfix); self-mode-authz migrated them
// to self: true + allowed_identities: [USER], which preserves the authenticated
// contract while skipping the FGA tuple lookup.
//
// Asserts:
//   - Self == true (self-mode annotation, no FGA rule)
//   - AllowedIdentities.Has(USER) (dashboard user sessions call these)
//   - Unauthenticated == false (no bypass of Envoy jwt_authn)
//   - Relation == "" (no FGA rule fields set)
//
// Spec: self-mode-authz Req 4.4.
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

			// Must be in self-mode (self-mode-authz Req 4.1).
			if !entry.Self {
				t.Errorf(
					"REGRESSION (self-mode-authz Req 4.4): "+
						"method %q must have Self: true — "+
						"it was migrated from unauthenticated:true to self:true by spec self-mode-authz. "+
						"Re-run `make authz-registry` after confirming the SDK proto annotation "+
						"for this RPC sets self: true.",
					method,
				)
			}

			// Must NOT be marked unauthenticated (self-mode-authz Req 4.2).
			if entry.Unauthenticated {
				t.Errorf(
					"REGRESSION (self-mode-authz Req 4.4): "+
						"method %q must NOT have Unauthenticated: true — "+
						"it was migrated to self:true by spec self-mode-authz; "+
						"the hotfix unauthenticated annotation must not be re-introduced.",
					method,
				)
			}

			// self-mode entries have no FGA rule fields.
			if entry.Relation != "" {
				t.Errorf(
					"REGRESSION (self-mode-authz Req 4.4): "+
						"method %q has non-empty Relation %q; "+
						"self-mode entries must not carry FGA rule fields.",
					method, entry.Relation,
				)
			}

			// Must allow at least the USER identity class.
			if !entry.AllowedIdentities.Has(registry.IdentityUser) {
				t.Errorf(
					"REGRESSION (self-mode-authz Req 4.4): "+
						"method %q AllowedIdentities (%d) does not include USER bit (%d); "+
						"dashboard user sessions call these RPCs and must be permitted. "+
						"Spec: self-mode-authz.",
					method, entry.AllowedIdentities, registry.IdentityUser,
				)
			}
		})
	}
}

// TestSelfModeEntriesAreUserOnly walks registry.Registry and asserts that
// every entry with Self == true has the USER bit set in AllowedIdentities.
// Self-bootstrap RPCs are user-session-only by design; SERVICE and COMPONENT
// tokens must never call them.
//
// Spec: self-mode-authz Req 4.4, 4.5.
func TestSelfModeEntriesAreUserOnly(t *testing.T) {
	for method, entry := range registry.Registry {
		if !entry.Self {
			continue
		}
		if !entry.AllowedIdentities.Has(registry.IdentityUser) {
			t.Errorf(
				"REGRESSION (self-mode-authz Req 4.4): "+
					"self-mode entry %q does not have the USER bit in AllowedIdentities (%d); "+
					"self-bootstrap RPCs are user-session-only. "+
					"Spec: self-mode-authz.",
				method, entry.AllowedIdentities,
			)
		}
	}
	// Sanity check: there must be at least one Self == true entry or this
	// test is vacuously passing on a stale registry.
	var selfCount int
	for _, entry := range registry.Registry {
		if entry.Self {
			selfCount++
		}
	}
	if selfCount == 0 {
		t.Error(
			"registry contains zero Self == true entries; " +
				"expected at least GetMyPermissions and ListMyMemberships. " +
				"Re-run `make authz-registry` — the registry may be stale. " +
				"Spec: self-mode-authz.",
		)
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
