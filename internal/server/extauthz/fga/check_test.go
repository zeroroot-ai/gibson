package fga

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/headers"
)

// testRegistry builds a Registry with four entries for AllowedIdentities tests.
// The YAML mirrors the shape that registry_test.go uses; entries are added for
// USER-only, COMPONENT-only, SERVICE+COMPONENT, and a zero-bitfield path.
const allowedIdentitiesYAML = `entries:
  "/test.v1.S/Public":
    unauthenticated: true
  "/test.v1.S/UserOnly":
    relation: "member"
    object_type: "tenant"
    object_deriver: "tenant_from_identity"
    allowed_identities:
      - USER
  "/test.v1.S/ServiceAndComponent":
    relation: "member"
    object_type: "tenant"
    object_deriver: "tenant_from_identity"
    allowed_identities:
      - SERVICE
      - COMPONENT
  "/test.v1.S/ComponentOnly":
    relation: "member"
    object_type: "tenant"
    object_deriver: "tenant_from_identity"
    allowed_identities:
      - COMPONENT
`

func makeAllowedIdentitiesReg(t *testing.T) *Registry {
	t.Helper()
	r, err := LoadRegistry([]byte(allowedIdentitiesYAML))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestCheck_UserVsUserOnlyRPC — USER caller on USER-only RPC is allowed.
func TestCheck_UserVsUserOnlyRPC(t *testing.T) {
	t.Parallel()
	stub := &mockFGA{allowed: true}
	checker := NewChecker(stub, makeAllowedIdentitiesReg(t))
	id := headers.Identity{Subject: "u-1", Tenant: "acme", CredentialType: "oidc-user"}
	ok, err := checker.Check(context.Background(), "/test.v1.S/UserOnly", id, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected allow for USER on USER-only RPC, got deny")
	}
}

// TestCheck_ServiceVsUserOnlyRPC — SERVICE caller on USER-only RPC is denied
// before FGA is consulted.
func TestCheck_ServiceVsUserOnlyRPC(t *testing.T) {
	t.Parallel()
	stub := &mockFGA{allowed: true} // FGA would allow, but should not be reached
	checker := NewChecker(stub, makeAllowedIdentitiesReg(t))
	id := headers.Identity{Subject: "sa-1", Tenant: "acme", CredentialType: "client-credentials"}
	ok, err := checker.Check(context.Background(), "/test.v1.S/UserOnly", id, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected deny for SERVICE on USER-only RPC, got allow")
	}
	// FGA must NOT have been called.
	if stub.calls != 0 {
		t.Fatalf("FGA was called %d times; expected 0 (identity-class check should short-circuit)", stub.calls)
	}
}

// TestCheck_ComponentVsServiceComponentRPC — COMPONENT caller on
// SERVICE+COMPONENT RPC is allowed.
func TestCheck_ComponentVsServiceComponentRPC(t *testing.T) {
	t.Parallel()
	stub := &mockFGA{allowed: true}
	checker := NewChecker(stub, makeAllowedIdentitiesReg(t))
	id := headers.Identity{Subject: "agent_principal:comp-1", Tenant: "acme", CredentialType: headers.CredentialCapabilityGrant}
	ok, err := checker.Check(context.Background(), "/test.v1.S/ServiceAndComponent", id, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected allow for COMPONENT on SERVICE+COMPONENT RPC, got deny")
	}
}

// TestCheck_ZeroBitfieldDenyAll — AllowedIdentities == 0 is treated as
// deny-all (defensive; codegen prevents this in practice but the runtime
// must be hardened per Req 2.3).
func TestCheck_ZeroBitfieldDenyAll(t *testing.T) {
	t.Parallel()
	// Construct a registry with a synthesized entry whose AllowedIdentities
	// is 0. We bypass LoadRegistry (which rejects zero) and inject directly.
	reg := &Registry{
		entries: map[string]Entry{
			"/test.v1.S/ZeroBits": {
				Method:            "/test.v1.S/ZeroBits",
				Service:           "test.v1.S",
				Relation:          "member",
				ObjectType:        "tenant",
				ObjectDeriver:     "tenant_from_identity",
				AllowedIdentities: 0, // zero — deny-all
			},
		},
	}
	stub := &mockFGA{allowed: true}
	checker := NewChecker(stub, reg)
	id := headers.Identity{Subject: "u-1", Tenant: "acme", CredentialType: "oidc-user"}
	ok, err := checker.Check(context.Background(), "/test.v1.S/ZeroBits", id, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected deny for AllowedIdentities==0, got allow")
	}
	if stub.calls != 0 {
		t.Fatalf("FGA was called %d times; expected 0 (zero bitfield must short-circuit)", stub.calls)
	}
}

// TestCheck_UnknownCredentialTypeDeny — an unknown CredentialType maps to
// class NONE (0), which is denied by any bitfield check.
func TestCheck_UnknownCredentialTypeDeny(t *testing.T) {
	t.Parallel()
	stub := &mockFGA{allowed: true}
	checker := NewChecker(stub, makeAllowedIdentitiesReg(t))
	id := headers.Identity{Subject: "x", Tenant: "acme", CredentialType: "unknown-future-type"}
	ok, err := checker.Check(context.Background(), "/test.v1.S/UserOnly", id, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected deny for unknown CredentialType, got allow")
	}
	if stub.calls != 0 {
		t.Fatalf("FGA was called %d times; expected 0", stub.calls)
	}
}

// TestCallerClass covers the credential-type → IdentityClass mapping.
func TestCallerClass(t *testing.T) {
	t.Parallel()
	cases := []struct {
		credType string
		want     IdentityClass
	}{
		{"oidc-user", IdentityUser},
		{"client-credentials", IdentityService},
		{"capability-grant", IdentityComponent},
		{"platform-operator", IdentityPlatformOperator},
		{"", 0},
		{"unknown", 0},
		{"component", 0}, // the stale string no longer maps (ADR-0045 uses capability-grant)
	}
	for _, tc := range cases {
		id := headers.Identity{CredentialType: tc.credType}
		if got := callerClass(id); got != tc.want {
			t.Errorf("callerClass(%q) = %v, want %v", tc.credType, got, tc.want)
		}
	}
}

// TestCachedChecker_AllowedIdentities_ServiceVsUserOnlyRPC ensures the cache
// layer also enforces the bitfield and that FGA is not consulted.
func TestCachedChecker_AllowedIdentities_ServiceVsUserOnlyRPC(t *testing.T) {
	t.Parallel()
	stub := &mockFGA{allowed: true}
	cc := NewCachedChecker(NewChecker(stub, makeAllowedIdentitiesReg(t)), 0, 100)
	id := headers.Identity{Subject: "sa-1", Tenant: "acme", CredentialType: "client-credentials"}
	ok, err := cc.Check(context.Background(), "/test.v1.S/UserOnly", id, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected deny at CachedChecker level, got allow")
	}
	if stub.calls != 0 {
		t.Fatalf("FGA was called %d times; expected 0", stub.calls)
	}
}

// ---- self-mode enforcer tests (spec: self-mode-authz) ----

const selfModeYAML = `entries:
  "/test.v1.S/Public":
    unauthenticated: true
  "/test.v1.S/UserOnly":
    relation: "member"
    object_type: "tenant"
    object_deriver: "tenant_from_identity"
    allowed_identities:
      - USER
  "/test.v1.S/SelfUserOnly":
    self: true
    allowed_identities:
      - USER
`

func makeSelfModeReg(t *testing.T) *Registry {
	t.Helper()
	r, err := LoadRegistry([]byte(selfModeYAML))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestCheck_SelfMode_UserToken_Allow — self:true RPC with USER token is allowed.
// FGA must NOT be called.
func TestCheck_SelfMode_UserToken_Allow(t *testing.T) {
	t.Parallel()
	stub := &mockFGA{allowed: false} // FGA returns deny — must not be reached
	checker := NewChecker(stub, makeSelfModeReg(t))
	id := headers.Identity{Subject: "u-123", Tenant: "acme", CredentialType: "oidc-user"}
	ok, err := checker.Check(context.Background(), "/test.v1.S/SelfUserOnly", id, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected allow for USER token on self-mode RPC, got deny")
	}
	// FGA must NOT have been called — self-mode skips the round-trip.
	if stub.calls != 0 {
		t.Fatalf("FGA was called %d times; self-mode must make ZERO FGA calls", stub.calls)
	}
}

// TestCheck_SelfMode_ServiceToken_Deny — self:true + USER-only RPC with SERVICE token is denied.
// FGA must NOT be called.
func TestCheck_SelfMode_ServiceToken_Deny(t *testing.T) {
	t.Parallel()
	stub := &mockFGA{allowed: true} // FGA would allow — must not be reached
	checker := NewChecker(stub, makeSelfModeReg(t))
	id := headers.Identity{Subject: "sa-42", Tenant: "acme", CredentialType: "client-credentials"}
	ok, err := checker.Check(context.Background(), "/test.v1.S/SelfUserOnly", id, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected deny for SERVICE token on USER-only self-mode RPC, got allow")
	}
	if stub.calls != 0 {
		t.Fatalf("FGA was called %d times; self-mode must make ZERO FGA calls", stub.calls)
	}
}

// TestCheck_SelfMode_EmptySubject_Deny — self:true RPC with empty subject is denied.
func TestCheck_SelfMode_EmptySubject_Deny(t *testing.T) {
	t.Parallel()
	stub := &mockFGA{allowed: true}
	checker := NewChecker(stub, makeSelfModeReg(t))
	id := headers.Identity{Subject: "", Tenant: "acme", CredentialType: "oidc-user"}
	ok, err := checker.Check(context.Background(), "/test.v1.S/SelfUserOnly", id, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected deny for empty subject on self-mode RPC, got allow")
	}
	if stub.calls != 0 {
		t.Fatalf("FGA was called %d times; self-mode must make ZERO FGA calls", stub.calls)
	}
}

// TestCheck_SelfMode_ZeroFGACalls — asserts that a mock FGA client receives
// absolutely zero calls during a self-mode request (proves the round-trip skip).
func TestCheck_SelfMode_ZeroFGACalls(t *testing.T) {
	t.Parallel()
	stub := &mockFGA{allowed: true}
	checker := NewChecker(stub, makeSelfModeReg(t))
	id := headers.Identity{Subject: "u-999", Tenant: "acme", CredentialType: "oidc-user"}

	for i := 0; i < 5; i++ {
		ok, err := checker.Check(context.Background(), "/test.v1.S/SelfUserOnly", id, nil)
		if err != nil || !ok {
			t.Fatalf("iteration %d: unexpected result ok=%v err=%v", i, ok, err)
		}
	}
	if got := atomic.LoadInt32(&stub.calls); got != 0 {
		t.Fatalf("FGA Check was called %d times across 5 self-mode requests; expected 0", got)
	}
}

// TestCheck_LegacyUnauthenticated_Unchanged — legacy unauthenticated entry still passes.
func TestCheck_LegacyUnauthenticated_Unchanged(t *testing.T) {
	t.Parallel()
	stub := &mockFGA{allowed: false}
	checker := NewChecker(stub, makeSelfModeReg(t))
	id := headers.Identity{Subject: "", Tenant: "", CredentialType: ""}
	ok, err := checker.Check(context.Background(), "/test.v1.S/Public", id, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected allow for unauthenticated RPC, got deny")
	}
	if stub.calls != 0 {
		t.Fatalf("FGA was called %d times; unauthenticated entry must skip FGA", stub.calls)
	}
}

// TestCheck_LegacyRuleMode_Unchanged — legacy rule-mode entry still routes to FGA.
func TestCheck_LegacyRuleMode_Unchanged(t *testing.T) {
	t.Parallel()
	stub := &mockFGA{allowed: true}
	checker := NewChecker(stub, makeSelfModeReg(t))
	id := headers.Identity{Subject: "u-1", Tenant: "acme", CredentialType: "oidc-user"}
	ok, err := checker.Check(context.Background(), "/test.v1.S/UserOnly", id, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected allow for rule-mode RPC with FGA allow, got deny")
	}
	if stub.calls == 0 {
		t.Fatal("expected at least one FGA call for rule-mode entry, got 0")
	}
}

// TestCachedChecker_SelfMode_ZeroFGACalls — CachedChecker also skips FGA + cache
// for self-mode entries.
func TestCachedChecker_SelfMode_ZeroFGACalls(t *testing.T) {
	t.Parallel()
	stub := &mockFGA{allowed: true}
	cc := NewCachedChecker(NewChecker(stub, makeSelfModeReg(t)), 0, 100)
	id := headers.Identity{Subject: "u-cc", Tenant: "acme", CredentialType: "oidc-user"}
	for i := 0; i < 3; i++ {
		ok, err := cc.Check(context.Background(), "/test.v1.S/SelfUserOnly", id, nil)
		if err != nil || !ok {
			t.Fatalf("iteration %d: unexpected result ok=%v err=%v", i, ok, err)
		}
	}
	if got := atomic.LoadInt32(&stub.calls); got != 0 {
		t.Fatalf("CachedChecker: FGA called %d times for self-mode; expected 0", got)
	}
}

// TestResolveObject covers every object_deriver branch, with emphasis on the
// colon-free tenant_and_field join (gibson#1024): tenant and field must be
// joined with "/", never ":", because OpenFGA rejects a colon inside an
// object id ("invalid 'object' field format") on both Write and Check.
func TestResolveObject(t *testing.T) {
	t.Parallel()
	id := headers.Identity{Subject: "u-1", Tenant: "acme"}
	cases := []struct {
		name    string
		entry   Entry
		meta    map[string]string
		want    string
		wantErr bool
	}{
		{
			name:  "tenant_from_identity uses identity tenant",
			entry: Entry{ObjectType: "tenant", ObjectDeriver: "tenant_from_identity"},
			want:  "tenant:acme",
		},
		{
			name:  "tenant_from_identity de-prefixes double-prefixed tenant",
			entry: Entry{ObjectType: "tenant", ObjectDeriver: "tenant_from_identity"},
			meta:  map[string]string{"tenant": "tenant:acme"},
			want:  "tenant:acme",
		},
		{
			name:  "system_tenant is the _system literal",
			entry: Entry{ObjectType: "system_tenant", ObjectDeriver: "system_tenant"},
			want:  "system_tenant:_system",
		},
		{
			name:  "from_field uses bare field value",
			entry: Entry{ObjectType: "plugin", ObjectDeriver: "from_field('plugin_id')"},
			meta:  map[string]string{"plugin_id": "p-7"},
			want:  "plugin:p-7",
		},
		{
			name:  "tenant_and_field joins tenant and field with slash not colon",
			entry: Entry{ObjectType: "plugin", ObjectDeriver: "tenant_and_field('plugin_id')"},
			meta:  map[string]string{"plugin_id": "p-7"},
			want:  "plugin:acme/p-7",
		},
		{
			name:  "tenant_and_field degrades to tenant-only when field absent",
			entry: Entry{ObjectType: "plugin", ObjectDeriver: "tenant_and_field('plugin_id')"},
			meta:  map[string]string{},
			want:  "plugin:acme",
		},
		{
			// gibson#1035: secret objects use "secret:tenant-<slug>/<ref>" — the
			// "tenant-" prefix is a fixed part of the id (matches the daemon writers
			// and the FGA model), and the ref may itself contain colons (e.g.
			// "cred:openai-prod"). The deriver must use SecretObjectFromDeriver
			// rather than the bare tenant_and_field format.
			name:  "tenant_and_field for secret adds tenant- prefix and slash separator",
			entry: Entry{ObjectType: "secret", ObjectDeriver: "tenant_and_field('secret_ref')"},
			meta:  map[string]string{"secret_ref": "cred:openai-prod"},
			want:  "secret:tenant-acme/cred:openai-prod",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveObject(tc.entry, id, tc.meta)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("resolveObject(%q) want error, got %q", tc.entry.ObjectDeriver, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveObject(%q) unexpected error: %v", tc.entry.ObjectDeriver, err)
			}
			if got != tc.want {
				t.Fatalf("resolveObject(%q) = %q, want %q", tc.entry.ObjectDeriver, got, tc.want)
			}
			// The tenant-separator must be "/" not ":". OpenFGA v1.8.4 rejects a
			// THIRD colon at the structural type-id boundary (e.g. "type:tenant:name"
			// is invalid). Exact string equality against tc.want already pins the
			// separator, so the invariant is enforced above; this comment preserves
			// the intent from the original gibson#1024 guard (the colon-count check
			// was removed because secret refs like "cred:openai-prod" legitimately
			// contain a colon in the body of the id).
		})
	}

	// With neither metadata nor identity tenant, tenant-scoped derivers must
	// fail closed rather than emit a malformed object id.
	t.Run("empty tenant fails closed", func(t *testing.T) {
		t.Parallel()
		_, err := resolveObject(
			Entry{ObjectType: "tenant", ObjectDeriver: "tenant_from_identity", Method: "/x.S/M"},
			headers.Identity{Subject: "u-1"}, // no Tenant
			map[string]string{},
		)
		if err == nil {
			t.Fatal("resolveObject with empty tenant: want error, got nil")
		}
	})
}
