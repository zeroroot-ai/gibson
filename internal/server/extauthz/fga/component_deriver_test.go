// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fga

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/headers"
)

// TestResolveObject_ComponentFromIdentity pins the component_from_identity
// deriver: the object is the component the caller IS, taken from the
// signature-verified component_scope claim carried on headers.Identity, and
// nothing else resolves it.
//
// The deriver is inert until a registry row names it (see
// TestComponentFromIdentityIsNotYetUsedByAnyRow), so these cases document the
// contract the SDK annotations will bind to.
func TestResolveObject_ComponentFromIdentity(t *testing.T) {
	t.Parallel()

	const method = "/gibson.daemon.discovery.v1.DiscoveryService/ListFindings"
	entry := Entry{
		Method:        method,
		ObjectType:    "component",
		ObjectDeriver: "component_from_identity",
	}

	cases := []struct {
		name    string
		scope   string
		want    string
		wantErr bool
	}{
		{
			name:  "canonical component:<name> scope resolves to that component",
			scope: "component:hello-world",
			want:  "component:hello-world",
		},
		{
			// The daemon mints "component:<name>"; a bare name is accepted
			// and re-prefixed rather than being turned into "component:".
			name:  "bare name is re-prefixed with the row's object type",
			scope: "hello-world",
			want:  "component:hello-world",
		},
		{
			name:  "dots, underscores, dashes and the tenant separator survive",
			scope: "component:acme/tool_v1.2-beta",
			want:  "component:acme/tool_v1.2-beta",
		},
		{
			// Absent claim: no object, therefore no question to ask FGA.
			// Must NOT fall back to component:_system or to the tenant.
			name:    "absent scope fails closed",
			scope:   "",
			wantErr: true,
		},
		{
			// A second colon would name a different object type, and
			// OpenFGA rejects the three-part form outright.
			name:    "extra colon fails closed",
			scope:   "component:evil:system_tenant",
			wantErr: true,
		},
		{
			name:    "the bare sentinel spelling is not privileged",
			scope:   "component:_system:x",
			wantErr: true,
		},
		{
			// '#' would make the reference a userset ("type:id#relation").
			name:    "userset separator fails closed",
			scope:   "component:evil#member",
			wantErr: true,
		},
		{
			name:    "whitespace fails closed",
			scope:   "component:evil name",
			wantErr: true,
		},
		{
			name:    "newline fails closed",
			scope:   "component:evil\nmember",
			wantErr: true,
		},
		{
			name:    "control character fails closed",
			scope:   "component:evil\x00name",
			wantErr: true,
		},
		{
			name:    "non-ASCII fails closed",
			scope:   "component:eviⅼ", // roman numeral, not "l"
			wantErr: true,
		},
		{
			name:    "prefix with an empty name fails closed",
			scope:   "component:",
			wantErr: true,
		},
		{
			name:    "an over-long id fails closed",
			scope:   "component:" + strings.Repeat("a", maxObjectIDLen+1),
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			id := headers.Identity{
				Subject:        "agent_principal:9",
				Tenant:         "acme",
				CredentialType: headers.CredentialCapabilityGrant,
				ComponentScope: tc.scope,
			}
			got, err := resolveObject(entry, id, map[string]string{"tenant": "acme"})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("resolveObject(scope=%q) = %q, want a deny", tc.scope, got)
				}
				if !errors.Is(err, ErrObjectUnresolvable) {
					t.Fatalf("err = %v, want ErrObjectUnresolvable (a policy deny, not an infra error)", err)
				}
				// Fail closed means fail closed: never the global sentinel,
				// never the tenant-wide object.
				if strings.Contains(err.Error(), "_system") {
					t.Fatalf("deny error mentions the _system sentinel: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveObject(scope=%q) unexpected error: %v", tc.scope, err)
			}
			if got != tc.want {
				t.Fatalf("resolveObject(scope=%q) = %q, want %q", tc.scope, got, tc.want)
			}
		})
	}
}

// TestResolveObject_ComponentScopeNotTakenFromRequestMetadata is the deriver
// half of the "a component cannot assert its own object" property: request
// metadata is the only channel a caller controls that reaches resolveObject,
// and the deriver must ignore it entirely. (The header half — that no request
// header ever populates Identity.ComponentScope — is pinned in the server
// package.)
func TestResolveObject_ComponentScopeNotTakenFromRequestMetadata(t *testing.T) {
	t.Parallel()

	entry := Entry{
		Method:        "/gibson.daemon.discovery.v1.DiscoveryService/ListFindings",
		ObjectType:    "component",
		ObjectDeriver: "component_from_identity",
	}
	// Identity carries no verified scope; the request tries to supply one
	// under every plausible key.
	id := headers.Identity{Subject: "agent_principal:9", Tenant: "acme"}
	meta := map[string]string{
		"tenant":          "acme",
		"component_scope": "component:victim",
		"componentScope":  "component:victim",
		"component":       "victim",
		"Name":            "victim",
	}

	got, err := resolveObject(entry, id, meta)
	if err == nil {
		t.Fatalf("resolveObject derived %q from request metadata; the scope must come "+
			"only from the verified claim", got)
	}
	if !errors.Is(err, ErrObjectUnresolvable) {
		t.Fatalf("err = %v, want ErrObjectUnresolvable", err)
	}
}

// TestCachedChecker_UnresolvableObjectIsADenyNotAnOutage pins the
// classification of an unresolvable object on the CACHED path, which is the
// path ext-authz actually uses.
//
// Checker.Check has always turned ErrObjectUnresolvable into (false, nil) — a
// policy deny. CachedChecker.Check resolves the object first, to build its
// cache key, and used to return the error verbatim; the server then reported
// FGA-unavailable and answered 503 instead of 403. Fail-closed either way, but
// the wrong signal: it counted as an outage, skipped the deny log and the
// object-unresolvable counter, and invited a retry that can never succeed.
// component_from_identity's fail-closed path runs through here.
func TestCachedChecker_UnresolvableObjectIsADenyNotAnOutage(t *testing.T) {
	t.Parallel()

	const method = "/gibson.daemon.discovery.v1.DiscoveryService/ListFindings"
	reg, err := LoadRegistry([]byte(`entries:
  "` + method + `":
    relation: "can_read_as_component"
    object_type: "component"
    object_deriver: "component_from_identity"
    allowed_identities:
      - COMPONENT
`))
	if err != nil {
		t.Fatal(err)
	}
	stub := &mockFGA{allowed: true} // would ALLOW if it were ever consulted
	cc := NewCachedChecker(NewChecker(stub, reg), time.Minute, 100)

	// A component identity with no verified component_scope.
	id := headers.Identity{
		Subject:        "agent_principal:9",
		Issuer:         headers.IssuerCapabilityGrant,
		CredentialType: headers.CredentialCapabilityGrant,
		Tenant:         "acme",
	}
	allowed, err := cc.Check(context.Background(), method, id, map[string]string{"tenant": "acme"})
	if err != nil {
		t.Fatalf("Check returned an infrastructure error for an unresolvable object: %v", err)
	}
	if allowed {
		t.Fatal("Check allowed a request whose object could not be derived")
	}
	if n := atomic.LoadInt32(&stub.calls); n != 0 {
		t.Fatalf("FGA consulted %d time(s); an unresolvable object must deny before any "+
			"question is asked", n)
	}
}

// TestLoadRegistry_AcceptsComponentFromIdentity checks that the registry
// loader accepts the new deriver spelling, so the SDK release that starts
// emitting it does not have to be sequenced against a loader change too.
//
// No row in the live registry names this deriver yet — that is deliberate,
// and it is why teaching gibson the deriver is safe to ship on its own:
// gibson must recognise it BEFORE the SDK emits it, or every row bound to it
// would fail closed on rollout.
func TestLoadRegistry_AcceptsComponentFromIdentity(t *testing.T) {
	t.Parallel()

	const y = `entries:
  "/gibson.daemon.discovery.v1.DiscoveryService/ListFindings":
    relation: "can_read_as_component"
    object_type: "component"
    object_deriver: "component_from_identity"
    allowed_identities:
      - COMPONENT
`
	reg, err := LoadRegistry([]byte(y))
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	got, ok := reg.Lookup("/gibson.daemon.discovery.v1.DiscoveryService/ListFindings")
	if !ok {
		t.Fatal("entry not found after load")
	}
	if got.ObjectDeriver != "component_from_identity" {
		t.Fatalf("ObjectDeriver = %q, want component_from_identity", got.ObjectDeriver)
	}
}
