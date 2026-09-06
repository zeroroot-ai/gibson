// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package admin

import (
	"strings"
	"testing"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestComponentObjectRef is the regression for the object-typing half of
// GHSA-75f4-34q5-82px.
//
// The old normaliser was `if !strings.Contains(ref, ":") { ref = "component:" +
// ref }`, so a reference that already carried a type went through untouched.
// The caller supplies that string, which meant the caller — not the RPC —
// decided which FGA object type the tuples landed on.
func TestComponentObjectRef(t *testing.T) {
	t.Run("kind-qualified and canonical refs canonicalize", func(t *testing.T) {
		cases := map[string]string{
			"tool:nmap":                "component:tool/nmap", // kind-qualified
			"agent:zerocool-http8":     "component:agent/zerocool-http8",
			"component:agent/zerocool": "component:agent/zerocool", // already canonical
			"component:tool:nmap":      "component:tool/nmap",      // legacy colon object
		}
		for in, want := range cases {
			got, err := componentObjectRef(in)
			if err != nil {
				t.Errorf("componentObjectRef(%q): %v", in, err)
				continue
			}
			if got != want {
				t.Errorf("componentObjectRef(%q) = %q, want %q", in, got, want)
			}
		}
	})

	t.Run("bare, kind-less refs are refused", func(t *testing.T) {
		// The kind is part of the object identity (ADR-0015); a kind-less
		// reference is never silently assigned one.
		for _, in := range []string{"nmap", "a-b_c.d", "component:nmap"} {
			got, err := componentObjectRef(in)
			if err == nil {
				t.Errorf("componentObjectRef(%q) = %q; a kind-less reference must be refused", in, got)
				continue
			}
			if code := status.Code(err); code != codes.InvalidArgument {
				t.Errorf("componentObjectRef(%q): code = %s, want InvalidArgument", in, code)
			}
		}
	})

	t.Run("any other object type is refused", func(t *testing.T) {
		for _, in := range []string{
			"tenant:victim-co",
			"secret:tenant-victim-co/openai",
			"team:victim-ops",
			"system_tenant:_system",
			"user:someone",
			// A leading colon leaves an empty type, which is still not
			// "component".
			":nmap",
		} {
			got, err := componentObjectRef(in)
			if err == nil {
				t.Errorf("componentObjectRef(%q) = %q with no error; only component objects are this RPC's business", in, got)
				continue
			}
			if code := status.Code(err); code != codes.InvalidArgument {
				t.Errorf("componentObjectRef(%q): code = %s, want InvalidArgument", in, code)
			}
		}
	})

	t.Run("empty is refused", func(t *testing.T) {
		for _, in := range []string{"", "component:"} {
			if _, err := componentObjectRef(in); err == nil {
				t.Errorf("componentObjectRef(%q) accepted an empty component name", in)
			}
		}
	})
}

// TestSetComponentAccess_RefusesANonComponentObject drives the guard through
// the RPC. A refused reference must not reach FGA at all: the reconcile's very
// first act on the object is a listing, and its last is a Write.
func TestSetComponentAccess_RefusesANonComponentObject(t *testing.T) {
	fga := &fakeAuthorizerCatalog{}
	srv := &TenantAdminServer{authorizer: fga}

	_, err := srv.SetComponentAccess(catalogCtx(), &tenantv1.SetComponentAccessRequest{
		Component: "tenant:victim-co",
		Entries: []*tenantv1.ComponentAccessEntry{
			{Relation: "team_write_disabled", TeamId: "red-team"},
		},
	})
	if err == nil {
		t.Fatal("SetComponentAccess accepted a tenant object as its component")
	}
	if code := status.Code(err); code != codes.InvalidArgument {
		t.Errorf("code = %s, want InvalidArgument", code)
	}
	if !strings.Contains(err.Error(), "tenant") {
		t.Errorf("error = %v, want it to name the type it refused", err)
	}
	if len(fga.tuples) != 0 {
		t.Errorf("wrote %+v; a refused object reference must not reach FGA", fga.tuples)
	}
}

// TestSetCatalogEnabled_RefusesANonComponentObject covers the sibling RPC.
// SetCatalogEnabled writes (tenant:<caller>, tenant_enabled, <object>), so an
// untyped reference let a caller attach their own tenant to an arbitrary
// object — the same normaliser, the same hole.
func TestSetCatalogEnabled_RefusesANonComponentObject(t *testing.T) {
	fga := &fakeAuthorizerCatalog{}
	srv := &TenantAdminServer{authorizer: fga}

	_, err := srv.SetCatalogEnabled(catalogCtx(), &tenantv1.SetCatalogEnabledRequest{
		ComponentRef: "secret:tenant-victim-co/openai",
		Enabled:      true,
	})
	if err == nil {
		t.Fatal("SetCatalogEnabled accepted a secret object as its component")
	}
	if code := status.Code(err); code != codes.InvalidArgument {
		t.Errorf("code = %s, want InvalidArgument", code)
	}
	if len(fga.tuples) != 0 {
		t.Errorf("wrote %+v; a refused object reference must not reach FGA", fga.tuples)
	}
}
