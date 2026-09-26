// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package tenantrole_test

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
)

// TestAll_HasExactlyTheFourTenantRolesInOrder pins the declared set the
// platform-operator's EnsureProjectRoles creates on the gibson project.
// The FGA-relation mapping and the Zitadel-key/FGA-relation helpers land
// with the rest of the tenantrole package in a later change.
func TestAll_HasExactlyTheFourTenantRolesInOrder(t *testing.T) {
	want := []tenantrole.Def{
		{tenantrole.Owner, "Owner"},
		{tenantrole.Admin, "Admin"},
		{tenantrole.Editor, "Editor"},
		{tenantrole.Viewer, "Viewer"},
	}
	if len(tenantrole.All) != len(want) {
		t.Fatalf("All = %+v, want %+v", tenantrole.All, want)
	}
	for i, d := range want {
		if tenantrole.All[i] != d {
			t.Errorf("All[%d] = %+v, want %+v", i, tenantrole.All[i], d)
		}
	}
}

// TestIsZitadelUserSubject pins the fail-closed filter (owner decision D2,
// option b) that keeps Sync from ever reading, writing or deleting a role
// tuple for a `user:`-typed subject that is not a Zitadel grant — most
// notably the exit-test runner's SPIFFE-derived identity, which is a real
// stored tenant.member tuple but has no Zitadel user behind it.
func TestIsZitadelUserSubject(t *testing.T) {
	cases := []struct {
		subject string
		want    bool
	}{
		{"user:218901902167211265", true},
		{"user:1", true},
		{"user:zeroroot.ai/platform/e2e-runner", false}, // the e2e runner, gibson#14 fixtures: a SPIFFE id, has "/"
		{"user:", false},
		{"user:bob-id", true}, // human-readable test fixture id, not numeric, but not SPIFFE-shaped either
		{"user:user-1", true}, // ditto
		{"agent_principal:abc-123", false},
		{"tenant:acme", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := tenantrole.IsZitadelUserSubject(tc.subject); got != tc.want {
			t.Errorf("IsZitadelUserSubject(%q) = %v, want %v", tc.subject, got, tc.want)
		}
	}
}
