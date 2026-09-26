// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package tenantrole_test

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
)

// TestAll_HasExactlyTheFourTenantRolesInOrder pins the declared set the
// platform-operator's EnsureProjectRoles creates on the gibson project.
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

// TestKeys_ReturnsTheFourRoleKeysInOrder pins the plain-string form a
// Zitadel project-grant call wants.
func TestKeys_ReturnsTheFourRoleKeysInOrder(t *testing.T) {
	want := []string{"owner", "admin", "editor", "viewer"}
	got := tenantrole.Keys()
	if len(got) != len(want) {
		t.Fatalf("Keys() = %v, want %v", got, want)
	}
	for i, k := range want {
		if got[i] != k {
			t.Errorf("Keys()[%d] = %q, want %q", i, got[i], k)
		}
	}
}

// TestRole_Relation pins the FGA relation each role maps to, including the
// two that predate ADR-0093's role names (Editor/writer, Viewer/member).
func TestRole_Relation(t *testing.T) {
	cases := []struct {
		role tenantrole.Role
		want string
	}{
		{tenantrole.Owner, "owner"},
		{tenantrole.Admin, "admin"},
		{tenantrole.Editor, "writer"},
		{tenantrole.Viewer, "member"},
		{tenantrole.Role("bogus"), ""},
	}
	for _, tc := range cases {
		if got := tc.role.Relation(); got != tc.want {
			t.Errorf("Role(%q).Relation() = %q, want %q", tc.role, got, tc.want)
		}
	}
}

// TestParse_RoundTripsEveryDeclaredKeyAndRejectsUnknown pins Parse against
// every key in All, plus the not-ok case for an undeclared key.
func TestParse_RoundTripsEveryDeclaredKeyAndRejectsUnknown(t *testing.T) {
	for _, d := range tenantrole.All {
		got, ok := tenantrole.Parse(string(d.Key))
		if !ok || got != d.Key {
			t.Errorf("Parse(%q) = (%q, %v), want (%q, true)", d.Key, got, ok, d.Key)
		}
	}
	if _, ok := tenantrole.Parse("superuser"); ok {
		t.Error("Parse(\"superuser\") ok = true, want false")
	}
}

// TestFromRelation_RoundTripsEveryDeclaredRoleAndRejectsUnknown pins the
// SetTenantRole boundary: every FGA relation name a role ever occupies maps
// back to that role, and a relation no role occupies is rejected.
func TestFromRelation_RoundTripsEveryDeclaredRoleAndRejectsUnknown(t *testing.T) {
	for _, d := range tenantrole.All {
		got, ok := tenantrole.FromRelation(d.Key.Relation())
		if !ok || got != d.Key {
			t.Errorf("FromRelation(%q) = (%q, %v), want (%q, true)", d.Key.Relation(), got, ok, d.Key)
		}
	}
	if _, ok := tenantrole.FromRelation("tenant_enabled"); ok {
		t.Error("FromRelation(\"tenant_enabled\") ok = true, want false")
	}
}
