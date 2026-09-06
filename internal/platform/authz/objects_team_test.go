// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package authz

import (
	"errors"
	"strings"
	"testing"
)

// TestTeamObject_UsesTheCanonicalTenantQualifiedSeparator pins the team object
// to the same separator plugin and secret objects use.
//
// This is not cosmetic. OpenFGA rejects a second colon at the structural
// type-id boundary, so "team:acme:ops" would fail every Write — silently, from
// the caller's point of view, since the tuple simply never lands and the
// matching Check then never matches (gibson#1024). Deriving the separator from
// TenantQualifiedSep rather than repeating "/" keeps team objects moving with
// the rest of the repo if that ever changes.
func TestTeamObject_UsesTheCanonicalTenantQualifiedSeparator(t *testing.T) {
	got, err := TeamObject("acme", "ops")
	if err != nil {
		t.Fatalf("TeamObject: %v", err)
	}
	want := "team:acme" + TenantQualifiedSep + "ops"
	if got != want {
		t.Errorf("TeamObject = %q, want %q", got, want)
	}
	if _, id, _ := strings.Cut(got, ":"); strings.Contains(id, ":") {
		t.Errorf("object id %q contains a colon; OpenFGA rejects that at the type-id boundary", got)
	}
}

// TestTeamObject_RejectsUnsafeSegments covers both sides. The team id is
// caller-supplied and lands inside an FGA reference; the tenant is not, but a
// bad one would produce an object no read path can attribute.
func TestTeamObject_RejectsUnsafeSegments(t *testing.T) {
	for _, tc := range []struct{ name, tenant, teamID string }{
		{"empty team id", "acme", ""},
		{"empty tenant", "", "ops"},
		{"separator in team id", "acme", "a/b"},
		{"separator in tenant", "a/b", "ops"},
		{"userset marker", "acme", "ops#member"},
		{"colon", "acme", "team:ops"},
		{"space", "acme", "ops team"},
		{"newline", "acme", "ops\n"},
		{"overlong", "acme", strings.Repeat("a", TeamObjectMaxIDLen+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := TeamObject(tc.tenant, tc.teamID)
			if err == nil {
				t.Fatalf("TeamObject(%q, %q) = %q, want a rejection", tc.tenant, tc.teamID, got)
			}
			if !errors.Is(err, ErrInvalidTeamSegment) {
				t.Errorf("error %v does not wrap ErrInvalidTeamSegment; callers match on it to pick a status code", err)
			}
		})
	}
}

// TestTeamObject_AcceptsOrdinarySlugs is the positive control: a validator that
// rejected everything would satisfy the table above for the wrong reason.
func TestTeamObject_AcceptsOrdinarySlugs(t *testing.T) {
	for _, id := range []string{"ops", "red-team", "team_2", "eng.platform", strings.Repeat("a", TeamObjectMaxIDLen)} {
		if _, err := TeamObject("acme", id); err != nil {
			t.Errorf("TeamObject(acme, %q): %v", id, err)
		}
	}
}

// TestTeamIDFromObject_RoundTripsAndRefusesForeignObjects is the read side.
func TestTeamIDFromObject_RoundTripsAndRefusesForeignObjects(t *testing.T) {
	obj, err := TeamObject("acme", "ops")
	if err != nil {
		t.Fatalf("TeamObject: %v", err)
	}
	if id, ok := TeamIDFromObject("acme", obj); !ok || id != "ops" {
		t.Errorf("TeamIDFromObject round trip = %q, %v; want ops, true", id, ok)
	}

	for _, tc := range []struct{ name, tenant, object string }{
		{"another tenant", "acme", "team:evil-co/ops"},
		{"legacy global object", "acme", "team:ops"},
		{"prefix collision", "acme", "team:acme-corp/ops"},
		{"empty id", "acme", "team:acme/"},
		{"nested separator", "acme", "team:acme/a/b"},
		{"empty tenant", "", "team:acme/ops"},
		{"wrong type", "acme", "plugin:acme/ops"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if id, ok := TeamIDFromObject(tc.tenant, tc.object); ok {
				t.Errorf("TeamIDFromObject(%q, %q) = %q, true; want false", tc.tenant, tc.object, id)
			}
		})
	}
}
