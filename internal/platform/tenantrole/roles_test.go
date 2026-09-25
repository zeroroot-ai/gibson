// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package tenantrole_test

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
)

func TestRole_RelationMapping(t *testing.T) {
	cases := []struct {
		role tenantrole.Role
		rel  string
	}{
		{tenantrole.Owner, "owner"},
		{tenantrole.Admin, "admin"},
		{tenantrole.Editor, "writer"},
		{tenantrole.Viewer, "member"},
	}
	for _, tc := range cases {
		if got := tc.role.Relation(); got != tc.rel {
			t.Errorf("%s.Relation() = %q, want %q", tc.role, got, tc.rel)
		}
	}
}

func TestParse_RoundTripsWithAll(t *testing.T) {
	for _, d := range tenantrole.All {
		got, ok := tenantrole.Parse(string(d.Key))
		if !ok || got != d.Key {
			t.Errorf("Parse(%q) = (%q, %v), want (%q, true)", d.Key, got, ok, d.Key)
		}
	}
	if _, ok := tenantrole.Parse("superuser"); ok {
		t.Error("Parse(superuser) ok = true, want false")
	}
}

func TestFromRelation_RoundTripsWithRelation(t *testing.T) {
	for _, d := range tenantrole.All {
		rel := d.Key.Relation()
		got, ok := tenantrole.FromRelation(rel)
		if !ok || got != d.Key {
			t.Errorf("FromRelation(%q) = (%q, %v), want (%q, true)", rel, got, ok, d.Key)
		}
	}
	if _, ok := tenantrole.FromRelation("tenant_enabled"); ok {
		t.Error("FromRelation(tenant_enabled) ok = true, want false")
	}
}

func TestKeys_MatchesAllInOrder(t *testing.T) {
	keys := tenantrole.Keys()
	if len(keys) != len(tenantrole.All) {
		t.Fatalf("len(Keys()) = %d, want %d", len(keys), len(tenantrole.All))
	}
	for i, d := range tenantrole.All {
		if keys[i] != string(d.Key) {
			t.Errorf("Keys()[%d] = %q, want %q", i, keys[i], d.Key)
		}
	}
}

func TestRelations_MatchesEveryRolesRelation(t *testing.T) {
	want := map[string]bool{}
	for _, d := range tenantrole.All {
		want[d.Key.Relation()] = true
	}
	got := map[string]bool{}
	for _, r := range tenantrole.Relations {
		got[r] = true
	}
	if len(got) != len(want) {
		t.Fatalf("Relations = %v, want exactly %v", tenantrole.Relations, want)
	}
	for r := range want {
		if !got[r] {
			t.Errorf("Relations missing %q", r)
		}
	}
}
