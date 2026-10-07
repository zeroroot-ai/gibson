// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package tenantrole

import "testing"

func TestRoleChecks_AskEachRelationHighestFirst(t *testing.T) {
	checks := RoleChecks("user:42", "tenant:acme")
	want := []string{"owner", "admin", "writer", "member"}
	if len(checks) != len(want) {
		t.Fatalf("checks = %v, want %d", checks, len(want))
	}
	for i, c := range checks {
		if c.User != "user:42" || c.Object != "tenant:acme" || c.Relation != want[i] {
			t.Errorf("check %d = %+v, want user:42 %s tenant:acme", i, c, want[i])
		}
	}
}

func TestHighestRelation(t *testing.T) {
	cases := []struct {
		held   []bool
		want   string
		wantOK bool
	}{
		// The FGA model computes each relation from the one above it, so an
		// Owner answers true down the chain. The highest wins.
		{[]bool{true, true, true, true}, "owner", true},
		{[]bool{false, true, true, true}, "admin", true},
		{[]bool{false, false, true, true}, "writer", true},
		{[]bool{false, false, false, true}, "member", true},
		{[]bool{false, false, false, false}, "", false},
		{nil, "", false},
	}
	for _, c := range cases {
		got, ok := HighestRelation(c.held)
		if got != c.want || ok != c.wantOK {
			t.Errorf("HighestRelation(%v) = %q, %v; want %q, %v", c.held, got, ok, c.want, c.wantOK)
		}
	}
}
