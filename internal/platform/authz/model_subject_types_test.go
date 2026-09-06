// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package authz

import (
	"errors"
	"testing"
)

// TestGibsonModelSubjectTypes pins the resolver against the real model.fga.
//
// Every case is a listing this repo actually makes (or made, wrongly). If
// model.fga changes a relation's type list, the case that changes meaning
// fails here rather than at the call site, where the symptom is an empty list
// nobody questions.
func TestGibsonModelSubjectTypes(t *testing.T) {
	m := gibsonFGAModel()

	cases := []struct {
		objectType, relation, userType string
		want                           bool
		why                            string
	}{
		// --- must admit user ---
		{"tenant", "member", "user", true, "[user, agent_principal, …] or writer"},
		{"tenant", "owner", "user", true, "[user]"},
		{"team", "member", "user", true, "[user, team#admin]"},
		{"team", "admin", "user", true, "[user] or admin from parent"},
		{"agent_principal", "owner", "user", true, "[user]"},
		{"plugin_principal", "owner", "user", true, "[user]"},
		{"system_tenant", "platform_operator", "user", true, "[user]"},
		// gibson#1244: user-scoped active_session gates tenant-less requests.
		// Self-referential: the subject and object are both `user`.
		{"user", "active_session", "user", true, "[user with token_not_revoked] — the tenant-less revocation gate"},
		// Reached only through a userset — the literal bracket list says
		// [team#member], but team#member expands to users.
		{"component", "team_write_disabled", "user", true, "[team#member] → team.member → [user, …]"},
		// Reached only through a tuple-to-userset hop.
		{"component", "can_read", "user", true, "direct_read → [user, …]"},
		{"mission_definition", "writer", "user", true, "admin from parent → tenant.admin → [user]"},

		// --- must NOT admit user ---
		{"team", "parent", "user", false, "[tenant] — the CreateTeam squat guard"},
		{"system_tenant", "parent", "user", false, "[tenant] — the catalog fan-out"},
		{"secret", "can_resolve", "user", false, "[plugin_principal] — structural, spec non-plugin-secret-isolation"},
		{"component", "owner", "user", false, "[tenant]"},
		{"agent_principal", "belongs_to", "user", false, "[tenant]"},

		// --- other subject types ---
		{"team", "parent", "tenant", true, "[tenant]"},
		{"system_tenant", "parent", "tenant", true, "[tenant]"},
		{"secret", "can_resolve", "plugin_principal", true, "[plugin_principal]"},
		{"tenant", "member", "agent_principal", true, "[.., agent_principal, ..]"},
		{"tenant", "member", "tenant", false, "a tenant is never a member of a tenant"},
		// A userset restriction yields the userset's members, not the
		// userset's own object type.
		{"component", "team_write_disabled", "team", false, "[team#member] yields users, not teams"},
	}

	for _, tc := range cases {
		got, err := m.admitsSubjectType(tc.objectType, tc.relation, tc.userType, map[string]bool{})
		if err != nil {
			t.Errorf("%s.%s @ %s: %v", tc.objectType, tc.relation, tc.userType, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s.%s admits %q = %v, want %v (%s)",
				tc.objectType, tc.relation, tc.userType, got, tc.want, tc.why)
		}
	}
}

// A relation model.fga does not define must be an error, not a "no". Answering
// "no" would make a drifted call site look like a deliberate refusal.
func TestGibsonModelSubjectTypes_UnknownIsAnError(t *testing.T) {
	m := gibsonFGAModel()
	if _, err := m.admitsSubjectType("team", "no_such_relation", "user", map[string]bool{}); err == nil {
		t.Error("unknown relation returned no error")
	}
	if _, err := m.admitsSubjectType("no_such_type", "member", "user", map[string]bool{}); err == nil {
		t.Error("unknown object type returned no error")
	}
	if err := requireSubjectType("team", "no_such_relation", "user"); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("requireSubjectType on an unknown relation = %v, want ErrInvalidArgument", err)
	}
}

// The parser has to survive the shapes model.fga actually uses. A parser that
// quietly produced empty definitions would make every relation "admits
// nothing", turning the guard into a blanket refusal — loud, but for the wrong
// reason — or, if it produced garbage type names, into a blanket allow.
func TestParseRelationBody(t *testing.T) {
	cases := []struct {
		name, body string
		direct     []string
		refs       []string
		ttus       [][2]string
	}{
		{"direct only", " [user]", []string{"user"}, nil, nil},
		{"direct plus ref", " [user] or owner", []string{"user"}, []string{"owner"}, nil},
		{"userset entry", " [user, team#admin]", []string{"user", "team#admin"}, nil, nil},
		{"condition suffix", " [user with token_not_revoked]", []string{"user"}, nil, nil},
		{"ttu only", " admin from parent", nil, nil, [][2]string{{"admin", "parent"}}},
		{"direct or ttu", " [user] or admin from parent", []string{"user"}, nil, [][2]string{{"admin", "parent"}}},
		{
			"parens and but-not",
			" (direct_read and in_tenant_catalog) but not any_read_deny",
			nil,
			[]string{"direct_read", "in_tenant_catalog", "any_read_deny"},
			nil,
		},
		{
			"ttu mixed with refs",
			" member from tenant_read_disabled or team_read_disabled or user_read_disabled",
			nil,
			[]string{"team_read_disabled", "user_read_disabled"},
			[][2]string{{"member", "tenant_read_disabled"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseRelationBody(tc.body)
			assertStrings(t, "direct", got.direct, tc.direct)
			assertStrings(t, "refs", got.refs, tc.refs)
			if len(got.ttus) != len(tc.ttus) {
				t.Fatalf("ttus = %v, want %v", got.ttus, tc.ttus)
			}
			for i := range tc.ttus {
				if got.ttus[i] != tc.ttus[i] {
					t.Errorf("ttus[%d] = %v, want %v", i, got.ttus[i], tc.ttus[i])
				}
			}
		})
	}
}

func assertStrings(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %v, want %v", label, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s[%d] = %q, want %q", label, i, got[i], want[i])
		}
	}
}

// Every type named in model.fga must parse with at least one relation. A
// silently-empty type would make every listing against it an error. `user`
// gained its first relation (active_session) in gibson#1244, so no type is
// relation-less any more.
func TestParseFGAModel_CoversEveryType(t *testing.T) {
	m := gibsonFGAModel()
	for _, typ := range []string{
		"user", "tenant", "agent_principal", "tool_principal", "plugin_principal",
		"component", "system_tenant", "team", "mission_definition", "mission",
		"run", "target", "finding", "tenant_component", "provider", "model",
		"secret", "plugin",
	} {
		rels, ok := m[typ]
		if !ok {
			t.Errorf("model.fga type %q did not parse", typ)
			continue
		}
		if len(rels) == 0 {
			t.Errorf("model.fga type %q parsed with zero relations", typ)
		}
	}
}
