// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package authz

import (
	"errors"
	"testing"
)

// TestPublishedMissionModel_OnlyAnAgentIdentityCalls pins the rule of the
// published_mission type (gibson#1408). Only an enrolled agent identity can hold
// the grant. A user, a tenant, a tenant member and a mission can never hold
// one, so no tenant member reaches a published definition by default.
func TestPublishedMissionModel_OnlyAnAgentIdentityCalls(t *testing.T) {
	m := gibsonFGAModel()

	cases := []struct {
		relation, userType string
		want               bool
		why                string
	}{
		{"can_originate", "agent_principal", true, "granted_caller"},
		{"can_originate", "user", false, "no direct grant to a person"},
		{"can_originate", "tenant", false, "no tenant#member grant, so no default grant"},
		{"can_originate", "team", false, "no team grant"},
		{"can_originate", "mission", false, "a grant goes to one identity, not to a mission"},
		{"granted_caller", "agent_principal", true, "[agent_principal]"},
		{"granted_caller", "tenant", false, "[agent_principal]"},
		{"granted_caller", "user", false, "[agent_principal]"},
		{"owner", "tenant", true, "[tenant]"},
		{"owner", "user", false, "[tenant]"},
		{"can_manage", "user", true, "admin from owner"},
		{"can_manage", "agent_principal", false, "tenant#admin admits a user only"},
	}
	for _, tc := range cases {
		got, err := m.admitsSubjectType("published_mission", tc.relation, tc.userType, map[string]bool{})
		if err != nil {
			t.Errorf("published_mission.%s @ %s: %v", tc.relation, tc.userType, err)
			continue
		}
		if got != tc.want {
			t.Errorf("published_mission.%s admits %q = %v, want %v (%s)", tc.relation, tc.userType, got, tc.want, tc.why)
		}
	}
}

// publishedMissionDefaultGrants returns each reason that the published_mission
// type of m gives a call right with no grant to one agent identity.
func publishedMissionDefaultGrants(m fgaModel) []string {
	var out []string
	def, ok := m["published_mission"]["can_originate"]
	if !ok {
		return []string{"published_mission.can_originate is not defined"}
	}
	if len(def.direct) != 0 || len(def.ttus) != 0 {
		out = append(out, "can_originate has a direct list or a computed tenant term")
	}
	for _, d := range m["published_mission"]["granted_caller"].direct {
		if d != "agent_principal" {
			out = append(out, "granted_caller admits "+d)
		}
	}
	return out
}

func TestPublishedMissionModel_NoDefaultGrantGuard(t *testing.T) {
	if got := publishedMissionDefaultGrants(gibsonFGAModel()); len(got) != 0 {
		t.Errorf("model.fga gives a default grant on published_mission: %v", got)
	}
}

// The failing fixture. A model that lets a tenant member call must be caught.
func TestPublishedMissionModel_NoDefaultGrantGuardFailsOnFixture(t *testing.T) {
	const bad = `model
  schema 1.1

type user

type tenant
  relations
    define member: [user]

type published_mission
  relations
    define owner: [tenant]
    define granted_caller: [agent_principal, tenant#member]
    define can_originate: [tenant#member] or granted_caller
`
	if got := publishedMissionDefaultGrants(parseFGAModel(bad)); len(got) == 0 {
		t.Fatal("the guard did not report a default grant in the bad fixture")
	}
}

func TestPublishedMissionObject(t *testing.T) {
	got, err := PublishedMissionObject("acme", "recon")
	if err != nil || got != "published_mission:acme/recon" {
		t.Errorf("PublishedMissionObject = %q, %v", got, err)
	}
	for name, tc := range map[string][2]string{
		"no tenant":             {"", "recon"},
		"tenant with separator": {"victim-co/acme", "recon"},
		"no agent":              {"acme", ""},
		"userset marker":        {"acme", "recon#member"},
	} {
		if got, err := PublishedMissionObject(tc[0], tc[1]); !errors.Is(err, ErrInvalidPublishedMissionObject) {
			t.Errorf("%s: PublishedMissionObject = %q, %v; want ErrInvalidPublishedMissionObject", name, got, err)
		}
	}
}
