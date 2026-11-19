// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package authz

import (
	"errors"
	"testing"
)

// TestOutsideAgentModel_OnlyAMissionCalls pins the rule of the outside_agent
// type (gibson#1403). Only a mission can hold a call grant. A user, a tenant, a
// tenant member and an agent can never hold one, so a tenant member reaches no
// outside agent until an admin grants it to a mission.
func TestOutsideAgentModel_OnlyAMissionCalls(t *testing.T) {
	m := gibsonFGAModel()

	cases := []struct {
		relation, userType string
		want               bool
		why                string
	}{
		{"can_call", "mission", true, "granted_mission"},
		{"can_call", "user", false, "no direct grant to a person"},
		{"can_call", "tenant", false, "no tenant#member grant, so no default grant"},
		{"can_call", "team", false, "no team grant"},
		{"can_call", "agent_principal", false, "a grant goes to one mission, not to an agent"},
		{"granted_mission", "mission", true, "[mission]"},
		{"granted_mission", "tenant", false, "[mission]"},
		{"granted_mission", "user", false, "[mission]"},
		{"owner", "tenant", true, "[tenant]"},
		{"owner", "user", false, "[tenant]"},
		{"can_manage", "user", true, "admin from owner"},
		{"can_manage", "agent_principal", false, "tenant#admin admits a user only"},
		{"can_manage", "mission", false, "a mission does not manage the record"},
	}
	for _, tc := range cases {
		got, err := m.admitsSubjectType("outside_agent", tc.relation, tc.userType, map[string]bool{})
		if err != nil {
			t.Errorf("outside_agent.%s @ %s: %v", tc.relation, tc.userType, err)
			continue
		}
		if got != tc.want {
			t.Errorf("outside_agent.%s admits %q = %v, want %v (%s)", tc.relation, tc.userType, got, tc.want, tc.why)
		}
	}
}

// outsideAgentDefaultGrants returns each reason that the outside_agent type of
// m gives a call right with no grant to one mission.
func outsideAgentDefaultGrants(m fgaModel) []string {
	var out []string
	def, ok := m["outside_agent"]["can_call"]
	if !ok {
		return []string{"outside_agent.can_call is not defined"}
	}
	if len(def.direct) != 0 || len(def.ttus) != 0 {
		out = append(out, "can_call has a direct list or a computed tenant term")
	}
	for _, d := range m["outside_agent"]["granted_mission"].direct {
		if d != "mission" {
			out = append(out, "granted_mission admits "+d)
		}
	}
	return out
}

func TestOutsideAgentModel_NoDefaultGrantGuard(t *testing.T) {
	if got := outsideAgentDefaultGrants(gibsonFGAModel()); len(got) != 0 {
		t.Errorf("model.fga gives a default grant on outside_agent: %v", got)
	}
}

// The failing fixture. A model that lets a tenant member call must be caught.
func TestOutsideAgentModel_NoDefaultGrantGuardFailsOnFixture(t *testing.T) {
	const bad = `model
  schema 1.1

type user

type tenant
  relations
    define member: [user]

type outside_agent
  relations
    define owner: [tenant]
    define granted_mission: [mission, tenant#member]
    define can_call: [tenant#member] or granted_mission
`
	if got := outsideAgentDefaultGrants(parseFGAModel(bad)); len(got) == 0 {
		t.Fatal("the guard did not report a default grant in the bad fixture")
	}
}

func TestOutsideAgentObject(t *testing.T) {
	got, err := OutsideAgentObject("acme", "partner-scout")
	if err != nil || got != "outside_agent:acme/partner-scout" {
		t.Errorf("OutsideAgentObject = %q, %v", got, err)
	}
	for name, tc := range map[string][2]string{
		"no tenant":             {"", "partner-scout"},
		"tenant with separator": {"victim-co/acme", "partner-scout"},
		"no name":               {"acme", ""},
		"userset marker":        {"acme", "scout#member"},
	} {
		if got, err := OutsideAgentObject(tc[0], tc[1]); !errors.Is(err, ErrInvalidOutsideAgentObject) {
			t.Errorf("%s: OutsideAgentObject = %q, %v; want ErrInvalidOutsideAgentObject", name, got, err)
		}
	}
}
