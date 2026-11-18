// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package authz

import (
	"errors"
	"testing"
)

// TestAgentSkillModel_NoDefaultGrant pins the rule of the agent_skill type
// (epic gibson#1364, decision 10). Only an agent and a mission can hold a load
// grant. A user, a tenant and a tenant member can never hold one, so a tenant
// member has no access until an admin writes a grant.
func TestAgentSkillModel_NoDefaultGrant(t *testing.T) {
	m := gibsonFGAModel()

	cases := []struct {
		relation, userType string
		want               bool
		why                string
	}{
		{"can_load", "agent_principal", true, "granted_agent"},
		{"can_load", "mission", true, "granted_mission"},
		{"can_load", "user", false, "no direct grant to a person"},
		{"can_load", "tenant", false, "no tenant#member grant, so no default grant"},
		{"can_load", "team", false, "no team grant"},
		{"can_load", "tool_principal", false, "only an agent loads an Agent Skill"},
		{"can_load", "plugin_principal", false, "only an agent loads an Agent Skill"},
		{"granted_agent", "agent_principal", true, "[agent_principal]"},
		{"granted_agent", "user", false, "[agent_principal]"},
		{"granted_mission", "mission", true, "[mission]"},
		{"granted_mission", "tenant", false, "[mission]"},
		{"owner", "tenant", true, "[tenant]"},
		{"owner", "user", false, "[tenant]"},
		// can_manage is a tenant admin through the owner tuple.
		{"can_manage", "user", true, "admin from owner"},
		{"can_manage", "agent_principal", false, "tenant#admin admits a user only"},
	}
	for _, tc := range cases {
		got, err := m.admitsSubjectType("agent_skill", tc.relation, tc.userType, map[string]bool{})
		if err != nil {
			t.Errorf("agent_skill.%s @ %s: %v", tc.relation, tc.userType, err)
			continue
		}
		if got != tc.want {
			t.Errorf("agent_skill.%s admits %q = %v, want %v (%s)", tc.relation, tc.userType, got, tc.want, tc.why)
		}
	}
}

// agentSkillDefaultGrants returns each reason that the agent_skill type of m
// gives a load right with no grant. It reports a direct type list or a
// tuple-to-userset term on can_load, and a subject type that is not an agent or
// a mission on a grant relation.
func agentSkillDefaultGrants(m fgaModel) []string {
	var out []string
	def, ok := m["agent_skill"]["can_load"]
	if !ok {
		return []string{"agent_skill.can_load is not defined"}
	}
	if len(def.direct) != 0 || len(def.ttus) != 0 {
		out = append(out, "can_load has a direct list or a computed tenant term")
	}
	for _, rel := range []string{"granted_agent", "granted_mission"} {
		for _, d := range m["agent_skill"][rel].direct {
			if d != "agent_principal" && d != "mission" {
				out = append(out, rel+" admits "+d)
			}
		}
	}
	return out
}

func TestAgentSkillModel_NoDefaultGrantGuard(t *testing.T) {
	if got := agentSkillDefaultGrants(gibsonFGAModel()); len(got) != 0 {
		t.Errorf("model.fga gives a default grant on agent_skill: %v", got)
	}
}

// The failing fixture. A model that lets a tenant member load must be caught.
func TestAgentSkillModel_NoDefaultGrantGuardFailsOnFixture(t *testing.T) {
	const bad = `model
  schema 1.1

type user

type tenant
  relations
    define member: [user]

type agent_skill
  relations
    define owner: [tenant]
    define granted_agent: [agent_principal, tenant#member]
    define can_load: [tenant#member] or granted_agent
`
	if got := agentSkillDefaultGrants(parseFGAModel(bad)); len(got) == 0 {
		t.Fatal("the guard did not report a default grant in the bad fixture")
	}
}

func TestAgentSkillObject(t *testing.T) {
	got, err := AgentSkillObject("acme", "web-recon")
	if err != nil || got != "agent_skill:acme/web-recon" {
		t.Errorf("AgentSkillObject = %q, %v", got, err)
	}
	for name, tc := range map[string][2]string{
		"no tenant":             {"", "web-recon"},
		"tenant with separator": {"victim-co/acme", "web-recon"},
		"no name":               {"acme", ""},
		"userset marker":        {"acme", "recon#member"},
	} {
		if got, err := AgentSkillObject(tc[0], tc[1]); !errors.Is(err, ErrInvalidAgentSkillObject) {
			t.Errorf("%s: AgentSkillObject = %q, %v; want ErrInvalidAgentSkillObject", name, got, err)
		}
	}
}
