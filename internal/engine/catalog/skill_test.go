// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package catalog

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
)

// grantChecker answers Check from a set of "user|relation|object" grants.
type grantChecker struct {
	grants map[string]bool
	seen   []string
	err    error
}

func (g *grantChecker) Check(_ context.Context, user, relation, object string) (bool, error) {
	g.seen = append(g.seen, user+"|"+relation+"|"+object)
	return g.grants[user+"|"+relation+"|"+object], g.err
}

func skillID(t *testing.T, name string) toolid.ID {
	t.Helper()
	id, err := toolid.ForSkill(name)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestFGAAuthorizer_SkillNeedsAGrantToTheAgentOrTheMission(t *testing.T) {
	const object = "agent_skill:acme/web-recon"
	cases := []struct {
		name   string
		grants map[string]bool
		caller Caller
		want   bool
	}{
		{"granted to the agent", map[string]bool{"agent_principal:a1|can_load|" + object: true},
			Caller{Tenant: "acme", Agent: "agent_principal:a1", Mission: "m1"}, true},
		{"granted to the mission", map[string]bool{"mission:m1|can_load|" + object: true},
			Caller{Tenant: "acme", Agent: "agent_principal:a1", Mission: "m1"}, true},
		{"no grant", nil, Caller{Tenant: "acme", Agent: "agent_principal:a1", Mission: "m1"}, false},
		{"granted to another agent", map[string]bool{"agent_principal:a2|can_load|" + object: true},
			Caller{Tenant: "acme", Agent: "agent_principal:a1", Mission: "m1"}, false},
		// The user of the run holds no right to an Agent Skill.
		{"granted to the user only", map[string]bool{"user:alice|can_load|" + object: true},
			Caller{Subject: "user:alice", Tenant: "acme", Agent: "agent_principal:a1", Mission: "m1"}, false},
		// The object is of the tenant of the caller. A grant in acme says
		// nothing about the same name in another tenant.
		{"another tenant", map[string]bool{"agent_principal:a1|can_load|" + object: true},
			Caller{Tenant: "other", Agent: "agent_principal:a1", Mission: "m1"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := NewFGAAuthorizer(&grantChecker{grants: tc.grants})
			got, err := a.CanExecute(context.Background(), tc.caller, skillID(t, "web-recon"))
			if err != nil || got != tc.want {
				t.Fatalf("CanExecute = (%v, %v), want (%v, nil)", got, err, tc.want)
			}
		})
	}
}

func TestFGAAuthorizer_SkillFailsClosed(t *testing.T) {
	a := NewFGAAuthorizer(&grantChecker{})
	// No agent principal and no mission: an error, never an allow.
	if _, err := a.CanExecute(context.Background(), Caller{Tenant: "acme", Subject: "user:alice"},
		skillID(t, "web-recon")); err == nil {
		t.Error("a caller with no agent and no mission must be an error")
	}
	// A user subject in the Agent field is not an agent principal.
	if _, err := a.CanExecute(context.Background(), Caller{Tenant: "acme", Agent: "user:alice"},
		skillID(t, "web-recon")); err == nil {
		t.Error("a user in the agent field must be an error")
	}
	if _, err := a.CanExecute(context.Background(), Caller{Agent: "agent_principal:a1"},
		skillID(t, "web-recon")); err == nil {
		t.Error("a caller with no tenant must be an error")
	}
	boom := errors.New("fga down")
	b := NewFGAAuthorizer(&grantChecker{err: boom})
	if _, err := b.CanExecute(context.Background(), Caller{Tenant: "acme", Mission: "m1"},
		skillID(t, "web-recon")); !errors.Is(err, boom) {
		t.Errorf("an FGA error must pass through, got %v", err)
	}
}

type staticLister []ToolEntry

func (s staticLister) ListTools(context.Context, string) ([]ToolEntry, error) { return s, nil }

// The search returns an Agent Skill next to the tools, and the FGA check is the
// last step: an Agent Skill with no grant is not in the result.
func TestSearch_ReturnsGrantedAgentSkillsNextToTools(t *testing.T) {
	tools := staticLister{{Source: toolid.SourceNative, Tool: "nmap", Description: "port scan"}}
	skills := staticLister{
		{Source: toolid.SourceSkill, Tool: "web-recon", Description: "map a web target before a scan"},
		{Source: toolid.SourceSkill, Tool: "secret-method", Description: "a scan method with no grant"},
		{Source: toolid.SourceSkill, Tool: "bad--name", Description: "a scan entry that cannot form an id"},
	}
	fga := &grantChecker{grants: map[string]bool{
		"agent_principal:a1|can_load|agent_skill:acme/web-recon": true,
		"user:alice|can_execute|component:tool/nmap":             true,
	}}
	e := NewEngine(CombineListers(tools, skills), NewFGAAuthorizer(fga))

	got, err := e.Search(context.Background(),
		Caller{Subject: "user:alice", Tenant: "acme", Agent: "agent_principal:a1", Mission: "m1"},
		Query{Text: "scan"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) != 2 || got[0].ID != "native:nmap" || got[1].ID != "skill:web-recon" {
		t.Fatalf("Search = %+v, want native:nmap and skill:web-recon", got)
	}
	if got[1].Source != "skill" || got[1].Tool != "web-recon" {
		t.Errorf("skill candidate = %+v", got[1])
	}

	// A filter by source returns the Agent Skills only.
	got, err = e.Search(context.Background(),
		Caller{Subject: "user:alice", Tenant: "acme", Agent: "agent_principal:a1"},
		Query{Sources: []toolid.Source{toolid.SourceSkill}})
	if err != nil || len(got) != 1 || got[0].ID != "skill:web-recon" {
		t.Fatalf("Search by source = %+v, %v", got, err)
	}

	// A caller with no grant sees no Agent Skill.
	got, err = e.Search(context.Background(),
		Caller{Subject: "user:alice", Tenant: "acme", Agent: "agent_principal:a2", Mission: "m2"},
		Query{Sources: []toolid.Source{toolid.SourceSkill}})
	if err != nil || len(got) != 0 {
		t.Fatalf("Search with no grant = %+v, %v, want none", got, err)
	}
}
