// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
	"github.com/zeroroot-ai/gibson/internal/platform/agentskillstore"
	"github.com/zeroroot-ai/sdk/auth"
)

func TestCatalogCaller_SetsTheAgentOnlyForAnAgentPrincipal(t *testing.T) {
	state := &RunAuthzState{UserID: "u1", TenantID: "acme", MissionID: "m1"}
	tenant := auth.MustNewTenantID("acme")

	agentCtx := auth.WithIdentity(context.Background(), auth.Identity{Subject: "agent_principal:a1", Tenant: tenant})
	got := catalogCaller(agentCtx, state)
	want := catalog.Caller{Subject: "user:u1", Tenant: "acme", Mission: "m1", Agent: "agent_principal:a1"}
	if got != want {
		t.Errorf("agent caller = %+v, want %+v", got, want)
	}

	// A person or a tool identity is not an agent. It gets no Agent field, so a
	// grant to an agent never matches it.
	for _, subject := range []string{"user:alice", "tool_principal:t1", "someone"} {
		ctx := auth.WithIdentity(context.Background(), auth.Identity{Subject: subject, Tenant: tenant})
		if c := catalogCaller(ctx, state); c.Agent != "" {
			t.Errorf("subject %q gave Agent %q, want none", subject, c.Agent)
		}
	}
	if c := catalogCaller(context.Background(), state); c.Agent != "" || c.Mission != "m1" {
		t.Errorf("no identity: %+v", c)
	}
}

type stubStore struct{ agentskillstore.Store }

type noEntries struct{}

func (noEntries) ListTools(context.Context, string) ([]catalog.ToolEntry, error) { return nil, nil }

func TestToolLister_AddsAgentSkillsOnlyWhenTheStoreIsReady(t *testing.T) {
	s := &HarnessCallbackService{}
	tools := noEntries{}
	if got := s.toolLister(tools); got != catalog.ToolLister(tools) {
		t.Error("with no store wired the lister must be the tool lister")
	}
	s.agentSkills = func() agentskillstore.Store { return nil }
	if got := s.toolLister(tools); got != catalog.ToolLister(tools) {
		t.Error("with a store that is not ready the lister must be the tool lister")
	}
	s.agentSkills = func() agentskillstore.Store { return stubStore{} }
	if got := s.toolLister(tools); got == catalog.ToolLister(tools) {
		t.Error("with a ready store the lister must also list Agent Skills")
	}
}
