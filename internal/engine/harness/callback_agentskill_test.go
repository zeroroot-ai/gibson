// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"testing"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
	"github.com/zeroroot-ai/gibson/internal/engine/metatool"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
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
	s := &HarnessCallbackService{agentSkills: noAgentSkillStore}
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

func TestSkillLoadHook_StampsTheRecordAndNeedsASink(t *testing.T) {
	s := &HarnessCallbackService{skillLoadSink: noSkillLoadSink}
	info := &harnesspb.ContextInfo{MissionRunId: "run-7"}
	load := metatool.SkillLoad{
		Tenant: "acme", Agent: "agent_principal:a1", MissionID: "m1", RunID: "r1",
		Name: "web-recon", Digest: "sha256:aa",
	}
	// The default sink refuses the load, so a daemon that records no load serves none.
	if err := s.skillLoadHook(info)(context.Background(), load); !errors.Is(err, ErrNoSkillLoadSink) {
		t.Fatalf("default sink error = %v, want ErrNoSkillLoadSink", err)
	}
	var got SkillLoadRecord
	var tenant string
	s.skillLoadSink = func(_ context.Context, tn string, l SkillLoadRecord) error { tenant, got = tn, l; return nil }
	if err := s.skillLoadHook(info)(context.Background(), load); err != nil {
		t.Fatalf("hook: %v", err)
	}
	if tenant != "acme" || got.MissionRunID != "run-7" || got.Digest != "sha256:aa" ||
		got.Agent != "agent_principal:a1" || got.RecordedAtUnixNano == 0 {
		t.Errorf("record = %+v, tenant %q", got, tenant)
	}
}

func TestHideBlockedSkills_HidesOnlyADeniedAgentSkill(t *testing.T) {
	if hideBlockedSkills(nil) != nil {
		t.Error("an empty deny list must hide nothing")
	}
	hide := hideBlockedSkills([]string{"skill:web-recon", "native:nmap", "SKILL:Other"})
	skill, _ := toolid.ForSkill("web-recon")
	other, _ := toolid.ForSkill("kept")
	nmap, _ := toolid.ForNative("nmap")
	if !hide(skill) {
		t.Error("a denied Agent Skill must be hidden")
	}
	if hide(other) {
		t.Error("an Agent Skill that is not denied must stay")
	}
	if hide(nmap) {
		t.Error("a denied tool is refused at the call, and is not hidden here")
	}
}

type oneSkillStore struct{ agentskillstore.Store }

func (oneSkillStore) List(context.Context, string, string, bool) ([]agentskillstore.Entry, error) {
	return []agentskillstore.Entry{{Name: "web-recon", Description: "d"}}, nil
}

type oneToolLister struct{}

func (oneToolLister) ListTools(context.Context, string) ([]catalog.ToolEntry, error) {
	return []catalog.ToolEntry{{Source: toolid.SourceNative, Tool: "nmap"}}, nil
}

// An Agent Skill comes before a tool, so a limit of one returns the Agent Skill.
func TestToolLister_ListsAgentSkillsBeforeTools(t *testing.T) {
	s := &HarnessCallbackService{agentSkills: func() agentskillstore.Store { return oneSkillStore{} }}
	got, err := s.toolLister(oneToolLister{}).ListTools(context.Background(), "acme")
	if err != nil || len(got) != 2 {
		t.Fatalf("ListTools = %+v, %v", got, err)
	}
	if got[0].Source != toolid.SourceSkill || got[1].Source != toolid.SourceNative {
		t.Errorf("order = %v then %v, want skill then native", got[0].Source, got[1].Source)
	}
}
