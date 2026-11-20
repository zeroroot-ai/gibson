// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package incidentreport

import (
	"context"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
)

type fakeSource struct {
	grants []capabilitygrant.AgentGrant
	tenant string
	name   string
}

func (f *fakeSource) GrantsByAgentName(_ context.Context, tenant, name string) ([]capabilitygrant.AgentGrant, error) {
	f.tenant, f.name = tenant, name
	return f.grants, nil
}

func agentGrant(id, capability, ref, status, owner string) capabilitygrant.AgentGrant {
	return capabilitygrant.AgentGrant{
		Grant: capabilitygrant.Grant{
			ID: id, CapabilityName: capability, ComponentRef: ref, Status: status,
			GrantedAt: time.Unix(1700000000, 0),
		},
		OwnerUserID: owner,
	}
}

func TestStoreGrants_FindsTheActiveGrantAndItsOwner(t *testing.T) {
	src := &fakeSource{grants: []capabilitygrant.AgentGrant{
		agentGrant("g-old", "execute:tool:mcp:okta:suspend_user", "", "revoked", "user-1"),
		agentGrant("g-other", "execute:tool:mcp:crowdstrike:contain_host", "", "active", "user-2"),
		agentGrant("g-ok", "execute:tool:mcp:okta:suspend_user", "", "active", "user-3"),
	}}
	got, err := StoreGrants{Source: src}.GrantFor(context.Background(), "acme", "incident-response", "mcp:okta:suspend_user")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.ID != "g-ok" || got.GrantedBy != "user-3" || got.GrantedAtUnix != 1700000000 {
		t.Errorf("grant = %+v", got)
	}
	if src.tenant != "acme" || src.name != "incident-response" {
		t.Errorf("asked for tenant %q and name %q", src.tenant, src.name)
	}
}

func TestStoreGrants_AGrantForAConnectorCoversItsTools(t *testing.T) {
	src := &fakeSource{grants: []capabilitygrant.AgentGrant{agentGrant("g1", "execute:tool:mcp:okta", "", "active", "u")}}
	got, _ := StoreGrants{Source: src}.GrantFor(context.Background(), "acme", "a", "mcp:okta:revoke_user_sessions")
	if got == nil || got.ID != "g1" {
		t.Errorf("grant = %+v", got)
	}
}

func TestStoreGrants_NoGrantGivesNil(t *testing.T) {
	src := &fakeSource{grants: []capabilitygrant.AgentGrant{agentGrant("g1", "execute:tool:nmap", "", "active", "u")}}
	got, err := StoreGrants{Source: src}.GrantFor(context.Background(), "acme", "a", "mcp:okta:suspend_user")
	if err != nil || got != nil {
		t.Errorf("got %+v, err %v", got, err)
	}
}
