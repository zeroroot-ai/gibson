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
	grant  *capabilitygrant.AgentGrant
	tenant string
	id     string
}

func (f *fakeSource) GrantByID(_ context.Context, tenant, id string) (*capabilitygrant.AgentGrant, error) {
	f.tenant, f.id = tenant, id
	return f.grant, nil
}

func TestStoreGrants_ReadsTheGrantOfTheEventAndItsOwner(t *testing.T) {
	src := &fakeSource{grant: &capabilitygrant.AgentGrant{
		Grant: capabilitygrant.Grant{
			ID: "g-ok", CapabilityName: "execute:tool:mcp:okta", Status: "active",
			GrantedAt: time.Unix(1700000000, 0),
		},
		OwnerUserID: "user-3",
	}}
	got, err := StoreGrants{Source: src}.GrantByID(context.Background(), "acme", "g-ok")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.ID != "g-ok" || got.GrantedBy != "user-3" || got.GrantedAtUnix != 1700000000 {
		t.Errorf("grant = %+v", got)
	}
	if src.tenant != "acme" || src.id != "g-ok" {
		t.Errorf("asked for tenant %q and id %q", src.tenant, src.id)
	}
}

func TestStoreGrants_NoGrantGivesNil(t *testing.T) {
	got, err := StoreGrants{Source: &fakeSource{}}.GrantByID(context.Background(), "acme", "g-none")
	if err != nil || got != nil {
		t.Errorf("got %+v, err %v", got, err)
	}
}
