// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package incidentreport

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
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

func TestStoreGrants_ReadsTheGrantOfTheEventAndNeverNamesTheOwnerAsGrantor(t *testing.T) {
	src := &fakeSource{grant: &capabilitygrant.AgentGrant{
		Grant: capabilitygrant.Grant{
			ID: "g-ok", CapabilityName: "execute:tool:mcp:okta", Status: "active",
			GrantedAt: time.Unix(1700000000, 0),
		},
		OwnerUserID: "user-3",
	}}
	got, err := StoreGrants{Source: src}.GrantByID(context.Background(), "acme", "g-ok", time.Unix(1700000500, 0))
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.ID != "g-ok" || got.GrantedBy != "" || got.GrantedAtUnix != 1700000000 {
		t.Errorf("grant = %+v", got)
	}
	if src.tenant != "acme" || src.id != "g-ok" {
		t.Errorf("asked for tenant %q and id %q", src.tenant, src.id)
	}
}

func TestStoreGrants_NoGrantGivesNil(t *testing.T) {
	got, err := StoreGrants{Source: &fakeSource{}}.GrantByID(context.Background(), "acme", "g-none", time.Time{})
	if err != nil || got != nil {
		t.Errorf("got %+v, err %v", got, err)
	}
}

// fakeChanges holds audit records by tenant, as the audit read does.
type fakeChanges struct{ byTenant map[string][]audit.PgEntry }

func (f fakeChanges) GrantChanges(_ context.Context, tenant, principal string, until time.Time) ([]audit.PgEntry, error) {
	var out []audit.PgEntry
	for _, e := range f.byTenant[tenant] {
		if e.TargetID == principal && !e.CreatedAt.After(until) {
			out = append(out, e)
		}
	}
	return out, nil
}

func change(action, actor, principal, object string, at int64) audit.PgEntry {
	md, _ := json.Marshal(map[string]string{"object": object, "relation": "can_execute"})
	return audit.PgEntry{Action: action, ActorID: actor, TargetID: principal, Metadata: md, CreatedAt: time.Unix(at, 0)}
}

func grantSource() *fakeSource {
	return &fakeSource{grant: &capabilitygrant.AgentGrant{
		Grant: capabilitygrant.Grant{
			ID: "g-1", CapabilityName: "execute:tool:mcp:okta-response", ComponentRef: "component:connector/okta-response",
			Status: "active", GrantedAt: time.Unix(1700000000, 0),
		},
		OwnerUserID: "user-owner", PrincipalRef: "agent_principal:p1",
	}}
}

func TestStoreGrants_GrantedByIsTheGrantorAndNotTheOwner(t *testing.T) {
	obj := "component:connector/okta-response"
	changes := fakeChanges{byTenant: map[string][]audit.PgEntry{"acme": {
		change("agent_grant_added", "user-admin", "agent_principal:p1", obj, 1700000100),
	}}}

	got, err := StoreGrants{Source: grantSource(), Changes: changes}.
		GrantByID(context.Background(), "acme", "g-1", time.Unix(1700000500, 0))

	if err != nil {
		t.Fatal(err)
	}
	if got.GrantedBy != "user-admin" || got.GrantedAtUnix != 1700000100 {
		t.Errorf("GrantedBy = %q at %d, want the grantor user-admin at 1700000100", got.GrantedBy, got.GrantedAtUnix)
	}
}

func TestStoreGrants_AGrantorOfAnotherTenantIsNotUsed(t *testing.T) {
	obj := "component:connector/okta-response"
	changes := fakeChanges{byTenant: map[string][]audit.PgEntry{"globex": {
		change("agent_grant_added", "user-other-tenant", "agent_principal:p1", obj, 1700000100),
	}}}

	got, err := StoreGrants{Source: grantSource(), Changes: changes}.
		GrantByID(context.Background(), "acme", "g-1", time.Unix(1700000500, 0))

	if err != nil {
		t.Fatal(err)
	}
	if got.GrantedBy != "" {
		t.Errorf("GrantedBy = %q, want empty: the record belongs to another tenant", got.GrantedBy)
	}
}

func TestStoreGrants_TheGrantInForceAtTheCallDecides(t *testing.T) {
	obj := "component:connector/okta-response"
	changes := fakeChanges{byTenant: map[string][]audit.PgEntry{"acme": {
		change("agent_grant_added", "user-first", "agent_principal:p1", obj, 100),
		change("agent_grant_removed", "user-first", "agent_principal:p1", obj, 200),
		change("agent_grant_added", "user-second", "agent_principal:p1", obj, 300),
	}}}
	for _, tt := range []struct {
		name string
		at   int64
		want string
	}{{"first", 150, "user-first"}, {"removed", 250, ""}, {"second", 350, "user-second"}} {
		got, err := StoreGrants{Source: grantSource(), Changes: changes}.
			GrantByID(context.Background(), "acme", "g-1", time.Unix(tt.at, 0))
		if err != nil {
			t.Fatal(err)
		}
		if got.GrantedBy != tt.want {
			t.Errorf("%s: GrantedBy = %q, want %q", tt.name, got.GrantedBy, tt.want)
		}
	}
}

type failingChanges struct{}

func (failingChanges) GrantChanges(context.Context, string, string, time.Time) ([]audit.PgEntry, error) {
	return nil, errors.New("audit down")
}

func TestStoreGrants_AFailedAuditReadIsAnError(t *testing.T) {
	_, err := StoreGrants{Source: grantSource(), Changes: failingChanges{}}.
		GrantByID(context.Background(), "acme", "g-1", time.Unix(1700000500, 0))
	if err == nil || !strings.Contains(err.Error(), "audit down") {
		t.Errorf("err = %v, want the audit error", err)
	}
}

// A call with no time reads the grant that is in force now.
func TestStoreGrants_ACallWithNoTimeUsesNow(t *testing.T) {
	obj := "component:connector/okta-response"
	changes := fakeChanges{byTenant: map[string][]audit.PgEntry{"acme": {
		change("agent_grant_added", "user-admin", "agent_principal:p1", obj, 1700000100),
	}}}
	got, err := StoreGrants{Source: grantSource(), Changes: changes}.GrantByID(context.Background(), "acme", "g-1", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if got.GrantedBy != "user-admin" {
		t.Errorf("GrantedBy = %q, want user-admin", got.GrantedBy)
	}
}

func TestCalledAt(t *testing.T) {
	if !calledAt(0).IsZero() {
		t.Error("a zero event time must give the zero time")
	}
	if got := calledAt(1700000000 * int64(time.Second)); got.Unix() != 1700000000 {
		t.Errorf("calledAt = %v", got)
	}
}
