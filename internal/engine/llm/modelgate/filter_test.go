// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package modelgate

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// fakeFGA holds tuples and tenant memberships. A check passes on an exact
// tuple, or on a tuple granted to tenant:<id>#member when the subject is a
// member of that tenant, which is how the real model resolves that userset.
type fakeFGA struct {
	authz.Authorizer
	tuples   map[authz.Tuple]bool
	members  map[string]string // subject → tenant
	checkErr error
	writes   int
	checks   int
}

func newFakeFGA() *fakeFGA {
	return &fakeFGA{tuples: map[authz.Tuple]bool{}, members: map[string]string{}}
}

func (f *fakeFGA) member(subject, tenant string) *fakeFGA {
	f.members[subject] = tenant
	return f
}

func (f *fakeFGA) holds(user, relation, object string) bool {
	if f.tuples[authz.Tuple{User: user, Relation: relation, Object: object}] {
		return true
	}
	if tenant, ok := f.members[user]; ok {
		return f.tuples[authz.Tuple{User: TenantMembers(tenant), Relation: relation, Object: object}]
	}
	return false
}

func (f *fakeFGA) Check(_ context.Context, user, relation, object string) (bool, error) {
	f.checks++
	if f.checkErr != nil {
		return false, f.checkErr
	}
	return f.holds(user, relation, object), nil
}

func (f *fakeFGA) BatchCheck(_ context.Context, reqs []authz.CheckRequest) ([]bool, error) {
	f.checks += len(reqs)
	if f.checkErr != nil {
		return nil, f.checkErr
	}
	out := make([]bool, len(reqs))
	for i, r := range reqs {
		out[i] = f.holds(r.User, r.Relation, r.Object)
	}
	return out, nil
}

func (f *fakeFGA) Write(_ context.Context, tuples []authz.Tuple) error {
	f.writes++
	for _, t := range tuples {
		f.tuples[t] = true
	}
	return nil
}

const testTenant = "acme"

var opus = Candidate{Provider: "anthropic", Model: "claude-opus"}

// tenantCtx is a request in testTenant with no user and no component.
func tenantCtx(t *testing.T) context.Context {
	t.Helper()
	return auth.WithTenant(context.Background(), auth.MustNewTenantID(testTenant))
}

func initiatorCtx(t *testing.T, user string) context.Context {
	t.Helper()
	return auth.ContextWithInitiatorUser(tenantCtx(t), user)
}

func permitted(t *testing.T, f Filter, ctx context.Context) bool {
	t.Helper()
	got, err := f.Permitted(ctx, []Candidate{opus})
	if err != nil {
		t.Fatalf("Permitted: %v", err)
	}
	return len(got) == 1
}

// TestDefaultAllow: after the default grant, each member of the tenant may
// use the provider's models, and a person outside the tenant may not.
func TestDefaultAllow(t *testing.T) {
	fga := newFakeFGA().member("user:alice", testTenant).member("agent_principal:scanner", testTenant)
	wrote, err := EnsureDefaultGrant(context.Background(), fga, testTenant, "anthropic")
	if err != nil || !wrote {
		t.Fatalf("EnsureDefaultGrant = %v, %v; want the default written", wrote, err)
	}
	f := NewFGAFilter(fga, nil, 0)

	if !permitted(t, f, initiatorCtx(t, "alice")) {
		t.Error("a member who started the mission is denied; the default must allow her")
	}
	component := auth.WithIdentity(tenantCtx(t), auth.Identity{Subject: "agent_principal:scanner", Tenant: auth.MustNewTenantID(testTenant)})
	if !permitted(t, f, component) {
		t.Error("a member component is denied; the default must allow it")
	}
	if !permitted(t, f, tenantCtx(t)) {
		t.Error("work that no person started is denied while the tenant-wide grant stands")
	}
	if permitted(t, f, initiatorCtx(t, "mallory")) {
		t.Error("a person who is not a member of the tenant is permitted")
	}
}

// TestExplicitOff: an administrator revokes the tenant-wide grant. The
// default is not written again, members are denied, work that no person
// started is denied, and a person with a grant of her own keeps access.
func TestExplicitOff(t *testing.T) {
	fga := newFakeFGA().member("user:alice", testTenant).member("user:bob", testTenant)
	if _, err := EnsureDefaultGrant(context.Background(), fga, testTenant, "anthropic"); err != nil {
		t.Fatalf("EnsureDefaultGrant: %v", err)
	}
	delete(fga.tuples, authz.Tuple{User: TenantMembers(testTenant), Relation: "can_use", Object: "provider:acme/anthropic"})
	fga.tuples[authz.Tuple{User: "user:bob", Relation: "can_use", Object: "model:acme/claude-opus"}] = true

	wrote, err := EnsureDefaultGrant(context.Background(), fga, testTenant, "anthropic")
	if err != nil || wrote {
		t.Fatalf("EnsureDefaultGrant after a revoke = %v, %v; it must not write the default again", wrote, err)
	}
	f := NewFGAFilter(fga, nil, 0)
	if permitted(t, f, initiatorCtx(t, "alice")) {
		t.Error("a member is permitted after the administrator revoked the tenant-wide grant")
	}
	if permitted(t, f, tenantCtx(t)) {
		t.Error("work that no person started is permitted after the revoke")
	}
	if !permitted(t, f, initiatorCtx(t, "bob")) {
		t.Error("a person with a grant on the model is denied")
	}
}

// TestFailClosed covers the three cases that used to permit every model.
func TestFailClosed(t *testing.T) {
	t.Run("no subject and no tenant", func(t *testing.T) {
		fga := newFakeFGA()
		if _, err := EnsureDefaultGrant(context.Background(), fga, testTenant, "anthropic"); err != nil {
			t.Fatalf("EnsureDefaultGrant: %v", err)
		}
		if permitted(t, NewFGAFilter(fga, nil, 0), context.Background()) {
			t.Error("a request that names nobody is permitted")
		}
	})
	t.Run("an FGA error", func(t *testing.T) {
		fga := newFakeFGA()
		fga.checkErr = errors.New("fga is down")
		got, err := NewFGAFilter(fga, nil, 0).Permitted(initiatorCtx(t, "alice"), []Candidate{opus})
		if err == nil || len(got) != 0 {
			t.Errorf("Permitted on an FGA error = %v, %v; want no candidate and the error", got, err)
		}
	})
	t.Run("no authorizer", func(t *testing.T) {
		got, err := NewFGAFilter(nil, nil, 0).Permitted(initiatorCtx(t, "alice"), []Candidate{opus})
		if err == nil || len(got) != 0 {
			t.Errorf("Permitted with no authorizer = %v, %v; want no candidate and an error", got, err)
		}
	})
}

// TestSubject pins the order: acting user, mission initiator, calling
// identity, then the tenant's members.
func TestSubject(t *testing.T) {
	tenant := auth.MustNewTenantID(testTenant)
	person := auth.WithIdentity(tenantCtx(t), auth.Identity{Subject: "u-carol", Tenant: tenant})
	component := auth.WithIdentity(tenantCtx(t), auth.Identity{Subject: "tool_principal:nmap", Tenant: tenant})
	for name, tc := range map[string]struct {
		ctx  context.Context
		want string
	}{
		"acting user wins":      {auth.ContextWithActingUser(auth.ContextWithInitiatorUser(person, "alice"), "dave"), "user:dave"},
		"initiator over caller": {auth.ContextWithInitiatorUser(component, "alice"), "user:alice"},
		"calling person":        {person, "user:u-carol"},
		"calling component":     {component, "tool_principal:nmap"},
		"tenant members":        {tenantCtx(t), "tenant:acme#member"},
		"nobody":                {context.Background(), ""},
	} {
		if got := Subject(tc.ctx); got != tc.want {
			t.Errorf("%s: Subject = %q, want %q", name, got, tc.want)
		}
	}
}

// TestCache: a decision is remembered, and InvalidateCache makes the next
// call ask FGA again, which is how a revoke takes effect at once.
func TestCache(t *testing.T) {
	fga := newFakeFGA().member("user:alice", testTenant)
	if _, err := EnsureDefaultGrant(context.Background(), fga, testTenant, "anthropic"); err != nil {
		t.Fatalf("EnsureDefaultGrant: %v", err)
	}
	f := NewFGAFilter(fga, nil, 0)
	ctx := initiatorCtx(t, "alice")
	if !permitted(t, f, ctx) {
		t.Fatal("first call denied")
	}
	asked := fga.checks
	if !permitted(t, f, ctx) || fga.checks != asked {
		t.Errorf("second call asked FGA again (%d → %d checks); the decision must be cached", asked, fga.checks)
	}
	delete(fga.tuples, authz.Tuple{User: TenantMembers(testTenant), Relation: "can_use", Object: "provider:acme/anthropic"})
	if !permitted(t, f, ctx) {
		t.Error("the cached decision changed without an invalidation")
	}
	f.InvalidateCache()
	if permitted(t, f, ctx) {
		t.Error("after InvalidateCache the revoke must deny")
	}
	if got, err := f.Permitted(ctx, nil); err != nil || len(got) != 0 {
		t.Errorf("Permitted with no candidate = %v, %v", got, err)
	}
}

// TestEnsureDefaultGrant_Refusals: the default needs an authorizer, a tenant
// and a provider, and an FGA error is returned.
func TestEnsureDefaultGrant_Refusals(t *testing.T) {
	if _, err := EnsureDefaultGrant(context.Background(), nil, testTenant, "anthropic"); err == nil {
		t.Error("no authorizer: want an error")
	}
	if _, err := EnsureDefaultGrant(context.Background(), newFakeFGA(), "", "anthropic"); err == nil {
		t.Error("no tenant: want an error")
	}
	if _, err := EnsureDefaultGrant(context.Background(), newFakeFGA(), testTenant, ""); err == nil {
		t.Error("no provider: want an error")
	}
	if _, err := EnsureDefaultGrant(context.Background(), newFakeFGA(), "victim-co/acme", "anthropic"); err == nil {
		t.Error("a tenant that carries a separator: want an error")
	}
	down := newFakeFGA()
	down.checkErr = errors.New("fga is down")
	if _, err := EnsureDefaultGrant(context.Background(), down, testTenant, "anthropic"); err == nil {
		t.Error("an FGA error: want it returned")
	}
}

// TestTenantScope: a grant in one tenant's namespace says nothing about the
// same provider name in another tenant. Before hosted#358 the objects were
// global, so one tenant's administrator could grant what another tenant's
// gate honored.
func TestTenantScope(t *testing.T) {
	fga := newFakeFGA().member("user:alice", "acme").member("user:alice", "acme")
	// An administrator of victim-co grants alice the provider in victim-co.
	fga.tuples[authz.Tuple{User: "user:alice", Relation: "can_use", Object: "provider:victim-co/anthropic"}] = true
	// A legacy global grant from before the namespace.
	fga.tuples[authz.Tuple{User: "user:alice", Relation: "can_use", Object: "provider:anthropic"}] = true

	if permitted(t, NewFGAFilter(fga, nil, 0), initiatorCtx(t, "alice")) {
		t.Error("a grant outside the tenant's namespace permitted a model in tenant acme")
	}
}

// TestUnnameableCandidate: a candidate whose name cannot form an FGA object
// is denied without a call to FGA.
func TestUnnameableCandidate(t *testing.T) {
	fga := newFakeFGA().member("user:alice", testTenant)
	if _, err := EnsureDefaultGrant(context.Background(), fga, testTenant, "anthropic"); err != nil {
		t.Fatalf("EnsureDefaultGrant: %v", err)
	}
	got, err := NewFGAFilter(fga, nil, 0).Permitted(initiatorCtx(t, "alice"), []Candidate{{Provider: "anthropic", Model: "bad#member"}, opus})
	if err != nil || len(got) != 1 || got[0] != opus {
		t.Errorf("Permitted = %v, %v; want only the nameable candidate", got, err)
	}
}
