// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package catalog

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
)

// fakeChecker records the exact (user, relation, object) triple and returns a
// canned result.
type fakeChecker struct {
	user, relation, object string
	allow                  bool
	err                    error
	calls                  int
}

func (f *fakeChecker) Check(_ context.Context, user, relation, object string) (bool, error) {
	f.calls++
	f.user, f.relation, f.object = user, relation, object
	return f.allow, f.err
}

func mustMCP(t *testing.T, connector, tool string) toolid.ID {
	t.Helper()
	id, err := toolid.ForMCP(connector, tool)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustNative(t *testing.T, tool string) toolid.ID {
	t.Helper()
	id, err := toolid.ForNative(tool)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestFGAAuthorizerMCPMapsToConnectorComponentCanExecute(t *testing.T) {
	fga := &fakeChecker{allow: true}
	a := NewFGAAuthorizer(fga)

	ok, err := a.CanExecute(context.Background(),
		Caller{Subject: "user:alice", Tenant: "acme"},
		mustMCP(t, "gitlab", "create_issue"))
	if err != nil || !ok {
		t.Fatalf("CanExecute = (%v, %v), want (true, nil)", ok, err)
	}
	// The exact triple is the contract (ADR-0067): connectors are component
	// objects, and the execute gate is per connector — the plugin-object
	// borrow (can_invoke on plugin:<tenant>/<connector>) is retired.
	if fga.user != "user:alice" || fga.relation != "can_execute" || fga.object != "component:connector/gitlab" {
		t.Fatalf("Check(%q, %q, %q), want (user:alice, can_execute, component:connector/gitlab)",
			fga.user, fga.relation, fga.object)
	}
}

// A deny on the connector component (a team or user execute deny folded into
// the model's can_execute) blocks the MCP tool for that subject.
func TestFGAAuthorizerMCPDenyBlocks(t *testing.T) {
	fga := &fakeChecker{allow: false}
	a := NewFGAAuthorizer(fga)

	ok, err := a.CanExecute(context.Background(),
		Caller{Subject: "user:bob", Tenant: "acme"},
		mustMCP(t, "gitlab", "create_issue"))
	if err != nil || ok {
		t.Fatalf("CanExecute = (%v, %v), want (false, nil)", ok, err)
	}
}

func TestFGAAuthorizerNativeMapsToComponentCanExecute(t *testing.T) {
	fga := &fakeChecker{allow: true}
	a := NewFGAAuthorizer(fga)

	ok, err := a.CanExecute(context.Background(),
		Caller{Subject: "agent_principal:agent-1", Tenant: "acme"},
		mustNative(t, "nmap"))
	if err != nil || !ok {
		t.Fatalf("CanExecute = (%v, %v), want (true, nil)", ok, err)
	}
	if fga.user != "agent_principal:agent-1" || fga.relation != "can_execute" || fga.object != "component:tool/nmap" {
		t.Fatalf("Check(%q, %q, %q), want (agent_principal:agent-1, can_execute, component:tool/nmap)",
			fga.user, fga.relation, fga.object)
	}
}

func TestFGAAuthorizerDenyPassesThrough(t *testing.T) {
	fga := &fakeChecker{allow: false}
	a := NewFGAAuthorizer(fga)

	ok, err := a.CanExecute(context.Background(),
		Caller{Subject: "user:bob", Tenant: "acme"},
		mustNative(t, "nmap"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("denied check must return false")
	}
}

func TestFGAAuthorizerFailsClosed(t *testing.T) {
	t.Run("missing subject", func(t *testing.T) {
		fga := &fakeChecker{allow: true}
		a := NewFGAAuthorizer(fga)
		ok, err := a.CanExecute(context.Background(),
			Caller{Tenant: "acme"}, mustNative(t, "nmap"))
		if ok || err == nil {
			t.Fatalf("want (false, error), got (%v, %v)", ok, err)
		}
		if fga.calls != 0 {
			t.Fatal("FGA must not be consulted without a subject")
		}
	})

	t.Run("mcp without tenant mirrors native", func(t *testing.T) {
		// ADR-0067: the connector object is a tenant-less component ref, so
		// no caller tenant is required — exactly like the native path. The
		// model itself fails closed: a subject without the tenant-scoped
		// grants is denied by the can_execute composition.
		fga := &fakeChecker{allow: false}
		a := NewFGAAuthorizer(fga)
		ok, err := a.CanExecute(context.Background(),
			Caller{Subject: "user:alice"}, mustMCP(t, "gitlab", "create_issue"))
		if ok || err != nil {
			t.Fatalf("want (false, nil) from the model, got (%v, %v)", ok, err)
		}
		if fga.calls != 1 {
			t.Fatal("the FGA check must run — denial comes from the model, not a local guard")
		}
	})

	t.Run("unknown source", func(t *testing.T) {
		fga := &fakeChecker{allow: true}
		a := NewFGAAuthorizer(fga)
		ok, err := a.CanExecute(context.Background(),
			Caller{Subject: "user:alice", Tenant: "acme"},
			toolid.ID{Source: toolid.Source("rogue"), Tool: "x"})
		if ok || err == nil {
			t.Fatalf("want (false, error), got (%v, %v)", ok, err)
		}
		if fga.calls != 0 {
			t.Fatal("FGA must not be consulted for an unknown source")
		}
	})

	t.Run("fga error propagates", func(t *testing.T) {
		fga := &fakeChecker{err: errors.New("fga down")}
		a := NewFGAAuthorizer(fga)
		ok, err := a.CanExecute(context.Background(),
			Caller{Subject: "user:alice", Tenant: "acme"}, mustNative(t, "nmap"))
		if ok || err == nil {
			t.Fatalf("want (false, error), got (%v, %v)", ok, err)
		}
	})
}

func TestNewFGAAuthorizerPanicsOnNil(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on nil checker")
		}
	}()
	NewFGAAuthorizer(nil)
}

// An FGA infrastructure failure on the mcp path propagates wrapped — never a
// silent allow or deny.
func TestFGAAuthorizerMCPCheckErrorPropagates(t *testing.T) {
	fga := &fakeChecker{err: context.DeadlineExceeded}
	a := NewFGAAuthorizer(fga)

	ok, err := a.CanExecute(context.Background(),
		Caller{Subject: "user:alice", Tenant: "acme"},
		mustMCP(t, "gitlab", "create_issue"))
	if ok || err == nil {
		t.Fatalf("want (false, error), got (%v, %v)", ok, err)
	}
}

// tupleChecker answers a Check from a set of tuples. A userset subject is a
// member of nothing, as in the FGA model: it passes only a tuple that names it,
// and it never passes can_execute. This is the behavior that run 45352739081 saw
// on a live OpenFGA.
type tupleChecker struct {
	tuples map[string]bool
	err    error
	seen   []string
}

func (c *tupleChecker) Check(_ context.Context, user, relation, object string) (bool, error) {
	key := user + "|" + relation + "|" + object
	c.seen = append(c.seen, key)
	if c.err != nil {
		return false, c.err
	}
	return c.tuples[key], nil
}

// The daemon calls a connector for a tenant as the member set of the tenant. The
// call is allowed when the tenant enabled the connector and its execute kill
// switch is off. The check never asks can_execute of the userset, which is false
// for every component.
func TestFGAAuthorizerTenantSetCaller(t *testing.T) {
	enabled := "tenant:acme|tenant_enabled|component:connector/github"
	disabled := "tenant:acme|tenant_execute_disabled|component:connector/github"
	cases := []struct {
		name   string
		tuples map[string]bool
		caller Caller
		want   bool
	}{
		{"enabled", map[string]bool{enabled: true}, Caller{Subject: "tenant:acme#member", Tenant: "acme"}, true},
		{"not enabled", map[string]bool{}, Caller{Subject: "tenant:acme#member", Tenant: "acme"}, false},
		{"kill switch on", map[string]bool{enabled: true, disabled: true}, Caller{Subject: "tenant:acme#member", Tenant: "acme"}, false},
		// Another tenant enabled the connector. The call of acme gets nothing from it.
		{"only another tenant enabled it", map[string]bool{"tenant:beta|tenant_enabled|component:connector/github": true},
			Caller{Subject: "tenant:acme#member", Tenant: "acme"}, false},
		// The subject names another tenant than the call. It takes the plain
		// userset check, which is false.
		{"subject of another tenant", map[string]bool{enabled: true, "tenant:beta|tenant_enabled|component:connector/github": true},
			Caller{Subject: "tenant:beta#member", Tenant: "acme"}, false},
		{"tenant with a separator", map[string]bool{"tenant:a#b|tenant_enabled|component:connector/github": true},
			Caller{Subject: "tenant:a#b#member", Tenant: "a#b"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fga := &tupleChecker{tuples: tc.tuples}
			ok, err := NewFGAAuthorizer(fga).CanExecute(context.Background(), tc.caller, mustMCP(t, "github", "list"))
			if err != nil || ok != tc.want {
				t.Fatalf("CanExecute = (%v, %v), want (%v, nil)", ok, err, tc.want)
			}
		})
	}
}

// An error of the tenant check is no answer. The call fails closed with the error.
func TestFGAAuthorizerTenantSetCallerFailsClosed(t *testing.T) {
	boom := errors.New("fga down")
	fga := &tupleChecker{err: boom}
	ok, err := NewFGAAuthorizer(fga).CanExecute(context.Background(),
		Caller{Subject: "tenant:acme#member", Tenant: "acme"}, mustNative(t, "nmap"))
	if ok || !errors.Is(err, boom) {
		t.Fatalf("CanExecute = (%v, %v), want (false, fga down)", ok, err)
	}

	// The kill switch read fails after the tenant enabled the tool.
	fga = &tupleChecker{tuples: map[string]bool{"tenant:acme|tenant_enabled|component:tool/nmap": true}}
	second := &failSecond{tupleChecker: fga, err: boom}
	ok, err = NewFGAAuthorizer(second).CanExecute(context.Background(),
		Caller{Subject: "tenant:acme#member", Tenant: "acme"}, mustNative(t, "nmap"))
	if ok || !errors.Is(err, boom) {
		t.Fatalf("CanExecute = (%v, %v), want (false, fga down)", ok, err)
	}
}

// failSecond fails the check of tenant_execute_disabled.
type failSecond struct {
	*tupleChecker
	err error
}

func (f *failSecond) Check(ctx context.Context, user, relation, object string) (bool, error) {
	if relation == "tenant_execute_disabled" {
		return false, f.err
	}
	return f.tupleChecker.Check(ctx, user, relation, object)
}
