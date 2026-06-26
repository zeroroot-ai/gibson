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

func TestFGAAuthorizerMCPMapsToPluginCanInvoke(t *testing.T) {
	fga := &fakeChecker{allow: true}
	a := NewFGAAuthorizer(fga)

	ok, err := a.CanExecute(context.Background(),
		Caller{Subject: "user:alice", Tenant: "acme"},
		mustMCP(t, "gitlab", "create_issue"))
	if err != nil || !ok {
		t.Fatalf("CanExecute = (%v, %v), want (true, nil)", ok, err)
	}
	// The exact triple is the contract: the same check that gates the
	// PluginInvoke dispatch, on the tenant-qualified plugin object.
	if fga.user != "user:alice" || fga.relation != "can_invoke" || fga.object != "plugin:acme/gitlab" {
		t.Fatalf("Check(%q, %q, %q), want (user:alice, can_invoke, plugin:acme/gitlab)",
			fga.user, fga.relation, fga.object)
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
	if fga.user != "agent_principal:agent-1" || fga.relation != "can_execute" || fga.object != "component:nmap" {
		t.Fatalf("Check(%q, %q, %q), want (agent_principal:agent-1, can_execute, component:nmap)",
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

	t.Run("mcp without tenant", func(t *testing.T) {
		fga := &fakeChecker{allow: true}
		a := NewFGAAuthorizer(fga)
		ok, err := a.CanExecute(context.Background(),
			Caller{Subject: "user:alice"}, mustMCP(t, "gitlab", "create_issue"))
		if ok || err == nil {
			t.Fatalf("want (false, error), got (%v, %v)", ok, err)
		}
		if fga.calls != 0 {
			t.Fatal("FGA must not be consulted for an mcp tool without a tenant")
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
