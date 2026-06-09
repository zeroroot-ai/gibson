package catalog_test

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/catalog"
	"github.com/zeroroot-ai/gibson/internal/toolid"
)

type fakeChecker struct {
	user, relation, object string
	called                 bool
	result                 bool
	err                    error
}

func (f *fakeChecker) Check(_ context.Context, user, relation, object string) (bool, error) {
	f.called = true
	f.user, f.relation, f.object = user, relation, object
	return f.result, f.err
}

// An MCP connector tool maps to can_invoke on the tenant-qualified plugin object
// — the exact gate PluginInvoke uses (gibson#694).
func TestFGAAuthorizer_MCPMapsToPluginCanInvoke(t *testing.T) {
	fc := &fakeChecker{result: true}
	a := catalog.NewFGAAuthorizer(fc)
	id := toolid.ID{Source: toolid.SourceMCP, Connector: "gitlab", Tool: "create_issue"}

	ok, err := a.CanExecute(context.Background(),
		catalog.Caller{Subject: "agent_principal:a1", Tenant: "acme"}, id)
	if err != nil {
		t.Fatalf("CanExecute error: %v", err)
	}
	if !ok {
		t.Fatalf("expected allow")
	}
	if fc.user != "agent_principal:a1" || fc.relation != "can_invoke" || fc.object != "plugin:acme:gitlab" {
		t.Fatalf("checked (%q,%q,%q), want (agent_principal:a1, can_invoke, plugin:acme:gitlab)",
			fc.user, fc.relation, fc.object)
	}
}

func TestFGAAuthorizer_MCPDeniedPropagates(t *testing.T) {
	fc := &fakeChecker{result: false}
	ok, err := catalog.NewFGAAuthorizer(fc).CanExecute(context.Background(),
		catalog.Caller{Subject: "user:bob", Tenant: "acme"},
		toolid.ID{Source: toolid.SourceMCP, Connector: "gitlab", Tool: "x"})
	if err != nil || ok {
		t.Fatalf("got (ok=%v, err=%v), want (false, nil)", ok, err)
	}
}

// Native tools are deferred until the component object space is reconciled
// (gibson#700): fail closed, and do not even call the checker.
func TestFGAAuthorizer_NativeDeferredDenied(t *testing.T) {
	fc := &fakeChecker{result: true}
	ok, err := catalog.NewFGAAuthorizer(fc).CanExecute(context.Background(),
		catalog.Caller{Subject: "user:bob", Tenant: "acme"},
		toolid.ID{Source: toolid.SourceNative, Tool: "nmap"})
	if err != nil || ok {
		t.Fatalf("native got (ok=%v, err=%v), want (false, nil)", ok, err)
	}
	if fc.called {
		t.Fatalf("checker should not be called for a deferred native id")
	}
}

func TestFGAAuthorizer_FailsClosedOnMissingIdentity(t *testing.T) {
	for _, c := range []catalog.Caller{
		{Subject: "", Tenant: "acme"},
		{Subject: "user:bob", Tenant: ""},
	} {
		fc := &fakeChecker{result: true}
		ok, err := catalog.NewFGAAuthorizer(fc).CanExecute(context.Background(), c,
			toolid.ID{Source: toolid.SourceMCP, Connector: "gitlab", Tool: "x"})
		if err != nil || ok {
			t.Fatalf("caller %+v got (ok=%v, err=%v), want (false, nil)", c, ok, err)
		}
		if fc.called {
			t.Fatalf("checker must not run with incomplete identity %+v", c)
		}
	}
}

func TestFGAAuthorizer_CheckerErrorPropagates(t *testing.T) {
	boom := errors.New("fga down")
	_, err := catalog.NewFGAAuthorizer(&fakeChecker{err: boom}).CanExecute(context.Background(),
		catalog.Caller{Subject: "user:bob", Tenant: "acme"},
		toolid.ID{Source: toolid.SourceMCP, Connector: "gitlab", Tool: "x"})
	if !errors.Is(err, boom) {
		t.Fatalf("checker error not propagated: %v", err)
	}
}

// The adapter satisfies the Authorizer interface the engine depends on.
func TestFGAAuthorizer_SatisfiesAuthorizer(t *testing.T) {
	var _ catalog.Authorizer = catalog.NewFGAAuthorizer(&fakeChecker{})
}
