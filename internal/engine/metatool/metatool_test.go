// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package metatool

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
)

type fakeQuerier struct {
	gotName, gotMethod string
	gotParams          map[string]any
	ret                any
	err                error
}

func (f *fakeQuerier) QueryPlugin(_ context.Context, name, method string, params map[string]any) (any, error) {
	f.gotName, f.gotMethod, f.gotParams = name, method, params
	return f.ret, f.err
}

// fakeAuthz allows ids whose canonical form is in allow.
type fakeAuthz struct {
	allow map[string]bool
	err   error
}

func (f fakeAuthz) CanExecute(_ context.Context, _ catalog.Caller, id toolid.ID) (bool, error) {
	return f.allow[id.Canonical()], f.err
}

type fakeSearcher struct {
	gotCaller catalog.Caller
	gotQuery  catalog.Query
	ret       []catalog.Candidate
	err       error
}

func (f *fakeSearcher) Search(_ context.Context, caller catalog.Caller, q catalog.Query) ([]catalog.Candidate, error) {
	f.gotCaller, f.gotQuery = caller, q
	return f.ret, f.err
}

func allowAll(ids ...string) fakeAuthz {
	m := map[string]bool{}
	for _, id := range ids {
		m[id] = true
	}
	return fakeAuthz{allow: m}
}

// invoke_tool decodes the canonical id, passes the can_invoke gate, and
// dispatches to the plugin method, forwarding the LLM args and returning result.
func TestInvoke_AuthorizedDecodesAndDispatches(t *testing.T) {
	q := &fakeQuerier{ret: map[string]any{"issue": 42}}
	h := NewHandler(nil, allowAll("mcp:gitlab:create_issue"), q, nil)

	args := map[string]any{"title": "broken pipeline"}
	got, err := h.Invoke(context.Background(), catalog.Caller{Subject: "user:alice", Tenant: "acme"}, "mcp:gitlab:create_issue", args)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if q.gotName != "gitlab" || q.gotMethod != "create_issue" {
		t.Fatalf("dispatched to %s.%s, want gitlab.create_issue", q.gotName, q.gotMethod)
	}
	if q.gotParams["title"] != "broken pipeline" {
		t.Fatalf("params not passed through: %+v", q.gotParams)
	}
	if m, ok := got.(map[string]any); !ok || m["issue"] != 42 {
		t.Fatalf("result not returned: %+v", got)
	}
}

// An id the caller is not authorized for is denied and never dispatched, even
// though the id is well-formed (the agent may pass an id it never searched).
func TestInvoke_UnauthorizedDeniedNotDispatched(t *testing.T) {
	q := &fakeQuerier{}
	h := NewHandler(nil, allowAll( /* nothing allowed */ ), q, nil)

	_, err := h.Invoke(context.Background(), catalog.Caller{}, "mcp:github:create_issue", nil)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("want ErrUnauthorized, got %v", err)
	}
	if q.gotName != "" {
		t.Fatalf("denied tool must not dispatch, got %s.%s", q.gotName, q.gotMethod)
	}
}

func TestInvoke_AuthzErrorSurfacesNotDispatched(t *testing.T) {
	q := &fakeQuerier{}
	boom := errors.New("fga down")
	h := NewHandler(nil, fakeAuthz{err: boom}, q, nil)
	if _, err := h.Invoke(context.Background(), catalog.Caller{}, "mcp:gitlab:create_issue", nil); !errors.Is(err, boom) {
		t.Fatalf("want authz error surfaced, got %v", err)
	}
	if q.gotName != "" {
		t.Fatal("must not dispatch when authz check errors")
	}
}

// The flattened native-function form decodes to the same target and is gated the
// same way.
func TestInvoke_ToleratesFlattenedForm(t *testing.T) {
	q := &fakeQuerier{}
	h := NewHandler(nil, allowAll("mcp:gitlab:create_issue"), q, nil)
	if _, err := h.Invoke(context.Background(), catalog.Caller{}, "mcp__gitlab__create_issue", nil); err != nil {
		t.Fatalf("Invoke flattened: %v", err)
	}
	if q.gotName != "gitlab" || q.gotMethod != "create_issue" {
		t.Fatalf("flattened dispatched to %s.%s, want gitlab.create_issue", q.gotName, q.gotMethod)
	}
}

type fakeNative struct {
	gotTool string
	gotArgs map[string]any
	ret     any
	err     error
}

func (f *fakeNative) CallNativeTool(_ context.Context, tool string, args map[string]any) (any, error) {
	f.gotTool, f.gotArgs = tool, args
	return f.ret, f.err
}

// A native:<tool> id passes the can_execute gate and goes to the native tool
// dispatch, never to the plugin path.
func TestInvoke_NativeToolDispatches(t *testing.T) {
	q := &fakeQuerier{}
	n := &fakeNative{ret: map[string]any{"open_ports": 3}}
	h := NewHandler(nil, allowAll("native:nmap"), q, n)

	got, err := h.Invoke(context.Background(), catalog.Caller{Subject: "user:alice", Tenant: "acme"}, "native:nmap", map[string]any{"target": "10.0.0.1"})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if n.gotTool != "nmap" || n.gotArgs["target"] != "10.0.0.1" {
		t.Fatalf("native dispatch got tool=%q args=%+v, want nmap with the args", n.gotTool, n.gotArgs)
	}
	if m, ok := got.(map[string]any); !ok || m["open_ports"] != 3 {
		t.Fatalf("result not returned: %+v", got)
	}
	if q.gotName != "" {
		t.Fatalf("querier should not be called for native tool, got %s.%s", q.gotName, q.gotMethod)
	}
}

// A native tool that the tenant did not enable is refused and never
// dispatched.
func TestInvoke_NativeToolNotEnabledIsRefused(t *testing.T) {
	n := &fakeNative{}
	h := NewHandler(nil, allowAll( /* nothing allowed */ ), &fakeQuerier{}, n)

	_, err := h.Invoke(context.Background(), catalog.Caller{Subject: "user:alice", Tenant: "acme"}, "native:nmap", nil)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	if n.gotTool != "" {
		t.Fatalf("a refused native tool was dispatched: %q", n.gotTool)
	}
}

// With no native dispatch wired, a native id fails closed.
func TestInvoke_NativeToolWithNoDispatchFailsClosed(t *testing.T) {
	h := NewHandler(nil, allowAll("native:nmap"), &fakeQuerier{}, nil)
	if _, err := h.Invoke(context.Background(), catalog.Caller{}, "native:nmap", nil); err == nil {
		t.Fatal("want a configuration error, got nil")
	}
}

func TestInvoke_RejectsMalformedId(t *testing.T) {
	h := NewHandler(nil, allowAll(), &fakeQuerier{}, nil)
	if _, err := h.Invoke(context.Background(), catalog.Caller{}, "not-a-real-id", nil); err == nil {
		t.Fatal("want error for malformed id, got nil")
	}
}

func TestInvoke_PropagatesQuerierError(t *testing.T) {
	wantErr := errors.New("plugin boom")
	h := NewHandler(nil, allowAll("mcp:gitlab:create_issue"), &fakeQuerier{err: wantErr}, nil)
	if _, err := h.Invoke(context.Background(), catalog.Caller{}, "mcp:gitlab:create_issue", nil); !errors.Is(err, wantErr) {
		t.Fatalf("want querier error propagated, got %v", err)
	}
}

func TestInvoke_NilConfigFailsClosed(t *testing.T) {
	h := NewHandler(&fakeSearcher{}, nil, nil, nil)
	if _, err := h.Invoke(context.Background(), catalog.Caller{}, "mcp:gitlab:create_issue", nil); err == nil {
		t.Fatal("want configuration error with nil querier/authz, got nil")
	}
}

// search_tools delegates to the catalog engine, forwarding caller and query.
func TestSearch_DelegatesToCatalog(t *testing.T) {
	s := &fakeSearcher{ret: []catalog.Candidate{{ID: "mcp:gitlab:create_issue"}}}
	h := NewHandler(s, allowAll(), nil, nil)

	caller := catalog.Caller{Subject: "user:alice", Tenant: "acme"}
	got, err := h.Search(context.Background(), caller, catalog.Query{Text: "open an issue", Limit: 5})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if s.gotCaller != caller || s.gotQuery.Text != "open an issue" || s.gotQuery.Limit != 5 {
		t.Fatalf("caller/query not forwarded: caller=%+v query=%+v", s.gotCaller, s.gotQuery)
	}
	if len(got) != 1 || got[0].ID != "mcp:gitlab:create_issue" {
		t.Fatalf("candidates not returned: %+v", got)
	}
}

func TestSearch_NilSearcherFailsClosed(t *testing.T) {
	h := NewHandler(nil, allowAll(), &fakeQuerier{}, nil)
	if _, err := h.Search(context.Background(), catalog.Caller{}, catalog.Query{}); err == nil {
		t.Fatal("want configuration error with nil searcher, got nil")
	}
}
