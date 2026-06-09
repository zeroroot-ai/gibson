package metatool

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/catalog"
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

// invoke_tool decodes the canonical id and dispatches to the plugin method,
// passing the LLM-supplied args through untouched and returning the result.
func TestInvoke_DecodesCanonicalMCPIdAndDispatches(t *testing.T) {
	q := &fakeQuerier{ret: map[string]any{"issue": 42}}
	h := NewHandler(nil, q)

	args := map[string]any{"title": "broken pipeline"}
	got, err := h.Invoke(context.Background(), "mcp:gitlab:create_issue", args)
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

// The flattened native-function form an agent may have been bound to decodes to
// the same dispatch target.
func TestInvoke_ToleratesFlattenedForm(t *testing.T) {
	q := &fakeQuerier{}
	h := NewHandler(nil, q)

	if _, err := h.Invoke(context.Background(), "mcp__gitlab__create_issue", nil); err != nil {
		t.Fatalf("Invoke flattened: %v", err)
	}
	if q.gotName != "gitlab" || q.gotMethod != "create_issue" {
		t.Fatalf("flattened dispatched to %s.%s, want gitlab.create_issue", q.gotName, q.gotMethod)
	}
}

// native:<tool> primitives are not PluginInvoke targets — invoke_tool declines
// them rather than guessing a route, and never touches the querier.
func TestInvoke_NativeToolDeclined(t *testing.T) {
	q := &fakeQuerier{}
	h := NewHandler(nil, q)

	if _, err := h.Invoke(context.Background(), "native:nmap", nil); err == nil {
		t.Fatal("want error for native tool, got nil")
	}
	if q.gotName != "" {
		t.Fatalf("querier should not be called for native tool, got %s.%s", q.gotName, q.gotMethod)
	}
}

func TestInvoke_RejectsMalformedId(t *testing.T) {
	h := NewHandler(nil, &fakeQuerier{})
	if _, err := h.Invoke(context.Background(), "not-a-real-id", nil); err == nil {
		t.Fatal("want error for malformed id, got nil")
	}
}

// A downstream dispatch error surfaces to the caller unchanged.
func TestInvoke_PropagatesQuerierError(t *testing.T) {
	wantErr := errors.New("plugin boom")
	h := NewHandler(nil, &fakeQuerier{err: wantErr})
	if _, err := h.Invoke(context.Background(), "mcp:gitlab:create_issue", nil); !errors.Is(err, wantErr) {
		t.Fatalf("want querier error propagated, got %v", err)
	}
}

func TestInvoke_NilQuerierFailsClosed(t *testing.T) {
	h := NewHandler(&fakeSearcher{}, nil)
	if _, err := h.Invoke(context.Background(), "mcp:gitlab:create_issue", nil); err == nil {
		t.Fatal("want configuration error with nil querier, got nil")
	}
}

// search_tools delegates to the catalog engine, forwarding caller and query.
func TestSearch_DelegatesToCatalog(t *testing.T) {
	s := &fakeSearcher{ret: []catalog.Candidate{{ID: "mcp:gitlab:create_issue"}}}
	h := NewHandler(s, nil)

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
	h := NewHandler(nil, &fakeQuerier{})
	if _, err := h.Search(context.Background(), catalog.Caller{}, catalog.Query{}); err == nil {
		t.Fatal("want configuration error with nil searcher, got nil")
	}
}
