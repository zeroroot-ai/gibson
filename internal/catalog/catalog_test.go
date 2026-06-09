package catalog_test

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/catalog"
	"github.com/zeroroot-ai/gibson/internal/toolid"
)

// fakeLister returns a fixed tool set regardless of tenant.
type fakeLister struct {
	entries []catalog.ToolEntry
	err     error
}

func (f fakeLister) ListTools(_ context.Context, _ string) ([]catalog.ToolEntry, error) {
	return f.entries, f.err
}

// fakeAuthz denies any tool whose connector is in deniedConnectors.
type fakeAuthz struct {
	deniedConnectors map[string]bool
	err              error
}

func (f fakeAuthz) CanExecute(_ context.Context, _ catalog.Caller, id toolid.ID) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return !f.deniedConnectors[id.Connector], nil
}

func sampleEntries() []catalog.ToolEntry {
	return []catalog.ToolEntry{
		{Source: toolid.SourceMCP, Connector: "gitlab", Tool: "create_issue", Description: "Open a GitLab issue"},
		{Source: toolid.SourceMCP, Connector: "gitlab", Tool: "list_issues", Description: "List GitLab issues"},
		{Source: toolid.SourceMCP, Connector: "github", Tool: "create_issue", Description: "Open a GitHub issue"},
		{Source: toolid.SourceNative, Tool: "nmap", Description: "Network scanner"},
	}
}

func ids(cs []catalog.Candidate) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.ID
	}
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// The security invariant: a denied connector's tools never appear, and every
// returned candidate carries a canonical id.
func TestSearchAuthzFiltered(t *testing.T) {
	e := catalog.NewEngine(
		fakeLister{entries: sampleEntries()},
		fakeAuthz{deniedConnectors: map[string]bool{"github": true}},
	)
	got, err := e.Search(context.Background(), catalog.Caller{Tenant: "t1"}, catalog.Query{})
	if err != nil {
		t.Fatalf("Search error: %v", err)
	}
	got_ids := ids(got)
	if contains(got_ids, "mcp:github:create_issue") {
		t.Fatalf("returned a tool from the denied connector github: %v", got_ids)
	}
	for _, want := range []string{"mcp:gitlab:create_issue", "mcp:gitlab:list_issues", "native:nmap"} {
		if !contains(got_ids, want) {
			t.Fatalf("missing expected authorized tool %q in %v", want, got_ids)
		}
	}
}

func TestSearchTextFilter(t *testing.T) {
	e := catalog.NewEngine(fakeLister{entries: sampleEntries()}, fakeAuthz{})
	got, err := e.Search(context.Background(), catalog.Caller{Tenant: "t1"}, catalog.Query{Text: "issue"})
	if err != nil {
		t.Fatalf("Search error: %v", err)
	}
	for _, c := range got {
		if c.Tool != "create_issue" && c.Tool != "list_issues" {
			t.Fatalf("text filter %q returned unrelated tool %q", "issue", c.ID)
		}
	}
	if contains(ids(got), "native:nmap") {
		t.Fatalf("text filter should have excluded native:nmap")
	}
}

func TestSearchSourceFilter(t *testing.T) {
	e := catalog.NewEngine(fakeLister{entries: sampleEntries()}, fakeAuthz{})
	got, err := e.Search(context.Background(), catalog.Caller{Tenant: "t1"}, catalog.Query{Sources: []toolid.Source{toolid.SourceNative}})
	if err != nil {
		t.Fatalf("Search error: %v", err)
	}
	if len(got) != 1 || got[0].ID != "native:nmap" {
		t.Fatalf("source filter native = %v, want [native:nmap]", ids(got))
	}
}

func TestSearchConnectorFilter(t *testing.T) {
	e := catalog.NewEngine(fakeLister{entries: sampleEntries()}, fakeAuthz{})
	got, err := e.Search(context.Background(), catalog.Caller{Tenant: "t1"}, catalog.Query{Connector: "gitlab"})
	if err != nil {
		t.Fatalf("Search error: %v", err)
	}
	for _, c := range got {
		if c.Connector != "gitlab" {
			t.Fatalf("connector filter returned %q", c.ID)
		}
	}
	if len(got) != 2 {
		t.Fatalf("connector filter gitlab = %v, want 2", ids(got))
	}
}

func TestSearchLimit(t *testing.T) {
	e := catalog.NewEngine(fakeLister{entries: sampleEntries()}, fakeAuthz{})
	got, err := e.Search(context.Background(), catalog.Caller{Tenant: "t1"}, catalog.Query{Limit: 2})
	if err != nil {
		t.Fatalf("Search error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("limit 2 returned %d", len(got))
	}
}

func TestSearchPropagatesErrors(t *testing.T) {
	listErr := errors.New("list boom")
	if _, err := catalog.NewEngine(fakeLister{err: listErr}, fakeAuthz{}).
		Search(context.Background(), catalog.Caller{Tenant: "t1"}, catalog.Query{}); !errors.Is(err, listErr) {
		t.Fatalf("list error not propagated: %v", err)
	}

	authzErr := errors.New("authz boom")
	if _, err := catalog.NewEngine(fakeLister{entries: sampleEntries()}, fakeAuthz{err: authzErr}).
		Search(context.Background(), catalog.Caller{Tenant: "t1"}, catalog.Query{}); !errors.Is(err, authzErr) {
		t.Fatalf("authz error not propagated: %v", err)
	}
}

// Malformed raw entries (empty tool name) are skipped, not returned or fatal.
func TestSearchSkipsMalformed(t *testing.T) {
	e := catalog.NewEngine(
		fakeLister{entries: []catalog.ToolEntry{
			{Source: toolid.SourceMCP, Connector: "gitlab", Tool: ""},
			{Source: toolid.SourceMCP, Connector: "gitlab", Tool: "ok"},
		}},
		fakeAuthz{},
	)
	got, err := e.Search(context.Background(), catalog.Caller{Tenant: "t1"}, catalog.Query{})
	if err != nil {
		t.Fatalf("Search error: %v", err)
	}
	if len(got) != 1 || got[0].ID != "mcp:gitlab:ok" {
		t.Fatalf("malformed entry not skipped cleanly: %v", ids(got))
	}
}
