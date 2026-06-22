package component_test

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

type fakeTenantLister struct {
	comps []component.ComponentInfo
	err   error
}

func (f fakeTenantLister) ListTenantComponents(_ context.Context, _ string) ([]component.ComponentInfo, error) {
	return f.comps, f.err
}

func find(entries []catalog.ToolEntry, source toolid.Source, connector, tool string) *catalog.ToolEntry {
	for i := range entries {
		e := &entries[i]
		if e.Source == source && e.Connector == connector && e.Tool == tool {
			return e
		}
	}
	return nil
}

// A plugin expands to one mcp entry per method (carrying the description); a tool
// to one native entry; an agent is skipped.
func TestCatalogToolLister_Expands(t *testing.T) {
	reg := fakeTenantLister{comps: []component.ComponentInfo{
		{
			Kind: "plugin", Name: "gitlab",
			Methods: []component.MethodInfo{
				{Name: "create_issue", Description: "open a GitLab issue", InputSchemaJSON: `{"type":"object"}`},
				{Name: "list_issues", Description: "list GitLab issues"},
			},
		},
		{Kind: "tool", Name: "nmap", Description: "network scanner", InputSchemaJSON: []byte(`{"x":1}`)},
		{Kind: "agent", Name: "recon-agent"},
	}}

	got, err := component.NewCatalogToolLister(reg).ListTools(context.Background(), "acme")
	if err != nil {
		t.Fatalf("ListTools error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3 (2 plugin methods + 1 native, agent skipped): %+v", len(got), got)
	}

	mr := find(got, toolid.SourceMCP, "gitlab", "create_issue")
	if mr == nil {
		t.Fatalf("missing mcp:gitlab:create_issue")
	}
	if mr.Description != "open a GitLab issue" {
		t.Fatalf("description not carried: %q", mr.Description)
	}
	if string(mr.InputSchema) != `{"type":"object"}` {
		t.Fatalf("input schema not carried: %q", string(mr.InputSchema))
	}

	if find(got, toolid.SourceMCP, "gitlab", "list_issues") == nil {
		t.Fatalf("missing mcp:gitlab:list_issues")
	}

	nat := find(got, toolid.SourceNative, "", "nmap")
	if nat == nil || nat.Description != "network scanner" {
		t.Fatalf("native nmap entry wrong: %+v", nat)
	}

	if find(got, toolid.SourceMCP, "recon-agent", "") != nil {
		t.Fatalf("agent component should be skipped")
	}
}

func TestCatalogToolLister_PluginWithNoMethodsYieldsNothing(t *testing.T) {
	reg := fakeTenantLister{comps: []component.ComponentInfo{{Kind: "plugin", Name: "empty"}}}
	got, err := component.NewCatalogToolLister(reg).ListTools(context.Background(), "acme")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("plugin with no method descriptors should yield 0 entries, got %d", len(got))
	}
}

func TestCatalogToolLister_PropagatesError(t *testing.T) {
	boom := errors.New("redis down")
	_, err := component.NewCatalogToolLister(fakeTenantLister{err: boom}).ListTools(context.Background(), "acme")
	if !errors.Is(err, boom) {
		t.Fatalf("registry error not propagated: %v", err)
	}
}

// Satisfies the catalog.ToolLister interface the engine depends on.
func TestCatalogToolLister_SatisfiesInterface(t *testing.T) {
	var _ catalog.ToolLister = component.NewCatalogToolLister(fakeTenantLister{})
}
