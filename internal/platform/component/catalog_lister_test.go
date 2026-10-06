// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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

type fakeConnectorTools struct {
	tools []catalog.ToolEntry
	err   error
}

func (f fakeConnectorTools) ListConnectorTools(context.Context, string) ([]catalog.ToolEntry, error) {
	return f.tools, f.err
}

// A tool expands to one native entry, each connector tool to one mcp entry,
// and an agent and a plugin to nothing. A plugin has no MCP (ADR-0065), so a
// plugin method is not an mcp: entry, also when a connector has its name.
func TestCatalogToolLister_Expands(t *testing.T) {
	reg := fakeTenantLister{comps: []component.ComponentInfo{
		{
			Kind: "plugin", Name: "gitlab",
			Methods: []component.MethodInfo{{Name: "list_issues", Description: "a plugin method"}},
		},
		{Kind: "tool", Name: "nmap", Description: "network scanner", InputSchemaJSON: []byte(`{"x":1}`)},
		{Kind: "agent", Name: "recon-agent"},
	}}
	connectors := fakeConnectorTools{tools: []catalog.ToolEntry{
		{Source: toolid.SourceMCP, Connector: "gitlab", Tool: "create_issue", Description: "open a GitLab issue", InputSchema: []byte(`{"type":"object"}`)},
	}}

	got, err := component.NewCatalogToolLister(reg, connectors).ListTools(context.Background(), "acme")
	if err != nil {
		t.Fatalf("ListTools error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2 (1 native + 1 connector tool): %+v", len(got), got)
	}
	if mr := find(got, toolid.SourceMCP, "gitlab", "create_issue"); mr == nil || mr.Description != "open a GitLab issue" {
		t.Fatalf("connector tool entry wrong: %+v", mr)
	}
	if find(got, toolid.SourceMCP, "gitlab", "list_issues") != nil {
		t.Fatal("a plugin method must not be an mcp: entry")
	}
	if nat := find(got, toolid.SourceNative, "", "nmap"); nat == nil || nat.Description != "network scanner" {
		t.Fatalf("native nmap entry wrong: %+v", nat)
	}
}

// With no connector source, the lister lists the native tools only.
func TestCatalogToolLister_NoConnectorSource(t *testing.T) {
	reg := fakeTenantLister{comps: []component.ComponentInfo{{Kind: "tool", Name: "nmap"}}}
	got, err := component.NewCatalogToolLister(reg, nil).ListTools(context.Background(), "acme")
	if err != nil || len(got) != 1 {
		t.Fatalf("got %+v, %v; want the one native entry", got, err)
	}
}

// An error of the connector source reaches the caller.
func TestCatalogToolLister_PropagatesConnectorError(t *testing.T) {
	boom := errors.New("mcp down")
	_, err := component.NewCatalogToolLister(fakeTenantLister{}, fakeConnectorTools{err: boom}).ListTools(context.Background(), "acme")
	if !errors.Is(err, boom) {
		t.Fatalf("connector error not propagated: %v", err)
	}
}

func TestCatalogToolLister_PropagatesError(t *testing.T) {
	boom := errors.New("redis down")
	_, err := component.NewCatalogToolLister(fakeTenantLister{err: boom}, nil).ListTools(context.Background(), "acme")
	if !errors.Is(err, boom) {
		t.Fatalf("registry error not propagated: %v", err)
	}
}

// Satisfies the catalog.ToolLister interface the engine depends on.
func TestCatalogToolLister_SatisfiesInterface(t *testing.T) {
	var _ catalog.ToolLister = component.NewCatalogToolLister(fakeTenantLister{}, nil)
}
