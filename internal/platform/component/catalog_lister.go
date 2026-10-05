// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
)

// tenantComponentLister is the narrow registry surface CatalogToolLister needs.
// Satisfied by ComponentRegistry (and faked in tests).
type tenantComponentLister interface {
	ListTenantComponents(ctx context.Context, tenant string) ([]ComponentInfo, error)
}

// ConnectorToolSource lists the tools of the connectors of a tenant as
// mcp:<connector>:<tool> entries. ConnectorMCP satisfies it.
type ConnectorToolSource interface {
	ListConnectorTools(ctx context.Context, tenant string) ([]catalog.ToolEntry, error)
}

// CatalogToolLister builds the catalog that search_tools ranks and
// authz-filters (ADR-0065):
//
//	a live component of kind "tool" -> one native:<name> entry
//	each tool of each connector     -> one mcp:<connector>:<tool> entry
//
// An mcp: id names a connector, the MCP integration. A plugin has no MCP, so
// a plugin method is not an invoke_tool entry: an agent reaches a plugin
// through QueryPlugin.
type CatalogToolLister struct {
	reg        tenantComponentLister
	connectors ConnectorToolSource
}

// NewCatalogToolLister constructs a CatalogToolLister. A nil connector source
// lists no connector tools.
func NewCatalogToolLister(reg tenantComponentLister, connectors ConnectorToolSource) *CatalogToolLister {
	return &CatalogToolLister{reg: reg, connectors: connectors}
}

// Compile-time assertion that CatalogToolLister satisfies catalog.ToolLister.
var _ catalog.ToolLister = (*CatalogToolLister)(nil)

// ListTools enumerates the tenant's native tools and connector tools.
func (l *CatalogToolLister) ListTools(ctx context.Context, tenant string) ([]catalog.ToolEntry, error) {
	comps, err := l.reg.ListTenantComponents(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("catalog tool lister: list components for tenant %q: %w", tenant, err)
	}
	var out []catalog.ToolEntry
	for _, c := range comps {
		if c.Kind != "tool" {
			continue
		}
		out = append(out, catalog.ToolEntry{
			Source:      toolid.SourceNative,
			Tool:        c.Name,
			Description: c.Description,
			InputSchema: c.InputSchemaJSON,
		})
	}
	if l.connectors != nil {
		tools, cerr := l.connectors.ListConnectorTools(ctx, tenant)
		if cerr != nil {
			return nil, fmt.Errorf("catalog tool lister: list connector tools for tenant %q: %w", tenant, cerr)
		}
		out = append(out, tools...)
	}
	return out, nil
}
