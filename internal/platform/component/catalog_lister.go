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

// CatalogToolLister adapts the component registry to catalog.ToolLister: it
// enumerates a tenant's live components and expands them into the per-tool
// entries the SearchTools engine ranks and authz-filters.
//
//	kind == "tool"   → one native:<name> entry
//	kind == "plugin" → one mcp:<name>:<method> entry per method descriptor,
//	                   carrying the method description (so an agent can
//	                   disambiguate) and input schema
//	kind == "agent"  → skipped (agents are not tools)
//
// A plugin registered by an SDK that predates method_descriptors has no
// per-method metadata and therefore contributes no entries until re-registered.
type CatalogToolLister struct {
	reg tenantComponentLister
}

// NewCatalogToolLister constructs a CatalogToolLister over a component lister.
func NewCatalogToolLister(reg tenantComponentLister) *CatalogToolLister {
	return &CatalogToolLister{reg: reg}
}

// Compile-time assertion that CatalogToolLister satisfies catalog.ToolLister.
var _ catalog.ToolLister = (*CatalogToolLister)(nil)

// ListTools enumerates and expands the tenant's live components into tool entries.
func (l *CatalogToolLister) ListTools(ctx context.Context, tenant string) ([]catalog.ToolEntry, error) {
	comps, err := l.reg.ListTenantComponents(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("catalog tool lister: list components for tenant %q: %w", tenant, err)
	}
	var out []catalog.ToolEntry
	for _, c := range comps {
		switch c.Kind {
		case "tool":
			out = append(out, catalog.ToolEntry{
				Source:      toolid.SourceNative,
				Tool:        c.Name,
				Description: c.Description,
				InputSchema: c.InputSchemaJSON,
			})
		case "plugin":
			for _, m := range c.Methods {
				out = append(out, catalog.ToolEntry{
					Source:      toolid.SourceMCP,
					Connector:   c.Name,
					Tool:        m.Name,
					Description: m.Description,
					InputSchema: []byte(m.InputSchemaJSON),
				})
			}
		}
	}
	return out, nil
}
