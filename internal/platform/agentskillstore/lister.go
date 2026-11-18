// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package agentskillstore

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
)

// ToolLister lists the current Agent Skills of a tenant as catalog entries. It
// is the third source of the catalog, next to the tools. It reads the tenant
// database. The catalog applies the FGA check to each entry.
type ToolLister struct{ Store Store }

var _ catalog.ToolLister = ToolLister{}

// ListTools implements catalog.ToolLister.
func (l ToolLister) ListTools(ctx context.Context, tenant string) ([]catalog.ToolEntry, error) {
	entries, err := l.Store.List(ctx, tenant, "", false)
	if err != nil {
		return nil, fmt.Errorf("agentskillstore: list Agent Skills: %w", err)
	}
	out := make([]catalog.ToolEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, catalog.ToolEntry{Source: toolid.SourceSkill, Tool: e.Name, Description: e.Description})
	}
	return out, nil
}
