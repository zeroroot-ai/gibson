// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
)

// ConnectorClient is what the meta-tools need from the one MCP client of the
// daemon: the tools of the connectors of a tenant, and a call of one tool.
// component.ConnectorMCP satisfies it.
type ConnectorClient interface {
	ListConnectorTools(ctx context.Context, tenant string) ([]catalog.ToolEntry, error)
	CallConnectorTool(ctx context.Context, tenant, connector, tool string, args map[string]any) (any, error)
}

// WithConnectors wires the one MCP client of the daemon into the meta-tools
// (ADR-0065, D22).
func WithConnectors(c ConnectorClient) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.connectors = c
	}
}
