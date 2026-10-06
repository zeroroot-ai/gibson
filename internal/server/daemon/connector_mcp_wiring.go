// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"

	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

// connectorMCP returns the one MCP client of the daemon (ADR-0065, D22),
// built on first use. search_tools and ListTools list connector tools
// through it, and invoke_tool calls a connector tool through it.
func (d *daemonImpl) connectorMCPClient() *component.ConnectorMCP {
	d.connectorMCPOnce.Do(func() {
		d.connectorMCP = component.NewConnectorMCP(
			component.ConnectorHTTPClient(d.connectorProxyToken),
			d.logger.WithComponent("connector-mcp").Slog(),
		)
	})
	return d.connectorMCP
}

// connectorProxyToken returns a JWT-SVID of the daemon for the ToolHive proxy
// of a connector. It reads the JWT source per request, because Start builds
// the source after the callback options exist. With no source the request
// carries no token, and a proxy that requires one refuses it.
func (d *daemonImpl) connectorProxyToken(ctx context.Context) (string, error) {
	src := d.spiffeJWTSource
	if src == nil {
		return "", nil
	}
	svid, err := src.FetchJWTSVID(ctx, jwtsvid.Params{Audience: component.ConnectorProxyAudience})
	if err != nil {
		return "", fmt.Errorf("fetch the JWT-SVID for the connector proxy: %w", err)
	}
	return svid.Marshal(), nil
}
