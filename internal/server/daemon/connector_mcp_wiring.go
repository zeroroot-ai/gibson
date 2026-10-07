// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"
	"math"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"

	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/gibson/internal/platform/tenantconnector"
	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
)

// connectorMCP returns the one MCP client of the daemon (ADR-0065, D22),
// built on first use. search_tools and ListTools list connector tools
// through it, and invoke_tool calls a connector tool through it.
func (d *daemonImpl) connectorMCPClient() *component.ConnectorMCP {
	d.connectorMCPOnce.Do(func() {
		d.connectorMCP = component.NewConnectorMCP(
			component.ConnectorHTTPClient(d.connectorProxyToken),
			d.logger.WithComponent("connector-mcp").Slog(),
		).WithToolCountRecorder(d.recordConnectorTools)
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
	svid, err := src.FetchJWTSVID(ctx, jwtsvid.Params{Audience: connectorv1alpha1.ProxyAudience})
	if err != nil {
		return "", fmt.Errorf("fetch the JWT-SVID for the connector proxy: %w", err)
	}
	return svid.Marshal(), nil
}

// recordConnectorTools stores the tool count of one connector of a tenant,
// which ListConnectors serves. A failed write is logged: the tool list of the
// call is still correct without it.
func (d *daemonImpl) recordConnectorTools(ctx context.Context, tenant, connector string, n int) {
	if d.platformDB == nil {
		return
	}
	count := int32(min(n, math.MaxInt32)) //nolint:gosec // bounded by the min above
	if err := tenantconnector.NewStore(d.platformDB).SetDiscoveredTools(ctx, tenant, connector, count); err != nil {
		d.logger.WithComponent("connector-mcp").Slog().WarnContext(ctx, "record the tool count of a connector",
			"tenant", tenant, "connector", connector, "error", err.Error())
	}
}
