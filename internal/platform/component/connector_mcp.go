// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/pkg/version"
)

// ConnectorMCP is the one MCP client of the platform (ADR-0065, D22). It
// reaches the ToolHive proxy of a connector in the namespace of a tenant,
// lists the tools of the connector, and calls one tool. An agent gets no
// network path to a connector: only the daemon calls it, after the
// can_execute check of invoke_tool.
//
// It reads which connectors exist from the platform catalog, and it reaches
// each one at the fixed address that the connector operator serves
// (connectorv1alpha1.ProxyURL). A connector that the tenant did not enable
// has no proxy, so it lists no tools.
type ConnectorMCP struct {
	httpClient *http.Client
	logger     *slog.Logger
	timeout    time.Duration

	// connectors returns the catalog connector ids. Tests replace it.
	connectors func() []string
	// proxyURL returns the address of one connector. Tests replace it.
	proxyURL func(connector, namespace string) string
}

// connectorCallTimeout bounds one MCP exchange with a connector.
const connectorCallTimeout = 30 * time.Second

// connectorListTimeout bounds the tools/list of one connector. A connector
// that the tenant did not enable answers no DNS name, so this is short.
const connectorListTimeout = 5 * time.Second

// NewConnectorMCP constructs the client. httpClient carries the transport
// identity of the daemon. A nil client uses http.DefaultClient.
func NewConnectorMCP(httpClient *http.Client, logger *slog.Logger) *ConnectorMCP {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &ConnectorMCP{
		httpClient: httpClient,
		logger:     logger.With("component", "connector_mcp"),
		timeout:    connectorCallTimeout,
		connectors: catalogConnectorIDs,
		proxyURL:   connectorv1alpha1.ProxyURL,
	}
}

func catalogConnectorIDs() []string {
	entries := componentcatalog.ListConnectors()
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		ids = append(ids, e.ID)
	}
	return ids
}

// tenantNamespace is the namespace of the connectors of a tenant.
func tenantNamespace(tenant string) string { return "tenant-" + tenant }

// ConnectorProxyHosts returns the host of the proxy of each catalog connector
// in the namespace of tenant: the hosts that the daemon dials. The sandbox
// network scope resolves them, so that no egress rule reaches a connector
// (gibson#723).
func ConnectorProxyHosts(tenant string) []string {
	ids := catalogConnectorIDs()
	hosts := make([]string, 0, len(ids))
	for _, id := range ids {
		if u, err := url.Parse(connectorv1alpha1.ProxyURL(id, tenantNamespace(tenant))); err == nil {
			hosts = append(hosts, u.Hostname())
		}
	}
	return hosts
}

// open starts an MCP session with one connector of one tenant.
func (c *ConnectorMCP) open(ctx context.Context, tenant, connector string) (*mcp.ClientSession, error) {
	if tenant == "" {
		return nil, errors.New("connector mcp: no tenant")
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "gibson-daemon", Version: version.Version}, nil)
	transport := &mcp.StreamableClientTransport{
		Endpoint:   c.proxyURL(connector, tenantNamespace(tenant)),
		HTTPClient: c.httpClient,
		MaxRetries: -1,
	}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return nil, fmt.Errorf("connector mcp: connect to %q: %w", connector, err)
	}
	return session, nil
}

// ListConnectorTools lists the tools of each connector of the tenant as
// mcp:<connector>:<tool> catalog entries. A connector that does not answer
// lists nothing; the others still list their tools.
func (c *ConnectorMCP) ListConnectorTools(ctx context.Context, tenant string) ([]catalog.ToolEntry, error) {
	var out []catalog.ToolEntry
	for _, connector := range c.connectors() {
		tools, err := c.listOne(ctx, tenant, connector)
		if err != nil {
			c.logger.DebugContext(ctx, "connector lists no tools",
				"connector", connector, "tenant", tenant, "error", err)
			continue
		}
		out = append(out, tools...)
	}
	return out, nil
}

func (c *ConnectorMCP) listOne(ctx context.Context, tenant, connector string) ([]catalog.ToolEntry, error) {
	lctx, cancel := context.WithTimeout(ctx, connectorListTimeout)
	defer cancel()
	session, err := c.open(lctx, tenant, connector)
	if err != nil {
		return nil, err
	}
	defer func() { _ = session.Close() }()

	var out []catalog.ToolEntry
	for tool, terr := range session.Tools(lctx, nil) {
		if terr != nil {
			return nil, fmt.Errorf("connector mcp: list the tools of %q: %w", connector, terr)
		}
		if _, err := toolid.ForMCP(connector, tool.Name); err != nil {
			// A name that cannot form a canonical id is not offered.
			continue
		}
		var schema []byte
		if tool.InputSchema != nil {
			schema, _ = json.Marshal(tool.InputSchema)
		}
		out = append(out, catalog.ToolEntry{
			Source:      toolid.SourceMCP,
			Connector:   connector,
			Tool:        tool.Name,
			Description: tool.Description,
			InputSchema: schema,
		})
	}
	return out, nil
}

// ErrUnknownConnector is the answer for a connector that the platform
// catalog does not list.
var ErrUnknownConnector = errors.New("connector mcp: the platform catalog lists no such connector")

// CallConnectorTool calls one tool of one connector of the tenant. It
// returns the structured result of the tool when the tool has one, and its
// content otherwise. A tool that reports an error returns that error.
func (c *ConnectorMCP) CallConnectorTool(ctx context.Context, tenant, connector, tool string, args map[string]any) (any, error) {
	if !c.isCatalogConnector(connector) {
		return nil, fmt.Errorf("%w: %q", ErrUnknownConnector, connector)
	}
	cctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	session, err := c.open(cctx, tenant, connector)
	if err != nil {
		return nil, err
	}
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(cctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		return nil, fmt.Errorf("connector mcp: call %s on %q: %w", tool, connector, err)
	}
	if res.IsError {
		return nil, fmt.Errorf("connector mcp: %s on %q reported an error: %s", tool, connector, contentText(res.Content))
	}
	if res.StructuredContent != nil {
		return res.StructuredContent, nil
	}
	return contentValue(res.Content)
}

func (c *ConnectorMCP) isCatalogConnector(connector string) bool {
	for _, id := range c.connectors() {
		if id == connector {
			return true
		}
	}
	return false
}

// contentText joins the text parts of a tool result.
func contentText(content []mcp.Content) string {
	parts := make([]string, 0, len(content))
	for _, part := range content {
		if t, ok := part.(*mcp.TextContent); ok {
			parts = append(parts, t.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// contentValue turns the content list of a tool result into a value that
// marshals to the same JSON.
func contentValue(content []mcp.Content) (any, error) {
	raw, err := json.Marshal(content)
	if err != nil {
		return nil, fmt.Errorf("connector mcp: encode the tool result: %w", err)
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("connector mcp: decode the tool result: %w", err)
	}
	return out, nil
}

// TokenFunc returns a bearer token for one request. An empty token sends no
// Authorization header.
type TokenFunc func(ctx context.Context) (string, error)

// ConnectorHTTPClient returns the HTTP client of the MCP client. Each request
// carries the token that token returns. A nil token func sends no token.
func ConnectorHTTPClient(token TokenFunc) *http.Client {
	return &http.Client{Transport: &bearerTransport{base: http.DefaultTransport, token: token}}
}

type bearerTransport struct {
	base  http.RoundTripper
	token TokenFunc
}

// RoundTrip implements http.RoundTripper. A token error fails the request:
// the call does not go out with no identity.
func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.token != nil {
		tok, err := t.token(req.Context())
		if err != nil {
			return nil, fmt.Errorf("connector mcp: fetch the identity token: %w", err)
		}
		if tok != "" {
			req = req.Clone(req.Context())
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("connector mcp: %w", err)
	}
	return resp, nil
}
