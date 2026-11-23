// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
	"github.com/zeroroot-ai/gibson/internal/engine/metatool"
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
	// recordTools receives the tool count of each connector that answered a
	// list. Nil records nothing.
	recordTools ToolCountRecorder
}

// ToolCountRecorder records how many tools one connector of a tenant served.
type ToolCountRecorder func(ctx context.Context, tenant, connector string, n int)

// WithToolCountRecorder sets the recorder of the tool count of each listed
// connector and returns c. The daemon records the count in the
// tenant_connectors table, which ListConnectors serves (gibson#723).
func (c *ConnectorMCP) WithToolCountRecorder(r ToolCountRecorder) *ConnectorMCP {
	c.recordTools = r
	return c
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
		return nil, fmt.Errorf("connector mcp: connect to %q: %w", connector, classifyTransport(ctx, err))
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
		if c.recordTools != nil {
			c.recordTools(ctx, tenant, connector, len(tools))
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
		return nil, fmt.Errorf("connector mcp: call %s on %q: %w", tool, connector, classifyCall(cctx, err))
	}
	// A tool that reports an error returns text only: the connector sends no structured mark
	// that says if the error is temporary, so the error stays unclassified here. The daemon
	// never reads the words of the text to guess.
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
	if temporaryStatus(resp.StatusCode) {
		// The proxy or the connector says that a later call may work. The transport marks the
		// status with an error type of the daemon, so the classifier never reads the codes or
		// the words that the connector put into its own answer.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		return nil, &temporaryStatusError{Status: resp.StatusCode}
	}
	return resp, nil
}

// temporaryStatus is true for the HTTP statuses that mean a later call may work.
func temporaryStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// temporaryStatusError is the error of a response with a temporary status. The transport makes
// it, and nothing that the connector sends can make it.
type temporaryStatusError struct{ Status int }

func (e *temporaryStatusError) Error() string {
	return fmt.Sprintf("connector mcp: the connector answered %d %s", e.Status, http.StatusText(e.Status))
}

// isRateLimited is true for a response with the status 429.
func isRateLimited(err error) bool {
	var status *temporaryStatusError
	return errors.As(err, &status) && status.Status == http.StatusTooManyRequests
}

// classifyTransport marks an error of the connection to a connector by its type. A bound that
// ended gives metatool.ErrConnectorTimeout. A call that the caller canceled stays as it is. An
// error that the allow-list of temporaryTransport names gives metatool.ErrConnectorUnavailable.
// Every other error stays unmarked, so the member reads it as a refusal. The error keeps its
// cause.
func classifyTransport(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded):
		return fmt.Errorf("%w: %w", metatool.ErrConnectorTimeout, err)
	case errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled):
		return err
	case isRateLimited(err):
		return fmt.Errorf("%w: %w", metatool.ErrConnectorRateLimited, err)
	case temporaryTransport(err):
		return fmt.Errorf("%w: %w", metatool.ErrConnectorUnavailable, err)
	default:
		return err
	}
}

// temporaryTransport is the allow-list of the errors that a later call may not repeat:
//   - the session that the connector ended (mcp.ErrSessionMissing)
//   - a failure to dial or a failure of the network (*net.OpError)
//   - an end of the stream or a reset of the connection
//   - a response with a temporary status, which the transport marks (temporaryStatusError).
//
// Every other error is no member of the list. A 401, a 403, a refusal of the certificate, a
// failure of the token and an error that the connector sent as a JSON-RPC body are refusals:
// a later call gives the same answer.
func temporaryTransport(err error) bool {
	var (
		unknownAuthority x509.UnknownAuthorityError
		invalidCert      x509.CertificateInvalidError
		hostname         x509.HostnameError
		verification     *tls.CertificateVerificationError
	)
	if errors.As(err, &unknownAuthority) || errors.As(err, &invalidCert) ||
		errors.As(err, &hostname) || errors.As(err, &verification) {
		return false
	}
	var (
		opErr  *net.OpError
		status *temporaryStatusError
	)
	return errors.Is(err, mcp.ErrSessionMissing) || errors.As(err, &opErr) || errors.As(err, &status) ||
		errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET)
}

// classifyCall marks the error of a tool call that went out on an open session. After the
// request was sent, the connector may have run the tool, so a repeat of a write could do the
// work twice. Only two failures prove that the request did not reach the connector: a dial error
// and a session that the connector ended. A 429 is a refusal before the tool ran, so it is rate
// limited. A JSON-RPC error that the connector answered with is a refusal and stays unmarked.
// Every other failure leaves the outcome unknown: the member must read the state before it
// calls again, so it gets a code that the member does not retry. A bound that ended after the
// request went out is no timeout of that kind, because the member retries a timeout.
func classifyCall(ctx context.Context, err error) error {
	var opErr *net.OpError
	switch {
	case errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled):
		return err
	case isRateLimited(err):
		return fmt.Errorf("%w: %w", metatool.ErrConnectorRateLimited, err)
	case errors.Is(err, mcp.ErrSessionMissing) || (errors.As(err, &opErr) && opErr.Op == "dial"):
		return fmt.Errorf("%w: %w", metatool.ErrConnectorUnavailable, err)
	case answeredByConnector(err):
		return err
	default:
		return fmt.Errorf("%w: %w", metatool.ErrConnectorOutcomeUnknown, err)
	}
}

// rejectedCode is the JSON-RPC code of the rejection that the MCP client makes itself. A
// connector can send the same code, so it never proves anything: this is only how the walk
// below skips the client's own wrapper.
const rejectedCode = -32005

// answeredByConnector is true when the chain holds a JSON-RPC error that is not the rejection
// of the client: the connector answered, so the call did not fail in the transport.
func answeredByConnector(err error) bool {
	found := false
	var walk func(error)
	walk = func(e error) {
		if e == nil || found {
			return
		}
		if w, ok := e.(*jsonrpc.Error); ok && w.Code != rejectedCode { //nolint:errorlint // the walk tests one node, errors.As would skip the wrapper
			found = true
			return
		}
		switch u := e.(type) { //nolint:errorlint // the walk unwraps one level at a time
		case interface{ Unwrap() []error }:
			for _, c := range u.Unwrap() {
				walk(c)
			}
		case interface{ Unwrap() error }:
			walk(u.Unwrap())
		}
	}
	walk(err)
	return found
}
