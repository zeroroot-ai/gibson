// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/zeroroot-ai/gibson/internal/engine/metatool"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
)

type echoIn struct {
	Text string `json:"text"`
}

type echoOut struct {
	Echo string `json:"echo"`
}

// newFakeConnector starts a real MCP server over streamable HTTP, as the
// ToolHive proxy of a connector serves it, and records the path of each
// request.
func newFakeConnector(t *testing.T) (srv *httptest.Server, paths *[]string) {
	t.Helper()
	server := mcp.NewServer(&mcp.Implementation{Name: "fake-connector", Version: "v0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "echo", Description: "echo the text"},
		func(_ context.Context, _ *mcp.CallToolRequest, in echoIn) (*mcp.CallToolResult, echoOut, error) {
			return nil, echoOut{Echo: in.Text}, nil
		})
	mcp.AddTool(server, &mcp.Tool{Name: "fail", Description: "always fails"},
		func(context.Context, *mcp.CallToolRequest, echoIn) (*mcp.CallToolResult, echoOut, error) {
			return nil, echoOut{}, errors.New("vendor said no")
		})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	var seen []string
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path)
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

// newTestConnectorMCP points the client at srv for the connector "github" of
// the tenant "acme", and at nothing for each other connector.
func newTestConnectorMCP(srv *httptest.Server, connectors ...string) *ConnectorMCP {
	c := NewConnectorMCP(srv.Client(), slog.Default())
	c.connectors = func() []string { return connectors }
	c.proxyURL = func(connector, namespace string) string {
		if connector == "github" && namespace == "tenant-acme" {
			return srv.URL + "/mcp"
		}
		return "http://127.0.0.1:1/mcp" // nothing listens: a connector that is not enabled
	}
	return c
}

// TestConnectorMCP_ListsTheToolsOfEachEnabledConnector: the tools of a
// connector that answers become mcp:<connector>:<tool> entries. A connector
// that does not answer lists nothing, and the call still succeeds.
func TestConnectorMCP_ListsTheToolsOfEachEnabledConnector(t *testing.T) {
	srv, _ := newFakeConnector(t)
	c := newTestConnectorMCP(srv, "github", "gitlab")

	got, err := c.ListConnectorTools(context.Background(), "acme")
	if err != nil {
		t.Fatalf("ListConnectorTools: %v", err)
	}
	names := map[string]bool{}
	for _, e := range got {
		if e.Source != toolid.SourceMCP || e.Connector != "github" {
			t.Fatalf("entry %+v; want an mcp entry of github", e)
		}
		names[e.Tool] = true
		if len(e.InputSchema) == 0 {
			t.Errorf("tool %q has no input schema", e.Tool)
		}
	}
	if !names["echo"] || !names["fail"] || len(got) != 2 {
		t.Fatalf("tools = %+v; want echo and fail of github", got)
	}
}

// TestConnectorMCP_CallsTheToolOfTheNamedConnector: the call reaches the
// proxy of the named connector in the namespace of the tenant, and the
// structured result returns.
func TestConnectorMCP_CallsTheToolOfTheNamedConnector(t *testing.T) {
	srv, paths := newFakeConnector(t)
	c := newTestConnectorMCP(srv, "github")

	got, err := c.CallConnectorTool(context.Background(), "acme", "github", "echo", map[string]any{"text": "hi"})
	if err != nil {
		t.Fatalf("CallConnectorTool: %v", err)
	}
	m, ok := got.(map[string]any)
	if !ok || m["echo"] != "hi" {
		t.Fatalf("result = %#v; want the structured echo", got)
	}
	if len(*paths) == 0 || (*paths)[0] != "/mcp" {
		t.Fatalf("paths = %v; want calls to /mcp", *paths)
	}
}

// TestConnectorMCP_Refusals: a tool error, a connector that the catalog does
// not list, a connector of a different tenant, and no tenant.
func TestConnectorMCP_Refusals(t *testing.T) {
	srv, _ := newFakeConnector(t)
	c := newTestConnectorMCP(srv, "github")
	ctx := context.Background()

	if _, err := c.CallConnectorTool(ctx, "acme", "github", "fail", nil); err == nil {
		t.Error("a tool that reports an error must return an error")
	}
	if _, err := c.CallConnectorTool(ctx, "acme", "not-in-catalog", "echo", nil); !errors.Is(err, ErrUnknownConnector) {
		t.Errorf("err = %v; want ErrUnknownConnector", err)
	}
	if _, err := c.CallConnectorTool(ctx, "other-tenant", "github", "echo", nil); err == nil {
		t.Error("the connector of a different tenant must not answer")
	}
	if _, err := c.CallConnectorTool(ctx, "", "github", "echo", nil); err == nil {
		t.Error("a call with no tenant must fail")
	}
}

// TestConnectorMCP_TheDefaultAddressIsTheOperatorAddress: with no override,
// the client dials the address that the connector operator writes.
func TestConnectorMCP_TheDefaultAddressIsTheOperatorAddress(t *testing.T) {
	c := NewConnectorMCP(nil, nil)
	if got := c.proxyURL("github", tenantNamespace("acme")); got != "http://mcp-github-proxy.tenant-acme.svc.cluster.local:8080/mcp" {
		t.Fatalf("proxy url = %q", got)
	}
	if len(c.connectors()) == 0 {
		t.Fatal("the default connector list must come from the platform catalog")
	}
}

// TestConnectorHTTPClient_SendsTheToken: each request carries the bearer
// token, an empty token sends none, and a token error stops the request.
func TestConnectorHTTPClient_SendsTheToken(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("Authorization"))
	}))
	defer srv.Close()

	for _, tok := range []string{"svid-token", ""} {
		client := ConnectorHTTPClient(func(context.Context) (string, error) { return tok, nil })
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		_ = resp.Body.Close()
	}
	if len(got) != 2 || got[0] != "Bearer svid-token" || got[1] != "" {
		t.Fatalf("Authorization headers = %q; want the token, then none", got)
	}

	failing := ConnectorHTTPClient(func(context.Context) (string, error) { return "", errors.New("no svid") })
	if resp, err := failing.Get(srv.URL); err == nil {
		_ = resp.Body.Close()
		t.Fatal("a token error must stop the request")
	}
	if len(got) != 2 {
		t.Fatal("a request went out with no identity")
	}

	plain := ConnectorHTTPClient(nil)
	resp, err := plain.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET with no token func: %v", err)
	}
	_ = resp.Body.Close()
}

// TestConnectorMCP_RecordsTheToolCountOfEachAnsweringConnector: the daemon is
// the one MCP client, so it records how many tools each connector served
// (gibson#723). A connector that does not answer records nothing.
func TestConnectorMCP_RecordsTheToolCountOfEachAnsweringConnector(t *testing.T) {
	srv, _ := newFakeConnector(t)
	got := map[string]int{}
	c := newTestConnectorMCP(srv, "github", "gitlab").WithToolCountRecorder(
		func(_ context.Context, tenant, connector string, n int) {
			got[tenant+"/"+connector] = n
		})

	if _, err := c.ListConnectorTools(context.Background(), "acme"); err != nil {
		t.Fatalf("ListConnectorTools: %v", err)
	}
	if len(got) != 1 || got["acme/github"] != 2 {
		t.Fatalf("recorded counts = %v; want acme/github = 2 only", got)
	}
}

// A connector that nothing listens on is a transport failure: the call may work later, so the
// error carries ErrConnectorUnavailable. A connector that answers with an error from the tool
// carries no mark, because the connector sends none, and the daemon does not guess from the text.
func TestConnectorMCP_ATransportFailureIsMarkedUnavailableAndAToolErrorIsNot(t *testing.T) {
	srv, _ := newFakeConnector(t)
	down := newTestConnectorMCP(srv, "github")
	down.proxyURL = func(string, string) string { return "http://127.0.0.1:1/mcp" }

	_, err := down.CallConnectorTool(context.Background(), "acme", "github", "echo", map[string]any{"text": "hi"})
	if !errors.Is(err, metatool.ErrConnectorUnavailable) || errors.Is(err, metatool.ErrConnectorTimeout) {
		t.Fatalf("err = %v, want ErrConnectorUnavailable", err)
	}

	up := newTestConnectorMCP(srv, "github")
	_, err = up.CallConnectorTool(context.Background(), "acme", "github", "fail", map[string]any{"text": "hi"})
	if err == nil || errors.Is(err, metatool.ErrConnectorUnavailable) || errors.Is(err, metatool.ErrConnectorTimeout) {
		t.Fatalf("err = %v, want an unmarked tool error", err)
	}
	_, err = up.CallConnectorTool(context.Background(), "acme", "github", "no-such-tool", nil)
	if err == nil || errors.Is(err, metatool.ErrConnectorUnavailable) {
		t.Fatalf("err = %v, want a refusal of the protocol that is no transport failure", err)
	}
}

// A connector that does not answer within the bound of the daemon gives ErrConnectorTimeout.
func TestConnectorMCP_ABoundThatEndsIsMarkedTimeout(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "slow-connector", Version: "v0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "slow", Description: "waits"},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ echoIn) (*mcp.CallToolResult, echoOut, error) {
			select {
			case <-ctx.Done():
			case <-time.After(3 * time.Second):
			}
			return nil, echoOut{}, errors.New("slow tool ended")
		})
	srv := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil))
	t.Cleanup(srv.Close)
	t.Cleanup(srv.CloseClientConnections)
	c := newTestConnectorMCP(srv, "github")
	c.timeout = 300 * time.Millisecond

	_, err := c.CallConnectorTool(context.Background(), "acme", "github", "slow", map[string]any{"text": "x"})

	if !errors.Is(err, metatool.ErrConnectorTimeout) {
		t.Fatalf("err = %v, want ErrConnectorTimeout", err)
	}
}

// A call that the caller canceled is no failure of the connector.
func TestClassifyTransport_ACanceledCallStaysAsItIs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := classifyTransport(ctx, context.Canceled)
	if errors.Is(err, metatool.ErrConnectorUnavailable) || errors.Is(err, metatool.ErrConnectorTimeout) {
		t.Fatalf("err = %v, want the cancellation unmarked", err)
	}
}

// connectorAt returns a client of the connector "github" that talks to url over client.
func connectorAt(url string, client *http.Client) *ConnectorMCP {
	c := NewConnectorMCP(client, slog.Default())
	c.connectors = func() []string { return []string{"github"} }
	c.proxyURL = func(string, string) string { return url }
	return c
}

// TestConnectorMCP_OnlyTemporaryFailuresAreUnavailable: UNAVAILABLE is an allow-list. A 429, a
// 502, 503 or 504 and a connection that breaks are temporary. A 401, a 403 with no JSON-RPC
// body, a refusal of the certificate, a failure of the token and a JSON-RPC error body are
// refusals: a later call gives the same answer, so they stay unmarked.
func TestConnectorMCP_OnlyTemporaryFailuresAreUnavailable(t *testing.T) {
	status := func(code int, body string) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		return srv
	}
	rpcBody := `{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"no access"}}`
	plain := func(code int, body string) *ConnectorMCP {
		return connectorAt(status(code, body).URL, http.DefaultClient)
	}
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(tlsSrv.Close)

	cases := map[string]struct {
		c           *ConnectorMCP
		unavailable bool
	}{
		"429":                       {plain(http.StatusTooManyRequests, ""), true},
		"502":                       {plain(http.StatusBadGateway, ""), true},
		"503":                       {plain(http.StatusServiceUnavailable, ""), true},
		"504":                       {plain(http.StatusGatewayTimeout, ""), true},
		"a connection that breaks":  {connectorAt("http://127.0.0.1:1/mcp", http.DefaultClient), true},
		"401":                       {plain(http.StatusUnauthorized, "denied"), false},
		"403 with no JSON-RPC body": {plain(http.StatusForbidden, "forbidden"), false},
		"403 with a JSON-RPC body":  {plain(http.StatusForbidden, rpcBody), false},
		"a refused certificate":     {connectorAt(tlsSrv.URL, http.DefaultClient), false},
		"a failure of the token": {connectorAt("http://connector.invalid/mcp", &http.Client{
			Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, errors.New("the token endpoint refused the client")
			}),
		}), false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			args := map[string]any{"text": "x"}
			_, err := tc.c.CallConnectorTool(context.Background(), "acme", "github", "echo", args)
			if err == nil {
				t.Fatal("want an error")
			}
			if got := errors.Is(err, metatool.ErrConnectorUnavailable); got != tc.unavailable {
				t.Fatalf("unavailable = %v, want %v (%v)", got, tc.unavailable, err)
			}
			if errors.Is(err, metatool.ErrConnectorTimeout) {
				t.Fatalf("a failure with no bound that ended is no timeout: %v", err)
			}
		})
	}
}

// The allow-list names the errors of a connection that breaks and of a session that ended.
func TestTemporaryTransport_NamesTheBrokenConnectionErrors(t *testing.T) {
	for name, err := range map[string]error{
		"an end of the stream":       fmt.Errorf("read: %w", io.ErrUnexpectedEOF),
		"a reset of the connection":  fmt.Errorf("read: %w", syscall.ECONNRESET),
		"a session the server ended": fmt.Errorf("call: %w", mcp.ErrSessionMissing),
	} {
		if !temporaryTransport(err) {
			t.Errorf("%s must be temporary", name)
		}
	}
	for name, err := range map[string]error{
		"a plain error": errors.New("boom"),
		"a certificate": x509.UnknownAuthorityError{},
	} {
		if temporaryTransport(err) {
			t.Errorf("%s must not be temporary", name)
		}
	}
}
