// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
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

// A tool call that the bound of the daemon ends may have run: the outcome is unknown, and the
// error is no TIMEOUT, because the member retries a timeout.
func TestConnectorMCP_ABoundThatEndsDuringACallIsAnUnknownOutcome(t *testing.T) {
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

	if !errors.Is(err, metatool.ErrConnectorOutcomeUnknown) || errors.Is(err, metatool.ErrConnectorTimeout) {
		t.Fatalf("err = %v, want the unknown outcome and no timeout", err)
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

// TestConnectorMCP_OnlyTemporaryFailuresAreUnavailable: UNAVAILABLE is an allow-list. The
// transport of the daemon marks a 502, 503 and 504, and a 429 is rate limited. A connection
// that breaks is temporary. A 401, a 403, a refusal of the certificate, a failure of the token
// and each JSON-RPC error body are refusals, also one with the code -32005 that the MCP client
// uses for its own rejection: a connector can send any code, so no code is a mark.
func TestConnectorMCP_OnlyTemporaryFailuresAreUnavailable(t *testing.T) {
	status := func(code int, body string) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		return srv
	}
	// rpcError answers each request with a JSON-RPC error of the given code and the given status.
	rpcError := func(httpStatus, rpcCode int) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				ID json.RawMessage `json:"id"`
			}
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &req)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(httpStatus)
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":%d,"message":"no"}}`, req.ID, rpcCode)
		}))
		t.Cleanup(srv.Close)
		return srv
	}
	// through is the client of the daemon: the bearer transport wraps the base transport.
	through := func(base http.RoundTripper, token func(context.Context) (string, error)) *http.Client {
		return &http.Client{Transport: &bearerTransport{base: base, token: token}}
	}
	plain := func(srv *httptest.Server) *ConnectorMCP {
		return connectorAt(srv.URL, through(http.DefaultTransport, nil))
	}
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(tlsSrv.Close)
	rpcBody := `{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"no access"}}`

	type want int
	const (
		refusal want = iota
		unavailable
		rateLimited
	)
	cases := map[string]struct {
		c    *ConnectorMCP
		want want
	}{
		"429": {plain(status(http.StatusTooManyRequests, "")), rateLimited},
		"502": {plain(status(http.StatusBadGateway, "")), unavailable},
		"503": {plain(status(http.StatusServiceUnavailable, "")), unavailable},
		"504": {plain(status(http.StatusGatewayTimeout, "")), unavailable},
		"a connection that breaks": {connectorAt("http://127.0.0.1:1/mcp", through(http.DefaultTransport, nil)),
			unavailable},
		"401":                       {plain(status(http.StatusUnauthorized, "denied")), refusal},
		"403 with no JSON-RPC body": {plain(status(http.StatusForbidden, "forbidden")), refusal},
		"403 with a JSON-RPC body":  {plain(status(http.StatusForbidden, rpcBody)), refusal},
		"code -32005 in a 200":      {plain(rpcError(http.StatusOK, -32005)), refusal},
		"code -32005 in a 400":      {plain(rpcError(http.StatusBadRequest, -32005)), refusal},
		"code -32005 in a 403":      {plain(rpcError(http.StatusForbidden, -32005)), refusal},
		"a refused certificate":     {connectorAt(tlsSrv.URL, through(http.DefaultTransport, nil)), refusal},
		"a failure of the token": {connectorAt("http://connector.invalid/mcp",
			through(http.DefaultTransport, func(context.Context) (string, error) {
				return "", errors.New("the token endpoint refused the client")
			})), refusal},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			args := map[string]any{"text": "x"}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			_, err := tc.c.CallConnectorTool(ctx, "acme", "github", "echo", args)
			if err == nil {
				t.Fatal("want an error")
			}
			if got := errors.Is(err, metatool.ErrConnectorUnavailable); got != (tc.want == unavailable) {
				t.Fatalf("unavailable = %v, want %v (%v)", got, tc.want == unavailable, err)
			}
			if got := errors.Is(err, metatool.ErrConnectorRateLimited); got != (tc.want == rateLimited) {
				t.Fatalf("rate limited = %v, want %v (%v)", got, tc.want == rateLimited, err)
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

// writerConnector serves a tool that does a write and counts it. After the tool ran, failAfter
// breaks the answer: a 502, a 503 or a dropped connection. Every other request (the handshake)
// passes through.
func writerConnector(t *testing.T, failAfter func(http.ResponseWriter)) (url string, writes *int) {
	t.Helper()
	count := 0
	server := mcp.NewServer(&mcp.Implementation{Name: "writer", Version: "v0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "write", Description: "does a write"},
		func(context.Context, *mcp.CallToolRequest, echoIn) (*mcp.CallToolResult, echoOut, error) {
			count++
			return nil, echoOut{Echo: "done"}, nil
		})
	inner := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(raw))
		var msg struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(raw, &msg)
		if r.Method != http.MethodPost || msg.Method != "tools/call" {
			inner.ServeHTTP(w, r)
			return
		}
		inner.ServeHTTP(httptest.NewRecorder(), r) // the tool runs, and its answer is thrown away
		failAfter(w)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &count
}

// A server that does the work and then fails the answer leaves the outcome unknown. The member
// must not repeat the write, so the error is no UNAVAILABLE and no TIMEOUT: both are retried.
func TestConnectorMCP_AFailureAfterTheWorkIsAnUnknownOutcome(t *testing.T) {
	status := func(code int) func(http.ResponseWriter) {
		return func(w http.ResponseWriter) { w.WriteHeader(code) }
	}
	drop := func(w http.ResponseWriter) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}
	for name, fail := range map[string]func(http.ResponseWriter){
		"a 502 after the work":       status(http.StatusBadGateway),
		"a 503 after the work":       status(http.StatusServiceUnavailable),
		"a 504 after the work":       status(http.StatusGatewayTimeout),
		"a dropped connection":       drop,
		"a 500 after the work":       status(http.StatusInternalServerError),
		"a 401 after the work (odd)": status(http.StatusUnauthorized),
	} {
		t.Run(name, func(t *testing.T) {
			url, writes := writerConnector(t, fail)
			c := connectorAt(url, &http.Client{Transport: &bearerTransport{base: http.DefaultTransport}})
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			_, err := c.CallConnectorTool(ctx, "acme", "github", "write", map[string]any{"text": "x"})

			if err == nil {
				t.Fatal("want an error")
			}
			if *writes != 1 {
				t.Fatalf("the tool ran %d times, want 1", *writes)
			}
			if errors.Is(err, metatool.ErrConnectorUnavailable) || errors.Is(err, metatool.ErrConnectorTimeout) {
				t.Fatalf("a retried code after the work ran: %v", err)
			}
			if !errors.Is(err, metatool.ErrConnectorOutcomeUnknown) {
				t.Fatalf("err = %v, want the unknown outcome", err)
			}
		})
	}
}

// A call that the daemon bound ended is also an unknown outcome and no TIMEOUT: the connector
// may have run the tool.
func TestClassifyCall(t *testing.T) {
	deadline, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-deadline.Done()
	canceled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	rpcAnswer := &jsonrpc.Error{Code: -32602, Message: "unknown tool"}
	for name, tc := range map[string]struct {
		ctx  context.Context
		err  error
		want error // nil: the error stays unmarked
		not  []error
	}{
		"a bound that ended after the request went out": {deadline, context.DeadlineExceeded,
			metatool.ErrConnectorOutcomeUnknown, []error{metatool.ErrConnectorTimeout, metatool.ErrConnectorUnavailable}},
		"a dial error": {context.Background(), &net.OpError{Op: "dial", Err: errors.New("refused")},
			metatool.ErrConnectorUnavailable, []error{metatool.ErrConnectorOutcomeUnknown}},
		"a read error": {context.Background(), &net.OpError{Op: "read", Err: errors.New("reset")},
			metatool.ErrConnectorOutcomeUnknown, []error{metatool.ErrConnectorUnavailable}},
		"an end of the stream": {context.Background(), io.ErrUnexpectedEOF, metatool.ErrConnectorOutcomeUnknown,
			[]error{metatool.ErrConnectorUnavailable}},
		"a session that ended": {context.Background(), mcp.ErrSessionMissing, metatool.ErrConnectorUnavailable, nil},
		"a 429": {context.Background(), &temporaryStatusError{Status: 429},
			metatool.ErrConnectorRateLimited, nil},
		"a 502": {context.Background(), &temporaryStatusError{Status: 502}, metatool.ErrConnectorOutcomeUnknown,
			[]error{metatool.ErrConnectorUnavailable}},
		"an answer of the connector": {context.Background(), fmt.Errorf("call: %w", rpcAnswer), nil,
			[]error{metatool.ErrConnectorOutcomeUnknown, metatool.ErrConnectorUnavailable}},
		"a cancel": {canceled, context.Canceled, nil, []error{metatool.ErrConnectorOutcomeUnknown}},
	} {
		t.Run(name, func(t *testing.T) {
			got := classifyCall(tc.ctx, tc.err)
			if tc.want != nil && !errors.Is(got, tc.want) {
				t.Errorf("err = %v, want %v", got, tc.want)
			}
			for _, n := range tc.not {
				if errors.Is(got, n) {
					t.Errorf("err = %v, must not be %v", got, n)
				}
			}
		})
	}
}
