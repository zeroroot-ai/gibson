// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build agentgateway_fixture

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/proto"
)

// This test runs agentgateway as a process, with three fake services around
// it: the mock model provider, a fake HTTP authorization service and an
// OTLP/HTTP trace receiver. It proves what the gateway does with a model call.
//
// The test needs a binary. Set AGENTGATEWAY_BIN to its path. The build tag
// keeps the test out of the normal unit run. The workflow
// .github/workflows/agentgateway-fixture.yml builds the binary and runs the
// test.

const (
	// Attribute names that the trace policy adds to each span.
	attrRequestBody  = "gibson.request_body"
	attrResponseBody = "gibson.response_body"

	// Fake secrets. No span may hold either one.
	providerKeyPrefix = "key-of-"
	tokenA            = "tok-a"
	tokenB            = "tok-b"
	tokenE            = "tok-e"

	forbiddenModel = "claude-forbidden"
	toolResultText = "open ports: 22/tcp ssh, 80/tcp http"
)

// tenantRoute is one tenant route of the gateway.
type tenantRoute struct {
	Name     string
	Provider string // the provider key of the gateway: anthropic or openAI
}

var routes = []tenantRoute{
	{Name: "tenant-a", Provider: "anthropic"},
	{Name: "tenant-b", Provider: "anthropic"},
	{Name: "tenant-e", Provider: "openAI"},
}

var tokens = map[string]string{
	"Bearer " + tokenA: "tenant-a",
	"Bearer " + tokenB: "tenant-b",
	"Bearer " + tokenE: "tenant-e",
}

const configTemplate = `config:
  logging:
    format: json
  readinessAddr: {{.Readiness}}
  statsAddr: {{.Stats}}
  adminAddr: {{.Admin}}
  tracing:
    otlpEndpoint: http://{{.OTLP}}
    otlpProtocol: http
    randomSampling: true
    fields:
      add:
        gibson.request_body: string(request.body)
        gibson.response_body: string(response.body)
        gibson.tenant: request.headers["x-gibson-tenant"]
        gibson.subject: request.headers["x-gibson-subject"]
        gibson.mission: request.headers["x-gibson-mission"]
        gibson.task: request.headers["x-gibson-task"]
frontendPolicies:
  http:
    maxBufferSize: 20971520
binds:
- port: {{.Port}}
  listeners:
  - routes:
{{- range .Routes}}
    - name: {{.Name}}
      matches:
      - headers:
        - name: x-gibson-tenant
          value:
            exact: {{.Name}}
      backends:
      - ai:
          name: {{.Name}}-backend
          provider:
            {{.Provider}}: {}
          hostOverride: {{$.Provider}}
      policies:
        ai:
          routes:
            /v1/messages: messages
            /v1/responses: responses
            /v1/embeddings: embeddings
            /v1/models: passthrough
        backendAuth:
          key: key-of-{{.Name}}
        extAuthz:
          host: {{$.Authz}}
          includeRequestHeaders: ["authorization", "x-gibson-tenant"]
          protocol:
            http:
              path: '"/check"'
              body: '""'
              includeResponseHeaders: ["x-gibson-tenant", "x-gibson-subject"]
              addRequestHeaders:
                x-route-tenant: '"{{.Name}}"'
                x-authz-model: 'json(request.body).model'
{{- end}}
`

// freeAddr returns a local address that no process listens on now.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find a free port: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("close probe listener: %v", err)
	}
	return addr
}

func hostOf(srv *httptest.Server) string {
	return strings.TrimPrefix(srv.URL, "http://")
}

// authzService is the fake HTTP authorization service. It allows a call when
// the token matches the tenant of the route and the model is not forbidden.
type authzService struct {
	mu    sync.Mutex
	calls int
}

func (a *authzService) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

func (a *authzService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.calls++
	a.mu.Unlock()
	tenant, known := tokens[r.Header.Get("Authorization")]
	allowed := known &&
		tenant == r.Header.Get("X-Route-Tenant") &&
		r.Header.Get("X-Authz-Model") != forbiddenModel
	if !allowed {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.Header().Set("X-Gibson-Tenant", tenant)
	w.Header().Set("X-Gibson-Subject", "user-from-authz")
	w.WriteHeader(http.StatusOK)
}

// span is one received span with its string attributes.
type span struct {
	Name  string
	Attrs map[string]string
	// StartNano and EndNano are the span times, in nanoseconds since the epoch.
	StartNano, EndNano uint64
	// StatusCode is the status code of the span: 0 unset, 1 ok, 2 error.
	StatusCode int32
	// All holds every attribute with its typed value. A test dumps it as data.
	All map[string]any
}

// otlpReceiver is the fake OTLP/HTTP trace receiver.
type otlpReceiver struct {
	mu    sync.Mutex
	raw   []byte
	spans []span
}

func (o *otlpReceiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if body, err = io.ReadAll(zr); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	var req coltrace.ExportTraceServiceRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	o.mu.Lock()
	o.raw = append(o.raw, body...)
	for _, rs := range req.GetResourceSpans() {
		for _, ss := range rs.GetScopeSpans() {
			for _, sp := range ss.GetSpans() {
				o.spans = append(o.spans, span{
					Name: sp.GetName(), Attrs: stringAttrs(sp.GetAttributes()), All: typedAttrs(sp.GetAttributes()),
					StartNano: sp.GetStartTimeUnixNano(), EndNano: sp.GetEndTimeUnixNano(),
					StatusCode: int32(sp.GetStatus().GetCode()),
				})
			}
		}
	}
	o.mu.Unlock()
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
}

func stringAttrs(kvs []*commonpb.KeyValue) map[string]string {
	out := make(map[string]string, len(kvs))
	for _, kv := range kvs {
		out[kv.GetKey()] = kv.GetValue().GetStringValue()
	}
	return out
}

// typedAttrs returns each attribute with its own type: string, int, double or bool.
func typedAttrs(kvs []*commonpb.KeyValue) map[string]any {
	out := make(map[string]any, len(kvs))
	for _, kv := range kvs {
		switch v := kv.GetValue().GetValue().(type) {
		case *commonpb.AnyValue_StringValue:
			out[kv.GetKey()] = v.StringValue
		case *commonpb.AnyValue_IntValue:
			out[kv.GetKey()] = v.IntValue
		case *commonpb.AnyValue_DoubleValue:
			out[kv.GetKey()] = v.DoubleValue
		case *commonpb.AnyValue_BoolValue:
			out[kv.GetKey()] = v.BoolValue
		}
	}
	return out
}

// dumpSpan writes the attributes of a span as JSON to $GATEWAY_SPAN_DUMP_DIR,
// when the variable is set. It is how the span data of the llmtrace tests was made.
func dumpSpan(t *testing.T, name string, sp span) {
	t.Helper()
	dir := os.Getenv("GATEWAY_SPAN_DUMP_DIR")
	if dir == "" {
		return
	}
	data, err := json.MarshalIndent(map[string]any{
		"name": sp.Name, "start_unix_nano": sp.StartNano, "end_unix_nano": sp.EndNano,
		"status_code": sp.StatusCode, "attributes": sp.All,
	}, "", "  ")
	if err != nil {
		t.Fatalf("marshal span: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".json"), data, 0o600); err != nil {
		t.Fatalf("write span dump: %v", err)
	}
}

func (o *otlpReceiver) rawBytes() []byte {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]byte(nil), o.raw...)
}

// waitSpan waits for a span whose request body holds marker.
func (o *otlpReceiver) waitSpan(t *testing.T, marker string) span {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		o.mu.Lock()
		for _, sp := range o.spans {
			if strings.Contains(sp.Attrs[attrRequestBody], marker) {
				o.mu.Unlock()
				return sp
			}
		}
		o.mu.Unlock()
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("no span with request body marker %q after 45s", marker)
	return span{}
}

// gateway is the running agentgateway process.
type gateway struct {
	base string
}

// startGateway renders the config template with data, starts the binary and
// waits until it is ready.
func startGateway(t *testing.T, bin, configTpl string, data map[string]any) *gateway {
	t.Helper()
	dir := t.TempDir()
	data["Port"] = freePort(t)
	data["Readiness"] = freeAddr(t)
	data["Stats"] = freeAddr(t)
	data["Admin"] = freeAddr(t)
	var cfg bytes.Buffer
	tpl, err := template.New("config").Parse(configTpl)
	if err != nil {
		t.Fatalf("parse config template: %v", err)
	}
	if err := tpl.Execute(&cfg, data); err != nil {
		t.Fatalf("render config: %v", err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, cfg.Bytes(), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	logPath := filepath.Join(dir, "gateway.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create gateway log: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, "-f", cfgPath)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start %s: %v", bin, err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait() // The process ends by signal. Its exit error is expected.
		if t.Failed() {
			if logData, rerr := os.ReadFile(logPath); rerr == nil {
				t.Logf("gateway log:\n%s", logData)
			}
		}
		_ = logFile.Close()
	})

	ready := "http://" + data["Readiness"].(string) + "/healthz/ready"
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(ready) //nolint:gosec,noctx // the address is a local test port
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return &gateway{base: "http://127.0.0.1:" + data["Port"].(string)}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("gateway not ready after 30s")
	return nil
}

func freePort(t *testing.T) string {
	t.Helper()
	return strings.TrimPrefix(freeAddr(t), "127.0.0.1:")
}

// reply is the result of one call through the gateway.
type reply struct {
	Status int
	Body   string
}

// call sends one request to the gateway for a tenant route with a token.
func (g *gateway) call(t *testing.T, method, path, route, token, body string) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, g.base+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gibson-Tenant", route)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Anthropic-Version", "2023-06-01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("call %s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read reply of %s %s: %v", method, path, err)
	}
	return reply{Status: resp.StatusCode, Body: string(data)}
}

func messagesBody(model, marker string, stream bool) string {
	body := map[string]any{
		"model": model, "max_tokens": 256, "stream": stream,
		"messages": []any{
			map[string]any{"role": "user", "content": "scan 10.0.0.5 " + marker},
			map[string]any{"role": "assistant", "content": []any{
				map[string]any{"type": "tool_use", "id": "toolu_1", "name": ToolName,
					"input": map[string]any{"target": "10.0.0.5"}},
			}},
			map[string]any{"role": "user", "content": []any{
				map[string]any{"type": "tool_result", "tool_use_id": "toolu_1", "content": toolResultText},
			}},
		},
	}
	out, err := json.Marshal(body)
	if err != nil {
		panic(fmt.Sprintf("marshal fixed request: %v", err))
	}
	return string(out)
}

func countPath(p *Provider, path string) int {
	n := 0
	for _, r := range p.Requests() {
		if r.Path == path {
			n++
		}
	}
	return n
}

func TestGatewayFixture(t *testing.T) {
	bin := os.Getenv("AGENTGATEWAY_BIN")
	if bin == "" {
		t.Fatal("AGENTGATEWAY_BIN is not set. Set it to the path of an agentgateway binary.")
	}

	provider := &Provider{}
	providerSrv := httptest.NewServer(provider)
	defer providerSrv.Close()
	authz := &authzService{}
	authzSrv := httptest.NewServer(authz)
	defer authzSrv.Close()
	otlp := &otlpReceiver{}
	otlpSrv := httptest.NewServer(otlp)
	defer otlpSrv.Close()

	gw := startGateway(t, bin, configTemplate, map[string]any{
		"Routes":   routes,
		"Provider": hostOf(providerSrv),
		"Authz":    hostOf(authzSrv),
		"OTLP":     hostOf(otlpSrv),
	})

	t.Run("a_span_holds_both_bodies_with_the_tool_result", func(t *testing.T) {
		const marker = "marker-plain-1"
		got := gw.call(t, http.MethodPost, "/v1/messages", "tenant-a", tokenA, messagesBody(Model, marker, false))
		if got.Status != http.StatusOK {
			t.Fatalf("status = %d, want 200. body: %s", got.Status, got.Body)
		}
		sp := otlp.waitSpan(t, marker)
		dumpSpan(t, "messages_plain", sp)
		reqBody, respBody := sp.Attrs[attrRequestBody], sp.Attrs[attrResponseBody]
		for _, want := range []string{toolResultText, "tool_result"} {
			if !strings.Contains(reqBody, want) {
				t.Errorf("request body in span lacks %q", want)
			}
		}
		for _, want := range []string{ThinkingText, ToolName, "tool_use"} {
			if !strings.Contains(respBody, want) {
				t.Errorf("response body in span lacks %q", want)
			}
		}
		// (f) The sizes are the input of the buffer limit decision.
		msg := fmt.Sprintf("body sizes: request.body=%d bytes, response.body=%d bytes", len(reqBody), len(respBody))
		t.Log(msg)
		fmt.Println(msg)

		// The provider got the key of the tenant of the route.
		var seen bool
		for _, r := range provider.Requests() {
			if r.Path == "/v1/messages" && strings.Contains(r.Body, marker) {
				seen = true
				if key := r.Header.Get("X-Api-Key"); key != providerKeyPrefix+"tenant-a" {
					t.Errorf("provider x-api-key = %q, want %q", key, providerKeyPrefix+"tenant-a")
				}
				// The gateway does not yet remove the x-gibson headers (epic slice 7b).
				// The test reports this and asserts nothing.
				t.Logf("provider saw x-gibson-tenant=%q", r.Header.Get("X-Gibson-Tenant"))
			}
		}
		if !seen {
			t.Error("provider recorded no /v1/messages request with the marker")
		}
	})

	t.Run("stream_span_holds_raw_sse_text", func(t *testing.T) {
		const marker = "marker-stream-1"
		got := gw.call(t, http.MethodPost, "/v1/messages", "tenant-a", tokenA, messagesBody(Model, marker, true))
		if got.Status != http.StatusOK || !strings.Contains(got.Body, "message_stop") {
			t.Fatalf("stream reply: status %d, body %s", got.Status, got.Body)
		}
		sp := otlp.waitSpan(t, marker)
		dumpSpan(t, "messages_stream", sp)
		respBody := sp.Attrs[attrResponseBody]
		for _, want := range []string{"event: message_start", "tool_use", ThinkingText} {
			if !strings.Contains(respBody, want) {
				t.Errorf("stream response body in span lacks %q", want)
			}
		}
		t.Logf("stream body sizes: request.body=%d bytes, response.body=%d bytes",
			len(sp.Attrs[attrRequestBody]), len(respBody))
	})

	t.Run("b_no_provider_key_and_no_token_in_any_span", func(t *testing.T) {
		raw := otlp.rawBytes()
		if len(raw) == 0 {
			t.Fatal("the receiver got no trace data")
		}
		secrets := []string{tokenA, tokenB, tokenE}
		for _, r := range routes {
			secrets = append(secrets, providerKeyPrefix+r.Name)
		}
		for _, secret := range secrets {
			if bytes.Contains(raw, []byte(secret)) {
				t.Errorf("trace data holds the secret %q", secret)
			}
		}
	})

	t.Run("model_list_and_embeddings_pass_through", func(t *testing.T) {
		list := gw.call(t, http.MethodGet, "/v1/models", "tenant-a", tokenA, "")
		if list.Status != http.StatusOK || !strings.Contains(list.Body, Model) {
			t.Errorf("model list: status %d, body %s", list.Status, list.Body)
		}
		emb := gw.call(t, http.MethodPost, "/v1/embeddings", "tenant-e", tokenE,
			`{"model":"text-embedding-3-small","input":["one","two"],"dimensions":5}`)
		if emb.Status != http.StatusOK {
			t.Fatalf("embeddings: status %d, body %s", emb.Status, emb.Body)
		}
		var parsed struct {
			Data []struct {
				Embedding []float64 `json:"embedding"`
			} `json:"data"`
		}
		if err := json.Unmarshal([]byte(emb.Body), &parsed); err != nil {
			t.Fatalf("parse embeddings reply: %v", err)
		}
		if len(parsed.Data) != 2 || len(parsed.Data[0].Embedding) != 5 {
			t.Errorf("embeddings reply has %d vectors, first has %d numbers, want 2 and 5",
				len(parsed.Data), len(parsed.Data[0].Embedding))
		}
	})

	t.Run("responses_call_reaches_an_openai_backend", func(t *testing.T) {
		const input = `[{"role":"user","content":"scan 10.0.0.5 %s"},` +
			`{"type":"function_call","call_id":"call_1","name":"nmap","arguments":"{\"target\":\"10.0.0.5\"}"},` +
			`{"type":"function_call_output","call_id":"call_1","output":"open ports: 22/tcp ssh, 80/tcp http"}]`
		for _, c := range []struct{ name, marker, stream string }{
			{"responses_plain", "marker-responses-1", "false"},
			{"responses_stream", "marker-responses-2", "true"},
		} {
			body := fmt.Sprintf(`{"model":"gpt-fixture","stream":%s,"input":`+input+`}`, c.stream, c.marker)
			got := gw.call(t, http.MethodPost, "/v1/responses", "tenant-e", tokenE, body)
			if got.Status != http.StatusOK || !strings.Contains(got.Body, "function_call") {
				t.Fatalf("%s: status %d, body %s", c.name, got.Status, got.Body)
			}
			dumpSpan(t, c.name, otlp.waitSpan(t, c.marker))
		}
	})

	t.Run("c_token_of_tenant_a_on_the_route_of_tenant_b_gets_403", func(t *testing.T) {
		before := countPath(provider, "/v1/messages")
		got := gw.call(t, http.MethodPost, "/v1/messages", "tenant-b", tokenA, messagesBody(Model, "marker-cross", false))
		if got.Status != http.StatusForbidden {
			t.Errorf("status = %d, want 403", got.Status)
		}
		if after := countPath(provider, "/v1/messages"); after != before {
			t.Errorf("provider got %d new request, want 0", after-before)
		}
		// The token of tenant B on its own route still works.
		ok := gw.call(t, http.MethodPost, "/v1/messages", "tenant-b", tokenB, messagesBody(Model, "marker-b", false))
		if ok.Status != http.StatusOK {
			t.Errorf("tenant B on its own route: status %d, want 200", ok.Status)
		}
	})

	t.Run("d_forbidden_model_gets_403_and_the_provider_gets_no_request", func(t *testing.T) {
		before := len(provider.Requests())
		got := gw.call(t, http.MethodPost, "/v1/messages", "tenant-a", tokenA,
			messagesBody(forbiddenModel, "marker-forbidden", false))
		if got.Status != http.StatusForbidden {
			t.Errorf("status = %d, want 403", got.Status)
		}
		if after := len(provider.Requests()); after != before {
			t.Errorf("provider got %d new request, want 0", after-before)
		}
	})

	t.Run("e_authorization_service_down_gives_403", func(t *testing.T) {
		before := len(provider.Requests())
		authzSrv.Close()
		got := gw.call(t, http.MethodPost, "/v1/messages", "tenant-a", tokenA, messagesBody(Model, "marker-down", false))
		if got.Status != http.StatusForbidden {
			t.Errorf("status = %d, want 403", got.Status)
		}
		if after := len(provider.Requests()); after != before {
			t.Errorf("provider got %d new request, want 0", after-before)
		}
	})
}
