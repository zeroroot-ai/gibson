// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package modelclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

type fakeGrants struct {
	token   string
	err     error
	callers []Caller
}

func (f *fakeGrants) Grant(_ context.Context, c Caller) (string, error) {
	f.callers = append(f.callers, c)
	return f.token, f.err
}

var (
	testTarget = Target{Tenant: "acme", Provider: "claude", Model: "claude-sonnet-4-5"}
	testCaller = Caller{Tenant: "acme", Mission: "m1", Task: "t1", Initiator: "user:u1", Purpose: "brain-decider"}
)

// gateway starts a test gateway. The handler receives each request, and the
// request body is read before the handler runs.
func gateway(t *testing.T, h func(w http.ResponseWriter, r *http.Request, body []byte)) (*Client, *fakeGrants) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		h(w, r, b)
	}))
	t.Cleanup(srv.Close)
	grants := &fakeGrants{token: "grant-token"}
	c, err := New(Config{BaseURL: srv.URL, Grants: grants})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, grants
}

const plainReply = `{"id":"resp_1","status":"completed","model":"claude-sonnet-4-5",
"output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hello"}]}],
"usage":{"input_tokens":11,"output_tokens":3,"total_tokens":14,"input_tokens_details":{"cached_tokens":2}}}`

func TestRespond_PlainCall(t *testing.T) {
	var gotPath, gotBody string
	var gotHeader http.Header
	c, grants := gateway(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		gotPath, gotBody, gotHeader = r.URL.Path, string(body), r.Header.Clone()
		_, _ = io.WriteString(w, plainReply)
	})
	resp, err := c.Respond(context.Background(), testCaller, testTarget, Request{
		Instructions: "be brief",
		Input:        []Item{UserMessage("hi")},
	})
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if resp.OutputText() != "hello" || resp.Usage.InputTokens != 11 || resp.Usage.InputTokensDetails.CachedTokens != 2 {
		t.Errorf("response = %+v", resp)
	}
	if gotPath != modelcall.RouteResponses {
		t.Errorf("path = %q", gotPath)
	}
	for _, h := range modelcall.RouteHeaders("acme", "claude") {
		if gotHeader.Get(h.Name) != h.Value {
			t.Errorf("header %s = %q, want %q", h.Name, gotHeader.Get(h.Name), h.Value)
		}
	}
	if gotHeader.Get(HeaderCapabilityGrant) != "grant-token" {
		t.Errorf("grant header = %q", gotHeader.Get(HeaderCapabilityGrant))
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(gotBody), &sent); err != nil {
		t.Fatalf("the request body is not JSON: %v", err)
	}
	if sent["model"] != "claude-sonnet-4-5" || sent["stream"] != nil {
		t.Errorf("request = %v, want the exact model and no stream", sent)
	}
	if len(grants.callers) != 1 || grants.callers[0].Mission != "m1" {
		t.Errorf("grant callers = %+v", grants.callers)
	}
}

func TestRespond_ToolsAndToolCallRoundTrip(t *testing.T) {
	call := `{"id":"r","status":"completed","model":"m","output":[
{"type":"reasoning","id":"rs_1","summary":[]},
{"type":"function_call","call_id":"c1","name":"nmap","arguments":"{\"host\":\"a\"}"}],"usage":{}}`
	var bodies []string
	c, _ := gateway(t, func(w http.ResponseWriter, _ *http.Request, body []byte) {
		bodies = append(bodies, string(body))
		if len(bodies) == 1 {
			_, _ = io.WriteString(w, call)
			return
		}
		_, _ = io.WriteString(w, plainReply)
	})
	schema := json.RawMessage(`{"type":"object","properties":{"host":{"type":"string"}}}`)
	req := Request{
		Input: []Item{UserMessage("scan a")},
		Tools: []Tool{FunctionTool("nmap", "scan a host", schema)},
	}
	first, err := c.Respond(context.Background(), testCaller, testTarget, req)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	calls := first.FunctionCalls()
	if len(calls) != 1 || calls[0].Name != "nmap" || calls[0].CallID != "c1" {
		t.Fatalf("function calls = %+v", calls)
	}
	// The next call replays the output items of the model, then the tool result.
	req.Input = append(req.Input, first.Output...)
	req.Input = append(req.Input, FunctionCallOutput("c1", "open: 22"))
	if _, err := c.Respond(context.Background(), testCaller, testTarget, req); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if !strings.Contains(bodies[0], `"tools":[{"type":"function","name":"nmap"`) {
		t.Errorf("first body has no tool: %s", bodies[0])
	}
	// The reasoning item goes back with its exact bytes.
	if !strings.Contains(bodies[1], `{"type":"reasoning","id":"rs_1","summary":[]}`) {
		t.Errorf("the reasoning item changed: %s", bodies[1])
	}
	if !strings.Contains(bodies[1], `"type":"function_call_output","call_id":"c1","output":"open: 22"`) {
		t.Errorf("the tool result is missing: %s", bodies[1])
	}
}

func TestRespond_StructuredOutput(t *testing.T) {
	var body string
	c, _ := gateway(t, func(w http.ResponseWriter, _ *http.Request, b []byte) {
		body = string(b)
		_, _ = io.WriteString(w, strings.Replace(plainReply, `"text":"hello"`, `"text":"{\"ok\":true}"`, 1))
	})
	schema := json.RawMessage(`{"type":"object","properties":{"ok":{"type":"boolean"}},"required":["ok"]}`)
	resp, err := c.Respond(context.Background(), testCaller, testTarget, Request{
		Input: []Item{UserMessage("go")},
		Text:  JSONSchemaFormat("answer", schema),
	})
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if resp.OutputText() != `{"ok":true}` {
		t.Errorf("text = %q", resp.OutputText())
	}
	if !strings.Contains(body, `"text":{"format":{"type":"json_schema","name":"answer"`) {
		t.Errorf("body has no format: %s", body)
	}
}

func TestStream_TextAndFinalResponse(t *testing.T) {
	sse := "event: response.created\ndata: {\"type\":\"response.created\"}\n\n" +
		"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hel\"}\n\n" +
		": keep-alive\n\n" +
		"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"lo\"}\n\n" +
		"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":" +
		strings.Join(strings.Fields(plainReply), " ") + "}\n\n" +
		"data: [DONE]\n\n"
	var body string
	c, _ := gateway(t, func(w http.ResponseWriter, r *http.Request, b []byte) {
		body = string(b)
		if r.Header.Get("Accept") != "text/event-stream" {
			t.Errorf("accept = %q", r.Header.Get("Accept"))
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, sse)
	})
	s, err := c.Stream(context.Background(), testCaller, testTarget, Request{Input: []Item{UserMessage("hi")}})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	defer s.Close()
	var text strings.Builder
	var final *Response
	for s.Next() {
		ev := s.Event()
		text.WriteString(ev.Delta)
		if ev.Response != nil {
			final = ev.Response
		}
	}
	if err := s.Err(); err != nil {
		t.Fatalf("Err: %v", err)
	}
	if text.String() != "hello" {
		t.Errorf("text = %q", text.String())
	}
	if final == nil || final.Usage.OutputTokens != 3 {
		t.Errorf("final = %+v", final)
	}
	if !strings.Contains(body, `"stream":true`) {
		t.Errorf("body has no stream flag: %s", body)
	}
}

func TestStream_FailureEvent(t *testing.T) {
	c, _ := gateway(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		_, _ = io.WriteString(w, "data: {\"type\":\"error\",\"code\":\"overloaded\",\"message\":\"busy\"}\n\n")
	})
	s, err := c.Stream(context.Background(), testCaller, testTarget, Request{Input: []Item{UserMessage("hi")}})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	defer s.Close()
	for s.Next() {
	}
	var f *ResponseFailure
	if !errors.As(s.Err(), &f) || f.Code != "overloaded" {
		t.Fatalf("Err = %v, want a ResponseFailure", s.Err())
	}
}

func TestRespond_GatewayRefusals(t *testing.T) {
	cases := map[int]struct{ refused, noRoute, retry bool }{
		http.StatusForbidden:          {refused: true},
		http.StatusUnauthorized:       {refused: true},
		http.StatusNotFound:           {noRoute: true, retry: true},
		http.StatusTooManyRequests:    {retry: true},
		http.StatusBadGateway:         {retry: true},
		http.StatusBadRequest:         {},
		http.StatusServiceUnavailable: {retry: true},
	}
	for code, want := range cases {
		c, _ := gateway(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
			w.WriteHeader(code)
			_, _ = io.WriteString(w, "denied by policy")
		})
		_, err := c.Respond(context.Background(), testCaller, testTarget, Request{Input: []Item{UserMessage("hi")}})
		var ae *APIError
		if !errors.As(err, &ae) || ae.Status != code {
			t.Fatalf("status %d: err = %v", code, err)
		}
		if ae.Refused() != want.refused || ae.NoRoute() != want.noRoute || ae.Retryable() != want.retry {
			t.Errorf("status %d: refused=%v noRoute=%v retryable=%v", code, ae.Refused(), ae.NoRoute(), ae.Retryable())
		}
		if !strings.Contains(ae.Body, "denied by policy") {
			t.Errorf("status %d: body = %q", code, ae.Body)
		}
	}
}

func TestRespond_BadTargetsAndCallers(t *testing.T) {
	called := false
	c, grants := gateway(t, func(http.ResponseWriter, *http.Request, []byte) { called = true })
	in := Request{Input: []Item{UserMessage("hi")}}
	cases := map[string]struct {
		caller Caller
		target Target
	}{
		"no model":        {testCaller, Target{Tenant: "acme", Provider: "claude"}},
		"no provider":     {testCaller, Target{Tenant: "acme", Model: "m"}},
		"no tenant":       {testCaller, Target{Provider: "claude", Model: "m"}},
		"tenant mismatch": {Caller{Tenant: "other", Mission: "m", Task: "t", Purpose: "p"}, testTarget},
	}
	for name, tc := range cases {
		if _, err := c.Respond(context.Background(), tc.caller, tc.target, in); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if called || len(grants.callers) != 0 {
		t.Error("a bad call reached the grant source or the gateway")
	}
}

func TestRespond_GrantErrorStopsTheCall(t *testing.T) {
	called := false
	c, grants := gateway(t, func(http.ResponseWriter, *http.Request, []byte) { called = true })
	grants.err = ErrNoMissionScope
	_, err := c.Respond(context.Background(), testCaller, testTarget, Request{Input: []Item{UserMessage("hi")}})
	if !errors.Is(err, ErrNoMissionScope) {
		t.Fatalf("err = %v", err)
	}
	if called {
		t.Error("the call reached the gateway without a grant")
	}
}

func TestRespond_FailedResponseObject(t *testing.T) {
	c, _ := gateway(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		_, _ = io.WriteString(w, `{"id":"r","status":"failed","error":{"code":"context_length","message":"too long"}}`)
	})
	_, err := c.Respond(context.Background(), testCaller, testTarget, Request{Input: []Item{UserMessage("hi")}})
	var f *ResponseFailure
	if !errors.As(err, &f) || f.Code != "context_length" {
		t.Fatalf("err = %v", err)
	}
}

func TestNew_RequiresItsParts(t *testing.T) {
	if _, err := New(Config{Grants: &fakeGrants{}}); err == nil {
		t.Error("no URL was accepted")
	}
	if _, err := New(Config{BaseURL: "http://x"}); err == nil {
		t.Error("no grant source was accepted")
	}
}

type fakeMinter struct {
	got capabilitygrant.MintRequest
}

func (m *fakeMinter) Mint(r capabilitygrant.MintRequest) (string, error) {
	m.got = r
	return "signed", nil
}

func TestMinterGrants(t *testing.T) {
	m := &fakeMinter{}
	g, err := NewMinterGrants(m)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := g.Grant(context.Background(), testCaller)
	if err != nil || tok != "signed" {
		t.Fatalf("Grant = %q, %v", tok, err)
	}
	r := m.got
	if r.Tenant != "acme" || r.MissionID != "m1" || r.TaskID != "t1" || r.Initiator != "user:u1" {
		t.Errorf("mint request = %+v", r)
	}
	want := map[string]bool{
		modelcall.RouteResponses: true, modelcall.RouteEmbeddings: true, modelcall.RouteModels: true,
	}
	if len(r.AllowedRPCs) != len(want) {
		t.Errorf("allowed = %v", r.AllowedRPCs)
	}
	for _, p := range r.AllowedRPCs {
		if !want[p] {
			t.Errorf("the grant lists %q", p)
		}
	}
	if r.TTL <= 0 || r.TTL > grantTTL {
		t.Errorf("ttl = %v", r.TTL)
	}
	// No mission, no grant.
	if _, err := g.Grant(context.Background(), Caller{Tenant: "acme", Purpose: "x"}); !errors.Is(err, ErrNoMissionScope) {
		t.Errorf("a call with no mission: %v", err)
	}
}
