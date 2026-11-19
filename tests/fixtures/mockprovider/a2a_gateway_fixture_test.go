// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build agentgateway_fixture

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
)

// This test sends A2A v1.0 calls through agentgateway to a small A2A agent. The
// agent uses the a2a-go v2 server. The test tries the JSON-RPC binding and the
// HTTP+JSON binding, and it asks for the Agent Card. It runs under the same
// build tag and binary as TestGatewayFixture. The result is recorded in
// .scratch/slices/a2a-gateway-proof.md.

const a2aConfigTemplate = `config:
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
        gibson.route_agent: request.headers["x-gibson-route-agent"]
frontendPolicies:
  http:
    maxBufferSize: 20971520
binds:
- port: {{.Port}}
  listeners:
  - routes:
    - name: a2a-agent
      matches:
      - path:
          pathPrefix: /
      backends:
      - host: {{.Agent}}
      policies:
        a2a: {}
`

// echoAgent answers each message with one agent message that echoes the text.
type echoAgent struct{}

func (echoAgent) Execute(_ context.Context, execCtx *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) {
		text := ""
		if execCtx.Message != nil {
			for _, p := range execCtx.Message.Parts {
				text += p.Text()
			}
		}
		yield(a2a.NewMessage(a2a.MessageRoleAgent, a2a.NewTextPart("echo: "+text)), nil)
	}
}

func (echoAgent) Cancel(_ context.Context, execCtx *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) {
		yield(a2a.NewStatusUpdateEvent(execCtx, a2a.TaskStateCanceled, nil), nil)
	}
}

// startA2AAgent serves the agent card, the JSON-RPC binding on /jsonrpc and the
// HTTP+JSON binding under /rest.
func startA2AAgent(t *testing.T) *httptest.Server {
	t.Helper()
	handler := a2asrv.NewHandler(echoAgent{})
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.Handle(a2asrv.WellKnownAgentCardPath, a2asrv.NewAgentCardHandler(
		a2asrv.AgentCardProducerFn(func(context.Context) (*a2a.AgentCard, error) {
			base := srv.URL
			return &a2a.AgentCard{
				Name:        "Echo Agent",
				Description: "Echoes each message.",
				Version:     "1.0.0",
				SupportedInterfaces: []*a2a.AgentInterface{
					a2a.NewAgentInterface(base+"/jsonrpc", a2a.TransportProtocolJSONRPC),
					a2a.NewAgentInterface(base+"/rest", a2a.TransportProtocolHTTPJSON),
				},
				DefaultInputModes:  []string{"text/plain"},
				DefaultOutputModes: []string{"text/plain"},
				Skills:             []a2a.AgentSkill{{ID: "echo", Name: "Echo", Description: "Echo", Tags: []string{"echo"}}},
			}, nil
		})))
	mux.Handle("/jsonrpc", a2asrv.NewJSONRPCHandler(handler))
	mux.Handle("/rest/", http.StripPrefix("/rest", a2asrv.NewRESTHandler(handler)))
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func a2aRequest(t *testing.T, method, url, body string) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("A2A-Version", "1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("call %s %s: %v", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read reply of %s %s: %v", method, url, err)
	}
	return resp.StatusCode, resp.Header, string(data)
}

func TestA2AThroughGateway(t *testing.T) {
	bin := os.Getenv("AGENTGATEWAY_BIN")
	if bin == "" {
		t.Fatal("AGENTGATEWAY_BIN is not set. Set it to the path of an agentgateway binary.")
	}
	agent := startA2AAgent(t)
	otlp := &otlpReceiver{}
	otlpSrv := httptest.NewServer(otlp)
	defer otlpSrv.Close()
	gw := startGateway(t, bin, a2aConfigTemplate, map[string]any{"Agent": hostOf(agent), "OTLP": hostOf(otlpSrv)})

	msg := a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("hello"))
	sendBody, err := json.Marshal(&a2a.SendMessageRequest{Message: msg})
	if err != nil {
		t.Fatalf("marshal SendMessageRequest: %v", err)
	}

	t.Run("agent_card", func(t *testing.T) {
		status, _, body := a2aRequest(t, http.MethodGet, gw.base+a2asrv.WellKnownAgentCardPath, "")
		t.Logf("agent card: status %d, body %s", status, body)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		var card map[string]any
		if err := json.Unmarshal([]byte(body), &card); err != nil {
			t.Fatalf("parse card: %v", err)
		}
		if card["name"] != "Echo Agent" {
			t.Errorf("card name = %v, want Echo Agent", card["name"])
		}
		// The gateway rewrites each interface URL to its own address.
		if strings.Contains(body, hostOf(agent)) {
			t.Errorf("card still holds the agent address %s", hostOf(agent))
		}
		if !strings.Contains(body, strings.TrimPrefix(gw.base, "http://")) {
			t.Errorf("card holds no gateway address %s", gw.base)
		}
	})

	t.Run("jsonrpc_send_message", func(t *testing.T) {
		rpc := fmt.Sprintf(`{"jsonrpc":"2.0","id":"1","method":"SendMessage","params":%s}`, sendBody)
		status, _, body := a2aRequest(t, http.MethodPost, gw.base+"/jsonrpc", rpc)
		t.Logf("jsonrpc SendMessage: status %d, body %s", status, body)
		if status != http.StatusOK || !strings.Contains(body, "echo: hello") || strings.Contains(body, `"error"`) {
			t.Fatalf("jsonrpc reply: status %d, body %s", status, body)
		}
	})

	t.Run("jsonrpc_streaming_message", func(t *testing.T) {
		rpc := fmt.Sprintf(`{"jsonrpc":"2.0","id":"2","method":"SendStreamingMessage","params":%s}`, sendBody)
		status, header, body := a2aRequest(t, http.MethodPost, gw.base+"/jsonrpc", rpc)
		t.Logf("jsonrpc SendStreamingMessage: status %d, content-type %s, body %s",
			status, header.Get("Content-Type"), body)
		if status != http.StatusOK || !strings.Contains(body, "echo: hello") {
			t.Fatalf("streaming reply: status %d, body %s", status, body)
		}
	})

	t.Run("http_json_send_message", func(t *testing.T) {
		status, _, body := a2aRequest(t, http.MethodPost, gw.base+"/rest/message:send", string(sendBody))
		t.Logf("http+json message:send: status %d, body %s", status, body)
		if status != http.StatusOK || !strings.Contains(body, "echo: hello") {
			t.Fatalf("http+json reply: status %d, body %s", status, body)
		}
	})

	// The span of an A2A call. The call carries the trusted headers that
	// ext-authz sets and the route headers of the caller. The span is the one
	// source of the record of a delegation to an outside agent. The test dumps
	// it to $GATEWAY_SPAN_DUMP_DIR when the variable is set.
	t.Run("span_of_a_call", func(t *testing.T) {
		const marker = "span-marker-1"
		rpcMsg := a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart(marker))
		body, err := json.Marshal(&a2a.SendMessageRequest{Message: rpcMsg})
		if err != nil {
			t.Fatalf("marshal SendMessageRequest: %v", err)
		}
		rpc := fmt.Sprintf(`{"jsonrpc":"2.0","id":"3","method":"SendMessage","params":%s}`, body)
		req, err := http.NewRequest(http.MethodPost, gw.base+"/jsonrpc", strings.NewReader(rpc))
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("A2A-Version", "1.0")
		for k, v := range map[string]string{
			"x-gibson-tenant": "tenant-a", "x-gibson-subject": "user:u1", "x-gibson-mission": "m-1",
			"x-gibson-task": "task-1", "x-gibson-route-agent": "partner-scout",
		} {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("send: %v", err)
		}
		_ = resp.Body.Close()
		sp := otlp.waitSpan(t, marker)
		dumpSpan(t, "a2a_send_message", sp)
		t.Logf("a2a span %q attributes: %v", sp.Name, sp.All)
	})
}
