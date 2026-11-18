// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build agentgateway_fixture

package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

// This test proves where the gateway puts the facts of a model call in the gRPC
// CheckRequest that it sends to ext-authz (gibson#1388):
//
//   - the fixed tenant and provider of the route, in context_extensions;
//   - the exact model name, in metadata_context.filter_metadata;
//   - the x-capability-grant header, the path and the method.
//
// It also proves that the headers of the allow reply replace a copy from the
// caller, and that a header on headers_to_remove does not reach the provider.
// The key names match internal/server/extauthz/modelcall.

const grpcAuthzConfigTemplate = `config:
  logging:
    format: json
  readinessAddr: {{.Readiness}}
  statsAddr: {{.Stats}}
  adminAddr: {{.Admin}}
binds:
- port: {{.Port}}
  listeners:
  - routes:
    - name: tenant-a-anthropic
      backends:
      - ai:
          name: tenant-a-anthropic-backend
          provider:
            openAI: {}
          hostOverride: {{.Provider}}
      policies:
        ai:
          routes:
            /v1/responses: responses
            /v1/models: passthrough
        backendAuth:
          key: key-of-tenant-a
        extAuthz:
          host: {{.Authz}}
          includeRequestHeaders: ["x-capability-grant", "x-gibson-subject", "x-gibson-mission", ":path", ":method"]
          protocol:
            grpc:
              context:
                gibson-tenant: tenant-a
                gibson-provider: anthropic
              metadata:
                gibson: '{"model": json(request.body).model}'
`

// recordingAuthz is a gRPC ext-authz service. It records each CheckRequest and
// allows it, with the four trusted headers and one header to remove.
type recordingAuthz struct {
	authv3.UnimplementedAuthorizationServer
	mu   sync.Mutex
	reqs []*authv3.CheckRequest
}

func (a *recordingAuthz) Check(_ context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	a.mu.Lock()
	a.reqs = append(a.reqs, req)
	a.mu.Unlock()
	opt := func(k, v string) *corev3.HeaderValueOption {
		return &corev3.HeaderValueOption{
			Header:       &corev3.HeaderValue{Key: k, Value: v},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		}
	}
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{OkResponse: &authv3.OkHttpResponse{
			Headers: []*corev3.HeaderValueOption{
				opt("x-gibson-tenant", "tenant-a"), opt("x-gibson-subject", "component:agent:claude"),
			},
			HeadersToRemove: []string{"x-gibson-mission"},
		}},
	}, nil
}

func (a *recordingAuthz) requests() []*authv3.CheckRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]*authv3.CheckRequest(nil), a.reqs...)
}

func TestExtAuthzGRPCCheckRequestFields(t *testing.T) {
	bin := os.Getenv("AGENTGATEWAY_BIN")
	if bin == "" {
		t.Fatal("AGENTGATEWAY_BIN is not set. Set it to the path of an agentgateway binary.")
	}
	provider := &Provider{}
	providerSrv := httptest.NewServer(provider)
	defer providerSrv.Close()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for ext-authz: %v", err)
	}
	authz := &recordingAuthz{}
	grpcSrv := grpc.NewServer()
	authv3.RegisterAuthorizationServer(grpcSrv, authz)
	go func() { _ = grpcSrv.Serve(lis) }()
	defer grpcSrv.Stop()

	gw := startGateway(t, bin, grpcAuthzConfigTemplate, map[string]any{
		"Provider": hostOf(providerSrv), "Authz": lis.Addr().String(),
	})

	body := `{"model":"claude-sonnet-5-5","input":"scan 10.0.0.5"}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, gw.base+"/v1/responses",
		strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Capability-Grant", "grant-token")
	req.Header.Set("X-Gibson-Subject", "forged-admin")
	req.Header.Set("X-Gibson-Mission", "forged-mission")
	req.Header.Set("X-Gibson-Task", "kept-because-ext-authz-does-not-touch-it")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("call the gateway: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	reqs := authz.requests()
	if len(reqs) != 1 {
		t.Fatalf("ext-authz got %d requests, want 1", len(reqs))
	}
	attrs := reqs[0].GetAttributes()
	t.Logf("context_extensions = %v", attrs.GetContextExtensions())
	t.Logf("filter_metadata = %v", attrs.GetMetadataContext().GetFilterMetadata())
	t.Logf("path = %q, method = %q", attrs.GetRequest().GetHttp().GetPath(), attrs.GetRequest().GetHttp().GetMethod())

	if got := attrs.GetContextExtensions()["gibson-tenant"]; got != "tenant-a" {
		t.Errorf("context_extensions[gibson-tenant] = %q, want tenant-a", got)
	}
	if got := attrs.GetContextExtensions()["gibson-provider"]; got != "anthropic" {
		t.Errorf("context_extensions[gibson-provider] = %q, want anthropic", got)
	}
	model := attrs.GetMetadataContext().GetFilterMetadata()["gibson"].GetFields()["model"].GetStringValue()
	if model != "claude-sonnet-5-5" {
		t.Errorf("filter_metadata[gibson].model = %q, want claude-sonnet-5-5", model)
	}
	if got := attrs.GetRequest().GetHttp().GetPath(); got != "/v1/responses" {
		t.Errorf("path = %q, want /v1/responses", got)
	}
	if got := attrs.GetRequest().GetHttp().GetHeaders()["x-capability-grant"]; got != "grant-token" {
		t.Errorf("x-capability-grant = %q, want grant-token", got)
	}

	// The provider got the values of ext-authz, and not the copies of the caller.
	var seen bool
	for _, r := range provider.Requests() {
		if r.Path != "/v1/responses" {
			continue
		}
		seen = true
		if got := r.Header.Get("X-Gibson-Subject"); got != "component:agent:claude" {
			t.Errorf("provider x-gibson-subject = %q, want the value of ext-authz", got)
		}
		if got := r.Header.Get("X-Gibson-Tenant"); got != "tenant-a" {
			t.Errorf("provider x-gibson-tenant = %q, want tenant-a", got)
		}
		if got := r.Header.Get("X-Gibson-Mission"); got != "" {
			t.Errorf("provider x-gibson-mission = %q, want it removed", got)
		}
		t.Logf("provider x-gibson-task = %q (ext-authz did not set it)", r.Header.Get("X-Gibson-Task"))
	}
	if !seen {
		t.Error("the provider got no /v1/responses request")
	}
}
