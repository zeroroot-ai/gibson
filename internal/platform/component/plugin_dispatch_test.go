// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/zeroroot-ai/gibson/internal/engine/harness/dispatchpolicy"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	pluginpb "github.com/zeroroot-ai/sdk/api/gen/gibson/plugin/v1"
	"github.com/zeroroot-ai/sdk/auth"
	pluginmanifest "github.com/zeroroot-ai/sdk/plugin/manifest"
)

// ---------------------------------------------------------------------------
// fakeComponentInstallRegistry is a test double for ComponentInstallRegistry.
// ---------------------------------------------------------------------------

type fakeComponentInstallRegistry struct {
	installs     map[string][]InstallInfo // key: tenantID+"/"+componentName
	dispatchFunc func(ctx context.Context, tenant auth.TenantID, name, method string, payload []byte, deadline time.Duration) ([]byte, error)
}

func newFakeComponentInstallRegistry() *fakeComponentInstallRegistry {
	return &fakeComponentInstallRegistry{
		installs: make(map[string][]InstallInfo),
	}
}

func (f *fakeComponentInstallRegistry) Register(_ context.Context, _ *ComponentInstall) error {
	return nil
}

func (f *fakeComponentInstallRegistry) Heartbeat(_ context.Context, _, _ string) error {
	return nil
}

func (f *fakeComponentInstallRegistry) ListInstalls(_ context.Context, tenant auth.TenantID, name string) ([]InstallInfo, error) {
	key := tenant.String() + "/" + name
	return f.installs[key], nil
}

func (f *fakeComponentInstallRegistry) DispatchOne(ctx context.Context, tenant auth.TenantID, name, method string, payload []byte, deadline time.Duration) ([]byte, error) {
	if f.dispatchFunc != nil {
		return f.dispatchFunc(ctx, tenant, name, method, payload, deadline)
	}
	// Default: Go-first plugins submit raw JSON verbatim via SubmitResult.
	// An empty JSON object models a method that returns no body.
	return []byte("{}"), nil
}

func (f *fakeComponentInstallRegistry) Status(_ context.Context, tenant auth.TenantID, name string) (RegistryStatus, error) {
	key := tenant.String() + "/" + name
	return RegistryStatus{Installs: f.installs[key]}, nil
}

func (f *fakeComponentInstallRegistry) addInstall(tenant auth.TenantID, name string, methods []string) {
	key := tenant.String() + "/" + name
	f.installs[key] = append(f.installs[key], InstallInfo{
		InstallID:       fmt.Sprintf("install-%s-%s-%d", tenant.String(), name, len(f.installs[key])),
		TenantID:        tenant,
		Name:            name,
		DeclaredMethods: methods,
		Status:          ComponentInstallStatusServing,
	})
}

// ---------------------------------------------------------------------------
// buildPluginInvokeCtx builds a context with a service-credential identity.
// ---------------------------------------------------------------------------

func buildPluginInvokeCtx(tenantStr string) context.Context {
	ctx := context.Background()
	tenant := auth.MustNewTenantID(tenantStr)
	ctx = auth.ContextWithTenant(ctx, tenant)
	id := auth.Identity{
		Subject:        "tool-subject-1",
		Issuer:         auth.IssuerOIDC,
		CredentialType: auth.CredentialClientCredentials,
		Tenant:         tenant,
	}
	ctx = auth.WithIdentity(ctx, id)
	return ctx
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestPluginInvokeService_HappyPath(t *testing.T) {
	tenant := auth.MustNewTenantID("tenant-abc")
	reg := newFakeComponentInstallRegistry()
	reg.addInstall(tenant, "lookup", []string{"search", "host"})

	// Dispatch returns raw JSON, mirroring a Go-first plugin's SubmitResult.
	reg.dispatchFunc = func(ctx context.Context, ten auth.TenantID, name, method string, payload []byte, deadline time.Duration) ([]byte, error) {
		return []byte("{}"), nil // empty success
	}

	svc := NewPluginInvokeService(reg, dispatchpolicy.ShapeSetecOnly, nil).WithAuthorizer(allowInvokeAuthz)
	ctx := buildPluginInvokeCtx("tenant-abc")

	resp, err := svc.PluginInvoke(ctx, &pluginpb.PluginInvokeRequest{
		PluginName: "lookup",
		Method:     "search",
		DeadlineMs: 5000,
	})

	if err != nil {
		t.Fatalf("unexpected gRPC error: %v", err)
	}
	if resp.GetError() != nil {
		t.Errorf("expected no plugin error, got: %v", resp.GetError())
	}
}

func TestPluginInvokeService_UNAVAILABLE_NoInstalls(t *testing.T) {
	reg := newFakeComponentInstallRegistry() // no installs registered
	svc := NewPluginInvokeService(reg, dispatchpolicy.ShapeSetecOnly, nil).WithAuthorizer(allowInvokeAuthz)
	ctx := buildPluginInvokeCtx("tenant-abc")

	resp, err := svc.PluginInvoke(ctx, &pluginpb.PluginInvokeRequest{
		PluginName: "lookup",
		Method:     "search",
	})
	if err != nil {
		t.Fatalf("unexpected gRPC error: %v", err)
	}
	if resp.GetError() == nil {
		t.Fatal("expected plugin error, got nil")
	}
	if resp.GetError().GetKind() != pluginpb.PluginError_PLUGIN_ERROR_KIND_UNAVAILABLE {
		t.Errorf("expected UNAVAILABLE, got %v", resp.GetError().GetKind())
	}
}

func TestPluginInvokeService_METHOD_NOT_FOUND(t *testing.T) {
	tenant := auth.MustNewTenantID("tenant-abc")
	reg := newFakeComponentInstallRegistry()
	reg.addInstall(tenant, "lookup", []string{"search"}) // only "search" declared

	svc := NewPluginInvokeService(reg, dispatchpolicy.ShapeSetecOnly, nil).WithAuthorizer(allowInvokeAuthz)
	ctx := buildPluginInvokeCtx("tenant-abc")

	resp, err := svc.PluginInvoke(ctx, &pluginpb.PluginInvokeRequest{
		PluginName: "lookup",
		Method:     "nonexistent",
	})
	if err != nil {
		t.Fatalf("unexpected gRPC error: %v", err)
	}
	if resp.GetError().GetKind() != pluginpb.PluginError_PLUGIN_ERROR_KIND_METHOD_NOT_FOUND {
		t.Errorf("expected METHOD_NOT_FOUND, got %v", resp.GetError().GetKind())
	}
}

func TestPluginInvokeService_DEADLINE_EXCEEDED(t *testing.T) {
	tenant := auth.MustNewTenantID("tenant-abc")
	reg := newFakeComponentInstallRegistry()
	reg.addInstall(tenant, "lookup", []string{"search"})

	reg.dispatchFunc = func(_ context.Context, _ auth.TenantID, _, _ string, _ []byte, _ time.Duration) ([]byte, error) {
		return nil, fmt.Errorf("timeout waiting for work abc: %w", context.DeadlineExceeded)
	}

	svc := NewPluginInvokeService(reg, dispatchpolicy.ShapeSetecOnly, nil).WithAuthorizer(allowInvokeAuthz)
	ctx := buildPluginInvokeCtx("tenant-abc")

	resp, err := svc.PluginInvoke(ctx, &pluginpb.PluginInvokeRequest{
		PluginName: "lookup",
		Method:     "search",
		DeadlineMs: 100,
	})
	if err != nil {
		t.Fatalf("unexpected gRPC error: %v", err)
	}
	if resp.GetError().GetKind() != pluginpb.PluginError_PLUGIN_ERROR_KIND_DEADLINE_EXCEEDED {
		t.Errorf("expected DEADLINE_EXCEEDED, got %v", resp.GetError().GetKind())
	}
}

func TestPluginInvokeService_HANDLER_FAILED(t *testing.T) {
	tenant := auth.MustNewTenantID("tenant-abc")
	reg := newFakeComponentInstallRegistry()
	reg.addInstall(tenant, "lookup", []string{"search"})

	reg.dispatchFunc = func(_ context.Context, _ auth.TenantID, _, _ string, _ []byte, _ time.Duration) ([]byte, error) {
		return nil, &PluginWorkError{Code: "HANDLER_FAILED", Message: "handler panicked"}
	}

	svc := NewPluginInvokeService(reg, dispatchpolicy.ShapeSetecOnly, nil).WithAuthorizer(allowInvokeAuthz)
	ctx := buildPluginInvokeCtx("tenant-abc")

	resp, err := svc.PluginInvoke(ctx, &pluginpb.PluginInvokeRequest{
		PluginName: "lookup",
		Method:     "search",
	})
	if err != nil {
		t.Fatalf("unexpected gRPC error: %v", err)
	}
	if resp.GetError().GetKind() != pluginpb.PluginError_PLUGIN_ERROR_KIND_HANDLER_FAILED {
		t.Errorf("expected HANDLER_FAILED, got %v", resp.GetError().GetKind())
	}
}

func TestPluginInvokeService_UNAVAILABLE_RegistryError(t *testing.T) {
	tenant := auth.MustNewTenantID("tenant-abc")
	reg := newFakeComponentInstallRegistry()
	reg.addInstall(tenant, "lookup", []string{"search"})

	reg.dispatchFunc = func(_ context.Context, _ auth.TenantID, _, _ string, _ []byte, _ time.Duration) ([]byte, error) {
		return nil, ErrComponentUnavailable
	}

	svc := NewPluginInvokeService(reg, dispatchpolicy.ShapeSetecOnly, nil).WithAuthorizer(allowInvokeAuthz)
	ctx := buildPluginInvokeCtx("tenant-abc")

	resp, err := svc.PluginInvoke(ctx, &pluginpb.PluginInvokeRequest{
		PluginName: "lookup",
		Method:     "search",
	})
	if err != nil {
		t.Fatalf("unexpected gRPC error: %v", err)
	}
	if resp.GetError().GetKind() != pluginpb.PluginError_PLUGIN_ERROR_KIND_UNAVAILABLE {
		t.Errorf("expected UNAVAILABLE, got %v", resp.GetError().GetKind())
	}
}

func TestPluginInvokeService_InvalidArgument_EmptyPluginName(t *testing.T) {
	reg := newFakeComponentInstallRegistry()
	svc := NewPluginInvokeService(reg, dispatchpolicy.ShapeSetecOnly, nil).WithAuthorizer(allowInvokeAuthz)
	ctx := buildPluginInvokeCtx("tenant-abc")

	_, err := svc.PluginInvoke(ctx, &pluginpb.PluginInvokeRequest{
		PluginName: "",
		Method:     "search",
	})
	if err == nil {
		t.Fatal("expected gRPC error for empty plugin_name")
	}
}

func TestPluginInvokeService_ConcurrencyLimit(t *testing.T) {
	tenant := auth.MustNewTenantID("tenant-abc")
	reg := newFakeComponentInstallRegistry()
	reg.addInstall(tenant, "lookup", []string{"search"})

	// Block all dispatch calls so we exhaust the semaphore.
	unblock := make(chan struct{})
	started := make(chan struct{}, int(pluginConcurrencyDefault)+1)
	reg.dispatchFunc = func(_ context.Context, _ auth.TenantID, _, _ string, _ []byte, _ time.Duration) ([]byte, error) {
		started <- struct{}{}
		<-unblock
		return []byte("{}"), nil
	}

	svc := NewPluginInvokeService(reg, dispatchpolicy.ShapeSetecOnly, nil).WithAuthorizer(allowInvokeAuthz)

	// Fill the semaphore with pluginConcurrencyDefault goroutines.
	done := make(chan struct{}, int(pluginConcurrencyDefault))
	for i := 0; i < int(pluginConcurrencyDefault); i++ {
		go func() {
			ctx := buildPluginInvokeCtx("tenant-abc")
			svc.PluginInvoke(ctx, &pluginpb.PluginInvokeRequest{ //nolint:errcheck
				PluginName: "lookup",
				Method:     "search",
				DeadlineMs: 5000,
			})
			done <- struct{}{}
		}()
	}

	// Wait until all goroutines have acquired the semaphore.
	for i := 0; i < int(pluginConcurrencyDefault); i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("goroutines did not start in time")
		}
	}

	// Extra call with a tiny deadline should get DEADLINE_EXCEEDED (semaphore full).
	ctx := buildPluginInvokeCtx("tenant-abc")
	resp, err := svc.PluginInvoke(ctx, &pluginpb.PluginInvokeRequest{
		PluginName: "lookup",
		Method:     "search",
		DeadlineMs: 10, // 10ms — should time out waiting for a semaphore slot
	})
	if err != nil {
		t.Fatalf("unexpected gRPC error: %v", err)
	}
	if resp.GetError().GetKind() != pluginpb.PluginError_PLUGIN_ERROR_KIND_DEADLINE_EXCEEDED {
		t.Errorf("expected DEADLINE_EXCEEDED for semaphore-full case, got %v", resp.GetError().GetKind())
	}

	// Unblock all pending goroutines.
	close(unblock)
	for i := 0; i < int(pluginConcurrencyDefault); i++ {
		<-done
	}
}

func TestPluginInvokeService_MissingIdentity(t *testing.T) {
	reg := newFakeComponentInstallRegistry()
	svc := NewPluginInvokeService(reg, dispatchpolicy.ShapeSetecOnly, nil).WithAuthorizer(allowInvokeAuthz)

	// Context with no identity.
	resp, err := svc.PluginInvoke(context.Background(), &pluginpb.PluginInvokeRequest{
		PluginName: "lookup",
		Method:     "search",
	})
	// Should return a gRPC Unauthenticated error.
	if err == nil && (resp == nil || resp.GetError() == nil) {
		t.Fatal("expected error for missing identity")
	}
}

func TestMethodDeclared(t *testing.T) {
	declared := []string{"search", "host", "scan"}
	tests := []struct {
		method string
		want   bool
	}{
		{"search", true},
		{"host", true},
		{"scan", true},
		{"nmap", false},
		{"", false},
	}
	for _, tt := range tests {
		got := methodDeclared(declared, tt.method)
		if got != tt.want {
			t.Errorf("methodDeclared(%q): want %v got %v", tt.method, tt.want, got)
		}
	}
}

func TestPluginErrorResponse(t *testing.T) {
	resp := pluginErrorResponse(pluginpb.PluginError_PLUGIN_ERROR_KIND_UNAVAILABLE, "test message")
	if resp.GetError().GetKind() != pluginpb.PluginError_PLUGIN_ERROR_KIND_UNAVAILABLE {
		t.Errorf("expected UNAVAILABLE")
	}
	if resp.GetError().GetMessage() != "test message" {
		t.Errorf("expected 'test message'")
	}
}

func TestPluginInvokeService_ClassifyDispatchError_PluginWorkError(t *testing.T) {
	svc := NewPluginInvokeService(newFakeComponentInstallRegistry(), dispatchpolicy.ShapeSetecOnly, nil).WithAuthorizer(allowInvokeAuthz)
	ctx := context.Background()

	cases := []struct {
		code string
		want pluginpb.PluginError_Kind
	}{
		{"DEADLINE_EXCEEDED", pluginpb.PluginError_PLUGIN_ERROR_KIND_DEADLINE_EXCEEDED},
		{"HANDLER_FAILED", pluginpb.PluginError_PLUGIN_ERROR_KIND_HANDLER_FAILED},
		{"METHOD_NOT_FOUND", pluginpb.PluginError_PLUGIN_ERROR_KIND_METHOD_NOT_FOUND},
		{"UNAVAILABLE", pluginpb.PluginError_PLUGIN_ERROR_KIND_UNAVAILABLE},
		{"OTHER", pluginpb.PluginError_PLUGIN_ERROR_KIND_HANDLER_FAILED},
	}
	for _, tc := range cases {
		err := &PluginWorkError{Code: tc.code, Message: "test"}
		resp := svc.classifyDispatchError(ctx, err, "plugin", "method")
		if resp.GetError().GetKind() != tc.want {
			t.Errorf("code %s: want %v got %v", tc.code, tc.want, resp.GetError().GetKind())
		}
	}
}

// Ensure fakeComponentInstallRegistry implements ComponentInstallRegistry (compile-time check).
var _ ComponentInstallRegistry = (*fakeComponentInstallRegistry)(nil)

// Ensure fakeComponentInstallRegistry.DispatchOne is reachable for coverage.
// The default return is raw JSON, matching a Go-first plugin's SubmitResult.
func TestFakePluginRegistry_DispatchOne_Default(t *testing.T) {
	reg := newFakeComponentInstallRegistry()
	tenant := auth.MustNewTenantID("t1")
	b, err := reg.DispatchOne(context.Background(), tenant, "p", "m", nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(b) {
		t.Fatalf("default dispatch result is not valid JSON: %q", b)
	}
}

// Ensure errors package is used (suppress import warning if tests are refactored).
var _ = errors.New

// ---------------------------------------------------------------------------
// Task 19: manifest-derived dispatch tests
// ---------------------------------------------------------------------------

// TestDispatchEcho_ManifestDerived loads the debug-plugin manifest, registers
// a test plugin install with DeclaredMethods derived from that manifest, and
// asserts that PluginInvoke with method "Echo" succeeds (returns no error and
// no PluginError). This test runs without a real daemon or Docker container.
func TestDispatchEcho_ManifestDerived(t *testing.T) {
	// Load the debug-plugin manifest from testdata (same YAML as
	// enterprise/plugins/debug-plugin/plugin.yaml).
	m, err := pluginmanifest.Load("testdata/debug-plugin.yaml")
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}

	// Build DeclaredMethods from the manifest.
	declaredMethods := make([]string, 0, len(m.Spec.Methods))
	for _, meth := range m.Spec.Methods {
		declaredMethods = append(declaredMethods, meth.Name)
	}
	if len(declaredMethods) == 0 {
		t.Fatal("manifest has no declared methods")
	}

	tenant := auth.MustNewTenantID("tenant-abc")
	reg := newFakeComponentInstallRegistry()
	reg.addInstall(tenant, m.Metadata.Name, declaredMethods)

	// The fake dispatch returns raw JSON, as a Go-first plugin would.
	reg.dispatchFunc = func(_ context.Context, _ auth.TenantID, _, _ string, _ []byte, _ time.Duration) ([]byte, error) {
		return []byte("{}"), nil
	}

	svc := NewPluginInvokeService(reg, dispatchpolicy.ShapeSetecOnly, nil).WithAuthorizer(allowInvokeAuthz)
	ctx := buildPluginInvokeCtx("tenant-abc")

	resp, err := svc.PluginInvoke(ctx, &pluginpb.PluginInvokeRequest{
		PluginName: m.Metadata.Name,
		Method:     "Echo",
		DeadlineMs: 5000,
	})
	if err != nil {
		t.Fatalf("unexpected gRPC error: %v", err)
	}
	if resp.GetError() != nil {
		t.Errorf("expected no plugin error, got: %v", resp.GetError())
	}
}

// TestDispatchOne_MethodDeclaredCheck asserts that calling PluginInvoke with a
// method name not in the plugin's DeclaredMethods list returns
// PLUGIN_ERROR_KIND_METHOD_NOT_FOUND. This is the registry-level method guard
// documented in design.md "Error Handling — Plugin Errors item 8".
func TestDispatchOne_MethodDeclaredCheck(t *testing.T) {
	tenant := auth.MustNewTenantID("tenant-abc")
	reg := newFakeComponentInstallRegistry()
	// Register debug-plugin with only "Echo" declared.
	reg.addInstall(tenant, "debug-plugin", []string{"Echo"})

	svc := NewPluginInvokeService(reg, dispatchpolicy.ShapeSetecOnly, nil).WithAuthorizer(allowInvokeAuthz)
	ctx := buildPluginInvokeCtx("tenant-abc")

	resp, err := svc.PluginInvoke(ctx, &pluginpb.PluginInvokeRequest{
		PluginName: "debug-plugin",
		Method:     "NonExistent",
		DeadlineMs: 5000,
	})
	if err != nil {
		t.Fatalf("unexpected gRPC error: %v", err)
	}
	if resp.GetError() == nil {
		t.Fatal("expected a plugin error for undeclared method")
	}
	if resp.GetError().GetKind() != pluginpb.PluginError_PLUGIN_ERROR_KIND_METHOD_NOT_FOUND {
		t.Errorf("expected PLUGIN_ERROR_KIND_METHOD_NOT_FOUND, got %v", resp.GetError().GetKind())
	}
}

var _ = json.Marshal

// addInstallWithTrust seeds one serving install carrying a content-trust
// classification, for the dispatch-policy gate tests (gibson#997).
func (f *fakeComponentInstallRegistry) addInstallWithTrust(tenant auth.TenantID, name string, methods []string, trust componentpb.ContentTrust) {
	key := tenant.String() + "/" + name
	f.installs[key] = append(f.installs[key], InstallInfo{
		InstallID:       fmt.Sprintf("install-%s-%s-%d", tenant.String(), name, len(f.installs[key])),
		TenantID:        tenant,
		Name:            name,
		DeclaredMethods: methods,
		Status:          ComponentInstallStatusServing,
		ContentTrust:    trust,
	})
}

// TestPluginInvoke_UntrustedDeniedUnderSetecOnly is the gibson#997 invariant: an
// UNTRUSTED plugin under the hosted setec-only shape is denied with a typed
// UNAUTHORIZED error AND never dispatched in-process (the spy dispatchFunc is
// not called).
func TestPluginInvoke_UntrustedDeniedUnderSetecOnly(t *testing.T) {
	tenant := auth.MustNewTenantID("tenant-abc")
	reg := newFakeComponentInstallRegistry()
	reg.addInstallWithTrust(tenant, "scanner", []string{"run"}, componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED)

	dispatched := false
	reg.dispatchFunc = func(_ context.Context, _ auth.TenantID, _, _ string, _ []byte, _ time.Duration) ([]byte, error) {
		dispatched = true
		return []byte("{}"), nil
	}

	svc := NewPluginInvokeService(reg, dispatchpolicy.ShapeSetecOnly, nil).WithAuthorizer(allowInvokeAuthz)
	ctx := buildPluginInvokeCtx("tenant-abc")

	resp, err := svc.PluginInvoke(ctx, &pluginpb.PluginInvokeRequest{PluginName: "scanner", Method: "run"})
	if err != nil {
		t.Fatalf("unexpected gRPC error: %v", err)
	}
	if resp.GetError() == nil || resp.GetError().GetKind() != pluginpb.PluginError_PLUGIN_ERROR_KIND_UNAUTHORIZED {
		t.Fatalf("expected UNAUTHORIZED deny, got %v", resp.GetError())
	}
	if dispatched {
		t.Fatal("untrusted plugin was dispatched in-process; the gate must deny before dispatch")
	}
}

// TestPluginInvoke_UntrustedAllowedUnderCustomerIsolation: on-prem the customer
// owns isolation, so an untrusted plugin is NOT denied (it dispatches).
func TestPluginInvoke_UntrustedAllowedUnderCustomerIsolation(t *testing.T) {
	tenant := auth.MustNewTenantID("tenant-abc")
	reg := newFakeComponentInstallRegistry()
	reg.addInstallWithTrust(tenant, "scanner", []string{"run"}, componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED)

	svc := NewPluginInvokeService(reg, dispatchpolicy.ShapeCustomerIsolation, nil).WithAuthorizer(allowInvokeAuthz)
	ctx := buildPluginInvokeCtx("tenant-abc")

	resp, err := svc.PluginInvoke(ctx, &pluginpb.PluginInvokeRequest{PluginName: "scanner", Method: "run"})
	if err != nil {
		t.Fatalf("unexpected gRPC error: %v", err)
	}
	if e := resp.GetError(); e != nil && e.GetKind() == pluginpb.PluginError_PLUGIN_ERROR_KIND_UNAUTHORIZED {
		t.Fatal("customer-isolation must not deny untrusted plugin invocation")
	}
}

// TestPluginInvoke_TrustedAllowedUnderSetecOnly: a trusted plugin proceeds even
// under setec-only.
func TestPluginInvoke_TrustedAllowedUnderSetecOnly(t *testing.T) {
	tenant := auth.MustNewTenantID("tenant-abc")
	reg := newFakeComponentInstallRegistry()
	reg.addInstallWithTrust(tenant, "scanner", []string{"run"}, componentpb.ContentTrust_CONTENT_TRUST_TRUSTED)

	svc := NewPluginInvokeService(reg, dispatchpolicy.ShapeSetecOnly, nil).WithAuthorizer(allowInvokeAuthz)
	ctx := buildPluginInvokeCtx("tenant-abc")

	resp, err := svc.PluginInvoke(ctx, &pluginpb.PluginInvokeRequest{PluginName: "scanner", Method: "run"})
	if err != nil {
		t.Fatalf("unexpected gRPC error: %v", err)
	}
	if e := resp.GetError(); e != nil && e.GetKind() == pluginpb.PluginError_PLUGIN_ERROR_KIND_UNAUTHORIZED {
		t.Fatal("trusted plugin must not be policy-denied")
	}
}

// ---------------------------------------------------------------------------
// ADR-0065 R4: Go-first plugin dispatches through the JSON path end to end.
// ---------------------------------------------------------------------------

// githubGetRepoRequest / githubGetRepoResponse model the typed Go structs a
// Go-first plugin authors with sdk plugin.WithHandler (see
// zeroroot-ai/integrations/plugins/github): JSON in, JSON out, no protobuf.
type githubGetRepoRequest struct {
	Owner string `json:"owner"`
	Repo  string `json:"repo"`
}

type githubGetRepoResponse struct {
	FullName string `json:"full_name"`
	Stars    int    `json:"stars"`
	Private  bool   `json:"private"`
}

// TestPluginInvoke_GoFirstJSONRoundTrip proves a Go-first plugin method
// dispatches through the JSON path end to end, with no proto message typing on
// the plugin path (ADR-0065 R4):
//
//   - the daemon forwards the request envelope verbatim; the plugin reads the
//     method args from PluginInvokeRequest.request.value as raw JSON;
//   - the plugin handler runs on typed Go structs and returns raw JSON;
//   - the daemon carries that JSON back in PluginInvokeResponse.result.value,
//     the mirror of request.request.value — never a marshalled proto message.
//
// The fake DispatchOne stands in for the SDK plugin/dispatch loop: it unmarshals
// the proto TRANSPORT envelope (which stays proto), extracts request.value as
// JSON, decodes it into the typed request, runs a handler, and submits the typed
// response marshalled back to raw JSON — exactly SubmitResult(workID, respJSON, nil).
func TestPluginInvoke_GoFirstJSONRoundTrip(t *testing.T) {
	tenant := auth.MustNewTenantID("tenant-abc")
	reg := newFakeComponentInstallRegistry()
	reg.addInstall(tenant, "github", []string{"GetRepo"})

	// The typed handler the plugin author writes.
	handler := func(in githubGetRepoRequest) githubGetRepoResponse {
		return githubGetRepoResponse{
			FullName: in.Owner + "/" + in.Repo,
			Stars:    42,
			Private:  false,
		}
	}

	// Fake DispatchOne == the SDK plugin/dispatch loop, hermetic (no network).
	var seenMethod string
	reg.dispatchFunc = func(_ context.Context, _ auth.TenantID, _, method string, payload []byte, _ time.Duration) ([]byte, error) {
		seenMethod = method

		// 1. The transport frame is proto; the payload is a PluginInvokeRequest.
		var envelope pluginpb.PluginInvokeRequest
		if err := proto.Unmarshal(payload, &envelope); err != nil {
			return nil, fmt.Errorf("plugin dispatch envelope not proto: %w", err)
		}

		// 2. The method args arrive as raw JSON in request.value — no proto typing.
		var reqJSON json.RawMessage
		if a := envelope.GetRequest(); a != nil {
			reqJSON = json.RawMessage(a.GetValue())
		}
		var in githubGetRepoRequest
		if err := json.Unmarshal(reqJSON, &in); err != nil {
			return nil, fmt.Errorf("plugin could not decode request JSON: %w", err)
		}

		// 3. Run the typed handler and submit the response as raw JSON verbatim.
		out := handler(in)
		respJSON, err := json.Marshal(out)
		if err != nil {
			return nil, fmt.Errorf("marshal plugin response: %w", err)
		}
		return respJSON, nil
	}

	svc := NewPluginInvokeService(reg, dispatchpolicy.ShapeSetecOnly, nil).WithAuthorizer(allowInvokeAuthz)
	ctx := buildPluginInvokeCtx("tenant-abc")

	// The tool caller marshals its typed args to JSON and puts them in
	// request.request.value — the mirror of the result path.
	argsJSON, err := json.Marshal(githubGetRepoRequest{Owner: "zeroroot-ai", Repo: "gibson"})
	if err != nil {
		t.Fatalf("marshal args: %v", err)
	}

	resp, err := svc.PluginInvoke(ctx, &pluginpb.PluginInvokeRequest{
		PluginName: "github",
		Method:     "GetRepo",
		Request:    &anypb.Any{Value: argsJSON},
		DeadlineMs: 5000,
	})
	if err != nil {
		t.Fatalf("unexpected gRPC error: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("expected no plugin error, got: %v", resp.GetError())
	}
	if seenMethod != "GetRepo" {
		t.Fatalf("dispatch saw method %q, want GetRepo", seenMethod)
	}

	// The response carries the plugin's raw JSON in result.value — decode it with
	// the method's typed output struct, proving no proto message typing was used.
	if resp.GetResult() == nil {
		t.Fatal("expected result.value populated with the plugin's JSON response")
	}
	var out githubGetRepoResponse
	if err := json.Unmarshal(resp.GetResult().GetValue(), &out); err != nil {
		t.Fatalf("result.value is not the plugin's JSON response: %v (raw=%q)", err, resp.GetResult().GetValue())
	}
	want := githubGetRepoResponse{FullName: "zeroroot-ai/gibson", Stars: 42, Private: false}
	if out != want {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", out, want)
	}

	// The result.value is exactly the plugin's JSON bytes — no proto Any type_url
	// resolution, no proto message wrap.
	if tu := resp.GetResult().GetTypeUrl(); tu != "" {
		t.Fatalf("result Any should carry no proto type_url on the JSON path, got %q", tu)
	}
}

// TestPluginInvoke_EmptyResultLeavesResultNil proves a Go-first method that
// returns no body (empty SubmitResult bytes) yields a success response with a
// nil result and no error — dispatch never proto-unmarshals the result bytes.
func TestPluginInvoke_EmptyResultLeavesResultNil(t *testing.T) {
	tenant := auth.MustNewTenantID("tenant-abc")
	reg := newFakeComponentInstallRegistry()
	reg.addInstall(tenant, "github", []string{"Ping"})
	reg.dispatchFunc = func(_ context.Context, _ auth.TenantID, _, _ string, _ []byte, _ time.Duration) ([]byte, error) {
		return nil, nil // a method that returns no body
	}

	svc := NewPluginInvokeService(reg, dispatchpolicy.ShapeSetecOnly, nil).WithAuthorizer(allowInvokeAuthz)
	ctx := buildPluginInvokeCtx("tenant-abc")

	resp, err := svc.PluginInvoke(ctx, &pluginpb.PluginInvokeRequest{
		PluginName: "github",
		Method:     "Ping",
		DeadlineMs: 5000,
	})
	if err != nil {
		t.Fatalf("unexpected gRPC error: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("expected no plugin error, got: %v", resp.GetError())
	}
	if resp.GetResult() != nil {
		t.Fatalf("empty result should leave result nil, got %v", resp.GetResult())
	}
}
