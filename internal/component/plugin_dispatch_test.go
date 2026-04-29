package component

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	pluginpb "github.com/zero-day-ai/sdk/api/gen/gibson/plugin/v1"
	"github.com/zero-day-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// fakePluginRegistry is a test double for PluginRegistry.
// ---------------------------------------------------------------------------

type fakePluginRegistry struct {
	installs     map[string][]InstallInfo // key: tenantID+"/"+pluginName
	dispatchFunc func(ctx context.Context, tenant auth.TenantID, name, method string, payload []byte, deadline time.Duration) ([]byte, error)
}

func newFakePluginRegistry() *fakePluginRegistry {
	return &fakePluginRegistry{
		installs: make(map[string][]InstallInfo),
	}
}

func (f *fakePluginRegistry) Register(_ context.Context, _ *PluginInstall) error {
	return nil
}

func (f *fakePluginRegistry) Heartbeat(_ context.Context, _, _ string) error {
	return nil
}

func (f *fakePluginRegistry) ListInstalls(_ context.Context, tenant auth.TenantID, name string) ([]InstallInfo, error) {
	key := tenant.String() + "/" + name
	return f.installs[key], nil
}

func (f *fakePluginRegistry) DispatchOne(ctx context.Context, tenant auth.TenantID, name, method string, payload []byte, deadline time.Duration) ([]byte, error) {
	if f.dispatchFunc != nil {
		return f.dispatchFunc(ctx, tenant, name, method, payload, deadline)
	}
	// Default: return an empty PluginInvokeResponse
	resp := &pluginpb.PluginInvokeResponse{}
	return proto.Marshal(resp)
}

func (f *fakePluginRegistry) Status(_ context.Context, tenant auth.TenantID, name string) (RegistryStatus, error) {
	key := tenant.String() + "/" + name
	return RegistryStatus{Installs: f.installs[key]}, nil
}

func (f *fakePluginRegistry) addInstall(tenant auth.TenantID, name string, methods []string) {
	key := tenant.String() + "/" + name
	f.installs[key] = append(f.installs[key], InstallInfo{
		InstallID:       fmt.Sprintf("install-%s-%s-%d", tenant.String(), name, len(f.installs[key])),
		TenantID:        tenant,
		Name:            name,
		DeclaredMethods: methods,
		Status:          PluginInstallStatusServing,
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
	reg := newFakePluginRegistry()
	reg.addInstall(tenant, "shodan", []string{"search", "host"})

	// Dispatch returns a successful PluginInvokeResponse.
	reg.dispatchFunc = func(ctx context.Context, ten auth.TenantID, name, method string, payload []byte, deadline time.Duration) ([]byte, error) {
		resp := &pluginpb.PluginInvokeResponse{} // empty success
		return proto.Marshal(resp)
	}

	svc := NewPluginInvokeService(reg, nil)
	ctx := buildPluginInvokeCtx("tenant-abc")

	resp, err := svc.PluginInvoke(ctx, &pluginpb.PluginInvokeRequest{
		PluginName: "shodan",
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
	reg := newFakePluginRegistry() // no installs registered
	svc := NewPluginInvokeService(reg, nil)
	ctx := buildPluginInvokeCtx("tenant-abc")

	resp, err := svc.PluginInvoke(ctx, &pluginpb.PluginInvokeRequest{
		PluginName: "shodan",
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
	reg := newFakePluginRegistry()
	reg.addInstall(tenant, "shodan", []string{"search"}) // only "search" declared

	svc := NewPluginInvokeService(reg, nil)
	ctx := buildPluginInvokeCtx("tenant-abc")

	resp, err := svc.PluginInvoke(ctx, &pluginpb.PluginInvokeRequest{
		PluginName: "shodan",
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
	reg := newFakePluginRegistry()
	reg.addInstall(tenant, "shodan", []string{"search"})

	reg.dispatchFunc = func(_ context.Context, _ auth.TenantID, _, _ string, _ []byte, _ time.Duration) ([]byte, error) {
		return nil, fmt.Errorf("timeout waiting for work abc: %w", context.DeadlineExceeded)
	}

	svc := NewPluginInvokeService(reg, nil)
	ctx := buildPluginInvokeCtx("tenant-abc")

	resp, err := svc.PluginInvoke(ctx, &pluginpb.PluginInvokeRequest{
		PluginName: "shodan",
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
	reg := newFakePluginRegistry()
	reg.addInstall(tenant, "shodan", []string{"search"})

	reg.dispatchFunc = func(_ context.Context, _ auth.TenantID, _, _ string, _ []byte, _ time.Duration) ([]byte, error) {
		return nil, &PluginWorkError{Code: "HANDLER_FAILED", Message: "handler panicked"}
	}

	svc := NewPluginInvokeService(reg, nil)
	ctx := buildPluginInvokeCtx("tenant-abc")

	resp, err := svc.PluginInvoke(ctx, &pluginpb.PluginInvokeRequest{
		PluginName: "shodan",
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
	reg := newFakePluginRegistry()
	reg.addInstall(tenant, "shodan", []string{"search"})

	reg.dispatchFunc = func(_ context.Context, _ auth.TenantID, _, _ string, _ []byte, _ time.Duration) ([]byte, error) {
		return nil, ErrPluginUnavailable
	}

	svc := NewPluginInvokeService(reg, nil)
	ctx := buildPluginInvokeCtx("tenant-abc")

	resp, err := svc.PluginInvoke(ctx, &pluginpb.PluginInvokeRequest{
		PluginName: "shodan",
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
	reg := newFakePluginRegistry()
	svc := NewPluginInvokeService(reg, nil)
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
	reg := newFakePluginRegistry()
	reg.addInstall(tenant, "shodan", []string{"search"})

	// Block all dispatch calls so we exhaust the semaphore.
	unblock := make(chan struct{})
	started := make(chan struct{}, int(pluginConcurrencyDefault)+1)
	reg.dispatchFunc = func(_ context.Context, _ auth.TenantID, _, _ string, _ []byte, _ time.Duration) ([]byte, error) {
		started <- struct{}{}
		<-unblock
		resp := &pluginpb.PluginInvokeResponse{}
		b, _ := proto.Marshal(resp)
		return b, nil
	}

	svc := NewPluginInvokeService(reg, nil)

	// Fill the semaphore with pluginConcurrencyDefault goroutines.
	done := make(chan struct{}, int(pluginConcurrencyDefault))
	for i := 0; i < int(pluginConcurrencyDefault); i++ {
		go func() {
			ctx := buildPluginInvokeCtx("tenant-abc")
			svc.PluginInvoke(ctx, &pluginpb.PluginInvokeRequest{ //nolint:errcheck
				PluginName: "shodan",
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
		PluginName: "shodan",
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
	reg := newFakePluginRegistry()
	svc := NewPluginInvokeService(reg, nil)

	// Context with no identity.
	resp, err := svc.PluginInvoke(context.Background(), &pluginpb.PluginInvokeRequest{
		PluginName: "shodan",
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
	svc := NewPluginInvokeService(newFakePluginRegistry(), nil)
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

// Ensure fakePluginRegistry implements PluginRegistry (compile-time check).
var _ PluginRegistry = (*fakePluginRegistry)(nil)

// Ensure fakePluginRegistry.DispatchOne is reachable for coverage.
func TestFakePluginRegistry_DispatchOne_Default(t *testing.T) {
	reg := newFakePluginRegistry()
	tenant := auth.MustNewTenantID("t1")
	b, err := reg.DispatchOne(context.Background(), tenant, "p", "m", nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var resp pluginpb.PluginInvokeResponse
	if err := proto.Unmarshal(b, &resp); err != nil {
		t.Fatal(err)
	}
}

// Ensure errors package is used (suppress import warning if tests are refactored).
var _ = errors.New
var _ = json.Marshal
