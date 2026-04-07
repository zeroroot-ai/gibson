package auth

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	sdkauth "github.com/zero-day-ai/sdk/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// --- Test helpers ------------------------------------------------------------

// fakeRecorder captures calls to SetAuthzSpanAttrsFunc and RecordAuthzMetricFunc
// so tests can assert observability side-effects without importing the
// observability package.
type fakeRecorder struct {
	mu           sync.Mutex
	spanCalls    []spanCall
	metricCalls  []metricCall
}

type spanCall struct {
	Method, Subject, Tenant, Permission, Reason string
	Allowed                                     bool
}

type metricCall struct {
	Decision, Method, Permission string
}

func (f *fakeRecorder) setAttrs(ctx context.Context, method, subject, tenant, permission string, allowed bool, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.spanCalls = append(f.spanCalls, spanCall{
		Method: method, Subject: subject, Tenant: tenant, Permission: permission, Allowed: allowed, Reason: reason,
	})
}

func (f *fakeRecorder) recordMetric(ctx context.Context, decision, method, permission string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.metricCalls = append(f.metricCalls, metricCall{Decision: decision, Method: method, Permission: permission})
}

// newTestInterceptor loads the production YAML + enforcer and wires a fake
// recorder. Used by most test cases so they exercise the real schema.
func newTestInterceptor(t *testing.T) (*RPCAuthzInterceptor, *fakeRecorder) {
	t.Helper()
	reg, enf, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	rec := &fakeRecorder{}
	interceptor, err := NewRPCAuthzInterceptor(reg, enf, slog.Default(), rec.setAttrs, rec.recordMetric)
	if err != nil {
		t.Fatalf("NewRPCAuthzInterceptor: %v", err)
	}
	return interceptor, rec
}

// ctxWithIdentity attaches a Gibson Identity plus a tenant context.
func ctxWithIdentity(subject string, roles []string, tenant string) context.Context {
	ctx := context.Background()
	identity := &Identity{
		Identity: sdkauth.Identity{
			Subject: subject,
		},
		Roles: roles,
	}
	ctx = ContextWithIdentity(ctx, identity)
	if tenant != "" {
		ctx = ContextWithTenant(ctx, tenant)
	}
	return ctx
}

// ctxWithGroupingPolicy binds the given subject to the given role in the
// given domain via Casbin, matching what the membership store does at runtime.
func (i *RPCAuthzInterceptor) bindRole(t *testing.T, subject, role, domain string) {
	t.Helper()
	if _, err := i.enforcer.AddGroupingPolicy(subject, role, domain); err != nil {
		t.Fatalf("AddGroupingPolicy(%s, %s, %s): %v", subject, role, domain, err)
	}
}

// --- Constructor validation --------------------------------------------------

func TestNewRPCAuthzInterceptor_RequiresRegistry(t *testing.T) {
	_, enf, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	if _, err := NewRPCAuthzInterceptor(nil, enf, nil, nil, nil); err == nil {
		t.Error("expected error for nil registry")
	}
}

func TestNewRPCAuthzInterceptor_RequiresEnforcer(t *testing.T) {
	reg, _, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	if _, err := NewRPCAuthzInterceptor(reg, nil, nil, nil, nil); err == nil {
		t.Error("expected error for nil enforcer")
	}
}

// --- Unary interceptor: allow path ------------------------------------------

func TestUnaryInterceptor_AllowsCallerWithRequiredPermission(t *testing.T) {
	interceptor, rec := newTestInterceptor(t)

	// Bind alice to the admin role in tenant-a. Admin transitively grants
	// missions:execute via operator inheritance.
	interceptor.bindRole(t, "alice", "admin", "tenant-a")

	ctx := ctxWithIdentity("alice", []string{"admin"}, "tenant-a")
	handlerCalled := false
	handler := func(ctx context.Context, req any) (any, error) {
		handlerCalled = true
		return "ok", nil
	}

	resp, err := interceptor.Unary()(ctx, nil, &grpc.UnaryServerInfo{
		FullMethod: "/gibson.daemon.v1.DaemonService/RunMission",
	}, handler)

	if err != nil {
		t.Fatalf("expected allow, got error: %v", err)
	}
	if !handlerCalled {
		t.Error("handler should have been called on allow")
	}
	if resp != "ok" {
		t.Errorf("handler response lost: %v", resp)
	}

	// Exactly one audit/metric call.
	if len(rec.spanCalls) != 1 || !rec.spanCalls[0].Allowed {
		t.Errorf("expected one allow span call, got %+v", rec.spanCalls)
	}
	if len(rec.metricCalls) != 1 || rec.metricCalls[0].Decision != "allow" {
		t.Errorf("expected one allow metric call, got %+v", rec.metricCalls)
	}
	if rec.metricCalls[0].Permission != "missions:execute" {
		t.Errorf("metric permission = %q, want missions:execute", rec.metricCalls[0].Permission)
	}
}

// --- Unary interceptor: deny paths ------------------------------------------

func TestUnaryInterceptor_DeniesCallerWithoutPermission(t *testing.T) {
	interceptor, rec := newTestInterceptor(t)

	// alice is only a viewer in tenant-a. viewer lacks missions:execute.
	interceptor.bindRole(t, "alice", "viewer", "tenant-a")

	ctx := ctxWithIdentity("alice", []string{"viewer"}, "tenant-a")
	handlerCalled := false
	handler := func(ctx context.Context, req any) (any, error) {
		handlerCalled = true
		return nil, nil
	}

	_, err := interceptor.Unary()(ctx, nil, &grpc.UnaryServerInfo{
		FullMethod: "/gibson.daemon.v1.DaemonService/RunMission",
	}, handler)

	if err == nil {
		t.Fatal("expected PermissionDenied error")
	}
	if handlerCalled {
		t.Error("handler must NOT run on deny")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied, got %v", status.Code(err))
	}
	// Generic caller-facing message.
	if !strings.Contains(err.Error(), "authorization failed") {
		t.Errorf("caller error should be generic, got: %v", err)
	}
	// Specific reason MUST NOT leak to the caller.
	if strings.Contains(err.Error(), "missions:execute") {
		t.Errorf("permission name must not leak to caller, got: %v", err)
	}
	// But the audit/metric must record the specific reason.
	if len(rec.spanCalls) != 1 || rec.spanCalls[0].Allowed {
		t.Errorf("expected one deny span call, got %+v", rec.spanCalls)
	}
	if !strings.Contains(rec.spanCalls[0].Reason, "missions:execute") {
		t.Errorf("deny reason should name the missing permission, got: %q", rec.spanCalls[0].Reason)
	}
	if rec.metricCalls[0].Decision != "deny" {
		t.Errorf("metric decision = %q, want deny", rec.metricCalls[0].Decision)
	}
}

func TestUnaryInterceptor_DeniesUnmappedRPC(t *testing.T) {
	interceptor, rec := newTestInterceptor(t)
	ctx := ctxWithIdentity("alice", []string{"owner"}, "tenant-a")

	handler := func(ctx context.Context, req any) (any, error) { return nil, errors.New("should not run") }
	_, err := interceptor.Unary()(ctx, nil, &grpc.UnaryServerInfo{
		FullMethod: "/fake.v1.Fake/Ghost",
	}, handler)

	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for unmapped rpc, got %v", err)
	}
	if rec.spanCalls[0].Reason != "rpc_not_in_schema" {
		t.Errorf("deny reason = %q, want rpc_not_in_schema", rec.spanCalls[0].Reason)
	}
	if rec.metricCalls[0].Permission != "rpc_not_in_schema" {
		t.Errorf("metric permission for unmapped rpc should be rpc_not_in_schema, got %q", rec.metricCalls[0].Permission)
	}
}

func TestUnaryInterceptor_DeniesNoIdentity(t *testing.T) {
	interceptor, rec := newTestInterceptor(t)
	// No identity in context.
	ctx := context.Background()

	handler := func(ctx context.Context, req any) (any, error) { return nil, errors.New("should not run") }
	_, err := interceptor.Unary()(ctx, nil, &grpc.UnaryServerInfo{
		FullMethod: "/gibson.daemon.v1.DaemonService/ListMissions",
	}, handler)

	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for missing identity, got %v", err)
	}
	if rec.spanCalls[0].Reason != "no_identity" {
		t.Errorf("deny reason = %q, want no_identity", rec.spanCalls[0].Reason)
	}
}

func TestUnaryInterceptor_DeniesTenantScopedRPCWithoutTenant(t *testing.T) {
	interceptor, rec := newTestInterceptor(t)
	// Identity present, but no tenant context set.
	ctx := ctxWithIdentity("alice", []string{"viewer"}, "")

	handler := func(ctx context.Context, req any) (any, error) { return nil, nil }
	_, err := interceptor.Unary()(ctx, nil, &grpc.UnaryServerInfo{
		FullMethod: "/gibson.daemon.v1.DaemonService/ListMissions",
	}, handler)

	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for missing tenant, got %v", err)
	}
	if rec.spanCalls[0].Reason != "tenant_missing_for_scoped_rpc" {
		t.Errorf("deny reason = %q, want tenant_missing_for_scoped_rpc", rec.spanCalls[0].Reason)
	}
}

// --- Cross-tenant flow: provisioner can call ProvisionTenant ----------------

func TestUnaryInterceptor_CrossTenantProvisioner(t *testing.T) {
	interceptor, rec := newTestInterceptor(t)

	// system-ops is bound to provisioner in the wildcard domain, mirroring
	// the dashboard signup flow.
	interceptor.bindRole(t, "system-ops", "provisioner", "*")

	ctx := ctxWithIdentity("system-ops", []string{"provisioner"}, "")

	handlerCalled := false
	handler := func(ctx context.Context, req any) (any, error) {
		handlerCalled = true
		return "provisioned", nil
	}

	resp, err := interceptor.Unary()(ctx, nil, &grpc.UnaryServerInfo{
		FullMethod: "/gibson.daemon.admin.v1.DaemonAdminService/ProvisionTenant",
	}, handler)

	if err != nil {
		t.Fatalf("provisioner should be allowed ProvisionTenant, got error: %v", err)
	}
	if !handlerCalled {
		t.Error("handler should have been called")
	}
	if resp != "provisioned" {
		t.Error("handler response lost")
	}
	if !rec.spanCalls[0].Allowed {
		t.Error("span call should be allow")
	}
}

// --- GetAuthSchema: any authenticated caller passes -------------------------

func TestUnaryInterceptor_GetAuthSchemaAnyAuthenticated(t *testing.T) {
	interceptor, rec := newTestInterceptor(t)

	// viewer has no schema:read permission directly, but GetAuthSchema has
	// empty required_permissions so any authenticated caller passes.
	ctx := ctxWithIdentity("alice", []string{"viewer"}, "tenant-a")

	handler := func(ctx context.Context, req any) (any, error) { return "schema", nil }
	_, err := interceptor.Unary()(ctx, nil, &grpc.UnaryServerInfo{
		FullMethod: "/gibson.daemon.admin.v1.DaemonAdminService/GetAuthSchema",
	}, handler)

	if err != nil {
		t.Fatalf("GetAuthSchema should pass for any authenticated caller, got: %v", err)
	}
	if !rec.spanCalls[0].Allowed {
		t.Error("GetAuthSchema span should record allow")
	}
	if rec.spanCalls[0].Reason != "any_authenticated" {
		t.Errorf("GetAuthSchema reason should be any_authenticated, got %q", rec.spanCalls[0].Reason)
	}
}

// --- Unauthenticated RPC: AcceptInvitation ---------------------------------

func TestUnaryInterceptor_UnauthenticatedRPCSkipsAuthz(t *testing.T) {
	interceptor, rec := newTestInterceptor(t)
	// No identity — AcceptInvitation is token-based.
	ctx := context.Background()

	handlerCalled := false
	handler := func(ctx context.Context, req any) (any, error) {
		handlerCalled = true
		return "accepted", nil
	}

	_, err := interceptor.Unary()(ctx, nil, &grpc.UnaryServerInfo{
		FullMethod: "/gibson.daemon.admin.v1.DaemonAdminService/AcceptInvitation",
	}, handler)

	if err != nil {
		t.Fatalf("AcceptInvitation should skip authz, got: %v", err)
	}
	if !handlerCalled {
		t.Error("handler should have been called")
	}
	if !rec.spanCalls[0].Allowed {
		t.Error("unauthenticated RPC span should record allow")
	}
	if rec.spanCalls[0].Reason != "unauthenticated_rpc" {
		t.Errorf("reason should be unauthenticated_rpc, got %q", rec.spanCalls[0].Reason)
	}
}

// --- Stream interceptor: same contract --------------------------------------

type fakeStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *fakeStream) Context() context.Context { return s.ctx }

func TestStreamInterceptor_AllowPath(t *testing.T) {
	interceptor, rec := newTestInterceptor(t)
	interceptor.bindRole(t, "alice", "viewer", "tenant-a")

	ctx := ctxWithIdentity("alice", []string{"viewer"}, "tenant-a")
	ss := &fakeStream{ctx: ctx}

	handlerCalled := false
	handler := func(srv any, stream grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}

	err := interceptor.Stream()(nil, ss, &grpc.StreamServerInfo{
		FullMethod: "/gibson.daemon.v1.DaemonService/Subscribe",
	}, handler)

	if err != nil {
		t.Fatalf("stream allow path failed: %v", err)
	}
	if !handlerCalled {
		t.Error("stream handler should have been called")
	}
	if !rec.spanCalls[0].Allowed {
		t.Error("stream span should record allow")
	}
}

func TestStreamInterceptor_DenyPath(t *testing.T) {
	interceptor, _ := newTestInterceptor(t)

	ctx := ctxWithIdentity("alice", []string{"viewer"}, "tenant-a")
	// viewer lacks missions:execute, so RunMission (stream) denies.
	ss := &fakeStream{ctx: ctx}

	handlerCalled := false
	handler := func(srv any, stream grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}

	err := interceptor.Stream()(nil, ss, &grpc.StreamServerInfo{
		FullMethod: "/gibson.daemon.v1.DaemonService/RunMission",
	}, handler)

	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied on stream deny, got %v", err)
	}
	if handlerCalled {
		t.Error("stream handler must NOT run on deny")
	}
}
