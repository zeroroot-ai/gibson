package identity

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
)

// -----------------------------------------------------------------------
// TenantFromContext
// -----------------------------------------------------------------------

func TestTenantFromContext_NilContext(t *testing.T) {
	//nolint:staticcheck // nil ctx is the explicit branch we are testing.
	got := TenantFromContext(nil)
	if got != SystemTenant {
		t.Errorf("got %q, want %q (SystemTenant)", got, SystemTenant)
	}
}

func TestTenantFromContext_ExplicitTenantOverrides(t *testing.T) {
	ctx := ContextWithTenant(t.Context(), "acme-corp")
	got := TenantFromContext(ctx)
	if got != "acme-corp" {
		t.Errorf("got %q, want %q", got, "acme-corp")
	}
}

func TestTenantFromContext_FromIdentity(t *testing.T) {
	id := Identity{
		Subject:        "user:x",
		Issuer:         "zitadel",
		CredentialType: "oidc",
		Tenant:         "tenant-from-identity",
		IssuedAt:       time.Now(),
	}
	ctx := WithIdentity(t.Context(), id)
	got := TenantFromContext(ctx)
	if got != "tenant-from-identity" {
		t.Errorf("got %q, want %q", got, "tenant-from-identity")
	}
}

func TestTenantFromContext_FallsBackToSystemTenant(t *testing.T) {
	// Context has no tenant key and no identity.
	got := TenantFromContext(t.Context())
	if got != SystemTenant {
		t.Errorf("got %q, want %q (SystemTenant)", got, SystemTenant)
	}
}

func TestTenantFromContext_ExplicitTenantPrecedesIdentityTenant(t *testing.T) {
	id := Identity{
		Subject:        "user:x",
		Issuer:         "zitadel",
		CredentialType: "oidc",
		Tenant:         "identity-tenant",
		IssuedAt:       time.Now(),
	}
	ctx := WithIdentity(t.Context(), id)
	ctx = ContextWithTenant(ctx, "explicit-tenant")
	got := TenantFromContext(ctx)
	if got != "explicit-tenant" {
		t.Errorf("expected explicit tenant %q, got %q", "explicit-tenant", got)
	}
}

// -----------------------------------------------------------------------
// ContextWithTenant / TenantFromContext round-trip
// -----------------------------------------------------------------------

func TestContextWithTenant_RoundTrip(t *testing.T) {
	ctx := ContextWithTenant(t.Context(), "round-trip-tenant")
	got := TenantFromContext(ctx)
	if got != "round-trip-tenant" {
		t.Errorf("got %q, want %q", got, "round-trip-tenant")
	}
}

// -----------------------------------------------------------------------
// ActingUserFromContext / ContextWithActingUser
// -----------------------------------------------------------------------

func TestActingUserFromContext_NotSet(t *testing.T) {
	_, ok := ActingUserFromContext(t.Context())
	if ok {
		t.Error("expected ok=false when acting user not in context")
	}
}

func TestActingUserFromContext_Set(t *testing.T) {
	ctx := ContextWithActingUser(t.Context(), "user-123")
	got, ok := ActingUserFromContext(ctx)
	if !ok {
		t.Error("expected ok=true after ContextWithActingUser")
	}
	if got != "user-123" {
		t.Errorf("got %q, want %q", got, "user-123")
	}
}

func TestActingUserFromContext_EmptyString(t *testing.T) {
	// An explicitly empty acting user should not be considered set.
	ctx := ContextWithActingUser(t.Context(), "")
	_, ok := ActingUserFromContext(ctx)
	if ok {
		t.Error("empty acting user string should not set ok=true")
	}
}

// -----------------------------------------------------------------------
// IsCrossTenantCaller
// -----------------------------------------------------------------------

func TestIsCrossTenantCaller_SpireIsTrue(t *testing.T) {
	id := Identity{Issuer: "spire"}
	if !IsCrossTenantCaller(id) {
		t.Error("spire issuer must be cross-tenant")
	}
}

func TestIsCrossTenantCaller_ZitadelIsFalse(t *testing.T) {
	id := Identity{Issuer: "zitadel"}
	if IsCrossTenantCaller(id) {
		t.Error("zitadel issuer must NOT be cross-tenant")
	}
}

func TestIsCrossTenantCaller_APIKeyIsFalse(t *testing.T) {
	id := Identity{Issuer: "apikey"}
	if IsCrossTenantCaller(id) {
		t.Error("apikey issuer must NOT be cross-tenant")
	}
}

func TestIsCrossTenantCaller_UnknownIsFalse(t *testing.T) {
	id := Identity{Issuer: "unknown-issuer"}
	if IsCrossTenantCaller(id) {
		t.Error("unknown issuer must NOT be cross-tenant")
	}
}

// -----------------------------------------------------------------------
// TenantScopedRedisKey
// -----------------------------------------------------------------------

func TestTenantScopedRedisKey(t *testing.T) {
	cases := []struct {
		tenant, key, want string
	}{
		{"acme", "session:abc", "tenant:acme:session:abc"},
		{"_system", "config", "tenant:_system:config"},
		{"", "orphan", "tenant::orphan"},
	}
	for _, tc := range cases {
		got := TenantScopedRedisKey(tc.tenant, tc.key)
		if got != tc.want {
			t.Errorf("TenantScopedRedisKey(%q, %q) = %q, want %q", tc.tenant, tc.key, got, tc.want)
		}
	}
}

// -----------------------------------------------------------------------
// ComponentScopeFromContext / ContextWithComponentScope
// -----------------------------------------------------------------------

func TestComponentScopeFromContext_NotSet(t *testing.T) {
	got := ComponentScopeFromContext(t.Context())
	if got != "" {
		t.Errorf("expected empty string when scope not set, got %q", got)
	}
}

func TestContextWithComponentScope_RoundTrip(t *testing.T) {
	ctx := ContextWithComponentScope(t.Context(), "component:agent-abc123")
	got := ComponentScopeFromContext(ctx)
	if got != "component:agent-abc123" {
		t.Errorf("got %q, want %q", got, "component:agent-abc123")
	}
}

func TestContextWithComponentScope_EmptyStringIsNoop(t *testing.T) {
	// An empty scope must not store anything — returns same context.
	ctx := ContextWithComponentScope(t.Context(), "")
	got := ComponentScopeFromContext(ctx)
	if got != "" {
		t.Errorf("empty scope should not be stored; got %q", got)
	}
}

// -----------------------------------------------------------------------
// wrappedStream.Context — covered by TestStreamInterceptor tests but also
// verified here at the unit level.
// -----------------------------------------------------------------------

// mockServerStream is a minimal grpc.ServerStream stub for unit tests.
type mockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context { return m.ctx }

func TestWrappedStream_Context(t *testing.T) {
	inner := &mockServerStream{ctx: t.Context()}
	want := ContextWithTenant(t.Context(), "wrapped-tenant")
	ws := &wrappedStream{ServerStream: inner, ctx: want}
	got := ws.Context()
	if got != want {
		t.Error("wrappedStream.Context() did not return the stored context")
	}
}
