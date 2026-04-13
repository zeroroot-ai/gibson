package auth

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkauth "github.com/zero-day-ai/sdk/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// ---------------------------------------------------------------------------
// Mock validators
// ---------------------------------------------------------------------------

// mockBetterAuthValidator is a test implementation of betterAuthValidatorIface.
// Most existing interceptor tests route through the default (Better Auth) path
// since the test tokens don't carry a gsk_ prefix or agent+jwt header.
type mockBetterAuthValidator struct {
	authenticateFn func(ctx context.Context, token string) (*Identity, error)
}

func (m *mockBetterAuthValidator) Authenticate(ctx context.Context, token string) (*Identity, error) {
	if m.authenticateFn != nil {
		return m.authenticateFn(ctx, token)
	}
	return nil, errInvalidToken
}

// mockAPIKeyValidator is a test implementation of apiKeyValidatorIface.
type mockAPIKeyValidator struct {
	authenticateFn func(ctx context.Context, token string) (*Identity, error)
}

func (m *mockAPIKeyValidator) Authenticate(ctx context.Context, token string) (*Identity, error) {
	if m.authenticateFn != nil {
		return m.authenticateFn(ctx, token)
	}
	return nil, errInvalidToken
}


// mockAgentJWTValidator is a test implementation of AgentJWTValidator.
type mockAgentJWTValidator struct {
	verifyFn func(ctx context.Context, tokenStr, expectedAud string) (*AgentAuthClaims, error)
}

func (m *mockAgentJWTValidator) VerifyAgentJWT(ctx context.Context, tokenStr, expectedAud string) (*AgentAuthClaims, error) {
	if m.verifyFn != nil {
		return m.verifyFn(ctx, tokenStr, expectedAud)
	}
	return nil, fmt.Errorf("agentauth: mock not configured")
}

// mockHandler is a test gRPC handler.
type mockHandler struct {
	called      bool
	err         error
	capturedCtx context.Context
}

func (m *mockHandler) handle(ctx context.Context, req any) (any, error) {
	m.called = true
	m.capturedCtx = ctx
	return "response", m.err
}

// mockServerStream implements grpc.ServerStream for testing.
type mockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

// mockStreamHandler is a test gRPC stream handler.
type mockStreamHandler struct {
	called bool
	err    error
}

func (m *mockStreamHandler) handle(srv any, stream grpc.ServerStream) error {
	m.called = true
	return m.err
}

// mockAddr implements net.Addr for testing.
type mockAddr struct {
	addr string
}

func (m *mockAddr) Network() string {
	return "tcp"
}

func (m *mockAddr) String() string {
	return m.addr
}

// ---------------------------------------------------------------------------
// Interceptor constructor helpers for tests
//
// newTestUnary / newTestStream construct the 4-path interceptor using only the
// Better Auth mock validator for the default path. Used by tests that care only
// about interceptor plumbing (mode checks, localhost bypass, tenant extraction)
// and not about which auth path was taken.
// ---------------------------------------------------------------------------

func newTestUnary(ba betterAuthValidatorIface, cfg *AuthConfig, logger *slog.Logger) grpc.UnaryServerInterceptor {
	return buildUnaryInterceptor(nil, nil, ba, cfg, logger)
}

func newTestStream(ba betterAuthValidatorIface, cfg *AuthConfig, logger *slog.Logger) grpc.StreamServerInterceptor {
	return buildStreamInterceptor(nil, nil, ba, cfg, logger)
}

// ---------------------------------------------------------------------------
// Mode / disabled tests
// ---------------------------------------------------------------------------

func TestUnaryAuthInterceptor_EmptyMode_Rejects(t *testing.T) {
	ba := &mockBetterAuthValidator{}
	cfg := &AuthConfig{Mode: ""}
	logger := slog.Default()

	interceptor := newTestUnary(ba, cfg, logger)

	handler := &mockHandler{}
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	ctx := context.Background()
	_, err := interceptor(ctx, "request", info, handler.handle)

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.Contains(t, err.Error(), "authentication required")
	assert.False(t, handler.called, "handler should not be called when auth mode is empty")
}

func TestUnaryAuthInterceptor_DisabledMode_Rejects(t *testing.T) {
	ba := &mockBetterAuthValidator{}
	cfg := &AuthConfig{Mode: "disabled"}
	logger := slog.Default()

	interceptor := newTestUnary(ba, cfg, logger)

	handler := &mockHandler{}
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	ctx := context.Background()
	_, err := interceptor(ctx, "request", info, handler.handle)

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.Contains(t, err.Error(), "authentication required")
	assert.False(t, handler.called, "handler should not be called when auth mode is disabled")
}

// ---------------------------------------------------------------------------
// Localhost bypass tests
// ---------------------------------------------------------------------------

func TestUnaryAuthInterceptor_LocalhostBypass(t *testing.T) {
	tests := []struct {
		name         string
		peerAddr     string
		shouldBypass bool
	}{
		{
			name:         "IPv4 localhost",
			peerAddr:     "127.0.0.1:12345",
			shouldBypass: true,
		},
		{
			name:         "IPv6 localhost",
			peerAddr:     "[::1]:12345",
			shouldBypass: true,
		},
		{
			name:         "localhost hostname",
			peerAddr:     "localhost:12345",
			shouldBypass: true,
		},
		{
			name:         "remote address",
			peerAddr:     "192.168.1.100:12345",
			shouldBypass: false,
		},
		{
			name:         "public IPv6",
			peerAddr:     "[2001:db8::1]:12345",
			shouldBypass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ba := &mockBetterAuthValidator{}
			cfg := &AuthConfig{
				Mode:           "enterprise",
				TrustLocalhost: true,
			}
			logger := slog.Default()

			interceptor := newTestUnary(ba, cfg, logger)

			handler := &mockHandler{}
			info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

			p := &peer.Peer{
				Addr: &mockAddr{addr: tt.peerAddr},
			}
			ctx := peer.NewContext(context.Background(), p)

			resp, err := interceptor(ctx, "request", info, handler.handle)

			if tt.shouldBypass {
				require.NoError(t, err)
				assert.Equal(t, "response", resp)
				assert.True(t, handler.called)

				identity, ok := IdentityFromContext(handler.capturedCtx)
				require.True(t, ok, "localhost identity should be in context")
				assert.Equal(t, "localhost", identity.Subject)
				assert.Equal(t, "internal", identity.Issuer)
			} else {
				require.Error(t, err)
				assert.Equal(t, codes.Unauthenticated, status.Code(err))
				assert.False(t, handler.called)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Missing / invalid token tests
// ---------------------------------------------------------------------------

func TestUnaryAuthInterceptor_MissingToken(t *testing.T) {
	ba := &mockBetterAuthValidator{}
	cfg := &AuthConfig{Mode: "enterprise"}
	logger := slog.Default()

	interceptor := newTestUnary(ba, cfg, logger)

	handler := &mockHandler{}
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	ctx := context.Background()

	resp, err := interceptor(ctx, "request", info, handler.handle)

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.Contains(t, err.Error(), "missing bearer token")
	assert.False(t, handler.called, "handler should not be called when token is missing")
}

func TestUnaryAuthInterceptor_InvalidToken(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		wantErr    string
	}{
		{
			name:       "missing Bearer prefix",
			authHeader: "token123",
			wantErr:    "missing bearer token",
		},
		{
			name:       "empty token after Bearer",
			authHeader: "Bearer ",
			wantErr:    "missing bearer token",
		},
		{
			name:       "invalid format",
			authHeader: "Basic dXNlcjpwYXNz",
			wantErr:    "missing bearer token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ba := &mockBetterAuthValidator{}
			cfg := &AuthConfig{Mode: "enterprise"}
			logger := slog.Default()

			interceptor := newTestUnary(ba, cfg, logger)

			handler := &mockHandler{}
			info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

			md := metadata.New(map[string]string{
				"authorization": tt.authHeader,
			})
			ctx := metadata.NewIncomingContext(context.Background(), md)

			resp, err := interceptor(ctx, "request", info, handler.handle)

			require.Error(t, err)
			assert.Nil(t, resp)
			assert.Equal(t, codes.Unauthenticated, status.Code(err))
			assert.Contains(t, err.Error(), tt.wantErr)
			assert.False(t, handler.called)
		})
	}
}

// ---------------------------------------------------------------------------
// Authentication failure mapping tests
// ---------------------------------------------------------------------------

func TestUnaryAuthInterceptor_AuthenticationFailure(t *testing.T) {
	tests := []struct {
		name     string
		authErr  error
		wantCode codes.Code
		wantMsg  string
	}{
		{
			name:     "token expired",
			authErr:  ErrTokenExpired(),
			wantCode: codes.Unauthenticated,
			wantMsg:  "token expired",
		},
		{
			name:     "invalid signature",
			authErr:  ErrInvalidSignature(),
			wantCode: codes.Unauthenticated,
			wantMsg:  "invalid token signature",
		},
		{
			name:     "unknown issuer",
			authErr:  ErrUnknownIssuer("https://unknown.issuer.com"),
			wantCode: codes.Unauthenticated,
			wantMsg:  "unknown token issuer",
		},
		{
			name:     "audience mismatch",
			authErr:  ErrInvalidAudience("expected", "actual"),
			wantCode: codes.Unauthenticated,
			wantMsg:  "invalid token audience",
		},
		{
			name:     "invalid token",
			authErr:  errInvalidToken,
			wantCode: codes.Unauthenticated,
			wantMsg:  "invalid token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ba := &mockBetterAuthValidator{
				authenticateFn: func(ctx context.Context, token string) (*Identity, error) {
					return nil, tt.authErr
				},
			}
			cfg := &AuthConfig{Mode: "enterprise"}
			logger := slog.Default()

			interceptor := newTestUnary(ba, cfg, logger)

			handler := &mockHandler{}
			info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

			md := metadata.New(map[string]string{
				"authorization": "Bearer test-token",
			})
			ctx := metadata.NewIncomingContext(context.Background(), md)

			resp, err := interceptor(ctx, "request", info, handler.handle)

			require.Error(t, err)
			assert.Nil(t, resp)
			assert.Equal(t, tt.wantCode, status.Code(err))
			assert.Contains(t, err.Error(), tt.wantMsg)
			assert.False(t, handler.called)
		})
	}
}

// ---------------------------------------------------------------------------
// Successful authentication
// ---------------------------------------------------------------------------

func TestUnaryAuthInterceptor_SuccessfulAuth(t *testing.T) {
	expectedIdentity := &Identity{
		Identity: sdkauth.Identity{
			Subject: "user@example.com",
			Issuer:  "https://issuer.example.com",
			Email:   "user@example.com",
			Groups:  []string{"developers", "security-team"},
		},
		Roles:       []string{"mission:execute", "findings:read"},
		Permissions: []Permission{{Action: "execute", Resource: "mission", Scope: "*"}},
	}

	ba := &mockBetterAuthValidator{
		authenticateFn: func(ctx context.Context, token string) (*Identity, error) {
			assert.Equal(t, "test-token-123", token)
			return expectedIdentity, nil
		},
	}
	cfg := &AuthConfig{Mode: "enterprise"}
	logger := slog.Default()

	interceptor := newTestUnary(ba, cfg, logger)

	handler := &mockHandler{}
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	md := metadata.New(map[string]string{
		"authorization": "Bearer test-token-123",
	})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	resp, err := interceptor(ctx, "request", info, handler.handle)

	require.NoError(t, err)
	assert.Equal(t, "response", resp)
	assert.True(t, handler.called)

	identity, ok := IdentityFromContext(handler.capturedCtx)
	require.True(t, ok, "identity should be in context")
	assert.Equal(t, expectedIdentity.Subject, identity.Subject)
	assert.Equal(t, expectedIdentity.Issuer, identity.Issuer)
	assert.Equal(t, expectedIdentity.Email, identity.Email)
	assert.Equal(t, expectedIdentity.Groups, identity.Groups)
}

// ---------------------------------------------------------------------------
// Stream interceptor tests
// ---------------------------------------------------------------------------

func TestStreamAuthInterceptor_EmptyMode_Rejects(t *testing.T) {
	ba := &mockBetterAuthValidator{}
	cfg := &AuthConfig{Mode: ""}
	logger := slog.Default()

	interceptor := newTestStream(ba, cfg, logger)

	streamHandler := &mockStreamHandler{}
	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}

	ctx := context.Background()
	stream := &mockServerStream{ctx: ctx}

	err := interceptor(nil, stream, info, streamHandler.handle)

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.Contains(t, err.Error(), "authentication required")
	assert.False(t, streamHandler.called, "handler should not be called when auth mode is empty")
}

func TestStreamAuthInterceptor_DisabledMode_Rejects(t *testing.T) {
	ba := &mockBetterAuthValidator{}
	cfg := &AuthConfig{Mode: "disabled"}
	logger := slog.Default()

	interceptor := newTestStream(ba, cfg, logger)

	streamHandler := &mockStreamHandler{}
	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}

	ctx := context.Background()
	stream := &mockServerStream{ctx: ctx}

	err := interceptor(nil, stream, info, streamHandler.handle)

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.Contains(t, err.Error(), "authentication required")
	assert.False(t, streamHandler.called, "handler should not be called when auth mode is disabled")
}

func TestStreamAuthInterceptor_MissingToken(t *testing.T) {
	ba := &mockBetterAuthValidator{}
	cfg := &AuthConfig{Mode: "enterprise"}
	logger := slog.Default()

	interceptor := newTestStream(ba, cfg, logger)

	streamHandler := &mockStreamHandler{}
	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}

	ctx := context.Background()
	stream := &mockServerStream{ctx: ctx}

	err := interceptor(nil, stream, info, streamHandler.handle)

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.Contains(t, err.Error(), "missing bearer token")
	assert.False(t, streamHandler.called)
}

func TestStreamAuthInterceptor_SuccessfulAuth(t *testing.T) {
	expectedIdentity := &Identity{
		Identity: sdkauth.Identity{
			Subject: "user@example.com",
			Issuer:  "https://issuer.example.com",
		},
		Roles: []string{"admin"},
	}

	ba := &mockBetterAuthValidator{
		authenticateFn: func(ctx context.Context, token string) (*Identity, error) {
			return expectedIdentity, nil
		},
	}
	cfg := &AuthConfig{Mode: "enterprise"}
	logger := slog.Default()

	interceptor := newTestStream(ba, cfg, logger)

	streamHandler := &mockStreamHandler{}
	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}

	md := metadata.New(map[string]string{
		"authorization": "Bearer stream-token",
	})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	stream := &mockServerStream{ctx: ctx}

	err := interceptor(nil, stream, info, streamHandler.handle)

	require.NoError(t, err)
	assert.True(t, streamHandler.called)
}

// ---------------------------------------------------------------------------
// Context injection helpers
// ---------------------------------------------------------------------------

func TestContextWithIdentity(t *testing.T) {
	identity := &Identity{
		Identity: sdkauth.Identity{
			Subject: "test-user",
			Issuer:  "test-issuer",
			Email:   "test@example.com",
		},
		Roles: []string{"admin"},
	}

	ctx := ContextWithIdentity(context.Background(), identity)

	extracted, ok := IdentityFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, identity.Subject, extracted.Subject)
	assert.Equal(t, identity.Issuer, extracted.Issuer)
	assert.Equal(t, identity.Email, extracted.Email)
}

func TestIdentityFromContext_NoIdentity(t *testing.T) {
	ctx := context.Background()

	identity, ok := IdentityFromContext(ctx)
	assert.False(t, ok)
	assert.Nil(t, identity)
}

// ---------------------------------------------------------------------------
// extractBearerToken tests
// ---------------------------------------------------------------------------

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    string
		wantErr error
	}{
		{
			name: "valid bearer token",
			headers: map[string]string{
				"authorization": "Bearer token123",
			},
			want:    "token123",
			wantErr: nil,
		},
		{
			name:    "missing authorization header",
			headers: map[string]string{},
			want:    "",
			wantErr: errMissingToken,
		},
		{
			name: "missing Bearer prefix",
			headers: map[string]string{
				"authorization": "token123",
			},
			want:    "",
			wantErr: errInvalidToken,
		},
		{
			name: "empty token",
			headers: map[string]string{
				"authorization": "Bearer ",
			},
			want:    "",
			wantErr: errInvalidToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			md := metadata.New(tt.headers)
			ctx := metadata.NewIncomingContext(context.Background(), md)

			token, err := extractBearerToken(ctx)

			if tt.wantErr != nil {
				require.Error(t, err)
				assert.Equal(t, tt.wantErr, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, token)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// checkLocalhostBypassWithAddr tests
// ---------------------------------------------------------------------------

func TestCheckLocalhostBypassWithAddr(t *testing.T) {
	tests := []struct {
		name         string
		peerAddr     string
		wantBypassed bool
		wantSubject  string
	}{
		{
			name:         "IPv4 localhost",
			peerAddr:     "127.0.0.1:50051",
			wantBypassed: true,
			wantSubject:  "localhost",
		},
		{
			name:         "IPv6 localhost",
			peerAddr:     "[::1]:50051",
			wantBypassed: true,
			wantSubject:  "localhost",
		},
		{
			name:         "localhost hostname",
			peerAddr:     "localhost:50051",
			wantBypassed: true,
			wantSubject:  "localhost",
		},
		{
			name:         "remote IPv4",
			peerAddr:     "192.168.1.100:50051",
			wantBypassed: false,
		},
		{
			name:         "remote IPv6",
			peerAddr:     "[2001:db8::1]:50051",
			wantBypassed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &peer.Peer{
				Addr: &mockAddr{addr: tt.peerAddr},
			}
			ctx := peer.NewContext(context.Background(), p)

			identity, bypassed, addr := checkLocalhostBypassWithAddr(ctx, slog.Default(), "/test.Service/Method")

			assert.Equal(t, tt.wantBypassed, bypassed)
			if tt.wantBypassed {
				require.NotNil(t, identity)
				assert.Equal(t, tt.wantSubject, identity.Subject)
				assert.Equal(t, "internal", identity.Issuer)
				assert.Contains(t, identity.Roles, "platform-operator")
				assert.Equal(t, tt.peerAddr, addr)
			} else {
				assert.Nil(t, identity)
				assert.Empty(t, addr)
			}
		})
	}
}

func TestCheckLocalhostBypassWithAddr_NoPeer(t *testing.T) {
	ctx := context.Background()

	identity, bypassed, addr := checkLocalhostBypassWithAddr(ctx, slog.Default(), "/test.Service/Method")

	assert.False(t, bypassed)
	assert.Nil(t, identity)
	assert.Empty(t, addr)
}

// ---------------------------------------------------------------------------
// mockStreamHandlerWithCtx captures the stream context for tenant assertions.
// ---------------------------------------------------------------------------

type mockStreamHandlerWithCtx struct {
	called      bool
	err         error
	capturedCtx context.Context
}

func (m *mockStreamHandlerWithCtx) handle(srv any, stream grpc.ServerStream) error {
	m.called = true
	m.capturedCtx = stream.Context()
	return m.err
}

// ---------------------------------------------------------------------------
// Tenant extraction helpers for tests
// ---------------------------------------------------------------------------

func newTestIdentity(issuer string, claims map[string]any) *Identity {
	return &Identity{
		Identity: sdkauth.Identity{
			Subject: "user@example.com",
			Issuer:  issuer,
			Email:   "user@example.com",
			Claims:  claims,
		},
		Roles: []string{"developer"},
	}
}

func newBearerContext(token string) context.Context {
	md := metadata.New(map[string]string{
		"authorization": "Bearer " + token,
	})
	return metadata.NewIncomingContext(context.Background(), md)
}

// ---------------------------------------------------------------------------
// Enterprise/SaaS tenant extraction tests
// ---------------------------------------------------------------------------

func TestUnaryAuthInterceptor_EnterpriseTenantExtraction(t *testing.T) {
	const testIssuer = "https://idp.example.com"

	tests := []struct {
		name          string
		mode          string
		identity      *Identity
		tenantClaim   string
		defaultTenant string
		wantTenant    string
		wantErr       bool
	}{
		{
			// Scenario A: enterprise + user session WITH tenant claim → claim value wins.
			name: "A: enterprise session with tenant claim",
			mode: "enterprise",
			identity: newTestIdentity(testIssuer, map[string]any{
				"tenant_id": "team-alpha",
			}),
			tenantClaim:   "tenant_id",
			defaultTenant: "",
			wantTenant:    "team-alpha",
		},
		{
			// Scenario B: enterprise + user session WITHOUT tenant claim + DefaultTenant set → fallback.
			name:          "B: enterprise session without tenant claim, default tenant set",
			mode:          "enterprise",
			identity:      newTestIdentity(testIssuer, map[string]any{}),
			tenantClaim:   "tenant_id",
			defaultTenant: "fallback-tenant",
			wantTenant:    "fallback-tenant",
		},
		{
			// Scenario C: enterprise + user session WITHOUT tenant claim + NO DefaultTenant.
			// After authz-02, TenantFromContext returns SystemTenant when no tenant set.
			name:          "C: enterprise session without tenant claim, no default",
			mode:          "enterprise",
			identity:      newTestIdentity(testIssuer, map[string]any{}),
			tenantClaim:   "tenant_id",
			defaultTenant: "",
			wantTenant:    SystemTenant,
		},
		{
			// Scenario D: enterprise + API key identity with tenant claim → claim value wins.
			name: "D: enterprise API key with tenant claim",
			mode: "enterprise",
			identity: newTestIdentity(apiKeyIssuer, map[string]any{
				"tenant_id": "api-tenant",
			}),
			tenantClaim:   "tenant_id",
			defaultTenant: "",
			wantTenant:    "api-tenant",
		},
		{
			// Scenario E: saas mode with tenant claim → claim value (unchanged behaviour).
			name: "E: saas session with tenant claim",
			mode: "saas",
			identity: newTestIdentity(testIssuer, map[string]any{
				"tenant_id": "saas-tenant",
			}),
			tenantClaim:   "tenant_id",
			defaultTenant: "",
			wantTenant:    "saas-tenant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ba := &mockBetterAuthValidator{
				authenticateFn: func(ctx context.Context, token string) (*Identity, error) {
					return tt.identity, nil
				},
			}
			cfg := &AuthConfig{
				Mode:          tt.mode,
				TenantClaim:   tt.tenantClaim,
				DefaultTenant: tt.defaultTenant,
			}
			logger := slog.Default()

			interceptor := newTestUnary(ba, cfg, logger)

			handler := &mockHandler{}
			info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
			ctx := newBearerContext("test-token")

			resp, err := interceptor(ctx, "request", info, handler.handle)

			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, resp)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, "response", resp)
			assert.True(t, handler.called)

			gotTenant := TenantFromContext(handler.capturedCtx)
			assert.Equal(t, tt.wantTenant, gotTenant)
		})
	}
}

func TestStreamAuthInterceptor_EnterpriseTenantExtraction(t *testing.T) {
	const testIssuer = "https://idp.example.com"

	tests := []struct {
		name          string
		mode          string
		identity      *Identity
		tenantClaim   string
		defaultTenant string
		wantTenant    string
	}{
		{
			name: "A: enterprise session with tenant claim",
			mode: "enterprise",
			identity: newTestIdentity(testIssuer, map[string]any{
				"tenant_id": "team-alpha",
			}),
			tenantClaim:   "tenant_id",
			defaultTenant: "",
			wantTenant:    "team-alpha",
		},
		{
			name:          "B: enterprise session without tenant claim, default tenant set",
			mode:          "enterprise",
			identity:      newTestIdentity(testIssuer, map[string]any{}),
			tenantClaim:   "tenant_id",
			defaultTenant: "fallback-tenant",
			wantTenant:    "fallback-tenant",
		},
		{
			name:          "C: enterprise session without tenant claim, no default",
			mode:          "enterprise",
			identity:      newTestIdentity(testIssuer, map[string]any{}),
			tenantClaim:   "tenant_id",
			defaultTenant: "",
			wantTenant:    SystemTenant,
		},
		{
			name: "D: enterprise API key with tenant claim",
			mode: "enterprise",
			identity: newTestIdentity(apiKeyIssuer, map[string]any{
				"tenant_id": "api-tenant",
			}),
			tenantClaim:   "tenant_id",
			defaultTenant: "",
			wantTenant:    "api-tenant",
		},
		{
			name: "E: saas session with tenant claim",
			mode: "saas",
			identity: newTestIdentity(testIssuer, map[string]any{
				"tenant_id": "saas-tenant",
			}),
			tenantClaim:   "tenant_id",
			defaultTenant: "",
			wantTenant:    "saas-tenant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ba := &mockBetterAuthValidator{
				authenticateFn: func(ctx context.Context, token string) (*Identity, error) {
					return tt.identity, nil
				},
			}
			cfg := &AuthConfig{
				Mode:          tt.mode,
				TenantClaim:   tt.tenantClaim,
				DefaultTenant: tt.defaultTenant,
			}
			logger := slog.Default()

			interceptor := newTestStream(ba, cfg, logger)

			streamHandler := &mockStreamHandlerWithCtx{}
			info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}
			ctx := newBearerContext("stream-token")
			stream := &mockServerStream{ctx: ctx}

			err := interceptor(nil, stream, info, streamHandler.handle)

			require.NoError(t, err)
			assert.True(t, streamHandler.called)

			gotTenant := TenantFromContext(streamHandler.capturedCtx)
			assert.Equal(t, tt.wantTenant, gotTenant)
		})
	}
}

// ---------------------------------------------------------------------------
// toGRPCStatus tests
// ---------------------------------------------------------------------------

func TestToGRPCStatus(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode codes.Code
		wantMsg  string
	}{
		{
			name:     "nil error",
			err:      nil,
			wantCode: codes.OK,
			wantMsg:  "",
		},
		{
			name:     "token expired",
			err:      ErrTokenExpired(),
			wantCode: codes.Unauthenticated,
			wantMsg:  "token expired",
		},
		{
			name:     "invalid signature",
			err:      ErrInvalidSignature(),
			wantCode: codes.Unauthenticated,
			wantMsg:  "invalid token signature",
		},
		{
			name:     "unknown issuer",
			err:      ErrUnknownIssuer("https://unknown.issuer.com"),
			wantCode: codes.Unauthenticated,
			wantMsg:  "unknown token issuer",
		},
		{
			name:     "audience mismatch",
			err:      ErrInvalidAudience("expected", "actual"),
			wantCode: codes.Unauthenticated,
			wantMsg:  "invalid token audience",
		},
		{
			name:     "invalid token",
			err:      errInvalidToken,
			wantCode: codes.Unauthenticated,
			wantMsg:  "invalid token",
		},
		{
			name:     "missing token",
			err:      errMissingToken,
			wantCode: codes.Unauthenticated,
			wantMsg:  "missing token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grpcErr := toGRPCStatus(tt.err)

			if tt.err == nil {
				assert.Nil(t, grpcErr)
			} else {
				require.Error(t, grpcErr)
				assert.Equal(t, tt.wantCode, status.Code(grpcErr))
				assert.Contains(t, grpcErr.Error(), tt.wantMsg)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 4-path routing tests
// ---------------------------------------------------------------------------

// fakeAgentJWTToken constructs a minimal three-part JWT string with an agent+jwt
// header, so IsAgentAuthJWT returns true. The payload and signature parts are
// placeholder values — the mock verifier does not perform any crypto.
func fakeAgentJWTToken() string {
	// base64url({"typ":"agent+jwt","alg":"EdDSA"})
	hdr := "eyJ0eXAiOiJhZ2VudCtqd3QiLCJhbGciOiJFZERTQSJ9"
	return hdr + ".cGF5bG9hZA.c2ln"
}

// fakeK8sToken constructs a three-part dot-separated string that is NOT an
// agent+jwt, triggering the K8s SA token path (isK8sToken returns true for any
// three-part token that is not an agent+jwt or gsk_ token).
func fakeK8sToken() string {
	return "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6ZGVmYXVsdDpteS1zYSJ9.c2ln"
}

// TestRouteAuth_APIKeyPath verifies that gsk_-prefixed tokens route to APIKeyAuthenticator.
func TestRouteAuth_APIKeyPath(t *testing.T) {
	expectedIdentity := &Identity{
		Identity: sdkauth.Identity{Subject: "gsk_tenant_abc123", Issuer: "apikey"},
		Roles:    []string{"admin"},
	}

	apiKeys := &mockAPIKeyValidator{
		authenticateFn: func(ctx context.Context, token string) (*Identity, error) {
			assert.Equal(t, "gsk_tenant_abc123def456", token)
			return expectedIdentity, nil
		},
	}
	ba := &mockBetterAuthValidator{
		authenticateFn: func(_ context.Context, _ string) (*Identity, error) {
			t.Fatal("BetterAuth must not be called for gsk_ tokens")
			return nil, nil
		},
	}

	cfg := &AuthConfig{Mode: "enterprise"}
	interceptor := buildUnaryInterceptor(apiKeys, nil, ba, cfg, slog.Default())

	handler := &mockHandler{}
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	ctx := newBearerContext("gsk_tenant_abc123def456")

	resp, err := interceptor(ctx, "req", info, handler.handle)
	require.NoError(t, err)
	assert.Equal(t, "response", resp)
	assert.True(t, handler.called)

	got, ok := GibsonIdentityFromContext(handler.capturedCtx)
	require.True(t, ok)
	assert.Equal(t, expectedIdentity.Subject, got.Subject)
}

// TestRouteAuth_APIKeyPath_ValidatorNil checks that a gsk_ token with no
// configured API key validator returns Unauthenticated.
func TestRouteAuth_APIKeyPath_ValidatorNil(t *testing.T) {
	ba := &mockBetterAuthValidator{}
	cfg := &AuthConfig{Mode: "enterprise"}
	interceptor := buildUnaryInterceptor(nil, nil, ba, cfg, slog.Default())

	handler := &mockHandler{}
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	ctx := newBearerContext("gsk_tenant_notconfigured")

	_, err := interceptor(ctx, "req", info, handler.handle)
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.False(t, handler.called)
}

// TestRouteAuth_AgentJWTPath verifies that agent+jwt tokens route to AgentJWTValidator.
func TestRouteAuth_AgentJWTPath(t *testing.T) {
	const ownerUserID = "user-owner-123"
	const tenantID = "acme"
	const agentID = "agent-abc"
	const hostID = "host-xyz"

	agentValidator := &mockAgentJWTValidator{
		verifyFn: func(ctx context.Context, tokenStr, expectedAud string) (*AgentAuthClaims, error) {
			return &AgentAuthClaims{
				AgentID:     agentID,
				HostID:      hostID,
				TenantID:    tenantID,
				OwnerUserID: ownerUserID,
				ExpiresAt:   time.Now().Add(time.Minute),
			}, nil
		},
	}
	ba := &mockBetterAuthValidator{
		authenticateFn: func(_ context.Context, _ string) (*Identity, error) {
			t.Fatal("BetterAuth must not be called for agent+jwt tokens")
			return nil, nil
		},
	}

	cfg := &AuthConfig{Mode: "enterprise"}
	interceptor := buildUnaryInterceptor(nil, agentValidator, ba, cfg, slog.Default())

	handler := &mockHandler{}
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	ctx := newBearerContext(fakeAgentJWTToken())

	resp, err := interceptor(ctx, "req", info, handler.handle)
	require.NoError(t, err)
	assert.Equal(t, "response", resp)
	assert.True(t, handler.called)

	// Agent Auth JWT sets Subject to the owner's user ID, not the agent ID.
	got, ok := GibsonIdentityFromContext(handler.capturedCtx)
	require.True(t, ok)
	assert.Equal(t, ownerUserID, got.Subject, "Subject must be the owner user ID")
	assert.Equal(t, "agent-auth", got.Issuer)
	assert.Equal(t, agentID, got.Claims["agent_id"])
	assert.Equal(t, hostID, got.Claims["host_id"])
}

// TestRouteAuth_AgentJWTPath_VerifyError checks that a failed JWT verification
// returns Unauthenticated.
func TestRouteAuth_AgentJWTPath_VerifyError(t *testing.T) {
	agentValidator := &mockAgentJWTValidator{
		verifyFn: func(_ context.Context, _, _ string) (*AgentAuthClaims, error) {
			return nil, fmt.Errorf("agentauth: VerifyAgentJWT: signature verification failed")
		},
	}
	ba := &mockBetterAuthValidator{}
	cfg := &AuthConfig{Mode: "enterprise"}
	interceptor := buildUnaryInterceptor(nil, agentValidator, ba, cfg, slog.Default())

	handler := &mockHandler{}
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	ctx := newBearerContext(fakeAgentJWTToken())

	_, err := interceptor(ctx, "req", info, handler.handle)
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err), "non-AuthError becomes Internal")
	assert.False(t, handler.called)
}

// TestRouteAuth_BetterAuthPath verifies that plain tokens route to BetterAuthValidator.
func TestRouteAuth_BetterAuthPath(t *testing.T) {
	expectedIdentity := &Identity{
		Identity: sdkauth.Identity{Subject: "user-456", Issuer: "better-auth"},
		Tenants:  []string{"acme"},
	}

	ba := &mockBetterAuthValidator{
		authenticateFn: func(ctx context.Context, token string) (*Identity, error) {
			assert.Equal(t, "plain-session-token.signature", token)
			return expectedIdentity, nil
		},
	}
	cfg := &AuthConfig{Mode: "enterprise"}
	interceptor := buildUnaryInterceptor(nil, nil, ba, cfg, slog.Default())

	handler := &mockHandler{}
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	ctx := newBearerContext("plain-session-token.signature")

	resp, err := interceptor(ctx, "req", info, handler.handle)
	require.NoError(t, err)
	assert.Equal(t, "response", resp)
	assert.True(t, handler.called)

	got, ok := GibsonIdentityFromContext(handler.capturedCtx)
	require.True(t, ok)
	assert.Equal(t, expectedIdentity.Subject, got.Subject)
}

// TestRouteAuth_BetterAuthPath_ValidatorNil checks that a missing BetterAuth
// validator returns Unauthenticated for plain tokens.
func TestRouteAuth_BetterAuthPath_ValidatorNil(t *testing.T) {
	cfg := &AuthConfig{Mode: "enterprise"}
	interceptor := buildUnaryInterceptor(nil, nil, nil, cfg, slog.Default())

	handler := &mockHandler{}
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	ctx := newBearerContext("plain-session-token.signature")

	_, err := interceptor(ctx, "req", info, handler.handle)
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.False(t, handler.called)
}

// TestRouteAuth_EmptyToken verifies that an empty (missing) token returns Unauthenticated.
func TestRouteAuth_EmptyToken(t *testing.T) {
	ba := &mockBetterAuthValidator{}
	cfg := &AuthConfig{Mode: "enterprise"}
	interceptor := buildUnaryInterceptor(nil, nil, ba, cfg, slog.Default())

	handler := &mockHandler{}
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
	ctx := context.Background() // no authorization metadata

	_, err := interceptor(ctx, "req", info, handler.handle)
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.False(t, handler.called)
}

// TestRouteAuth_TrustLocalhost verifies that the localhost bypass fires before
// token routing and creates a synthetic platform-operator identity.
func TestRouteAuth_TrustLocalhost(t *testing.T) {
	ba := &mockBetterAuthValidator{
		authenticateFn: func(_ context.Context, _ string) (*Identity, error) {
			t.Fatal("BetterAuth must not be called when localhost bypass fires")
			return nil, nil
		},
	}
	cfg := &AuthConfig{
		Mode:           "enterprise",
		TrustLocalhost: true,
	}
	interceptor := buildUnaryInterceptor(nil, nil, ba, cfg, slog.Default())

	handler := &mockHandler{}
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	p := &peer.Peer{Addr: &mockAddr{addr: "127.0.0.1:54321"}}
	ctx := peer.NewContext(context.Background(), p)
	// No authorization header — localhost bypass must fire before token extraction.

	resp, err := interceptor(ctx, "req", info, handler.handle)
	require.NoError(t, err)
	assert.Equal(t, "response", resp)
	assert.True(t, handler.called)

	got, ok := GibsonIdentityFromContext(handler.capturedCtx)
	require.True(t, ok)
	assert.Equal(t, "localhost", got.Subject)
	assert.Equal(t, "internal", got.Issuer)
	assert.Contains(t, got.Roles, "platform-operator")
}

// TestAgentClaimsToIdentity verifies that the owner user ID becomes the Subject
// and that the agent/host IDs are preserved as audit claims.
func TestAgentClaimsToIdentity(t *testing.T) {
	claims := &AgentAuthClaims{
		AgentID:     "agent-abc",
		HostID:      "host-xyz",
		TenantID:    "acme",
		OwnerUserID: "user-owner-456",
		ExpiresAt:   time.Now().Add(time.Minute),
	}

	identity := agentClaimsToIdentity(claims)

	assert.Equal(t, "user-owner-456", identity.Subject, "Subject must be owner user ID")
	assert.Equal(t, "agent-auth", identity.Issuer)
	assert.Equal(t, []string{"acme"}, identity.Tenants)
	assert.Equal(t, "agent-abc", identity.Claims["agent_id"])
	assert.Equal(t, "host-xyz", identity.Claims["host_id"])
}

// TestIsAgentAuthJWT verifies header-based detection of Agent Auth JWTs.
func TestIsAgentAuthJWT(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  bool
	}{
		{
			name:  "agent+jwt EdDSA",
			token: fakeAgentJWTToken(),
			want:  true,
		},
		{
			name: "host+jwt EdDSA",
			// base64url({"typ":"host+jwt","alg":"EdDSA"})
			token: "eyJ0eXAiOiJob3N0K2p3dCIsImFsZyI6IkVkRFNBIn0.cGF5bG9hZA.c2ln",
			want:  true,
		},
		{
			name:  "gsk_ API key",
			token: "gsk_tenant_abc123",
			want:  false,
		},
		{
			name:  "compact RS256 JWT (K8s SA style)",
			token: fakeK8sToken(),
			want:  false,
		},
		{
			name:  "plain session token",
			token: "plain-session-token.signature",
			want:  false,
		},
		{
			name:  "empty string",
			token: "",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsAgentAuthJWT(tt.token))
		})
	}
}
