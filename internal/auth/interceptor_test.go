package auth

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// mockAuthenticator is a test implementation of Authenticator.
type mockAuthenticator struct {
	authenticateFn func(ctx context.Context, token string) (*Identity, error)
}

func (m *mockAuthenticator) Authenticate(ctx context.Context, token string) (*Identity, error) {
	if m.authenticateFn != nil {
		return m.authenticateFn(ctx, token)
	}
	return nil, errInvalidToken
}

// mockHandler is a test gRPC handler.
type mockHandler struct {
	called     bool
	err        error
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

// TestUnaryAuthInterceptor_AuthDisabled tests that requests pass through when auth is disabled.
func TestUnaryAuthInterceptor_AuthDisabled(t *testing.T) {
	auth := &mockAuthenticator{}
	cfg := &AuthConfig{Enabled: false}
	logger := slog.Default()

	interceptor := UnaryAuthInterceptor(auth, cfg, logger)

	handler := &mockHandler{}
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	ctx := context.Background()
	resp, err := interceptor(ctx, "request", info, handler.handle)

	require.NoError(t, err)
	assert.Equal(t, "response", resp)
	assert.True(t, handler.called, "handler should be called when auth is disabled")
}

// TestUnaryAuthInterceptor_LocalhostBypass tests localhost bypass functionality.
func TestUnaryAuthInterceptor_LocalhostBypass(t *testing.T) {
	tests := []struct {
		name      string
		peerAddr  string
		shouldBypass bool
	}{
		{
			name:      "IPv4 localhost",
			peerAddr:  "127.0.0.1:12345",
			shouldBypass: true,
		},
		{
			name:      "IPv6 localhost",
			peerAddr:  "[::1]:12345",
			shouldBypass: true,
		},
		{
			name:      "localhost hostname",
			peerAddr:  "localhost:12345",
			shouldBypass: true,
		},
		{
			name:      "remote address",
			peerAddr:  "192.168.1.100:12345",
			shouldBypass: false,
		},
		{
			name:      "public IPv6",
			peerAddr:  "[2001:db8::1]:12345",
			shouldBypass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := &mockAuthenticator{}
			cfg := &AuthConfig{
				Enabled:        true,
				TrustLocalhost: true,
			}
			logger := slog.Default()

			interceptor := UnaryAuthInterceptor(auth, cfg, logger)

			handler := &mockHandler{}
			info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

			// Create context with peer information
			p := &peer.Peer{
				Addr: &mockAddr{addr: tt.peerAddr},
			}
			ctx := peer.NewContext(context.Background(), p)

			resp, err := interceptor(ctx, "request", info, handler.handle)

			if tt.shouldBypass {
				// Should succeed without token
				require.NoError(t, err)
				assert.Equal(t, "response", resp)
				assert.True(t, handler.called)

				// Verify localhost identity was injected (check captured context from handler)
				identity, ok := IdentityFromContext(handler.capturedCtx)
				require.True(t, ok, "localhost identity should be in context")
				assert.Equal(t, "localhost", identity.Subject)
				assert.Equal(t, "internal", identity.Issuer)
				assert.Contains(t, identity.Roles, "admin")
			} else {
				// Should fail without token
				require.Error(t, err)
				assert.Equal(t, codes.Unauthenticated, status.Code(err))
				assert.False(t, handler.called)
			}
		})
	}
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

// TestUnaryAuthInterceptor_MissingToken tests missing bearer token error.
func TestUnaryAuthInterceptor_MissingToken(t *testing.T) {
	auth := &mockAuthenticator{}
	cfg := &AuthConfig{Enabled: true}
	logger := slog.Default()

	interceptor := UnaryAuthInterceptor(auth, cfg, logger)

	handler := &mockHandler{}
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	// Context without authorization metadata
	ctx := context.Background()

	resp, err := interceptor(ctx, "request", info, handler.handle)

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.Contains(t, err.Error(), "missing bearer token")
	assert.False(t, handler.called, "handler should not be called when token is missing")
}

// TestUnaryAuthInterceptor_InvalidToken tests invalid token format.
func TestUnaryAuthInterceptor_InvalidToken(t *testing.T) {
	tests := []struct {
		name     string
		authHeader string
		wantErr  string
	}{
		{
			name:     "missing Bearer prefix",
			authHeader: "token123",
			wantErr:  "missing bearer token",
		},
		{
			name:     "empty token after Bearer",
			authHeader: "Bearer ",
			wantErr:  "missing bearer token",
		},
		{
			name:     "invalid format",
			authHeader: "Basic dXNlcjpwYXNz",
			wantErr:  "missing bearer token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := &mockAuthenticator{}
			cfg := &AuthConfig{Enabled: true}
			logger := slog.Default()

			interceptor := UnaryAuthInterceptor(auth, cfg, logger)

			handler := &mockHandler{}
			info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

			// Context with invalid authorization metadata
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

// TestUnaryAuthInterceptor_AuthenticationFailure tests authentication failure scenarios.
func TestUnaryAuthInterceptor_AuthenticationFailure(t *testing.T) {
	tests := []struct {
		name    string
		authErr error
		wantCode codes.Code
		wantMsg string
	}{
		{
			name:    "token expired",
			authErr: ErrTokenExpired(),
			wantCode: codes.Unauthenticated,
			wantMsg: "token expired",
		},
		{
			name:    "invalid signature",
			authErr: ErrInvalidSignature(),
			wantCode: codes.Unauthenticated,
			wantMsg: "invalid token signature",
		},
		{
			name:    "unknown issuer",
			authErr: ErrUnknownIssuer("https://unknown.issuer.com"),
			wantCode: codes.Unauthenticated,
			wantMsg: "unknown token issuer",
		},
		{
			name:    "audience mismatch",
			authErr: ErrInvalidAudience("expected", "actual"),
			wantCode: codes.Unauthenticated,
			wantMsg: "invalid token audience",
		},
		{
			name:    "invalid token",
			authErr: errInvalidToken,
			wantCode: codes.Unauthenticated,
			wantMsg: "invalid token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := &mockAuthenticator{
				authenticateFn: func(ctx context.Context, token string) (*Identity, error) {
					return nil, tt.authErr
				},
			}
			cfg := &AuthConfig{Enabled: true}
			logger := slog.Default()

			interceptor := UnaryAuthInterceptor(auth, cfg, logger)

			handler := &mockHandler{}
			info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

			// Context with valid Bearer token format
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

// TestUnaryAuthInterceptor_SuccessfulAuth tests successful authentication flow.
func TestUnaryAuthInterceptor_SuccessfulAuth(t *testing.T) {
	expectedIdentity := &Identity{
		Subject:     "user@example.com",
		Issuer:      "https://issuer.example.com",
		Email:       "user@example.com",
		Groups:      []string{"developers", "security-team"},
		Roles:       []string{"mission:execute", "findings:read"},
		Permissions: []Permission{{Action: "execute", Resource: "mission", Scope: "*"}},
	}

	auth := &mockAuthenticator{
		authenticateFn: func(ctx context.Context, token string) (*Identity, error) {
			assert.Equal(t, "test-token-123", token)
			return expectedIdentity, nil
		},
	}
	cfg := &AuthConfig{Enabled: true}
	logger := slog.Default()

	interceptor := UnaryAuthInterceptor(auth, cfg, logger)

	handler := &mockHandler{}
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

	// Context with valid Bearer token
	md := metadata.New(map[string]string{
		"authorization": "Bearer test-token-123",
	})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	resp, err := interceptor(ctx, "request", info, handler.handle)

	require.NoError(t, err)
	assert.Equal(t, "response", resp)
	assert.True(t, handler.called)

	// Verify identity was injected into context (check captured context from handler)
	identity, ok := IdentityFromContext(handler.capturedCtx)
	require.True(t, ok, "identity should be in context")
	assert.Equal(t, expectedIdentity.Subject, identity.Subject)
	assert.Equal(t, expectedIdentity.Issuer, identity.Issuer)
	assert.Equal(t, expectedIdentity.Email, identity.Email)
	assert.Equal(t, expectedIdentity.Groups, identity.Groups)
	assert.Equal(t, expectedIdentity.Roles, identity.Roles)
}

// TestStreamAuthInterceptor_AuthDisabled tests stream auth with disabled authentication.
func TestStreamAuthInterceptor_AuthDisabled(t *testing.T) {
	auth := &mockAuthenticator{}
	cfg := &AuthConfig{Enabled: false}
	logger := slog.Default()

	interceptor := StreamAuthInterceptor(auth, cfg, logger)

	streamHandler := &mockStreamHandler{}
	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}

	ctx := context.Background()
	stream := &mockServerStream{ctx: ctx}

	err := interceptor(nil, stream, info, streamHandler.handle)

	require.NoError(t, err)
	assert.True(t, streamHandler.called)
}

// TestStreamAuthInterceptor_MissingToken tests stream auth with missing token.
func TestStreamAuthInterceptor_MissingToken(t *testing.T) {
	auth := &mockAuthenticator{}
	cfg := &AuthConfig{Enabled: true}
	logger := slog.Default()

	interceptor := StreamAuthInterceptor(auth, cfg, logger)

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

// TestStreamAuthInterceptor_SuccessfulAuth tests successful stream authentication.
func TestStreamAuthInterceptor_SuccessfulAuth(t *testing.T) {
	expectedIdentity := &Identity{
		Subject: "user@example.com",
		Issuer:  "https://issuer.example.com",
		Roles:   []string{"admin"},
	}

	auth := &mockAuthenticator{
		authenticateFn: func(ctx context.Context, token string) (*Identity, error) {
			return expectedIdentity, nil
		},
	}
	cfg := &AuthConfig{Enabled: true}
	logger := slog.Default()

	interceptor := StreamAuthInterceptor(auth, cfg, logger)

	streamHandler := &mockStreamHandler{}
	info := &grpc.StreamServerInfo{FullMethod: "/test.Service/StreamMethod"}

	// Context with valid Bearer token
	md := metadata.New(map[string]string{
		"authorization": "Bearer stream-token",
	})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	stream := &mockServerStream{ctx: ctx}

	err := interceptor(nil, stream, info, streamHandler.handle)

	require.NoError(t, err)
	assert.True(t, streamHandler.called)
}

// TestContextWithIdentity tests identity context injection and extraction.
func TestContextWithIdentity(t *testing.T) {
	identity := &Identity{
		Subject: "test-user",
		Issuer:  "test-issuer",
		Email:   "test@example.com",
		Roles:   []string{"admin"},
	}

	// Test injection
	ctx := ContextWithIdentity(context.Background(), identity)

	// Test extraction
	extracted, ok := IdentityFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, identity.Subject, extracted.Subject)
	assert.Equal(t, identity.Issuer, extracted.Issuer)
	assert.Equal(t, identity.Email, extracted.Email)
	assert.Equal(t, identity.Roles, extracted.Roles)
}

// TestIdentityFromContext_NoIdentity tests extraction when no identity is present.
func TestIdentityFromContext_NoIdentity(t *testing.T) {
	ctx := context.Background()

	identity, ok := IdentityFromContext(ctx)
	assert.False(t, ok)
	assert.Nil(t, identity)
}

// TestRequirePermission tests permission checking.
func TestRequirePermission(t *testing.T) {
	tests := []struct {
		name        string
		identity    *Identity
		action      string
		resource    string
		wantErr     bool
		wantCode    codes.Code
		wantMsg     string
	}{
		{
			name: "has exact permission",
			identity: &Identity{
				Subject:     "user",
				Permissions: []Permission{{Action: "execute", Resource: "mission", Scope: "*"}},
			},
			action:   "execute",
			resource: "mission",
			wantErr:  false,
		},
		{
			name: "has wildcard action",
			identity: &Identity{
				Subject:     "user",
				Permissions: []Permission{{Action: "*", Resource: "mission", Scope: "*"}},
			},
			action:   "execute",
			resource: "mission",
			wantErr:  false,
		},
		{
			name: "has wildcard resource",
			identity: &Identity{
				Subject:     "user",
				Permissions: []Permission{{Action: "execute", Resource: "*", Scope: "*"}},
			},
			action:   "execute",
			resource: "mission",
			wantErr:  false,
		},
		{
			name: "missing permission",
			identity: &Identity{
				Subject:     "user",
				Permissions: []Permission{{Action: "read", Resource: "finding", Scope: "*"}},
			},
			action:   "execute",
			resource: "mission",
			wantErr:  true,
			wantCode: codes.PermissionDenied,
			wantMsg:  "insufficient permissions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := ContextWithIdentity(context.Background(), tt.identity)

			err := RequirePermission(ctx, tt.action, tt.resource)

			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, tt.wantCode, status.Code(err))
				assert.Contains(t, err.Error(), tt.wantMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestRequirePermission_NoIdentity tests RequirePermission without identity.
func TestRequirePermission_NoIdentity(t *testing.T) {
	ctx := context.Background()

	err := RequirePermission(ctx, "execute", "mission")

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.Contains(t, err.Error(), "not authenticated")
}

// TestRequireRole tests role checking.
func TestRequireRole(t *testing.T) {
	tests := []struct {
		name     string
		identity *Identity
		role     string
		wantErr  bool
		wantCode codes.Code
		wantMsg  string
	}{
		{
			name: "has exact role",
			identity: &Identity{
				Subject: "user",
				Roles:   []string{"admin", "developer"},
			},
			role:    "admin",
			wantErr: false,
		},
		{
			name: "missing role",
			identity: &Identity{
				Subject: "user",
				Roles:   []string{"developer"},
			},
			role:     "admin",
			wantErr:  true,
			wantCode: codes.PermissionDenied,
			wantMsg:  "missing required role",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := ContextWithIdentity(context.Background(), tt.identity)

			err := RequireRole(ctx, tt.role)

			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, tt.wantCode, status.Code(err))
				assert.Contains(t, err.Error(), tt.wantMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestRequireRole_NoIdentity tests RequireRole without identity.
func TestRequireRole_NoIdentity(t *testing.T) {
	ctx := context.Background()

	err := RequireRole(ctx, "admin")

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.Contains(t, err.Error(), "not authenticated")
}

// TestExtractBearerToken tests bearer token extraction.
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
			name: "missing authorization header",
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

// TestCheckLocalhostBypassWithAddr tests localhost detection.
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
				assert.Contains(t, identity.Roles, "admin")
				assert.Equal(t, tt.peerAddr, addr)
			} else {
				assert.Nil(t, identity)
				assert.Empty(t, addr)
			}
		})
	}
}

// TestCheckLocalhostBypassWithAddr_NoPeer tests localhost bypass without peer context.
func TestCheckLocalhostBypassWithAddr_NoPeer(t *testing.T) {
	ctx := context.Background()

	identity, bypassed, addr := checkLocalhostBypassWithAddr(ctx, slog.Default(), "/test.Service/Method")

	assert.False(t, bypassed)
	assert.Nil(t, identity)
	assert.Empty(t, addr)
}

// TestToGRPCStatus tests error code mapping.
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
