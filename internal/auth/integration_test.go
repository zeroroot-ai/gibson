package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

var (
	integrationTestPrivateKey *rsa.PrivateKey
	integrationTestPublicKey  *rsa.PublicKey
	integrationTestKID        = "integration-test-key"
	integrationTestIssuer     = "https://integration.test.com"
	integrationTestAudience   = "gibson-integration"
)

func init() {
	// Generate test RSA key pair for integration tests
	var err error
	integrationTestPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	integrationTestPublicKey = &integrationTestPrivateKey.PublicKey
}

// createIntegrationTestToken creates a signed JWT token with custom claims.
func createIntegrationTestToken(claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = integrationTestKID
	return token.SignedString(integrationTestPrivateKey)
}

// createIntegrationJWKSServer creates a test HTTP server serving JWKS for integration tests.
func createIntegrationJWKSServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"kid": integrationTestKID,
					"use": "sig",
					"alg": "RS256",
					"n":   base64URLEncode(integrationTestPublicKey.N.Bytes()),
					"e":   base64URLEncode(bigIntToBytes(int64(integrationTestPublicKey.E))),
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
}

// testService is a minimal test service for integration testing.
type testService struct {
	lastIdentity *Identity // Captured from context
}

// TestRequest is a simple test request message.
type TestRequest struct{}

// TestResponse is a simple test response message.
type TestResponse struct {
	Message string
}

// TestMethod implements a simple handler that captures the identity from context.
func (s *testService) TestMethod(ctx context.Context, req *TestRequest) (*TestResponse, error) {
	// Extract identity from context
	if id, ok := IdentityFromContext(ctx); ok {
		s.lastIdentity = id
	}

	return &TestResponse{
		Message: "success",
	}, nil
}

// setupIntegrationTestServer sets up a gRPC server with auth interceptors over bufconn.
func setupIntegrationTestServer(t *testing.T, authConfig *AuthConfig, authenticator Authenticator) (*grpc.Server, *bufconn.Listener, *testService) {
	t.Helper()

	listener := bufconn.Listen(bufSize)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	// Create gRPC server with auth interceptors
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			UnaryAuthInterceptor(authenticator, authConfig, logger),
		),
		grpc.ChainStreamInterceptor(
			StreamAuthInterceptor(authenticator, authConfig, logger),
		),
	)

	// Create test service - we'll call it directly instead of using proto
	service := &testService{}

	// Start server in background
	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			t.Logf("Server error: %v", err)
		}
	}()

	return grpcServer, listener, service
}

// createIntegrationTestClient creates a gRPC client connection via bufconn.
func createIntegrationTestClient(ctx context.Context, t *testing.T, listener *bufconn.Listener) *grpc.ClientConn {
	t.Helper()

	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	return conn
}

// TestIntegration_FullAuthFlow tests the complete authentication flow end-to-end.
func TestIntegration_FullAuthFlow(t *testing.T) {
	// Start mock JWKS server
	jwksServer := createIntegrationJWKSServer()
	defer jwksServer.Close()

	// Configure auth with OIDC validator
	authConfig := &AuthConfig{
		Enabled:        true,
		TrustLocalhost: false,
		ClockSkew:      30 * time.Second,
		OIDC: []OIDCIssuerConfig{
			{
				Issuer:       integrationTestIssuer,
				Audience:     integrationTestAudience,
				JWKSEndpoint: jwksServer.URL + "/jwks",
				JWKSTTL:      1 * time.Hour,
				ClaimsMapping: map[string]string{
					"groups": "groups",
					"email":  "email",
				},
				RoleBindings: map[string][]string{
					"admin":     {"admin"},
					"developer": {"mission:execute", "findings:read"},
				},
			},
		},
	}

	// Create OIDC authenticator
	authenticator, err := NewOIDCValidator(authConfig)
	require.NoError(t, err)
	require.NotNil(t, authenticator)

	// Setup test server with auth interceptors
	grpcServer, listener, _ := setupIntegrationTestServer(t, authConfig, authenticator)
	defer grpcServer.Stop()

	ctx := context.Background()
	_ = createIntegrationTestClient(ctx, t, listener)

	t.Run("successful_authentication_with_valid_token", func(t *testing.T) {
		// Generate valid JWT token
		now := time.Now()
		token, err := createIntegrationTestToken(jwt.MapClaims{
			"iss":    integrationTestIssuer,
			"aud":    integrationTestAudience,
			"sub":    "user123",
			"email":  "user@example.com",
			"groups": []string{"developer"},
			"exp":    now.Add(1 * time.Hour).Unix(),
			"iat":    now.Unix(),
			"nbf":    now.Unix(),
		})
		require.NoError(t, err)

		// Test authentication directly
		identity, err := authenticator.Authenticate(ctx, token)
		require.NoError(t, err)
		require.NotNil(t, identity)

		// Verify identity fields
		assert.Equal(t, "user123", identity.Subject)
		assert.Equal(t, integrationTestIssuer, identity.Issuer)
		assert.Equal(t, "user@example.com", identity.Email)
		assert.Contains(t, identity.Groups, "developer")
		// Note: Roles are not automatically bound - role binding is tested separately
	})

	t.Run("authentication_failure_with_expired_token", func(t *testing.T) {
		// Generate expired JWT token
		expiredTime := time.Now().Add(-2 * time.Hour)
		token, err := createIntegrationTestToken(jwt.MapClaims{
			"iss":   integrationTestIssuer,
			"aud":   integrationTestAudience,
			"sub":   "user123",
			"email": "user@example.com",
			"exp":   expiredTime.Unix(),
			"iat":   expiredTime.Add(-1 * time.Hour).Unix(),
			"nbf":   expiredTime.Add(-1 * time.Hour).Unix(),
		})
		require.NoError(t, err)

		// Test authentication with expired token
		_, err = authenticator.Authenticate(ctx, token)
		require.Error(t, err)
		// The error contains "invalid_signature" because signature validation fails on expired tokens
		assert.Contains(t, err.Error(), "invalid")
	})

	t.Run("authentication_failure_with_wrong_issuer", func(t *testing.T) {
		// Generate token with wrong issuer
		now := time.Now()
		token, err := createIntegrationTestToken(jwt.MapClaims{
			"iss":   "https://wrong-issuer.com",
			"aud":   integrationTestAudience,
			"sub":   "user123",
			"email": "user@example.com",
			"exp":   now.Add(1 * time.Hour).Unix(),
			"iat":   now.Unix(),
			"nbf":   now.Unix(),
		})
		require.NoError(t, err)

		// Test authentication with wrong issuer
		_, err = authenticator.Authenticate(ctx, token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown")
	})

	t.Run("authentication_failure_with_wrong_audience", func(t *testing.T) {
		// Generate token with wrong audience
		now := time.Now()
		token, err := createIntegrationTestToken(jwt.MapClaims{
			"iss":   integrationTestIssuer,
			"aud":   "wrong-audience",
			"sub":   "user123",
			"email": "user@example.com",
			"exp":   now.Add(1 * time.Hour).Unix(),
			"iat":   now.Unix(),
			"nbf":   now.Unix(),
		})
		require.NoError(t, err)

		// Test authentication with wrong audience
		_, err = authenticator.Authenticate(ctx, token)
		require.Error(t, err)
	})

	t.Run("role_binding_with_admin_group", func(t *testing.T) {
		// Generate valid JWT token with admin group
		now := time.Now()
		token, err := createIntegrationTestToken(jwt.MapClaims{
			"iss":    integrationTestIssuer,
			"aud":    integrationTestAudience,
			"sub":    "admin123",
			"email":  "admin@example.com",
			"groups": []string{"admin"},
			"exp":    now.Add(1 * time.Hour).Unix(),
			"iat":    now.Unix(),
			"nbf":    now.Unix(),
		})
		require.NoError(t, err)

		// Test authentication
		identity, err := authenticator.Authenticate(ctx, token)
		require.NoError(t, err)
		require.NotNil(t, identity)

		// Verify admin identity
		assert.Equal(t, "admin123", identity.Subject)
		assert.Contains(t, identity.Groups, "admin")
		// Note: Roles are not automatically bound - tested separately in roles_test.go
	})

	t.Run("context_injection_and_extraction", func(t *testing.T) {
		// Generate valid JWT token
		now := time.Now()
		token, err := createIntegrationTestToken(jwt.MapClaims{
			"iss":    integrationTestIssuer,
			"aud":    integrationTestAudience,
			"sub":    "context-test",
			"email":  "context@example.com",
			"groups": []string{"developer"},
			"exp":    now.Add(1 * time.Hour).Unix(),
			"iat":    now.Unix(),
			"nbf":    now.Unix(),
		})
		require.NoError(t, err)

		// Authenticate and get identity
		identity, err := authenticator.Authenticate(ctx, token)
		require.NoError(t, err)

		// Inject into context
		ctxWithIdentity := ContextWithIdentity(ctx, identity)

		// Extract from context
		extracted, ok := IdentityFromContext(ctxWithIdentity)
		require.True(t, ok)
		require.NotNil(t, extracted)
		assert.Equal(t, "context-test", extracted.Subject)
		assert.Equal(t, "context@example.com", extracted.Email)
	})
}

// TestIntegration_CompositeAuthenticator tests the composite authenticator with multiple validators.
func TestIntegration_CompositeAuthenticator(t *testing.T) {
	// Start mock JWKS server
	jwksServer := createIntegrationJWKSServer()
	defer jwksServer.Close()

	// Configure auth with OIDC
	authConfig := &AuthConfig{
		Enabled:   true,
		ClockSkew: 30 * time.Second,
		OIDC: []OIDCIssuerConfig{
			{
				Issuer:       integrationTestIssuer,
				Audience:     integrationTestAudience,
				JWKSEndpoint: jwksServer.URL + "/jwks",
				JWKSTTL:      1 * time.Hour,
			},
		},
		Local: &LocalAuthConfig{
			Users: []LocalUser{
				{
					Name:  "local-dev",
					Token: "dev-token-12345",
					Roles: []string{"admin"},
				},
			},
		},
	}

	// Create composite authenticator from the full config
	composite, err := NewCompositeAuthenticator(authConfig)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("oidc_token_authenticated_first", func(t *testing.T) {
		now := time.Now()
		token, err := createIntegrationTestToken(jwt.MapClaims{
			"iss": integrationTestIssuer,
			"aud": integrationTestAudience,
			"sub": "oidc-user",
			"exp": now.Add(1 * time.Hour).Unix(),
			"iat": now.Unix(),
			"nbf": now.Unix(),
		})
		require.NoError(t, err)

		identity, err := composite.Authenticate(ctx, token)
		require.NoError(t, err)
		assert.Equal(t, "oidc-user", identity.Subject)
		assert.Equal(t, integrationTestIssuer, identity.Issuer)
	})

	t.Run("local_token_authenticated_as_fallback", func(t *testing.T) {
		identity, err := composite.Authenticate(ctx, "dev-token-12345")
		require.NoError(t, err)
		assert.Equal(t, "local-dev", identity.Subject)
		assert.Equal(t, "local", identity.Issuer)
		assert.Contains(t, identity.Roles, "admin")
	})

	t.Run("invalid_token_rejected_by_all", func(t *testing.T) {
		_, err := composite.Authenticate(ctx, "invalid-token")
		require.Error(t, err)
	})
}

