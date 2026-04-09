package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testIssuerFixture holds test data for generating and validating test tokens.
type testIssuerFixture struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
	issuerURL  string
	audience   string
	server     *httptest.Server
}

// newTestIssuer creates a test OIDC issuer with TLS JWKS endpoint.
func newTestIssuer(t *testing.T) *testIssuerFixture {
	t.Helper()

	// Generate RSA key pair for signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ti := &testIssuerFixture{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		keyID:      "test-key-id",
		audience:   "gibson-api",
	}

	// Create mock JWKS endpoint with TLS
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		jwks := ti.createJWKS()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})

	// Use TLS server (required by SDK's JWKS cache which requires HTTPS)
	ti.server = httptest.NewTLSServer(mux)
	ti.issuerURL = ti.server.URL

	return ti
}

// close shuts down the test issuer server.
func (ti *testIssuerFixture) close() {
	if ti.server != nil {
		ti.server.Close()
	}
}

// createToken generates a signed JWT with the given claims.
func (ti *testIssuerFixture) createToken(claims jwt.MapClaims) (string, error) {
	// Set required claims if not provided
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = ti.issuerURL
	}
	if _, ok := claims["aud"]; !ok {
		claims["aud"] = ti.audience
	}
	if _, ok := claims["sub"]; !ok {
		claims["sub"] = "test-user"
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(1 * time.Hour).Unix()
	}
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = time.Now().Unix()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = ti.keyID

	return token.SignedString(ti.privateKey)
}

// createJWKS creates a JWKS response for the test public key.
func (ti *testIssuerFixture) createJWKS() map[string]interface{} {
	n := ti.publicKey.N.Bytes()
	e := []byte{byte(ti.publicKey.E >> 16), byte(ti.publicKey.E >> 8), byte(ti.publicKey.E)}

	// Remove leading zeros from exponent
	for len(e) > 1 && e[0] == 0 {
		e = e[1:]
	}

	return map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"kid": ti.keyID,
				"alg": "RS256",
				"n":   base64URLEncode(n),
				"e":   base64URLEncode(e),
			},
		},
	}
}

// Helper to base64 URL encode - use standard library for correct JWKS encoding
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// Shared test issuer for tests that need compatibility with old pattern.
// Tests should call initSharedTestIssuer() and use sharedTestIssuer.
var sharedTestIssuer *testIssuerFixture

// initSharedTestIssuer initializes the shared test issuer if not already done.
func initSharedTestIssuer(t testing.TB) *testIssuerFixture {
	t.Helper()
	if sharedTestIssuer == nil {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}

		ti := &testIssuerFixture{
			privateKey: privateKey,
			publicKey:  &privateKey.PublicKey,
			keyID:      "test-key-id",
			audience:   "gibson-api",
		}

		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
			jwks := ti.createJWKS()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jwks)
		})

		ti.server = httptest.NewTLSServer(mux)
		ti.issuerURL = ti.server.URL
		sharedTestIssuer = ti
	}
	return sharedTestIssuer
}

func TestNewOIDCValidator(t *testing.T) {
	tests := []struct {
		name    string
		config  *AuthConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
			errMsg:  "auth config is nil",
		},
		{
			name: "empty issuer",
			config: &AuthConfig{
				OIDC: []OIDCIssuerConfig{
					{Issuer: ""},
				},
			},
			wantErr: true,
			errMsg:  "OIDC issuer URL cannot be empty",
		},
		{
			name: "valid single issuer",
			config: &AuthConfig{
				OIDC: []OIDCIssuerConfig{
					{
						Issuer:   "https://test.issuer.com",
						Audience: "gibson-api",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "multiple issuers",
			config: &AuthConfig{
				OIDC: []OIDCIssuerConfig{
					{Issuer: "https://issuer1.com"},
					{Issuer: "https://issuer2.com"},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator, err := NewOIDCValidator(tt.config)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, validator)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, validator)
				// SDK validator handles JWKS caching internally
				assert.NotNil(t, validator.validator)
			}
		})
	}
}

func TestOIDCValidator_Authenticate_Success(t *testing.T) {
	// Create test issuer with TLS JWKS server
	ti := newTestIssuer(t)
	defer ti.close()

	// Create validator config
	cfg := &AuthConfig{
		OIDC: []OIDCIssuerConfig{
			{
				Issuer:       ti.issuerURL,
				Audience:     ti.audience,
				JWKSEndpoint: ti.server.URL + "/.well-known/jwks.json",
			},
		},
	}

	validator, err := NewOIDCValidator(cfg)
	require.NoError(t, err)

	// Override HTTP client to use test server's client (handles TLS)
	validator.validator.SetHTTPClient(ti.server.Client())

	// Create valid token
	token, err := ti.createToken(jwt.MapClaims{
		"sub":    "user123",
		"email":  "user@example.com",
		"groups": []string{"developers", "security-team"},
	})
	require.NoError(t, err)

	// Authenticate
	ctx := context.Background()
	identity, err := validator.Authenticate(ctx, token)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, identity)
	assert.Equal(t, "user123", identity.Subject)
	assert.Equal(t, ti.issuerURL, identity.Issuer)
	assert.Equal(t, "user@example.com", identity.Email)
	assert.Equal(t, []string{"developers", "security-team"}, identity.Groups)
	assert.NotZero(t, identity.AuthenticatedAt)
	assert.False(t, identity.IsExpired())
}

func TestOIDCValidator_Authenticate_ExpiredToken(t *testing.T) {
	ti := newTestIssuer(t)
	defer ti.close()

	cfg := &AuthConfig{
		OIDC: []OIDCIssuerConfig{
			{
				Issuer:       ti.issuerURL,
				Audience:     ti.audience,
				JWKSEndpoint: ti.server.URL + "/.well-known/jwks.json",
			},
		},
		ClockSkew: 1 * time.Second, // Minimal clock skew
	}

	validator, err := NewOIDCValidator(cfg)
	require.NoError(t, err)
	validator.validator.SetHTTPClient(ti.server.Client())

	// Create expired token (expired 1 minute ago - well beyond clock skew)
	token, err := ti.createToken(jwt.MapClaims{
		"exp": time.Now().Add(-1 * time.Minute).Unix(),
	})
	require.NoError(t, err)

	// Authenticate
	ctx := context.Background()
	identity, err := validator.Authenticate(ctx, token)

	// Assertions
	assert.Error(t, err)
	assert.Nil(t, identity)
	assert.True(t, IsTokenExpiredError(err), "Expected token expired error, got: %v", err)
}

func TestOIDCValidator_Authenticate_UnknownIssuer(t *testing.T) {
	ti := newTestIssuer(t)
	defer ti.close()

	// Configure validator with different issuer than the token
	cfg := &AuthConfig{
		OIDC: []OIDCIssuerConfig{
			{
				Issuer:   "https://different-issuer.com",
				Audience: ti.audience,
			},
		},
	}

	validator, err := NewOIDCValidator(cfg)
	require.NoError(t, err)

	// Create token with test issuer URL (different from configured)
	token, err := ti.createToken(jwt.MapClaims{})
	require.NoError(t, err)

	// Authenticate
	ctx := context.Background()
	identity, err := validator.Authenticate(ctx, token)

	// Assertions
	assert.Error(t, err)
	assert.Nil(t, identity)
	assert.True(t, IsUnknownIssuerError(err))
	assert.Contains(t, err.Error(), ti.issuerURL)
}

func TestOIDCValidator_Authenticate_InvalidAudience(t *testing.T) {
	ti := newTestIssuer(t)
	defer ti.close()

	cfg := &AuthConfig{
		OIDC: []OIDCIssuerConfig{
			{
				Issuer:       ti.issuerURL,
				Audience:     "expected-audience",
				JWKSEndpoint: ti.server.URL + "/.well-known/jwks.json",
			},
		},
	}

	validator, err := NewOIDCValidator(cfg)
	require.NoError(t, err)
	validator.validator.SetHTTPClient(ti.server.Client())

	// Create token with wrong audience
	token, err := ti.createToken(jwt.MapClaims{
		"aud": "wrong-audience",
	})
	require.NoError(t, err)

	// Authenticate
	ctx := context.Background()
	identity, err := validator.Authenticate(ctx, token)

	// Assertions
	assert.Error(t, err)
	assert.Nil(t, identity)
	assert.True(t, IsAudienceMismatchError(err))
}

func TestOIDCValidator_Authenticate_MalformedToken(t *testing.T) {
	cfg := &AuthConfig{
		OIDC: []OIDCIssuerConfig{
			{Issuer: "https://test.issuer.com"},
		},
	}

	validator, err := NewOIDCValidator(cfg)
	require.NoError(t, err)

	tests := []struct {
		name  string
		token string
	}{
		{"empty token", ""},
		{"invalid format", "not.a.valid.jwt"},
		{"missing parts", "header.payload"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, err := validator.Authenticate(context.Background(), tt.token)
			assert.Error(t, err)
			assert.Nil(t, identity)
		})
	}
}

func TestOIDCValidator_Authenticate_MultipleAudiences(t *testing.T) {
	ti := newTestIssuer(t)
	defer ti.close()

	cfg := &AuthConfig{
		OIDC: []OIDCIssuerConfig{
			{
				Issuer:       ti.issuerURL,
				Audience:     ti.audience,
				JWKSEndpoint: ti.server.URL + "/.well-known/jwks.json",
			},
		},
	}

	validator, err := NewOIDCValidator(cfg)
	require.NoError(t, err)
	validator.validator.SetHTTPClient(ti.server.Client())

	// Create token with multiple audiences (array format)
	token, err := ti.createToken(jwt.MapClaims{
		"aud": []string{ti.audience, "other-api"},
	})
	require.NoError(t, err)

	// Authenticate
	ctx := context.Background()
	identity, err := validator.Authenticate(ctx, token)

	// Should succeed because gibson-api is in the audience list
	require.NoError(t, err)
	require.NotNil(t, identity)
	assert.Equal(t, "test-user", identity.Subject)
}

func TestOIDCValidator_ClaimsMapping(t *testing.T) {
	ti := newTestIssuer(t)
	defer ti.close()

	cfg := &AuthConfig{
		OIDC: []OIDCIssuerConfig{
			{
				Issuer:       ti.issuerURL,
				JWKSEndpoint: ti.server.URL + "/.well-known/jwks.json",
				ClaimsMapping: map[string]string{
					"roles":  "custom_roles_claim",
					"tenant": "org_id",
				},
			},
		},
	}

	validator, err := NewOIDCValidator(cfg)
	require.NoError(t, err)
	validator.validator.SetHTTPClient(ti.server.Client())

	// Create token with custom claims
	token, err := ti.createToken(jwt.MapClaims{
		"custom_roles_claim": []string{"admin", "developer"},
		"org_id":             "acme-corp",
	})
	require.NoError(t, err)

	// Authenticate
	ctx := context.Background()
	identity, err := validator.Authenticate(ctx, token)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, identity)

	// Verify mapped claims are present
	assert.Contains(t, identity.Claims, "roles")
	assert.Contains(t, identity.Claims, "tenant")
}

func TestOIDCValidator_GroupsExtraction(t *testing.T) {
	ti := newTestIssuer(t)
	defer ti.close()

	cfg := &AuthConfig{
		OIDC: []OIDCIssuerConfig{
			{
				Issuer:       ti.issuerURL,
				JWKSEndpoint: ti.server.URL + "/.well-known/jwks.json",
			},
		},
	}

	validator, err := NewOIDCValidator(cfg)
	require.NoError(t, err)
	validator.validator.SetHTTPClient(ti.server.Client())

	tests := []struct {
		name           string
		groupsClaim    interface{}
		expectedGroups []string
	}{
		{
			name:           "string array",
			groupsClaim:    []string{"admin", "developer"},
			expectedGroups: []string{"admin", "developer"},
		},
		{
			name:           "interface array",
			groupsClaim:    []interface{}{"admin", "developer"},
			expectedGroups: []string{"admin", "developer"},
		},
		{
			name:           "no groups",
			groupsClaim:    nil,
			expectedGroups: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := jwt.MapClaims{}
			if tt.groupsClaim != nil {
				claims["groups"] = tt.groupsClaim
			}

			token, err := ti.createToken(claims)
			require.NoError(t, err)

			identity, err := validator.Authenticate(context.Background(), token)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedGroups, identity.Groups)
		})
	}
}

func TestOIDCValidator_ClockSkewTolerance(t *testing.T) {
	ti := newTestIssuer(t)
	defer ti.close()

	cfg := &AuthConfig{
		OIDC: []OIDCIssuerConfig{
			{
				Issuer:       ti.issuerURL,
				JWKSEndpoint: ti.server.URL + "/.well-known/jwks.json",
			},
		},
		ClockSkew: 1 * time.Minute, // Allow 1 minute clock skew
	}

	validator, err := NewOIDCValidator(cfg)
	require.NoError(t, err)
	validator.validator.SetHTTPClient(ti.server.Client())

	// Create token that expired 30 seconds ago (within clock skew)
	token, err := ti.createToken(jwt.MapClaims{
		"exp": time.Now().Add(-30 * time.Second).Unix(),
		"iat": time.Now().Add(-1 * time.Hour).Unix(),
	})
	require.NoError(t, err)

	// Should succeed due to clock skew tolerance
	identity, err := validator.Authenticate(context.Background(), token)
	assert.NoError(t, err)
	assert.NotNil(t, identity)
}

func TestOIDCValidator_ConcurrentAuthentication(t *testing.T) {
	ti := newTestIssuer(t)
	defer ti.close()

	cfg := &AuthConfig{
		OIDC: []OIDCIssuerConfig{
			{
				Issuer:       ti.issuerURL,
				JWKSEndpoint: ti.server.URL + "/.well-known/jwks.json",
			},
		},
	}

	validator, err := NewOIDCValidator(cfg)
	require.NoError(t, err)
	validator.validator.SetHTTPClient(ti.server.Client())

	// Create valid token
	token, err := ti.createToken(jwt.MapClaims{
		"sub": "user123",
	})
	require.NoError(t, err)

	// Run multiple concurrent authentication requests
	const numGoroutines = 50
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			identity, err := validator.Authenticate(context.Background(), token)
			assert.NoError(t, err)
			assert.NotNil(t, identity)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

func TestOIDCValidator_ContextCancellation(t *testing.T) {
	ti := newTestIssuer(t)
	defer ti.close()

	cfg := &AuthConfig{
		OIDC: []OIDCIssuerConfig{
			{
				Issuer:       ti.issuerURL,
				JWKSEndpoint: ti.server.URL + "/.well-known/jwks.json",
			},
		},
	}

	validator, err := NewOIDCValidator(cfg)
	require.NoError(t, err)
	validator.validator.SetHTTPClient(ti.server.Client())

	token, err := ti.createToken(jwt.MapClaims{})
	require.NoError(t, err)

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Authentication should still work (cancellation doesn't affect JWT validation)
	// But JWKS fetching might be affected
	identity, err := validator.Authenticate(ctx, token)

	// Result depends on whether JWKS was already cached
	// If not cached, it might fail due to context cancellation
	if err != nil {
		t.Logf("Authentication failed with cancelled context: %v", err)
	} else {
		assert.NotNil(t, identity)
	}
}

// Benchmark tests
func BenchmarkOIDCValidator_Authenticate(b *testing.B) {
	ti := initSharedTestIssuer(b)

	cfg := &AuthConfig{
		OIDC: []OIDCIssuerConfig{
			{
				Issuer:       ti.issuerURL,
				JWKSEndpoint: ti.server.URL + "/.well-known/jwks.json",
			},
		},
	}

	validator, err := NewOIDCValidator(cfg)
	require.NoError(b, err)
	validator.validator.SetHTTPClient(ti.server.Client())

	token, err := ti.createToken(jwt.MapClaims{
		"sub": "user123",
	})
	require.NoError(b, err)

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := validator.Authenticate(ctx, token)
		if err != nil {
			b.Fatalf("Authentication failed: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// extractOrganizationsClaim unit tests (authz-02-keycloak-organizations, task 21)
// ---------------------------------------------------------------------------

// TestExtractOrganizationsClaim covers the six scenarios specified in
// Requirements 6.1, 6.2, and 6.4.
func TestExtractOrganizationsClaim(t *testing.T) {
	tests := []struct {
		name     string
		claims   map[string]any
		expected []string
		wantNil  bool // true when we expect the return to be nil (claim absent)
	}{
		{
			name:    "missing_claim_returns_nil",
			claims:  map[string]any{"sub": "user123"},
			wantNil: true,
		},
		{
			name:     "empty_array_returns_empty_non_nil_slice",
			claims:   map[string]any{"organizations": []interface{}{}},
			expected: []string{},
			wantNil:  false,
		},
		{
			name:     "single_string_non_array_form",
			claims:   map[string]any{"organizations": "zero-day-ai"},
			expected: []string{"zero-day-ai"},
		},
		{
			name:     "single_element_array",
			claims:   map[string]any{"organizations": []interface{}{"acme-corp"}},
			expected: []string{"acme-corp"},
		},
		{
			name:     "multi_element_array",
			claims:   map[string]any{"organizations": []interface{}{"tenant-a", "tenant-b", "tenant-c"}},
			expected: []string{"tenant-a", "tenant-b", "tenant-c"},
		},
		{
			name:    "legacy_tenant_id_fallback_not_handled_here",
			// extractOrganizationsClaim only parses the "organizations" key.
			// The legacy tenant_id fallback is in the caller (OIDCValidator.Authenticate).
			// When "organizations" is absent and "tenant_id" is present, this
			// function returns nil — the caller does the fallback.
			claims:  map[string]any{"tenant_id": "legacy-tenant"},
			wantNil: true,
		},
		{
			name:     "already_typed_string_slice",
			claims:   map[string]any{"organizations": []string{"org-a", "org-b"}},
			expected: []string{"org-a", "org-b"},
		},
		{
			name:    "unrecognized_type_returns_nil",
			claims:  map[string]any{"organizations": 42},
			wantNil: true,
		},
		{
			name:     "empty_string_in_array_filtered_out",
			claims:   map[string]any{"organizations": []interface{}{"org-a", "", "org-b"}},
			expected: []string{"org-a", "org-b"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractOrganizationsClaim(tc.claims)

			if tc.wantNil {
				assert.Nil(t, got, "expected nil for absent or unrecognized claim")
				return
			}

			require.NotNil(t, got, "expected non-nil slice for present claim")
			assert.Equal(t, tc.expected, got)
		})
	}
}

// TestExtractOrganizationsClaim_LegacyFallback_Integration verifies that the
// caller (OIDCValidator) falls back to the legacy tenant_id claim when the
// organizations claim is absent. This test operates at the claims-parsing
// level by calling extractOrganizationsClaim directly and asserting the nil
// return that triggers the fallback in the caller.
func TestExtractOrganizationsClaim_NilTriggersFallback(t *testing.T) {
	// Simulate a pre-migration JWT that only has tenant_id.
	claims := map[string]any{
		"sub":       "user-abc",
		"tenant_id": "my-tenant",
	}
	result := extractOrganizationsClaim(claims)
	assert.Nil(t, result, "nil return from extractOrganizationsClaim should trigger tenant_id fallback in caller")
}
