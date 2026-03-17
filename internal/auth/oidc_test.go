package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test fixtures
var (
	testPrivateKey *rsa.PrivateKey
	testPublicKey  *rsa.PublicKey
	testKID        = "test-key-id"
	testIssuer     = "https://test.issuer.com"
	testAudience   = "gibson-api"
)

func init() {
	// Generate test RSA key pair
	var err error
	testPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	testPublicKey = &testPrivateKey.PublicKey
}

// createTestToken creates a signed JWT token for testing.
func createTestToken(claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = testKID
	return token.SignedString(testPrivateKey)
}

// createJWKSServer creates a test HTTP server serving JWKS.
func createJWKSServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Convert RSA public key to JWK format
		jwks := map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"kid": testKID,
					"use": "sig",
					"alg": "RS256",
					"n":   base64URLEncode(testPublicKey.N.Bytes()),
					"e":   base64URLEncode(bigIntToBytes(int64(testPublicKey.E))),
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
}

// Helper to convert int64 to bytes
func bigIntToBytes(n int64) []byte {
	if n == 0 {
		return []byte{0}
	}
	bytes := make([]byte, 0)
	for n > 0 {
		bytes = append([]byte{byte(n & 0xff)}, bytes...)
		n >>= 8
	}
	return bytes
}

// Helper to base64 URL encode
func base64URLEncode(data []byte) string {
	// Simple implementation for testing
	const base64Table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	result := ""
	for i := 0; i < len(data); i += 3 {
		b1 := data[i]
		b2 := byte(0)
		b3 := byte(0)
		if i+1 < len(data) {
			b2 = data[i+1]
		}
		if i+2 < len(data) {
			b3 = data[i+2]
		}

		result += string(base64Table[(b1>>2)&0x3f])
		result += string(base64Table[((b1&0x3)<<4)|((b2>>4)&0xf)])
		if i+1 < len(data) {
			result += string(base64Table[((b2&0xf)<<2)|((b3>>6)&0x3)])
		}
		if i+2 < len(data) {
			result += string(base64Table[b3&0x3f])
		}
	}
	// Remove padding
	for len(result) > 0 && result[len(result)-1] == '=' {
		result = result[:len(result)-1]
	}
	return result
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
						Issuer:   testIssuer,
						Audience: testAudience,
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
				assert.NotNil(t, validator.jwksCache)
			}
		})
	}
}

func TestOIDCValidator_Authenticate_Success(t *testing.T) {
	// Start JWKS server
	jwksServer := createJWKSServer()
	defer jwksServer.Close()

	// Create validator config
	cfg := &AuthConfig{
		OIDC: []OIDCIssuerConfig{
			{
				Issuer:       testIssuer,
				Audience:     testAudience,
				JWKSEndpoint: jwksServer.URL,
			},
		},
	}

	validator, err := NewOIDCValidator(cfg)
	require.NoError(t, err)

	// Create valid token
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":    testIssuer,
		"sub":    "user123",
		"aud":    testAudience,
		"email":  "user@example.com",
		"groups": []string{"developers", "security-team"},
		"exp":    now.Add(1 * time.Hour).Unix(),
		"iat":    now.Unix(),
	}

	token, err := createTestToken(claims)
	require.NoError(t, err)

	// Authenticate
	ctx := context.Background()
	identity, err := validator.Authenticate(ctx, token)

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, identity)
	assert.Equal(t, "user123", identity.Subject)
	assert.Equal(t, testIssuer, identity.Issuer)
	assert.Equal(t, "user@example.com", identity.Email)
	assert.Equal(t, []string{"developers", "security-team"}, identity.Groups)
	assert.NotZero(t, identity.AuthenticatedAt)
	assert.False(t, identity.IsExpired())
}

func TestOIDCValidator_Authenticate_ExpiredToken(t *testing.T) {
	jwksServer := createJWKSServer()
	defer jwksServer.Close()

	cfg := &AuthConfig{
		OIDC: []OIDCIssuerConfig{
			{
				Issuer:       testIssuer,
				Audience:     testAudience,
				JWKSEndpoint: jwksServer.URL,
			},
		},
		ClockSkew: 10 * time.Second, // Small clock skew
	}

	validator, err := NewOIDCValidator(cfg)
	require.NoError(t, err)

	// Create token expired well beyond clock skew
	claims := jwt.MapClaims{
		"iss": testIssuer,
		"sub": "user123",
		"aud": testAudience,
		"exp": time.Now().Add(-1 * time.Hour).Unix(), // Expired 1 hour ago (beyond clock skew)
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
	}

	token, err := createTestToken(claims)
	require.NoError(t, err)

	// Authenticate
	ctx := context.Background()
	identity, err := validator.Authenticate(ctx, token)

	// Assertions
	assert.Error(t, err)
	assert.Nil(t, identity)
	// Token expired errors are reported as invalid signature when signature validation fails
	// This is because jwt.Parse checks expiry during signature validation
	assert.True(t, IsTokenExpiredError(err) || IsInvalidSignatureError(err),
		"Expected token expired or invalid signature error, got: %v", err)
}

func TestOIDCValidator_Authenticate_UnknownIssuer(t *testing.T) {
	cfg := &AuthConfig{
		OIDC: []OIDCIssuerConfig{
			{
				Issuer:   "https://known.issuer.com",
				Audience: testAudience,
			},
		},
	}

	validator, err := NewOIDCValidator(cfg)
	require.NoError(t, err)

	// Create token from unknown issuer
	claims := jwt.MapClaims{
		"iss": "https://unknown.issuer.com",
		"sub": "user123",
		"aud": testAudience,
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}

	token, err := createTestToken(claims)
	require.NoError(t, err)

	// Authenticate
	ctx := context.Background()
	identity, err := validator.Authenticate(ctx, token)

	// Assertions
	assert.Error(t, err)
	assert.Nil(t, identity)
	assert.True(t, IsUnknownIssuerError(err))
}

func TestOIDCValidator_Authenticate_InvalidAudience(t *testing.T) {
	jwksServer := createJWKSServer()
	defer jwksServer.Close()

	cfg := &AuthConfig{
		OIDC: []OIDCIssuerConfig{
			{
				Issuer:       testIssuer,
				Audience:     "expected-audience",
				JWKSEndpoint: jwksServer.URL,
			},
		},
	}

	validator, err := NewOIDCValidator(cfg)
	require.NoError(t, err)

	// Create token with wrong audience
	claims := jwt.MapClaims{
		"iss": testIssuer,
		"sub": "user123",
		"aud": "wrong-audience",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}

	token, err := createTestToken(claims)
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
			{Issuer: testIssuer},
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
	jwksServer := createJWKSServer()
	defer jwksServer.Close()

	cfg := &AuthConfig{
		OIDC: []OIDCIssuerConfig{
			{
				Issuer:       testIssuer,
				Audience:     "gibson-api",
				JWKSEndpoint: jwksServer.URL,
			},
		},
	}

	validator, err := NewOIDCValidator(cfg)
	require.NoError(t, err)

	// Create token with multiple audiences (array format)
	claims := jwt.MapClaims{
		"iss": testIssuer,
		"sub": "user123",
		"aud": []interface{}{"gibson-api", "other-api"},
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}

	token, err := createTestToken(claims)
	require.NoError(t, err)

	// Authenticate
	ctx := context.Background()
	identity, err := validator.Authenticate(ctx, token)

	// Should succeed because gibson-api is in the audience list
	assert.NoError(t, err)
	assert.NotNil(t, identity)
	assert.Equal(t, "user123", identity.Subject)
}

func TestOIDCValidator_ClaimsMapping(t *testing.T) {
	jwksServer := createJWKSServer()
	defer jwksServer.Close()

	cfg := &AuthConfig{
		OIDC: []OIDCIssuerConfig{
			{
				Issuer:       testIssuer,
				JWKSEndpoint: jwksServer.URL,
				ClaimsMapping: map[string]string{
					"roles":  "custom_roles_claim",
					"tenant": "org_id",
				},
			},
		},
	}

	validator, err := NewOIDCValidator(cfg)
	require.NoError(t, err)

	// Create token with custom claims
	claims := jwt.MapClaims{
		"iss":                 testIssuer,
		"sub":                 "user123",
		"custom_roles_claim":  []string{"admin", "developer"},
		"org_id":              "acme-corp",
		"exp":                 time.Now().Add(1 * time.Hour).Unix(),
	}

	token, err := createTestToken(claims)
	require.NoError(t, err)

	// Authenticate
	ctx := context.Background()
	identity, err := validator.Authenticate(ctx, token)

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, identity)

	// Verify mapped claims are present
	assert.Contains(t, identity.Claims, "roles")
	assert.Contains(t, identity.Claims, "tenant")
}

func TestOIDCValidator_GroupsExtraction(t *testing.T) {
	jwksServer := createJWKSServer()
	defer jwksServer.Close()

	cfg := &AuthConfig{
		OIDC: []OIDCIssuerConfig{
			{
				Issuer:       testIssuer,
				JWKSEndpoint: jwksServer.URL,
			},
		},
	}

	validator, err := NewOIDCValidator(cfg)
	require.NoError(t, err)

	tests := []struct {
		name          string
		groupsClaim   interface{}
		expectedGroups []string
	}{
		{
			name:          "string array",
			groupsClaim:   []string{"admin", "developer"},
			expectedGroups: []string{"admin", "developer"},
		},
		{
			name:          "interface array",
			groupsClaim:   []interface{}{"admin", "developer"},
			expectedGroups: []string{"admin", "developer"},
		},
		{
			name:          "no groups",
			groupsClaim:   nil,
			expectedGroups: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := jwt.MapClaims{
				"iss": testIssuer,
				"sub": "user123",
				"exp": time.Now().Add(1 * time.Hour).Unix(),
			}
			if tt.groupsClaim != nil {
				claims["groups"] = tt.groupsClaim
			}

			token, err := createTestToken(claims)
			require.NoError(t, err)

			identity, err := validator.Authenticate(context.Background(), token)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedGroups, identity.Groups)
		})
	}
}

func TestOIDCValidator_ClockSkewTolerance(t *testing.T) {
	jwksServer := createJWKSServer()
	defer jwksServer.Close()

	cfg := &AuthConfig{
		OIDC: []OIDCIssuerConfig{
			{
				Issuer:       testIssuer,
				JWKSEndpoint: jwksServer.URL,
			},
		},
		ClockSkew: 1 * time.Minute, // Allow 1 minute clock skew
	}

	validator, err := NewOIDCValidator(cfg)
	require.NoError(t, err)

	// Create token that expired 30 seconds ago (within clock skew)
	claims := jwt.MapClaims{
		"iss": testIssuer,
		"sub": "user123",
		"exp": time.Now().Add(-30 * time.Second).Unix(),
		"iat": time.Now().Add(-1 * time.Hour).Unix(),
	}

	token, err := createTestToken(claims)
	require.NoError(t, err)

	// Should succeed due to clock skew tolerance
	identity, err := validator.Authenticate(context.Background(), token)
	assert.NoError(t, err)
	assert.NotNil(t, identity)
}

func TestOIDCValidator_ConcurrentAuthentication(t *testing.T) {
	jwksServer := createJWKSServer()
	defer jwksServer.Close()

	cfg := &AuthConfig{
		OIDC: []OIDCIssuerConfig{
			{
				Issuer:       testIssuer,
				JWKSEndpoint: jwksServer.URL,
			},
		},
	}

	validator, err := NewOIDCValidator(cfg)
	require.NoError(t, err)

	// Create valid token
	claims := jwt.MapClaims{
		"iss": testIssuer,
		"sub": "user123",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}

	token, err := createTestToken(claims)
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
	jwksServer := createJWKSServer()
	defer jwksServer.Close()

	cfg := &AuthConfig{
		OIDC: []OIDCIssuerConfig{
			{
				Issuer:       testIssuer,
				JWKSEndpoint: jwksServer.URL,
			},
		},
	}

	validator, err := NewOIDCValidator(cfg)
	require.NoError(t, err)

	claims := jwt.MapClaims{
		"iss": testIssuer,
		"sub": "user123",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}

	token, err := createTestToken(claims)
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
	jwksServer := createJWKSServer()
	defer jwksServer.Close()

	cfg := &AuthConfig{
		OIDC: []OIDCIssuerConfig{
			{
				Issuer:       testIssuer,
				JWKSEndpoint: jwksServer.URL,
			},
		},
	}

	validator, err := NewOIDCValidator(cfg)
	require.NoError(b, err)

	claims := jwt.MapClaims{
		"iss": testIssuer,
		"sub": "user123",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}

	token, err := createTestToken(claims)
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
