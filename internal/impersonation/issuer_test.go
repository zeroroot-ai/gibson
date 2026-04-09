package impersonation

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

func TestIssueToken_ReturnsParsableJWT(t *testing.T) {
	key := []byte("test-signing-key-32-bytes-padded")
	issuer := New(key, 15*time.Minute, testLogger)

	ctx := context.Background()
	token, err := issuer.IssueToken(ctx, "tenant-xyz")
	require.NoError(t, err)
	require.NotEmpty(t, token)

	// Parse and verify the token.
	parsed, parseErr := jwtv5.ParseWithClaims(token, &impersonationClaims{}, func(tok *jwtv5.Token) (interface{}, error) {
		assert.Equal(t, jwtv5.SigningMethodHS256.Alg(), tok.Method.Alg())
		return key, nil
	})
	require.NoError(t, parseErr)
	require.True(t, parsed.Valid)

	claims, ok := parsed.Claims.(*impersonationClaims)
	require.True(t, ok)
	assert.Equal(t, "tenant-xyz", claims.Subject)
	assert.Equal(t, tokenType, claims.Typ)
}

func TestIssueToken_TTLClampedToOneHour(t *testing.T) {
	key := []byte("test-signing-key-32-bytes-padded")
	// Request 2-hour TTL — should be clamped to 1 hour.
	issuer := New(key, 2*time.Hour, testLogger)

	ctx := context.Background()
	token, err := issuer.IssueToken(ctx, "tenant-ttl")
	require.NoError(t, err)

	parsed, parseErr := jwtv5.ParseWithClaims(token, &impersonationClaims{}, func(_ *jwtv5.Token) (interface{}, error) {
		return key, nil
	})
	require.NoError(t, parseErr)

	claims, ok := parsed.Claims.(*impersonationClaims)
	require.True(t, ok)
	ttl := claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time)
	assert.LessOrEqual(t, ttl, maxTTL, "TTL must not exceed maxTTL (1 hour)")
	assert.Greater(t, ttl, 59*time.Minute, "TTL should be close to 1 hour")
}

func TestIssueToken_WrongKey_VerificationFails(t *testing.T) {
	signingKey := []byte("correct-signing-key-32b-paddddddd")
	wrongKey := []byte("wrong-signing-key-32b-padddddddddd")
	issuer := New(signingKey, 15*time.Minute, testLogger)

	ctx := context.Background()
	token, err := issuer.IssueToken(ctx, "tenant-hmac")
	require.NoError(t, err)

	_, parseErr := jwtv5.ParseWithClaims(token, &impersonationClaims{}, func(_ *jwtv5.Token) (interface{}, error) {
		return wrongKey, nil
	})
	assert.Error(t, parseErr, "token signed with different key must not validate")
}

func TestIssueToken_EmptyTenantID_Error(t *testing.T) {
	key := []byte("test-signing-key-32-bytes-padded")
	issuer := New(key, 15*time.Minute, testLogger)

	_, err := issuer.IssueToken(context.Background(), "")
	assert.Error(t, err)
}

func TestNew_NilKey_GeneratesRandomKey(t *testing.T) {
	// Should not panic; logs a warning.
	assert.NotPanics(t, func() {
		i := New(nil, 0, testLogger)
		assert.NotNil(t, i)
		assert.Len(t, i.signingKey, 32)
	})
}

func TestNew_ZeroTTL_UsesDefault(t *testing.T) {
	key := []byte("test-signing-key-32-bytes-padded")
	i := New(key, 0, testLogger)
	assert.Equal(t, defaultTTL, i.defaultTTL)
}
