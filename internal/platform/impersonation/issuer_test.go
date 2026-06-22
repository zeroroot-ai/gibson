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

// keyA/B/C are distinct ≥32-byte fixtures. Using semantic names rather
// than "current"/"previous" lets each test pick its own rotation role.
var (
	keyA = []byte("AAAA-test-signing-key-32bytes-OK")
	keyB = []byte("BBBB-test-signing-key-32bytes-OK")
	keyC = []byte("CCCC-test-signing-key-32bytes-OK")
)

func init() {
	for name, k := range map[string][]byte{"keyA": keyA, "keyB": keyB, "keyC": keyC} {
		if len(k) < minKeyBytes {
			panic("test fixture " + name + " under minKeyBytes")
		}
	}
}

func TestIssueToken_ReturnsParsableJWT(t *testing.T) {
	issuer, err := New(keyA, nil, 15*time.Minute, testLogger)
	require.NoError(t, err)

	token, err := issuer.IssueToken(context.Background(), "tenant-xyz")
	require.NoError(t, err)
	require.NotEmpty(t, token)

	parsed, parseErr := jwtv5.ParseWithClaims(token, &impersonationClaims{}, func(tok *jwtv5.Token) (interface{}, error) {
		assert.Equal(t, jwtv5.SigningMethodHS256.Alg(), tok.Method.Alg())
		return keyA, nil
	})
	require.NoError(t, parseErr)
	require.True(t, parsed.Valid)

	claims, ok := parsed.Claims.(*impersonationClaims)
	require.True(t, ok)
	assert.Equal(t, "tenant-xyz", claims.Subject)
	assert.Equal(t, tokenType, claims.Typ)
}

func TestIssueToken_TTLClampedToOneHour(t *testing.T) {
	issuer, err := New(keyA, nil, 2*time.Hour, testLogger)
	require.NoError(t, err)

	token, err := issuer.IssueToken(context.Background(), "tenant-ttl")
	require.NoError(t, err)

	parsed, parseErr := jwtv5.ParseWithClaims(token, &impersonationClaims{}, func(_ *jwtv5.Token) (interface{}, error) {
		return keyA, nil
	})
	require.NoError(t, parseErr)

	claims, ok := parsed.Claims.(*impersonationClaims)
	require.True(t, ok)
	ttl := claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time)
	assert.LessOrEqual(t, ttl, maxTTL, "TTL must not exceed maxTTL (1 hour)")
	assert.Greater(t, ttl, 59*time.Minute, "TTL should be close to 1 hour")
}

func TestIssueToken_WrongKey_VerificationFails(t *testing.T) {
	issuer, err := New(keyA, nil, 15*time.Minute, testLogger)
	require.NoError(t, err)

	token, err := issuer.IssueToken(context.Background(), "tenant-hmac")
	require.NoError(t, err)

	_, parseErr := jwtv5.ParseWithClaims(token, &impersonationClaims{}, func(_ *jwtv5.Token) (interface{}, error) {
		return keyB, nil
	})
	assert.Error(t, parseErr, "token signed with different key must not validate")
}

func TestIssueToken_EmptyTenantID_Error(t *testing.T) {
	issuer, err := New(keyA, nil, 15*time.Minute, testLogger)
	require.NoError(t, err)

	_, err = issuer.IssueToken(context.Background(), "")
	assert.Error(t, err)
}

// TestNew_RejectsEmptyKey locks in the fail-closed contract: callers MUST
// supply a current signing key. A nil/empty key would previously have
// been replaced with an in-process random, invalidating every previously-
// issued token on each restart and diverging across HA replicas (gibson#103).
func TestNew_RejectsEmptyCurrentKey(t *testing.T) {
	for _, k := range [][]byte{nil, {}} {
		i, err := New(k, nil, 0, testLogger)
		require.Error(t, err, "empty current key must be rejected")
		assert.Nil(t, i)
		assert.Contains(t, err.Error(), "GIBSON_IMPERSONATION_KEY")
	}
}

// TestNew_RejectsShortCurrentKey locks in RFC 7518 §3.2: HS256 keys ≥ 32 bytes.
func TestNew_RejectsShortCurrentKey(t *testing.T) {
	short := []byte("only-31-bytes-not-enough-padddd") // 31
	require.Less(t, len(short), minKeyBytes)

	i, err := New(short, nil, 0, testLogger)
	require.Error(t, err)
	assert.Nil(t, i)
}

// TestNew_AcceptsEmptyPreviousKey — disabling rotation is the steady state.
func TestNew_AcceptsEmptyPreviousKey(t *testing.T) {
	for _, prev := range [][]byte{nil, {}} {
		i, err := New(keyA, prev, 0, testLogger)
		require.NoError(t, err)
		require.NotNil(t, i)
		assert.Empty(t, i.previousKey)
	}
}

// TestNew_RejectsShortPreviousKey — a non-empty previous slot must meet
// the same minimum as current; under-sized = misconfiguration, fail loud.
func TestNew_RejectsShortPreviousKey(t *testing.T) {
	short := []byte("31-bytes-not-enough-padding-XYZ") // 31
	require.Less(t, len(short), minKeyBytes)

	i, err := New(keyA, short, 0, testLogger)
	require.Error(t, err)
	assert.Nil(t, i)
	assert.Contains(t, err.Error(), "GIBSON_IMPERSONATION_KEY_PREVIOUS")
}

func TestNew_ZeroTTL_UsesDefault(t *testing.T) {
	i, err := New(keyA, nil, 0, testLogger)
	require.NoError(t, err)
	assert.Equal(t, defaultTTL, i.defaultTTL)
}

// ---------------------------------------------------------------------------
// Verify — rotation semantics.
// ---------------------------------------------------------------------------

func TestVerify_AcceptsTokenSignedByCurrentKey(t *testing.T) {
	issuer, err := New(keyA, nil, 15*time.Minute, testLogger)
	require.NoError(t, err)

	tok, err := issuer.IssueToken(context.Background(), "tenant-current")
	require.NoError(t, err)

	claims, err := issuer.Verify(tok)
	require.NoError(t, err)
	assert.Equal(t, "tenant-current", claims.TenantID)
	assert.Equal(t, tokenType, "impersonation") // sanity
	assert.WithinDuration(t, time.Now().Add(15*time.Minute), claims.ExpiresAt, 2*time.Second)
}

// TestVerify_AcceptsTokenSignedByPreviousKey models a rotation in flight:
// an old issuer signed with keyB; the operator has since rotated, so the
// new issuer has keyA current + keyB previous. Tokens minted under keyB
// must keep verifying until they expire.
func TestVerify_AcceptsTokenSignedByPreviousKey(t *testing.T) {
	oldIssuer, err := New(keyB, nil, 15*time.Minute, testLogger)
	require.NoError(t, err)
	tok, err := oldIssuer.IssueToken(context.Background(), "tenant-rot")
	require.NoError(t, err)

	rotatedIssuer, err := New(keyA, keyB, 15*time.Minute, testLogger)
	require.NoError(t, err)

	claims, err := rotatedIssuer.Verify(tok)
	require.NoError(t, err)
	assert.Equal(t, "tenant-rot", claims.TenantID)
}

// TestVerify_RejectsTokenSignedByUnknownKey — the key has been retired
// from BOTH current and previous slots (i.e. rotation completed and the
// previous slot has been cleared). Tokens minted under the retired key
// must no longer verify.
func TestVerify_RejectsTokenSignedByUnknownKey(t *testing.T) {
	retiredIssuer, err := New(keyC, nil, 15*time.Minute, testLogger)
	require.NoError(t, err)
	tok, err := retiredIssuer.IssueToken(context.Background(), "tenant-stale")
	require.NoError(t, err)

	current, err := New(keyA, keyB, 15*time.Minute, testLogger)
	require.NoError(t, err)

	_, err = current.Verify(tok)
	require.Error(t, err)
}

func TestVerify_RejectsExpiredToken(t *testing.T) {
	issuer, err := New(keyA, nil, 15*time.Minute, testLogger)
	require.NoError(t, err)

	// Mint a token with claims set 2h in the past so exp is in the past.
	past := time.Now().Add(-2 * time.Hour)
	claims := impersonationClaims{
		RegisteredClaims: jwtv5.RegisteredClaims{
			Subject:   "tenant-stale",
			IssuedAt:  jwtv5.NewNumericDate(past),
			ExpiresAt: jwtv5.NewNumericDate(past.Add(15 * time.Minute)),
		},
		Typ: tokenType,
	}
	signed, err := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims).SignedString(keyA)
	require.NoError(t, err)

	_, err = issuer.Verify(signed)
	require.Error(t, err)
}

// TestVerify_RejectsWrongTyp — a JWT signed by the right key but with a
// non-impersonation typ claim must NOT be accepted. Prevents the impersonation
// HMAC key from being repurposed to forge other JWT types if the same key
// is ever (mis)used elsewhere.
func TestVerify_RejectsWrongTyp(t *testing.T) {
	issuer, err := New(keyA, nil, 15*time.Minute, testLogger)
	require.NoError(t, err)

	now := time.Now()
	claims := impersonationClaims{
		RegisteredClaims: jwtv5.RegisteredClaims{
			Subject:   "tenant-x",
			IssuedAt:  jwtv5.NewNumericDate(now),
			ExpiresAt: jwtv5.NewNumericDate(now.Add(15 * time.Minute)),
		},
		Typ: "not-impersonation",
	}
	signed, err := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims).SignedString(keyA)
	require.NoError(t, err)

	_, err = issuer.Verify(signed)
	require.Error(t, err)
}

// TestVerify_RejectsNoneAlg — JWT "alg: none" attacks must be refused
// even though jwt/v5 already rejects them; this is a regression lock.
func TestVerify_RejectsNoneAlg(t *testing.T) {
	issuer, err := New(keyA, nil, 15*time.Minute, testLogger)
	require.NoError(t, err)

	// Craft a deliberately-bogus token; the parser must reject it.
	_, err = issuer.Verify("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZW5hbnQtaGFjayJ9.")
	require.Error(t, err)
}
