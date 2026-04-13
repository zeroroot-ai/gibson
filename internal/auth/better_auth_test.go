package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unwrapAll returns a concatenated string of all messages in the error chain.
// This allows test assertions to check inner error detail without depending on
// the exact format of the outer AuthError.Error() method.
func unwrapAll(err error) string {
	if err == nil {
		return ""
	}
	msgs := []string{err.Error()}
	for inner := errors.Unwrap(err); inner != nil; inner = errors.Unwrap(inner) {
		msgs = append(msgs, inner.Error())
	}
	return strings.Join(msgs, ": ")
}

const testBetterAuthSecret = "test-better-auth-secret-32-chars!!"

// buildTestToken creates a valid Better Auth session token signed with the
// given secret. If expiresAt is zero, it defaults to 1 hour from now.
func buildTestToken(secret string, userID, activeOrgID string, expiresAt time.Time) string {
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(1 * time.Hour)
	}

	payload := betterAuthPayload{
		Token:                "sess_test_123",
		UserID:               userID,
		ExpiresAt:            expiresAt.UTC().Format(time.RFC3339),
		ActiveOrganizationID: activeOrgID,
		CreatedAt:            time.Now().UTC().Format(time.RFC3339),
	}

	payloadBytes, _ := json.Marshal(payload)
	payloadPart := base64.RawURLEncoding.EncodeToString(payloadBytes)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payloadBytes)
	sigBytes := mac.Sum(nil)
	sigPart := base64.RawURLEncoding.EncodeToString(sigBytes)

	return payloadPart + "." + sigPart
}

// ---------------------------------------------------------------------------
// TestNewBetterAuthValidator
// ---------------------------------------------------------------------------

func TestNewBetterAuthValidator_EmptySecret(t *testing.T) {
	_, err := NewBetterAuthValidator("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "BETTER_AUTH_SECRET")
}

func TestNewBetterAuthValidator_ValidSecret(t *testing.T) {
	v, err := NewBetterAuthValidator(testBetterAuthSecret)
	require.NoError(t, err)
	assert.NotNil(t, v)
}

// ---------------------------------------------------------------------------
// TestBetterAuthValidator_ValidToken
// ---------------------------------------------------------------------------

func TestBetterAuthValidator_ValidToken(t *testing.T) {
	v, err := NewBetterAuthValidator(testBetterAuthSecret)
	require.NoError(t, err)

	token := buildTestToken(testBetterAuthSecret, "user-uuid-123", "org-slug-abc", time.Time{})

	identity, err := v.Authenticate(context.Background(), token)
	require.NoError(t, err)
	require.NotNil(t, identity)

	assert.Equal(t, "user-uuid-123", identity.Subject)
	assert.Equal(t, betterAuthIssuer, identity.Issuer)
	assert.Equal(t, []string{"org-slug-abc"}, identity.Tenants)
	assert.Empty(t, identity.Roles)
	assert.Empty(t, identity.Permissions)
	assert.Nil(t, identity.Capabilities)
}

func TestBetterAuthValidator_ValidToken_NoOrg(t *testing.T) {
	v, err := NewBetterAuthValidator(testBetterAuthSecret)
	require.NoError(t, err)

	// No activeOrganizationId
	token := buildTestToken(testBetterAuthSecret, "user-uuid-456", "", time.Time{})

	identity, err := v.Authenticate(context.Background(), token)
	require.NoError(t, err)
	require.NotNil(t, identity)

	assert.Equal(t, "user-uuid-456", identity.Subject)
	assert.Nil(t, identity.Tenants)
}

// ---------------------------------------------------------------------------
// TestBetterAuthValidator_ExpiredToken
// ---------------------------------------------------------------------------

func TestBetterAuthValidator_ExpiredToken(t *testing.T) {
	v, err := NewBetterAuthValidator(testBetterAuthSecret)
	require.NoError(t, err)

	// Expired well beyond the 30s clock-skew window.
	expired := time.Now().Add(-10 * time.Minute)
	token := buildTestToken(testBetterAuthSecret, "user-uuid-789", "", expired)

	_, err = v.Authenticate(context.Background(), token)
	require.Error(t, err)

	authErr, ok := err.(*AuthError)
	require.True(t, ok, "expected *AuthError, got %T: %v", err, err)
	assert.Equal(t, "expired_token", authErr.Reason)
}

func TestBetterAuthValidator_TokenWithinClockSkew(t *testing.T) {
	v, err := NewBetterAuthValidator(testBetterAuthSecret)
	require.NoError(t, err)

	// Expired 10 seconds ago — within the 30s clock-skew tolerance.
	slightlyExpired := time.Now().Add(-10 * time.Second)
	token := buildTestToken(testBetterAuthSecret, "user-uuid-000", "", slightlyExpired)

	identity, err := v.Authenticate(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "user-uuid-000", identity.Subject)
}

// ---------------------------------------------------------------------------
// TestBetterAuthValidator_TamperedSignature
// ---------------------------------------------------------------------------

func TestBetterAuthValidator_TamperedSignature(t *testing.T) {
	v, err := NewBetterAuthValidator(testBetterAuthSecret)
	require.NoError(t, err)

	token := buildTestToken(testBetterAuthSecret, "user-uuid-123", "org-abc", time.Time{})

	// Tamper with the last character of the signature.
	parts := strings.Split(token, ".")
	require.Len(t, parts, 2)

	sig := parts[1]
	// Flip the last byte of the base64-encoded signature.
	lastChar := sig[len(sig)-1]
	var newLastChar byte
	if lastChar == 'A' {
		newLastChar = 'B'
	} else {
		newLastChar = 'A'
	}
	tamperedSig := sig[:len(sig)-1] + string(newLastChar)
	tamperedToken := parts[0] + "." + tamperedSig

	_, err = v.Authenticate(context.Background(), tamperedToken)
	require.Error(t, err)
	// ErrInvalidToken wraps the detail; check both the top-level reason and the
	// inner error for the specific message.
	assert.True(t, IsInvalidTokenError(err), "expected invalid_token error, got: %v", err)
	assert.Contains(t, unwrapAll(err), "signature verification failed")
}

func TestBetterAuthValidator_WrongSecret(t *testing.T) {
	v, err := NewBetterAuthValidator("wrong-secret")
	require.NoError(t, err)

	// Token was signed with a different secret.
	token := buildTestToken(testBetterAuthSecret, "user-uuid-123", "org-abc", time.Time{})

	_, err = v.Authenticate(context.Background(), token)
	require.Error(t, err)
	assert.True(t, IsInvalidTokenError(err), "expected invalid_token error, got: %v", err)
	assert.Contains(t, unwrapAll(err), "signature verification failed")
}

// ---------------------------------------------------------------------------
// TestBetterAuthValidator_MalformedToken
// ---------------------------------------------------------------------------

func TestBetterAuthValidator_EmptyToken(t *testing.T) {
	v, err := NewBetterAuthValidator(testBetterAuthSecret)
	require.NoError(t, err)

	_, err = v.Authenticate(context.Background(), "")
	require.Error(t, err)
}

func TestBetterAuthValidator_NoSeparator(t *testing.T) {
	v, err := NewBetterAuthValidator(testBetterAuthSecret)
	require.NoError(t, err)

	_, err = v.Authenticate(context.Background(), "notadottoken")
	require.Error(t, err)
	assert.True(t, IsInvalidTokenError(err), "expected invalid_token error, got: %v", err)
	assert.Contains(t, unwrapAll(err), "missing signature separator")
}

func TestBetterAuthValidator_InvalidBase64Payload(t *testing.T) {
	v, err := NewBetterAuthValidator(testBetterAuthSecret)
	require.NoError(t, err)

	_, err = v.Authenticate(context.Background(), "not-valid-base64!!!.c29tZXNpZ25hdHVyZQ")
	require.Error(t, err)
	assert.True(t, IsInvalidTokenError(err), "expected invalid_token error, got: %v", err)
	assert.Contains(t, unwrapAll(err), "failed to decode payload")
}

func TestBetterAuthValidator_InvalidJSONPayload(t *testing.T) {
	v, err := NewBetterAuthValidator(testBetterAuthSecret)
	require.NoError(t, err)

	// Valid base64 but not valid JSON.
	badPayload := base64.RawURLEncoding.EncodeToString([]byte("{not-valid-json"))

	// Compute a valid signature for the bad payload so we get past signature check.
	mac := hmac.New(sha256.New, []byte(testBetterAuthSecret))
	mac.Write([]byte("{not-valid-json"))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	token := badPayload + "." + sig
	_, err = v.Authenticate(context.Background(), token)
	require.Error(t, err)
	assert.True(t, IsInvalidTokenError(err), "expected invalid_token error, got: %v", err)
	assert.Contains(t, unwrapAll(err), "failed to decode payload JSON")
}

// ---------------------------------------------------------------------------
// TestBetterAuthValidator_MissingRequiredFields
// ---------------------------------------------------------------------------

func TestBetterAuthValidator_MissingUserID(t *testing.T) {
	v, err := NewBetterAuthValidator(testBetterAuthSecret)
	require.NoError(t, err)

	payload := map[string]string{
		"token":     "sess_test",
		"expiresAt": time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339),
		// Intentionally omitting "userId"
	}
	token := buildSignedToken(testBetterAuthSecret, payload)

	_, err = v.Authenticate(context.Background(), token)
	require.Error(t, err)
	assert.True(t, IsInvalidTokenError(err), "expected invalid_token error, got: %v", err)
	assert.Contains(t, unwrapAll(err), "missing userId")
}

func TestBetterAuthValidator_MissingExpiresAt(t *testing.T) {
	v, err := NewBetterAuthValidator(testBetterAuthSecret)
	require.NoError(t, err)

	payload := map[string]string{
		"token":  "sess_test",
		"userId": "user-abc",
		// Intentionally omitting "expiresAt"
	}
	token := buildSignedToken(testBetterAuthSecret, payload)

	_, err = v.Authenticate(context.Background(), token)
	require.Error(t, err)
	assert.True(t, IsInvalidTokenError(err), "expected invalid_token error, got: %v", err)
	assert.Contains(t, unwrapAll(err), "missing expiresAt")
}

// buildSignedToken signs an arbitrary map payload for testing edge cases.
func buildSignedToken(secret string, payload interface{}) string {
	payloadBytes, _ := json.Marshal(payload)
	payloadPart := base64.RawURLEncoding.EncodeToString(payloadBytes)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payloadBytes)
	sigPart := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf("%s.%s", payloadPart, sigPart)
}
