// Package auth — better_auth.go
//
// BetterAuthValidator validates Better Auth session tokens sent by the dashboard
// in gRPC Authorization: Bearer <token> headers.
//
// Better Auth cookie-cached session token format:
//
//	<base64url(json-payload)>.<base64url(hmac-sha256-signature)>
//
// The JSON payload contains:
//
//	{
//	  "token": "<session-id>",
//	  "userId": "<uuid-v4>",
//	  "expiresAt": "<ISO-8601>",
//	  "activeOrganizationId": "<org-id-or-null>",
//	  "createdAt": "<ISO-8601>"
//	}
//
// Verification steps:
//  1. Split token on "." to get payload and signature parts.
//  2. Base64url-decode both parts.
//  3. Compute HMAC-SHA256(raw-payload-bytes, BETTER_AUTH_SECRET).
//  4. Compare computed MAC with decoded signature using constant-time comparison.
//  5. Decode JSON payload, check expiresAt with 30s clock-skew tolerance.
//  6. Construct Identity with Subject=userId, Tenants=[activeOrganizationId] (if set).
//
// This validator makes zero network calls. It is pure cryptographic verification.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	sdkauth "github.com/zero-day-ai/sdk/auth"
	"google.golang.org/grpc/codes"
)

const (
	// betterAuthIssuer is used in metrics and audit trail for tokens authenticated
	// via this validator.
	betterAuthIssuer = "better-auth"

	// betterAuthClockSkew is the tolerance window when checking token expiry.
	// A token expiring within this window (or slightly past) is still accepted.
	betterAuthClockSkew = 30 * time.Second
)

// betterAuthPayload is the JSON payload contained in a Better Auth session token.
type betterAuthPayload struct {
	// Token is the session identifier (opaque string).
	Token string `json:"token"`

	// UserID is the Better Auth user UUID.
	UserID string `json:"userId"`

	// ExpiresAt is the session expiry time in ISO-8601 format.
	ExpiresAt string `json:"expiresAt"`

	// ActiveOrganizationID is the currently active organization slug or UUID.
	// May be empty if the user has not selected an organization.
	ActiveOrganizationID string `json:"activeOrganizationId"`

	// CreatedAt is when the session was created (ISO-8601). Not used for validation.
	CreatedAt string `json:"createdAt"`
}

// BetterAuthValidator validates Better Auth session tokens using HMAC-SHA256
// signature verification.
//
// The shared secret (BETTER_AUTH_SECRET) must match the secret configured in
// the Better Auth server instance running in the dashboard process.
//
// Implements the Authenticator interface.
// Thread-safe for concurrent use — the secret is read-only after construction.
type BetterAuthValidator struct {
	// secret is the raw bytes of the BETTER_AUTH_SECRET shared between the
	// dashboard (Better Auth server) and the daemon.
	secret []byte
}

// NewBetterAuthValidator creates a BetterAuthValidator from the given shared secret.
//
// Returns an error if the secret is empty.
func NewBetterAuthValidator(secret string) (*BetterAuthValidator, error) {
	if secret == "" {
		return nil, fmt.Errorf("better_auth: BETTER_AUTH_SECRET must not be empty")
	}
	return &BetterAuthValidator{
		secret: []byte(secret),
	}, nil
}

// Authenticate validates a Better Auth session token and returns the authenticated identity.
//
// Process:
//  1. Split token into payload and signature parts (separated by ".").
//  2. Base64url-decode both parts.
//  3. Verify HMAC-SHA256 signature using the shared secret.
//  4. Decode JSON payload and check expiresAt (with 30s clock skew tolerance).
//  5. Construct Identity with Subject=userId, Tenants=[activeOrganizationId] if non-empty.
//  6. Record auth metrics.
//
// Returns ErrInvalidToken for malformed tokens, expired tokens, or bad signatures.
func (v *BetterAuthValidator) Authenticate(ctx context.Context, token string) (*Identity, error) {
	startTime := time.Now()

	// Record latency on completion regardless of outcome.
	defer func() {
		latencyMs := float64(time.Since(startTime).Milliseconds())
		recordAuthLatency(ctx, betterAuthIssuer, latencyMs)
	}()

	identity, err := v.validate(ctx, token)
	if err != nil {
		recordAuthAttempt(ctx, betterAuthIssuer, "failure")
		return nil, err
	}

	recordAuthAttempt(ctx, betterAuthIssuer, "success")
	return identity, nil
}

// validate performs the actual token validation and returns the Identity on success.
// Separated from Authenticate so the defer for metrics fires correctly.
func (v *BetterAuthValidator) validate(ctx context.Context, token string) (*Identity, error) {
	if token == "" {
		return nil, ErrMissingToken()
	}

	// Split into two parts: <payload>.<signature>
	// Better Auth tokens use exactly one "." separator.
	dotIdx := strings.LastIndex(token, ".")
	if dotIdx < 0 || dotIdx == len(token)-1 {
		return nil, ErrInvalidToken(fmt.Errorf("better_auth: token missing signature separator"))
	}

	payloadPart := token[:dotIdx]
	sigPart := token[dotIdx+1:]

	// Decode the base64url-encoded payload (raw bytes — used for HMAC verification).
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		return nil, ErrInvalidToken(fmt.Errorf("better_auth: failed to decode payload: %w", err))
	}

	// Decode the base64url-encoded HMAC signature.
	sigBytes, err := base64.RawURLEncoding.DecodeString(sigPart)
	if err != nil {
		return nil, ErrInvalidToken(fmt.Errorf("better_auth: failed to decode signature: %w", err))
	}

	// Verify HMAC-SHA256 signature using the shared secret.
	// Use constant-time comparison to prevent timing attacks.
	mac := hmac.New(sha256.New, v.secret)
	mac.Write(payloadBytes)
	expectedSig := mac.Sum(nil)

	if !hmac.Equal(expectedSig, sigBytes) {
		return nil, ErrInvalidToken(fmt.Errorf("better_auth: signature verification failed"))
	}

	// Decode the JSON payload.
	var payload betterAuthPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, ErrInvalidToken(fmt.Errorf("better_auth: failed to decode payload JSON: %w", err))
	}

	// Validate required fields.
	if payload.UserID == "" {
		return nil, ErrInvalidToken(fmt.Errorf("better_auth: payload missing userId"))
	}
	if payload.ExpiresAt == "" {
		return nil, ErrInvalidToken(fmt.Errorf("better_auth: payload missing expiresAt"))
	}

	// Parse and validate token expiry with clock-skew tolerance.
	expiresAt, err := time.Parse(time.RFC3339, payload.ExpiresAt)
	if err != nil {
		// Try RFC3339Nano in case nanoseconds are present.
		expiresAt, err = time.Parse(time.RFC3339Nano, payload.ExpiresAt)
		if err != nil {
			return nil, ErrInvalidToken(fmt.Errorf("better_auth: invalid expiresAt %q: %w", payload.ExpiresAt, err))
		}
	}

	// Allow tokens that expired within the clock-skew window.
	if time.Now().After(expiresAt.Add(betterAuthClockSkew)) {
		return nil, &AuthError{
			Code:    codes.Unauthenticated,
			Message: fmt.Sprintf("better_auth: token expired at %s", expiresAt.Format(time.RFC3339)),
			Reason:  "expired_token",
		}
	}

	// Build the tenants slice from activeOrganizationId (may be empty).
	var tenants []string
	if payload.ActiveOrganizationID != "" {
		tenants = []string{payload.ActiveOrganizationID}
	}

	// Construct the Gibson Identity.
	// Roles, Permissions, and Capabilities are left empty — they are resolved
	// by the RPCAuthzInterceptor via permissions.yaml at the authorization layer.
	identity := &Identity{
		Identity: sdkauth.Identity{
			Subject:         payload.UserID,
			Issuer:          betterAuthIssuer,
			ExpiresAt:       expiresAt,
			AuthenticatedAt: time.Now(),
		},
		Roles:        []string{},
		Permissions:  []Permission{},
		Capabilities: nil,
		Tenants:      tenants,
	}

	return identity, nil
}
