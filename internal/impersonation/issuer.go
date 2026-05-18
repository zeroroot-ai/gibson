package impersonation

// issuer.go implements HMAC-SHA256 signed JWT impersonation tokens.
//
// The issued token carries the following claims:
//
//	sub:          target tenant ID
//	impersonator: user subject of the admin who requested the token
//	iat:          issued-at Unix timestamp
//	exp:          expiry Unix timestamp (iat + ttl, clamped to max 1 hour)
//	typ:          "impersonation"
//
// Tokens are stateless; revocation is by expiry only. The signing key MUST
// be at least 32 bytes and supplied by the operator — there is no in-process
// random fallback. A randomly-minted key would invalidate every previously-
// issued token on every daemon restart and would diverge silently across
// replicas in any HA deployment. See gibson#103.
//
// Key rotation: a second optional "previous" key may be configured. The
// Issuer mints ONLY with the current key, but Verify accepts tokens signed
// by either key. Operators rotate by promoting the existing current key
// into the previous slot, minting a new current key, and clearing the
// previous slot after maxTTL has elapsed (1 hour) — by which point every
// token issued under the old key has expired naturally.

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/zero-day-ai/sdk/auth"
)

const (
	// maxTTL is the hard upper bound on impersonation token lifetime.
	maxTTL = time.Hour

	// defaultTTL is used when the caller passes zero.
	defaultTTL = 15 * time.Minute

	// minKeyBytes is the minimum acceptable signing-key length for HS256.
	// RFC 7518 §3.2 requires the key to be at least as long as the hash
	// output (256 bits / 32 bytes); shorter keys MUST be rejected.
	minKeyBytes = 32

	tokenType = "impersonation"
)

// impersonationClaims extends jwt.RegisteredClaims with Gibson-specific fields.
type impersonationClaims struct {
	jwtv5.RegisteredClaims

	// Impersonator is the user subject of the operator who issued the token.
	Impersonator string `json:"impersonator"`

	// Typ identifies the token as an impersonation token.
	Typ string `json:"typ"`
}

// Issuer signs impersonation JWTs with HMAC-SHA256.
type Issuer struct {
	signingKey  []byte
	previousKey []byte // optional; used by Verify only, never to sign
	defaultTTL  time.Duration
	logger      *slog.Logger
}

// New creates an Issuer with the given current signing key, optional
// previous signing key, and default TTL.
//
// The current key MUST be at least minKeyBytes (32) bytes; New returns an
// error otherwise. The previous key, when non-empty, MUST also satisfy
// minKeyBytes — pass nil or an empty slice to disable rotation acceptance.
//
// Callers are responsible for sourcing keys from durable storage (Helm
// ExternalSecret → env vars in production; test fixtures in unit tests).
// There is no random-key fallback — that would invalidate every
// previously-issued token on every daemon restart and diverge silently
// across HA replicas.
//
// The defaultTTL is clamped to maxTTL; zero → defaultTTL constant (15m).
func New(currentKey, previousKey []byte, ttl time.Duration, logger *slog.Logger) (*Issuer, error) {
	if logger == nil {
		logger = slog.Default()
	}

	if len(currentKey) < minKeyBytes {
		return nil, fmt.Errorf("impersonation: current signing key must be at least %d bytes (got %d) — set GIBSON_IMPERSONATION_KEY", minKeyBytes, len(currentKey))
	}
	if len(previousKey) > 0 && len(previousKey) < minKeyBytes {
		return nil, fmt.Errorf("impersonation: previous signing key must be empty OR at least %d bytes (got %d) — fix GIBSON_IMPERSONATION_KEY_PREVIOUS", minKeyBytes, len(previousKey))
	}

	if ttl <= 0 {
		ttl = defaultTTL
	}
	if ttl > maxTTL {
		ttl = maxTTL
	}

	return &Issuer{
		signingKey:  currentKey,
		previousKey: previousKey,
		defaultTTL:  ttl,
		logger:      logger,
	}, nil
}

// IssueToken generates a signed impersonation JWT for the given tenantID.
// The caller's identity is extracted from the context and embedded as the
// "impersonator" claim. The token TTL is clamped to maxTTL (1 hour).
func (i *Issuer) IssueToken(ctx context.Context, tenantID string) (string, error) {
	if tenantID == "" {
		return "", fmt.Errorf("tenantID is required")
	}

	// Extract the caller's identity for the impersonator claim.
	impersonatorSubject := ""
	if id, err := auth.IdentityFromContext(ctx); err == nil {
		impersonatorSubject = id.Subject
	}

	now := time.Now()
	exp := now.Add(i.defaultTTL)

	claims := impersonationClaims{
		RegisteredClaims: jwtv5.RegisteredClaims{
			Subject:   tenantID,
			IssuedAt:  jwtv5.NewNumericDate(now),
			ExpiresAt: jwtv5.NewNumericDate(exp),
		},
		Impersonator: impersonatorSubject,
		Typ:          tokenType,
	}

	token := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims)
	signed, err := token.SignedString(i.signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign impersonation token: %w", err)
	}

	i.logger.InfoContext(ctx, "impersonation: issued token",
		slog.String("impersonator", impersonatorSubject),
		slog.String("target_tenant", tenantID),
		slog.Duration("ttl", i.defaultTTL),
		// token value is intentionally NOT logged.
	)

	return signed, nil
}

// VerifiedClaims is the subset of impersonationClaims a verified caller
// learns about a token. Exposed (vs the package-private claims struct) so
// downstream consumers don't import jwt/v5 transitively.
type VerifiedClaims struct {
	// TenantID is the target tenant the token grants impersonation of.
	TenantID string
	// Impersonator is the operator subject who minted the token. Empty
	// when the issuer ran without an authenticated caller (test paths).
	Impersonator string
	// ExpiresAt is the absolute UTC expiry. The library already enforces
	// it via the jwt.WithExpirationRequired option; surfaced here for
	// audit logging and downstream short-circuit checks.
	ExpiresAt time.Time
}

// Verify parses and validates an impersonation token. A token is accepted
// when it (a) parses as HS256, (b) has not expired, (c) carries the
// "impersonation" typ claim, and (d) verifies against the current key
// OR the configured previous key.
//
// During rotation the operator promotes the existing current key into
// the previous slot before minting a new current key. Tokens minted
// under the old key continue to verify until they expire naturally
// (maxTTL upper-bounds the window at 1 hour). Once that window has
// elapsed the operator clears the previous slot.
//
// Verify is intended for use by the future impersonation-token verifier
// (no in-tree consumer today; the daemon's RPC mints tokens, but the
// downstream presents-and-verifies path is not yet implemented). It
// lives here so the rotation contract sits next to the key material.
func (i *Issuer) Verify(tokenString string) (VerifiedClaims, error) {
	// Try current key first (the steady-state hot path).
	if claims, err := i.parseWithKey(tokenString, i.signingKey); err == nil {
		return claims, nil
	} else if len(i.previousKey) == 0 {
		// No fallback configured — surface the original failure.
		return VerifiedClaims{}, err
	}

	// Try the previous key. We don't differentiate "current rejected,
	// previous accepted" in the return value — that's an operator
	// metric, not a security signal — but we log it so rotation can be
	// observed in flight.
	claims, err := i.parseWithKey(tokenString, i.previousKey)
	if err != nil {
		return VerifiedClaims{}, err
	}
	i.logger.Info("impersonation: token verified with previous key — rotation in flight",
		slog.String("target_tenant", claims.TenantID),
		slog.Time("expires_at", claims.ExpiresAt),
	)
	return claims, nil
}

func (i *Issuer) parseWithKey(tokenString string, key []byte) (VerifiedClaims, error) {
	parsed, err := jwtv5.ParseWithClaims(
		tokenString,
		&impersonationClaims{},
		func(tok *jwtv5.Token) (interface{}, error) {
			if tok.Method.Alg() != jwtv5.SigningMethodHS256.Alg() {
				return nil, fmt.Errorf("unexpected signing method %q", tok.Method.Alg())
			}
			return key, nil
		},
		jwtv5.WithValidMethods([]string{jwtv5.SigningMethodHS256.Alg()}),
		jwtv5.WithExpirationRequired(),
	)
	if err != nil {
		return VerifiedClaims{}, fmt.Errorf("verify impersonation token: %w", err)
	}
	claims, ok := parsed.Claims.(*impersonationClaims)
	if !ok || !parsed.Valid {
		return VerifiedClaims{}, fmt.Errorf("verify impersonation token: invalid claims")
	}
	if claims.Typ != tokenType {
		return VerifiedClaims{}, fmt.Errorf("verify impersonation token: typ=%q, expected %q", claims.Typ, tokenType)
	}
	exp := time.Time{}
	if claims.ExpiresAt != nil {
		exp = claims.ExpiresAt.Time
	}
	return VerifiedClaims{
		TenantID:     claims.Subject,
		Impersonator: claims.Impersonator,
		ExpiresAt:    exp,
	}, nil
}
