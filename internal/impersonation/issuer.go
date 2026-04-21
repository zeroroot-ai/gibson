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
// Tokens are stateless; revocation is by expiry only. The signing key must be
// at least 32 bytes; a warning is logged if a generated (non-configured) key
// is in use.

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/zero-day-ai/gibson/internal/identity"
)

const (
	// maxTTL is the hard upper bound on impersonation token lifetime.
	maxTTL = time.Hour

	// defaultTTL is used when the caller passes zero.
	defaultTTL = 15 * time.Minute

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
	signingKey []byte
	defaultTTL time.Duration
	logger     *slog.Logger
}

// New creates an Issuer with the given signing key and default TTL.
// If signingKey is empty or nil, a random 32-byte key is generated and a
// warning is logged — this is acceptable in development but not in production.
// The defaultTTL is clamped to maxTTL; zero → defaultTTL constant (15m).
func New(signingKey []byte, ttl time.Duration, logger *slog.Logger) *Issuer {
	if logger == nil {
		logger = slog.Default()
	}

	if len(signingKey) == 0 {
		generated := make([]byte, 32)
		if _, err := rand.Read(generated); err != nil {
			panic(fmt.Sprintf("impersonation: failed to generate signing key: %v", err))
		}
		signingKey = generated
		logger.Warn("impersonation: using a randomly generated signing key — configure a persistent key for production",
			slog.String("hint", "set security.impersonation_key in config"),
		)
	}

	if ttl <= 0 {
		ttl = defaultTTL
	}
	if ttl > maxTTL {
		ttl = maxTTL
	}

	return &Issuer{
		signingKey: signingKey,
		defaultTTL: ttl,
		logger:     logger,
	}
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
	if id, err := identity.IdentityFromContext(ctx); err == nil {
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
