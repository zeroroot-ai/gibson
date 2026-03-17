package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// OIDCValidator validates OIDC JWT tokens from configured issuers.
//
// Implements the Authenticator interface.
// Thread-safe for concurrent use.
type OIDCValidator struct {
	issuers   map[string]*OIDCIssuerConfig
	jwksCache *JWKSCache
	clockSkew time.Duration
}

// NewOIDCValidator creates a new OIDC validator from configuration.
//
// Returns an error if configuration is invalid.
func NewOIDCValidator(cfg *AuthConfig) (*OIDCValidator, error) {
	if cfg == nil {
		return nil, fmt.Errorf("auth config is nil")
	}

	// Build issuer map for fast lookup
	issuers := make(map[string]*OIDCIssuerConfig)
	for i := range cfg.OIDC {
		issuer := &cfg.OIDC[i]
		if issuer.Issuer == "" {
			return nil, fmt.Errorf("OIDC issuer URL cannot be empty")
		}
		issuers[issuer.Issuer] = issuer
	}

	// Use default TTL if not configured
	defaultTTL := 1 * time.Hour
	for _, issuer := range issuers {
		if issuer.JWKSTTL == 0 {
			issuer.JWKSTTL = defaultTTL
		}
	}

	clockSkew := cfg.ClockSkew
	if clockSkew == 0 {
		clockSkew = 30 * time.Second
	}

	return &OIDCValidator{
		issuers:   issuers,
		jwksCache: NewJWKSCache(defaultTTL),
		clockSkew: clockSkew,
	}, nil
}

// Authenticate validates a JWT token and returns the authenticated identity.
//
// Validates:
//   - Token format and signature
//   - Issuer is trusted
//   - Token has not expired (with clock skew tolerance)
//   - Audience matches configuration (if configured)
//
// Returns Identity with extracted claims and resolved roles.
func (v *OIDCValidator) Authenticate(ctx context.Context, tokenString string) (*Identity, error) {
	startTime := time.Now()
	var issuerClaim string
	defer func() {
		latencyMs := float64(time.Since(startTime).Milliseconds())
		if issuerClaim != "" {
			recordAuthLatency(ctx, issuerClaim, latencyMs)
		}
	}()

	// Parse token without validation first to extract issuer
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		recordAuthAttempt(ctx, "unknown", "error")
		return nil, ErrMalformedToken(err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrMalformedToken(fmt.Errorf("invalid claims type"))
	}

	// Extract issuer claim
	issuerClaim, ok = claims["iss"].(string)
	if !ok || issuerClaim == "" {
		recordAuthAttempt(ctx, "unknown", "error")
		return nil, ErrMalformedToken(fmt.Errorf("missing or invalid iss claim"))
	}

	// Find issuer configuration
	issuerConfig, ok := v.issuers[issuerClaim]
	if !ok {
		recordAuthAttempt(ctx, issuerClaim, "failure")
		return nil, ErrUnknownIssuer(issuerClaim)
	}

	// Parse and validate token with signature verification
	validatedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method is expected
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA, *jwt.SigningMethodECDSA:
			// OK - asymmetric signing
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get key ID from token header
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("missing kid in token header")
		}

		// Determine JWKS URL
		jwksURL := issuerConfig.JWKSEndpoint
		if jwksURL == "" {
			// Auto-discover: {issuer}/.well-known/jwks.json
			jwksURL = issuerClaim + "/.well-known/jwks.json"
		}

		// Fetch public key from cache or JWKS endpoint
		pubKey, err := v.jwksCache.GetKey(ctx, issuerClaim, kid, jwksURL)
		if err != nil {
			return nil, err
		}

		return pubKey, nil
	}, jwt.WithLeeway(v.clockSkew))

	if err != nil {
		recordAuthAttempt(ctx, issuerClaim, "failure")
		if err == jwt.ErrTokenExpired || err == jwt.ErrTokenNotValidYet {
			return nil, ErrTokenExpired()
		}
		return nil, ErrInvalidSignature()
	}

	if !validatedToken.Valid {
		recordAuthAttempt(ctx, issuerClaim, "failure")
		return nil, ErrInvalidSignature()
	}

	// Extract validated claims
	validatedClaims, ok := validatedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrMalformedToken(fmt.Errorf("invalid claims type after validation"))
	}

	// Validate audience if configured
	if issuerConfig.Audience != "" {
		audClaim, ok := validatedClaims["aud"]
		if !ok {
			return nil, ErrInvalidAudience(issuerConfig.Audience, "missing")
		}

		// Audience can be string or []string
		var audienceMatch bool
		switch aud := audClaim.(type) {
		case string:
			audienceMatch = aud == issuerConfig.Audience
		case []interface{}:
			for _, a := range aud {
				if audStr, ok := a.(string); ok && audStr == issuerConfig.Audience {
					audienceMatch = true
					break
				}
			}
		}

		if !audienceMatch {
			return nil, ErrInvalidAudience(issuerConfig.Audience, fmt.Sprintf("%v", audClaim))
		}
	}

	// Extract standard claims
	subject, _ := validatedClaims["sub"].(string)
	email, _ := validatedClaims["email"].(string)

	// Extract expiry time
	var expiresAt time.Time
	if exp, ok := validatedClaims["exp"].(float64); ok {
		expiresAt = time.Unix(int64(exp), 0)
	}

	// Extract groups (may be in different claim names depending on provider)
	var groups []string
	if groupsClaim, ok := validatedClaims["groups"]; ok {
		switch g := groupsClaim.(type) {
		case []interface{}:
			for _, group := range g {
				if groupStr, ok := group.(string); ok {
					groups = append(groups, groupStr)
				}
			}
		case []string:
			groups = g
		}
	}

	// Apply claims mapping if configured
	mappedClaims := v.mapClaims(validatedClaims, issuerConfig)

	// Build identity
	identity := &Identity{
		Subject:         subject,
		Issuer:          issuerClaim,
		Email:           email,
		Groups:          groups,
		Claims:          mappedClaims,
		Roles:           []string{}, // Will be filled by role binder
		Permissions:     []Permission{},
		ExpiresAt:       expiresAt,
		AuthenticatedAt: time.Now(),
	}

	recordAuthAttempt(ctx, issuerClaim, "success")
	return identity, nil
}

// mapClaims applies claim mappings from issuer configuration.
func (v *OIDCValidator) mapClaims(claims jwt.MapClaims, config *OIDCIssuerConfig) map[string]any {
	mapped := make(map[string]any)

	// Copy all claims first
	for k, v := range claims {
		mapped[k] = v
	}

	// Apply mappings if configured
	if config.ClaimsMapping != nil {
		for targetKey, sourceKey := range config.ClaimsMapping {
			if value, ok := claims[sourceKey]; ok {
				mapped[targetKey] = value
			}
		}
	}

	return mapped
}
