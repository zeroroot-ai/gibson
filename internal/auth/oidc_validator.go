package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	sdkauth "github.com/zero-day-ai/sdk/auth"
)

// IssuerConfig configures a single trusted OIDC issuer.
type IssuerConfig struct {
	// Issuer is the expected "iss" claim in tokens (e.g., "http://keycloak:8080/realms/gibson").
	Issuer string

	// Audience is the expected "aud" claim. Empty means no audience check.
	Audience string

	// JWKSEndpoint overrides the auto-discovered JWKS URL. When empty,
	// the validator fetches {Issuer}/.well-known/openid-configuration
	// and reads the jwks_uri field.
	JWKSEndpoint string

	// JWKSTTL is the cache TTL for JWKS keys. Default: 1 hour.
	JWKSTTL time.Duration

	// ClaimsMapping maps provider-specific claim names to standard names.
	// Format: {"target_claim": "source_claim"}.
	ClaimsMapping map[string]string

	// RoleBindings maps group/role claims to Gibson roles.
	// Stored here for use by the daemon's role binder (not used by the validator itself).
	RoleBindings map[string][]string
}

// DaemonOIDCValidator validates OIDC JWT tokens using proper OIDC discovery.
//
// Unlike the SDK's OIDCValidator which guesses the JWKS URL, this validator
// fetches the OIDC discovery document to find the correct jwks_uri.
//
// Thread-safe for concurrent use.
type DaemonOIDCValidator struct {
	issuers   map[string]*IssuerConfig
	jwksCache *DaemonJWKSCache
	clockSkew time.Duration
	client    *http.Client

	// discoveredJWKS maps issuer URL → discovered jwks_uri
	discoveredJWKS map[string]string
	discoveryMu    sync.RWMutex
}

// NewDaemonOIDCValidator creates a new OIDC validator with proper discovery.
//
// For each issuer without an explicit JWKSEndpoint, the validator will
// perform OIDC discovery on first token validation to find the jwks_uri.
func NewDaemonOIDCValidator(issuers []IssuerConfig, clockSkew time.Duration) (*DaemonOIDCValidator, error) {
	if len(issuers) == 0 {
		return nil, fmt.Errorf("at least one OIDC issuer must be configured")
	}

	issuerMap := make(map[string]*IssuerConfig)
	for i := range issuers {
		cfg := &issuers[i]
		if cfg.Issuer == "" {
			return nil, fmt.Errorf("issuer URL cannot be empty")
		}
		if cfg.JWKSTTL == 0 {
			cfg.JWKSTTL = 1 * time.Hour
		}
		issuerMap[cfg.Issuer] = cfg
	}

	if clockSkew == 0 {
		clockSkew = 30 * time.Second
	}

	return &DaemonOIDCValidator{
		issuers:        issuerMap,
		jwksCache:      NewDaemonJWKSCache(1 * time.Hour),
		clockSkew:      clockSkew,
		client:         &http.Client{Timeout: 10 * time.Second},
		discoveredJWKS: make(map[string]string),
	}, nil
}

// discoverJWKSURI fetches the OIDC discovery document and extracts jwks_uri.
// Results are cached per issuer.
func (v *DaemonOIDCValidator) discoverJWKSURI(ctx context.Context, issuer string) (string, error) {
	// Check cache first
	v.discoveryMu.RLock()
	if uri, ok := v.discoveredJWKS[issuer]; ok {
		v.discoveryMu.RUnlock()
		return uri, nil
	}
	v.discoveryMu.RUnlock()

	// Fetch discovery document
	discoveryURL := issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", fmt.Errorf("oidc_discovery_failed: failed to create request for %s: %w", discoveryURL, err)
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("oidc_discovery_failed: GET %s: %w", discoveryURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oidc_discovery_failed: GET %s returned HTTP %d", discoveryURL, resp.StatusCode)
	}

	var discovery struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return "", fmt.Errorf("oidc_discovery_failed: failed to parse response from %s: %w", discoveryURL, err)
	}

	if discovery.JWKSURI == "" {
		return "", fmt.Errorf("oidc_discovery_failed: no jwks_uri in discovery document at %s", discoveryURL)
	}

	// Cache the result
	v.discoveryMu.Lock()
	v.discoveredJWKS[issuer] = discovery.JWKSURI
	v.discoveryMu.Unlock()

	slog.Info("OIDC discovery completed",
		"issuer", issuer,
		"jwks_uri", discovery.JWKSURI,
	)

	return discovery.JWKSURI, nil
}

// getJWKSURL returns the JWKS URL for an issuer, using explicit config or discovery.
func (v *DaemonOIDCValidator) getJWKSURL(ctx context.Context, issuer string, config *IssuerConfig) (string, error) {
	if config.JWKSEndpoint != "" {
		return config.JWKSEndpoint, nil
	}
	return v.discoverJWKSURI(ctx, issuer)
}

// Validate validates a JWT token and returns the authenticated identity.
//
// Validation steps:
//  1. Parse JWT without verification to extract issuer claim
//  2. Find issuer in trusted issuers list
//  3. Determine JWKS URL (explicit or via OIDC discovery)
//  4. Fetch/cache public key matching token's kid
//  5. Verify signature (RSA or ECDSA only)
//  6. Check expiry with clock skew
//  7. Validate audience if configured
//  8. Extract claims and build Identity
//
// Every failure returns a specific, descriptive error for debugging.
func (v *DaemonOIDCValidator) Validate(ctx context.Context, tokenString string) (*sdkauth.Identity, error) {
	// Step 1: Parse without validation to get issuer
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("malformed_token: failed to parse JWT: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("malformed_token: invalid claims type")
	}

	// Step 2: Find issuer
	issuerClaim, ok := claims["iss"].(string)
	if !ok || issuerClaim == "" {
		return nil, fmt.Errorf("malformed_token: missing or empty iss claim")
	}

	issuerConfig, ok := v.issuers[issuerClaim]
	if !ok {
		return nil, fmt.Errorf("unknown_issuer: %s (trusted issuers: %v)", issuerClaim, v.trustedIssuers())
	}

	// Step 3-5: Parse and validate with signature verification
	validatedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Reject HMAC signatures
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA, *jwt.SigningMethodECDSA:
			// OK
		default:
			return nil, fmt.Errorf("unsupported_signing_method: %v (only RSA and ECDSA accepted)", token.Header["alg"])
		}

		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("missing_kid: token has no kid header")
		}

		// Get JWKS URL via discovery or explicit config
		jwksURL, err := v.getJWKSURL(ctx, issuerClaim, issuerConfig)
		if err != nil {
			return nil, err
		}

		// Fetch key
		pubKey, err := v.jwksCache.GetKey(ctx, issuerClaim, kid, jwksURL)
		if err != nil {
			return nil, fmt.Errorf("jwks_key_error: kid=%s issuer=%s: %w", kid, issuerClaim, err)
		}

		return pubKey, nil
	}, jwt.WithLeeway(v.clockSkew))

	if err != nil {
		// Preserve the specific error — don't swallow it
		if errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, fmt.Errorf("token_expired: %w", err)
		}
		return nil, fmt.Errorf("token_validation_failed: %w", err)
	}

	if !validatedToken.Valid {
		return nil, fmt.Errorf("token_invalid: token did not pass validation")
	}

	// Step 6: Extract validated claims
	validatedClaims, ok := validatedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("malformed_token: invalid claims type after validation")
	}

	// Step 7: Validate audience
	if issuerConfig.Audience != "" {
		if err := validateAudience(validatedClaims, issuerConfig.Audience); err != nil {
			return nil, err
		}
	}

	// Step 8: Extract claims and build identity
	subject, _ := validatedClaims["sub"].(string)
	email, _ := validatedClaims["email"].(string)

	var expiresAt time.Time
	if exp, ok := validatedClaims["exp"].(float64); ok {
		expiresAt = time.Unix(int64(exp), 0)
	}

	groups := extractGroups(validatedClaims)
	mappedClaims := mapClaims(validatedClaims, issuerConfig)

	identity := &sdkauth.Identity{
		Subject:         subject,
		Issuer:          issuerClaim,
		Email:           email,
		Groups:          groups,
		Claims:          mappedClaims,
		ExpiresAt:       expiresAt,
		AuthenticatedAt: time.Now(),
	}

	return identity, nil
}

// trustedIssuers returns a list of configured issuer URLs for error messages.
func (v *DaemonOIDCValidator) trustedIssuers() []string {
	issuers := make([]string, 0, len(v.issuers))
	for k := range v.issuers {
		issuers = append(issuers, k)
	}
	return issuers
}

// SetHTTPClient sets the HTTP client used for discovery and JWKS fetching.
// Primarily for testing.
func (v *DaemonOIDCValidator) SetHTTPClient(client *http.Client) {
	v.client = client
	v.jwksCache.client = client
}

// --- Helper functions (not methods, shared) ---

func validateAudience(claims jwt.MapClaims, expected string) error {
	audClaim, ok := claims["aud"]
	if !ok {
		return fmt.Errorf("audience_mismatch: expected=%s, got=missing", expected)
	}

	switch aud := audClaim.(type) {
	case string:
		if aud == expected {
			return nil
		}
		return fmt.Errorf("audience_mismatch: expected=%s, got=%s", expected, aud)
	case []interface{}:
		for _, a := range aud {
			if audStr, ok := a.(string); ok && audStr == expected {
				return nil
			}
		}
		return fmt.Errorf("audience_mismatch: expected=%s, got=%v", expected, audClaim)
	default:
		return fmt.Errorf("audience_mismatch: expected=%s, got=%T(%v)", expected, audClaim, audClaim)
	}
}

func extractGroups(claims jwt.MapClaims) []string {
	for _, claimName := range []string{"groups", "roles", "teams", "realm_access"} {
		if claimName == "realm_access" {
			// Keycloak puts roles in realm_access.roles
			if ra, ok := claims["realm_access"].(map[string]interface{}); ok {
				if roles, ok := ra["roles"].([]interface{}); ok {
					var groups []string
					for _, r := range roles {
						if s, ok := r.(string); ok {
							groups = append(groups, s)
						}
					}
					if len(groups) > 0 {
						return groups
					}
				}
			}
			continue
		}

		if groupsClaim, ok := claims[claimName]; ok {
			switch g := groupsClaim.(type) {
			case []interface{}:
				var groups []string
				for _, group := range g {
					if s, ok := group.(string); ok {
						groups = append(groups, s)
					}
				}
				if len(groups) > 0 {
					return groups
				}
			case []string:
				return g
			}
		}
	}
	return nil
}

func mapClaims(claims jwt.MapClaims, config *IssuerConfig) map[string]any {
	mapped := make(map[string]any)
	for k, v := range claims {
		mapped[k] = v
	}
	if config.ClaimsMapping != nil {
		for targetKey, sourceKey := range config.ClaimsMapping {
			if value, ok := claims[sourceKey]; ok {
				mapped[targetKey] = value
			}
		}
	}
	return mapped
}
