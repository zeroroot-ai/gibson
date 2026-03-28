package auth

import (
	"context"
	"fmt"
	"time"

	sdkauth "github.com/zero-day-ai/sdk/auth"
)

// OIDCValidator validates OIDC JWT tokens from configured issuers.
//
// This wraps the SDK OIDCValidator and adds Gibson-specific functionality:
//   - Role binding resolution from groups
//   - Permission derivation from roles
//   - Authentication metrics recording
//   - Integration with Gibson's AuthConfig format
//
// Implements the Authenticator interface.
// Thread-safe for concurrent use.
type OIDCValidator struct {
	// sdkValidator performs the actual OIDC token validation
	sdkValidator *sdkauth.OIDCValidator

	// issuerConfigs maps issuer URLs to Gibson issuer configs
	// Used for role binding resolution after SDK validation
	issuerConfigs map[string]*OIDCIssuerConfig

	// roleBinder resolves roles from groups using role bindings
	roleBinder *RoleBinder
}

// NewOIDCValidator creates a new OIDC validator from Gibson configuration.
//
// Converts Gibson's AuthConfig to SDK Config format and wraps the SDK validator
// with Gibson-specific authorization logic (role binding, permissions).
//
// Returns an error if configuration is invalid.
func NewOIDCValidator(cfg *AuthConfig) (*OIDCValidator, error) {
	if cfg == nil {
		return nil, fmt.Errorf("auth config is nil")
	}

	if len(cfg.OIDC) == 0 {
		return nil, fmt.Errorf("no OIDC issuers configured")
	}

	// Convert Gibson config to SDK config format
	sdkCfg := &sdkauth.Config{
		Issuers:   make([]sdkauth.OIDCConfig, len(cfg.OIDC)),
		ClockSkew: cfg.ClockSkew,
	}

	// Build issuer map for role binding lookup
	issuerConfigs := make(map[string]*OIDCIssuerConfig)

	// Convert each issuer config
	for i := range cfg.OIDC {
		gibsonIssuer := &cfg.OIDC[i]
		if gibsonIssuer.Issuer == "" {
			return nil, fmt.Errorf("OIDC issuer URL cannot be empty")
		}

		// Convert to SDK format
		sdkCfg.Issuers[i] = sdkauth.OIDCConfig{
			Issuer:        gibsonIssuer.Issuer,
			Audience:      gibsonIssuer.Audience,
			JWKSEndpoint:  gibsonIssuer.JWKSEndpoint,
			JWKSTTL:       gibsonIssuer.JWKSTTL,
			ClaimsMapping: gibsonIssuer.ClaimsMapping,
		}

		// Store Gibson config for role binding
		issuerConfigs[gibsonIssuer.Issuer] = gibsonIssuer
	}

	// Apply defaults
	sdkCfg.ApplyDefaults()

	// Create SDK validator
	sdkValidator, err := sdkauth.NewOIDCValidator(sdkCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create SDK validator: %w", err)
	}

	// Aggregate all role bindings from all issuers
	allRoleBindings := make(map[string][]string)
	for _, issuerCfg := range cfg.OIDC {
		for pattern, roles := range issuerCfg.RoleBindings {
			// Merge role bindings (later bindings override earlier ones)
			allRoleBindings[pattern] = roles
		}
	}

	// Create role binder from config
	roleBinder := NewRoleBinderFromConfig(allRoleBindings)

	return &OIDCValidator{
		sdkValidator:  sdkValidator,
		issuerConfigs: issuerConfigs,
		roleBinder:    roleBinder,
	}, nil
}

// Authenticate validates a JWT token and returns the authenticated identity.
//
// Process:
//  1. Delegate to SDK validator for OIDC token validation
//  2. Record authentication metrics
//  3. Resolve roles from groups using role bindings
//  4. Derive permissions from roles
//  5. Return Gibson Identity with authorization info
//
// Validates:
//   - Token format and signature (via SDK)
//   - Issuer is trusted (via SDK)
//   - Token has not expired (via SDK with clock skew tolerance)
//   - Audience matches configuration (via SDK, if configured)
//
// Returns Identity with extracted claims and resolved roles/permissions.
func (v *OIDCValidator) Authenticate(ctx context.Context, tokenString string) (*Identity, error) {
	startTime := time.Now()
	var issuer string

	// Record metrics on completion
	defer func() {
		if issuer != "" {
			latencyMs := float64(time.Since(startTime).Milliseconds())
			recordAuthLatency(ctx, issuer, latencyMs)
		}
	}()

	// Delegate to SDK validator for OIDC validation
	sdkIdentity, err := v.sdkValidator.Validate(ctx, tokenString)
	if err != nil {
		// Extract issuer from error for metrics if available
		// For unknown issuer errors, record as "unknown"
		issuer = "unknown"
		if sdkIdentity != nil {
			issuer = sdkIdentity.Issuer
		}
		recordAuthAttempt(ctx, issuer, "failure")

		// SDK errors are already properly formatted AuthError types
		// We can return them directly - they have correct gRPC codes
		return nil, err
	}

	issuer = sdkIdentity.Issuer
	recordAuthAttempt(ctx, issuer, "success")

	// Build Gibson Identity by embedding SDK Identity
	// and adding Gibson-specific authorization fields
	gibsonIdentity := &Identity{
		Identity: *sdkIdentity,
	}

	// Resolve roles and permissions from groups using role bindings
	if v.roleBinder != nil {
		roles, permissions, err := v.roleBinder.ResolveRoles(gibsonIdentity)
		if err != nil {
			// Role resolution failure is not a hard error in some cases
			// (e.g., user has no matching role bindings but we still want to authenticate them)
			// Log the error but continue with empty roles
			// The interceptor or handler can decide if roles are required
			gibsonIdentity.Roles = []string{}
			gibsonIdentity.Permissions = []Permission{}
		} else {
			gibsonIdentity.Roles = roles
			gibsonIdentity.Permissions = permissions
		}
	} else {
		// No role binder configured - set empty roles/permissions
		gibsonIdentity.Roles = []string{}
		gibsonIdentity.Permissions = []Permission{}
	}

	return gibsonIdentity, nil
}
