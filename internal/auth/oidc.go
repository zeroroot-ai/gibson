package auth

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/casbin/casbin/v2"
)

// OIDCValidator validates OIDC JWT tokens from configured issuers.
//
// Uses the daemon's own DaemonOIDCValidator for OIDC token validation
// (with proper OIDC discovery for JWKS endpoints), and adds Gibson-specific:
//   - Role binding resolution from groups
//   - Permission derivation from roles
//   - Capability resolution from roles via roleCapabilities
//   - Casbin policy sync for role-derived capabilities
//   - Authentication metrics recording
//
// Implements the Authenticator interface.
// Thread-safe for concurrent use.
type OIDCValidator struct {
	// validator performs OIDC token validation with proper discovery
	validator *DaemonOIDCValidator

	// issuerConfigs maps issuer URLs to Gibson issuer configs
	issuerConfigs map[string]*OIDCIssuerConfig

	// roleBinder resolves roles from groups using role bindings
	roleBinder *RoleBinder

	// enforcer is the optional Casbin enforcer for capability sync
	enforcer *casbin.Enforcer
}

// NewOIDCValidator creates a new OIDC validator from Gibson configuration.
//
// Uses proper OIDC discovery to find JWKS endpoints — no hardcoded paths.
// Returns an error if configuration is invalid.
func NewOIDCValidator(cfg *AuthConfig) (*OIDCValidator, error) {
	if cfg == nil {
		return nil, fmt.Errorf("auth config is nil")
	}

	if len(cfg.OIDC) == 0 {
		return nil, fmt.Errorf("no OIDC issuers configured")
	}

	// Convert Gibson config to DaemonOIDCValidator IssuerConfig format
	issuers := make([]IssuerConfig, len(cfg.OIDC))
	issuerConfigs := make(map[string]*OIDCIssuerConfig)

	for i := range cfg.OIDC {
		gibsonIssuer := &cfg.OIDC[i]
		if gibsonIssuer.Issuer == "" {
			return nil, fmt.Errorf("OIDC issuer URL cannot be empty")
		}

		issuers[i] = IssuerConfig{
			Issuer:        gibsonIssuer.Issuer,
			Audience:      gibsonIssuer.Audience,
			JWKSEndpoint:  gibsonIssuer.JWKSEndpoint,
			JWKSTTL:       gibsonIssuer.JWKSTTL,
			ClaimsMapping: gibsonIssuer.ClaimsMapping,
			RoleBindings:  gibsonIssuer.RoleBindings,
		}

		issuerConfigs[gibsonIssuer.Issuer] = gibsonIssuer
	}

	// Create daemon OIDC validator (uses proper OIDC discovery)
	validator, err := NewDaemonOIDCValidator(issuers, cfg.ClockSkew)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC validator: %w", err)
	}

	// Aggregate all role bindings from all issuers
	allRoleBindings := make(map[string][]string)
	for _, issuerCfg := range cfg.OIDC {
		for pattern, roles := range issuerCfg.RoleBindings {
			allRoleBindings[pattern] = roles
		}
	}

	roleBinder := NewRoleBinderFromConfig(allRoleBindings)

	return &OIDCValidator{
		validator:     validator,
		issuerConfigs: issuerConfigs,
		roleBinder:    roleBinder,
	}, nil
}

// SetEnforcer attaches a Casbin enforcer to the validator.
//
// When set, Authenticate will sync the role-derived capabilities for each
// authenticated identity into Casbin as policies, using an upsert pattern
// (remove all existing policies for the subject, then add the new set).
//
// This method is safe to call before the validator is used concurrently,
// but must not be called after Authenticate has started being called on
// multiple goroutines.
func (v *OIDCValidator) SetEnforcer(e *casbin.Enforcer) {
	v.enforcer = e
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

	// Validate token using daemon's OIDC validator (proper discovery)
	sdkIdentity, err := v.validator.Validate(ctx, tokenString)
	if err != nil {
		issuer = "unknown"
		if sdkIdentity != nil {
			issuer = sdkIdentity.Issuer
		}
		recordAuthAttempt(ctx, issuer, "failure")
		return nil, err
	}

	issuer = sdkIdentity.Issuer
	recordAuthAttempt(ctx, issuer, "success")

	// Build Gibson Identity with SDK Identity embedded
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

	// Resolve capabilities from roles using the roleCapabilities map.
	//
	// If any role grants the wildcard "*", short-circuit and grant full access.
	// Otherwise collect and deduplicate all capabilities across all roles.
	caps := resolveCapabilitiesFromRoles(gibsonIdentity.Roles)
	gibsonIdentity.Capabilities = caps

	// Sync capabilities into Casbin if an enforcer is configured.
	if v.enforcer != nil {
		v.syncCasbin(ctx, gibsonIdentity, caps)
	}

	return gibsonIdentity, nil
}

// syncCasbin performs an upsert of the identity's capabilities into Casbin.
//
// The tenant is extracted from the "tenant_id" claim in the token. If the claim
// is absent, Casbin sync is skipped with a warning — the tenant may be injected
// later in the request pipeline by a higher-level interceptor.
//
// Errors from Casbin are logged but do not fail authentication.
func (v *OIDCValidator) syncCasbin(ctx context.Context, identity *Identity, caps []string) {
	if len(caps) == 0 {
		return
	}

	tenantID := identity.Identity.GetStringClaim("tenant_id")
	if tenantID == "" {
		slog.WarnContext(ctx, "oidc: skipping casbin sync — tenant_id claim absent",
			"subject", identity.Subject,
			"issuer", identity.Issuer,
		)
		return
	}

	// Upsert: remove stale policies first, then add the current set.
	if err := RemovePoliciesForKey(v.enforcer, identity.Subject); err != nil {
		slog.ErrorContext(ctx, "oidc: failed to remove stale casbin policies",
			"subject", identity.Subject,
			"tenant_id", tenantID,
			"error", err,
		)
		// Continue — adding policies is still worthwhile even if removal fails.
	}

	if err := AddPoliciesForKey(v.enforcer, identity.Subject, tenantID, caps); err != nil {
		slog.ErrorContext(ctx, "oidc: failed to add casbin policies",
			"subject", identity.Subject,
			"tenant_id", tenantID,
			"error", err,
		)
	}
}
