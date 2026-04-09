package auth

import (
	"context"
	"fmt"
	"time"
)

// OIDCValidator validates OIDC JWT tokens from configured issuers.
//
// Uses the daemon's own DaemonOIDCValidator for OIDC token validation
// (with proper OIDC discovery for JWKS endpoints), and adds Gibson-specific:
//   - Role binding resolution from groups (via operator-supplied helm config)
//   - Authentication metrics recording
//
// Authorization is handled by the RPCAuthzInterceptor via permissions.yaml;
// this validator is only responsible for authenticating the caller.
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

	// Capabilities are not derived from roles anymore — the
	// declarative-rbac-framework interceptor authorizes via Casbin using
	// roles loaded from permissions.yaml at startup. Handlers that still
	// perform data-scoping on Capabilities read from Identity.Capabilities
	// directly (API keys populate this field; OIDC identities leave it empty).
	gibsonIdentity.Capabilities = nil

	// Extract tenant memberships from the JWT.
	// Prefer the "organizations" claim (Keycloak Organization Membership Mapper,
	// added by authz-02) over the legacy "tenant_id" claim. After the
	// Organizations migration completes (authz-07), the legacy claim extraction
	// will be removed.
	gibsonIdentity.Tenants = extractOrganizationsClaim(sdkIdentity.Claims)
	if gibsonIdentity.Tenants == nil {
		// Fall back to legacy tenant_id claim for pre-migration users.
		if tenantID, _ := sdkIdentity.Claims["tenant_id"].(string); tenantID != "" {
			gibsonIdentity.Tenants = []string{tenantID}
		}
	}

	return gibsonIdentity, nil
}

// extractOrganizationsClaim parses the "organizations" claim from JWT claims.
//
// Keycloak's Organization Membership Mapper sets this claim as a JSON array
// of organization aliases (e.g. ["zero-day-ai", "acme-corp"]). This function
// handles all forms the claim may take:
//   - Missing: returns nil (no organizations claim present)
//   - []interface{}: normal JSON array — extract string elements
//   - []string: already typed — return a copy
//   - string: single-value form — wrap in slice
//   - anything else: returns nil with a debug log
//
// A nil return means the claim was absent. An empty non-nil slice means the
// claim was present but the user belongs to zero organizations.
func extractOrganizationsClaim(claims map[string]any) []string {
	raw, ok := claims["organizations"]
	if !ok {
		return nil
	}

	switch v := raw.(type) {
	case []interface{}:
		tenants := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				tenants = append(tenants, s)
			}
		}
		return tenants // may be empty but non-nil — claim was present

	case []string:
		result := make([]string, len(v))
		copy(result, v)
		return result

	case string:
		if v == "" {
			return []string{}
		}
		return []string{v}

	default:
		// Claim present but unrecognized type — treat as absent.
		return nil
	}
}
