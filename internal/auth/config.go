package auth

import (
	"fmt"
	"time"
)

// AuthConfig contains authentication and authorization configuration.
//
// This configuration is loaded from gibson.yaml and supports multiple
// deployment models through the Mode field:
//   - "disabled": No authentication (default for backward compatibility)
//   - "dev": Static tokens for testing
//   - "enterprise": OIDC validation with config-based RBAC, single or multi-team
//   - "saas": OIDC + tenant isolation + database-based RBAC
type AuthConfig struct {
	// Mode specifies the authentication deployment model.
	// Valid values:
	//   - "disabled": No authentication, all requests allowed (default)
	//   - "dev": Static tokens for local development
	//   - "enterprise": Customer IdP (Okta, Azure AD, Keycloak) with OIDC validation
	//   - "saas": Multi-tenant with tenant isolation via claims
	// Default: "disabled"
	Mode string `mapstructure:"mode" yaml:"mode"`

	// TenantClaim is the JWT claim name to extract the tenant ID from.
	// Used in "saas" and "enterprise" modes for tenant isolation.
	// Common values: "tenant_id", "org_id", "organization"
	// Supports dot notation for nested claims: "custom.tenant.id"
	// Default: "tenant_id"
	TenantClaim string `mapstructure:"tenant_claim" yaml:"tenant_claim"`

	// DefaultTenant is the fallback tenant ID when no tenant claim is present.
	// Used in "enterprise" mode for single-tenant deployments.
	// In "saas" mode, missing tenant claims result in authentication failure.
	// Optional - no default value
	DefaultTenant string `mapstructure:"default_tenant" yaml:"default_tenant"`

	// Enabled is deprecated. Use Mode instead.
	// Ignored when Mode is set. Removed in a future release.
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`

	// TrustLocalhost skips authentication for connections from 127.0.0.1 or ::1.
	// Useful for local development with external tools.
	// Only applies when Mode is not "disabled".
	// Default: false
	TrustLocalhost bool `mapstructure:"trust_localhost" yaml:"trust_localhost"`

	// ClockSkew is the maximum allowed time difference when validating token expiry.
	// Accommodates clock drift between Gibson and identity providers.
	// Default: 30s
	ClockSkew time.Duration `mapstructure:"clock_skew" yaml:"clock_skew"`

	// OIDC contains OpenID Connect provider configurations.
	// Multiple providers can be configured for federation (Okta, GitHub Actions, GitLab CI).
	// Tokens are matched to providers by their issuer claim.
	// Required for "enterprise" and "saas" modes.
	OIDC []OIDCIssuerConfig `mapstructure:"oidc" yaml:"oidc"`

	// Kubernetes enables validation of Kubernetes ServiceAccount tokens.
	// Used for in-cluster workloads (ArgoCD, Tekton, etc).
	// Optional - only enabled when configured.
	Kubernetes *K8sAuthConfig `mapstructure:"kubernetes" yaml:"kubernetes,omitempty"`

	// Local enables static token authentication for local development.
	// Required for "dev" mode, ignored in other modes.
	// NOT FOR PRODUCTION - tokens are stored in plaintext config.
	// Optional - only enabled when configured.
	Local *LocalAuthConfig `mapstructure:"local" yaml:"local,omitempty"`

	// AutoProvisionTenants controls whether new tenants are automatically created
	// when an OIDC token contains a tenant claim value that doesn't match any existing tenant.
	// Default: true for "enterprise" mode, false for "saas" mode.
	AutoProvisionTenants *bool `mapstructure:"auto_provision_tenants" yaml:"auto_provision_tenants,omitempty"`
}

// OIDCIssuerConfig configures an OpenID Connect identity provider.
//
// Each issuer represents a trusted OIDC provider (Okta, Auth0, GitHub Actions, etc).
// Tokens from the issuer are validated using JWKS endpoint public keys.
type OIDCIssuerConfig struct {
	// Issuer is the OIDC issuer URL (must match token's iss claim).
	// Examples: "https://company.okta.com", "https://token.actions.githubusercontent.com"
	// Required
	Issuer string `mapstructure:"issuer" yaml:"issuer" validate:"required,url"`

	// Audience is the expected audience value (aud claim).
	// Tokens without matching audience are rejected.
	// Examples: "gibson-prod", "sts.amazonaws.com"
	// Optional - if empty, audience is not validated.
	Audience string `mapstructure:"audience" yaml:"audience"`

	// JWKSEndpoint overrides automatic JWKS discovery.
	// By default, Gibson fetches JWKS from {issuer}/.well-known/jwks.json
	// Only needed for non-standard OIDC implementations.
	// Optional
	JWKSEndpoint string `mapstructure:"jwks_endpoint" yaml:"jwks_endpoint,omitempty"`

	// JWKSTTL is how long to cache JWKS responses before refreshing.
	// Reduces load on identity provider and improves auth performance.
	// Default: 1h
	JWKSTTL time.Duration `mapstructure:"jwks_ttl" yaml:"jwks_ttl"`

	// ClaimsMapping maps token claim names to Identity fields.
	// Allows normalization of provider-specific claim names.
	// Examples:
	//   {"groups": "groups"} - standard OIDC groups claim
	//   {"repository": "repo", "ref": "branch"} - GitHub Actions claims
	//   {"project_path": "project"} - GitLab CI claims
	// Optional - defaults to standard OIDC claim names
	ClaimsMapping map[string]string `mapstructure:"claims_mapping" yaml:"claims_mapping,omitempty"`

	// RoleBindings maps claim values to Gibson roles.
	// Keys are claim values (or patterns), values are lists of role names.
	// Examples:
	//   {"security-admins": ["admin"]} - group to role
	//   {"myorg/infra:refs/heads/main": ["mission:execute"]} - repo/branch to role
	// Supports wildcard matching in keys.
	RoleBindings map[string][]string `mapstructure:"role_bindings" yaml:"role_bindings,omitempty"`
}

// K8sAuthConfig configures Kubernetes ServiceAccount token validation.
//
// Uses the Kubernetes TokenReview API to validate tokens issued by
// the Kubernetes API server. Requires access to the K8s API.
type K8sAuthConfig struct {
	// Enabled controls whether K8s token validation is active.
	// Default: false
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`

	// RoleBindings maps service account identities to Gibson roles.
	// Keys are in format "namespace:serviceaccount" (supports wildcards).
	// Examples:
	//   {"ci-cd:security-scanner": ["mission:execute"]}
	//   {"ci-cd:*": ["findings:read"]} - all SAs in ci-cd namespace
	//   {"*:admin": ["admin"]} - admin SA in any namespace
	RoleBindings map[string][]string `mapstructure:"role_bindings" yaml:"role_bindings,omitempty"`

	// KubeconfigPath overrides automatic in-cluster config detection.
	// Useful for out-of-cluster testing.
	// Optional - defaults to in-cluster config when running in K8s.
	KubeconfigPath string `mapstructure:"kubeconfig_path" yaml:"kubeconfig_path,omitempty"`
}

// LocalAuthConfig enables static token authentication for development.
//
// WARNING: This stores tokens in plaintext configuration.
// NEVER use in production - for local development only.
type LocalAuthConfig struct {
	// Users defines static token-to-identity mappings.
	Users []LocalUser `mapstructure:"users" yaml:"users"`
}

// LocalUser represents a static token identity for local development.
type LocalUser struct {
	// Name is a human-readable identifier for this user.
	Name string `mapstructure:"name" yaml:"name"`

	// Token is the bearer token value to match.
	// WARNING: Stored in plaintext - development only!
	Token string `mapstructure:"token" yaml:"token"`

	// Roles are the Gibson roles granted to this token.
	Roles []string `mapstructure:"roles" yaml:"roles"`
}

// IsAuthEnabled returns true if authentication should be enforced.
// Mode is the source of truth. The deprecated Enabled field is only
// checked as a fallback when Mode is empty or "disabled".
func (c *AuthConfig) IsAuthEnabled() bool {
	if c.Mode != "" && c.Mode != "disabled" {
		return true
	}
	return c.Enabled
}

// ShouldAutoProvision returns whether auto-provisioning is enabled for the current mode.
// When AutoProvisionTenants is set explicitly it takes precedence over the mode default.
// The mode defaults are: enterprise=true, saas=false.
func (c *AuthConfig) ShouldAutoProvision() bool {
	if c.AutoProvisionTenants != nil {
		return *c.AutoProvisionTenants
	}
	// Default: true for enterprise, false for saas
	return c.Mode == "enterprise"
}

// ApplyDefaults fills in zero-valued fields with sensible defaults.
func (c *AuthConfig) ApplyDefaults() {
	// Default to disabled mode for backward compatibility
	// Users must explicitly configure authentication mode
	if c.Mode == "" {
		c.Mode = "disabled"
	}

	// Default tenant claim name
	if c.TenantClaim == "" {
		c.TenantClaim = "tenant_id"
	}

	// Default clock skew tolerance
	if c.ClockSkew == 0 {
		c.ClockSkew = 30 * time.Second
	}

	// Apply defaults to OIDC issuers
	for i := range c.OIDC {
		if c.OIDC[i].JWKSTTL == 0 {
			c.OIDC[i].JWKSTTL = 1 * time.Hour
		}
	}
}

// Validate checks that the configuration is valid.
// Returns an error if the Mode value is not one of the valid values.
func (c *AuthConfig) Validate() error {
	validModes := map[string]bool{
		"disabled":   true,
		"dev":        true,
		"enterprise": true,
		"saas":       true,
	}

	if !validModes[c.Mode] {
		return fmt.Errorf("invalid auth mode %q: must be one of: disabled, dev, enterprise, saas", c.Mode)
	}

	// Validate mode-specific requirements
	switch c.Mode {
	case "dev":
		if c.Local == nil || len(c.Local.Users) == 0 {
			return fmt.Errorf("auth mode %q requires local.users configuration", c.Mode)
		}
	case "enterprise", "saas":
		if len(c.OIDC) == 0 {
			return fmt.Errorf("auth mode %q requires at least one OIDC issuer", c.Mode)
		}
	}

	return nil
}
