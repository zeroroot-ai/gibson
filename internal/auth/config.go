package auth

import (
	"fmt"
	"time"
)

// BetterAuthConfig holds configuration for the Better Auth session token validator.
//
// The Secret is the shared BETTER_AUTH_SECRET that was used to sign session tokens
// in the dashboard's Better Auth server. It must match exactly.
//
// When Enabled is false the BetterAuthValidator is not added to the authenticator
// chain even if Secret is set.
type BetterAuthConfig struct {
	// Enabled controls whether Better Auth session token validation is active.
	// Default: false
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`

	// Secret is the HMAC-SHA256 signing secret shared between the dashboard
	// Better Auth server and the daemon.
	// Override: BETTER_AUTH_SECRET env var is handled in the loader.
	Secret string `mapstructure:"secret" yaml:"secret"`
}

// AuthConfig contains authentication and authorization configuration.
//
// This configuration is loaded from gibson.yaml and supports multiple
// deployment models through the Mode field:
//   - "dev": API key / K8s SA / Better Auth / Agent Auth JWT
//   - "enterprise": API key / K8s SA / Better Auth / Agent Auth JWT
//   - "saas": API key / K8s SA / Better Auth / Agent Auth JWT
//
// The 4-path interceptor (Task 10) handles routing between these methods.
type AuthConfig struct {
	// Mode specifies the authentication deployment model.
	// Valid values: "dev", "enterprise", "saas"
	// Required: auth mode must be explicitly configured.
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
	// Default: false
	TrustLocalhost bool `mapstructure:"trust_localhost" yaml:"trust_localhost"`

	// ClockSkew is the maximum allowed time difference when validating token expiry.
	// Accommodates clock drift between Gibson and identity providers.
	// Default: 30s
	ClockSkew time.Duration `mapstructure:"clock_skew" yaml:"clock_skew"`

	// Kubernetes enables validation of Kubernetes ServiceAccount tokens.
	// Used for in-cluster workloads (ArgoCD, Tekton, etc).
	// Optional - only enabled when configured.
	Kubernetes *K8sAuthConfig `mapstructure:"kubernetes" yaml:"kubernetes,omitempty"`

	// BetterAuth configures HMAC-SHA256 session token validation for Better Auth
	// sessions issued by the dashboard.
	// Optional — omit when not using the dashboard's Better Auth integration.
	BetterAuth BetterAuthConfig `mapstructure:"better_auth" yaml:"better_auth,omitempty"`

	// AutoProvisionTenants controls whether new tenants are automatically created
	// when a token contains a tenant claim value that doesn't match any existing tenant.
	// Default: true for "enterprise" mode, false for "saas" mode.
	AutoProvisionTenants *bool `mapstructure:"auto_provision_tenants" yaml:"auto_provision_tenants,omitempty"`
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

// IsAuthEnabled returns true if authentication should be enforced.
// Auth is always enabled when a valid mode is configured.
// The deprecated Enabled field is checked as a fallback when Mode is empty.
func (c *AuthConfig) IsAuthEnabled() bool {
	if c.Mode != "" {
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
// Note: Mode is NOT defaulted — it must be explicitly configured.
// An empty mode will cause Validate() to return an error.
func (c *AuthConfig) ApplyDefaults() {
	// Default tenant claim name
	if c.TenantClaim == "" {
		c.TenantClaim = "tenant_id"
	}

	// Default clock skew tolerance
	if c.ClockSkew == 0 {
		c.ClockSkew = 30 * time.Second
	}
}

// Validate checks that the configuration is valid.
// Returns an error if the Mode value is empty or not one of the valid values.
func (c *AuthConfig) Validate() error {
	if c.Mode == "" {
		return fmt.Errorf("auth mode is required (must be one of: dev, enterprise, saas)")
	}

	validModes := map[string]bool{
		"dev":        true,
		"enterprise": true,
		"saas":       true,
	}

	if !validModes[c.Mode] {
		return fmt.Errorf("invalid auth mode %q: must be one of: dev, enterprise, saas", c.Mode)
	}

	return nil
}
