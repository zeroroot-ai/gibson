package auth

import (
	"context"
	"fmt"
	"strings"
)

// CompositeAuthenticator tries multiple authentication strategies in order.
//
// This allows Gibson to support multiple authentication methods simultaneously:
//   - OIDC tokens from configured providers (Okta, GitHub Actions, GitLab CI)
//   - Kubernetes ServiceAccount tokens via TokenReview API
//   - Local static tokens for development
//
// Authentication is attempted in the order: OIDC → K8s → Local.
// The first successful authentication wins and returns the Identity.
//
// If all authenticators fail, returns an error aggregating all failure reasons.
//
// Implements the Authenticator interface.
// Thread-safe for concurrent use.
type CompositeAuthenticator struct {
	authenticators []authenticatorEntry
}

// authenticatorEntry wraps an authenticator with metadata.
type authenticatorEntry struct {
	name          string
	authenticator Authenticator
}

// NewCompositeAuthenticator creates a composite authenticator from configuration.
//
// Initializes authenticators based on the configured auth mode:
//
//   - "disabled": Returns nil (caller should skip authentication entirely)
//   - "dev": Only local static token authenticator
//   - "enterprise": OIDC + Kubernetes (if enabled)
//   - "saas": OIDC only (Kubernetes not typical for SaaS deployments)
//
// Authenticators are tried in priority order:
//  1. OIDC (if configured for the mode)
//  2. Kubernetes (if configured for the mode)
//  3. Local (if configured for the mode)
//
// Returns nil authenticator for "disabled" mode - caller should handle this case.
// Returns an error if configuration is invalid for the specified mode.
func NewCompositeAuthenticator(cfg *AuthConfig) (*CompositeAuthenticator, error) {
	if cfg == nil {
		return nil, fmt.Errorf("auth config is nil")
	}

	// Apply defaults to ensure mode is set
	cfg.ApplyDefaults()

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid auth config: %w", err)
	}

	// For disabled mode, return nil - caller should skip authentication entirely
	if cfg.Mode == "disabled" {
		return nil, nil
	}

	var authenticators []authenticatorEntry

	// Configure authenticators based on mode
	switch cfg.Mode {
	case "dev":
		// Dev mode: Only local static tokens
		if cfg.Local == nil || len(cfg.Local.Users) == 0 {
			return nil, fmt.Errorf("dev mode requires local.users configuration")
		}
		localValidator, err := NewLocalValidator(cfg.Local)
		if err != nil {
			return nil, fmt.Errorf("failed to create local validator: %w", err)
		}
		authenticators = append(authenticators, authenticatorEntry{
			name:          "local",
			authenticator: localValidator,
		})

	case "enterprise":
		// Enterprise mode: OIDC + optional Kubernetes
		if len(cfg.OIDC) == 0 {
			return nil, fmt.Errorf("enterprise mode requires at least one OIDC issuer")
		}

		// 1. Add OIDC validator
		oidcValidator, err := NewOIDCValidator(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create OIDC validator: %w", err)
		}
		authenticators = append(authenticators, authenticatorEntry{
			name:          "oidc",
			authenticator: oidcValidator,
		})

		// 2. Add K8s validator if enabled (optional in enterprise mode)
		if cfg.Kubernetes != nil && cfg.Kubernetes.Enabled {
			k8sValidator, err := NewK8sValidator(cfg.Kubernetes)
			if err != nil {
				return nil, fmt.Errorf("failed to create k8s validator: %w", err)
			}
			authenticators = append(authenticators, authenticatorEntry{
				name:          "kubernetes",
				authenticator: k8sValidator,
			})
		}

	case "saas":
		// SaaS mode: OIDC only (Kubernetes not typical for SaaS)
		if len(cfg.OIDC) == 0 {
			return nil, fmt.Errorf("saas mode requires at least one OIDC issuer")
		}

		// Add OIDC validator only
		oidcValidator, err := NewOIDCValidator(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create OIDC validator: %w", err)
		}
		authenticators = append(authenticators, authenticatorEntry{
			name:          "oidc",
			authenticator: oidcValidator,
		})

	default:
		return nil, fmt.Errorf("unsupported auth mode: %s (must be: disabled, dev, enterprise, saas)", cfg.Mode)
	}

	if len(authenticators) == 0 {
		return nil, fmt.Errorf("no authenticators configured for mode %q", cfg.Mode)
	}

	return &CompositeAuthenticator{
		authenticators: authenticators,
	}, nil
}

// Authenticate tries each authenticator in order until one succeeds.
//
// Process:
//  1. Try OIDC authentication first (if configured)
//  2. Try Kubernetes TokenReview (if enabled)
//  3. Try local static token (if configured)
//  4. If all fail, return composite error
//
// Returns the Identity from the first successful authenticator.
// Returns an error aggregating all failures if all authenticators fail.
func (c *CompositeAuthenticator) Authenticate(ctx context.Context, token string) (*Identity, error) {
	if token == "" {
		return nil, ErrMissingToken()
	}

	// Track errors from each authenticator
	var errors []string

	// Try each authenticator in order
	for _, entry := range c.authenticators {
		identity, err := entry.authenticator.Authenticate(ctx, token)
		if err == nil {
			// Success! Return the identity
			return identity, nil
		}

		// Authentication failed - record error and try next authenticator
		errors = append(errors, fmt.Sprintf("%s: %v", entry.name, err))
	}

	// All authenticators failed - return composite error
	return nil, &AuthError{
		Code:    ErrInvalidToken(nil).(*AuthError).Code,
		Message: fmt.Sprintf("all authenticators failed: %s", strings.Join(errors, "; ")),
		Reason:  "all_authenticators_failed",
	}
}

// GetAuthenticatorNames returns the names of configured authenticators in order.
//
// Useful for debugging and logging configuration.
func (c *CompositeAuthenticator) GetAuthenticatorNames() []string {
	names := make([]string, len(c.authenticators))
	for i, entry := range c.authenticators {
		names[i] = entry.name
	}
	return names
}

// HasOIDC returns true if OIDC authentication is configured.
func (c *CompositeAuthenticator) HasOIDC() bool {
	for _, entry := range c.authenticators {
		if entry.name == "oidc" {
			return true
		}
	}
	return false
}

// HasKubernetes returns true if Kubernetes authentication is configured.
func (c *CompositeAuthenticator) HasKubernetes() bool {
	for _, entry := range c.authenticators {
		if entry.name == "kubernetes" {
			return true
		}
	}
	return false
}

// HasLocal returns true if local authentication is configured.
func (c *CompositeAuthenticator) HasLocal() bool {
	for _, entry := range c.authenticators {
		if entry.name == "local" {
			return true
		}
	}
	return false
}
