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
// Initializes enabled authenticators in priority order:
//  1. OIDC (if any issuers configured)
//  2. Kubernetes (if enabled)
//  3. Local (if configured)
//
// Returns an error if no authenticators are configured.
func NewCompositeAuthenticator(cfg *AuthConfig) (*CompositeAuthenticator, error) {
	if cfg == nil {
		return nil, fmt.Errorf("auth config is nil")
	}

	var authenticators []authenticatorEntry

	// 1. Add OIDC validator if issuers configured
	if len(cfg.OIDC) > 0 {
		oidcValidator, err := NewOIDCValidator(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create OIDC validator: %w", err)
		}
		authenticators = append(authenticators, authenticatorEntry{
			name:          "oidc",
			authenticator: oidcValidator,
		})
	}

	// 2. Add K8s validator if enabled
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

	// 3. Add local validator if configured
	if cfg.Local != nil && len(cfg.Local.Users) > 0 {
		localValidator, err := NewLocalValidator(cfg.Local)
		if err != nil {
			return nil, fmt.Errorf("failed to create local validator: %w", err)
		}
		authenticators = append(authenticators, authenticatorEntry{
			name:          "local",
			authenticator: localValidator,
		})
	}

	if len(authenticators) == 0 {
		return nil, fmt.Errorf("no authenticators configured (no OIDC issuers, K8s disabled, no local users)")
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
