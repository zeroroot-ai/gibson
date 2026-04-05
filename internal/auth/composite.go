package auth

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// CompositeAuthenticator tries multiple authentication strategies in order.
//
// This allows Gibson to support multiple authentication methods simultaneously:
//   - API key tokens prefixed with "gsk_" (routed directly, bypasses OIDC/K8s chain)
//   - OIDC tokens from configured providers (Okta, GitHub Actions, GitLab CI)
//   - Kubernetes ServiceAccount tokens via TokenReview API
//   - Local static tokens for development
//
// Authentication routing:
//   - Tokens starting with "gsk_" are routed directly to the APIKeyAuthenticator
//     (if configured). No fallback to the OIDC/K8s chain occurs on failure.
//   - All other tokens are tried in order: OIDC → K8s → Local.
//
// The first successful authentication wins and returns the Identity.
// If all applicable authenticators fail, returns an error aggregating all failure reasons.
//
// Implements the Authenticator interface.
// Thread-safe for concurrent use.
type CompositeAuthenticator struct {
	authenticators []authenticatorEntry

	// apiKey is the optional API key authenticator for "gsk_"-prefixed tokens.
	// When non-nil, tokens starting with "gsk_" are routed exclusively to this
	// authenticator and never fall through to the OIDC/K8s chain.
	apiKey *APIKeyAuthenticator
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
//   - "dev": Only local static token authenticator
//   - "enterprise": API key (if provided) + OIDC + Kubernetes (if enabled)
//   - "saas": API key (if provided) + OIDC only
//
// The optional apiKeyAuthenticator parameter wires in API key support for
// "enterprise" and "saas" modes. Pass nil to omit API key authentication.
// In "dev" mode the apiKeyAuthenticator is ignored even if provided.
//
// Token routing:
//   - Tokens with "gsk_" prefix are routed exclusively to the API key authenticator.
//   - All other tokens fall through the OIDC → K8s → Local chain.
//
// Authenticators in the fallback chain are tried in priority order:
//  1. OIDC (if configured for the mode)
//  2. Kubernetes (if configured for the mode)
//  3. Local (if configured for the mode)
//
// Returns an error if configuration is invalid for the specified mode.
func NewCompositeAuthenticator(cfg *AuthConfig, apiKeyAuthenticator *APIKeyAuthenticator) (*CompositeAuthenticator, error) {
	if cfg == nil {
		return nil, fmt.Errorf("auth config is nil")
	}

	// Apply defaults to ensure mode is set
	cfg.ApplyDefaults()

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid auth config: %w", err)
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
		// Enterprise mode: OIDC + auto-detected Kubernetes SA
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

		// 2. Auto-detect K8s SA auth — works when running in K8s, silently
		// skipped when running outside K8s (local dev, Docker).
		k8sValidator, err := NewK8sValidator(cfg.Kubernetes)
		if err != nil {
			slog.Warn("K8s SA auth unavailable, skipping — components must use API keys or OIDC",
				"error", err)
		} else {
			authenticators = append(authenticators, authenticatorEntry{
				name:          "kubernetes",
				authenticator: k8sValidator,
			})
		}

	case "saas":
		// SaaS mode: OIDC + auto-detected Kubernetes SA
		if len(cfg.OIDC) == 0 {
			return nil, fmt.Errorf("saas mode requires at least one OIDC issuer")
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

		// 2. Auto-detect K8s SA auth (same as enterprise)
		k8sValidator, err := NewK8sValidator(cfg.Kubernetes)
		if err != nil {
			slog.Warn("K8s SA auth unavailable, skipping", "error", err)
		} else {
			authenticators = append(authenticators, authenticatorEntry{
				name:          "kubernetes",
				authenticator: k8sValidator,
			})
		}

	default:
		return nil, fmt.Errorf("unsupported auth mode: %s (must be: dev, enterprise, saas)", cfg.Mode)
	}

	if len(authenticators) == 0 {
		return nil, fmt.Errorf("no authenticators configured for mode %q", cfg.Mode)
	}

	composite := &CompositeAuthenticator{
		authenticators: authenticators,
	}

	// Wire in API key authenticator for enterprise and saas modes.
	// Dev mode does not support API key authentication.
	if apiKeyAuthenticator != nil && (cfg.Mode == "enterprise" || cfg.Mode == "saas") {
		composite.apiKey = apiKeyAuthenticator
	}

	return composite, nil
}

// Authenticate tries each authenticator in order until one succeeds.
//
// Routing:
//   - Tokens starting with "gsk_" are routed exclusively to the API key
//     authenticator. If no API key authenticator is configured, these tokens
//     are rejected immediately without falling through to OIDC/K8s.
//   - All other tokens are tried against the OIDC → K8s → Local chain.
//
// Returns the Identity from the first successful authenticator.
// Returns an error aggregating all failures if all authenticators fail.
func (c *CompositeAuthenticator) Authenticate(ctx context.Context, token string) (*Identity, error) {
	if token == "" {
		return nil, ErrMissingToken()
	}

	// Route "gsk_"-prefixed tokens exclusively to the API key authenticator.
	// These tokens must never fall through to the OIDC/K8s chain — a gsk_ token
	// that fails API key auth is always an auth failure, not an OIDC token.
	if strings.HasPrefix(token, apiKeyPrefix+"_") {
		if c.apiKey == nil {
			return nil, ErrInvalidToken(fmt.Errorf("API key authentication is not configured"))
		}
		return c.apiKey.Authenticate(ctx, token)
	}

	// Track errors from each authenticator in the fallback chain
	var errors []string

	// Try each authenticator in order: OIDC → K8s → Local
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

// GetOIDCValidator returns the OIDC validator if configured, or nil otherwise.
//
// This is primarily intended for testing to allow setting custom HTTP clients
// for JWKS fetching from test servers.
func (c *CompositeAuthenticator) GetOIDCValidator() *OIDCValidator {
	for _, entry := range c.authenticators {
		if entry.name == "oidc" {
			if validator, ok := entry.authenticator.(*OIDCValidator); ok {
				return validator
			}
		}
	}
	return nil
}

// HasAPIKey returns true if API key authentication is configured.
//
// When true, tokens starting with "gsk_" will be routed to the API key
// authenticator rather than the OIDC/K8s chain.
func (c *CompositeAuthenticator) HasAPIKey() bool {
	return c.apiKey != nil
}

// GetAPIKeyAuthenticator returns the API key authenticator if configured, or nil otherwise.
//
// This is primarily intended for use by management APIs (CreateKey, RevokeKey,
// ListKeys) that need direct access to the authenticator beyond token validation.
func (c *CompositeAuthenticator) GetAPIKeyAuthenticator() *APIKeyAuthenticator {
	return c.apiKey
}
