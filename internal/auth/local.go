package auth

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"time"
)

// LocalValidator validates static tokens for local development.
//
// WARNING: This validator is for development only and should NEVER be used
// in production. Tokens are stored in plaintext configuration and compared
// using constant-time comparison to prevent timing attacks.
//
// Implements the Authenticator interface.
// Thread-safe for concurrent use.
type LocalValidator struct {
	users map[string]*localUserEntry
}

// localUserEntry stores a configured local user's credentials.
type localUserEntry struct {
	name  string
	token string
	roles []string
}

// NewLocalValidator creates a new local token validator.
//
// Logs a warning when initialized to alert operators that this is
// a development-only authentication method.
//
// Returns an error if configuration is invalid.
func NewLocalValidator(cfg *LocalAuthConfig) (*LocalValidator, error) {
	if cfg == nil {
		return nil, fmt.Errorf("local auth config is nil")
	}

	if len(cfg.Users) == 0 {
		return nil, fmt.Errorf("local auth config has no users defined")
	}

	// Build token lookup map
	users := make(map[string]*localUserEntry, len(cfg.Users))
	for i := range cfg.Users {
		user := &cfg.Users[i]

		if user.Token == "" {
			slog.Warn("local auth user has empty token, skipping", "name", user.Name)
			continue
		}

		if user.Name == "" {
			slog.Warn("local auth user has empty name, skipping", "token_prefix", user.Token[:min(8, len(user.Token))])
			continue
		}

		users[user.Token] = &localUserEntry{
			name:  user.Name,
			token: user.Token,
			roles: user.Roles,
		}
	}

	if len(users) == 0 {
		return nil, fmt.Errorf("local auth config has no valid users after filtering")
	}

	// Log warning about development-only use
	slog.Warn("local auth validator initialized - DEVELOPMENT ONLY, DO NOT USE IN PRODUCTION",
		"user_count", len(users),
	)

	return &LocalValidator{
		users: users,
	}, nil
}

// Authenticate validates a static token and returns the associated identity.
//
// Uses constant-time comparison to prevent timing attacks even in dev mode.
//
// Process:
//  1. Look up token in configured users (constant-time comparison)
//  2. Build Identity with configured roles
//  3. Compute permissions from roles
//
// Returns Identity if token matches, error otherwise.
func (v *LocalValidator) Authenticate(ctx context.Context, token string) (*Identity, error) {
	startTime := time.Now()
	defer func() {
		latencyMs := float64(time.Since(startTime).Milliseconds())
		recordAuthLatency(ctx, "local", latencyMs)
	}()

	if token == "" {
		recordAuthAttempt(ctx, "local", "error")
		return nil, ErrMissingToken()
	}

	// Look up user by token using constant-time comparison
	// This prevents timing attacks even in development mode
	var matchedUser *localUserEntry
	for userToken, user := range v.users {
		if constantTimeCompare(token, userToken) {
			matchedUser = user
			break
		}
	}

	if matchedUser == nil {
		recordAuthAttempt(ctx, "local", "failure")
		return nil, ErrInvalidToken(fmt.Errorf("token does not match any configured local user"))
	}

	// Build claims
	claims := map[string]any{
		"name":           matchedUser.name,
		"authentication": "local",
		"warning":        "development_only",
	}

	// Compute permissions from roles
	roleBinder := NewRoleBinder(nil) // No role bindings - roles come from config
	permissions := roleBinder.computePermissions(matchedUser.roles)

	// Build identity
	identity := &Identity{
		Subject:         matchedUser.name,
		Issuer:          "local",
		Email:           "", // Local users don't have emails
		Groups:          []string{},
		Claims:          claims,
		Roles:           matchedUser.roles,
		Permissions:     permissions,
		ExpiresAt:       time.Now().Add(24 * time.Hour), // Static tokens don't expire
		AuthenticatedAt: time.Now(),
	}

	slog.Debug("local auth: authenticated user",
		"name", matchedUser.name,
		"roles", matchedUser.roles,
	)

	recordAuthAttempt(ctx, "local", "success")
	return identity, nil
}

// constantTimeCompare performs constant-time string comparison.
//
// Uses subtle.ConstantTimeCompare to prevent timing attacks.
// Returns true if strings are equal, false otherwise.
func constantTimeCompare(a, b string) bool {
	// Convert strings to byte slices for comparison
	aBytes := []byte(a)
	bBytes := []byte(b)

	// If lengths differ, still perform comparison on equal-length slices
	// to maintain constant time behavior
	if len(aBytes) != len(bBytes) {
		return false
	}

	return subtle.ConstantTimeCompare(aBytes, bBytes) == 1
}

// min returns the minimum of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
