package auth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkauth "github.com/zero-day-ai/sdk/auth"
)

// TestIntegration_ContextInjection tests identity context injection and extraction.
func TestIntegration_ContextInjection(t *testing.T) {
	ctx := context.Background()

	// Build a synthetic identity directly to test context helpers
	identity := &Identity{
		Identity: sdkauth.Identity{
			Subject:         "context-test",
			Issuer:          "internal",
			Email:           "context@example.com",
			Groups:          []string{"developer"},
			Claims:          map[string]any{},
			ExpiresAt:       time.Now().Add(1 * time.Hour),
			AuthenticatedAt: time.Now(),
		},
		Roles:       []string{},
		Permissions: []Permission{},
	}

	// Inject into context
	ctxWithIdentity := ContextWithIdentity(ctx, identity)

	// Extract from context via SDK helper
	extracted, ok := IdentityFromContext(ctxWithIdentity)
	require.True(t, ok)
	require.NotNil(t, extracted)
	assert.Equal(t, "context-test", extracted.Subject)
	assert.Equal(t, "context@example.com", extracted.Email)

	// Also verify Gibson identity extraction
	gibsonIdentity, ok := GibsonIdentityFromContext(ctxWithIdentity)
	require.True(t, ok)
	require.NotNil(t, gibsonIdentity)
	assert.Equal(t, "context-test", gibsonIdentity.Subject)
}
