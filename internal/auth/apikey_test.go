package auth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdkauth "github.com/zero-day-ai/sdk/auth"
)

// newTestAuthenticator starts an in-process miniredis instance and returns an
// APIKeyAuthenticator wired to it. The miniredis instance is automatically
// closed when the test ends via t.Cleanup (miniredis.RunT registers its own
// cleanup).
func newTestAuthenticator(t *testing.T) *APIKeyAuthenticator {
	t.Helper()

	mr := miniredis.RunT(t)

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	t.Cleanup(func() { _ = client.Close() })

	auth, err := NewAPIKeyAuthenticator(client)
	require.NoError(t, err)
	require.NotNil(t, auth)

	return auth
}

// TestAPIKeyAuthenticator_CreateAndAuthenticate verifies the basic round-trip:
// create a key, present the raw key to Authenticate, get back a valid Identity.
func TestAPIKeyAuthenticator_CreateAndAuthenticate(t *testing.T) {
	a := newTestAuthenticator(t)
	ctx := context.Background()

	rawKey, record, err := a.CreateKey(ctx, "acme", nil, nil, nil, "", "")
	require.NoError(t, err)
	require.NotEmpty(t, rawKey)
	require.NotNil(t, record)

	identity, err := a.Authenticate(ctx, rawKey)
	require.NoError(t, err)
	require.NotNil(t, identity)

	assert.Equal(t, record.KeyID, identity.Subject)
	assert.Equal(t, apiKeyIssuer, identity.Issuer)
}

// TestAPIKeyAuthenticator_KeyFormat verifies that every generated raw key starts
// with the canonical "gsk_" prefix so log scanners can identify key material.
func TestAPIKeyAuthenticator_KeyFormat(t *testing.T) {
	a := newTestAuthenticator(t)
	ctx := context.Background()

	rawKey, _, err := a.CreateKey(ctx, "acme", nil, nil, nil, "", "")
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(rawKey, "gsk_"),
		"raw key %q must start with \"gsk_\"", rawKey)
}

// TestAPIKeyAuthenticator_InvalidKeyRejected verifies that a random string that
// was never issued returns an authentication error.
func TestAPIKeyAuthenticator_InvalidKeyRejected(t *testing.T) {
	a := newTestAuthenticator(t)
	ctx := context.Background()

	_, err := a.Authenticate(ctx, "gsk_nobody_000000000000000000000000000000000000000000000000000000000000000")
	require.Error(t, err)
	assert.True(t, IsInvalidTokenError(err),
		"expected invalid_token error, got: %v", err)
}

// TestAPIKeyAuthenticator_EmptyTokenRejected verifies that an empty token string
// returns a missing-token error rather than an invalid-token error.
func TestAPIKeyAuthenticator_EmptyTokenRejected(t *testing.T) {
	a := newTestAuthenticator(t)
	ctx := context.Background()

	_, err := a.Authenticate(ctx, "")
	require.Error(t, err)
	assert.True(t, IsMissingTokenError(err),
		"expected missing_token error, got: %v", err)
}

// TestAPIKeyAuthenticator_RevokedKeyRejected verifies the revocation lifecycle:
// create a key, revoke it, then confirm Authenticate refuses the key.
func TestAPIKeyAuthenticator_RevokedKeyRejected(t *testing.T) {
	a := newTestAuthenticator(t)
	ctx := context.Background()

	rawKey, record, err := a.CreateKey(ctx, "acme", nil, nil, nil, "", "")
	require.NoError(t, err)

	// Sanity-check: key works before revocation.
	_, err = a.Authenticate(ctx, rawKey)
	require.NoError(t, err, "key must authenticate before revocation")

	err = a.RevokeKey(ctx, record.KeyID)
	require.NoError(t, err)

	// After revocation the key must be refused.
	_, err = a.Authenticate(ctx, rawKey)
	require.Error(t, err)
	assert.True(t, IsTokenExpiredError(err),
		"expected token_expired error for revoked key, got: %v", err)
}

// TestAPIKeyAuthenticator_RevokeIdempotent verifies that revoking an already-
// revoked key is a no-op that returns nil.
func TestAPIKeyAuthenticator_RevokeIdempotent(t *testing.T) {
	a := newTestAuthenticator(t)
	ctx := context.Background()

	_, record, err := a.CreateKey(ctx, "acme", nil, nil, nil, "", "")
	require.NoError(t, err)

	require.NoError(t, a.RevokeKey(ctx, record.KeyID))
	require.NoError(t, a.RevokeKey(ctx, record.KeyID), "second revoke must be idempotent")
}

// TestAPIKeyAuthenticator_TenantExtraction verifies that the tenant_id claim in
// the returned Identity matches the tenant used during key creation.
func TestAPIKeyAuthenticator_TenantExtraction(t *testing.T) {
	a := newTestAuthenticator(t)
	ctx := context.Background()

	const wantTenant = "acme"

	rawKey, _, err := a.CreateKey(ctx, wantTenant, nil, nil, nil, "", "")
	require.NoError(t, err)

	identity, err := a.Authenticate(ctx, rawKey)
	require.NoError(t, err)

	tenantFromClaim, ok := identity.Claims["tenant_id"].(string)
	require.True(t, ok, "tenant_id claim must be a string")
	assert.Equal(t, wantTenant, tenantFromClaim)

	// Also verify via ExtractTenantFromIdentity, the canonical helper.
	assert.Equal(t, wantTenant, ExtractTenantFromIdentity(identity, "tenant_id"))
}

// TestAPIKeyAuthenticator_AllowedKinds verifies that AllowedKinds specified at
// creation time are persisted faithfully in the stored record.
func TestAPIKeyAuthenticator_AllowedKinds(t *testing.T) {
	a := newTestAuthenticator(t)
	ctx := context.Background()

	wantKinds := []string{"scanner", "recon"}

	_, record, err := a.CreateKey(ctx, "acme", wantKinds, nil, nil, "", "")
	require.NoError(t, err)

	assert.Equal(t, wantKinds, record.AllowedKinds,
		"AllowedKinds must be stored as provided")
}

// TestAPIKeyAuthenticator_AllowedKindsInIdentityClaims verifies that
// AllowedKinds also surface in the Identity claims after authentication.
func TestAPIKeyAuthenticator_AllowedKindsInIdentityClaims(t *testing.T) {
	a := newTestAuthenticator(t)
	ctx := context.Background()

	wantKinds := []string{"scanner", "recon"}

	rawKey, _, err := a.CreateKey(ctx, "acme", wantKinds, nil, nil, "", "")
	require.NoError(t, err)

	identity, err := a.Authenticate(ctx, rawKey)
	require.NoError(t, err)

	got, ok := identity.Claims["allowed_kinds"].([]string)
	require.True(t, ok, "allowed_kinds claim must be a []string")
	assert.Equal(t, wantKinds, got)
}

// TestAPIKeyAuthenticator_NilAllowedKindsDefaultsToEmptySlice verifies that
// passing nil for allowedKinds stores an empty (non-nil) slice in the record.
func TestAPIKeyAuthenticator_NilAllowedKindsDefaultsToEmptySlice(t *testing.T) {
	a := newTestAuthenticator(t)
	ctx := context.Background()

	_, record, err := a.CreateKey(ctx, "acme", nil, nil, nil, "", "")
	require.NoError(t, err)

	assert.NotNil(t, record.AllowedKinds)
	assert.Empty(t, record.AllowedKinds)
}

// TestAPIKeyAuthenticator_LastUsedAtUpdated verifies that Authenticate triggers
// an asynchronous update to the LastUsedAt field.
//
// Because updateLastUsed runs in a fire-and-forget goroutine the test waits up
// to 500 ms for the record to be updated before failing.
func TestAPIKeyAuthenticator_LastUsedAtUpdated(t *testing.T) {
	a := newTestAuthenticator(t)
	ctx := context.Background()

	rawKey, record, err := a.CreateKey(ctx, "acme", nil, nil, nil, "", "")
	require.NoError(t, err)

	createdAt := record.CreatedAt

	// Ensure measurable wall-clock gap between creation and authentication.
	time.Sleep(2 * time.Millisecond)

	_, err = a.Authenticate(ctx, rawKey)
	require.NoError(t, err)

	// Poll until the background goroutine persists LastUsedAt.
	var updatedRecord *APIKeyRecord
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		updatedRecord, err = a.fetchRecord(ctx, record.KeyID)
		require.NoError(t, err)
		if updatedRecord.LastUsedAt.After(createdAt) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	assert.True(t, updatedRecord.LastUsedAt.After(createdAt),
		"LastUsedAt (%v) must be after CreatedAt (%v) following authentication",
		updatedRecord.LastUsedAt, createdAt)
}

// TestAPIKeyAuthenticator_ListKeys verifies that ListKeys returns all keys
// created for a tenant, including both active and revoked keys.
func TestAPIKeyAuthenticator_ListKeys(t *testing.T) {
	a := newTestAuthenticator(t)
	ctx := context.Background()

	const tenant = "acme"

	// Create three keys for the tenant.
	_, rec1, err := a.CreateKey(ctx, tenant, nil, nil, nil, "", "")
	require.NoError(t, err)
	_, rec2, err := a.CreateKey(ctx, tenant, nil, nil, nil, "", "")
	require.NoError(t, err)
	_, rec3, err := a.CreateKey(ctx, tenant, nil, nil, nil, "", "")
	require.NoError(t, err)

	// Revoke the third key.
	require.NoError(t, a.RevokeKey(ctx, rec3.KeyID))

	keys, err := a.ListKeys(ctx, tenant)
	require.NoError(t, err)
	assert.Len(t, keys, 3, "ListKeys must return all three keys for the tenant")

	// Collect key IDs for membership assertions.
	ids := make(map[string]string, len(keys)) // key_id -> status
	for _, k := range keys {
		ids[k.KeyID] = k.Status
	}

	assert.Contains(t, ids, rec1.KeyID)
	assert.Contains(t, ids, rec2.KeyID)
	assert.Contains(t, ids, rec3.KeyID)

	// Revoked key must retain its status in the list.
	assert.Equal(t, apiKeyStatusRevoked, ids[rec3.KeyID],
		"revoked key must appear with status %q", apiKeyStatusRevoked)
}

// TestAPIKeyAuthenticator_ListKeysEmptyTenant verifies that listing keys for a
// tenant with no keys returns an empty slice rather than an error.
func TestAPIKeyAuthenticator_ListKeysEmptyTenant(t *testing.T) {
	a := newTestAuthenticator(t)
	ctx := context.Background()

	keys, err := a.ListKeys(ctx, "unknown-tenant")
	require.NoError(t, err)
	assert.Empty(t, keys)
}

// TestAPIKeyAuthenticator_ListKeysIsolatedByTenant verifies that ListKeys only
// returns keys belonging to the requested tenant and not those of other tenants.
func TestAPIKeyAuthenticator_ListKeysIsolatedByTenant(t *testing.T) {
	a := newTestAuthenticator(t)
	ctx := context.Background()

	_, _, err := a.CreateKey(ctx, "acme", nil, nil, nil, "", "")
	require.NoError(t, err)
	_, _, err = a.CreateKey(ctx, "other-corp", nil, nil, nil, "", "")
	require.NoError(t, err)

	acmeKeys, err := a.ListKeys(ctx, "acme")
	require.NoError(t, err)
	assert.Len(t, acmeKeys, 1, "acme must have exactly one key")
	assert.Equal(t, "acme", acmeKeys[0].TenantID)
}

// TestAPIKeyAuthenticator_EmptyTenantIDRejected verifies that CreateKey refuses
// an empty tenant ID with a descriptive error.
func TestAPIKeyAuthenticator_EmptyTenantIDRejected(t *testing.T) {
	a := newTestAuthenticator(t)
	ctx := context.Background()

	_, _, err := a.CreateKey(ctx, "", nil, nil, nil, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenantID")
}

// TestAPIKeyAuthenticator_KeysAreUnique verifies that two CreateKey calls for
// the same tenant produce distinct keys and distinct key IDs.
func TestAPIKeyAuthenticator_KeysAreUnique(t *testing.T) {
	a := newTestAuthenticator(t)
	ctx := context.Background()

	rawKey1, rec1, err := a.CreateKey(ctx, "acme", nil, nil, nil, "", "")
	require.NoError(t, err)
	rawKey2, rec2, err := a.CreateKey(ctx, "acme", nil, nil, nil, "", "")
	require.NoError(t, err)

	assert.NotEqual(t, rawKey1, rawKey2, "raw keys must be distinct")
	assert.NotEqual(t, rec1.KeyID, rec2.KeyID, "key IDs must be distinct")
}

// TestNewAPIKeyAuthenticator_NilClientRejected verifies the constructor returns
// an error when given a nil Redis client.
func TestNewAPIKeyAuthenticator_NilClientRejected(t *testing.T) {
	_, err := NewAPIKeyAuthenticator(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

// ---------------------------------------------------------------------------
// SystemTenant key creation tests
// ---------------------------------------------------------------------------

// adminIdentityContext returns a context carrying a synthetic Identity with the
// given roles, mimicking what the auth interceptor injects after authentication.
func adminIdentityContext(roles []string) context.Context {
	identity := &Identity{
		Identity: sdkauth.Identity{
			Subject: "test-admin",
			Issuer:  "test",
		},
		Roles: roles,
		Permissions: []Permission{
			{Action: "*", Resource: "*", Scope: "*"},
		},
	}
	return ContextWithIdentity(context.Background(), identity)
}

// TestAPIKeyAuthenticator_SystemTenantRequiresAdminRole verifies that creating a
// key for the reserved SystemTenant ("_system") is rejected when the caller does
// not hold the "admin" or "platform-operator" role.
func TestAPIKeyAuthenticator_SystemTenantRequiresAdminRole(t *testing.T) {
	a := newTestAuthenticator(t)

	// No identity in context — must be rejected.
	_, _, err := a.CreateKey(context.Background(), SystemTenant, nil, nil, nil, "", "")
	require.Error(t, err, "no identity in context must be rejected")
	assert.Contains(t, err.Error(), SystemTenant)

	// Identity present but wrong role — must be rejected.
	ctx := adminIdentityContext([]string{"viewer"})
	_, _, err = a.CreateKey(ctx, SystemTenant, nil, nil, nil, "", "")
	require.Error(t, err, "unprivileged role must be rejected")
	assert.Contains(t, err.Error(), SystemTenant)
}

// TestAPIKeyAuthenticator_SystemTenantAllowedForAdmin verifies that an identity
// with the "admin" role can create a key scoped to SystemTenant.
func TestAPIKeyAuthenticator_SystemTenantAllowedForAdmin(t *testing.T) {
	a := newTestAuthenticator(t)
	ctx := adminIdentityContext([]string{"admin"})

	rawKey, record, err := a.CreateKey(ctx, SystemTenant, nil, nil, nil, "", "")
	require.NoError(t, err)
	require.NotEmpty(t, rawKey)
	assert.Equal(t, SystemTenant, record.TenantID)
	assert.True(t, strings.HasPrefix(rawKey, "gsk_"+SystemTenant+"_"),
		"key %q must carry the system tenant in its prefix", rawKey)
}

// TestAPIKeyAuthenticator_SystemTenantAllowedForPlatformOperator verifies that an
// identity with the "platform-operator" role can create a key scoped to SystemTenant.
func TestAPIKeyAuthenticator_SystemTenantAllowedForPlatformOperator(t *testing.T) {
	a := newTestAuthenticator(t)
	ctx := adminIdentityContext([]string{"platform-operator"})

	rawKey, record, err := a.CreateKey(ctx, SystemTenant, nil, nil, nil, "", "")
	require.NoError(t, err)
	require.NotEmpty(t, rawKey)
	assert.Equal(t, SystemTenant, record.TenantID)
}

// TestAPIKeyAuthenticator_SystemTenantKeyAuthenticatesWithCorrectTenant verifies
// that a key created for SystemTenant authenticates and surfaces "_system" as the
// tenant_id claim, so that TenantFromContext will return "_system" after the
// interceptor processes the identity.
func TestAPIKeyAuthenticator_SystemTenantKeyAuthenticatesWithCorrectTenant(t *testing.T) {
	a := newTestAuthenticator(t)
	ctx := adminIdentityContext([]string{"admin"})

	rawKey, _, err := a.CreateKey(ctx, SystemTenant, nil, nil, nil, "", "")
	require.NoError(t, err)

	identity, err := a.Authenticate(context.Background(), rawKey)
	require.NoError(t, err)

	tenantClaim, ok := identity.Claims["tenant_id"].(string)
	require.True(t, ok, "tenant_id claim must be a string")
	assert.Equal(t, SystemTenant, tenantClaim,
		"authenticated identity must carry %q as tenant_id", SystemTenant)

	// Simulate what the interceptor does: store tenant in context and read it back.
	tenantCtx := ContextWithTenant(context.Background(), tenantClaim)
	assert.Equal(t, SystemTenant, TenantFromContext(tenantCtx),
		"TenantFromContext must return %q for a _system-scoped key", SystemTenant)
}
