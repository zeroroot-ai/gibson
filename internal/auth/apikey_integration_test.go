//go:build integration
// +build integration

// Package auth — apikey_integration_test.go
//
// Integration tests for APIKeyAuthenticator against a real Postgres instance.
// These tests require Docker (via testcontainers-go) to spin up a real Postgres
// instance.
//
// Run with:
//
//	go test -tags integration ./internal/auth/...
package auth

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/zero-day-ai/gibson/internal/provisioner"
)

// setupAPIKeyPostgres starts a Postgres container, runs all migrations, and
// returns a *sql.DB ready for testing. The returned cleanup function stops the
// container.
func setupAPIKeyPostgres(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	ctx := context.Background()

	// Verify Docker is available before spending time starting containers.
	provider, err := testcontainers.ProviderDocker.GetProvider()
	if err != nil {
		t.Skipf("Docker not available, skipping Postgres integration test: %v", err)
		return nil, func() {}
	}
	if healthErr := provider.Health(ctx); healthErr != nil {
		t.Skipf("Docker not running, skipping Postgres integration test: %v", healthErr)
		return nil, func() {}
	}

	const (
		pgUser     = "testuser"
		pgPassword = "testpassword"
		pgDB       = "testdb"
	)

	req := testcontainers.ContainerRequest{
		Image: "postgres:15-alpine",
		Env: map[string]string{
			"POSTGRES_USER":     pgUser,
			"POSTGRES_PASSWORD": pgPassword,
			"POSTGRES_DB":       pgDB,
		},
		ExposedPorts: []string{"5432/tcp"},
		WaitingFor: wait.ForAll(
			wait.ForLog("database system is ready to accept connections"),
			wait.ForListeningPort("5432/tcp"),
		),
	}

	pgC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err, "failed to start Postgres container")

	cleanup := func() {
		if termErr := pgC.Terminate(ctx); termErr != nil {
			t.Logf("warning: failed to terminate Postgres container: %v", termErr)
		}
	}

	host, err := pgC.Host(ctx)
	require.NoError(t, err)

	mappedPort, err := pgC.MappedPort(ctx, "5432")
	require.NoError(t, err)

	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, mappedPort.Port(), pgUser, pgPassword, pgDB)

	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err, "failed to open Postgres connection")
	t.Cleanup(func() { _ = db.Close() })

	// Wait for Postgres to be fully ready.
	require.Eventually(t, func() bool {
		return db.PingContext(ctx) == nil
	}, 30*time.Second, 200*time.Millisecond, "Postgres did not become ready in time")

	// Run all migrations including the api_keys table.
	require.NoError(t, provisioner.RunMigrations(ctx, db), "RunMigrations must succeed")

	return db, cleanup
}

// newIntegrationAuthenticator creates an APIKeyAuthenticator backed by the
// provided *sql.DB.
func newIntegrationAuthenticator(t *testing.T, db *sql.DB) *APIKeyAuthenticator {
	t.Helper()
	a, err := NewAPIKeyAuthenticator(db)
	require.NoError(t, err)
	require.NotNil(t, a)
	return a
}

// ---------------------------------------------------------------------------
// Create and Authenticate
// ---------------------------------------------------------------------------

// TestAPIKeyAuthenticator_CreateAndAuthenticate verifies the basic round-trip:
// create a key, present the raw key to Authenticate, get back a valid Identity.
func TestAPIKeyAuthenticator_CreateAndAuthenticate(t *testing.T) {
	db, cleanup := setupAPIKeyPostgres(t)
	defer cleanup()
	a := newIntegrationAuthenticator(t, db)
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
	db, cleanup := setupAPIKeyPostgres(t)
	defer cleanup()
	a := newIntegrationAuthenticator(t, db)
	ctx := context.Background()

	rawKey, _, err := a.CreateKey(ctx, "acme", nil, nil, nil, "", "")
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(rawKey, "gsk_"),
		"raw key %q must start with \"gsk_\"", rawKey)
}

// TestAPIKeyAuthenticator_InvalidKeyRejected verifies that a random string that
// was never issued returns an authentication error.
func TestAPIKeyAuthenticator_InvalidKeyRejected(t *testing.T) {
	db, cleanup := setupAPIKeyPostgres(t)
	defer cleanup()
	a := newIntegrationAuthenticator(t, db)
	ctx := context.Background()

	_, err := a.Authenticate(ctx, "gsk_nobody_000000000000000000000000000000000000000000000000000000000000000")
	require.Error(t, err)
	assert.True(t, IsInvalidTokenError(err),
		"expected invalid_token error, got: %v", err)
}

// TestAPIKeyAuthenticator_EmptyTokenRejected verifies that an empty token string
// returns a missing-token error rather than an invalid-token error.
func TestAPIKeyAuthenticator_EmptyTokenRejected(t *testing.T) {
	db, cleanup := setupAPIKeyPostgres(t)
	defer cleanup()
	a := newIntegrationAuthenticator(t, db)
	ctx := context.Background()

	_, err := a.Authenticate(ctx, "")
	require.Error(t, err)
	assert.True(t, IsMissingTokenError(err),
		"expected missing_token error, got: %v", err)
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

// TestAPIKeyAuthenticator_RevokedKeyRejected verifies the revocation lifecycle:
// create a key, revoke it, then confirm Authenticate refuses the key.
func TestAPIKeyAuthenticator_RevokedKeyRejected(t *testing.T) {
	db, cleanup := setupAPIKeyPostgres(t)
	defer cleanup()
	a := newIntegrationAuthenticator(t, db)
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
	assert.True(t, IsInvalidTokenError(err) || IsTokenExpiredError(err),
		"expected invalid or expired token error for revoked key, got: %v", err)
}

// TestAPIKeyAuthenticator_RevokeIdempotent verifies that revoking an already-
// revoked key is a no-op that returns nil.
func TestAPIKeyAuthenticator_RevokeIdempotent(t *testing.T) {
	db, cleanup := setupAPIKeyPostgres(t)
	defer cleanup()
	a := newIntegrationAuthenticator(t, db)
	ctx := context.Background()

	_, record, err := a.CreateKey(ctx, "acme", nil, nil, nil, "", "")
	require.NoError(t, err)

	require.NoError(t, a.RevokeKey(ctx, record.KeyID))
	require.NoError(t, a.RevokeKey(ctx, record.KeyID), "second revoke must be idempotent")
}

// ---------------------------------------------------------------------------
// Tenant and claims
// ---------------------------------------------------------------------------

// TestAPIKeyAuthenticator_TenantExtraction verifies that the tenant_id claim in
// the returned Identity matches the tenant used during key creation.
func TestAPIKeyAuthenticator_TenantExtraction(t *testing.T) {
	db, cleanup := setupAPIKeyPostgres(t)
	defer cleanup()
	a := newIntegrationAuthenticator(t, db)
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
	db, cleanup := setupAPIKeyPostgres(t)
	defer cleanup()
	a := newIntegrationAuthenticator(t, db)
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
	db, cleanup := setupAPIKeyPostgres(t)
	defer cleanup()
	a := newIntegrationAuthenticator(t, db)
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
	db, cleanup := setupAPIKeyPostgres(t)
	defer cleanup()
	a := newIntegrationAuthenticator(t, db)
	ctx := context.Background()

	_, record, err := a.CreateKey(ctx, "acme", nil, nil, nil, "", "")
	require.NoError(t, err)

	assert.NotNil(t, record.AllowedKinds)
	assert.Empty(t, record.AllowedKinds)
}

// ---------------------------------------------------------------------------
// use_count and last_used_at
// ---------------------------------------------------------------------------

// TestAPIKeyAuthenticator_LastUsedAtUpdated verifies that Authenticate updates
// the last_used_at and use_count fields in Postgres.
func TestAPIKeyAuthenticator_LastUsedAtUpdated(t *testing.T) {
	db, cleanup := setupAPIKeyPostgres(t)
	defer cleanup()
	a := newIntegrationAuthenticator(t, db)
	ctx := context.Background()

	rawKey, record, err := a.CreateKey(ctx, "acme", nil, nil, nil, "", "")
	require.NoError(t, err)

	// Ensure measurable wall-clock gap.
	time.Sleep(2 * time.Millisecond)

	_, err = a.Authenticate(ctx, rawKey)
	require.NoError(t, err)

	// Poll until Postgres reflects the update.
	var updated *APIKeyRecord
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		updated, err = a.fetchRecord(ctx, record.KeyID)
		require.NoError(t, err)
		if updated.LastUsedAt != nil && updated.UseCount > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	require.NotNil(t, updated.LastUsedAt, "last_used_at must be set after authentication")
	assert.Equal(t, 1, updated.UseCount, "use_count must be 1 after first authentication")
}

// ---------------------------------------------------------------------------
// max_uses / single-use keys
// ---------------------------------------------------------------------------

// TestAPIKeyAuthenticator_MaxUsesOneConsumedAfterFirstUse verifies that a key
// with max_uses=1 is consumed (status="consumed") after the first successful
// authentication and rejected on the second attempt.
func TestAPIKeyAuthenticator_MaxUsesOneConsumedAfterFirstUse(t *testing.T) {
	db, cleanup := setupAPIKeyPostgres(t)
	defer cleanup()
	ctx := context.Background()

	maxUses := 1

	// Insert a key with max_uses=1 directly.
	const insert = `
INSERT INTO api_keys (key_id, tenant_id, key_hash, status, max_uses, use_count)
VALUES ($1, $2, $3, 'active', $4, 0)`

	rawKey := "gsk_acme_singleuse00000000000000000000000000000000000000000000000000000000"
	keyHash := hashKey(rawKey)
	keyID := "gsk_acme_singleuse0000"

	_, err := db.ExecContext(ctx, insert, keyID, "acme", keyHash, maxUses)
	require.NoError(t, err)

	a, err := NewAPIKeyAuthenticator(db)
	require.NoError(t, err)

	// First authentication must succeed.
	identity, err := a.Authenticate(ctx, rawKey)
	require.NoError(t, err)
	require.NotNil(t, identity)

	// The key must now be consumed.
	record, err := a.fetchRecord(ctx, keyID)
	require.NoError(t, err)
	assert.Equal(t, apiKeyStatusConsumed, record.Status,
		"key must be consumed after max_uses=1 is reached")

	// Second authentication must fail.
	_, err = a.Authenticate(ctx, rawKey)
	require.Error(t, err, "consumed key must not authenticate a second time")
}

// TestAPIKeyAuthenticator_MaxUsesThreeConsumedAfterThirdUse verifies that a
// key with max_uses=3 transitions to consumed only on the third use.
func TestAPIKeyAuthenticator_MaxUsesThreeConsumedAfterThirdUse(t *testing.T) {
	db, cleanup := setupAPIKeyPostgres(t)
	defer cleanup()
	ctx := context.Background()

	maxUses := 3

	rawKey := "gsk_acme_multiuse00000000000000000000000000000000000000000000000000000000"
	keyHash := hashKey(rawKey)
	keyID := "gsk_acme_multiuse00000"

	const insert = `
INSERT INTO api_keys (key_id, tenant_id, key_hash, status, max_uses, use_count)
VALUES ($1, $2, $3, 'active', $4, 0)`
	_, err := db.ExecContext(ctx, insert, keyID, "acme", keyHash, maxUses)
	require.NoError(t, err)

	a, err := NewAPIKeyAuthenticator(db)
	require.NoError(t, err)

	// Uses 1 and 2 must succeed and leave the key active.
	for i := 1; i <= 2; i++ {
		_, authErr := a.Authenticate(ctx, rawKey)
		require.NoError(t, authErr, "use %d must succeed", i)

		rec, recErr := a.fetchRecord(ctx, keyID)
		require.NoError(t, recErr)
		assert.Equal(t, apiKeyStatusActive, rec.Status,
			"key must remain active after use %d of %d", i, maxUses)
		assert.Equal(t, i, rec.UseCount)
	}

	// Use 3 must succeed and then the key must be consumed.
	_, authErr := a.Authenticate(ctx, rawKey)
	require.NoError(t, authErr, "third use must succeed")

	rec, recErr := a.fetchRecord(ctx, keyID)
	require.NoError(t, recErr)
	assert.Equal(t, apiKeyStatusConsumed, rec.Status,
		"key must be consumed after third use")
	assert.Equal(t, 3, rec.UseCount)

	// Fourth use must fail.
	_, err = a.Authenticate(ctx, rawKey)
	require.Error(t, err, "consumed key must not authenticate")
}

// ---------------------------------------------------------------------------
// Expiry
// ---------------------------------------------------------------------------

// TestAPIKeyAuthenticator_ExpiredKeyRejected verifies that a key with a past
// expires_at is refused by Authenticate.
func TestAPIKeyAuthenticator_ExpiredKeyRejected(t *testing.T) {
	db, cleanup := setupAPIKeyPostgres(t)
	defer cleanup()
	ctx := context.Background()

	rawKey := "gsk_acme_expired000000000000000000000000000000000000000000000000000000000"
	keyHash := hashKey(rawKey)
	keyID := "gsk_acme_expired00000"

	past := time.Now().UTC().Add(-1 * time.Hour)

	const insert = `
INSERT INTO api_keys (key_id, tenant_id, key_hash, status, expires_at)
VALUES ($1, $2, $3, 'active', $4)`
	_, err := db.ExecContext(ctx, insert, keyID, "acme", keyHash, past)
	require.NoError(t, err)

	a, err := NewAPIKeyAuthenticator(db)
	require.NoError(t, err)

	_, authErr := a.Authenticate(ctx, rawKey)
	require.Error(t, authErr, "expired key must not authenticate")
	assert.True(t, IsTokenExpiredError(authErr),
		"expected token_expired error, got: %v", authErr)
}

// ---------------------------------------------------------------------------
// ListKeys
// ---------------------------------------------------------------------------

// TestAPIKeyAuthenticator_ListKeys verifies that ListKeys returns all keys
// created for a tenant, including both active and revoked keys.
func TestAPIKeyAuthenticator_ListKeys(t *testing.T) {
	db, cleanup := setupAPIKeyPostgres(t)
	defer cleanup()
	a := newIntegrationAuthenticator(t, db)
	ctx := context.Background()

	const tenant = "acme"

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

	ids := make(map[string]string, len(keys))
	for _, k := range keys {
		ids[k.KeyID] = k.Status
	}

	assert.Contains(t, ids, rec1.KeyID)
	assert.Contains(t, ids, rec2.KeyID)
	assert.Contains(t, ids, rec3.KeyID)

	assert.Equal(t, apiKeyStatusRevoked, ids[rec3.KeyID],
		"revoked key must appear with status %q", apiKeyStatusRevoked)
}

// TestAPIKeyAuthenticator_ListKeysEmptyTenant verifies that listing keys for a
// tenant with no keys returns an empty slice rather than an error.
func TestAPIKeyAuthenticator_ListKeysEmptyTenant(t *testing.T) {
	db, cleanup := setupAPIKeyPostgres(t)
	defer cleanup()
	a := newIntegrationAuthenticator(t, db)
	ctx := context.Background()

	keys, err := a.ListKeys(ctx, "unknown-tenant")
	require.NoError(t, err)
	assert.Empty(t, keys)
}

// TestAPIKeyAuthenticator_ListKeysIsolatedByTenant verifies that ListKeys only
// returns keys belonging to the requested tenant and not those of other tenants.
func TestAPIKeyAuthenticator_ListKeysIsolatedByTenant(t *testing.T) {
	db, cleanup := setupAPIKeyPostgres(t)
	defer cleanup()
	a := newIntegrationAuthenticator(t, db)
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

// ---------------------------------------------------------------------------
// Uniqueness and validation
// ---------------------------------------------------------------------------

// TestAPIKeyAuthenticator_EmptyTenantIDRejected verifies that CreateKey refuses
// an empty tenant ID with a descriptive error.
func TestAPIKeyAuthenticator_EmptyTenantIDRejected(t *testing.T) {
	db, cleanup := setupAPIKeyPostgres(t)
	defer cleanup()
	a := newIntegrationAuthenticator(t, db)
	ctx := context.Background()

	_, _, err := a.CreateKey(ctx, "", nil, nil, nil, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenantID")
}

// TestAPIKeyAuthenticator_KeysAreUnique verifies that two CreateKey calls for
// the same tenant produce distinct keys and distinct key IDs.
func TestAPIKeyAuthenticator_KeysAreUnique(t *testing.T) {
	db, cleanup := setupAPIKeyPostgres(t)
	defer cleanup()
	a := newIntegrationAuthenticator(t, db)
	ctx := context.Background()

	rawKey1, rec1, err := a.CreateKey(ctx, "acme", nil, nil, nil, "", "")
	require.NoError(t, err)
	rawKey2, rec2, err := a.CreateKey(ctx, "acme", nil, nil, nil, "", "")
	require.NoError(t, err)

	assert.NotEqual(t, rawKey1, rawKey2, "raw keys must be distinct")
	assert.NotEqual(t, rec1.KeyID, rec2.KeyID, "key IDs must be distinct")
}

// ---------------------------------------------------------------------------
// SystemTenant key tests
// ---------------------------------------------------------------------------

// TestAPIKeyAuthenticator_SystemTenantAllowedForPlatformOperatorCreate verifies
// that an identity with the "platform-operator" role can create a key scoped to
// SystemTenant.
func TestAPIKeyAuthenticator_SystemTenantAllowedForPlatformOperatorCreate(t *testing.T) {
	db, cleanup := setupAPIKeyPostgres(t)
	defer cleanup()
	a := newIntegrationAuthenticator(t, db)
	ctx := adminIdentityContext([]string{"platform-operator"})

	rawKey, record, err := a.CreateKey(ctx, SystemTenant, nil, nil, nil, "", "")
	require.NoError(t, err)
	require.NotEmpty(t, rawKey)
	assert.Equal(t, SystemTenant, record.TenantID)
	assert.True(t, strings.HasPrefix(rawKey, "gsk_"+SystemTenant+"_"),
		"key %q must carry the system tenant in its prefix", rawKey)
}

// TestAPIKeyAuthenticator_SystemTenantKeyAuthenticatesWithCorrectTenant verifies
// that a key created for SystemTenant authenticates and surfaces "_system" as
// the tenant_id claim.
func TestAPIKeyAuthenticator_SystemTenantKeyAuthenticatesWithCorrectTenant(t *testing.T) {
	db, cleanup := setupAPIKeyPostgres(t)
	defer cleanup()
	a := newIntegrationAuthenticator(t, db)
	ctx := adminIdentityContext([]string{"platform-operator"})

	rawKey, _, err := a.CreateKey(ctx, SystemTenant, nil, nil, nil, "", "")
	require.NoError(t, err)

	identity, err := a.Authenticate(context.Background(), rawKey)
	require.NoError(t, err)

	tenantClaim, ok := identity.Claims["tenant_id"].(string)
	require.True(t, ok, "tenant_id claim must be a string")
	assert.Equal(t, SystemTenant, tenantClaim,
		"authenticated identity must carry %q as tenant_id", SystemTenant)

	tenantCtx := ContextWithTenant(context.Background(), tenantClaim)
	assert.Equal(t, SystemTenant, TenantFromContext(tenantCtx),
		"TenantFromContext must return %q for a _system-scoped key", SystemTenant)
}
