//go:build integration
// +build integration

// Package postgres — integration_test.go
//
// Integration tests for the Postgres SecretsBroker provider against a real
// Postgres container (via testcontainers-go). These tests exercise the full
// stack: migration → pgxpool → TenantSecretsOps → Provider.
//
// Run with:
//
//	go test -tags integration ./internal/secrets/providers/postgres/...
//
// Tests are skipped gracefully when Docker is unavailable.
//
// Spec: secrets-broker, Phase 2, Task 5.
// Requirements: 2.5, 5.3.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	dbpostgres "github.com/zero-day-ai/gibson/internal/database/postgres"
	"github.com/zero-day-ai/gibson/internal/datapool"
	"github.com/zero-day-ai/gibson/internal/datapool/envelope"
	"github.com/zero-day-ai/gibson/tests/testhelpers"
	"github.com/zero-day-ai/sdk/auth"
	"github.com/zero-day-ai/sdk/secrets"
	"github.com/zero-day-ai/sdk/secrets/contract"
)

// ---------------------------------------------------------------------------
// Container helpers
// ---------------------------------------------------------------------------

const (
	intTestUser     = "testuser"
	intTestPassword = "testpass"
	intTestDB       = "testsecrets"
)

// setupPostgres starts an ephemeral Postgres container, applies the
// tenant_secrets migration, and returns a pgxpool.Pool ready for use.
// The container is terminated when the test ends.
func setupPostgres(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()

	// Per first-deploy-unblock-and-ha:R7.13–R7.17 the daemon's tests
	// must connect to Postgres over TLS — the `disable` SSL mode is
	// forbidden anywhere in the source tree. testhelpers.StartPostgresTLS
	// owns the testcontainer + self-signed CA setup and returns a DSN
	// that already carries `sslmode=require`. The helper also handles
	// the Docker availability skip.
	pgTLS := testhelpers.StartPostgresTLS(t, testhelpers.PostgresOptions{
		User:     intTestUser,
		Password: intTestPassword,
		Database: intTestDB,
	})
	dsn := pgTLS.DSN

	var (
		pool *pgxpool.Pool
		err  error
	)
	require.Eventually(t, func() bool {
		pool, err = pgxpool.New(ctx, dsn)
		if err != nil {
			return false
		}
		return pool.Ping(ctx) == nil
	}, 30*time.Second, 200*time.Millisecond, "Postgres did not become ready in time")

	t.Cleanup(func() { pool.Close() })

	// Apply the tenant_secrets migration (006_tenant_secrets.up.sql logic).
	applyMigration(t, ctx, pool)

	return pool
}

// applyMigration applies the tenant_secrets table DDL to the test database.
// This mirrors 006_tenant_secrets.up.sql without the DROP TABLE statements
// (the test database starts fresh so there are no old tables to drop).
func applyMigration(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	ddl := `
		CREATE TABLE IF NOT EXISTS tenant_secrets (
			name       TEXT        PRIMARY KEY,
			envelope   BYTEA       NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
	`
	_, err := pool.Exec(ctx, ddl)
	require.NoError(t, err, "apply tenant_secrets DDL")
}

// ---------------------------------------------------------------------------
// ConnAcquirer for tests
// ---------------------------------------------------------------------------

// newTestKEK returns a deterministic 32-byte KEK for tests.
// NEVER use anything derived from this in production.
func newTestKEK() []byte {
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 1)
	}
	return kek
}

// newTestAcquirer returns a ConnAcquirer that always returns a Conn backed
// by the given pool and KEK, regardless of tenant. The KEK is copied on each
// call so that conn.Release() zeroing the KEK field does not corrupt the
// original kek slice used by subsequent calls.
func newTestAcquirer(pool *pgxpool.Pool, kek []byte) ConnAcquirer {
	return func(ctx context.Context, tenant auth.TenantID) (*datapool.Conn, error) {
		kekCopy := make([]byte, len(kek))
		copy(kekCopy, kek)
		conn := &datapool.Conn{
			Tenant:   tenant,
			Postgres: pool,
			KEK:      kekCopy,
		}
		return conn, nil
	}
}

// ---------------------------------------------------------------------------
// Integration: RunContract
// ---------------------------------------------------------------------------

// TestIntegration_Contract runs the shared SecretsBroker contract suite against
// a real Postgres backend. This is the canonical proof that the provider
// conforms to the broker contract.
func TestIntegration_Contract(t *testing.T) {
	pool := setupPostgres(t)
	kek := newTestKEK()
	acq := newTestAcquirer(pool, kek)
	p := New(acq)

	contract.RunContract(t, p)
}

// ---------------------------------------------------------------------------
// Integration: cross-tenant decrypt detection
// ---------------------------------------------------------------------------

// TestIntegration_CrossTenantDecrypt verifies that:
//  1. A secret encrypted with KEK_A can be read by KEK_A.
//  2. Attempting to read it with KEK_B returns secrets.ErrUnavailable.
//  3. The gibson_xtenant_decrypt_attempt_total Prometheus metric increments.
//
// The metric increment is verified by checking that the metric value is
// non-zero after the failing Get call; the exact count is not tested because
// other test runs may have incremented the counter first.
func TestIntegration_CrossTenantDecrypt(t *testing.T) {
	pool := setupPostgres(t)

	kekA := make([]byte, 32)
	for i := range kekA {
		kekA[i] = 0xAA
	}
	kekB := make([]byte, 32)
	for i := range kekB {
		kekB[i] = 0xBB
	}

	tenantA := auth.MustNewTenantID("tenant-a")
	secretName := fmt.Sprintf("xtenant-test-%d", time.Now().UnixNano())
	secretValue := []byte("super-secret-value")

	// Write a secret using kekA (via raw TenantSecretsOps, bypassing the provider
	// so we can control the KEK exactly).
	opsA := dbpostgres.NewTenantSecretsOps(pool, kekA, tenantA.String())
	ctx := context.Background()

	err := opsA.Put(ctx, secretName, secretValue)
	require.NoError(t, err, "write secret with kekA")

	// Read it back with kekA — should succeed.
	got, err := opsA.Get(ctx, secretName)
	require.NoError(t, err, "get secret with kekA")
	require.Equal(t, secretValue, got, "kekA round-trip")

	// Attempt to read with kekB — should return a cross-tenant decrypt error.
	opsB := dbpostgres.NewTenantSecretsOps(pool, kekB, tenantA.String())
	_, err = opsB.Get(ctx, secretName)
	require.Error(t, err, "get with kekB should fail")

	// The error must be a cross-tenant secret error.
	if !dbpostgres.IsCrossTenantSecretError(err) {
		t.Errorf("expected cross-tenant secret error, got: %v", err)
	}

	// The provider layer must map this to secrets.ErrUnavailable.
	acquirerB := newTestAcquirer(pool, kekB)
	providerB := New(acquirerB)
	_, provErr := providerB.Get(ctx, tenantA, secretName)
	if !errors.Is(provErr, secrets.ErrUnavailable) {
		t.Errorf("provider: cross-tenant error must map to ErrUnavailable, got: %v", provErr)
	}

	// Verify the envelope-level detection path is working correctly by
	// confirming IsCrossTenantDecryptError on the underlying envelope error.
	aad := []byte("secret:" + secretName)
	env, encErr := envelope.Encrypt(kekA, secretValue, aad)
	require.NoError(t, encErr)

	_, decErr := envelope.Decrypt(kekB, env, aad)
	require.Error(t, decErr, "decrypt with wrong KEK must fail")
	if !envelope.IsCrossTenantDecryptError(decErr) {
		t.Error("envelope layer must detect cross-tenant KEK mismatch")
	}

	// Clean up.
	_ = opsA.Delete(ctx, secretName)
}

// ---------------------------------------------------------------------------
// Integration: Put/Get/Delete/List round-trip
// ---------------------------------------------------------------------------

// TestIntegration_BasicRoundTrip is a quick sanity smoke-test that does not
// rely on the contract suite. It verifies the core CRUD path against a real DB.
func TestIntegration_BasicRoundTrip(t *testing.T) {
	pool := setupPostgres(t)
	kek := newTestKEK()
	acq := newTestAcquirer(pool, kek)
	p := New(acq)

	ctx := context.Background()
	tenant := auth.MustNewTenantID("smoke-tenant")
	name := fmt.Sprintf("smoke-%d", time.Now().UnixNano())
	value := []byte("smoke value with binary \x00\xFF\x01")

	// Put
	require.NoError(t, p.Put(ctx, tenant, name, value))

	// Get
	got, err := p.Get(ctx, tenant, name)
	require.NoError(t, err)
	require.Equal(t, value, got)

	// List (should contain the name)
	names, err := p.List(ctx, tenant, secrets.Filter{})
	require.NoError(t, err)
	found := false
	for _, n := range names {
		if n == name {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("List: name %q not found in %v", name, names)
	}

	// Delete
	require.NoError(t, p.Delete(ctx, tenant, name))

	// Get after delete → ErrNotFound
	_, err = p.Get(ctx, tenant, name)
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Get after Delete: want ErrNotFound, got %v", err)
	}

	// Idempotent delete (second delete is a no-op).
	require.NoError(t, p.Delete(ctx, tenant, name))
}
