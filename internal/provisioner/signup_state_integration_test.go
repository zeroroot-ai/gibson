//go:build integration
// +build integration

// Package provisioner — signup_state_integration_test.go
//
// Integration tests for PgProvisioningStore. These tests require Docker (via
// testcontainers-go) to spin up a real Postgres instance.
//
// Run with:
//
//	go test -tags integration ./internal/provisioner/...
package provisioner

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// setupPostgresContainer starts a Postgres container and returns an open *sql.DB
// with the tenant_provisioning schema already applied. The returned cleanup
// function stops the container.
func setupPostgresContainer(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	ctx := context.Background()

	// Verify Docker is available and running before spending time starting containers.
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
			wait.ForListeningPort("5432/tcp"),
			wait.ForLog("database system is ready to accept connections"),
		).WithDeadline(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err, "failed to start Postgres container")

	host, err := container.Host(ctx)
	require.NoError(t, err)

	mappedPort, err := container.MappedPort(ctx, "5432")
	require.NoError(t, err)

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		pgUser, pgPassword, host, mappedPort.Port(), pgDB)

	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)

	// Wait for the DB to actually accept connections (beyond port listening).
	require.Eventually(t, func() bool {
		pingErr := db.Ping()
		return pingErr == nil
	}, 30*time.Second, 500*time.Millisecond, "postgres did not become ready in time")

	// Apply schema migrations.
	err = RunMigrations(ctx, db)
	require.NoError(t, err, "RunMigrations should succeed")

	cleanup := func() {
		_ = db.Close()
		_ = container.Terminate(ctx)
	}
	return db, cleanup
}

// newTestState returns a minimal valid SignupState for testing.
func newTestState(userID string) SignupState {
	return SignupState{
		Status:       "requested",
		Email:        userID + "@example.com",
		CompanyName:  "Test Corp " + userID,
		TenantID:     "test-slug-" + userID,
		Plan:         "indie",
		CurrentStep:  "fga",
		StepStatuses: map[string]string{"fga": "pending", "provision": "pending"},
		Error:        "",
	}
}

// ---------------------------------------------------------------------------
// Create + Get round-trip
// ---------------------------------------------------------------------------

func TestPgProvisioningStore_CreateAndGet(t *testing.T) {
	db, cleanup := setupPostgresContainer(t)
	defer cleanup()

	store := NewPgProvisioningStore(db)
	ctx := context.Background()

	userID := "user-create-get-001"
	state := newTestState(userID)

	err := store.Create(ctx, userID, state)
	require.NoError(t, err)

	got, err := store.Get(ctx, userID)
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, state.Status, got.Status)
	assert.Equal(t, state.Email, got.Email)
	assert.Equal(t, state.CompanyName, got.CompanyName)
	assert.Equal(t, state.TenantID, got.TenantID)
	assert.Equal(t, state.Plan, got.Plan)
	assert.Equal(t, state.CurrentStep, got.CurrentStep)
	assert.Equal(t, state.StepStatuses, got.StepStatuses)
	assert.Empty(t, got.Error)
	assert.Greater(t, got.CreatedAt, int64(0), "created_at should be non-zero")
	assert.Zero(t, got.CompletedAt, "completed_at should be zero before completion")
}

// ---------------------------------------------------------------------------
// Get on non-existent user returns (nil, nil)
// ---------------------------------------------------------------------------

func TestPgProvisioningStore_GetNonExistent(t *testing.T) {
	db, cleanup := setupPostgresContainer(t)
	defer cleanup()

	store := NewPgProvisioningStore(db)
	ctx := context.Background()

	got, err := store.Get(ctx, "no-such-user-xyz")
	require.NoError(t, err, "missing record should not return error")
	assert.Nil(t, got, "missing record should return nil state")
}

// ---------------------------------------------------------------------------
// UpdateField
// ---------------------------------------------------------------------------

func TestPgProvisioningStore_UpdateField_Status(t *testing.T) {
	db, cleanup := setupPostgresContainer(t)
	defer cleanup()

	store := NewPgProvisioningStore(db)
	ctx := context.Background()

	userID := "user-updatefield-status"
	require.NoError(t, store.Create(ctx, userID, newTestState(userID)))

	require.NoError(t, store.UpdateField(ctx, userID, "status", "provisioning"))

	got, err := store.Get(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, "provisioning", got.Status)
}

func TestPgProvisioningStore_UpdateField_CurrentStep(t *testing.T) {
	db, cleanup := setupPostgresContainer(t)
	defer cleanup()

	store := NewPgProvisioningStore(db)
	ctx := context.Background()

	userID := "user-updatefield-step"
	require.NoError(t, store.Create(ctx, userID, newTestState(userID)))

	require.NoError(t, store.UpdateField(ctx, userID, "current_step", "provision"))

	got, err := store.Get(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, "provision", got.CurrentStep)
}

func TestPgProvisioningStore_UpdateField_StepStatusFGA(t *testing.T) {
	db, cleanup := setupPostgresContainer(t)
	defer cleanup()

	store := NewPgProvisioningStore(db)
	ctx := context.Background()

	userID := "user-updatefield-fga"
	require.NoError(t, store.Create(ctx, userID, newTestState(userID)))

	require.NoError(t, store.UpdateField(ctx, userID, "step_status_fga", "completed"))

	got, err := store.Get(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, "completed", got.StepStatuses["fga"], "fga step_status should be updated in JSONB")
}

func TestPgProvisioningStore_UpdateField_StepStatusProvision(t *testing.T) {
	db, cleanup := setupPostgresContainer(t)
	defer cleanup()

	store := NewPgProvisioningStore(db)
	ctx := context.Background()

	userID := "user-updatefield-provision"
	require.NoError(t, store.Create(ctx, userID, newTestState(userID)))

	require.NoError(t, store.UpdateField(ctx, userID, "step_status_provision", "running"))

	got, err := store.Get(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, "running", got.StepStatuses["provision"], "provision step_status should be updated in JSONB")
}

func TestPgProvisioningStore_UpdateField_UnsupportedField(t *testing.T) {
	db, cleanup := setupPostgresContainer(t)
	defer cleanup()

	store := NewPgProvisioningStore(db)
	ctx := context.Background()

	userID := "user-updatefield-bad"
	require.NoError(t, store.Create(ctx, userID, newTestState(userID)))

	err := store.UpdateField(ctx, userID, "nonexistent_column", "value")
	require.Error(t, err, "unsupported field should return error")
	assert.Contains(t, err.Error(), "unsupported field")
}

// ---------------------------------------------------------------------------
// IncrRetry
// ---------------------------------------------------------------------------

func TestPgProvisioningStore_IncrRetry_FGA(t *testing.T) {
	db, cleanup := setupPostgresContainer(t)
	defer cleanup()

	store := NewPgProvisioningStore(db)
	ctx := context.Background()

	userID := "user-incrretry-fga"
	require.NoError(t, store.Create(ctx, userID, newTestState(userID)))

	count1, err := store.IncrRetry(ctx, userID, "fga")
	require.NoError(t, err)
	assert.Equal(t, 1, count1, "first IncrRetry should return 1")

	count2, err := store.IncrRetry(ctx, userID, "fga")
	require.NoError(t, err)
	assert.Equal(t, 2, count2, "second IncrRetry should return 2")

	count3, err := store.IncrRetry(ctx, userID, "fga")
	require.NoError(t, err)
	assert.Equal(t, 3, count3, "third IncrRetry should return 3")
}

func TestPgProvisioningStore_IncrRetry_Provision(t *testing.T) {
	db, cleanup := setupPostgresContainer(t)
	defer cleanup()

	store := NewPgProvisioningStore(db)
	ctx := context.Background()

	userID := "user-incrretry-provision"
	require.NoError(t, store.Create(ctx, userID, newTestState(userID)))

	count, err := store.IncrRetry(ctx, userID, "provision")
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestPgProvisioningStore_IncrRetry_UnknownStep(t *testing.T) {
	db, cleanup := setupPostgresContainer(t)
	defer cleanup()

	store := NewPgProvisioningStore(db)
	ctx := context.Background()

	userID := "user-incrretry-unknown"
	require.NoError(t, store.Create(ctx, userID, newTestState(userID)))

	_, err := store.IncrRetry(ctx, userID, "org") // removed step
	require.Error(t, err, "unknown step should return error")
	assert.Contains(t, err.Error(), "unknown step")
}

// ---------------------------------------------------------------------------
// SetFailed
// ---------------------------------------------------------------------------

func TestPgProvisioningStore_SetFailed(t *testing.T) {
	db, cleanup := setupPostgresContainer(t)
	defer cleanup()

	store := NewPgProvisioningStore(db)
	ctx := context.Background()

	userID := "user-setfailed"
	require.NoError(t, store.Create(ctx, userID, newTestState(userID)))

	errMsg := "fga: timeout after 3 retries"
	require.NoError(t, store.SetFailed(ctx, userID, "fga", errMsg))

	got, err := store.Get(ctx, userID)
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, "failed", got.Status, "status should be failed")
	assert.Equal(t, "fga", got.CurrentStep, "current_step should be the failing step")
	assert.Equal(t, errMsg, got.Error, "error message should be persisted")
}

// ---------------------------------------------------------------------------
// SetCompleted
// ---------------------------------------------------------------------------

func TestPgProvisioningStore_SetCompleted(t *testing.T) {
	db, cleanup := setupPostgresContainer(t)
	defer cleanup()

	store := NewPgProvisioningStore(db)
	ctx := context.Background()

	userID := "user-setcompleted"
	require.NoError(t, store.Create(ctx, userID, newTestState(userID)))

	beforeComplete := time.Now().Unix()
	require.NoError(t, store.SetCompleted(ctx, userID))

	got, err := store.Get(ctx, userID)
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, "active", got.Status, "status should be active after completion")
	assert.GreaterOrEqual(t, got.CompletedAt, beforeComplete, "completed_at should be set to now or later")
}

// ---------------------------------------------------------------------------
// JSONB step_statuses persistence round-trip
// ---------------------------------------------------------------------------

func TestPgProvisioningStore_StepStatusesJSONB_RoundTrip(t *testing.T) {
	db, cleanup := setupPostgresContainer(t)
	defer cleanup()

	store := NewPgProvisioningStore(db)
	ctx := context.Background()

	userID := "user-jsonb-roundtrip"
	state := newTestState(userID)
	state.StepStatuses = map[string]string{
		"fga":       "completed",
		"provision": "running",
	}
	require.NoError(t, store.Create(ctx, userID, state))

	got, err := store.Get(ctx, userID)
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, "completed", got.StepStatuses["fga"])
	assert.Equal(t, "running", got.StepStatuses["provision"])
}

// ---------------------------------------------------------------------------
// Create idempotency (ON CONFLICT DO UPDATE)
// ---------------------------------------------------------------------------

func TestPgProvisioningStore_Create_Idempotent(t *testing.T) {
	db, cleanup := setupPostgresContainer(t)
	defer cleanup()

	store := NewPgProvisioningStore(db)
	ctx := context.Background()

	userID := "user-create-idempotent"
	state := newTestState(userID)

	require.NoError(t, store.Create(ctx, userID, state), "first Create should succeed")

	// Re-init with updated plan.
	state.Plan = "pro"
	require.NoError(t, store.Create(ctx, userID, state), "second Create should succeed (upsert)")

	got, err := store.Get(ctx, userID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "pro", got.Plan, "plan should be updated by the second Create")
}

// ---------------------------------------------------------------------------
// RunMigrations idempotency
// ---------------------------------------------------------------------------

func TestRunMigrations_Idempotent(t *testing.T) {
	db, cleanup := setupPostgresContainer(t)
	defer cleanup()

	ctx := context.Background()

	// First run already happened in setupPostgresContainer.
	// Running again should be a no-op.
	err := RunMigrations(ctx, db)
	require.NoError(t, err, "second RunMigrations call should be idempotent")
}
