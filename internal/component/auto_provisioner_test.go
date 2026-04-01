package component

// auto_provisioner_test.go contains unit tests for TenantAutoProvisioner.
//
// All tests use miniredis so no real Redis instance is required.

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// fakeLangfuse is a simple in-process stub for LangfuseProvisioner.
type fakeLangfuse struct {
	calls  []string
	retErr error
}

func (f *fakeLangfuse) CreateProject(_ context.Context, tenantID string) error {
	f.calls = append(f.calls, tenantID)
	return f.retErr
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestAutoProvisioner(t *testing.T) (*TenantAutoProvisioner, *TenantService, *miniredis.Miniredis) {
	t.Helper()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := NewTenantService(client, logger, nil)
	prov := NewTenantAutoProvisioner(svc, nil, nil, nil, logger)
	return prov, svc, mr
}

// ---------------------------------------------------------------------------
// EnsureTenant — tenant does not exist
// ---------------------------------------------------------------------------

func TestTenantAutoProvisioner_EnsureTenant_CreatesWhenMissing(t *testing.T) {
	prov, svc, _ := newTestAutoProvisioner(t)

	err := prov.EnsureTenant(context.Background(), "acme")
	require.NoError(t, err)

	// Confirm the record was actually stored by reading directly via fetchTenant.
	record, err := svc.fetchTenant(context.Background(), "acme")
	require.NoError(t, err)
	assert.Equal(t, "acme", record.TenantID)
	assert.Equal(t, "active", record.Status)
	assert.Equal(t, "true", record.Config["auto_provisioned"])
}

// ---------------------------------------------------------------------------
// EnsureTenant — tenant already exists
// ---------------------------------------------------------------------------

func TestTenantAutoProvisioner_EnsureTenant_IdempotentWhenExists(t *testing.T) {
	prov, _, mr := newTestAutoProvisioner(t)

	// Pre-seed a tenant so it already exists.
	seedTenant(t, mr, "acme", "ACME Corp")

	err := prov.EnsureTenant(context.Background(), "acme")
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// EnsureTenant — second sequential call (same tenant already created)
// ---------------------------------------------------------------------------

func TestTenantAutoProvisioner_EnsureTenant_SecondCallAfterCreation(t *testing.T) {
	prov, _, _ := newTestAutoProvisioner(t)

	// First call creates the tenant.
	require.NoError(t, prov.EnsureTenant(context.Background(), "globex"))

	// Second call should see the tenant exists and return immediately.
	err := prov.EnsureTenant(context.Background(), "globex")
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// EnsureTenant — Langfuse success path
// ---------------------------------------------------------------------------

func TestTenantAutoProvisioner_EnsureTenant_CallsLangfuse(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := NewTenantService(client, logger, nil)
	lf := &fakeLangfuse{}
	prov := NewTenantAutoProvisioner(svc, nil, lf, nil, logger)

	err := prov.EnsureTenant(context.Background(), "wayne-enterprises")
	require.NoError(t, err)

	assert.Equal(t, []string{"wayne-enterprises"}, lf.calls,
		"Langfuse CreateProject must be called once with the new tenant ID")
}

// ---------------------------------------------------------------------------
// EnsureTenant — Langfuse failure is non-fatal
// ---------------------------------------------------------------------------

func TestTenantAutoProvisioner_EnsureTenant_LangfuseFailureIsNonFatal(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := NewTenantService(client, logger, nil)
	lf := &fakeLangfuse{retErr: errors.New("langfuse unavailable")}
	prov := NewTenantAutoProvisioner(svc, nil, lf, nil, logger)

	// Despite Langfuse failing, EnsureTenant must succeed.
	err := prov.EnsureTenant(context.Background(), "stark-industries")
	require.NoError(t, err, "Langfuse failure must not propagate as an error")

	// Tenant record must still exist.
	record, err := svc.fetchTenant(context.Background(), "stark-industries")
	require.NoError(t, err)
	assert.Equal(t, "stark-industries", record.TenantID)
}

// ---------------------------------------------------------------------------
// EnsureTenant — nil Langfuse provisioner
// ---------------------------------------------------------------------------

func TestTenantAutoProvisioner_EnsureTenant_NilLangfuseIsSkipped(t *testing.T) {
	prov, svc, _ := newTestAutoProvisioner(t) // langfuse is nil

	err := prov.EnsureTenant(context.Background(), "umbrella-corp")
	require.NoError(t, err)

	record, err := svc.fetchTenant(context.Background(), "umbrella-corp")
	require.NoError(t, err)
	assert.Equal(t, "umbrella-corp", record.TenantID)
}

// ---------------------------------------------------------------------------
// waitForProvisioning — timeout
// ---------------------------------------------------------------------------

func TestTenantAutoProvisioner_WaitForProvisioning_Timeout(t *testing.T) {
	prov, _, _ := newTestAutoProvisioner(t)

	// "missing-corp" is never created, so waitForProvisioning must time out.
	err := prov.waitForProvisioning(context.Background(), "missing-corp", 600*time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
}

// ---------------------------------------------------------------------------
// waitForProvisioning — returns nil once tenant appears
// ---------------------------------------------------------------------------

func TestTenantAutoProvisioner_WaitForProvisioning_SucceedsWhenTenantAppears(t *testing.T) {
	prov, _, mr := newTestAutoProvisioner(t)

	// Seed the tenant after a short delay (simulating a concurrent provisioner).
	go func() {
		time.Sleep(200 * time.Millisecond)
		seedTenant(t, mr, "late-corp", "Late Corp")
	}()

	err := prov.waitForProvisioning(context.Background(), "late-corp", 2*time.Second)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// waitForProvisioning — context cancellation
// ---------------------------------------------------------------------------

func TestTenantAutoProvisioner_WaitForProvisioning_ContextCancelled(t *testing.T) {
	prov, _, _ := newTestAutoProvisioner(t)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	err := prov.waitForProvisioning(ctx, "never-created", 5*time.Second)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}
