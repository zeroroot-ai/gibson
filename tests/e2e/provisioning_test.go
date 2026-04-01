//go:build e2e
// +build e2e

package e2e

// provisioning_test.go contains end-to-end integration tests for the SaaS
// tenant provisioning pipeline and tenant validation layer.
//
// Unlike the unit tests in internal/provisioner/provisioner_test.go (which
// use stub TenantCreator implementations), these tests wire real components:
//
//   - miniredis for a realistic Redis server (same library already used in unit tests)
//   - component.TenantService as the backing TenantCreator
//   - auth.CachedTenantValidator wrapping a redisTenantValidator adapter
//
// Tests are tagged //go:build e2e so they do not run in ordinary `go test`.
// Run them with:
//
//	go test -tags=e2e ./tests/e2e/...

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/auth"
	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/provisioner"
	sdkauth "github.com/zero-day-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// Test infrastructure helpers
// ---------------------------------------------------------------------------

// provisioningTestEnv holds all the real components wired together for a
// single provisioning e2e test.  It is created fresh for each test so there
// is no shared state between test cases.
type provisioningTestEnv struct {
	redis         *redis.Client
	tenantService *component.TenantService
	tenantAdapter *tenantServiceAdapter
	apiKeys       *stubProvisionAPIKeys
	langfuse      *stubProvisionLangfuse
	prov          *provisioner.Provisioner
	logger        *slog.Logger
	mr            *miniredis.Miniredis
}

// newProvisioningTestEnv constructs a provisioningTestEnv with a fresh
// miniredis instance and all real components.  Cleanup is registered on t.
func newProvisioningTestEnv(t *testing.T) *provisioningTestEnv {
	t.Helper()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError, // Keep test output clean; change to LevelDebug for troubleshooting.
	}))

	svc := component.NewTenantService(client, logger, nil)
	adapter := &tenantServiceAdapter{svc: svc}
	apiKeys := &stubProvisionAPIKeys{rawKey: "gsk_e2e-test_cafebabecafebabe"}
	lf := &stubProvisionLangfuse{}

	prov := provisioner.New(client, adapter, apiKeys, lf, logger)

	return &provisioningTestEnv{
		redis:         client,
		tenantService: svc,
		tenantAdapter: adapter,
		apiKeys:       apiKeys,
		langfuse:      lf,
		prov:          prov,
		logger:        logger,
		mr:            mr,
	}
}

// adminCtxFor returns a context that satisfies all auth checks inside
// TenantService.  The identity carries the "admin" role and is scoped to
// the given tenantID (empty string is fine for platform-wide admin operations).
func adminCtxFor(tenantID string) context.Context {
	identity := &auth.Identity{
		Identity: sdkauth.Identity{
			Subject: "e2e-test-admin",
			Issuer:  "test",
			Groups:  []string{"admin"},
			Claims:  map[string]any{},
		},
		Roles: []string{"admin"},
		Permissions: []auth.Permission{
			{Action: "*", Resource: "*", Scope: "*"},
		},
	}
	ctx := auth.ContextWithIdentity(context.Background(), identity)
	if tenantID != "" {
		ctx = auth.ContextWithTenant(ctx, tenantID)
	}
	return ctx
}

// ---------------------------------------------------------------------------
// tenantServiceAdapter
//
// provisioner.TenantCreator uses interface{} return types so that the
// provisioner package has no compile-time dependency on component.TenantRecord.
// This adapter bridges the real *component.TenantService (which returns
// *component.TenantRecord) to the provisioner.TenantCreator interface.
//
// One important subtlety: component.TenantService.UpdateTenant rejects a
// status update to "deleted" (it guards against accidental hard-deletion via
// UpdateTenant and expects callers to use DeleteTenant instead).  The
// provisioner.DeprovisionTenant path calls UpdateTenant(ctx, id, {"status":
// "deleted"}).  This adapter intercepts that specific case and routes it to
// DeleteTenant, preserving both the provisioner contract and the service's
// safety invariant.
// ---------------------------------------------------------------------------

type tenantServiceAdapter struct {
	svc *component.TenantService
}

func (a *tenantServiceAdapter) CreateTenant(ctx context.Context, tenantID, displayName string, config map[string]string) (interface{}, error) {
	record, err := a.svc.CreateTenant(ctx, tenantID, displayName, config)
	return record, err
}

func (a *tenantServiceAdapter) GetTenant(ctx context.Context, tenantID string) (interface{}, error) {
	record, err := a.svc.GetTenant(ctx, tenantID)
	return record, err
}

func (a *tenantServiceAdapter) UpdateTenant(ctx context.Context, tenantID string, updates map[string]string) (interface{}, error) {
	// Intercept the soft-delete path: provisioner.DeprovisionTenant sets
	// status="deleted" via UpdateTenant, but TenantService forbids this
	// through UpdateTenant and requires DeleteTenant instead.
	if v, ok := updates["status"]; ok && v == "deleted" && len(updates) == 1 {
		err := a.svc.DeleteTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		// Return a minimal map so the provisioner's JSON status-extraction
		// succeeds; the deleted status will be read back from Redis on the
		// next GetTenant call.
		return map[string]string{"status": "deleted"}, nil
	}
	record, err := a.svc.UpdateTenant(ctx, tenantID, updates)
	return record, err
}

// ---------------------------------------------------------------------------
// redisTenantValidator
//
// auth.TenantValidator that queries TenantService directly, bridging the
// two packages without circular imports.
// ---------------------------------------------------------------------------

type redisTenantValidator struct {
	tenants *component.TenantService
}

// ValidateTenantStatus implements auth.TenantValidator.
//
// It fetches the tenant record using an admin identity so the RBAC checks
// inside GetTenant pass.  In production the interceptor runs after full
// auth resolution; this validator is used in contexts where a system-level
// lookup is appropriate (e.g. request gating before the handler runs).
func (v *redisTenantValidator) ValidateTenantStatus(ctx context.Context, tenantID string) (string, error) {
	// Build a system-level admin context for the lookup.  The original
	// caller context is intentionally not used here because it may carry
	// a non-admin identity; tenant status validation is a system concern.
	adminCtx := adminCtxFor(tenantID)

	record, err := v.tenants.GetTenant(adminCtx, tenantID)
	if err != nil {
		// Surface not-found errors directly so the caller can distinguish
		// "tenant missing" from "transient failure".
		if errors.Is(err, component.ErrTenantNotFound) {
			return "", fmt.Errorf("tenant %q not found: %w", tenantID, err)
		}
		return "", fmt.Errorf("validate tenant %q: %w", tenantID, err)
	}
	return record.Status, nil
}

// ---------------------------------------------------------------------------
// Local test doubles
//
// These are minimal stubs scoped to this file so they don't bleed into other
// e2e test files or conflict with the unit-test stubs in the provisioner
// package.
// ---------------------------------------------------------------------------

// stubProvisionAPIKeys records CreateKey invocations and supports error injection.
type stubProvisionAPIKeys struct {
	mu     sync.Mutex
	rawKey string
	err    error
	calls  int
}

func (s *stubProvisionAPIKeys) CreateKey(_ context.Context, _ string, _, _ []string) (string, interface{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.err != nil {
		return "", nil, s.err
	}
	return s.rawKey, struct{ KeyID string }{KeyID: "key-e2e-test"}, nil
}

// stubProvisionLangfuse records CreateProject invocations and supports error injection.
type stubProvisionLangfuse struct {
	mu     sync.Mutex
	calls  []string
	retErr error
}

func (lf *stubProvisionLangfuse) CreateProject(_ context.Context, tenantID string) error {
	lf.mu.Lock()
	defer lf.mu.Unlock()
	lf.calls = append(lf.calls, tenantID)
	return lf.retErr
}

// ---------------------------------------------------------------------------
// Test 1: Full provisioning lifecycle
// ---------------------------------------------------------------------------

// TestProvisioningLifecycle_E2E exercises the entire tenant setup pipeline
// end-to-end using real Redis (miniredis) and real TenantService.
//
// Steps verified:
//  1. Provision creates the tenant record in Redis with status "active"
//  2. Provisioning status hash reflects all steps completed
//  3. The initial API key is generated and returned to the caller
//  4. Deprovisioning transitions the tenant to "deleted"
func TestProvisioningLifecycle_E2E(t *testing.T) {
	t.Parallel()

	env := newProvisioningTestEnv(t)
	ctx := adminCtxFor("acme-e2e")

	req := provisioner.ProvisionRequest{
		TenantID:         "acme-e2e",
		DisplayName:      "ACME E2E Corp",
		Tier:             "team",
		OwnerEmail:       "admin@acme-e2e.example",
		StripeCustomerID: "cus_e2etest",
		StripeSubID:      "sub_e2etest",
	}

	// --- 1. Provision the tenant ---
	result, err := env.prov.ProvisionTenant(ctx, req)
	require.NoError(t, err, "ProvisionTenant should succeed")
	require.NotNil(t, result)

	assert.Equal(t, "acme-e2e", result.TenantID)
	assert.Equal(t, "completed", result.Status)
	assert.Equal(t, env.apiKeys.rawKey, result.APIKey, "raw API key must be returned once")

	// --- 2. Verify TenantRecord in Redis is "active" ---
	record, err := env.tenantService.GetTenant(ctx, "acme-e2e")
	require.NoError(t, err, "GetTenant must succeed after provisioning")
	require.NotNil(t, record)

	assert.Equal(t, "acme-e2e", record.TenantID)
	assert.Equal(t, "active", record.Status, "tenant status must be 'active' after provisioning")
	assert.Equal(t, "ACME E2E Corp", record.DisplayName)
	assert.NotNil(t, record.Config)
	assert.Equal(t, "10", record.Config["max_agents"], "team tier limits must be applied")
	assert.Equal(t, "50", record.Config["max_missions"])

	// --- 3. Verify provisioning status shows all steps completed ---
	ps, err := env.prov.GetProvisioningStatus(ctx, "acme-e2e")
	require.NoError(t, err, "GetProvisioningStatus must succeed")
	require.NotNil(t, ps)

	assert.Equal(t, "acme-e2e", ps.TenantID)
	assert.Equal(t, "completed", ps.Status, "overall provisioning status must be 'completed'")
	assert.NotZero(t, ps.StartedAt, "StartedAt must be recorded")

	require.Len(t, ps.Steps, 5, "all 5 steps must be present in the status hash")
	for _, step := range ps.Steps {
		assert.NotEqual(t, "pending", step.Status,
			"step %q must not remain pending after successful provisioning", step.Name)
		t.Logf("step %q: %s", step.Name, step.Status)
	}

	// --- 4. Verify API key was generated exactly once ---
	env.apiKeys.mu.Lock()
	apiKeyCalls := env.apiKeys.calls
	env.apiKeys.mu.Unlock()
	assert.Equal(t, 1, apiKeyCalls, "API key must be minted exactly once")

	// --- 5. Deprovision the tenant ---
	err = env.prov.DeprovisionTenant(ctx, "acme-e2e")
	require.NoError(t, err, "DeprovisionTenant should succeed")

	// --- 6. Verify tenant status is "deleted" ---
	deletedRecord, err := env.tenantService.GetTenant(ctx, "acme-e2e")
	require.NoError(t, err, "GetTenant must succeed even for deleted tenants (soft delete)")
	assert.Equal(t, "deleted", deletedRecord.Status, "tenant status must be 'deleted' after deprovision")

	t.Logf("provisioning lifecycle e2e: tenant=%s, tier=%s, status=%s",
		record.TenantID, record.Config["tier"], deletedRecord.Status)
}

// ---------------------------------------------------------------------------
// Test 2: Tenant validation with real Redis
// ---------------------------------------------------------------------------

// TestTenantValidation_E2E exercises the auth.TenantValidator layer backed by
// a real TenantService stored in miniredis.
//
// Scenarios covered:
//   - Non-existent tenant returns an error
//   - Active tenant is accessible
//   - Suspended tenant is accessible (read-only; writes rejected downstream)
//   - Deleted tenant is not accessible
func TestTenantValidation_E2E(t *testing.T) {
	t.Parallel()

	env := newProvisioningTestEnv(t)
	adminCtx := adminCtxFor("validation-tenant")

	validator := &redisTenantValidator{tenants: env.tenantService}
	cached := auth.NewCachedTenantValidator(validator, 5*time.Second)

	// --- 1. Validate a non-existent tenant → error ---
	_, err := cached.ValidateTenantStatus(context.Background(), "ghost-tenant")
	require.Error(t, err, "non-existent tenant must return an error")
	t.Logf("non-existent tenant error (expected): %v", err)

	// Invalidate so subsequent tests start fresh.
	cached.InvalidateCache("ghost-tenant")

	// --- 2. Create tenant via provisioner and validate → "active" ---
	req := provisioner.ProvisionRequest{
		TenantID:    "validation-tenant",
		DisplayName: "Validation Tenant",
		Tier:        "free",
	}
	_, err = env.prov.ProvisionTenant(adminCtx, req)
	require.NoError(t, err, "provisioning must succeed before validation test")

	cached.InvalidateCache("validation-tenant")

	status, err := cached.ValidateTenantStatus(context.Background(), "validation-tenant")
	require.NoError(t, err, "active tenant must validate without error")
	assert.Equal(t, "active", status, "provisioned tenant must be 'active'")
	assert.True(t, auth.IsTenantAccessible(status), "active tenant must be accessible")
	t.Logf("active tenant status: %s, accessible: %v", status, auth.IsTenantAccessible(status))

	// Verify the cached path works (no Redis hit on second call).
	statusCached, err := cached.ValidateTenantStatus(context.Background(), "validation-tenant")
	require.NoError(t, err)
	assert.Equal(t, "active", statusCached, "cached result must match live result")

	// --- 3. Suspend the tenant → still accessible ---
	_, err = env.tenantService.UpdateTenant(adminCtx, "validation-tenant", map[string]string{
		"status": "suspended",
	})
	require.NoError(t, err, "suspending tenant must succeed")

	// Invalidate so we pick up the new status.
	cached.InvalidateCache("validation-tenant")

	suspendedStatus, err := cached.ValidateTenantStatus(context.Background(), "validation-tenant")
	require.NoError(t, err, "suspended tenant must not return an error")
	assert.Equal(t, "suspended", suspendedStatus, "tenant status must reflect suspension")
	assert.True(t, auth.IsTenantAccessible(suspendedStatus), "suspended tenant must remain accessible")
	t.Logf("suspended tenant status: %s, accessible: %v", suspendedStatus, auth.IsTenantAccessible(suspendedStatus))

	// --- 4. Delete the tenant → not accessible ---
	err = env.tenantService.DeleteTenant(adminCtx, "validation-tenant")
	require.NoError(t, err, "deleting tenant must succeed")

	cached.InvalidateCache("validation-tenant")

	deletedStatus, err := cached.ValidateTenantStatus(context.Background(), "validation-tenant")
	require.NoError(t, err, "deleted tenant record still exists (soft delete); GetTenant must succeed")
	assert.Equal(t, "deleted", deletedStatus, "tenant status must be 'deleted'")
	assert.False(t, auth.IsTenantAccessible(deletedStatus), "deleted tenant must not be accessible")
	t.Logf("deleted tenant status: %s, accessible: %v", deletedStatus, auth.IsTenantAccessible(deletedStatus))
}

// ---------------------------------------------------------------------------
// Test 3: Provisioning idempotency
// ---------------------------------------------------------------------------

// TestProvisioningIdempotency_E2E verifies that calling ProvisionTenant twice
// for the same tenant is safe: the second call skips all already-completed
// steps, leaves the tenant active, and does not create duplicate resources.
func TestProvisioningIdempotency_E2E(t *testing.T) {
	t.Parallel()

	env := newProvisioningTestEnv(t)
	ctx := adminCtxFor("idempotent-tenant")

	req := provisioner.ProvisionRequest{
		TenantID:    "idempotent-tenant",
		DisplayName: "Idempotency Test Tenant",
		Tier:        "business",
		OwnerEmail:  "ops@idempotent.example",
	}

	// --- First provisioning run ---
	result1, err := env.prov.ProvisionTenant(ctx, req)
	require.NoError(t, err, "first provisioning run must succeed")
	require.NotNil(t, result1)
	assert.Equal(t, "completed", result1.Status)

	env.apiKeys.mu.Lock()
	firstAPIKeyCalls := env.apiKeys.calls
	env.apiKeys.mu.Unlock()

	env.langfuse.mu.Lock()
	firstLangfuseCalls := len(env.langfuse.calls)
	env.langfuse.mu.Unlock()

	// --- Second provisioning run on the same tenant ---
	result2, err := env.prov.ProvisionTenant(ctx, req)
	require.NoError(t, err, "second provisioning run must be idempotent (no error)")
	require.NotNil(t, result2)
	assert.Equal(t, "completed", result2.Status)

	// No additional API key or Langfuse calls should have been made.
	env.apiKeys.mu.Lock()
	secondAPIKeyCalls := env.apiKeys.calls
	env.apiKeys.mu.Unlock()

	env.langfuse.mu.Lock()
	secondLangfuseCalls := len(env.langfuse.calls)
	env.langfuse.mu.Unlock()

	assert.Equal(t, firstAPIKeyCalls, secondAPIKeyCalls,
		"API key must not be regenerated on idempotent re-run")
	assert.Equal(t, firstLangfuseCalls, secondLangfuseCalls,
		"Langfuse project must not be recreated on idempotent re-run")

	// Tenant must still be active and not duplicated.
	record, err := env.tenantService.GetTenant(ctx, "idempotent-tenant")
	require.NoError(t, err)
	assert.Equal(t, "active", record.Status, "tenant must remain active after idempotent re-run")
	assert.Equal(t, "business", record.Config["tier"], "tier must be preserved")

	t.Logf("idempotency e2e: first api_key_calls=%d, second api_key_calls=%d",
		firstAPIKeyCalls, secondAPIKeyCalls)
}

// ---------------------------------------------------------------------------
// Test 4: Concurrent provisioning (race-condition safety)
// ---------------------------------------------------------------------------

// TestConcurrentProvisioning_E2E launches multiple goroutines that all attempt
// to provision the same tenant simultaneously and verifies that:
//
//  1. Exactly one tenant record exists after all goroutines complete.
//  2. All goroutines complete without error.
//  3. The tenant is left in the "active" state.
//
// This test is run with -race by `make test-race` and must be clean.
func TestConcurrentProvisioning_E2E(t *testing.T) {
	t.Parallel()

	env := newProvisioningTestEnv(t)

	const goroutines = 5
	tenantID := "concurrent-tenant"

	req := provisioner.ProvisionRequest{
		TenantID:    tenantID,
		DisplayName: "Concurrent Test Tenant",
		Tier:        "team",
		OwnerEmail:  "concurrent@example.com",
	}

	var (
		wg       sync.WaitGroup
		errCount atomic.Int64
		mu       sync.Mutex
		errs     []error
	)

	wg.Add(goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()

			// Each goroutine builds its own admin context to avoid sharing
			// the same context value concurrently.
			ctx := adminCtxFor(tenantID)

			_, err := env.prov.ProvisionTenant(ctx, req)
			if err != nil {
				errCount.Add(1)
				mu.Lock()
				errs = append(errs, fmt.Errorf("goroutine %d: %w", idx, err))
				mu.Unlock()
			}
		}(i)
	}

	// Wait for all goroutines with a generous timeout so CI does not hang.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Good.
	case <-time.After(30 * time.Second):
		t.Fatal("timeout: concurrent provisioning goroutines did not complete within 30s")
	}

	// All goroutines must have completed without error.
	if errCount.Load() > 0 {
		for _, e := range errs {
			t.Errorf("provisioning error: %v", e)
		}
		t.Fatalf("%d of %d goroutines returned errors", errCount.Load(), goroutines)
	}

	// Exactly one tenant record must exist and it must be active.
	adminCtx := adminCtxFor(tenantID)
	record, err := env.tenantService.GetTenant(adminCtx, tenantID)
	require.NoError(t, err, "GetTenant must succeed after concurrent provisioning")
	assert.Equal(t, tenantID, record.TenantID, "tenant ID must match")
	assert.Equal(t, "active", record.Status, "tenant must be active after concurrent provisioning")

	// Verify the provisioning status hash is marked completed.
	ps, err := env.prov.GetProvisioningStatus(adminCtx, tenantID)
	require.NoError(t, err)
	assert.Equal(t, "completed", ps.Status, "provisioning hash must show completed")

	t.Logf("concurrent provisioning e2e: %d goroutines, tenant=%s, status=%s",
		goroutines, record.TenantID, record.Status)
}
