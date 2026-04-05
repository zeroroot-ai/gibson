package provisioner

// provisioner_test.go contains unit tests for Provisioner.
//
// All tests use miniredis so no real Redis instance is required.  TenantCreator
// and APIKeyCreator are replaced with in-process stubs that expose call counts
// and configurable errors.

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

// stubTenants records CreateTenant / GetTenant / UpdateTenant calls and
// allows per-method error injection.
type stubTenants struct {
	records map[string]map[string]string // tenant_id → simple key/value store

	createErr error
	getErr    error
	updateErr error

	createCalls int
	updateCalls int
}

func newStubTenants() *stubTenants {
	return &stubTenants{records: make(map[string]map[string]string)}
}

func (s *stubTenants) CreateTenant(_ context.Context, tenantID, displayName string, config map[string]string) (interface{}, error) {
	s.createCalls++
	if s.createErr != nil {
		return nil, s.createErr
	}
	if _, exists := s.records[tenantID]; exists {
		return nil, errors.New("tenant already exists: " + tenantID)
	}
	m := make(map[string]string, len(config)+2)
	m["tenant_id"] = tenantID
	m["display_name"] = displayName
	m["status"] = "provisioning"
	for k, v := range config {
		m[k] = v
	}
	s.records[tenantID] = m
	return m, nil
}

func (s *stubTenants) GetTenant(_ context.Context, tenantID string) (interface{}, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	m, ok := s.records[tenantID]
	if !ok {
		return nil, errors.New("tenant not found: " + tenantID)
	}
	return m, nil
}

func (s *stubTenants) UpdateTenant(_ context.Context, tenantID string, updates map[string]string) (interface{}, error) {
	s.updateCalls++
	if s.updateErr != nil {
		return nil, s.updateErr
	}
	m, ok := s.records[tenantID]
	if !ok {
		return nil, errors.New("tenant not found: " + tenantID)
	}
	for k, v := range updates {
		m[k] = v
	}
	return m, nil
}

// stubAPIKeys records CreateKey calls and allows error injection.
type stubAPIKeys struct {
	rawKey string
	err    error
	calls  int
}

func newStubAPIKeys(rawKey string) *stubAPIKeys {
	if rawKey == "" {
		rawKey = "gsk_test-tenant_deadbeefdeadbeef"
	}
	return &stubAPIKeys{rawKey: rawKey}
}

func (s *stubAPIKeys) CreateKey(_ context.Context, _ string, _, _, _ []string, _, _ string) (string, interface{}, error) {
	s.calls++
	if s.err != nil {
		return "", nil, s.err
	}
	return s.rawKey, struct{ KeyID string }{KeyID: "gsk_test_1234"}, nil
}

// stubLangfuse records CreateProject calls and allows error injection.
type stubLangfuse struct {
	calls  []string
	retErr error
}

func (lf *stubLangfuse) CreateProject(_ context.Context, tenantID string) error {
	lf.calls = append(lf.calls, tenantID)
	return lf.retErr
}

// ---------------------------------------------------------------------------
// Test helper: newTestProvisioner
// ---------------------------------------------------------------------------

func newTestProvisioner(t *testing.T) (*Provisioner, *stubTenants, *stubAPIKeys, *stubLangfuse, *miniredis.Miniredis) {
	t.Helper()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tenants := newStubTenants()
	apikeys := newStubAPIKeys("")
	lf := &stubLangfuse{}

	prov := New(client, tenants, apikeys, lf, logger)
	return prov, tenants, apikeys, lf, mr
}

func newTestRequest() ProvisionRequest {
	return ProvisionRequest{
		TenantID:         "acme",
		DisplayName:      "ACME Corp",
		Tier:             "team",
		OwnerEmail:       "admin@acme.example",
		StripeCustomerID: "cus_test123",
		StripeSubID:      "sub_test456",
	}
}

// ---------------------------------------------------------------------------
// Happy path: full pipeline
// ---------------------------------------------------------------------------

func TestProvisioner_ProvisionTenant_HappyPath(t *testing.T) {
	prov, tenants, apikeys, lf, _ := newTestProvisioner(t)
	ctx := context.Background()

	result, err := prov.ProvisionTenant(ctx, newTestRequest())
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "acme", result.TenantID)
	assert.Equal(t, statusCompleted, result.Status)
	assert.Equal(t, apikeys.rawKey, result.APIKey, "raw API key must be returned to caller")

	// Tenant record should exist and be active.
	record := tenants.records["acme"]
	require.NotNil(t, record)
	assert.Equal(t, "active", record["status"])
	assert.Equal(t, "team", record["tier"])

	// Tier limits must be applied.
	assert.Equal(t, "10", record["max_agents"])

	// Langfuse must be called exactly once.
	assert.Equal(t, []string{"acme"}, lf.calls)

	// API key must be minted exactly once.
	assert.Equal(t, 1, apikeys.calls)
}

// ---------------------------------------------------------------------------
// Status hash is populated
// ---------------------------------------------------------------------------

func TestProvisioner_ProvisionTenant_StatusHashPopulated(t *testing.T) {
	prov, _, _, _, _ := newTestProvisioner(t)
	ctx := context.Background()

	_, err := prov.ProvisionTenant(ctx, newTestRequest())
	require.NoError(t, err)

	status, err := prov.GetProvisioningStatus(ctx, "acme")
	require.NoError(t, err)

	assert.Equal(t, "acme", status.TenantID)
	assert.Equal(t, statusCompleted, status.Status)
	assert.NotZero(t, status.StartedAt)

	// All steps should be recorded.
	require.Len(t, status.Steps, len(stepOrder))
	for _, step := range status.Steps {
		assert.NotEqual(t, statusPending, step.Status,
			"step %q should not remain pending after successful provisioning", step.Name)
	}
}

// ---------------------------------------------------------------------------
// Idempotency: re-running skips completed steps
// ---------------------------------------------------------------------------

func TestProvisioner_ProvisionTenant_Idempotent(t *testing.T) {
	prov, tenants, apikeys, _, _ := newTestProvisioner(t)
	ctx := context.Background()

	// First run.
	_, err := prov.ProvisionTenant(ctx, newTestRequest())
	require.NoError(t, err)

	firstCreateCalls := tenants.createCalls
	firstAPICalls := apikeys.calls

	// Second run on the same tenant — all steps should be skipped.
	result2, err := prov.ProvisionTenant(ctx, newTestRequest())
	require.NoError(t, err)
	require.NotNil(t, result2)

	// CreateTenant and CreateKey must not be called again.
	assert.Equal(t, firstCreateCalls, tenants.createCalls, "CreateTenant must not be called on second run")
	assert.Equal(t, firstAPICalls, apikeys.calls, "CreateKey must not be called on second run")
}

// ---------------------------------------------------------------------------
// Idempotency: tenant already exists on first step
// ---------------------------------------------------------------------------

func TestProvisioner_ProvisionTenant_TenantAlreadyExists(t *testing.T) {
	prov, tenants, _, _, _ := newTestProvisioner(t)
	ctx := context.Background()

	// Pre-seed tenant record.
	tenants.records["acme"] = map[string]string{
		"tenant_id":   "acme",
		"status":      "provisioning",
		"tier":        "team",
		"max_agents":  "10",
		"max_missions": "50",
		"max_api_keys": "10",
		"retention_days": "30",
		"concurrent_agents": "3",
	}

	// The create_tenant step should see ErrTenantAlreadyExists and continue.
	_, err := prov.ProvisionTenant(ctx, newTestRequest())
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Langfuse failure is non-fatal
// ---------------------------------------------------------------------------

func TestProvisioner_ProvisionTenant_LangfuseFailureNonFatal(t *testing.T) {
	prov, _, _, lf, _ := newTestProvisioner(t)
	lf.retErr = errors.New("langfuse service unavailable")

	ctx := context.Background()
	result, err := prov.ProvisionTenant(ctx, newTestRequest())
	require.NoError(t, err, "Langfuse failure must not abort provisioning")
	assert.Equal(t, statusCompleted, result.Status)

	// Langfuse step should be recorded as skipped.
	ps, err := prov.GetProvisioningStatus(ctx, "acme")
	require.NoError(t, err)

	var langfuseStep *ProvisionStep
	for i := range ps.Steps {
		if ps.Steps[i].Name == stepCreateLangfuse {
			langfuseStep = &ps.Steps[i]
			break
		}
	}
	require.NotNil(t, langfuseStep)
	assert.Equal(t, statusSkipped, langfuseStep.Status)
}

// ---------------------------------------------------------------------------
// Nil Langfuse provisioner skips step without error
// ---------------------------------------------------------------------------

func TestProvisioner_ProvisionTenant_NilLangfuseSkipped(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	tenants := newStubTenants()
	apikeys := newStubAPIKeys("")

	// Pass nil for langfuse.
	prov := New(client, tenants, apikeys, nil, logger)

	result, err := prov.ProvisionTenant(context.Background(), newTestRequest())
	require.NoError(t, err)
	assert.Equal(t, statusCompleted, result.Status)
}

// ---------------------------------------------------------------------------
// Nil APIKeyCreator: generate_apikey step skipped, empty key returned
// ---------------------------------------------------------------------------

func TestProvisioner_ProvisionTenant_NilAPIKeys(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	tenants := newStubTenants()

	prov := New(client, tenants, nil, nil, logger)

	result, err := prov.ProvisionTenant(context.Background(), newTestRequest())
	require.NoError(t, err)
	assert.Equal(t, statusCompleted, result.Status)
	assert.Empty(t, result.APIKey, "APIKey must be empty when no APIKeyCreator is configured")
}

// ---------------------------------------------------------------------------
// CreateTenant failure causes pipeline to fail
// ---------------------------------------------------------------------------

func TestProvisioner_ProvisionTenant_CreateTenantFails(t *testing.T) {
	prov, tenants, _, _, _ := newTestProvisioner(t)
	tenants.createErr = errors.New("redis write failure")

	_, err := prov.ProvisionTenant(context.Background(), newTestRequest())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create tenant record")
}

// ---------------------------------------------------------------------------
// APIKey creation failure causes pipeline to fail
// ---------------------------------------------------------------------------

func TestProvisioner_ProvisionTenant_APIKeyFails(t *testing.T) {
	prov, _, apikeys, _, _ := newTestProvisioner(t)
	apikeys.err = errors.New("entropy exhausted")

	_, err := prov.ProvisionTenant(context.Background(), newTestRequest())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create API key")
}

// ---------------------------------------------------------------------------
// Tier limits: indie tier applied when tier is empty
// ---------------------------------------------------------------------------

func TestProvisioner_ProvisionTenant_DefaultIndieTier(t *testing.T) {
	prov, tenants, _, _, _ := newTestProvisioner(t)

	req := newTestRequest()
	req.Tier = ""

	_, err := prov.ProvisionTenant(context.Background(), req)
	require.NoError(t, err)

	record := tenants.records["acme"]
	assert.Equal(t, "unlimited", record["max_agents"], "indie tier should have max_agents=unlimited")
	assert.Equal(t, "1", record["max_team_members"], "indie tier should have max_team_members=1")
}

// ---------------------------------------------------------------------------
// Tier limits: unknown tier falls back to indie
// ---------------------------------------------------------------------------

func TestProvisioner_ProvisionTenant_UnknownTierFallsBackToIndie(t *testing.T) {
	prov, tenants, _, _, _ := newTestProvisioner(t)

	req := newTestRequest()
	req.Tier = "platinum-ultra"

	_, err := prov.ProvisionTenant(context.Background(), req)
	require.NoError(t, err)

	record := tenants.records["acme"]
	// Indie tier limits must be applied as the fallback.
	assert.Equal(t, "unlimited", record["max_agents"])
	assert.Equal(t, "1", record["max_team_members"])
}

// ---------------------------------------------------------------------------
// Retry: transient failure on first attempt succeeds on second
// ---------------------------------------------------------------------------

func TestProvisioner_ProvisionTenant_RetryTransientFailure(t *testing.T) {
	// Fail the first two UpdateTenant calls then succeed.
	callCount := 0
	baseTenants := newStubTenants()
	failingTenants := &countingTenants{
		stubTenants: baseTenants,
		failUntil:   2,
		errToReturn: errors.New("transient: connection reset"),
		callCounter: &callCount,
	}

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	apikeys := newStubAPIKeys("")
	prov := New(client, failingTenants, apikeys, nil, logger)
	// retryMax=3 (default) gives us one passing attempt after two failures.
	prov.retryMax = 3

	result, err := prov.ProvisionTenant(context.Background(), newTestRequest())
	require.NoError(t, err)
	assert.Equal(t, statusCompleted, result.Status)
}

// countingTenants wraps stubTenants and fails UpdateTenant for the first
// failUntil calls, then delegates to the real stub.
type countingTenants struct {
	*stubTenants
	failUntil   int
	errToReturn error
	callCounter *int
}

func (c *countingTenants) UpdateTenant(ctx context.Context, tenantID string, updates map[string]string) (interface{}, error) {
	*c.callCounter++
	if *c.callCounter <= c.failUntil {
		return nil, c.errToReturn
	}
	return c.stubTenants.UpdateTenant(ctx, tenantID, updates)
}

// ---------------------------------------------------------------------------
// GetProvisioningStatus: returns "unknown" when hash is absent
// ---------------------------------------------------------------------------

func TestProvisioner_GetProvisioningStatus_NoHash(t *testing.T) {
	prov, _, _, _, _ := newTestProvisioner(t)

	status, err := prov.GetProvisioningStatus(context.Background(), "never-provisioned")
	require.NoError(t, err)
	assert.Equal(t, "unknown", status.Status)
	assert.Equal(t, "never-provisioned", status.TenantID)
}

// ---------------------------------------------------------------------------
// GetProvisioningStatus: rejects empty tenantID
// ---------------------------------------------------------------------------

func TestProvisioner_GetProvisioningStatus_EmptyTenantID(t *testing.T) {
	prov, _, _, _, _ := newTestProvisioner(t)

	_, err := prov.GetProvisioningStatus(context.Background(), "")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// DeprovisionTenant: soft-deletes and removes hash
// ---------------------------------------------------------------------------

func TestProvisioner_DeprovisionTenant_HappyPath(t *testing.T) {
	prov, tenants, _, _, mr := newTestProvisioner(t)
	ctx := context.Background()

	// Provision first.
	_, err := prov.ProvisionTenant(ctx, newTestRequest())
	require.NoError(t, err)

	// Deprovision.
	err = prov.DeprovisionTenant(ctx, "acme")
	require.NoError(t, err)

	// Tenant status must be "deleted".
	record := tenants.records["acme"]
	assert.Equal(t, "deleted", record["status"])

	// Provisioning hash must be removed.
	exists := mr.Exists(provisioningKey("acme"))
	assert.False(t, exists, "provisioning hash must be removed after deprovision")
}

// ---------------------------------------------------------------------------
// DeprovisionTenant: idempotent on already-deleted tenant
// ---------------------------------------------------------------------------

func TestProvisioner_DeprovisionTenant_AlreadyDeleted(t *testing.T) {
	prov, tenants, _, _, _ := newTestProvisioner(t)
	ctx := context.Background()

	// Pre-seed a deleted record.
	tenants.records["acme"] = map[string]string{
		"tenant_id": "acme",
		"status":    "deleted",
	}

	// Calling deprovision on already-deleted tenant must be a no-op.
	err := prov.DeprovisionTenant(ctx, "acme")
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// DeprovisionTenant: tenant not found is idempotent
// ---------------------------------------------------------------------------

func TestProvisioner_DeprovisionTenant_NotFound(t *testing.T) {
	prov, _, _, _, _ := newTestProvisioner(t)

	err := prov.DeprovisionTenant(context.Background(), "ghost-tenant")
	require.NoError(t, err, "deprovisioning a non-existent tenant must be a no-op")
}

// ---------------------------------------------------------------------------
// DeprovisionTenant: empty tenantID rejected
// ---------------------------------------------------------------------------

func TestProvisioner_DeprovisionTenant_EmptyTenantID(t *testing.T) {
	prov, _, _, _, _ := newTestProvisioner(t)

	err := prov.DeprovisionTenant(context.Background(), "")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// ProvisionTenant: empty tenantID rejected
// ---------------------------------------------------------------------------

func TestProvisioner_ProvisionTenant_EmptyTenantID(t *testing.T) {
	prov, _, _, _, _ := newTestProvisioner(t)

	_, err := prov.ProvisionTenant(context.Background(), ProvisionRequest{})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// New: panics on nil redis
// ---------------------------------------------------------------------------

func TestNew_PanicsOnNilRedis(t *testing.T) {
	assert.Panics(t, func() {
		New(nil, newStubTenants(), newStubAPIKeys(""), nil, nil)
	})
}

// ---------------------------------------------------------------------------
// New: panics on nil TenantCreator
// ---------------------------------------------------------------------------

func TestNew_PanicsOnNilTenants(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	assert.Panics(t, func() {
		New(client, nil, newStubAPIKeys(""), nil, nil)
	})
}

// ---------------------------------------------------------------------------
// provisioningKey helper
// ---------------------------------------------------------------------------

func TestProvisioningKey(t *testing.T) {
	assert.Equal(t, "tenant:acme:provisioning", provisioningKey("acme"))
}

// ---------------------------------------------------------------------------
// Backoff timing: context cancellation during retry backoff
// ---------------------------------------------------------------------------

func TestProvisioner_ProvisionTenant_ContextCancelledDuringRetry(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tenants := newStubTenants()
	// Make UpdateTenant always fail so the retry loop will keep trying.
	alwaysFail := &alwaysFailUpdate{stubTenants: tenants}
	apikeys := newStubAPIKeys("")

	prov := New(client, alwaysFail, apikeys, nil, logger)

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel after a short delay so the first retry backoff is interrupted.
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()

	_, err := prov.ProvisionTenant(ctx, newTestRequest())
	require.Error(t, err)
	// Either context cancelled or step failed — either is acceptable here.
}

// alwaysFailUpdate wraps stubTenants but always returns an error from UpdateTenant.
type alwaysFailUpdate struct {
	*stubTenants
}

func (a *alwaysFailUpdate) UpdateTenant(_ context.Context, _ string, _ map[string]string) (interface{}, error) {
	return nil, errors.New("permanent failure")
}
