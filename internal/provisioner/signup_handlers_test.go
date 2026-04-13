// Package provisioner — signup_handlers_test.go
//
// Unit tests for the SignupPipeline step handlers (handleFGA, handleProvision)
// and the failSignup helper. Tests run inside the provisioner package
// (white-box) so they can call unexported pipeline methods directly.
//
// Better Auth migration notes:
//   - handleOrg tests have been removed: the org step no longer exists.
//     Better Auth creates the organisation in the dashboard.
//   - handleFGA now consumes signup.requested events (not signup.org_created).
//   - The store field is typed as ProvisioningStateStore (interface); tests use
//     an in-memory stub rather than a miniredis-backed SignupStateStore.
//   - The kc KeycloakAdmin parameter has been removed from NewSignupPipeline.
package provisioner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/authz"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// mockAuthz is a minimal stub for authz.Authorizer.
type mockAuthz struct {
	writeErr   error
	writeCalls []authz.Tuple
	mu         sync.Mutex
}

func (m *mockAuthz) Check(_ context.Context, _, _, _ string) (bool, error)      { return true, nil }
func (m *mockAuthz) BatchCheck(_ context.Context, _ []authz.CheckRequest) ([]bool, error) {
	return nil, nil
}
func (m *mockAuthz) Write(_ context.Context, tuples []authz.Tuple) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writeCalls = append(m.writeCalls, tuples...)
	return m.writeErr
}
func (m *mockAuthz) Delete(_ context.Context, _ []authz.Tuple) error { return nil }
func (m *mockAuthz) ListObjects(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (m *mockAuthz) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (m *mockAuthz) StoreID() string { return "" }
func (m *mockAuthz) ModelID() string { return "" }
func (m *mockAuthz) Close() error    { return nil }

// memProvisioningStore is an in-memory ProvisioningStateStore for unit tests.
// It stores states in a map protected by a mutex.
type memProvisioningStore struct {
	mu     sync.Mutex
	states map[string]*SignupState
}

func newMemProvisioningStore() *memProvisioningStore {
	return &memProvisioningStore{states: make(map[string]*SignupState)}
}

func (m *memProvisioningStore) Create(ctx context.Context, userID string, state SignupState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	copy := state
	if copy.StepStatuses == nil {
		copy.StepStatuses = make(map[string]string)
	}
	m.states[userID] = &copy
	return nil
}

func (m *memProvisioningStore) Get(ctx context.Context, userID string) (*SignupState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.states[userID]
	if !ok {
		return nil, nil
	}
	// Return a copy.
	copy := *s
	if copy.StepStatuses != nil {
		ss := make(map[string]string, len(copy.StepStatuses))
		for k, v := range copy.StepStatuses {
			ss[k] = v
		}
		copy.StepStatuses = ss
	}
	return &copy, nil
}

func (m *memProvisioningStore) UpdateField(ctx context.Context, userID, field, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.states[userID]
	if !ok {
		return nil
	}
	switch field {
	case "status":
		s.Status = value
	case "current_step":
		s.CurrentStep = value
	case "error":
		s.Error = value
	case "step_status_fga":
		if s.StepStatuses == nil {
			s.StepStatuses = make(map[string]string)
		}
		s.StepStatuses["fga"] = value
	case "step_status_provision":
		if s.StepStatuses == nil {
			s.StepStatuses = make(map[string]string)
		}
		s.StepStatuses["provision"] = value
	}
	return nil
}

func (m *memProvisioningStore) IncrRetry(ctx context.Context, userID, step string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.states[userID]
	if !ok {
		return 0, errors.New("record not found")
	}
	retryKey := step + "_retry"
	if s.StepStatuses == nil {
		s.StepStatuses = make(map[string]string)
	}
	// Parse existing count, increment, store back.
	count := 0
	if v, exists := s.StepStatuses[retryKey]; exists {
		_, _ = fmt.Sscanf(v, "%d", &count)
	}
	count++
	s.StepStatuses[retryKey] = fmt.Sprintf("%d", count)
	return count, nil
}

func (m *memProvisioningStore) SetFailed(ctx context.Context, userID, step, errMsg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.states[userID]
	if !ok {
		return nil
	}
	s.Status = "failed"
	s.CurrentStep = step
	s.Error = errMsg
	return nil
}

func (m *memProvisioningStore) SetCompleted(ctx context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.states[userID]
	if !ok {
		return nil
	}
	s.Status = "active"
	return nil
}

// noopTenantCreator satisfies the TenantCreator interface with no-ops so
// Provisioner.ProvisionTenant can complete without real external services.
type noopTenantCreator struct{}

func (n *noopTenantCreator) CreateTenant(_ context.Context, _, _ string, _ map[string]string) (interface{}, error) {
	return map[string]string{"status": "ok"}, nil
}
func (n *noopTenantCreator) GetTenant(_ context.Context, _ string) (interface{}, error) {
	return map[string]string{"status": "ok"}, nil
}
func (n *noopTenantCreator) UpdateTenant(_ context.Context, _ string, _ map[string]string) (interface{}, error) {
	return map[string]string{"status": "ok"}, nil
}

// newTestMinimalProvisioner creates a *Provisioner backed by miniredis.
func newTestMinimalProvisioner(t *testing.T, mr *miniredis.Miniredis) *Provisioner {
	t.Helper()
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return New(rdb, &noopTenantCreator{}, nil, nil, logger)
}

// makeMsg builds a minimal goredis.XMessage for the given event type and userID.
func makeMsg(eventType, userID, tenantID string) goredis.XMessage {
	return goredis.XMessage{
		ID: "1-0",
		Values: map[string]interface{}{
			"event_type": eventType,
			"user_id":    userID,
			"tenant_id":  tenantID,
		},
	}
}

// seedState writes a minimal SignupState for userID into the store.
func seedState(t *testing.T, store ProvisioningStateStore, userID string, overrides SignupState) {
	t.Helper()
	ctx := context.Background()
	base := SignupState{
		Status:      "requested",
		Email:       "alice@example.com",
		CompanyName: "Acme Corp",
		TenantID:    "acme-corp",
		Plan:        "free",
		StepStatuses: map[string]string{
			"fga":       "pending",
			"provision": "pending",
		},
	}
	if overrides.Status != "" {
		base.Status = overrides.Status
	}
	if overrides.StepStatuses != nil {
		base.StepStatuses = overrides.StepStatuses
	}
	require.NoError(t, store.Create(ctx, userID, base))
}

// newTestPipeline creates a SignupPipeline with the given store and stubs.
func newTestPipeline(
	t *testing.T,
	mr *miniredis.Miniredis,
	az authz.Authorizer,
	prov *Provisioner,
	store ProvisioningStateStore,
) *SignupPipeline {
	t.Helper()

	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	return &SignupPipeline{
		redis:    rdb,
		authz:    az,
		prov:     prov,
		store:    store,
		logger:   logger,
		consumer: "test-pod",
	}
}

// ---------------------------------------------------------------------------
// TestHandleFGA_WriteTuple
// ---------------------------------------------------------------------------

func TestHandleFGA_WriteTuple(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)

	az := &mockAuthz{}
	prov := newTestMinimalProvisioner(t, mr)
	store := newMemProvisioningStore()

	p := newTestPipeline(t, mr, az, prov, store)
	seedState(t, store, "user-fga", SignupState{})

	// handleFGA now consumes signup.requested events.
	msg := makeMsg("signup.requested", "user-fga", "acme-corp")
	err := p.handleFGA(ctx, msg)
	require.NoError(t, err)

	az.mu.Lock()
	calls := az.writeCalls
	az.mu.Unlock()

	require.Len(t, calls, 1, "authz.Write must be called once")
	assert.Equal(t, "user:user-fga", calls[0].User)
	assert.Equal(t, "admin", calls[0].Relation)
	assert.Equal(t, "tenant:acme-corp", calls[0].Object)

	got, err := store.Get(ctx, "user-fga")
	require.NoError(t, err)
	assert.Equal(t, "completed", got.StepStatuses["fga"])
}

// ---------------------------------------------------------------------------
// TestHandleFGA_Idempotent
// ---------------------------------------------------------------------------

func TestHandleFGA_Idempotent(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)

	az := &mockAuthz{writeErr: errors.New("must not be called")}
	prov := newTestMinimalProvisioner(t, mr)
	store := newMemProvisioningStore()

	p := newTestPipeline(t, mr, az, prov, store)

	seedState(t, store, "user-fga-idem", SignupState{
		StepStatuses: map[string]string{
			"fga":       "completed",
			"provision": "pending",
		},
	})

	// handleFGA: signup.requested event with fga already completed → no-op.
	msg := makeMsg("signup.requested", "user-fga-idem", "acme-corp")
	err := p.handleFGA(ctx, msg)
	require.NoError(t, err, "idempotent FGA call must not error")

	az.mu.Lock()
	calls := az.writeCalls
	az.mu.Unlock()
	assert.Empty(t, calls, "authz.Write must NOT be called when fga step is already completed")
}

// ---------------------------------------------------------------------------
// TestHandleProvision_CallsProvisionTenant
// ---------------------------------------------------------------------------

func TestHandleProvision_CallsProvisionTenant(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)

	az := &mockAuthz{}
	prov := newTestMinimalProvisioner(t, mr)
	store := newMemProvisioningStore()

	p := newTestPipeline(t, mr, az, prov, store)
	seedState(t, store, "user-prov", SignupState{})

	msg := makeMsg("signup.fga_written", "user-prov", "acme-corp")
	err := p.handleProvision(ctx, msg)
	require.NoError(t, err)

	got, err := store.Get(ctx, "user-prov")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "active", got.Status)
	assert.Equal(t, "completed", got.StepStatuses["provision"])
}

// ---------------------------------------------------------------------------
// TestHandleProvision_Idempotent
// ---------------------------------------------------------------------------

func TestHandleProvision_Idempotent(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)

	az := &mockAuthz{}
	prov := newTestMinimalProvisioner(t, mr)
	store := newMemProvisioningStore()

	p := newTestPipeline(t, mr, az, prov, store)

	seedState(t, store, "user-prov-idem", SignupState{
		Status: "active",
		StepStatuses: map[string]string{
			"fga":       "completed",
			"provision": "completed",
		},
	})

	msg := makeMsg("signup.fga_written", "user-prov-idem", "acme-corp")
	err := p.handleProvision(ctx, msg)
	require.NoError(t, err, "idempotent provision call must not error")
}

// ---------------------------------------------------------------------------
// TestFailSignup_SetsStatusAndError
// ---------------------------------------------------------------------------

func TestFailSignup_SetsStatusAndError(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)

	az := &mockAuthz{}
	prov := newTestMinimalProvisioner(t, mr)
	store := newMemProvisioningStore()

	p := newTestPipeline(t, mr, az, prov, store)
	seedState(t, store, "user-fs", SignupState{})

	cause := errors.New("fga unreachable")
	_ = p.failSignup(ctx, "msg-1", "user-fs", "fga", cause)

	got, err := store.Get(ctx, "user-fs")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "failed", got.Status)
	assert.Equal(t, "fga unreachable", got.Error)
}
