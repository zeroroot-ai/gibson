package secrets_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/resilience"
	"github.com/zeroroot-ai/gibson/internal/infra/secrets"
	"github.com/zeroroot-ai/sdk/auth"
)

// ─────────────────────────────────────────────────────────────────────────────
// Test tenant helpers
// ─────────────────────────────────────────────────────────────────────────────

func tid(t *testing.T, s string) auth.TenantID {
	t.Helper()
	id, err := auth.NewTenantID(s)
	if err != nil {
		t.Fatalf("NewTenantID(%q): %v", s, err)
	}
	return id
}

// ─────────────────────────────────────────────────────────────────────────────
// Fake provider for circuit breaker / cross-tenant tests
// ─────────────────────────────────────────────────────────────────────────────

type fakeProvider struct {
	mu    sync.Mutex
	store map[string][]byte // key: "<tenantID>/<name>" → value
	failN int               // if > 0, next N calls return an error
}

func newFakeProvider() *fakeProvider {
	return &fakeProvider{store: make(map[string][]byte)}
}

func (f *fakeProvider) storeKey(tenant auth.TenantID, name string) string {
	return tenant.String() + "/" + name
}

func (f *fakeProvider) Capabilities() secrets.Capabilities {
	return secrets.Capabilities{
		CanPut:    true,
		CanDelete: true,
		CanList:   true,
		CanRotate: true,
		CanProbe:  true,
	}
}

func (f *fakeProvider) Get(_ context.Context, tenant auth.TenantID, name string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failN > 0 {
		f.failN--
		return nil, fmt.Errorf("%w: injected failure", secrets.ErrUnavailable)
	}
	v, ok := f.store[f.storeKey(tenant, name)]
	if !ok {
		return nil, fmt.Errorf("%w: %s/%s", secrets.ErrNotFound, tenant.String(), name)
	}
	// Return a copy.
	out := make([]byte, len(v))
	copy(out, v)
	return out, nil
}

func (f *fakeProvider) Put(_ context.Context, tenant auth.TenantID, name string, value []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failN > 0 {
		f.failN--
		return fmt.Errorf("%w: injected failure", secrets.ErrUnavailable)
	}
	stored := make([]byte, len(value))
	copy(stored, value)
	f.store[f.storeKey(tenant, name)] = stored
	return nil
}

func (f *fakeProvider) Delete(_ context.Context, tenant auth.TenantID, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failN > 0 {
		f.failN--
		return fmt.Errorf("%w: injected failure", secrets.ErrUnavailable)
	}
	delete(f.store, f.storeKey(tenant, name))
	return nil
}

func (f *fakeProvider) List(_ context.Context, tenant auth.TenantID, filter secrets.Filter) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failN > 0 {
		f.failN--
		return nil, fmt.Errorf("%w: injected failure", secrets.ErrUnavailable)
	}
	prefix := tenant.String() + "/"
	var out []string
	for k := range f.store {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		name := strings.TrimPrefix(k, prefix)
		if filter.Prefix != "" && !strings.HasPrefix(name, filter.Prefix) {
			continue
		}
		out = append(out, name)
	}
	return out, nil
}

func (f *fakeProvider) Health(_ context.Context) error {
	return nil
}

func (f *fakeProvider) Probe(_ context.Context) error {
	return nil
}

func (f *fakeProvider) Rotate(_ context.Context, tenant auth.TenantID, name string, oldValue, newValue []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failN > 0 {
		f.failN--
		return fmt.Errorf("%w: injected failure", secrets.ErrUnavailable)
	}
	key := f.storeKey(tenant, name)
	existing, ok := f.store[key]
	if !ok {
		return fmt.Errorf("%w: %s/%s", secrets.ErrNotFound, tenant.String(), name)
	}
	if string(existing) != string(oldValue) {
		return fmt.Errorf("%w: oldValue mismatch for %s/%s", secrets.ErrPermissionDenied, tenant.String(), name)
	}
	stored := make([]byte, len(newValue))
	copy(stored, newValue)
	f.store[key] = stored
	return nil
}

func (f *fakeProvider) Close() error { return nil }

func (f *fakeProvider) injectFailures(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failN = n
}

// ─────────────────────────────────────────────────────────────────────────────
// Circuit breaker test helpers
//
// gobreaker does not support clock injection so these tests use short real
// timeouts (Timeout=50ms) and time.Sleep instead of a fake clock.
// ─────────────────────────────────────────────────────────────────────────────

const (
	testFailThreshold = 5
	testCBTimeout     = 50 * time.Millisecond
)

// newTestBroker creates a Broker with a tight circuit configuration suitable
// for unit tests (threshold=testFailThreshold, timeout=testCBTimeout).
func newTestBroker(t *testing.T, provider secrets.Broker, name string) secrets.Broker {
	t.Helper()
	cfg := resilience.CircuitConfig{
		ConsecutiveFailures: testFailThreshold,
		Interval:            10 * time.Second,
		Timeout:             testCBTimeout,
	}
	b, err := secrets.NewBroker(secrets.BrokerOptions{
		Provider:      provider,
		ProviderName:  name,
		CircuitConfig: cfg,
		Logger:        slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	t.Cleanup(func() {
		if c, ok := b.(secrets.Closer); ok {
			_ = c.Close()
		}
	})
	return b
}

// ─────────────────────────────────────────────────────────────────────────────
// Circuit breaker state machine tests
// ─────────────────────────────────────────────────────────────────────────────

// TestCircuitBreaker_TripsAfterNFailures verifies the circuit opens after
// testFailThreshold consecutive errors.
func TestCircuitBreaker_TripsAfterNFailures(t *testing.T) {
	prov := newFakeProvider()
	b := newTestBroker(t, prov, "vault")

	ctx := context.Background()
	tenantA := tid(t, "tenant-a")
	prov.injectFailures(testFailThreshold)

	for range testFailThreshold {
		_, _ = b.Get(ctx, tenantA, "key1")
	}

	_, err := b.Get(ctx, tenantA, "key1")
	if err == nil {
		t.Fatal("expected ErrUnavailable from open circuit, got nil")
	}
	if !errors.Is(err, secrets.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got: %v", err)
	}
}

// TestCircuitBreaker_HalfOpenProbeSuccessCloses verifies the full
// Closed → Open → HalfOpen → Closed state machine.
func TestCircuitBreaker_HalfOpenProbeSuccessCloses(t *testing.T) {
	prov := newFakeProvider()
	b := newTestBroker(t, prov, "vault")

	ctx := context.Background()
	tenantA := tid(t, "tenant-a")

	// Seed a value so the probe call succeeds.
	if err := prov.Put(ctx, tenantA, "key1", []byte("hello")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Trip the circuit open.
	prov.injectFailures(testFailThreshold)
	for range testFailThreshold {
		_, _ = b.Get(ctx, tenantA, "key1")
	}

	// Advance past the open duration (gobreaker uses real time).
	time.Sleep(testCBTimeout + 20*time.Millisecond)

	// First call after advancing is the probe — should succeed.
	val, err := b.Get(ctx, tenantA, "key1")
	if err != nil {
		t.Fatalf("probe call failed: %v", err)
	}
	if string(val) != "hello" {
		t.Fatalf("expected 'hello', got %q", val)
	}

	// Circuit is now Closed; a subsequent call should also succeed.
	val2, err2 := b.Get(ctx, tenantA, "key1")
	if err2 != nil {
		t.Fatalf("post-close call failed: %v", err2)
	}
	if string(val2) != "hello" {
		t.Fatalf("expected 'hello', got %q", val2)
	}
}

// TestCircuitBreaker_HalfOpenProbeFailsReopens verifies that a failing
// probe re-opens the circuit.
func TestCircuitBreaker_HalfOpenProbeFailsReopens(t *testing.T) {
	prov := newFakeProvider()
	b := newTestBroker(t, prov, "vault")

	ctx := context.Background()
	tenantA := tid(t, "tenant-a")

	// Trip circuit open.
	prov.injectFailures(testFailThreshold)
	for range testFailThreshold {
		_, _ = b.Get(ctx, tenantA, "key1")
	}

	// Advance past open duration.
	time.Sleep(testCBTimeout + 20*time.Millisecond)

	// Inject one more failure for the probe.
	prov.injectFailures(1)
	_, err := b.Get(ctx, tenantA, "key1")
	if err == nil {
		t.Fatal("expected error on failing probe")
	}

	// Circuit must be open again.
	_, err2 := b.Get(ctx, tenantA, "key1")
	if !errors.Is(err2, secrets.ErrUnavailable) {
		t.Fatalf("expected circuit still open (ErrUnavailable), got: %v", err2)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-tenant isolation test
// ─────────────────────────────────────────────────────────────────────────────

// TestCrossTenantIsolation verifies that rotating a secret for one tenant
// does not affect another tenant's secrets.
func TestCrossTenantIsolation(t *testing.T) {
	type entry struct {
		tenantID string
		name     string
		initial  string
		rotated  string
	}

	cases := []entry{
		{"tenant-alpha", "db-password", "alpha-secret-v1", "alpha-secret-v2"},
		{"tenant-beta", "db-password", "beta-secret-v1", "beta-secret-v2"},
		{"tenant-gamma", "api-key", "gamma-api-v1", "gamma-api-v2"},
	}

	prov := newFakeProvider()
	b, err := secrets.NewBroker(secrets.BrokerOptions{
		Provider:     prov,
		ProviderName: "vault",
		Logger:       slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	t.Cleanup(func() {
		if c, ok := b.(secrets.Closer); ok {
			_ = c.Close()
		}
	})

	ctx := context.Background()

	tenantOf := make(map[string]auth.TenantID, len(cases))
	for _, c := range cases {
		tenantOf[c.tenantID] = tid(t, c.tenantID)
	}

	// Seed all initial values.
	for _, tt := range cases {
		if setErr := b.Put(ctx, tenantOf[tt.tenantID], tt.name, []byte(tt.initial)); setErr != nil {
			t.Fatalf("Put(%s/%s): %v", tt.tenantID, tt.name, setErr)
		}
	}

	// Rotate only tenant-alpha's db-password.
	if !b.Capabilities().CanRotate {
		t.Fatal("expected provider to support rotation")
	}
	if rotErr := prov.Rotate(ctx, tenantOf["tenant-alpha"], "db-password", []byte("alpha-secret-v1"), []byte("alpha-secret-v2")); rotErr != nil {
		t.Fatalf("Rotate: %v", rotErr)
	}

	// Verify: alpha's db-password is v2; all others unchanged.
	expected := map[string]map[string]string{
		"tenant-alpha": {"db-password": "alpha-secret-v2"},
		"tenant-beta":  {"db-password": "beta-secret-v1"},
		"tenant-gamma": {"api-key": "gamma-api-v1"},
	}

	for tenantID, names := range expected {
		for name, want := range names {
			got, getErr := b.Get(ctx, tenantOf[tenantID], name)
			if getErr != nil {
				t.Errorf("Get(%s/%s): %v", tenantID, name, getErr)
				continue
			}
			if string(got) != want {
				t.Errorf("Get(%s/%s) = %q, want %q (cross-tenant leak?)", tenantID, name, got, want)
			}
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Capability gating
// ─────────────────────────────────────────────────────────────────────────────

// readOnlyProvider declares no capabilities so we can exercise the
// broker's capability gating for Put/Delete/List.
type readOnlyProvider struct{ *fakeProvider }

func (readOnlyProvider) Capabilities() secrets.Capabilities {
	return secrets.Capabilities{}
}

// TestCapabilityGating verifies that Put/Delete/List return ErrUnsupported
// when the provider does not declare the capability.
func TestCapabilityGating(t *testing.T) {
	prov := readOnlyProvider{fakeProvider: newFakeProvider()}
	b, err := secrets.NewBroker(secrets.BrokerOptions{
		Provider:     prov,
		ProviderName: "ro",
		Logger:       slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	t.Cleanup(func() {
		if c, ok := b.(secrets.Closer); ok {
			_ = c.Close()
		}
	})

	ctx := context.Background()
	tenantA := tid(t, "tenant-a")

	if err := b.Put(ctx, tenantA, "k", []byte("v")); !errors.Is(err, secrets.ErrUnsupported) {
		t.Errorf("Put: expected ErrUnsupported, got: %v", err)
	}
	if err := b.Delete(ctx, tenantA, "k"); !errors.Is(err, secrets.ErrUnsupported) {
		t.Errorf("Delete: expected ErrUnsupported, got: %v", err)
	}
	if _, err := b.List(ctx, tenantA, secrets.Filter{}); !errors.Is(err, secrets.ErrUnsupported) {
		t.Errorf("List: expected ErrUnsupported, got: %v", err)
	}
}
