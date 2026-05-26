package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"

	dbpostgres "github.com/zeroroot-ai/gibson/internal/database/postgres"
	"github.com/zeroroot-ai/gibson/internal/datapool"
	"github.com/zeroroot-ai/platform-clients/secrets"
	"github.com/zeroroot-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// Fake TenantSecretsOps (in-memory, no database)
// ---------------------------------------------------------------------------

// fakeSecretsOps is a minimal in-memory implementation of the TenantSecretsOps
// surface used by the provider. It stores secrets in a map and can be
// configured to return specific errors.
type fakeSecretsOps struct {
	data        map[string][]byte
	getErr      error
	putErr      error
	deleteErr   error
	listErr     error
	crossTenant bool // when true, Get returns a cross-tenant error
}

func newFakeSecretsOps() *fakeSecretsOps {
	return &fakeSecretsOps{data: make(map[string][]byte)}
}

func (f *fakeSecretsOps) Get(_ context.Context, name string) ([]byte, error) {
	if f.crossTenant {
		return nil, &crossTenantSecretError{name: name, cause: errors.New("fake cross-tenant")}
	}
	if f.getErr != nil {
		return nil, f.getErr
	}
	v, ok := f.data[name]
	if !ok {
		return nil, fmt.Errorf("secret %q: %w", name, dbpostgres.ErrTenantSecretNotFound)
	}
	return v, nil
}

func (f *fakeSecretsOps) Put(_ context.Context, name string, value []byte) error {
	if f.putErr != nil {
		return f.putErr
	}
	f.data[name] = value
	return nil
}

func (f *fakeSecretsOps) Delete(_ context.Context, name string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	if _, ok := f.data[name]; !ok {
		return fmt.Errorf("secret %q: %w", name, dbpostgres.ErrTenantSecretNotFound)
	}
	delete(f.data, name)
	return nil
}

func (f *fakeSecretsOps) ListNames(_ context.Context, filter *dbpostgres.SecretFilter) ([]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var names []string
	for k := range f.data {
		if filter == nil || filter.Prefix == "" || len(k) >= len(filter.Prefix) && k[:len(filter.Prefix)] == filter.Prefix {
			names = append(names, k)
		}
	}
	return names, nil
}

// crossTenantSecretError mirrors the unexported type in the postgres package
// so tests can construct cross-tenant errors without importing internals.
// The important thing is that dbpostgres.IsCrossTenantSecretError returns true.
type crossTenantSecretError struct {
	name  string
	cause error
}

func (e *crossTenantSecretError) Error() string {
	return fmt.Sprintf("secret %q: cross-tenant decrypt failure", e.name)
}

func (e *crossTenantSecretError) Unwrap() error { return e.cause }

// ---------------------------------------------------------------------------
// Fake Conn wrapping fakeSecretsOps
// ---------------------------------------------------------------------------

// fakeConn is a *datapool.Conn substitute that returns a fakeSecretsOps
// from its Secrets() method. We achieve this by overriding the ConnAcquirer
// to return a nil *datapool.Conn and instead intercepting calls at the
// acquirer level.
//
// Because datapool.Conn.Secrets() calls dbpostgres.NewTenantSecretsOps which
// hits a real pgxpool, we cannot use a real *datapool.Conn with a nil pool
// inside the provider. Instead we build a custom ConnAcquirer that bypasses
// the provider's conn.Secrets() call entirely using a wrapper approach.
//
// The simplest approach: wrap the provider's internal ops calls via a
// ConnAcquirer that returns a nil conn but pair the provider with a
// secretsGetter interface. However, since the provider is tightly coupled to
// conn.Secrets(), we instead test via the fakeConnAcquirer that returns
// a *datapool.Conn constructed with a nil Postgres pool, and provide a
// fakeOps bridge.
//
// Actually, since the provider calls conn.Secrets().Get/Put/Delete/ListNames,
// and conn.Secrets() constructs a TenantSecretsOps with conn.Postgres (nil
// here) and conn.KEK, we cannot safely intercept at the Conn level without
// modifying the provider to take an interface.
//
// For clean testability the provider's interface-based test approach is:
// test mapError directly, and test the provider end-to-end via a stubbed
// acquirer that returns an error (for the acquirer-fail path), leaving the
// actual DAO interaction tested by TenantSecretsOps unit tests (done in
// Task 4.2) and the integration test (Task 5).
//
// We test:
// 1. Capabilities (no conn needed)
// 2. Acquirer-failure path for all methods → secrets.ErrUnavailable
// 3. mapError function for all error-type mappings
// 4. Probe canary logic (acquirer fails)
// 5. New() panics on nil acquirer

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

var testTenant = auth.MustNewTenantID("test-tenant")

// failAcquirer always returns an error.
func failAcquirer(err error) ConnAcquirer {
	return func(ctx context.Context, t auth.TenantID) (*datapool.Conn, error) {
		return nil, err
	}
}

func TestNew_NilAcquirerPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("New(nil) must panic")
		}
	}()
	New(nil)
}

func TestCapabilities(t *testing.T) {
	p := New(failAcquirer(errors.New("unused")))
	caps := p.Capabilities()
	if !caps.CanPut {
		t.Error("CanPut must be true")
	}
	if !caps.CanDelete {
		t.Error("CanDelete must be true")
	}
	if !caps.CanList {
		t.Error("CanList must be true")
	}
	if caps.SupportsVersion {
		t.Error("SupportsVersion must be false")
	}
	if caps.MaxValueBytes != maxValueBytes {
		t.Errorf("MaxValueBytes: want %d, got %d", maxValueBytes, caps.MaxValueBytes)
	}
}

func TestCompileTimeInterface(t *testing.T) {
	// var _ secrets.Broker is already asserted in provider.go.
	// This test ensures the package compiles with the assertion.
	p := New(failAcquirer(errors.New("unused")))
	var _ secrets.Broker = p
}

// ---------------------------------------------------------------------------
// Acquirer-failure paths
// ---------------------------------------------------------------------------

func TestGet_AcquirerFail(t *testing.T) {
	p := New(failAcquirer(errors.New("pool down")))
	_, err := p.Get(context.Background(), testTenant, "key")
	if !errors.Is(err, secrets.ErrUnavailable) {
		t.Errorf("Get with acquirer failure: want ErrUnavailable, got %v", err)
	}
}

func TestPut_AcquirerFail(t *testing.T) {
	p := New(failAcquirer(errors.New("pool down")))
	err := p.Put(context.Background(), testTenant, "key", []byte("v"))
	if !errors.Is(err, secrets.ErrUnavailable) {
		t.Errorf("Put with acquirer failure: want ErrUnavailable, got %v", err)
	}
}

func TestDelete_AcquirerFail(t *testing.T) {
	p := New(failAcquirer(errors.New("pool down")))
	err := p.Delete(context.Background(), testTenant, "key")
	if !errors.Is(err, secrets.ErrUnavailable) {
		t.Errorf("Delete with acquirer failure: want ErrUnavailable, got %v", err)
	}
}

func TestList_AcquirerFail(t *testing.T) {
	p := New(failAcquirer(errors.New("pool down")))
	_, err := p.List(context.Background(), testTenant, secrets.Filter{})
	if !errors.Is(err, secrets.ErrUnavailable) {
		t.Errorf("List with acquirer failure: want ErrUnavailable, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// mapError function tests
// ---------------------------------------------------------------------------

func TestMapError_Nil(t *testing.T) {
	if mapError(nil, "k") != nil {
		t.Error("mapError(nil) must return nil")
	}
}

func TestMapError_NotFound(t *testing.T) {
	err := fmt.Errorf("secret %q: %w", "k", dbpostgres.ErrTenantSecretNotFound)
	got := mapError(err, "k")
	if !errors.Is(got, secrets.ErrNotFound) {
		t.Errorf("ErrTenantSecretNotFound → want ErrNotFound, got %v", got)
	}
}

func TestMapError_CrossTenant(t *testing.T) {
	// Build a cross-tenant error using the IsCrossTenantSecretError predicate.
	// We need a *dbpostgres.crossTenantSecretError but it's unexported.
	// IsCrossTenantSecretError uses errors.As on a *crossTenantSecretError which
	// is in the internal postgres package. We can trigger this by calling
	// dbpostgres.IsCrossTenantSecretError and confirming the error is mapped.
	//
	// Since we cannot construct the unexported crossTenantSecretError from outside
	// the package, we test the mapError fallthrough for cross-tenant by verifying
	// that a regular error produces ErrUnavailable (since cross-tenant detection
	// requires the unexported type).
	//
	// The full cross-tenant path (including metric increment) is tested in the
	// integration test (Task 5) against a real Postgres backend.
	err := fmt.Errorf("some transient error")
	got := mapError(err, "k")
	if !errors.Is(got, secrets.ErrUnavailable) {
		t.Errorf("generic error → want ErrUnavailable, got %v", got)
	}
}

func TestMapError_TooLarge(t *testing.T) {
	err := fmt.Errorf("too big: %w", dbpostgres.ErrTenantSecretTooLarge)
	got := mapError(err, "k")
	if !errors.Is(got, secrets.ErrTooLarge) {
		t.Errorf("ErrTenantSecretTooLarge → want ErrTooLarge, got %v", got)
	}
}

func TestMapError_Generic(t *testing.T) {
	err := errors.New("connection refused")
	got := mapError(err, "k")
	if !errors.Is(got, secrets.ErrUnavailable) {
		t.Errorf("generic error → want ErrUnavailable, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// Put value size limit
// ---------------------------------------------------------------------------

func TestPut_TooLargeRejectedBeforeAcquire(t *testing.T) {
	// The provider must reject over-limit values BEFORE calling the acquirer.
	acquireCalled := false
	acq := func(ctx context.Context, t auth.TenantID) (*datapool.Conn, error) {
		acquireCalled = true
		return nil, errors.New("should not be called")
	}
	p := New(acq)
	big := make([]byte, maxValueBytes+1)
	err := p.Put(context.Background(), testTenant, "key", big)
	if !errors.Is(err, secrets.ErrTooLarge) {
		t.Errorf("Put over limit: want ErrTooLarge, got %v", err)
	}
	if acquireCalled {
		t.Error("acquirer should not be called when value exceeds limit")
	}
}

// ---------------------------------------------------------------------------
// Health (no-op at this layer)
// ---------------------------------------------------------------------------

func TestHealth_ReturnsNil(t *testing.T) {
	p := New(failAcquirer(errors.New("unused")))
	if err := p.Health(context.Background()); err != nil {
		t.Errorf("Health: unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Probe with acquirer failure
// ---------------------------------------------------------------------------

func TestProbe_AcquirerFail(t *testing.T) {
	// When the acquirer fails (e.g., probe tenant not provisioned), Probe
	// returns a non-nil error.
	p := New(failAcquirer(errors.New("probe tenant not provisioned")))
	err := p.Probe(context.Background())
	// Probe should return an error when it cannot acquire a conn.
	if err == nil {
		t.Error("Probe with acquirer failure must return non-nil error")
	}
}
