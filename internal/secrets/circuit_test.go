package secrets

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdksecrets "github.com/zero-day-ai/platform-clients/secrets"
)

// --- fake clock ---

type fakeClock struct {
	now time.Time
}

func newFakeClock(t time.Time) *fakeClock    { return &fakeClock{now: t} }
func (f *fakeClock) Now() time.Time          { return f.now }
func (f *fakeClock) Advance(d time.Duration) { f.now = f.now.Add(d) }

// --- helpers ---

const (
	cbTenant   = "acme-corp"
	cbProvider = "vault"
)

func newTestCB(fc *fakeClock) *CircuitBreaker {
	return NewCircuitBreaker(slog.Default(), fc.Now)
}

// --- tests ---

func TestCircuitBreaker_InitiallyClosed(t *testing.T) {
	fc := newFakeClock(time.Now())
	cb := newTestCB(fc)
	require.NoError(t, cb.Allow(cbTenant, cbProvider))
	assert.Equal(t, circuitClosed, cb.State(cbTenant, cbProvider))
}

func TestCircuitBreaker_OpenAfterThreshold(t *testing.T) {
	fc := newFakeClock(time.Now())
	cb := newTestCB(fc)

	// Record cbFailureThreshold - 1 failures — circuit must stay closed.
	for i := 0; i < cbFailureThreshold-1; i++ {
		cb.RecordFailure(cbTenant, cbProvider)
	}
	require.NoError(t, cb.Allow(cbTenant, cbProvider), "circuit should be closed before threshold")

	// One more failure crosses the threshold.
	cb.RecordFailure(cbTenant, cbProvider)
	assert.Equal(t, circuitOpen, cb.State(cbTenant, cbProvider))

	err := cb.Allow(cbTenant, cbProvider)
	require.Error(t, err)
	assert.ErrorIs(t, err, sdksecrets.ErrUnavailable)
}

func TestCircuitBreaker_ResetsCounterAfterWindow(t *testing.T) {
	fc := newFakeClock(time.Now())
	cb := newTestCB(fc)

	// Accumulate threshold - 1 failures.
	for i := 0; i < cbFailureThreshold-1; i++ {
		cb.RecordFailure(cbTenant, cbProvider)
	}

	// Advance past the failure window; the next failure should reset.
	fc.Advance(cbFailureWindow + time.Millisecond)
	cb.RecordFailure(cbTenant, cbProvider)

	// Circuit should still be closed (window reset, counter = 1).
	assert.Equal(t, circuitClosed, cb.State(cbTenant, cbProvider))
	require.NoError(t, cb.Allow(cbTenant, cbProvider))
}

func TestCircuitBreaker_HalfOpenAfterOpenDuration(t *testing.T) {
	fc := newFakeClock(time.Now())
	cb := newTestCB(fc)

	// Open the circuit.
	for i := 0; i < cbFailureThreshold; i++ {
		cb.RecordFailure(cbTenant, cbProvider)
	}
	require.Equal(t, circuitOpen, cb.State(cbTenant, cbProvider))

	// Advance past the open period.
	fc.Advance(cbOpenDuration + time.Millisecond)

	// First Allow should return nil (probe admitted).
	require.NoError(t, cb.Allow(cbTenant, cbProvider))
	assert.Equal(t, circuitHalfOpen, cb.State(cbTenant, cbProvider))

	// Second Allow while probe is in flight must fail.
	err := cb.Allow(cbTenant, cbProvider)
	require.Error(t, err)
	assert.ErrorIs(t, err, sdksecrets.ErrUnavailable)
}

func TestCircuitBreaker_ClosesOnProbeSuccess(t *testing.T) {
	fc := newFakeClock(time.Now())
	cb := newTestCB(fc)

	for i := 0; i < cbFailureThreshold; i++ {
		cb.RecordFailure(cbTenant, cbProvider)
	}
	fc.Advance(cbOpenDuration + time.Millisecond)
	require.NoError(t, cb.Allow(cbTenant, cbProvider)) // enters half-open
	assert.Equal(t, circuitHalfOpen, cb.State(cbTenant, cbProvider))

	cb.RecordSuccess(cbTenant, cbProvider)
	assert.Equal(t, circuitClosed, cb.State(cbTenant, cbProvider))

	// Circuit is closed again; Allow must succeed.
	require.NoError(t, cb.Allow(cbTenant, cbProvider))
}

func TestCircuitBreaker_ReOpensOnProbeFailure(t *testing.T) {
	fc := newFakeClock(time.Now())
	cb := newTestCB(fc)

	for i := 0; i < cbFailureThreshold; i++ {
		cb.RecordFailure(cbTenant, cbProvider)
	}
	fc.Advance(cbOpenDuration + time.Millisecond)
	require.NoError(t, cb.Allow(cbTenant, cbProvider)) // half-open
	cb.RecordFailure(cbTenant, cbProvider)             // probe fails

	assert.Equal(t, circuitOpen, cb.State(cbTenant, cbProvider))
	err := cb.Allow(cbTenant, cbProvider)
	require.Error(t, err)
	assert.ErrorIs(t, err, sdksecrets.ErrUnavailable)
}

func TestCircuitBreaker_SuccessResetsClosed(t *testing.T) {
	fc := newFakeClock(time.Now())
	cb := newTestCB(fc)

	// Record 3 failures (below threshold).
	for i := 0; i < 3; i++ {
		cb.RecordFailure(cbTenant, cbProvider)
	}
	// Success resets the counter.
	cb.RecordSuccess(cbTenant, cbProvider)

	// Should take another full cbFailureThreshold failures to open.
	for i := 0; i < cbFailureThreshold-1; i++ {
		cb.RecordFailure(cbTenant, cbProvider)
	}
	assert.Equal(t, circuitClosed, cb.State(cbTenant, cbProvider))

	cb.RecordFailure(cbTenant, cbProvider)
	assert.Equal(t, circuitOpen, cb.State(cbTenant, cbProvider))
}

func TestCircuitBreaker_PerTenantIsolation(t *testing.T) {
	fc := newFakeClock(time.Now())
	cb := newTestCB(fc)

	// Open circuit for tenant A.
	tenantA := "alpha-co"
	tenantB := "beta-co"
	for i := 0; i < cbFailureThreshold; i++ {
		cb.RecordFailure(tenantA, cbProvider)
	}
	assert.Equal(t, circuitOpen, cb.State(tenantA, cbProvider))

	// Tenant B should be unaffected.
	require.NoError(t, cb.Allow(tenantB, cbProvider))
	assert.Equal(t, circuitClosed, cb.State(tenantB, cbProvider))
}

func TestCircuitBreaker_PerProviderIsolation(t *testing.T) {
	fc := newFakeClock(time.Now())
	cb := newTestCB(fc)

	provA := "vault"
	provB := "awssm"
	for i := 0; i < cbFailureThreshold; i++ {
		cb.RecordFailure(cbTenant, provA)
	}
	assert.Equal(t, circuitOpen, cb.State(cbTenant, provA))
	require.NoError(t, cb.Allow(cbTenant, provB))
}
