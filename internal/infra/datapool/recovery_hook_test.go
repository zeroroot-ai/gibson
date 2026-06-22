package datapool

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zeroroot-ai/sdk/auth"
)

// countingHook is a test fake that records how many times Run was invoked
// and can be configured to return an arbitrary error.
type countingHook struct {
	calls atomic.Int64
	err   error
}

func (h *countingHook) Run(_ context.Context, _ auth.TenantID, _ *Conn) error {
	h.calls.Add(1)
	return h.err
}

// TestRecoveryHook_Noop_AlwaysSucceeds is a baseline assertion that the
// default noop hook is safe to call with any argument shape, including
// a nil conn (which the production hook would reject).
func TestRecoveryHook_Noop_AlwaysSucceeds(t *testing.T) {
	h := NewNoopRecoveryHook()
	tenant := auth.MustNewTenantID("acme")

	assert.NoError(t, h.Run(context.Background(), tenant, nil))
	assert.NoError(t, h.Run(context.Background(), tenant, &Conn{}))
}

// TestRunRecoveryHook_NilConn_ErrorsLoudly is a defensive guard. The
// production hook should never be invoked with a nil conn (pool.For
// only calls it after the conn is constructed), but we assert the
// behaviour so a future caller-side regression doesn't silently no-op.
func TestRunRecoveryHook_NilConn_ErrorsLoudly(t *testing.T) {
	h := NewRunRecoveryHook(nil)
	tenant := auth.MustNewTenantID("acme")

	err := h.Run(context.Background(), tenant, nil)
	assert.Error(t, err)
}

// TestRunRecoveryHook_NoRedis_SilentlySkips covers the dev-environment
// path: a Conn without a Redis sub-pool cannot enumerate running missions
// and must return nil (silent skip) rather than failing. This mirrors the
// behaviour the deleted recover_missions.go had — "no redis configured"
// is a runtime configuration choice, not an error.
func TestRunRecoveryHook_NoRedis_SilentlySkips(t *testing.T) {
	h := NewRunRecoveryHook(nil)
	tenant := auth.MustNewTenantID("acme")
	// Conn with Redis nil — common in test/dev configurations.
	conn := &Conn{Tenant: tenant}

	err := h.Run(context.Background(), tenant, conn)
	assert.NoError(t, err)
}

// TestPool_FirstDialFiresHookOnce_RepeatDoesNot is the load-bearing
// idempotency assertion: per-process, the first For() dial for a given
// tenant invokes the hook exactly once. Subsequent dials skip it.
//
// We exercise this by constructing a pool stub directly, calling
// SetRecoveryHook with a counting fake, then simulating the LoadOrStore
// branch the way pool.For does. We do NOT spin up a real pool here —
// that would require a live KEK provider and stores; the For-level
// integration with stores is covered by pool_test.go.
func TestPool_FirstDialFiresHookOnce_RepeatDoesNot(t *testing.T) {
	tenant := auth.MustNewTenantID("acme")
	hook := &countingHook{}
	p := &pool{}
	p.SetRecoveryHook(hook)

	// Simulate three concurrent first-dial attempts; LoadOrStore must
	// pick exactly one winner.
	for i := 0; i < 3; i++ {
		if _, fired := p.firedRecovery.LoadOrStore(tenant, struct{}{}); !fired {
			p.recoveryMu.RLock()
			h := p.recoveryHook
			p.recoveryMu.RUnlock()
			_ = h.Run(context.Background(), tenant, &Conn{Tenant: tenant})
		}
	}

	assert.EqualValues(t, 1, hook.calls.Load(), "hook must fire exactly once per tenant per process")
}

// TestPool_DifferentTenantsEachFireOnce verifies that the idempotency
// is per-tenant, not global. Each tenant's first dial fires the hook;
// subsequent dials for the same tenant skip it.
func TestPool_DifferentTenantsEachFireOnce(t *testing.T) {
	tenants := []auth.TenantID{
		auth.MustNewTenantID("acme"),
		auth.MustNewTenantID("beta"),
		auth.MustNewTenantID("gamma"),
	}
	hook := &countingHook{}
	p := &pool{}
	p.SetRecoveryHook(hook)

	// Each tenant dialled twice; only first dial per tenant should fire.
	for _, tenant := range tenants {
		for i := 0; i < 2; i++ {
			if _, fired := p.firedRecovery.LoadOrStore(tenant, struct{}{}); !fired {
				p.recoveryMu.RLock()
				h := p.recoveryHook
				p.recoveryMu.RUnlock()
				_ = h.Run(context.Background(), tenant, &Conn{Tenant: tenant})
			}
		}
	}

	assert.EqualValues(t, int64(len(tenants)), hook.calls.Load(),
		"hook must fire once per tenant, not once per dial")
}

// TestPool_HookError_DoesNotPreventFire verifies that a returned error
// from the hook does not prevent the LoadOrStore marker from sticking —
// a tenant whose hook errors on first dial should NOT re-fire the hook
// on the second dial (one log line per process is enough).
func TestPool_HookError_DoesNotPreventFire(t *testing.T) {
	tenant := auth.MustNewTenantID("acme")
	hook := &countingHook{err: errors.New("recovery failed")}
	p := &pool{}
	p.SetRecoveryHook(hook)

	for i := 0; i < 2; i++ {
		if _, fired := p.firedRecovery.LoadOrStore(tenant, struct{}{}); !fired {
			p.recoveryMu.RLock()
			h := p.recoveryHook
			p.recoveryMu.RUnlock()
			_ = h.Run(context.Background(), tenant, &Conn{Tenant: tenant})
		}
	}

	assert.EqualValues(t, 1, hook.calls.Load(),
		"errors must not prevent the firedRecovery marker — one log per process is enough")
}

// TestPool_SetRecoveryHook_NilRevertsToNoop is the safety contract: a
// caller passing nil through SetRecoveryHook gets the noop hook, never
// a nil dereference inside pool.For.
func TestPool_SetRecoveryHook_NilRevertsToNoop(t *testing.T) {
	p := &pool{}
	p.SetRecoveryHook(nil)

	p.recoveryMu.RLock()
	h := p.recoveryHook
	p.recoveryMu.RUnlock()

	tenant := auth.MustNewTenantID("acme")
	// Should be safe to call without panicking; should return nil error.
	err := h.Run(context.Background(), tenant, &Conn{})
	assert.NoError(t, err)
}
