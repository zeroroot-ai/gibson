package datapool

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/sdk/auth"
)

// fakeProbe is a hand-written test fake for DataPlaneProbe. It records the
// number of calls per method (so we can assert cache behaviour) and lets
// the test set arbitrary return values per call.
type fakeProbe struct {
	brokerExists bool
	brokerErr    error
	pingable     bool
	pingErr      error

	brokerCalls atomic.Int64
	pingCalls   atomic.Int64
}

func (f *fakeProbe) BrokerConfigExists(_ context.Context, _ auth.TenantID) (bool, error) {
	f.brokerCalls.Add(1)
	return f.brokerExists, f.brokerErr
}

func (f *fakeProbe) Pingable(_ context.Context, _ auth.TenantID) (bool, error) {
	f.pingCalls.Add(1)
	return f.pingable, f.pingErr
}

// TestProvisioningChecker_BothSignalsTrue_Ready is the happy path: the
// tenant_secrets_broker_config row exists and the per-tenant DB is
// reachable. isProvisioned returns (true, nil).
func TestProvisioningChecker_BothSignalsTrue_Ready(t *testing.T) {
	tenant := auth.MustNewTenantID("acme")
	probe := &fakeProbe{brokerExists: true, pingable: true}
	checker := newProvisioningChecker(probe, 5*time.Minute)

	ok, err := checker.isProvisioned(context.Background(), tenant)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.EqualValues(t, 1, probe.brokerCalls.Load())
	assert.EqualValues(t, 1, probe.pingCalls.Load())
}

// TestProvisioningChecker_BrokerAbsent_NotProvisionedError covers the
// "tenant never finished provisioning" terminal case. The broker_config
// row is absent so the daemon cannot construct a Vault provider; this is
// a NotProvisionedError that the dashboard renders as the "your data
// plane is still being set up" empty-state.
func TestProvisioningChecker_BrokerAbsent_NotProvisionedError(t *testing.T) {
	tenant := auth.MustNewTenantID("acme")
	probe := &fakeProbe{brokerExists: false}
	checker := newProvisioningChecker(probe, 5*time.Minute)

	ok, err := checker.isProvisioned(context.Background(), tenant)
	assert.False(t, ok)

	var npErr *NotProvisionedError
	require.ErrorAs(t, err, &npErr)
	assert.Equal(t, "acme", npErr.Tenant)
	assert.Contains(t, npErr.Reason, "broker_config")

	// Should NOT be confused with the unreachable error.
	var unreach *DataPlaneUnreachableError
	assert.False(t, errors.As(err, &unreach))

	// Did not waste a Pingable call when the broker row is absent.
	assert.EqualValues(t, 1, probe.brokerCalls.Load())
	assert.EqualValues(t, 0, probe.pingCalls.Load())
}

// TestProvisioningChecker_RowExistsButDBUnreachable_DataPlaneUnreachable
// covers the transient infrastructure case: the broker row says the
// tenant IS provisioned, but the per-tenant database is not currently
// reachable. The dashboard renders this as the "data plane is having
// trouble, retry shortly" empty-state — distinct from "you haven't
// finished provisioning yet."
func TestProvisioningChecker_RowExistsButDBUnreachable_DataPlaneUnreachable(t *testing.T) {
	tenant := auth.MustNewTenantID("acme")
	probe := &fakeProbe{brokerExists: true, pingable: false}
	checker := newProvisioningChecker(probe, 5*time.Minute)

	ok, err := checker.isProvisioned(context.Background(), tenant)
	assert.False(t, ok)

	var unreach *DataPlaneUnreachableError
	require.ErrorAs(t, err, &unreach)
	assert.Equal(t, "acme", unreach.Tenant)

	// Distinct from NotProvisioned — critical for the dashboard's empty-state routing.
	var npErr *NotProvisionedError
	assert.False(t, errors.As(err, &npErr))
}

// TestProvisioningChecker_ProbeError_PropagatesAsUnreachable verifies
// that a probe-level failure (e.g. platform postgres temporarily down)
// surfaces as DataPlaneUnreachableError so callers can retry. It is NOT
// cached — a transient failure should not poison the cache.
func TestProvisioningChecker_ProbeError_PropagatesAsUnreachable(t *testing.T) {
	tenant := auth.MustNewTenantID("acme")
	probe := &fakeProbe{brokerErr: errors.New("platform pg down")}
	checker := newProvisioningChecker(probe, 5*time.Minute)

	_, err := checker.isProvisioned(context.Background(), tenant)
	var unreach *DataPlaneUnreachableError
	require.ErrorAs(t, err, &unreach)

	// A second call should re-invoke the probe rather than serving a cached
	// "failed" state — transient failures must not pin the cache.
	_, _ = checker.isProvisioned(context.Background(), tenant)
	assert.EqualValues(t, 2, probe.brokerCalls.Load(), "probe failures must not be cached")
}

// TestProvisioningChecker_CacheHit_AvoidsProbe verifies the cache works:
// a second isProvisioned call within the TTL serves from cache and does
// not invoke the probe again.
func TestProvisioningChecker_CacheHit_AvoidsProbe(t *testing.T) {
	tenant := auth.MustNewTenantID("acme")
	probe := &fakeProbe{brokerExists: true, pingable: true}
	checker := newProvisioningChecker(probe, 5*time.Minute)

	_, err := checker.isProvisioned(context.Background(), tenant)
	require.NoError(t, err)

	_, err = checker.isProvisioned(context.Background(), tenant)
	require.NoError(t, err)

	// One probe call total — second isProvisioned served from cache.
	assert.EqualValues(t, 1, probe.brokerCalls.Load())
	assert.EqualValues(t, 1, probe.pingCalls.Load())
}

// TestProvisioningChecker_StaleCacheRefetches verifies that a cache
// entry older than the TTL triggers a fresh probe.
func TestProvisioningChecker_StaleCacheRefetches(t *testing.T) {
	tenant := auth.MustNewTenantID("refresh")
	probe := &fakeProbe{brokerExists: true, pingable: true}
	checker := newProvisioningChecker(probe, 1*time.Nanosecond)

	// First call populates the cache.
	_, err := checker.isProvisioned(context.Background(), tenant)
	require.NoError(t, err)
	assert.EqualValues(t, 1, probe.brokerCalls.Load())

	// Wait beyond TTL.
	time.Sleep(2 * time.Millisecond)

	// Second call must refetch.
	_, err = checker.isProvisioned(context.Background(), tenant)
	require.NoError(t, err)
	assert.EqualValues(t, 2, probe.brokerCalls.Load())
}

// TestProvisioningChecker_Invalidate verifies that an explicit cache
// invalidation forces a re-fetch on the next isProvisioned call,
// regardless of TTL.
func TestProvisioningChecker_Invalidate(t *testing.T) {
	tenant := auth.MustNewTenantID("inv")
	probe := &fakeProbe{brokerExists: true, pingable: true}
	checker := newProvisioningChecker(probe, 5*time.Minute)

	_, err := checker.isProvisioned(context.Background(), tenant)
	require.NoError(t, err)
	assert.EqualValues(t, 1, probe.brokerCalls.Load())

	checker.Invalidate(tenant)

	_, err = checker.isProvisioned(context.Background(), tenant)
	require.NoError(t, err)
	assert.EqualValues(t, 2, probe.brokerCalls.Load())
}

// TestProvisioningChecker_NilProbe_FailsClosed mirrors the previous
// "no Kubernetes client configured (dev mode)" semantics: a nil probe
// returns NotProvisionedError for every tenant. Production code must
// wire a real probe; the nil path is reserved for tests that exercise
// the not-provisioned branch without standing up the probe deps.
func TestProvisioningChecker_NilProbe_FailsClosed(t *testing.T) {
	tenant := auth.MustNewTenantID("acme")
	checker := newProvisioningChecker(nil, 5*time.Minute)

	_, err := checker.isProvisioned(context.Background(), tenant)
	var npErr *NotProvisionedError
	require.ErrorAs(t, err, &npErr)
}
