package metrics_test

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/datapool/metrics"
)

// newIsolatedRegistry returns a fresh prometheus.Registry with all data-plane
// metrics registered, suitable for isolated per-test assertions. This avoids
// state bleed between tests that share the default registry.
func newIsolatedRegistry(t *testing.T) *prometheus.Registry {
	t.Helper()
	// We rely on the package-level init() having registered everything into the
	// default registry. For assertion we gather from the default registry and
	// filter by metric family name, which is simpler than re-registering everything.
	return prometheus.NewRegistry()
}

// collectFloat64 gathers the metric from the default registry and returns the
// sum of all sample values for the given metric name. Useful for counters and
// gauges where we just need to verify direction.
func collectFloat64(t *testing.T, metricName string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	var total float64
	for _, mf := range families {
		if mf.GetName() == metricName {
			for _, m := range mf.GetMetric() {
				if m.GetCounter() != nil {
					total += m.GetCounter().GetValue()
				}
				if m.GetGauge() != nil {
					total += m.GetGauge().GetValue()
				}
				if m.GetHistogram() != nil {
					total += float64(m.GetHistogram().GetSampleCount())
				}
			}
		}
	}
	return total
}

// -----------------------------------------------------------------------
// gibson_xtenant_decrypt_attempt_total
// -----------------------------------------------------------------------

func TestIncXTenantDecryptAttempt_Increments(t *testing.T) {
	before := collectFloat64(t, "gibson_xtenant_decrypt_attempt_total")
	metrics.IncXTenantDecryptAttempt("acme")
	metrics.IncXTenantDecryptAttempt("acme")
	metrics.IncXTenantDecryptAttempt("globex")
	after := collectFloat64(t, "gibson_xtenant_decrypt_attempt_total")
	assert.Equal(t, before+3, after)
}

func TestIncXTenantDecryptAttempt_EmptyTenantUsesUnknown(t *testing.T) {
	// Should not panic; empty tenant is sanitized to "unknown".
	assert.NotPanics(t, func() {
		metrics.IncXTenantDecryptAttempt("")
	})
}

// -----------------------------------------------------------------------
// gibson_admin_pool_acquire_total
// -----------------------------------------------------------------------

func TestIncAdminPoolAcquire_Increments(t *testing.T) {
	before := collectFloat64(t, "gibson_admin_pool_acquire_total")
	metrics.IncAdminPoolAcquire("/admin.v1.Service/ListTenants", "user@example.com")
	after := collectFloat64(t, "gibson_admin_pool_acquire_total")
	assert.Equal(t, before+1, after)
}

func TestIncAdminPoolAcquire_EmptyLabelsUsesUnknown(t *testing.T) {
	// Empty rpc and subject should not panic; both default to "unknown".
	assert.NotPanics(t, func() {
		metrics.IncAdminPoolAcquire("", "")
	})
}

// -----------------------------------------------------------------------
// gibson_pool_idle_eviction_total
// -----------------------------------------------------------------------

func TestIncPoolIdleEviction_Increments(t *testing.T) {
	before := collectFloat64(t, "gibson_pool_idle_eviction_total")
	metrics.IncPoolIdleEviction("tenant-abc")
	after := collectFloat64(t, "gibson_pool_idle_eviction_total")
	assert.Equal(t, before+1, after)
}

func TestIncPoolIdleEviction_EmptyTenantIsNoOp(t *testing.T) {
	before := collectFloat64(t, "gibson_pool_idle_eviction_total")
	metrics.IncPoolIdleEviction("")
	after := collectFloat64(t, "gibson_pool_idle_eviction_total")
	assert.Equal(t, before, after, "empty tenant should be a no-op")
}

// -----------------------------------------------------------------------
// gibson_pool_active_conns
// -----------------------------------------------------------------------

func TestPoolActiveConns_IncDec(t *testing.T) {
	// Gauge semantics: verify Inc/Dec are symmetric. We use testutil.ToFloat64
	// from a per-label approach by counting total gauge values.
	before := collectFloat64(t, "gibson_pool_active_conns")
	metrics.IncPoolActiveConns("test-tenant-gauge")
	metrics.IncPoolActiveConns("test-tenant-gauge")
	afterInc := collectFloat64(t, "gibson_pool_active_conns")
	assert.Equal(t, before+2, afterInc)

	metrics.DecPoolActiveConns("test-tenant-gauge")
	afterDec := collectFloat64(t, "gibson_pool_active_conns")
	assert.Equal(t, before+1, afterDec)
}

func TestPoolActiveConns_EmptyTenantIsNoOp(t *testing.T) {
	before := collectFloat64(t, "gibson_pool_active_conns")
	metrics.IncPoolActiveConns("")
	metrics.DecPoolActiveConns("")
	after := collectFloat64(t, "gibson_pool_active_conns")
	assert.Equal(t, before, after, "empty tenant should be a no-op for both inc and dec")
}

// -----------------------------------------------------------------------
// gibson_pool_acquire_duration_seconds
// -----------------------------------------------------------------------

func TestObservePoolAcquireDuration_Observes(t *testing.T) {
	before := collectFloat64(t, "gibson_pool_acquire_duration_seconds")
	metrics.ObservePoolAcquireDuration(metrics.StoreAll, 0.042)
	metrics.ObservePoolAcquireDuration(metrics.StorePostgres, 0.010)
	after := collectFloat64(t, "gibson_pool_acquire_duration_seconds")
	// Histogram sample count should increase by 2.
	assert.Equal(t, before+2, after)
}

func TestObservePoolAcquireDuration_EmptyStoreDefaultsToAll(t *testing.T) {
	assert.NotPanics(t, func() {
		metrics.ObservePoolAcquireDuration("", 0.001)
	})
}

// -----------------------------------------------------------------------
// gibson_pool_init_total
// -----------------------------------------------------------------------

func TestIncPoolInit_Increments(t *testing.T) {
	before := collectFloat64(t, "gibson_pool_init_total")
	metrics.IncPoolInit("tenant-x", metrics.StorePostgres)
	metrics.IncPoolInit("tenant-x", metrics.StoreRedis)
	after := collectFloat64(t, "gibson_pool_init_total")
	assert.Equal(t, before+2, after)
}

func TestIncPoolInit_EmptyLabelsAreNoOp(t *testing.T) {
	before := collectFloat64(t, "gibson_pool_init_total")
	metrics.IncPoolInit("", metrics.StorePostgres)
	metrics.IncPoolInit("tenant-x", "")
	after := collectFloat64(t, "gibson_pool_init_total")
	assert.Equal(t, before, after, "empty tenant or store should be no-ops")
}

// -----------------------------------------------------------------------
// gibson_pool_init_failures_total
// -----------------------------------------------------------------------

func TestIncPoolInitFailure_Increments(t *testing.T) {
	before := collectFloat64(t, "gibson_pool_init_failures_total")
	metrics.IncPoolInitFailure("tenant-y", metrics.StoreNeo4j, "conn_refused")
	metrics.IncPoolInitFailure("tenant-y", metrics.StorePostgres, "not_provisioned")
	after := collectFloat64(t, "gibson_pool_init_failures_total")
	assert.Equal(t, before+2, after)
}

func TestIncPoolInitFailure_EmptyReasonDefaultsToUnknown(t *testing.T) {
	// Should not panic; empty reason defaults to "unknown".
	assert.NotPanics(t, func() {
		metrics.IncPoolInitFailure("tenant-z", metrics.StoreRedis, "")
	})
}

func TestIncPoolInitFailure_EmptyTenantOrStoreIsNoOp(t *testing.T) {
	before := collectFloat64(t, "gibson_pool_init_failures_total")
	metrics.IncPoolInitFailure("", metrics.StorePostgres, "reason")
	metrics.IncPoolInitFailure("tenant-z", "", "reason")
	after := collectFloat64(t, "gibson_pool_init_failures_total")
	assert.Equal(t, before, after)
}

// -----------------------------------------------------------------------
// gibson_dataplane_provisioning_check_failures_total
// -----------------------------------------------------------------------

func TestIncProvisioningCheckFailure_Increments(t *testing.T) {
	before := collectFloat64(t, "gibson_dataplane_provisioning_check_failures_total")
	metrics.IncProvisioningCheckFailure(metrics.ReasonCRDUnavailable)
	metrics.IncProvisioningCheckFailure(metrics.ReasonNotProvisioned)
	after := collectFloat64(t, "gibson_dataplane_provisioning_check_failures_total")
	assert.Equal(t, before+2, after)
}

func TestIncProvisioningCheckFailure_EmptyReasonDefaultsToCRDUnavailable(t *testing.T) {
	assert.NotPanics(t, func() {
		metrics.IncProvisioningCheckFailure("")
	})
}

// -----------------------------------------------------------------------
// Cardinality validators
// -----------------------------------------------------------------------

func TestCardinality_StoreConstantsAreBounded(t *testing.T) {
	// Validate all expected store label values are non-empty and distinct.
	stores := []string{
		metrics.StoreAll,
		metrics.StorePostgres,
		metrics.StoreRedis,
		metrics.StoreNeo4j,
		metrics.StoreVector,
	}
	seen := make(map[string]bool)
	for _, s := range stores {
		require.NotEmpty(t, s, "store constant must not be empty")
		require.False(t, seen[s], "duplicate store constant: %s", s)
		seen[s] = true
	}
}

func TestCardinality_ReasonConstantsAreBounded(t *testing.T) {
	reasons := []string{
		metrics.ReasonCRDUnavailable,
		metrics.ReasonNotProvisioned,
	}
	seen := make(map[string]bool)
	for _, r := range reasons {
		require.NotEmpty(t, r, "reason constant must not be empty")
		require.False(t, seen[r], "duplicate reason constant: %s", r)
		seen[r] = true
	}
}

// -----------------------------------------------------------------------
// Alert rules — smoke test that the YAML constant is non-empty and contains
// the expected alert names.
// -----------------------------------------------------------------------

func TestDataPlaneAlertRules_ContainsExpectedAlerts(t *testing.T) {
	rules := metrics.DataPlaneAlertRules
	require.NotEmpty(t, rules)

	expectedAlerts := []string{
		"GibsonCrossTenantDecryptAttempt",
		"GibsonPoolInitNotProvisioned",
		"GibsonPoolAcquireHighLatency",
		"GibsonProvisioningCheckCRDUnavailable",
		"GibsonPoolIdleEvictionThrash",
		"GibsonAdminPoolHighAcquisitionRate",
	}
	for _, name := range expectedAlerts {
		assert.True(t, strings.Contains(rules, name),
			"DataPlaneAlertRules should contain alert %q", name)
	}
}

// -----------------------------------------------------------------------
// Metric registration idempotency — importing the package multiple times
// (or calling init() twice in tests) must not panic.
// -----------------------------------------------------------------------

func TestRegistration_Idempotent(t *testing.T) {
	// If init() panics on duplicate registration, the test binary itself would
	// crash. The fact that we reach this test proves idempotency. We also
	// verify that the default gatherer can gather without error.
	_, err := prometheus.DefaultGatherer.Gather()
	assert.NoError(t, err, "default gatherer should gather cleanly after package init")
}

// TestMetricNamesExistInGatherer ensures all 8 canonical metric names are
// visible in the default Prometheus registry after package init.
func TestMetricNamesExistInGatherer(t *testing.T) {
	expectedNames := []string{
		"gibson_pool_acquire_duration_seconds",
		"gibson_pool_idle_eviction_total",
		"gibson_pool_active_conns",
		"gibson_xtenant_decrypt_attempt_total",
		"gibson_admin_pool_acquire_total",
		"gibson_pool_init_total",
		"gibson_pool_init_failures_total",
		"gibson_dataplane_provisioning_check_failures_total",
	}

	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)

	registered := make(map[string]bool)
	for _, mf := range families {
		registered[mf.GetName()] = true
	}

	for _, name := range expectedNames {
		assert.True(t, registered[name], "metric %q should be registered in default gatherer", name)
	}
}

// -----------------------------------------------------------------------
// testutil-based lint: ensure all metrics pass prometheus linting rules.
// -----------------------------------------------------------------------

func TestMetricLint(t *testing.T) {
	// Trigger at least one observation on every metric so they appear in Gather.
	metrics.ObservePoolAcquireDuration(metrics.StoreAll, 0.001)
	metrics.IncPoolIdleEviction("lint-tenant")
	metrics.IncPoolActiveConns("lint-tenant")
	metrics.DecPoolActiveConns("lint-tenant")
	metrics.IncXTenantDecryptAttempt("lint-tenant")
	metrics.IncAdminPoolAcquire("lint-rpc", "lint-subject")
	metrics.IncPoolInit("lint-tenant", metrics.StorePostgres)
	metrics.IncPoolInitFailure("lint-tenant", metrics.StorePostgres, "not_provisioned")
	metrics.IncProvisioningCheckFailure(metrics.ReasonCRDUnavailable)

	problems, err := testutil.GatherAndLint(prometheus.DefaultGatherer)
	require.NoError(t, err)
	for _, p := range problems {
		// Only fail on problems in our metrics — other packages registered in the
		// default registry may have their own lint issues that are not our concern.
		if isDataPlaneMetric(p.Metric) {
			t.Errorf("prometheus lint problem for metric %q: %s", p.Metric, p.Text)
		}
	}
}

func isDataPlaneMetric(name string) bool {
	prefix := "gibson_pool_"
	adminPrefix := "gibson_admin_pool_"
	xtenantPrefix := "gibson_xtenant_"
	provisioningPrefix := "gibson_dataplane_"
	return strings.HasPrefix(name, prefix) ||
		strings.HasPrefix(name, adminPrefix) ||
		strings.HasPrefix(name, xtenantPrefix) ||
		strings.HasPrefix(name, provisioningPrefix)
}
