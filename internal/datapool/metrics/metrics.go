// Package metrics defines and exports all data-plane observability metrics for
// the Gibson daemon's per-tenant connection pool subsystem.
//
// All eight canonical metrics are defined in this single file so there is one
// authoritative source of metric names, label sets, and bucket configurations.
// No other package in the daemon may declare prometheus.NewCounterVec,
// NewHistogramVec, or NewGaugeVec for data-plane metrics — call the typed
// Inc*/Observe*/Set* helpers exported here instead.
//
// High-cardinality guidance:
//   - The "tenant" label is bounded by active tenant count and is acceptable
//     on eviction, active-conn, and cross-tenant-decrypt metrics where
//     per-tenant attribution is required (Requirement 6.5).
//   - The "tenant" label is intentionally absent from gibson_pool_acquire_duration_seconds
//     because it is on the hot path of every Pool.For call; per-store resolution
//     is sufficient for latency alerting. Per-tenant latency is derivable from
//     the gibson_pool_active_conns gauge.
//
// Spec: database-per-tenant-data-plane, Phase K, task 11.1.
// Requirements: 16.4.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Label name constants prevent typos at call sites.
const (
	LabelStore  = "store"
	LabelTenant = "tenant"
	LabelRPC    = "rpc"
	LabelSubject = "subject"
	LabelReason = "reason"

	// Store label values used by Inc/Observe helpers.
	StorePostgres = "postgres"
	StoreRedis    = "redis"
	StoreNeo4j    = "neo4j"
	StoreVector   = "vector"
	StoreAll      = "all"

	// Reason label values for provisioning check failures.
	ReasonCRDUnavailable = "crd_unavailable"
	ReasonNotProvisioned = "not_provisioned"
)

var (
	// poolAcquireDuration tracks Pool.For() latency from first call to conn
	// returned. Labeled by store="all" for the total acquire, or per-store name
	// when sub-pool init is timed individually in future work.
	//
	// Alert: p99 > 500ms is a warning.
	poolAcquireDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "gibson_pool_acquire_duration_seconds",
			Help:    "Latency of Pool.For() from entry to Conn returned, in seconds. Label 'store' identifies which store was the bottleneck.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0},
		},
		[]string{LabelStore},
	)

	// poolIdleEvictionTotal counts the number of tenant pools evicted due to
	// idle timeout. One increment per evicted tenant per evictor sweep.
	poolIdleEvictionTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gibson_pool_idle_eviction_total",
			Help: "Number of per-tenant pool evictions due to idle timeout.",
		},
		[]string{LabelTenant},
	)

	// poolActiveConns is a gauge tracking the number of currently checked-out
	// Conns per tenant. Incremented on Pool.For() success; decremented on
	// Conn.Release(). Never goes negative.
	poolActiveConns = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gibson_pool_active_conns",
			Help: "Number of currently checked-out Conns per tenant.",
		},
		[]string{LabelTenant},
	)

	// xTenantDecryptAttemptTotal counts AES-Unwrap authentication failures
	// that indicate a cross-tenant decryption attempt. Any non-zero value is
	// alert-worthy (Requirement 6.5).
	//
	// Migrated from internal/database/metrics.go (Phase K).
	xTenantDecryptAttemptTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gibson_xtenant_decrypt_attempt_total",
			Help: "Number of AES-Unwrap authentication failures indicating a cross-tenant decryption attempt. Any non-zero value is alert-worthy (Requirement 6.5).",
		},
		[]string{LabelTenant},
	)

	// adminPoolAcquireTotal counts AdminConn acquisitions. Every acquisition is
	// an audit event (Requirement 11.3). Labeled by rpc method and calling subject.
	//
	// Migrated from internal/datapool/admin/metrics.go (Phase K).
	adminPoolAcquireTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gibson_admin_pool_acquire_total",
			Help: "Total number of AdminConn acquisitions labeled by RPC method and calling subject. Every non-zero value is an audit event.",
		},
		[]string{LabelRPC, LabelSubject},
	)

	// poolInitTotal counts the first-time per-store sub-pool creation per tenant.
	poolInitTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gibson_pool_init_total",
			Help: "Number of first-time per-store sub-pool initializations, labeled by tenant and store.",
		},
		[]string{LabelTenant, LabelStore},
	)

	// poolInitFailuresTotal counts per-store sub-pool creation failures.
	// The reason label captures the failure category (not_provisioned, conn_refused, etc.).
	poolInitFailuresTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gibson_pool_init_failures_total",
			Help: "Number of per-store sub-pool initialization failures, labeled by tenant, store, and reason.",
		},
		[]string{LabelTenant, LabelStore, LabelReason},
	)

	// dataplaneProvisioningCheckFailuresTotal counts provisioning_check.go cache-miss
	// fetch failures. The reason label is one of crd_unavailable|not_provisioned.
	dataplaneProvisioningCheckFailuresTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gibson_dataplane_provisioning_check_failures_total",
			Help: "Number of provisioning check failures when fetching tenant CRD status. Labeled by reason (crd_unavailable|not_provisioned).",
		},
		[]string{LabelReason},
	)
)

func init() {
	// Register all metrics against the default Prometheus registry. On duplicate
	// registration (e.g., in tests importing multiple packages that both call
	// init), prometheus.Register returns an AlreadyRegisteredError which we
	// intentionally ignore so tests can import this package freely.
	for _, c := range []prometheus.Collector{
		poolAcquireDuration,
		poolIdleEvictionTotal,
		poolActiveConns,
		xTenantDecryptAttemptTotal,
		adminPoolAcquireTotal,
		poolInitTotal,
		poolInitFailuresTotal,
		dataplaneProvisioningCheckFailuresTotal,
	} {
		if err := prometheus.Register(c); err != nil {
			// AlreadyRegisteredError is benign; surface any other unexpected error
			// via panic so mis-registration is caught during development.
			var are prometheus.AlreadyRegisteredError
			if ok := isAlreadyRegistered(err, &are); !ok {
				panic("datapool/metrics: failed to register metric: " + err.Error())
			}
		}
	}
}

// isAlreadyRegistered checks whether err is a prometheus.AlreadyRegisteredError
// and writes it to target. This avoids importing reflect for a type assertion.
func isAlreadyRegistered(err error, target *prometheus.AlreadyRegisteredError) bool {
	if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
		*target = are
		return true
	}
	return false
}

// -------------------------------------------------------------------
// Typed helpers — callers use these instead of raw *Vec references.
// -------------------------------------------------------------------

// ObservePoolAcquireDuration records the duration of a Pool.For() call.
// store must be one of the Store* constants (StoreAll, StorePostgres, etc.).
func ObservePoolAcquireDuration(store string, seconds float64) {
	if store == "" {
		store = StoreAll
	}
	poolAcquireDuration.WithLabelValues(store).Observe(seconds)
}

// IncPoolIdleEviction increments the idle eviction counter for the given tenant.
// tenant must be the string representation of auth.TenantID.
func IncPoolIdleEviction(tenant string) {
	if tenant == "" {
		return
	}
	poolIdleEvictionTotal.WithLabelValues(tenant).Inc()
}

// IncPoolActiveConns increments the active connection gauge for tenant.
func IncPoolActiveConns(tenant string) {
	if tenant == "" {
		return
	}
	poolActiveConns.WithLabelValues(tenant).Inc()
}

// DecPoolActiveConns decrements the active connection gauge for tenant.
func DecPoolActiveConns(tenant string) {
	if tenant == "" {
		return
	}
	poolActiveConns.WithLabelValues(tenant).Dec()
}

// IncXTenantDecryptAttempt increments the cross-tenant decrypt counter for tenant.
// Any non-zero value triggers an alert per Requirement 6.5.
func IncXTenantDecryptAttempt(tenant string) {
	if tenant == "" {
		tenant = "unknown"
	}
	xTenantDecryptAttemptTotal.WithLabelValues(tenant).Inc()
}

// IncAdminPoolAcquire increments the admin pool acquire counter.
// rpc and subject are sanitized to "unknown" when empty.
func IncAdminPoolAcquire(rpc, subject string) {
	if rpc == "" {
		rpc = "unknown"
	}
	if subject == "" {
		subject = "unknown"
	}
	adminPoolAcquireTotal.WithLabelValues(rpc, subject).Inc()
}

// IncPoolInit increments the sub-pool initialization counter for a
// (tenant, store) pair. Called on first successful per-store connection.
func IncPoolInit(tenant, store string) {
	if tenant == "" || store == "" {
		return
	}
	poolInitTotal.WithLabelValues(tenant, store).Inc()
}

// IncPoolInitFailure increments the sub-pool initialization failure counter
// for a (tenant, store, reason) triple. reason should be a short, bounded
// string such as "not_provisioned", "conn_refused", or "timeout".
func IncPoolInitFailure(tenant, store, reason string) {
	if tenant == "" || store == "" {
		return
	}
	if reason == "" {
		reason = "unknown"
	}
	poolInitFailuresTotal.WithLabelValues(tenant, store, reason).Inc()
}

// IncProvisioningCheckFailure increments the provisioning check failure counter.
// reason must be one of ReasonCRDUnavailable or ReasonNotProvisioned.
func IncProvisioningCheckFailure(reason string) {
	if reason == "" {
		reason = ReasonCRDUnavailable
	}
	dataplaneProvisioningCheckFailuresTotal.WithLabelValues(reason).Inc()
}
