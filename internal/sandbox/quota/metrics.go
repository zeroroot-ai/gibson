// Package quota — metrics.go
//
// Prometheus metrics for per-tenant sandbox detonation observability.
// All metrics are registered once per process via sync.Once + promauto.
//
// Counter: gibson_sandbox_detonation_total
//   Labels: tenant (string), outcome (enum)
//   Outcomes: success | quota_exceeded | sandbox_unavailable | detonation_error | timeout
//
// Spec: setec-sandbox-prod-default §"Resource quotas" (R4.4, R4.6).
package quota

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	// Outcome label values — kept as constants so callers and tests share
	// a single source of truth and won't silently diverge on spelling.

	// OutcomeSuccess is the label value for a completed sandbox detonation.
	OutcomeSuccess = "success"

	// OutcomeQuotaExceeded is the label value when the per-tenant concurrent
	// detonation cap has been reached.
	OutcomeQuotaExceeded = "quota_exceeded"

	// OutcomeSandboxUnavailable is the label value when the dispatch gate
	// denies the call because the sandbox health check / circuit breaker
	// is in the open state.
	OutcomeSandboxUnavailable = "sandbox_unavailable"

	// OutcomeDetonationError is the label value for a sandbox launch failure
	// or a non-zero exit code returned by the microVM.
	OutcomeDetonationError = "detonation_error"

	// OutcomeTimeout is the label value when the microVM execution exceeds
	// the per-call timeout and is killed by the executor.
	OutcomeTimeout = "timeout"
)

var (
	metricsOnce           sync.Once
	detonationTotalVec    *prometheus.CounterVec
)

// initMetrics registers Prometheus metrics exactly once per process lifetime.
// Calling it multiple times is safe (the sync.Once guard prevents re-registration).
func initMetrics() {
	metricsOnce.Do(func() {
		detonationTotalVec = promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gibson_sandbox_detonation_total",
				Help: "Total number of sandbox detonations by tenant and outcome. " +
					"Outcomes: success | quota_exceeded | sandbox_unavailable | " +
					"detonation_error | timeout.",
			},
			[]string{"tenant", "outcome"},
		)
	})
}

// IncrDetonation increments the per-tenant detonation counter for the given
// outcome. Calling IncrDetonation before the metrics are initialised is a
// no-op (the counter vector is nil until the first call to initMetrics or
// NewRedisQuota).
func IncrDetonation(tenant, outcome string) {
	if detonationTotalVec == nil {
		return
	}
	detonationTotalVec.WithLabelValues(tenant, outcome).Inc()
}
