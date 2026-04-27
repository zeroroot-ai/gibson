package admin

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	metricsOnce          sync.Once
	adminPoolAcquireTotal *prometheus.CounterVec
)

// initMetrics registers the Prometheus counters once per process lifetime.
// The sync.Once guard ensures they are registered exactly once even when
// multiple AdminPool instances are created (e.g., in tests).
func initMetrics() {
	metricsOnce.Do(func() {
		adminPoolAcquireTotal = promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gibson_admin_pool_acquire_total",
				Help: "Total number of AdminConn acquisitions, labeled by RPC method and calling subject. Every non-zero value is an audit event.",
			},
			[]string{"rpc", "subject"},
		)
	})
}

// recordAcquire increments the admin_pool_acquire metric for the given
// (rpc, subject) pair. Called inside Acquire after authorization succeeds.
func recordAcquire(rpc, subject string) {
	if rpc == "" {
		rpc = "unknown"
	}
	if subject == "" {
		subject = "unknown"
	}
	adminPoolAcquireTotal.WithLabelValues(rpc, subject).Inc()
}
