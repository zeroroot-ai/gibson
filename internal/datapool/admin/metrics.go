package admin

import "github.com/zero-day-ai/gibson/internal/datapool/metrics"

// recordAcquire increments gibson_admin_pool_acquire_total for the given
// (rpc, subject) pair. The metric definition now lives in
// internal/datapool/metrics (Phase K consolidation). This wrapper keeps
// the call site in admin_pool.go unchanged.
//
// initMetrics is a no-op kept for call-site compatibility. The metric is
// registered by the metrics package init() function.
func initMetrics() {}

func recordAcquire(rpc, subject string) {
	metrics.IncAdminPoolAcquire(rpc, subject)
}
