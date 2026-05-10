// Package health emits sandbox health and tier indicator metrics.
//
// Spec setec-sandbox-prod-default Task 55 / R10.1 / R2.B.4.
//
// The tier gauge is a single, set-once-at-startup indicator that surfaces
// the active Setec tier in dashboards (R10.1 "Setec tier" panel) and
// alert routing (gibson_setec_tier{tier="production"} as a sanity check
// in alert annotations).
//
// The gauge value is always 1; the operationally interesting bit is the
// `tier` label. A scrape that shows zero `gibson_setec_tier` series means
// the daemon never set the gauge (likely a fail-closed startup before the
// metric registration ran), which is itself a useful operator signal.
//
// Design choice: the tier value comes from configuration (env
// GIBSON_SETEC_TIER, set by the chart in templates/gibson/statefulset.yaml).
// It is NOT hardcoded — forward-compatible with any future tier the
// design's deviation note allows ("future tiers, e.g., capacity-tiered or
// region-tiered, slot in here without code change").
package health

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// gibsonSetecTier is the constant-value-with-tier-label gauge.
// We set the gauge exactly once at startup via SetTier; promauto registers
// it on first reference. The sync.Once below ensures repeated SetTier
// calls do not flap the gauge (R10.1 explicitly requires "set once at
// startup; no flapping").
var gibsonSetecTier = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "gibson_setec_tier",
		Help: "Active Setec sandbox tier indicator. Value is always 1; the `tier` label carries the meaningful signal (today: only \"production\").",
	},
	[]string{"tier"},
)

// setOnce gates the SetTier call so a buggy caller cannot create multiple
// gauge series with conflicting tier labels.
var setOnce sync.Once

// SetTier records the active Setec tier. Idempotent: only the first call
// has effect; subsequent calls log a warning at the call site (the caller
// is expected to log; this package stays log-agnostic to avoid pulling in
// a logger dependency the tests would have to mock).
//
// Called once from cmd/gibson/main.go after config load, with tier sourced
// from GIBSON_SETEC_TIER (default "production" from the chart's
// values.yaml setec.tier default).
//
// If tier is empty, the call is a no-op — operators on a daemon build
// without GIBSON_SETEC_TIER wired (e.g. a unit-test binary) won't see the
// gauge, which is intended behaviour.
func SetTier(tier string) {
	if tier == "" {
		return
	}
	setOnce.Do(func() {
		gibsonSetecTier.WithLabelValues(tier).Set(1)
	})
}

// resetForTest is a test-only helper that resets the once-guard so
// individual unit tests can exercise SetTier with different inputs in
// isolation. Production callers MUST NOT use this — it would let a bug
// cause the gauge to flap, breaking the dashboard's tier panel.
//
//nolint:unused // exported via export_test.go for unit-test access only.
func resetForTest() {
	setOnce = sync.Once{}
	gibsonSetecTier.Reset()
}
