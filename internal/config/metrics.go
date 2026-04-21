package config

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ---------------------------------------------------------------------------
// Prometheus metrics (package-level, registered once per process)
// ---------------------------------------------------------------------------

var (
	modeMetricsOnce sync.Once
	modeInfoGauge   *prometheus.GaugeVec
)

// initModeMetrics registers the gibson_mode_info gauge exactly once per
// process. The sync.Once guard keeps tests hermetic when multiple Config
// instances are created in the same process.
func initModeMetrics() {
	modeMetricsOnce.Do(func() {
		modeInfoGauge = promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "gibson_mode_info",
				Help: "Deployment mode the Gibson daemon is running in (1 for the active mode). " +
					"Labels: mode=saas|selfhost|dev.",
			},
			[]string{"mode"},
		)
	})
}

// EmitModeMetric sets the gibson_mode_info{mode=<m>} gauge to 1 and resets
// all other mode labels to 0, so Prometheus time-series for inactive modes do
// not linger as stale series with value 1 after a restart.
//
// Call once from daemon startup, after config has been loaded and logged.
func EmitModeMetric(cfg *Config) {
	initModeMetrics()

	// Reset all known mode labels to 0 first to avoid ghost series across
	// daemon restarts that change mode.
	for _, m := range []Mode{ModeSaaS, ModeSelfhost, ModeDev} {
		modeInfoGauge.WithLabelValues(m.String()).Set(0)
	}

	// Set the active mode to 1.
	modeInfoGauge.WithLabelValues(cfg.Mode().String()).Set(1)
}
