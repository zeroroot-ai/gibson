package ontology

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// closureRebuildBuckets are tuned for synchronous in-memory closure rebuild:
// small vocabs (tens of thousands of triples) should complete in
// microseconds to low milliseconds.
var closureRebuildBuckets = []float64{
	0.0001, // 100µs
	0.0005, // 500µs
	0.001,  // 1ms
	0.005,  // 5ms
	0.01,   // 10ms
	0.025,  // 25ms
	0.05,   // 50ms
	0.1,    // 100ms
	0.25,   // 250ms
	0.5,    // 500ms
	1.0,    // 1s
}

// timerFunc is the function returned by Histogram.Start-like patterns.
// Calling it records the observation.
type timerFunc func()

// Metrics holds Prometheus collectors for the ontology reasoner.
type Metrics struct {
	// ExtensionsLoaded is a gauge per extension name: 1 when registered, 0
	// after unregister.
	ExtensionsLoaded *prometheus.GaugeVec

	// IRIsTotal is the total number of distinct IRIs in the live graph.
	IRIsTotal prometheus.Gauge

	// ClosureRebuildDuration observes the wall-clock time for each synchronous
	// closure rebuild triggered by RegisterExtension / UnregisterExtension.
	ClosureRebuildDuration *histogramTimer

	// RegistrationFailures counts rejected RegisterExtension calls, labelled
	// by reason: "cycle", "unknown_prefix".
	RegistrationFailures *prometheus.CounterVec
}

// NewMetrics constructs Metrics with all collectors initialised but NOT
// registered in any Prometheus registry. Call Register to attach.
func NewMetrics() *Metrics {
	return &Metrics{
		ExtensionsLoaded: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "reasoner_extensions_loaded",
				Help: "1 when a named ontology extension is registered; 0 after unregister.",
			},
			[]string{"extension"},
		),
		IRIsTotal: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "reasoner_iris_total",
				Help: "Total number of distinct IRIs in the live ontology graph.",
			},
		),
		ClosureRebuildDuration: newHistogramTimer(prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "reasoner_closure_rebuild_duration_seconds",
				Help:    "Duration of synchronous transitive-closure rebuilds.",
				Buckets: closureRebuildBuckets,
			},
		)),
		RegistrationFailures: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "reasoner_registration_failures_total",
				Help: "Count of failed RegisterExtension calls, by reason (cycle, unknown_prefix).",
			},
			[]string{"reason"},
		),
	}
}

// Register registers all collectors with reg. Returns the first error
// encountered.
func (m *Metrics) Register(reg prometheus.Registerer) error {
	for _, c := range []prometheus.Collector{
		m.ExtensionsLoaded,
		m.IRIsTotal,
		m.ClosureRebuildDuration.h,
		m.RegistrationFailures,
	} {
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	return nil
}

// MustRegister registers all collectors with reg, panicking on error.
func (m *Metrics) MustRegister(reg prometheus.Registerer) {
	if err := m.Register(reg); err != nil {
		panic(err)
	}
}

// histogramTimer wraps a prometheus.Histogram to expose a Start() method that
// returns a stop function (records the observation when called).
type histogramTimer struct {
	h  prometheus.Histogram
	mu sync.Mutex
}

func newHistogramTimer(h prometheus.Histogram) *histogramTimer {
	return &histogramTimer{h: h}
}

// Start begins a timer. The returned function records the elapsed duration
// when called. Each Start call produces an independent timer.
func (t *histogramTimer) Start() timerFunc {
	timer := prometheus.NewTimer(t.h)
	return func() { timer.ObserveDuration() }
}
