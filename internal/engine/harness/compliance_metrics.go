package harness

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// emitLatencyBuckets are tuned for compliance signal emission overhead —
// well under a millisecond on the fast path, up to a few hundred ms on the
// slow path (when the graph lookup in the resource resolver is slow).
var emitLatencyBuckets = []float64{
	0.00005, // 50µs
	0.0001,  // 100µs
	0.00025, // 250µs
	0.0005,  // 500µs
	0.001,   // 1ms
	0.0025,  // 2.5ms
	0.005,   // 5ms
	0.01,    // 10ms
	0.025,   // 25ms
	0.05,    // 50ms
	0.1,     // 100ms
	0.25,    // 250ms
	0.5,     // 500ms
	1.0,     // 1s
}

// ComplianceMetrics collects Prometheus metrics for the compliance emitter.
// Labels are intentionally low-cardinality (bounded by closed vocabularies
// from the taxonomy YAML and fixed reason strings) per Requirement 11 and
// the non-functional cardinality constraint in requirements.md.
//
// NO tenant, actor, or free-form labels — those would explode cardinality at
// Gibson's signal rate and are queryable via the graph instead.
type ComplianceMetrics struct {
	// SignalsEmitted counts successful + failed signal emissions, labeled by
	// action, effect, and success so that operators can see effect=write
	// failures specifically.
	SignalsEmitted *prometheus.CounterVec

	// PersistFailures counts signal persistence failures by reason
	// (e.g., "neo4j_unavailable", "validation_error", "panic", "serialization_error").
	PersistFailures *prometheus.CounterVec

	// EmitLatency observes the wall-clock time the emit() path takes, from
	// entering the middleware to completing persistence (or dropping into
	// the failure buffer).
	EmitLatency prometheus.Histogram

	// SignalsDropped counts signals dropped from the bounded fail buffer
	// when the buffer is full (Requirement 10.3).
	SignalsDropped prometheus.Counter

	// SignalsBuffered is the current depth of the fail buffer, consumed by
	// the /readyz health check (Requirement 11.3).
	SignalsBuffered prometheus.Gauge

	// ReservedKeyViolations counts tag-merge events where a reserved key's
	// value failed closed-vocabulary validation (Requirement 5.5). Labels
	// are bounded by the reserved-key list and the source precedence.
	ReservedKeyViolations *prometheus.CounterVec

	// SubstrateEmissions counts signals projected from the audit substrates
	// (audit_logger, auth_audit), per Requirement 9.5.
	SubstrateEmissions *prometheus.CounterVec

	// EmitterDisabled is 1 when the emitter has been put into emergency
	// no-op mode via the disable flag, 0 otherwise (Requirement 12.2).
	EmitterDisabled prometheus.Gauge
}

// NewComplianceMetrics constructs a new ComplianceMetrics with all collectors
// initialized. Call Register or MustRegister separately to attach the
// collectors to a Prometheus registry — the constructor does not auto-register
// to keep tests hermetic.
func NewComplianceMetrics() *ComplianceMetrics {
	return &ComplianceMetrics{
		SignalsEmitted: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gibson_compliance_signals_emitted_total",
				Help: "Total compliance signals emitted by the daemon harness middleware",
			},
			[]string{"action", "effect", "success"},
		),
		PersistFailures: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gibson_compliance_signal_persist_failures_total",
				Help: "Total compliance signal persistence failures by reason",
			},
			[]string{"reason"},
		),
		EmitLatency: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "gibson_compliance_signal_emit_latency_seconds",
				Help:    "Time taken to build and persist a compliance signal",
				Buckets: emitLatencyBuckets,
			},
		),
		SignalsDropped: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "gibson_compliance_signals_dropped_total",
				Help: "Total compliance signals dropped from the bounded fail buffer",
			},
		),
		SignalsBuffered: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "gibson_compliance_signals_buffered",
				Help: "Current depth of the compliance signal fail buffer",
			},
		),
		ReservedKeyViolations: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gibson_compliance_reserved_key_violations_total",
				Help: "Total reserved-key closed-vocabulary violations during tag merge",
			},
			[]string{"key", "source"},
		),
		SubstrateEmissions: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gibson_compliance_signal_substrate_emissions_total",
				Help: "Total compliance signals projected from audit substrates",
			},
			[]string{"source"},
		),
		EmitterDisabled: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "gibson_compliance_emitter_disabled",
				Help: "1 when the compliance emitter is in emergency no-op mode, 0 otherwise",
			},
		),
	}
}

// collectors returns every Prometheus collector owned by ComplianceMetrics.
// Used by Register and MustRegister.
func (m *ComplianceMetrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{
		m.SignalsEmitted,
		m.PersistFailures,
		m.EmitLatency,
		m.SignalsDropped,
		m.SignalsBuffered,
		m.ReservedKeyViolations,
		m.SubstrateEmissions,
		m.EmitterDisabled,
	}
}

// Register attaches all collectors to the given registerer. Returns the
// first registration error encountered — later collectors are NOT registered
// if an earlier one fails.
func (m *ComplianceMetrics) Register(r prometheus.Registerer) error {
	for _, c := range m.collectors() {
		if err := r.Register(c); err != nil {
			return err
		}
	}
	return nil
}

// MustRegister attaches all collectors to the default registry and panics on
// failure. Call this from daemon startup.
func (m *ComplianceMetrics) MustRegister() {
	prometheus.MustRegister(m.collectors()...)
}

// Global singleton for the compliance metrics, initialised on first use.
// The middleware should accept a *ComplianceMetrics via constructor injection
// in production; tests construct their own to avoid collector re-registration
// panics.
var (
	globalComplianceMetrics     *ComplianceMetrics
	globalComplianceMetricsOnce sync.Once
)

// --- Convenience recording helpers (thin wrappers that document intent) ---

// RecordEmitted increments SignalsEmitted with the canonical labels.
func (m *ComplianceMetrics) RecordEmitted(action, effect string, success bool) {
	s := "true"
	if !success {
		s = "false"
	}
	m.SignalsEmitted.WithLabelValues(action, effect, s).Inc()
}

// RecordPersistFailure increments PersistFailures with a stable reason key.
func (m *ComplianceMetrics) RecordPersistFailure(reason string) {
	m.PersistFailures.WithLabelValues(reason).Inc()
}

// RecordSubstrateEmission counts a successful substrate projection.
func (m *ComplianceMetrics) RecordSubstrateEmission(source string) {
	m.SubstrateEmissions.WithLabelValues(source).Inc()
}

// RecordReservedKeyViolation counts a reserved-key vocabulary violation.
func (m *ComplianceMetrics) RecordReservedKeyViolation(key, source string) {
	m.ReservedKeyViolations.WithLabelValues(key, source).Inc()
}

// SetBuffered sets the current fail-buffer depth.
func (m *ComplianceMetrics) SetBuffered(depth int) {
	m.SignalsBuffered.Set(float64(depth))
}

// SetDisabled sets the emergency-disabled gauge.
func (m *ComplianceMetrics) SetDisabled(disabled bool) {
	if disabled {
		m.EmitterDisabled.Set(1)
	} else {
		m.EmitterDisabled.Set(0)
	}
}
