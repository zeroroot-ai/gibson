package checkpoint

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Bucket definitions for histograms
var (
	// sizeBuckets defines buckets for checkpoint size measurements (1KB to 100MB)
	sizeBuckets = []float64{1024, 10240, 102400, 1048576, 10485760, 104857600}

	// durationBuckets defines buckets for duration measurements (10ms to 5s)
	durationBuckets = []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 5}
)

// CheckpointMetrics provides Prometheus metrics for checkpoint operations
type CheckpointMetrics struct {
	// Counters
	checkpointsCreated  *prometheus.CounterVec
	checkpointsRestored *prometheus.CounterVec
	checkpointsDeleted  *prometheus.CounterVec

	// Histograms
	checkpointSize    *prometheus.HistogramVec
	createDuration    *prometheus.HistogramVec
	restoreDuration   *prometheus.HistogramVec
	serializeDuration *prometheus.HistogramVec

	// Gauges
	activeThreads *prometheus.GaugeVec

	// Spec 4 R7.1 series — orchestrator-driven write/restore observability.
	// These intentionally have no per-mission labels (cardinality control).
	writeDurationMs     prometheus.Histogram
	writeSizeBytes      prometheus.Histogram
	writeFailureTotal   *prometheus.CounterVec // labels: reason
	restoreDurationMs   prometheus.Histogram
	restoreTotal        *prometheus.CounterVec // labels: outcome
	resumeFromScratch   prometheus.Counter
	cadenceSkippedTotal *prometheus.CounterVec // labels: cadence_reason
}

// NewCheckpointMetrics creates a new CheckpointMetrics instance with all metrics initialized
func NewCheckpointMetrics() *CheckpointMetrics {
	m := &CheckpointMetrics{
		// Counter: checkpoint creation tracking
		checkpointsCreated: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gibson_checkpoint_created_total",
				Help: "Total number of checkpoints created",
			},
			[]string{"mission_id", "thread_id", "outcome"},
		),

		// Counter: checkpoint restoration tracking
		checkpointsRestored: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gibson_checkpoint_restored_total",
				Help: "Total number of checkpoints restored",
			},
			[]string{"mission_id", "thread_id", "outcome"},
		),

		// Counter: checkpoint deletion tracking
		checkpointsDeleted: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gibson_checkpoint_deleted_total",
				Help: "Total number of checkpoints deleted",
			},
			[]string{"mission_id", "reason"},
		),

		// Histogram: checkpoint size distribution
		checkpointSize: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "gibson_checkpoint_size_bytes",
				Help:    "Size of checkpoints in bytes",
				Buckets: sizeBuckets,
			},
			[]string{"mission_id"},
		),

		// Histogram: checkpoint creation duration
		createDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "gibson_checkpoint_create_duration_seconds",
				Help:    "Time taken to create checkpoints in seconds",
				Buckets: durationBuckets,
			},
			[]string{"mission_id"},
		),

		// Histogram: checkpoint restoration duration
		restoreDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "gibson_checkpoint_restore_duration_seconds",
				Help:    "Time taken to restore checkpoints in seconds",
				Buckets: durationBuckets,
			},
			[]string{"mission_id"},
		),

		// Histogram: serialization duration
		serializeDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "gibson_checkpoint_serialize_duration_seconds",
				Help:    "Time taken to serialize checkpoint data in seconds",
				Buckets: durationBuckets,
			},
			[]string{"format"},
		),

		// Gauge: active thread count per mission
		activeThreads: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "gibson_active_threads_total",
				Help: "Current number of active threads per mission",
			},
			[]string{"mission_id"},
		),

		// Spec 4 R7.1 — orchestrator-driven write/restore observability.
		writeDurationMs: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "gibson_checkpoint_write_duration_milliseconds",
			Help:    "Time taken to persist a checkpoint payload (ms)",
			Buckets: []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500},
		}),
		writeSizeBytes: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "gibson_checkpoint_write_size_bytes",
			Help:    "Persisted checkpoint payload size (bytes)",
			Buckets: sizeBuckets,
		}),
		writeFailureTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gibson_checkpoint_write_failure_total",
			Help: "Total number of checkpoint write failures by reason",
		}, []string{"reason"}),
		restoreDurationMs: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "gibson_checkpoint_restore_duration_milliseconds",
			Help:    "Time taken to restore a checkpoint payload (ms)",
			Buckets: []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500},
		}),
		restoreTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gibson_checkpoint_restore_total",
			Help: "Total number of checkpoint restore attempts by outcome",
		}, []string{"outcome"}),
		resumeFromScratch: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "gibson_mission_resume_from_scratch_total",
			Help: "Total number of mission resumes that fell back to from-scratch (no usable checkpoint)",
		}),
		cadenceSkippedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "gibson_checkpoint_cadence_skipped_total",
			Help: "Total number of checkpoint writes skipped by the cadence policy",
		}, []string{"cadence_reason"}),
	}

	return m
}

// MustRegister registers all metrics with the default Prometheus registry.
// Already-registered metrics (AlreadyRegisteredError) are tolerated so the
// global registry initialization is idempotent across init paths.
func (m *CheckpointMetrics) MustRegister() {
	for _, c := range m.collectors() {
		if err := prometheus.Register(c); err != nil {
			if _, already := err.(prometheus.AlreadyRegisteredError); !already {
				panic(err)
			}
		}
	}
}

// collectors returns every metric collector owned by m.
func (m *CheckpointMetrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{
		m.checkpointsCreated,
		m.checkpointsRestored,
		m.checkpointsDeleted,
		m.checkpointSize,
		m.createDuration,
		m.restoreDuration,
		m.serializeDuration,
		m.activeThreads,
		m.writeDurationMs,
		m.writeSizeBytes,
		m.writeFailureTotal,
		m.restoreDurationMs,
		m.restoreTotal,
		m.resumeFromScratch,
		m.cadenceSkippedTotal,
	}
}

// Register registers all metrics with a custom Prometheus registry.
// Returns an error if any metric cannot be registered.
func (m *CheckpointMetrics) Register(registry prometheus.Registerer) error {
	for _, collector := range m.collectors() {
		if err := registry.Register(collector); err != nil {
			if _, already := err.(prometheus.AlreadyRegisteredError); already {
				continue
			}
			return err
		}
	}
	return nil
}

// RecordCheckpointCreated records a checkpoint creation event with its outcome and metrics
func (m *CheckpointMetrics) RecordCheckpointCreated(missionID, threadID string, success bool, sizeBytes int64, duration time.Duration) {
	outcome := "success"
	if !success {
		outcome = "failure"
	}

	m.checkpointsCreated.WithLabelValues(missionID, threadID, outcome).Inc()

	if success {
		m.checkpointSize.WithLabelValues(missionID).Observe(float64(sizeBytes))
		m.createDuration.WithLabelValues(missionID).Observe(duration.Seconds())
	}
}

// RecordCheckpointRestored records a checkpoint restoration event with its outcome
func (m *CheckpointMetrics) RecordCheckpointRestored(missionID, threadID string, success bool, duration time.Duration) {
	outcome := "success"
	if !success {
		outcome = "failure"
	}

	m.checkpointsRestored.WithLabelValues(missionID, threadID, outcome).Inc()

	if success {
		m.restoreDuration.WithLabelValues(missionID).Observe(duration.Seconds())
	}
}

// RecordCheckpointDeleted records a checkpoint deletion event with the deletion reason
func (m *CheckpointMetrics) RecordCheckpointDeleted(missionID string, reason string) {
	m.checkpointsDeleted.WithLabelValues(missionID, reason).Inc()
}

// RecordSerializeDuration records the time taken to serialize checkpoint data
func (m *CheckpointMetrics) RecordSerializeDuration(format string, duration time.Duration) {
	m.serializeDuration.WithLabelValues(format).Observe(duration.Seconds())
}

// SetActiveThreads sets the current number of active threads for a mission
func (m *CheckpointMetrics) SetActiveThreads(missionID string, count int) {
	m.activeThreads.WithLabelValues(missionID).Set(float64(count))
}

// RecordWriteOutcome records a single checkpoint write outcome for Spec 4 R7.1.
//   - success    — true if the write completed; false on failure (also bumps
//     the write_failure_total counter with the supplied reason).
//   - durationMs — observed write duration in milliseconds (any value when failed,
//     histogram is recorded only on success to keep latency clean).
//   - sizeBytes  — observed payload size; not recorded on failure.
//   - reason     — failure reason label (e.g. "store_unavailable",
//     "kms_unavailable", "integration_error"); ignored on success.
func (m *CheckpointMetrics) RecordWriteOutcome(success bool, durationMs float64, sizeBytes int64, reason string) {
	if success {
		if durationMs >= 0 {
			m.writeDurationMs.Observe(durationMs)
		}
		if sizeBytes > 0 {
			m.writeSizeBytes.Observe(float64(sizeBytes))
		}
		return
	}
	if reason == "" {
		reason = "unknown"
	}
	m.writeFailureTotal.WithLabelValues(reason).Inc()
}

// RecordRestoreOutcome records a checkpoint restore outcome for Spec 4 R7.1.
func (m *CheckpointMetrics) RecordRestoreOutcome(success bool, durationMs float64) {
	outcome := "success"
	if !success {
		outcome = "failure"
	}
	m.restoreTotal.WithLabelValues(outcome).Inc()
	if success && durationMs >= 0 {
		m.restoreDurationMs.Observe(durationMs)
	}
}

// RecordResumeFromScratch counts a mission resume that fell back to executing
// from scratch because no usable checkpoint was found. Spec 4 R7.1.
func (m *CheckpointMetrics) RecordResumeFromScratch() {
	m.resumeFromScratch.Inc()
}

// RecordCadenceSkipped counts a checkpoint write skipped by the cadence policy.
// Spec 4 R2.2 / R7.1.
func (m *CheckpointMetrics) RecordCadenceSkipped(reason string) {
	if reason == "" {
		reason = "min_interval"
	}
	m.cadenceSkippedTotal.WithLabelValues(reason).Inc()
}

// Global metrics instance management
var (
	globalMetrics *CheckpointMetrics
	metricsOnce   sync.Once
)

// GetMetrics returns the global metrics instance, initializing it on first call
func GetMetrics() *CheckpointMetrics {
	metricsOnce.Do(func() {
		globalMetrics = NewCheckpointMetrics()
		globalMetrics.MustRegister()
	})
	return globalMetrics
}
