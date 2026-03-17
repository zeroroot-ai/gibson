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
	approvalsRequested  prometheus.Counter
	approvalsReceived   *prometheus.CounterVec

	// Histograms
	checkpointSize    *prometheus.HistogramVec
	createDuration    *prometheus.HistogramVec
	restoreDuration   *prometheus.HistogramVec
	serializeDuration *prometheus.HistogramVec

	// Gauges
	activeThreads    *prometheus.GaugeVec
	pendingApprovals prometheus.Gauge
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

		// Counter: approval requests
		approvalsRequested: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "gibson_approval_requested_total",
				Help: "Total number of approval requests made",
			},
		),

		// Counter: approval outcomes
		approvalsReceived: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gibson_approval_received_total",
				Help: "Total number of approval decisions received",
			},
			[]string{"mission_id", "outcome"},
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

		// Gauge: pending approval count
		pendingApprovals: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "gibson_pending_approvals_total",
				Help: "Current number of pending approval requests",
			},
		),
	}

	return m
}

// MustRegister registers all metrics with the default Prometheus registry.
// Panics if any metric cannot be registered.
func (m *CheckpointMetrics) MustRegister() {
	prometheus.MustRegister(
		m.checkpointsCreated,
		m.checkpointsRestored,
		m.checkpointsDeleted,
		m.approvalsRequested,
		m.approvalsReceived,
		m.checkpointSize,
		m.createDuration,
		m.restoreDuration,
		m.serializeDuration,
		m.activeThreads,
		m.pendingApprovals,
	)
}

// Register registers all metrics with a custom Prometheus registry.
// Returns an error if any metric cannot be registered.
func (m *CheckpointMetrics) Register(registry prometheus.Registerer) error {
	collectors := []prometheus.Collector{
		m.checkpointsCreated,
		m.checkpointsRestored,
		m.checkpointsDeleted,
		m.approvalsRequested,
		m.approvalsReceived,
		m.checkpointSize,
		m.createDuration,
		m.restoreDuration,
		m.serializeDuration,
		m.activeThreads,
		m.pendingApprovals,
	}

	for _, collector := range collectors {
		if err := registry.Register(collector); err != nil {
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

// RecordApprovalRequested records that an approval request was made
func (m *CheckpointMetrics) RecordApprovalRequested(missionID string) {
	m.approvalsRequested.Inc()
}

// RecordApprovalReceived records an approval decision with its outcome
func (m *CheckpointMetrics) RecordApprovalReceived(missionID string, outcome string) {
	m.approvalsReceived.WithLabelValues(missionID, outcome).Inc()
}

// RecordSerializeDuration records the time taken to serialize checkpoint data
func (m *CheckpointMetrics) RecordSerializeDuration(format string, duration time.Duration) {
	m.serializeDuration.WithLabelValues(format).Observe(duration.Seconds())
}

// SetActiveThreads sets the current number of active threads for a mission
func (m *CheckpointMetrics) SetActiveThreads(missionID string, count int) {
	m.activeThreads.WithLabelValues(missionID).Set(float64(count))
}

// SetPendingApprovals sets the current number of pending approval requests
func (m *CheckpointMetrics) SetPendingApprovals(count int) {
	m.pendingApprovals.Set(float64(count))
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
