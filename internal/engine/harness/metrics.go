package harness

// MetricsRecorder provides an interface for recording operational metrics
// during agent execution. This enables observability and performance monitoring
// without coupling the harness to a specific metrics implementation.
//
// Implementations should handle thread-safety internally, as metrics may be
// recorded from multiple goroutines during concurrent agent execution.
type MetricsRecorder interface {
	// RecordCounter increments a counter metric by the given value.
	// Counters are cumulative metrics that only increase (e.g., request count, error count).
	//
	// Parameters:
	//   - name: The metric name (e.g., "agent.tasks.completed")
	//   - value: The amount to increment (must be non-negative)
	//   - labels: Key-value pairs for metric dimensions (e.g., {"agent": "recon", "severity": "high"})
	//
	// Example:
	//   metrics.RecordCounter("llm.requests.total", 1, map[string]string{
	//       "provider": "anthropic",
	//       "model": "claude-3-opus",
	//   })
	RecordCounter(name string, value int64, labels map[string]string)

	// RecordGauge sets a gauge metric to the given value.
	// Gauges represent point-in-time measurements that can go up or down
	// (e.g., active connections, memory usage, queue depth).
	//
	// Parameters:
	//   - name: The metric name (e.g., "agent.active_tasks")
	//   - value: The current measurement value
	//   - labels: Key-value pairs for metric dimensions
	//
	// Example:
	//   metrics.RecordGauge("memory.working.size_bytes", 1024.0, map[string]string{
	//       "mission_id": missionID.String(),
	//   })
	RecordGauge(name string, value float64, labels map[string]string)

	// RecordHistogram records a value in a histogram metric.
	// Histograms track distributions of values over time (e.g., latency, response size).
	// The implementation determines bucket boundaries and aggregation strategy.
	//
	// Parameters:
	//   - name: The metric name (e.g., "llm.completion.duration_ms")
	//   - value: The observed value to record
	//   - labels: Key-value pairs for metric dimensions
	//
	// Example:
	//   metrics.RecordHistogram("tool.execution.duration_ms", 150.5, map[string]string{
	//       "tool_name": "nmap_scan",
	//       "status": "success",
	//   })
	RecordHistogram(name string, value float64, labels map[string]string)
}

// NoOpMetricsRecorder is a no-operation implementation of MetricsRecorder.
// It discards all metrics, useful for testing or when metrics are disabled.
//
// This implementation is safe for concurrent use as it performs no operations.
//
// Example usage:
//
//	var metrics MetricsRecorder = NewNoOpMetricsRecorder()
//	metrics.RecordCounter("test", 1, nil) // Does nothing
type NoOpMetricsRecorder struct{}

// NewNoOpMetricsRecorder creates a new no-op metrics recorder.
// All recording methods are no-ops and safe to call with nil labels.
func NewNoOpMetricsRecorder() *NoOpMetricsRecorder {
	return &NoOpMetricsRecorder{}
}

// RecordCounter is a no-op implementation that discards counter metrics.
func (n *NoOpMetricsRecorder) RecordCounter(name string, value int64, labels map[string]string) {
	// No-op: metrics are discarded
}

// RecordGauge is a no-op implementation that discards gauge metrics.
func (n *NoOpMetricsRecorder) RecordGauge(name string, value float64, labels map[string]string) {
	// No-op: metrics are discarded
}

// RecordHistogram is a no-op implementation that discards histogram metrics.
func (n *NoOpMetricsRecorder) RecordHistogram(name string, value float64, labels map[string]string) {
	// No-op: metrics are discarded
}

// Ensure NoOpMetricsRecorder implements MetricsRecorder at compile time
var _ MetricsRecorder = (*NoOpMetricsRecorder)(nil)
