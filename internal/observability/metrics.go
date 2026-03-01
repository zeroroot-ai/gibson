package observability

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/zero-day-ai/gibson/internal/harness"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// Metric name constants for Gibson framework observability.
// These constants provide a centralized definition of all metric names
// to ensure consistency across the codebase and prevent typos.
const (
	// LLM completion metrics
	MetricLLMCompletions  = "gibson.llm.completions"
	MetricLLMTokensInput  = "gibson.llm.tokens.input"
	MetricLLMTokensOutput = "gibson.llm.tokens.output"
	MetricLLMLatency      = "gibson.llm.latency"
	MetricLLMCost         = "gibson.llm.cost"

	// Tool execution metrics
	MetricToolCalls    = "gibson.tool.calls"
	MetricToolDuration = "gibson.tool.duration"

	// Finding submission metrics
	MetricFindingsSubmitted = "gibson.findings.submitted"

	// Agent delegation metrics
	MetricAgentDelegations = "gibson.agent.delegations"

	// Mission metrics
	MetricMissionStatus    = "gibson.mission.status"
	MetricMissionDuration  = "gibson.mission.duration"
	MetricMissionNodes     = "gibson.mission.nodes"
	MetricMissionsActive   = "gibson.missions.active"
	MetricMissionsTotal    = "gibson.missions.total"
	MetricMissionIterations = "gibson.mission.iterations"
)

// InitMetrics initializes and returns a metrics provider based on the configuration.
// Supports "prometheus" and "otlp" provider types.
//
// For Prometheus:
//   - Creates a Prometheus exporter that exposes metrics on the configured port
//   - Metrics are scraped by a Prometheus server
//   - No explicit shutdown required (handled by HTTP server)
//
// For OTLP:
//   - Creates an OTLP gRPC exporter that pushes metrics to a collector
//   - Metrics are sent periodically to the configured endpoint
//   - Requires explicit shutdown via the returned MeterProvider
//
// Parameters:
//   - ctx: Context for initialization (used for OTLP connection)
//   - cfg: MetricsConfig containing provider type and connection details
//
// Returns:
//   - metric.MeterProvider: The initialized meter provider for creating meters
//   - error: Any initialization error (invalid provider, connection failure, etc.)
//
// Example:
//
//	cfg := MetricsConfig{
//	    Enabled: true,
//	    Provider: "prometheus",
//	    Port: 9090,
//	}
//	provider, err := InitMetrics(ctx, cfg)
//	if err != nil {
//	    return err
//	}
//	defer provider.Shutdown(ctx)
func InitMetrics(ctx context.Context, cfg MetricsConfig) (metric.MeterProvider, error) {
	if !cfg.Enabled {
		return noop.NewMeterProvider(), nil
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid metrics config: %w", err)
	}

	provider := strings.ToLower(cfg.Provider)

	switch provider {
	case "prometheus":
		return initPrometheusProvider()

	case "otlp":
		return initOTLPProvider(ctx, cfg)

	default:
		return nil, fmt.Errorf("unsupported metrics provider: %s", cfg.Provider)
	}
}

// initPrometheusProvider creates and initializes a Prometheus metrics provider.
// The exporter creates an HTTP endpoint that Prometheus can scrape for metrics.
func initPrometheusProvider() (metric.MeterProvider, error) {
	exporter, err := prometheus.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create prometheus exporter: %w", err)
	}

	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(exporter),
	)

	return provider, nil
}

// initOTLPProvider creates and initializes an OTLP metrics provider.
// The exporter pushes metrics to an OTLP collector endpoint via gRPC.
func initOTLPProvider(ctx context.Context, cfg MetricsConfig) (metric.MeterProvider, error) {
	// Create OTLP gRPC exporter
	exporter, err := otlpmetricgrpc.New(ctx,
		otlpmetricgrpc.WithEndpoint(fmt.Sprintf("localhost:%d", cfg.Port)),
		otlpmetricgrpc.WithInsecure(), // Use secure connection in production
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create otlp exporter: %w", err)
	}

	// Create periodic reader that exports metrics at regular intervals
	reader := sdkmetric.NewPeriodicReader(exporter)

	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(reader),
	)

	return provider, nil
}

// OpenTelemetryMetricsRecorder implements harness.MetricsRecorder using OpenTelemetry.
// It provides thread-safe recording of counters, gauges, and histograms.
//
// Metrics are lazily created on first use and cached for subsequent recordings.
// This approach reduces initialization overhead and only creates metrics that are
// actually used by the application.
//
// Thread safety:
//   - Uses sync.RWMutex to protect concurrent access to metric maps
//   - Safe to call from multiple goroutines simultaneously
//   - Reader lock for metric lookups, writer lock for metric creation
//
// Example:
//
//	meter := provider.Meter("gibson")
//	recorder := NewOpenTelemetryMetricsRecorder(meter)
//	recorder.RecordCounter("requests.total", 1, map[string]string{"status": "success"})
type OpenTelemetryMetricsRecorder struct {
	meter      metric.Meter
	counters   map[string]metric.Int64Counter
	gauges     map[string]metric.Float64ObservableGauge
	histograms map[string]metric.Float64Histogram
	mu         sync.RWMutex

	// Gauge callback storage for observable gauges
	gaugeValues   map[string]float64
	gaugeLabels   map[string]map[string]string
	gaugeValuesMu sync.RWMutex
}

// NewOpenTelemetryMetricsRecorder creates a new OpenTelemetry-based metrics recorder.
// The meter is used to create and manage all metric instruments.
//
// Parameters:
//   - meter: The OpenTelemetry meter for creating metric instruments
//
// Returns:
//   - *OpenTelemetryMetricsRecorder: A new metrics recorder instance
//
// Example:
//
//	provider, _ := InitMetrics(ctx, cfg)
//	meter := provider.Meter("gibson")
//	recorder := NewOpenTelemetryMetricsRecorder(meter)
func NewOpenTelemetryMetricsRecorder(meter metric.Meter) *OpenTelemetryMetricsRecorder {
	return &OpenTelemetryMetricsRecorder{
		meter:       meter,
		counters:    make(map[string]metric.Int64Counter),
		gauges:      make(map[string]metric.Float64ObservableGauge),
		histograms:  make(map[string]metric.Float64Histogram),
		gaugeValues: make(map[string]float64),
		gaugeLabels: make(map[string]map[string]string),
	}
}

// RecordCounter increments a counter metric by the given value.
// Counters are cumulative metrics that only increase.
//
// Implementation notes:
//   - Lazily creates counter instruments on first use
//   - Thread-safe via mutex protection
//   - Converts labels to OpenTelemetry attributes
//
// Parameters:
//   - name: The metric name (e.g., "gibson.llm.completions")
//   - value: The amount to increment (must be non-negative)
//   - labels: Key-value pairs for metric dimensions
//
// Example:
//
//	recorder.RecordCounter("gibson.llm.completions", 1, map[string]string{
//	    "provider": "anthropic",
//	    "model": "claude-3-opus",
//	    "status": "success",
//	})
func (r *OpenTelemetryMetricsRecorder) RecordCounter(name string, value int64, labels map[string]string) {
	counter := r.getOrCreateCounter(name)
	if counter == nil {
		return
	}

	attrs := labelsToAttributes(labels)
	counter.Add(context.Background(), value, metric.WithAttributes(attrs...))
}

// RecordGauge sets a gauge metric to the given value.
// Gauges represent point-in-time measurements that can go up or down.
//
// Note: OpenTelemetry gauges are implemented as observable gauges with callbacks.
// This implementation stores the latest value and provides it via callback.
//
// Parameters:
//   - name: The metric name (e.g., "gibson.agent.active_tasks")
//   - value: The current measurement value
//   - labels: Key-value pairs for metric dimensions
//
// Example:
//
//	recorder.RecordGauge("gibson.memory.working_size_bytes", 1024.0, map[string]string{
//	    "mission_id": missionID,
//	})
func (r *OpenTelemetryMetricsRecorder) RecordGauge(name string, value float64, labels map[string]string) {
	// For observable gauges, we store the value and it's read via callback
	// Note: This is a simplified implementation. In production, you may want
	// to use a more sophisticated approach with proper gauge registration.
	r.gaugeValuesMu.Lock()
	r.gaugeValues[name] = value
	r.gaugeLabels[name] = labels
	r.gaugeValuesMu.Unlock()

	// Ensure gauge is created (even if not used immediately)
	_ = r.getOrCreateGauge(name)
}

// RecordHistogram records a value in a histogram metric.
// Histograms track distributions of values over time.
//
// Implementation notes:
//   - Lazily creates histogram instruments on first use
//   - Thread-safe via mutex protection
//   - Bucket boundaries determined by the metrics provider
//
// Parameters:
//   - name: The metric name (e.g., "gibson.llm.latency")
//   - value: The observed value to record
//   - labels: Key-value pairs for metric dimensions
//
// Example:
//
//	recorder.RecordHistogram("gibson.llm.latency", 150.5, map[string]string{
//	    "provider": "anthropic",
//	    "model": "claude-3-opus",
//	})
func (r *OpenTelemetryMetricsRecorder) RecordHistogram(name string, value float64, labels map[string]string) {
	histogram := r.getOrCreateHistogram(name)
	if histogram == nil {
		return
	}

	attrs := labelsToAttributes(labels)
	histogram.Record(context.Background(), value, metric.WithAttributes(attrs...))
}

// RecordLLMCompletion records metrics for an LLM completion request.
// This is a convenience method that records multiple related metrics atomically.
//
// Recorded metrics:
//   - gibson.llm.completions (counter): Total completions
//   - gibson.llm.tokens.input (counter): Input tokens consumed
//   - gibson.llm.tokens.output (counter): Output tokens generated
//   - gibson.llm.latency (histogram): Request latency in milliseconds
//   - gibson.llm.cost (histogram): Request cost in dollars
//
// Parameters:
//   - slot: The LLM slot identifier (e.g., "primary", "fallback")
//   - provider: The LLM provider (e.g., "anthropic", "openai")
//   - model: The model name (e.g., "claude-3-opus", "gpt-4")
//   - status: The completion status (e.g., "success", "error", "timeout")
//   - inputTokens: Number of input tokens consumed
//   - outputTokens: Number of output tokens generated
//   - latencyMs: Request latency in milliseconds
//   - cost: Request cost in dollars
//
// Example:
//
//	recorder.RecordLLMCompletion(
//	    "primary",
//	    "anthropic",
//	    "claude-3-opus",
//	    "success",
//	    1000, // input tokens
//	    500,  // output tokens
//	    150.5, // latency ms
//	    0.015, // cost $
//	)
func (r *OpenTelemetryMetricsRecorder) RecordLLMCompletion(
	slot, provider, model, status string,
	inputTokens, outputTokens int,
	latencyMs, cost float64,
) {
	labels := map[string]string{
		"slot":     slot,
		"provider": provider,
		"model":    model,
		"status":   status,
	}

	// Record completion count
	r.RecordCounter(MetricLLMCompletions, 1, labels)

	// Record token usage
	r.RecordCounter(MetricLLMTokensInput, int64(inputTokens), labels)
	r.RecordCounter(MetricLLMTokensOutput, int64(outputTokens), labels)

	// Record latency distribution
	r.RecordHistogram(MetricLLMLatency, latencyMs, labels)

	// Record cost distribution
	r.RecordHistogram(MetricLLMCost, cost, labels)
}

// RecordToolCall records metrics for a tool execution.
// Tracks tool call counts and execution duration.
//
// Recorded metrics:
//   - gibson.tool.calls (counter): Total tool calls
//   - gibson.tool.duration (histogram): Tool execution duration in milliseconds
//
// Parameters:
//   - tool: The tool name (e.g., "nmap_scan", "nuclei_scan")
//   - status: The execution status (e.g., "success", "error", "timeout")
//   - durationMs: Execution duration in milliseconds
//
// Example:
//
//	recorder.RecordToolCall("nmap_scan", "success", 2500.0)
func (r *OpenTelemetryMetricsRecorder) RecordToolCall(tool, status string, durationMs float64) {
	labels := map[string]string{
		"tool":   tool,
		"status": status,
	}

	r.RecordCounter(MetricToolCalls, 1, labels)
	r.RecordHistogram(MetricToolDuration, durationMs, labels)
}

// RecordFindingSubmitted records metrics for a finding submission.
// Tracks the number of findings by severity and category.
//
// Recorded metrics:
//   - gibson.findings.submitted (counter): Total findings submitted
//
// Parameters:
//   - severity: The finding severity (e.g., "critical", "high", "medium", "low")
//   - category: The finding category (e.g., "sqli", "xss", "rce")
//
// Example:
//
//	recorder.RecordFindingSubmitted("high", "sqli")
func (r *OpenTelemetryMetricsRecorder) RecordFindingSubmitted(severity, category string) {
	labels := map[string]string{
		"severity": severity,
		"category": category,
	}

	r.RecordCounter(MetricFindingsSubmitted, 1, labels)
}

// RecordAgentDelegation records metrics for an agent delegation event.
// Tracks when one agent delegates work to another agent.
//
// Recorded metrics:
//   - gibson.agent.delegations (counter): Total agent delegations
//
// Parameters:
//   - sourceAgent: The agent initiating the delegation
//   - targetAgent: The agent receiving the delegation
//   - status: The delegation status (e.g., "success", "error", "rejected")
//
// Example:
//
//	recorder.RecordAgentDelegation("recon_agent", "exploit_agent", "success")
func (r *OpenTelemetryMetricsRecorder) RecordAgentDelegation(sourceAgent, targetAgent, status string) {
	labels := map[string]string{
		"source_agent": sourceAgent,
		"target_agent": targetAgent,
		"status":       status,
	}

	r.RecordCounter(MetricAgentDelegations, 1, labels)
}

// RecordMissionStarted records metrics when a mission starts.
// Sets the mission status gauge to 1 (running) and increments mission counters.
//
// Recorded metrics:
//   - gibson.mission.status (gauge): Current mission status (1=running)
//   - gibson.missions.total (counter): Total missions started
//   - gibson.missions.active (gauge): Currently active missions
//
// Parameters:
//   - missionID: The unique mission identifier
//
// Example:
//
//	recorder.RecordMissionStarted("mission-abc-123")
func (r *OpenTelemetryMetricsRecorder) RecordMissionStarted(missionID string) {
	labels := map[string]string{
		"mission_id": missionID,
		"status":     "running",
	}

	// Set mission status to running (1)
	r.RecordGauge(MetricMissionStatus, 1, labels)

	// Increment total missions counter
	r.RecordCounter(MetricMissionsTotal, 1, map[string]string{})

	// Track active missions (simplified - in production use atomic counter)
	r.RecordGauge(MetricMissionsActive, 1, map[string]string{})
}

// RecordMissionCompleted records metrics when a mission completes successfully.
// Updates the mission status gauge and records completion metrics.
//
// Recorded metrics:
//   - gibson.mission.status (gauge): Mission status (0=completed successfully)
//   - gibson.mission.duration (histogram): Total mission duration in seconds
//   - gibson.mission.nodes (counter): Nodes completed/failed during mission
//   - gibson.mission.iterations (counter): Total orchestration iterations
//
// Parameters:
//   - missionID: The unique mission identifier
//   - durationSecs: Total duration in seconds
//   - completedNodes: Number of workflow nodes completed
//   - failedNodes: Number of workflow nodes failed
//   - iterations: Total orchestration loop iterations
//
// Example:
//
//	recorder.RecordMissionCompleted("mission-abc-123", 120.5, 15, 2, 25)
func (r *OpenTelemetryMetricsRecorder) RecordMissionCompleted(
	missionID string,
	durationSecs float64,
	completedNodes, failedNodes, iterations int,
) {
	labels := map[string]string{
		"mission_id": missionID,
		"status":     "completed",
	}

	// Set mission status to completed (0 = success)
	r.RecordGauge(MetricMissionStatus, 0, labels)

	// Record duration
	r.RecordHistogram(MetricMissionDuration, durationSecs, map[string]string{
		"mission_id": missionID,
		"status":     "completed",
	})

	// Record node counts
	r.RecordCounter(MetricMissionNodes, int64(completedNodes), map[string]string{
		"mission_id": missionID,
		"status":     "completed",
	})
	r.RecordCounter(MetricMissionNodes, int64(failedNodes), map[string]string{
		"mission_id": missionID,
		"status":     "failed",
	})

	// Record iterations
	r.RecordCounter(MetricMissionIterations, int64(iterations), map[string]string{
		"mission_id": missionID,
	})
}

// RecordMissionFailed records metrics when a mission fails.
// Updates the mission status gauge to indicate failure.
//
// Recorded metrics:
//   - gibson.mission.status (gauge): Mission status (2=failed)
//   - gibson.mission.duration (histogram): Total mission duration in seconds
//   - gibson.mission.iterations (counter): Total orchestration iterations
//
// Parameters:
//   - missionID: The unique mission identifier
//   - reason: The failure reason (e.g., "error", "timeout", "cancelled", "budget_exceeded")
//   - durationSecs: Total duration in seconds
//   - iterations: Total orchestration loop iterations
//
// Example:
//
//	recorder.RecordMissionFailed("mission-abc-123", "timeout", 300.0, 50)
func (r *OpenTelemetryMetricsRecorder) RecordMissionFailed(
	missionID, reason string,
	durationSecs float64,
	iterations int,
) {
	labels := map[string]string{
		"mission_id": missionID,
		"status":     reason,
	}

	// Set mission status to failed (2)
	r.RecordGauge(MetricMissionStatus, 2, labels)

	// Record duration
	r.RecordHistogram(MetricMissionDuration, durationSecs, map[string]string{
		"mission_id": missionID,
		"status":     reason,
	})

	// Record iterations
	r.RecordCounter(MetricMissionIterations, int64(iterations), map[string]string{
		"mission_id": missionID,
	})
}

// getOrCreateCounter retrieves or creates a counter metric instrument.
// Thread-safe via read-write mutex.
func (r *OpenTelemetryMetricsRecorder) getOrCreateCounter(name string) metric.Int64Counter {
	// Try read lock first for fast path
	r.mu.RLock()
	counter, exists := r.counters[name]
	r.mu.RUnlock()

	if exists {
		return counter
	}

	// Need to create - acquire write lock
	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check in case another goroutine created it
	if counter, exists := r.counters[name]; exists {
		return counter
	}

	// Create new counter
	counter, err := r.meter.Int64Counter(name)
	if err != nil {
		// In production, log this error
		return nil
	}

	r.counters[name] = counter
	return counter
}

// getOrCreateGauge retrieves or creates an observable gauge metric instrument.
// Thread-safe via read-write mutex.
func (r *OpenTelemetryMetricsRecorder) getOrCreateGauge(name string) metric.Float64ObservableGauge {
	// Try read lock first for fast path
	r.mu.RLock()
	gauge, exists := r.gauges[name]
	r.mu.RUnlock()

	if exists {
		return gauge
	}

	// Need to create - acquire write lock
	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check in case another goroutine created it
	if gauge, exists := r.gauges[name]; exists {
		return gauge
	}

	// Create new observable gauge with callback
	gauge, err := r.meter.Float64ObservableGauge(
		name,
		metric.WithFloat64Callback(func(ctx context.Context, observer metric.Float64Observer) error {
			r.gaugeValuesMu.RLock()
			value, hasValue := r.gaugeValues[name]
			labels := r.gaugeLabels[name]
			r.gaugeValuesMu.RUnlock()

			if hasValue {
				attrs := labelsToAttributes(labels)
				observer.Observe(value, metric.WithAttributes(attrs...))
			}
			return nil
		}),
	)
	if err != nil {
		// In production, log this error
		return nil
	}

	r.gauges[name] = gauge
	return gauge
}

// getOrCreateHistogram retrieves or creates a histogram metric instrument.
// Thread-safe via read-write mutex.
func (r *OpenTelemetryMetricsRecorder) getOrCreateHistogram(name string) metric.Float64Histogram {
	// Try read lock first for fast path
	r.mu.RLock()
	histogram, exists := r.histograms[name]
	r.mu.RUnlock()

	if exists {
		return histogram
	}

	// Need to create - acquire write lock
	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check in case another goroutine created it
	if histogram, exists := r.histograms[name]; exists {
		return histogram
	}

	// Create new histogram
	histogram, err := r.meter.Float64Histogram(name)
	if err != nil {
		// In production, log this error
		return nil
	}

	r.histograms[name] = histogram
	return histogram
}

// labelsToAttributes converts a string map to OpenTelemetry attributes.
// Returns an empty slice if labels is nil.
func labelsToAttributes(labels map[string]string) []attribute.KeyValue {
	if labels == nil {
		return []attribute.KeyValue{}
	}

	attrs := make([]attribute.KeyValue, 0, len(labels))
	for k, v := range labels {
		attrs = append(attrs, attribute.String(k, v))
	}
	return attrs
}

// Ensure OpenTelemetryMetricsRecorder implements harness.MetricsRecorder at compile time
var _ harness.MetricsRecorder = (*OpenTelemetryMetricsRecorder)(nil)
