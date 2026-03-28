package intelligence

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Metrics tracks intelligence service metrics using OpenTelemetry.
type Metrics struct {
	queryDuration metric.Float64Histogram
	queryCount    metric.Int64Counter
	cacheHits     metric.Int64Counter
	cacheMisses   metric.Int64Counter
	circuitBreaks metric.Int64Counter
	queryErrors   metric.Int64Counter
}

// NewMetrics creates a new metrics recorder.
func NewMetrics() (*Metrics, error) {
	meter := otel.Meter("gibson.intelligence")

	queryDuration, err := meter.Float64Histogram(
		"intelligence.query.duration",
		metric.WithDescription("Duration of intelligence queries in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	queryCount, err := meter.Int64Counter(
		"intelligence.query.count",
		metric.WithDescription("Total number of intelligence queries"),
	)
	if err != nil {
		return nil, err
	}

	cacheHits, err := meter.Int64Counter(
		"intelligence.cache.hits",
		metric.WithDescription("Number of cache hits"),
	)
	if err != nil {
		return nil, err
	}

	cacheMisses, err := meter.Int64Counter(
		"intelligence.cache.misses",
		metric.WithDescription("Number of cache misses"),
	)
	if err != nil {
		return nil, err
	}

	circuitBreaks, err := meter.Int64Counter(
		"intelligence.circuit.breaks",
		metric.WithDescription("Number of circuit breaker activations"),
	)
	if err != nil {
		return nil, err
	}

	queryErrors, err := meter.Int64Counter(
		"intelligence.query.errors",
		metric.WithDescription("Number of query errors"),
	)
	if err != nil {
		return nil, err
	}

	return &Metrics{
		queryDuration: queryDuration,
		queryCount:    queryCount,
		cacheHits:     cacheHits,
		cacheMisses:   cacheMisses,
		circuitBreaks: circuitBreaks,
		queryErrors:   queryErrors,
	}, nil
}

// RecordQuery records a query with its duration and result.
func (m *Metrics) RecordQuery(ctx context.Context, queryType string, duration time.Duration, cached bool, err error) {
	attrs := []attribute.KeyValue{
		attribute.String("query_type", queryType),
	}

	m.queryCount.Add(ctx, 1, metric.WithAttributes(attrs...))
	m.queryDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(attrs...))

	if cached {
		m.cacheHits.Add(ctx, 1, metric.WithAttributes(attrs...))
	} else {
		m.cacheMisses.Add(ctx, 1, metric.WithAttributes(attrs...))
	}

	if err != nil {
		m.queryErrors.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

// RecordCircuitBreak records a circuit breaker activation.
func (m *Metrics) RecordCircuitBreak(ctx context.Context) {
	m.circuitBreaks.Add(ctx, 1)
}

// NoOpMetrics is a no-op implementation for when metrics are disabled.
type NoOpMetrics struct{}

// NewNoOpMetrics creates a no-op metrics recorder.
func NewNoOpMetrics() *NoOpMetrics {
	return &NoOpMetrics{}
}

// RecordQuery is a no-op.
func (m *NoOpMetrics) RecordQuery(ctx context.Context, queryType string, duration time.Duration, cached bool, err error) {
}

// RecordCircuitBreak is a no-op.
func (m *NoOpMetrics) RecordCircuitBreak(ctx context.Context) {
}

// MetricsRecorder defines the metrics interface.
type MetricsRecorder interface {
	RecordQuery(ctx context.Context, queryType string, duration time.Duration, cached bool, err error)
	RecordCircuitBreak(ctx context.Context)
}

// Compile-time interface checks
var (
	_ MetricsRecorder = (*Metrics)(nil)
	_ MetricsRecorder = (*NoOpMetrics)(nil)
)
