package observability

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var (
	// contextBackground is a cached background context for metric recording
	contextBackground = context.Background()

	// attributeString is a helper for creating string attributes
	attributeString = attribute.String
)

// ActivityMetrics holds Prometheus metrics for activity logging.
// These metrics provide observability into the activity stream's health and performance.
type ActivityMetrics struct {
	// eventsTotal tracks the total number of activity events emitted
	eventsTotal metric.Int64Counter

	// eventsDropped tracks events dropped due to buffer overflow
	eventsDropped metric.Int64Counter

	// bufferSize tracks the current number of events in the buffer
	bufferSize metric.Int64Gauge

	// mu protects metric initialization
	mu sync.Mutex
}

// NewActivityMetrics creates and registers activity logging metrics.
// Returns nil if meter is nil (metrics disabled).
func NewActivityMetrics(meter metric.Meter) (*ActivityMetrics, error) {
	if meter == nil {
		return nil, nil
	}

	am := &ActivityMetrics{}

	var err error

	// gibson_activity_events_total: Counter with labels event_type, agent_name, level
	am.eventsTotal, err = meter.Int64Counter(
		"gibson_activity_events_total",
		metric.WithDescription("Total number of activity events emitted"),
		metric.WithUnit("{event}"),
	)
	if err != nil {
		return nil, err
	}

	// gibson_activity_events_dropped_total: Counter with no labels
	am.eventsDropped, err = meter.Int64Counter(
		"gibson_activity_events_dropped_total",
		metric.WithDescription("Total number of activity events dropped due to buffer overflow"),
		metric.WithUnit("{event}"),
	)
	if err != nil {
		return nil, err
	}

	// gibson_activity_buffer_size: Gauge tracking current buffer utilization
	am.bufferSize, err = meter.Int64Gauge(
		"gibson_activity_buffer_size",
		metric.WithDescription("Current number of events in the activity buffer"),
		metric.WithUnit("{event}"),
	)
	if err != nil {
		return nil, err
	}

	return am, nil
}

// RecordEventEmitted increments the events_total counter.
// Labels are provided for event_type, agent_name, and level to enable dimensional queries.
func (m *ActivityMetrics) RecordEventEmitted(eventType, agentName, level string) {
	if m == nil || m.eventsTotal == nil {
		return
	}

	m.eventsTotal.Add(
		contextBackground,
		1,
		metric.WithAttributes(
			attributeString("event_type", eventType),
			attributeString("agent_name", agentName),
			attributeString("level", level),
		),
	)
}

// RecordEventDropped increments the events_dropped counter.
// No labels are used to minimize cardinality - this is a system-wide health metric.
func (m *ActivityMetrics) RecordEventDropped() {
	if m == nil || m.eventsDropped == nil {
		return
	}

	m.eventsDropped.Add(contextBackground, 1)
}

// RecordBufferSize updates the buffer_size gauge to the current buffer utilization.
// This metric helps operators understand buffer pressure and tune buffer sizes.
func (m *ActivityMetrics) RecordBufferSize(size int) {
	if m == nil || m.bufferSize == nil {
		return
	}

	m.bufferSize.Record(contextBackground, int64(size))
}
