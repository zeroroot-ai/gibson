package observability

import (
	"bytes"
	"context"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestActivityMetrics(t *testing.T) {
	// Create a metric reader for testing
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	meter := provider.Meter("gibson-test")

	// Create activity metrics
	metrics, err := NewActivityMetrics(meter)
	if err != nil {
		t.Fatalf("Failed to create activity metrics: %v", err)
	}

	// Record some events
	metrics.RecordEventEmitted("LLM_PROMPT", "test-agent", "INFO")
	metrics.RecordEventEmitted("LLM_RESPONSE", "test-agent", "INFO")
	metrics.RecordEventEmitted("TOOL_CALL", "test-agent", "INFO")
	metrics.RecordEventDropped()
	metrics.RecordEventDropped()
	metrics.RecordBufferSize(10)

	// Collect metrics
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Verify metrics were recorded
	if len(rm.ScopeMetrics) == 0 {
		t.Fatal("No metrics collected")
	}

	metricsFound := make(map[string]bool)
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			metricsFound[m.Name] = true
			t.Logf("Found metric: %s", m.Name)
		}
	}

	// Check expected metrics exist
	expectedMetrics := []string{
		"gibson_activity_events_total",
		"gibson_activity_events_dropped_total",
		"gibson_activity_buffer_size",
	}

	for _, expected := range expectedMetrics {
		if !metricsFound[expected] {
			t.Errorf("Expected metric %s not found", expected)
		}
	}
}

func TestActivityLoggerWithMetrics(t *testing.T) {
	// Create a metric reader for testing
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	meter := provider.Meter("gibson-test")

	// Create activity metrics
	metrics, err := NewActivityMetrics(meter)
	if err != nil {
		t.Fatalf("Failed to create activity metrics: %v", err)
	}

	// Create activity logger with metrics
	var buf bytes.Buffer
	logger, err := NewActivityLogger(ActivityLoggerConfig{
		Level:            ActivityLevelVerbose,
		MaxContentLength: 500,
		Output:           &buf,
		BufferSize:       100,
		MissionID:        "test-mission",
		AgentName:        "test-agent",
		Metrics:          metrics,
	})
	if err != nil {
		t.Fatalf("Failed to create activity logger: %v", err)
	}
	defer logger.Close()

	// Emit some events
	ctx := context.Background()
	logger.EmitAgentStart(ctx, "test-agent", "Test task")
	logger.EmitError(ctx, "test_operation", context.DeadlineExceeded)
	logger.EmitDecision(ctx, "execute", "node-1", "looks good", 0.95)

	// Wait for async writes
	time.Sleep(100 * time.Millisecond)

	// Collect metrics
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Verify events_total counter was incremented
	foundEventsTotal := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "gibson_activity_events_total" {
				foundEventsTotal = true
				// Verify we have data points
				if sum, ok := m.Data.(metricdata.Sum[int64]); ok {
					if len(sum.DataPoints) == 0 {
						t.Error("No data points in events_total metric")
					} else {
						t.Logf("events_total has %d data points", len(sum.DataPoints))
						for _, dp := range sum.DataPoints {
							t.Logf("  - value=%d, attrs=%v", dp.Value, dp.Attributes)
						}
					}
				}
			}
		}
	}

	if !foundEventsTotal {
		t.Error("events_total metric not found")
	}

	// Verify JSON output was written
	if buf.Len() == 0 {
		t.Error("No events written to output")
	}
}

func TestActivityLoggerBufferOverflow(t *testing.T) {
	// Create a metric reader for testing
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	meter := provider.Meter("gibson-test")

	// Create activity metrics
	metrics, err := NewActivityMetrics(meter)
	if err != nil {
		t.Fatalf("Failed to create activity metrics: %v", err)
	}

	// Create activity logger with small buffer
	var buf bytes.Buffer
	logger, err := NewActivityLogger(ActivityLoggerConfig{
		Level:            ActivityLevelVerbose,
		MaxContentLength: 500,
		Output:           &buf,
		BufferSize:       5, // Very small buffer to trigger overflow
		MissionID:        "test-mission",
		AgentName:        "test-agent",
		Metrics:          metrics,
	})
	if err != nil {
		t.Fatalf("Failed to create activity logger: %v", err)
	}
	defer logger.Close()

	// Fill the buffer completely and trigger overflow
	ctx := context.Background()
	for i := 0; i < 100; i++ {
		logger.EmitError(ctx, "test_operation", context.DeadlineExceeded)
	}

	// Check that some events were dropped
	dropped := logger.eventsDropped.Load()
	if dropped == 0 {
		t.Error("Expected some events to be dropped but got 0")
	} else {
		t.Logf("Dropped %d events as expected", dropped)
	}

	// Collect metrics
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Failed to collect metrics: %v", err)
	}

	// Verify events_dropped counter was incremented
	foundEventsDropped := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "gibson_activity_events_dropped_total" {
				foundEventsDropped = true
				if sum, ok := m.Data.(metricdata.Sum[int64]); ok {
					if len(sum.DataPoints) > 0 {
						value := sum.DataPoints[0].Value
						if value == 0 {
							t.Error("events_dropped metric is 0, expected > 0")
						} else {
							t.Logf("events_dropped metric = %d", value)
						}
					}
				}
			}
		}
	}

	if !foundEventsDropped {
		t.Error("events_dropped metric not found")
	}
}

func TestNewActivityMetricsNilMeter(t *testing.T) {
	// Test that nil meter returns nil metrics (graceful degradation)
	metrics, err := NewActivityMetrics(nil)
	if err != nil {
		t.Errorf("Expected no error with nil meter, got: %v", err)
	}
	if metrics != nil {
		t.Error("Expected nil metrics with nil meter")
	}
}

func TestActivityMetricsNilRecorder(t *testing.T) {
	// Test that nil metrics recorder doesn't panic
	var metrics *ActivityMetrics = nil

	// These should all be safe to call with nil receiver
	metrics.RecordEventEmitted("TEST", "agent", "INFO")
	metrics.RecordEventDropped()
	metrics.RecordBufferSize(10)

	// If we get here without panicking, test passes
	t.Log("Nil metrics recorder handled gracefully")
}
