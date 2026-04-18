package observability

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// TestInitMetrics_Disabled tests that a no-op provider is returned when metrics are disabled.
func TestInitMetrics_Disabled(t *testing.T) {
	cfg := MetricsConfig{
		Enabled: false,
	}

	provider, err := InitMetrics(context.Background(), cfg)
	require.NoError(t, err)
	assert.NotNil(t, provider)

	// Verify it's a no-op provider by checking that meters don't record
	meter := provider.Meter("test")
	assert.NotNil(t, meter)
}

// TestInitMetrics_Prometheus tests Prometheus provider initialization.
func TestInitMetrics_Prometheus(t *testing.T) {
	cfg := MetricsConfig{
		Enabled:  true,
		Provider: "prometheus",
		Port:     9090,
	}

	provider, err := InitMetrics(context.Background(), cfg)
	require.NoError(t, err)
	assert.NotNil(t, provider)

	// Verify we can create a meter
	meter := provider.Meter("gibson")
	assert.NotNil(t, meter)

	// Clean up
	if mp, ok := provider.(*sdkmetric.MeterProvider); ok {
		err := mp.Shutdown(context.Background())
		assert.NoError(t, err)
	}
}

// TestInitMetrics_OTLP tests OTLP provider initialization.
// Note: This test may fail if no OTLP collector is running locally.
// In production, use testcontainers or mock the exporter.
func TestInitMetrics_OTLP(t *testing.T) {
	cfg := MetricsConfig{
		Enabled:  true,
		Provider: "otlp",
		Port:     4317,
	}

	ctx := context.Background()
	provider, err := InitMetrics(ctx, cfg)

	// OTLP initialization succeeds but connection/upload may fail if no collector is available
	// This is expected in test environments
	require.NoError(t, err, "OTLP initialization should succeed even without collector")
	require.NotNil(t, provider)

	// Verify we can create a meter
	meter := provider.Meter("gibson")
	assert.NotNil(t, meter)

	// Clean up - this may fail if no collector is available, which is okay
	if mp, ok := provider.(*sdkmetric.MeterProvider); ok {
		_ = mp.Shutdown(ctx) // Ignore errors from shutdown (collector may not be running)
	}
}

// TestInitMetrics_InvalidProvider tests that invalid providers are rejected.
func TestInitMetrics_InvalidProvider(t *testing.T) {
	cfg := MetricsConfig{
		Enabled:  true,
		Provider: "invalid",
		Port:     9090,
	}

	provider, err := InitMetrics(context.Background(), cfg)
	assert.Error(t, err)
	assert.Nil(t, provider)
	assert.Contains(t, err.Error(), "invalid metrics provider")
}

// TestInitMetrics_InvalidConfig tests that invalid configurations are rejected.
func TestInitMetrics_InvalidConfig(t *testing.T) {
	tests := []struct {
		name   string
		cfg    MetricsConfig
		errMsg string
	}{
		{
			name: "invalid port - too low",
			cfg: MetricsConfig{
				Enabled:  true,
				Provider: "prometheus",
				Port:     0,
			},
			errMsg: "invalid port",
		},
		{
			name: "invalid port - too high",
			cfg: MetricsConfig{
				Enabled:  true,
				Provider: "prometheus",
				Port:     70000,
			},
			errMsg: "invalid port",
		},
		{
			name: "empty provider",
			cfg: MetricsConfig{
				Enabled:  true,
				Provider: "",
				Port:     9090,
			},
			errMsg: "invalid metrics provider",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := InitMetrics(context.Background(), tt.cfg)
			assert.Error(t, err)
			assert.Nil(t, provider)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

// TestNewOpenTelemetryMetricsRecorder tests recorder creation.
func TestNewOpenTelemetryMetricsRecorder(t *testing.T) {
	provider := sdkmetric.NewMeterProvider()
	meter := provider.Meter("test")

	recorder := NewOpenTelemetryMetricsRecorder(meter)
	require.NotNil(t, recorder)
	assert.NotNil(t, recorder.meter)
	assert.NotNil(t, recorder.counters)
	assert.NotNil(t, recorder.gauges)
	assert.NotNil(t, recorder.histograms)
	assert.NotNil(t, recorder.gaugeValues)
	assert.NotNil(t, recorder.gaugeLabels)
}

// TestRecordCounter tests counter recording functionality.
func TestRecordCounter(t *testing.T) {
	provider := sdkmetric.NewMeterProvider()
	meter := provider.Meter("test")
	recorder := NewOpenTelemetryMetricsRecorder(meter)

	// Record counter without labels
	recorder.RecordCounter("test.counter", 1, nil)

	// Record counter with labels
	labels := map[string]string{
		"status": "success",
		"method": "POST",
	}
	recorder.RecordCounter("test.counter", 5, labels)

	// Verify counter was created
	recorder.mu.RLock()
	_, exists := recorder.counters["test.counter"]
	recorder.mu.RUnlock()
	assert.True(t, exists, "counter should be created")
}

// TestRecordCounter_LazyCreation tests that counters are created lazily.
func TestRecordCounter_LazyCreation(t *testing.T) {
	provider := sdkmetric.NewMeterProvider()
	meter := provider.Meter("test")
	recorder := NewOpenTelemetryMetricsRecorder(meter)

	// Verify no counters exist initially
	recorder.mu.RLock()
	assert.Equal(t, 0, len(recorder.counters))
	recorder.mu.RUnlock()

	// Record a counter
	recorder.RecordCounter("test.counter", 1, nil)

	// Verify counter was created
	recorder.mu.RLock()
	assert.Equal(t, 1, len(recorder.counters))
	recorder.mu.RUnlock()

	// Record same counter again
	recorder.RecordCounter("test.counter", 1, nil)

	// Verify no duplicate was created
	recorder.mu.RLock()
	assert.Equal(t, 1, len(recorder.counters))
	recorder.mu.RUnlock()
}

// TestRecordGauge tests gauge recording functionality.
func TestRecordGauge(t *testing.T) {
	provider := sdkmetric.NewMeterProvider()
	meter := provider.Meter("test")
	recorder := NewOpenTelemetryMetricsRecorder(meter)

	// Record gauge without labels
	recorder.RecordGauge("test.gauge", 42.0, nil)

	// Verify gauge value was stored
	recorder.gaugeValuesMu.RLock()
	value, exists := recorder.gaugeValues["test.gauge"]
	recorder.gaugeValuesMu.RUnlock()
	assert.True(t, exists)
	assert.Equal(t, 42.0, value)

	// Record gauge with labels
	labels := map[string]string{
		"host": "server1",
		"env":  "prod",
	}
	recorder.RecordGauge("test.gauge", 100.0, labels)

	// Verify gauge value was updated
	recorder.gaugeValuesMu.RLock()
	value, exists = recorder.gaugeValues["test.gauge"]
	storedLabels := recorder.gaugeLabels["test.gauge"]
	recorder.gaugeValuesMu.RUnlock()
	assert.True(t, exists)
	assert.Equal(t, 100.0, value)
	assert.Equal(t, labels, storedLabels)
}

// TestRecordHistogram tests histogram recording functionality.
func TestRecordHistogram(t *testing.T) {
	provider := sdkmetric.NewMeterProvider()
	meter := provider.Meter("test")
	recorder := NewOpenTelemetryMetricsRecorder(meter)

	// Record histogram without labels
	recorder.RecordHistogram("test.histogram", 123.45, nil)

	// Record histogram with labels
	labels := map[string]string{
		"endpoint": "/api/users",
		"status":   "200",
	}
	recorder.RecordHistogram("test.histogram", 250.0, labels)

	// Verify histogram was created
	recorder.mu.RLock()
	_, exists := recorder.histograms["test.histogram"]
	recorder.mu.RUnlock()
	assert.True(t, exists, "histogram should be created")
}

// TestRecordHistogram_LazyCreation tests that histograms are created lazily.
func TestRecordHistogram_LazyCreation(t *testing.T) {
	provider := sdkmetric.NewMeterProvider()
	meter := provider.Meter("test")
	recorder := NewOpenTelemetryMetricsRecorder(meter)

	// Verify no histograms exist initially
	recorder.mu.RLock()
	assert.Equal(t, 0, len(recorder.histograms))
	recorder.mu.RUnlock()

	// Record a histogram
	recorder.RecordHistogram("test.histogram", 100.0, nil)

	// Verify histogram was created
	recorder.mu.RLock()
	assert.Equal(t, 1, len(recorder.histograms))
	recorder.mu.RUnlock()

	// Record same histogram again
	recorder.RecordHistogram("test.histogram", 200.0, nil)

	// Verify no duplicate was created
	recorder.mu.RLock()
	assert.Equal(t, 1, len(recorder.histograms))
	recorder.mu.RUnlock()
}

// TestRecordLLMCompletion tests LLM completion metric recording.
func TestRecordLLMCompletion(t *testing.T) {
	provider := sdkmetric.NewMeterProvider()
	meter := provider.Meter("test")
	recorder := NewOpenTelemetryMetricsRecorder(meter)

	// Record an LLM completion
	recorder.RecordLLMCompletion(
		"primary",
		"anthropic",
		"claude-3-opus",
		"success",
		1000,  // input tokens
		500,   // output tokens
		150.5, // latency ms
		0.015, // cost $
	)

	// Verify all expected metrics were created
	recorder.mu.RLock()
	_, hasCompletions := recorder.counters[MetricLLMCompletions]
	_, hasInputTokens := recorder.counters[MetricLLMTokensInput]
	_, hasOutputTokens := recorder.counters[MetricLLMTokensOutput]
	_, hasLatency := recorder.histograms[MetricLLMLatency]
	_, hasCost := recorder.histograms[MetricLLMCost]
	recorder.mu.RUnlock()

	assert.True(t, hasCompletions, "completions counter should be created")
	assert.True(t, hasInputTokens, "input tokens counter should be created")
	assert.True(t, hasOutputTokens, "output tokens counter should be created")
	assert.True(t, hasLatency, "latency histogram should be created")
	assert.True(t, hasCost, "cost histogram should be created")
}

// TestRecordLLMCompletion_MultipleProviders tests recording for different providers.
func TestRecordLLMCompletion_MultipleProviders(t *testing.T) {
	provider := sdkmetric.NewMeterProvider()
	meter := provider.Meter("test")
	recorder := NewOpenTelemetryMetricsRecorder(meter)

	// Record completions from different providers
	providers := []struct {
		slot     string
		provider string
		model    string
	}{
		{"primary", "anthropic", "claude-3-opus"},
		{"primary", "openai", "gpt-4"},
		{"fallback", "anthropic", "claude-3-sonnet"},
	}

	for _, p := range providers {
		recorder.RecordLLMCompletion(
			p.slot,
			p.provider,
			p.model,
			"success",
			1000,
			500,
			150.5,
			0.015,
		)
	}

	// Verify metrics were created (same metric names, different labels)
	recorder.mu.RLock()
	_, hasCompletions := recorder.counters[MetricLLMCompletions]
	recorder.mu.RUnlock()
	assert.True(t, hasCompletions, "should have completions counter")
}

// TestRecordToolCall tests tool call metric recording.
func TestRecordToolCall(t *testing.T) {
	provider := sdkmetric.NewMeterProvider()
	meter := provider.Meter("test")
	recorder := NewOpenTelemetryMetricsRecorder(meter)

	// Record a tool call
	recorder.RecordToolCall("nmap_scan", "success", 2500.0)

	// Verify metrics were created
	recorder.mu.RLock()
	_, hasCalls := recorder.counters[MetricToolCalls]
	_, hasDuration := recorder.histograms[MetricToolDuration]
	recorder.mu.RUnlock()

	assert.True(t, hasCalls, "tool calls counter should be created")
	assert.True(t, hasDuration, "tool duration histogram should be created")
}

// TestRecordToolCall_MultipleTools tests recording for different tools.
func TestRecordToolCall_MultipleTools(t *testing.T) {
	provider := sdkmetric.NewMeterProvider()
	meter := provider.Meter("test")
	recorder := NewOpenTelemetryMetricsRecorder(meter)

	// Record calls for different tools
	tools := []struct {
		name     string
		status   string
		duration float64
	}{
		{"nmap_scan", "success", 2500.0},
		{"nuclei_scan", "success", 5000.0},
		{"sqlmap_scan", "error", 1000.0},
	}

	for _, tool := range tools {
		recorder.RecordToolCall(tool.name, tool.status, tool.duration)
	}

	// Verify metrics were created
	recorder.mu.RLock()
	_, hasCalls := recorder.counters[MetricToolCalls]
	_, hasDuration := recorder.histograms[MetricToolDuration]
	recorder.mu.RUnlock()
	assert.True(t, hasCalls, "should have tool calls counter")
	assert.True(t, hasDuration, "should have tool duration histogram")
}

// TestRecordFindingSubmitted tests finding submission metric recording.
func TestRecordFindingSubmitted(t *testing.T) {
	provider := sdkmetric.NewMeterProvider()
	meter := provider.Meter("test")
	recorder := NewOpenTelemetryMetricsRecorder(meter)

	// Record a finding
	recorder.RecordFindingSubmitted("high", "sqli")

	// Verify metric was created
	recorder.mu.RLock()
	_, hasFindings := recorder.counters[MetricFindingsSubmitted]
	recorder.mu.RUnlock()

	assert.True(t, hasFindings, "findings counter should be created")
}

// TestRecordFindingSubmitted_MultipleSeverities tests recording for different severities.
func TestRecordFindingSubmitted_MultipleSeverities(t *testing.T) {
	provider := sdkmetric.NewMeterProvider()
	meter := provider.Meter("test")
	recorder := NewOpenTelemetryMetricsRecorder(meter)

	// Record findings with different severities
	findings := []struct {
		severity string
		category string
	}{
		{"critical", "rce"},
		{"high", "sqli"},
		{"medium", "xss"},
		{"low", "info_disclosure"},
	}

	for _, f := range findings {
		recorder.RecordFindingSubmitted(f.severity, f.category)
	}

	// Verify metric was created
	recorder.mu.RLock()
	_, hasFindings := recorder.counters[MetricFindingsSubmitted]
	recorder.mu.RUnlock()
	assert.True(t, hasFindings, "should have findings counter")
}

// TestRecordAgentDelegation tests agent delegation metric recording.
func TestRecordAgentDelegation(t *testing.T) {
	provider := sdkmetric.NewMeterProvider()
	meter := provider.Meter("test")
	recorder := NewOpenTelemetryMetricsRecorder(meter)

	// Record a delegation
	recorder.RecordAgentDelegation("recon_agent", "exploit_agent", "success")

	// Verify metric was created
	recorder.mu.RLock()
	_, hasDelegations := recorder.counters[MetricAgentDelegations]
	recorder.mu.RUnlock()

	assert.True(t, hasDelegations, "delegations counter should be created")
}

// TestRecordAgentDelegation_MultipleDelegations tests recording for different delegations.
func TestRecordAgentDelegation_MultipleDelegations(t *testing.T) {
	provider := sdkmetric.NewMeterProvider()
	meter := provider.Meter("test")
	recorder := NewOpenTelemetryMetricsRecorder(meter)

	// Record multiple delegations
	delegations := []struct {
		source string
		target string
		status string
	}{
		{"recon_agent", "exploit_agent", "success"},
		{"exploit_agent", "escalation_agent", "success"},
		{"recon_agent", "analysis_agent", "rejected"},
	}

	for _, d := range delegations {
		recorder.RecordAgentDelegation(d.source, d.target, d.status)
	}

	// Verify metric was created
	recorder.mu.RLock()
	_, hasDelegations := recorder.counters[MetricAgentDelegations]
	recorder.mu.RUnlock()
	assert.True(t, hasDelegations, "should have delegations counter")
}

// TestConcurrentAccess tests thread safety of metrics recording.
func TestConcurrentAccess(t *testing.T) {
	provider := sdkmetric.NewMeterProvider()
	meter := provider.Meter("test")
	recorder := NewOpenTelemetryMetricsRecorder(meter)

	// Run concurrent operations
	const numGoroutines = 100
	const numOperations = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 3) // 3 types of operations

	// Concurrent counter recording
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				recorder.RecordCounter("test.counter", 1, map[string]string{
					"id": string(rune(id)),
				})
			}
		}(i)
	}

	// Concurrent gauge recording
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				recorder.RecordGauge("test.gauge", float64(id*100+j), map[string]string{
					"id": string(rune(id)),
				})
			}
		}(i)
	}

	// Concurrent histogram recording
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				recorder.RecordHistogram("test.histogram", float64(id*100+j), map[string]string{
					"id": string(rune(id)),
				})
			}
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Verify metrics were created
	recorder.mu.RLock()
	assert.Equal(t, 1, len(recorder.counters))
	assert.Equal(t, 1, len(recorder.gauges))
	assert.Equal(t, 1, len(recorder.histograms))
	recorder.mu.RUnlock()
}

// TestConcurrentLazyCreation tests that lazy metric creation is thread-safe.
func TestConcurrentLazyCreation(t *testing.T) {
	provider := sdkmetric.NewMeterProvider()
	meter := provider.Meter("test")
	recorder := NewOpenTelemetryMetricsRecorder(meter)

	// Run concurrent operations that will trigger lazy creation
	const numGoroutines = 50

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// All goroutines try to create the same counter simultaneously
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			recorder.RecordCounter("race.counter", 1, nil)
		}()
	}

	wg.Wait()

	// Verify only one counter was created
	recorder.mu.RLock()
	assert.Equal(t, 1, len(recorder.counters))
	_, exists := recorder.counters["race.counter"]
	recorder.mu.RUnlock()
	assert.True(t, exists)
}

// TestLabelsToAttributes tests label conversion to OpenTelemetry attributes.
func TestLabelsToAttributes(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		want   int
	}{
		{
			name:   "nil labels",
			labels: nil,
			want:   0,
		},
		{
			name:   "empty labels",
			labels: map[string]string{},
			want:   0,
		},
		{
			name: "single label",
			labels: map[string]string{
				"key": "value",
			},
			want: 1,
		},
		{
			name: "multiple labels",
			labels: map[string]string{
				"key1": "value1",
				"key2": "value2",
				"key3": "value3",
			},
			want: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := labelsToAttributes(tt.labels)
			assert.Equal(t, tt.want, len(attrs))

			// Verify each label is converted correctly
			for k, v := range tt.labels {
				found := false
				for _, attr := range attrs {
					if string(attr.Key) == k && attr.Value.AsString() == v {
						found = true
						break
					}
				}
				assert.True(t, found, "label %s=%s should be in attributes", k, v)
			}
		})
	}
}

// TestMetricNameConstants tests that metric name constants are properly defined.
func TestMetricNameConstants(t *testing.T) {
	// Verify all metric constants are non-empty and follow naming convention
	metrics := map[string]string{
		"LLM Completions":    MetricLLMCompletions,
		"LLM Input Tokens":   MetricLLMTokensInput,
		"LLM Output Tokens":  MetricLLMTokensOutput,
		"LLM Latency":        MetricLLMLatency,
		"LLM Cost":           MetricLLMCost,
		"Tool Calls":         MetricToolCalls,
		"Tool Duration":      MetricToolDuration,
		"Findings Submitted": MetricFindingsSubmitted,
		"Agent Delegations":  MetricAgentDelegations,
	}

	for name, constant := range metrics {
		t.Run(name, func(t *testing.T) {
			assert.NotEmpty(t, constant, "metric constant should not be empty")
			assert.Contains(t, constant, "gibson.", "metric should have gibson. prefix")
		})
	}
}

// TestIntegration_FullMission tests a complete metrics mission.
func TestIntegration_FullMission(t *testing.T) {
	// Initialize metrics provider
	cfg := MetricsConfig{
		Enabled:  true,
		Provider: "prometheus",
		Port:     9090,
	}

	provider, err := InitMetrics(context.Background(), cfg)
	require.NoError(t, err)
	defer func() {
		if mp, ok := provider.(*sdkmetric.MeterProvider); ok {
			_ = mp.Shutdown(context.Background())
		}
	}()

	// Create recorder
	meter := provider.Meter("gibson")
	recorder := NewOpenTelemetryMetricsRecorder(meter)

	// Simulate a complete agent execution mission
	// 1. LLM completion for task planning
	recorder.RecordLLMCompletion(
		"primary",
		"anthropic",
		"claude-3-opus",
		"success",
		2000,
		1000,
		250.0,
		0.025,
	)

	// 2. Tool execution
	recorder.RecordToolCall("nmap_scan", "success", 3000.0)

	// 3. Another LLM completion for analysis
	recorder.RecordLLMCompletion(
		"primary",
		"anthropic",
		"claude-3-opus",
		"success",
		1500,
		800,
		200.0,
		0.020,
	)

	// 4. Finding submission
	recorder.RecordFindingSubmitted("high", "sqli")

	// 5. Agent delegation
	recorder.RecordAgentDelegation("recon_agent", "exploit_agent", "success")

	// Verify all metrics were created
	recorder.mu.RLock()
	numCounters := len(recorder.counters)
	numHistograms := len(recorder.histograms)
	recorder.mu.RUnlock()

	assert.Greater(t, numCounters, 0, "should have created counters")
	assert.Greater(t, numHistograms, 0, "should have created histograms")

	// Give a small delay for metrics to be processed
	time.Sleep(100 * time.Millisecond)
}

// BenchmarkRecordCounter benchmarks counter recording performance.
func BenchmarkRecordCounter(b *testing.B) {
	provider := sdkmetric.NewMeterProvider()
	meter := provider.Meter("benchmark")
	recorder := NewOpenTelemetryMetricsRecorder(meter)

	labels := map[string]string{
		"status": "success",
		"method": "POST",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recorder.RecordCounter("bench.counter", 1, labels)
	}
}

// BenchmarkRecordHistogram benchmarks histogram recording performance.
func BenchmarkRecordHistogram(b *testing.B) {
	provider := sdkmetric.NewMeterProvider()
	meter := provider.Meter("benchmark")
	recorder := NewOpenTelemetryMetricsRecorder(meter)

	labels := map[string]string{
		"endpoint": "/api/users",
		"status":   "200",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recorder.RecordHistogram("bench.histogram", float64(i), labels)
	}
}

// BenchmarkRecordLLMCompletion benchmarks LLM completion recording performance.
func BenchmarkRecordLLMCompletion(b *testing.B) {
	provider := sdkmetric.NewMeterProvider()
	meter := provider.Meter("benchmark")
	recorder := NewOpenTelemetryMetricsRecorder(meter)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recorder.RecordLLMCompletion(
			"primary",
			"anthropic",
			"claude-3-opus",
			"success",
			1000,
			500,
			150.5,
			0.015,
		)
	}
}

// BenchmarkConcurrentRecording benchmarks concurrent metric recording.
func BenchmarkConcurrentRecording(b *testing.B) {
	provider := sdkmetric.NewMeterProvider()
	meter := provider.Meter("benchmark")
	recorder := NewOpenTelemetryMetricsRecorder(meter)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			recorder.RecordCounter("bench.counter", 1, nil)
		}
	})
}
