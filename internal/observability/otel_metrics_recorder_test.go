package observability

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// TestNewOTelMetricsRecorder tests the constructor creates recorder
func TestNewOTelMetricsRecorder(t *testing.T) {
	// Create test meter provider
	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	// Create recorder
	recorder, err := NewOTelMetricsRecorder(mp)

	// Verify success
	require.NoError(t, err)
	assert.NotNil(t, recorder)
	assert.NotNil(t, recorder.meter)
	assert.NotNil(t, recorder.llmRequestsTotal)
	assert.NotNil(t, recorder.llmTokensTotal)
	assert.NotNil(t, recorder.llmCostTotal)
	assert.NotNil(t, recorder.toolCallsTotal)
	assert.NotNil(t, recorder.findingsTotal)
	assert.NotNil(t, recorder.agentExecutionsTotal)
	assert.NotNil(t, recorder.missionsTotal)
	assert.NotNil(t, recorder.memoryOpsTotal)
	assert.NotNil(t, recorder.graphOpsTotal)
	assert.NotNil(t, recorder.decisionsTotal)
	assert.NotNil(t, recorder.llmLatencySeconds)
	assert.NotNil(t, recorder.toolLatencySeconds)
	assert.NotNil(t, recorder.agentDurationSeconds)
	assert.NotNil(t, recorder.missionDurationSeconds)
}

// TestNewOTelMetricsRecorder_NilProvider tests returning noop recorder
func TestNewOTelMetricsRecorder_NilProvider(t *testing.T) {
	// Create recorder with nil provider
	recorder, err := NewOTelMetricsRecorder(nil)

	// Should succeed with noop recorder
	require.NoError(t, err)
	assert.NotNil(t, recorder)

	// Should be safe to call methods on noop recorder
	assert.NotPanics(t, func() {
		recorder.RecordLLMCompletion(context.Background(), "openai", "gpt-4", "success", 100, 50, 1500.0, 0.05)
	})
}

// TestNoopMetricsRecorder tests noop recorder behavior
func TestNoopMetricsRecorder(t *testing.T) {
	recorder := NoopMetricsRecorder()

	assert.NotNil(t, recorder)

	// All methods should be safe to call
	assert.NotPanics(t, func() {
		recorder.RecordLLMCompletion(context.Background(), "openai", "gpt-4", "success", 100, 50, 1500.0, 0.05)
		recorder.RecordToolCall(context.Background(), "nmap", "success", 2500.0)
		recorder.RecordFinding(context.Background(), "high", "sql_injection")
		recorder.RecordAgentExecution(context.Background(), "test-agent", "completed", 45000.0)
		recorder.RecordMission(context.Background(), "completed", 300000.0)
		recorder.RecordMemoryOp(context.Background(), "short", "set")
		recorder.RecordGraphOp(context.Background(), "store")
		recorder.RecordDecision(context.Background(), "execute_agent")
	})
}

// TestOTelMetricsRecorder_RecordLLMCompletion tests recording LLM metrics
func TestOTelMetricsRecorder_RecordLLMCompletion(t *testing.T) {
	// Create test meter provider
	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	recorder, err := NewOTelMetricsRecorder(mp)
	require.NoError(t, err)

	ctx := context.Background()

	// Record LLM completion
	recorder.RecordLLMCompletion(ctx, "openai", "gpt-4", "success", 100, 50, 1500.0, 0.05)

	// Collect metrics
	rm := &metricdata.ResourceMetrics{}
	err = reader.Collect(ctx, rm)
	require.NoError(t, err)

	// Verify metrics were recorded
	found := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "gibson.llm.requests.total" {
				found = true
				// Verify it's a sum
				sum, ok := m.Data.(metricdata.Sum[int64])
				require.True(t, ok)
				assert.Len(t, sum.DataPoints, 1)
				assert.Equal(t, int64(1), sum.DataPoints[0].Value)
			}
		}
	}
	assert.True(t, found, "Expected to find gibson.llm.requests.total metric")
}

// TestOTelMetricsRecorder_RecordLLMCompletion_MultipleProviders tests metrics with different labels
func TestOTelMetricsRecorder_RecordLLMCompletion_MultipleProviders(t *testing.T) {
	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	recorder, err := NewOTelMetricsRecorder(mp)
	require.NoError(t, err)

	ctx := context.Background()

	// Record multiple completions with different providers
	recorder.RecordLLMCompletion(ctx, "openai", "gpt-4", "success", 100, 50, 1500.0, 0.05)
	recorder.RecordLLMCompletion(ctx, "anthropic", "claude-3-opus", "success", 200, 100, 2000.0, 0.10)
	recorder.RecordLLMCompletion(ctx, "openai", "gpt-4", "error", 50, 0, 1000.0, 0.0)

	// Collect metrics
	rm := &metricdata.ResourceMetrics{}
	err = reader.Collect(ctx, rm)
	require.NoError(t, err)

	// Verify metrics
	var requestCount int
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "gibson.llm.requests.total" {
				sum, ok := m.Data.(metricdata.Sum[int64])
				require.True(t, ok)
				requestCount = len(sum.DataPoints)
			}
		}
	}

	// Should have separate data points for each provider/model/status combination
	assert.GreaterOrEqual(t, requestCount, 2)
}

// TestOTelMetricsRecorder_RecordToolCall tests recording tool metrics
func TestOTelMetricsRecorder_RecordToolCall(t *testing.T) {
	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	recorder, err := NewOTelMetricsRecorder(mp)
	require.NoError(t, err)

	ctx := context.Background()

	// Record tool calls
	recorder.RecordToolCall(ctx, "nmap", "success", 2500.0)
	recorder.RecordToolCall(ctx, "nmap", "success", 3000.0)
	recorder.RecordToolCall(ctx, "nuclei", "success", 1500.0)

	// Collect metrics
	rm := &metricdata.ResourceMetrics{}
	err = reader.Collect(ctx, rm)
	require.NoError(t, err)

	// Verify tool calls counter
	foundCounter := false
	foundHistogram := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "gibson.tool.calls.total" {
				foundCounter = true
				sum, ok := m.Data.(metricdata.Sum[int64])
				require.True(t, ok)
				assert.GreaterOrEqual(t, len(sum.DataPoints), 1)
			}
			if m.Name == "gibson.tool.latency.seconds" {
				foundHistogram = true
				hist, ok := m.Data.(metricdata.Histogram[float64])
				require.True(t, ok)
				assert.GreaterOrEqual(t, len(hist.DataPoints), 1)
			}
		}
	}
	assert.True(t, foundCounter, "Expected to find tool calls counter")
	assert.True(t, foundHistogram, "Expected to find tool latency histogram")
}

// TestOTelMetricsRecorder_RecordFinding tests recording finding metrics
func TestOTelMetricsRecorder_RecordFinding(t *testing.T) {
	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	recorder, err := NewOTelMetricsRecorder(mp)
	require.NoError(t, err)

	ctx := context.Background()

	// Record findings with different severities
	recorder.RecordFinding(ctx, "critical", "sql_injection")
	recorder.RecordFinding(ctx, "high", "xss")
	recorder.RecordFinding(ctx, "medium", "misconfiguration")

	// Collect metrics
	rm := &metricdata.ResourceMetrics{}
	err = reader.Collect(ctx, rm)
	require.NoError(t, err)

	// Verify findings counter
	found := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "gibson.finding.submissions.total" {
				found = true
				sum, ok := m.Data.(metricdata.Sum[int64])
				require.True(t, ok)
				// Should have multiple data points for different severity/category combinations
				assert.GreaterOrEqual(t, len(sum.DataPoints), 1)
			}
		}
	}
	assert.True(t, found, "Expected to find findings counter")
}

// TestOTelMetricsRecorder_RecordAgentExecution tests recording agent metrics
func TestOTelMetricsRecorder_RecordAgentExecution(t *testing.T) {
	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	recorder, err := NewOTelMetricsRecorder(mp)
	require.NoError(t, err)

	ctx := context.Background()

	// Record agent executions
	recorder.RecordAgentExecution(ctx, "recon-agent", "completed", 45000.0)
	recorder.RecordAgentExecution(ctx, "exploit-agent", "completed", 60000.0)
	recorder.RecordAgentExecution(ctx, "recon-agent", "failed", 5000.0)

	// Collect metrics
	rm := &metricdata.ResourceMetrics{}
	err = reader.Collect(ctx, rm)
	require.NoError(t, err)

	// Verify agent execution metrics
	foundCounter := false
	foundHistogram := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "gibson.agent.executions.total" {
				foundCounter = true
				sum, ok := m.Data.(metricdata.Sum[int64])
				require.True(t, ok)
				assert.GreaterOrEqual(t, len(sum.DataPoints), 1)
			}
			if m.Name == "gibson.agent.duration.seconds" {
				foundHistogram = true
				hist, ok := m.Data.(metricdata.Histogram[float64])
				require.True(t, ok)
				assert.GreaterOrEqual(t, len(hist.DataPoints), 1)
			}
		}
	}
	assert.True(t, foundCounter, "Expected to find agent executions counter")
	assert.True(t, foundHistogram, "Expected to find agent duration histogram")
}

// TestOTelMetricsRecorder_RecordMission tests recording mission metrics
func TestOTelMetricsRecorder_RecordMission(t *testing.T) {
	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	recorder, err := NewOTelMetricsRecorder(mp)
	require.NoError(t, err)

	ctx := context.Background()

	// Record missions
	recorder.RecordMission(ctx, "completed", 300000.0)
	recorder.RecordMission(ctx, "completed", 450000.0)
	recorder.RecordMission(ctx, "failed", 60000.0)

	// Collect metrics
	rm := &metricdata.ResourceMetrics{}
	err = reader.Collect(ctx, rm)
	require.NoError(t, err)

	// Verify mission metrics
	foundCounter := false
	foundHistogram := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "gibson.mission.total" {
				foundCounter = true
				sum, ok := m.Data.(metricdata.Sum[int64])
				require.True(t, ok)
				assert.GreaterOrEqual(t, len(sum.DataPoints), 1)
			}
			if m.Name == "gibson.mission.duration.seconds" {
				foundHistogram = true
				hist, ok := m.Data.(metricdata.Histogram[float64])
				require.True(t, ok)
				assert.GreaterOrEqual(t, len(hist.DataPoints), 1)
			}
		}
	}
	assert.True(t, foundCounter, "Expected to find mission counter")
	assert.True(t, foundHistogram, "Expected to find mission duration histogram")
}

// TestOTelMetricsRecorder_RecordMemoryOp tests recording memory metrics
func TestOTelMetricsRecorder_RecordMemoryOp(t *testing.T) {
	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	recorder, err := NewOTelMetricsRecorder(mp)
	require.NoError(t, err)

	ctx := context.Background()

	// Record memory operations
	recorder.RecordMemoryOp(ctx, "short", "set")
	recorder.RecordMemoryOp(ctx, "short", "get")
	recorder.RecordMemoryOp(ctx, "long", "set")
	recorder.RecordMemoryOp(ctx, "vector", "search")

	// Collect metrics
	rm := &metricdata.ResourceMetrics{}
	err = reader.Collect(ctx, rm)
	require.NoError(t, err)

	// Verify memory ops counter
	found := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "gibson.memory.operations.total" {
				found = true
				sum, ok := m.Data.(metricdata.Sum[int64])
				require.True(t, ok)
				// Should have multiple data points for different tier/operation combinations
				assert.GreaterOrEqual(t, len(sum.DataPoints), 1)
			}
		}
	}
	assert.True(t, found, "Expected to find memory operations counter")
}

// TestOTelMetricsRecorder_RecordGraphOp tests recording graph metrics
func TestOTelMetricsRecorder_RecordGraphOp(t *testing.T) {
	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	recorder, err := NewOTelMetricsRecorder(mp)
	require.NoError(t, err)

	ctx := context.Background()

	// Record graph operations
	recorder.RecordGraphOp(ctx, "store")
	recorder.RecordGraphOp(ctx, "query")
	recorder.RecordGraphOp(ctx, "store")

	// Collect metrics
	rm := &metricdata.ResourceMetrics{}
	err = reader.Collect(ctx, rm)
	require.NoError(t, err)

	// Verify graph ops counter
	found := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "gibson.graph.operations.total" {
				found = true
				sum, ok := m.Data.(metricdata.Sum[int64])
				require.True(t, ok)
				assert.GreaterOrEqual(t, len(sum.DataPoints), 1)
			}
		}
	}
	assert.True(t, found, "Expected to find graph operations counter")
}

// TestOTelMetricsRecorder_RecordDecision tests recording decision metrics
func TestOTelMetricsRecorder_RecordDecision(t *testing.T) {
	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	recorder, err := NewOTelMetricsRecorder(mp)
	require.NoError(t, err)

	ctx := context.Background()

	// Record decisions
	recorder.RecordDecision(ctx, "execute_agent")
	recorder.RecordDecision(ctx, "complete")
	recorder.RecordDecision(ctx, "execute_agent")

	// Collect metrics
	rm := &metricdata.ResourceMetrics{}
	err = reader.Collect(ctx, rm)
	require.NoError(t, err)

	// Verify decisions counter
	found := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "gibson.orchestrator.decisions.total" {
				found = true
				sum, ok := m.Data.(metricdata.Sum[int64])
				require.True(t, ok)
				assert.GreaterOrEqual(t, len(sum.DataPoints), 1)
			}
		}
	}
	assert.True(t, found, "Expected to find decisions counter")
}

// TestOTelMetricsRecorder_HistogramBuckets tests histogram bucket boundaries
func TestOTelMetricsRecorder_HistogramBuckets(t *testing.T) {
	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	recorder, err := NewOTelMetricsRecorder(mp)
	require.NoError(t, err)

	ctx := context.Background()

	// Record values that should fall into different buckets
	recorder.RecordLLMCompletion(ctx, "openai", "gpt-4", "success", 100, 50, 100.0, 0.01)    // 0.1s
	recorder.RecordLLMCompletion(ctx, "openai", "gpt-4", "success", 100, 50, 2500.0, 0.05)   // 2.5s
	recorder.RecordLLMCompletion(ctx, "openai", "gpt-4", "success", 100, 50, 15000.0, 0.15)  // 15s

	// Collect metrics
	rm := &metricdata.ResourceMetrics{}
	err = reader.Collect(ctx, rm)
	require.NoError(t, err)

	// Find LLM latency histogram
	found := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "gibson.llm.latency.seconds" {
				found = true
				hist, ok := m.Data.(metricdata.Histogram[float64])
				require.True(t, ok)
				assert.GreaterOrEqual(t, len(hist.DataPoints), 1)

				// Verify histogram has buckets
				for _, dp := range hist.DataPoints {
					assert.NotEmpty(t, dp.BucketCounts, "Expected histogram to have buckets")
					assert.Equal(t, uint64(3), dp.Count, "Expected 3 observations")
				}
			}
		}
	}
	assert.True(t, found, "Expected to find LLM latency histogram")
}

// TestOTelMetricsRecorder_ZeroValues tests handling zero values
func TestOTelMetricsRecorder_ZeroValues(t *testing.T) {
	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	recorder, err := NewOTelMetricsRecorder(mp)
	require.NoError(t, err)

	ctx := context.Background()

	// Record with zero values (should be skipped)
	recorder.RecordLLMCompletion(ctx, "openai", "gpt-4", "success", 0, 0, 0.0, 0.0)

	// Collect metrics
	rm := &metricdata.ResourceMetrics{}
	err = reader.Collect(ctx, rm)
	require.NoError(t, err)

	// Verify request counter was still incremented
	foundRequest := false
	foundTokens := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "gibson.llm.requests.total" {
				foundRequest = true
			}
			if m.Name == "gibson.llm.tokens.total" {
				sum, ok := m.Data.(metricdata.Sum[int64])
				if ok && len(sum.DataPoints) > 0 {
					foundTokens = true
				}
			}
		}
	}
	assert.True(t, foundRequest, "Expected request counter to increment")
	// Tokens should not be recorded for zero values
	assert.False(t, foundTokens, "Expected no token metrics for zero values")
}

// TestOTelMetricsRecorder_NilRecorder tests nil receiver safety
func TestOTelMetricsRecorder_NilRecorder(t *testing.T) {
	var recorder *OTelMetricsRecorder

	ctx := context.Background()

	// All methods should be safe to call on nil receiver
	assert.NotPanics(t, func() {
		recorder.RecordLLMCompletion(ctx, "openai", "gpt-4", "success", 100, 50, 1500.0, 0.05)
		recorder.RecordToolCall(ctx, "nmap", "success", 2500.0)
		recorder.RecordFinding(ctx, "high", "sql_injection")
		recorder.RecordAgentExecution(ctx, "test-agent", "completed", 45000.0)
		recorder.RecordMission(ctx, "completed", 300000.0)
		recorder.RecordMemoryOp(ctx, "short", "set")
		recorder.RecordGraphOp(ctx, "store")
		recorder.RecordDecision(ctx, "execute_agent")
	})
}

// TestOTelMetricsRecorder_TokenTracking tests input and output token tracking
func TestOTelMetricsRecorder_TokenTracking(t *testing.T) {
	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	recorder, err := NewOTelMetricsRecorder(mp)
	require.NoError(t, err)

	ctx := context.Background()

	// Record LLM completions with different token counts
	recorder.RecordLLMCompletion(ctx, "openai", "gpt-4", "success", 100, 50, 1500.0, 0.05)
	recorder.RecordLLMCompletion(ctx, "openai", "gpt-4", "success", 200, 100, 2000.0, 0.10)

	// Collect metrics
	rm := &metricdata.ResourceMetrics{}
	err = reader.Collect(ctx, rm)
	require.NoError(t, err)

	// Verify token counters
	inputTokens := int64(0)
	outputTokens := int64(0)

	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "gibson.llm.tokens.total" {
				sum, ok := m.Data.(metricdata.Sum[int64])
				require.True(t, ok)
				for _, dp := range sum.DataPoints {
					// Check attributes to determine token type
					for _, attr := range dp.Attributes.ToSlice() {
						if string(attr.Key) == MetricAttrTokenType {
							if attr.Value.AsString() == "input" {
								inputTokens += dp.Value
							} else if attr.Value.AsString() == "output" {
								outputTokens += dp.Value
							}
						}
					}
				}
			}
		}
	}

	assert.Equal(t, int64(300), inputTokens, "Expected 300 input tokens total")
	assert.Equal(t, int64(150), outputTokens, "Expected 150 output tokens total")
}

// TestOTelMetricsRecorder_CostTracking tests cost accumulation
func TestOTelMetricsRecorder_CostTracking(t *testing.T) {
	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	recorder, err := NewOTelMetricsRecorder(mp)
	require.NoError(t, err)

	ctx := context.Background()

	// Record LLM completions with costs
	recorder.RecordLLMCompletion(ctx, "openai", "gpt-4", "success", 100, 50, 1500.0, 0.05)
	recorder.RecordLLMCompletion(ctx, "openai", "gpt-4", "success", 200, 100, 2000.0, 0.10)

	// Collect metrics
	rm := &metricdata.ResourceMetrics{}
	err = reader.Collect(ctx, rm)
	require.NoError(t, err)

	// Verify cost counter
	found := false
	totalCost := 0.0

	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "gibson.llm.cost.total" {
				found = true
				sum, ok := m.Data.(metricdata.Sum[float64])
				require.True(t, ok)
				for _, dp := range sum.DataPoints {
					totalCost += dp.Value
				}
			}
		}
	}

	assert.True(t, found, "Expected to find cost counter")
	assert.InDelta(t, 0.15, totalCost, 0.001, "Expected total cost of 0.15")
}
