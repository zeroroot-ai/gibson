package eval

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/sdk/eval"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// TestNewExternalExporter_NilOptions tests that nil options return an error
func TestNewExternalExporter_NilOptions(t *testing.T) {
	tracer := otel.Tracer("test")
	exporter, err := NewExternalExporter(nil, tracer, "mission-123")
	assert.Error(t, err)
	assert.Nil(t, exporter)
	assert.Contains(t, err.Error(), "options cannot be nil")
}

// TestNewExternalExporter_DisabledExports tests that both exports disabled works
func TestNewExternalExporter_DisabledExports(t *testing.T) {
	opts := &EvalOptions{
		Enabled:        true,
		ExportLangfuse: false,
		ExportOTel:     false,
	}

	exporter, err := NewExternalExporter(opts, nil, "mission-123")
	require.NoError(t, err)
	require.NotNil(t, exporter)
	assert.Nil(t, exporter.langfuseExporter)
	assert.False(t, exporter.otelEnabled)
	assert.Equal(t, "mission-123", exporter.missionID)
}

// TestNewExternalExporter_LangfuseMissingCredentials tests error when credentials missing
func TestNewExternalExporter_LangfuseMissingCredentials(t *testing.T) {
	// Save original env vars
	origPublic := os.Getenv("LANGFUSE_PUBLIC_KEY")
	origSecret := os.Getenv("LANGFUSE_SECRET_KEY")
	defer func() {
		os.Setenv("LANGFUSE_PUBLIC_KEY", origPublic)
		os.Setenv("LANGFUSE_SECRET_KEY", origSecret)
	}()

	// Clear credentials
	os.Unsetenv("LANGFUSE_PUBLIC_KEY")
	os.Unsetenv("LANGFUSE_SECRET_KEY")

	opts := &EvalOptions{
		Enabled:        true,
		ExportLangfuse: true,
		ExportOTel:     false,
	}

	exporter, err := NewExternalExporter(opts, nil, "mission-123")
	assert.Error(t, err)
	assert.Nil(t, exporter)
	assert.Contains(t, err.Error(), "missing credentials")
}

// TestNewExternalExporter_LangfuseWithCredentials tests successful initialization
func TestNewExternalExporter_LangfuseWithCredentials(t *testing.T) {
	// Save original env vars
	origPublic := os.Getenv("LANGFUSE_PUBLIC_KEY")
	origSecret := os.Getenv("LANGFUSE_SECRET_KEY")
	origHost := os.Getenv("LANGFUSE_HOST")
	defer func() {
		os.Setenv("LANGFUSE_PUBLIC_KEY", origPublic)
		os.Setenv("LANGFUSE_SECRET_KEY", origSecret)
		os.Setenv("LANGFUSE_HOST", origHost)
	}()

	// Set test credentials
	os.Setenv("LANGFUSE_PUBLIC_KEY", "pk-test-123")
	os.Setenv("LANGFUSE_SECRET_KEY", "sk-test-456")
	os.Setenv("LANGFUSE_HOST", "https://test.langfuse.com")

	opts := &EvalOptions{
		Enabled:        true,
		ExportLangfuse: true,
		ExportOTel:     false,
	}

	exporter, err := NewExternalExporter(opts, nil, "mission-123")
	require.NoError(t, err)
	require.NotNil(t, exporter)
	assert.NotNil(t, exporter.langfuseExporter)
	assert.False(t, exporter.otelEnabled)

	// Clean up
	err = exporter.Close()
	assert.NoError(t, err)
}

// TestNewExternalExporter_LangfuseDefaultHost tests default host usage
func TestNewExternalExporter_LangfuseDefaultHost(t *testing.T) {
	// Save original env vars
	origPublic := os.Getenv("LANGFUSE_PUBLIC_KEY")
	origSecret := os.Getenv("LANGFUSE_SECRET_KEY")
	origHost := os.Getenv("LANGFUSE_HOST")
	defer func() {
		os.Setenv("LANGFUSE_PUBLIC_KEY", origPublic)
		os.Setenv("LANGFUSE_SECRET_KEY", origSecret)
		os.Setenv("LANGFUSE_HOST", origHost)
	}()

	// Set credentials but no host
	os.Setenv("LANGFUSE_PUBLIC_KEY", "pk-test-123")
	os.Setenv("LANGFUSE_SECRET_KEY", "sk-test-456")
	os.Unsetenv("LANGFUSE_HOST")

	opts := &EvalOptions{
		Enabled:        true,
		ExportLangfuse: true,
		ExportOTel:     false,
	}

	exporter, err := NewExternalExporter(opts, nil, "mission-123")
	require.NoError(t, err)
	require.NotNil(t, exporter)
	assert.NotNil(t, exporter.langfuseExporter)

	// Clean up
	err = exporter.Close()
	assert.NoError(t, err)
}

// TestNewExternalExporter_OTelMissingTracer tests error when tracer is nil
func TestNewExternalExporter_OTelMissingTracer(t *testing.T) {
	opts := &EvalOptions{
		Enabled:        true,
		ExportLangfuse: false,
		ExportOTel:     true,
	}

	exporter, err := NewExternalExporter(opts, nil, "mission-123")
	assert.Error(t, err)
	assert.Nil(t, exporter)
	assert.Contains(t, err.Error(), "tracer is nil")
}

// TestNewExternalExporter_OTelWithTracer tests successful OTel initialization
func TestNewExternalExporter_OTelWithTracer(t *testing.T) {
	tracer := otel.Tracer("test")

	opts := &EvalOptions{
		Enabled:        true,
		ExportLangfuse: false,
		ExportOTel:     true,
	}

	exporter, err := NewExternalExporter(opts, tracer, "mission-123")
	require.NoError(t, err)
	require.NotNil(t, exporter)
	assert.Nil(t, exporter.langfuseExporter)
	assert.True(t, exporter.otelEnabled)
	assert.NotNil(t, exporter.tracer)
}

// TestNewExternalExporter_BothEnabled tests both Langfuse and OTel enabled
func TestNewExternalExporter_BothEnabled(t *testing.T) {
	// Save original env vars
	origPublic := os.Getenv("LANGFUSE_PUBLIC_KEY")
	origSecret := os.Getenv("LANGFUSE_SECRET_KEY")
	defer func() {
		os.Setenv("LANGFUSE_PUBLIC_KEY", origPublic)
		os.Setenv("LANGFUSE_SECRET_KEY", origSecret)
	}()

	// Set test credentials
	os.Setenv("LANGFUSE_PUBLIC_KEY", "pk-test-123")
	os.Setenv("LANGFUSE_SECRET_KEY", "sk-test-456")

	tracer := otel.Tracer("test")

	opts := &EvalOptions{
		Enabled:        true,
		ExportLangfuse: true,
		ExportOTel:     true,
	}

	exporter, err := NewExternalExporter(opts, tracer, "mission-123")
	require.NoError(t, err)
	require.NotNil(t, exporter)
	assert.NotNil(t, exporter.langfuseExporter)
	assert.True(t, exporter.otelEnabled)
	assert.NotNil(t, exporter.tracer)

	// Clean up
	err = exporter.Close()
	assert.NoError(t, err)
}

// TestExportResults_NilSummary tests that nil summary returns error
func TestExportResults_NilSummary(t *testing.T) {
	opts := &EvalOptions{
		Enabled:        true,
		ExportLangfuse: false,
		ExportOTel:     false,
	}

	exporter, err := NewExternalExporter(opts, nil, "mission-123")
	require.NoError(t, err)

	ctx := context.Background()
	err = exporter.ExportResults(ctx, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "summary cannot be nil")
}

// TestExportResults_DisabledExports tests export with no exporters enabled
func TestExportResults_DisabledExports(t *testing.T) {
	opts := &EvalOptions{
		Enabled:        true,
		ExportLangfuse: false,
		ExportOTel:     false,
	}

	exporter, err := NewExternalExporter(opts, nil, "mission-123")
	require.NoError(t, err)

	summary := NewEvalSummary("mission-123")
	summary.ScorerScores["test_scorer"] = 0.85
	summary.OverallScore = 0.85

	ctx := context.Background()
	err = exporter.ExportResults(ctx, summary)
	assert.NoError(t, err) // Should succeed with no-op
}

// TestExportResults_OTel tests OpenTelemetry export
func TestExportResults_OTel(t *testing.T) {
	// Create a test span recorder
	spanRecorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	tracer := tracerProvider.Tracer("test")

	opts := &EvalOptions{
		Enabled:        true,
		ExportLangfuse: false,
		ExportOTel:     true,
	}

	exporter, err := NewExternalExporter(opts, tracer, "mission-123")
	require.NoError(t, err)

	// Create a summary with test data
	summary := NewEvalSummary("mission-123")
	summary.ScorerScores["exact_match"] = 0.85
	summary.ScorerScores["tool_correctness"] = 0.92
	summary.OverallScore = 0.885
	summary.TotalSteps = 10
	summary.TotalAlerts = 2
	summary.WarningCount = 1
	summary.CriticalCount = 1
	summary.TokensUsed = 1500
	summary.Duration = 5 * time.Second

	// Add feedback with alerts
	summary.FeedbackHistory = []eval.Feedback{
		{
			Timestamp: time.Now(),
			StepIndex: 5,
			Alerts: []eval.Alert{
				{
					Level:     eval.AlertWarning,
					Scorer:    "exact_match",
					Score:     0.45,
					Threshold: 0.5,
					Message:   "Score below warning threshold",
				},
				{
					Level:     eval.AlertCritical,
					Scorer:    "tool_correctness",
					Score:     0.15,
					Threshold: 0.2,
					Message:   "Score below critical threshold",
				},
			},
		},
	}

	ctx := context.Background()
	err = exporter.ExportResults(ctx, summary)
	require.NoError(t, err)

	// Verify spans were recorded
	spans := spanRecorder.Ended()
	require.Len(t, spans, 1, "Expected exactly one span")

	span := spans[0]
	assert.Equal(t, "eval.results", span.Name())

	// Verify span attributes
	attrs := span.Attributes()
	attrMap := make(map[string]interface{})
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value.AsInterface()
	}

	assert.Equal(t, "mission-123", attrMap["mission.id"])
	assert.Equal(t, 0.885, attrMap["eval.overall_score"])
	assert.Equal(t, int64(10), attrMap["eval.total_steps"])
	assert.Equal(t, int64(2), attrMap["eval.total_alerts"])
	assert.Equal(t, int64(1), attrMap["eval.warning_count"])
	assert.Equal(t, int64(1), attrMap["eval.critical_count"])
	assert.Equal(t, int64(1500), attrMap["eval.tokens_used"])
	assert.Equal(t, 0.85, attrMap["eval.scorer.exact_match"])
	assert.Equal(t, 0.92, attrMap["eval.scorer.tool_correctness"])

	// Verify span events for alerts
	events := span.Events()
	assert.Greater(t, len(events), 0, "Expected alert events")
}

// TestExportResults_OTelNoAlerts tests OTel export with no alerts
func TestExportResults_OTelNoAlerts(t *testing.T) {
	// Create a test span recorder
	spanRecorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	tracer := tracerProvider.Tracer("test")

	opts := &EvalOptions{
		Enabled:        true,
		ExportLangfuse: false,
		ExportOTel:     true,
	}

	exporter, err := NewExternalExporter(opts, tracer, "mission-123")
	require.NoError(t, err)

	// Create a summary with good scores
	summary := NewEvalSummary("mission-123")
	summary.ScorerScores["test_scorer"] = 0.95
	summary.OverallScore = 0.95
	summary.TotalSteps = 5

	ctx := context.Background()
	err = exporter.ExportResults(ctx, summary)
	require.NoError(t, err)

	// Verify spans were recorded
	spans := spanRecorder.Ended()
	require.Len(t, spans, 1)

	span := spans[0]
	assert.Equal(t, "eval.results", span.Name())
}

// TestExportPartialScore_EmptyAgentName tests error when agent name is empty
func TestExportPartialScore_EmptyAgentName(t *testing.T) {
	opts := &EvalOptions{
		Enabled:        true,
		ExportLangfuse: false,
		ExportOTel:     false,
	}

	exporter, err := NewExternalExporter(opts, nil, "mission-123")
	require.NoError(t, err)

	ctx := context.Background()
	score := eval.PartialScore{
		Score:      0.85,
		Confidence: 0.9,
		Status:     eval.ScoreStatusPartial,
	}

	err = exporter.ExportPartialScore(ctx, "", score)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "agent name cannot be empty")
}

// TestExportPartialScore_DisabledExports tests partial score export with no exporters
func TestExportPartialScore_DisabledExports(t *testing.T) {
	opts := &EvalOptions{
		Enabled:        true,
		ExportLangfuse: false,
		ExportOTel:     false,
	}

	exporter, err := NewExternalExporter(opts, nil, "mission-123")
	require.NoError(t, err)

	ctx := context.Background()
	score := eval.PartialScore{
		Score:      0.85,
		Confidence: 0.9,
		Status:     eval.ScoreStatusPartial,
	}

	err = exporter.ExportPartialScore(ctx, "test_agent", score)
	assert.NoError(t, err) // Should succeed with no-op
}

// TestExportPartialScore_OTel tests OTel partial score export
func TestExportPartialScore_OTel(t *testing.T) {
	// Create a test span recorder
	spanRecorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	tracer := tracerProvider.Tracer("test")

	opts := &EvalOptions{
		Enabled:        true,
		ExportLangfuse: false,
		ExportOTel:     true,
	}

	exporter, err := NewExternalExporter(opts, tracer, "mission-123")
	require.NoError(t, err)

	// Create a parent span to test event recording
	ctx := context.Background()
	ctx, parentSpan := tracer.Start(ctx, "test_parent")

	score := eval.PartialScore{
		Score:      0.85,
		Confidence: 0.9,
		Status:     eval.ScoreStatusPartial,
	}

	err = exporter.ExportPartialScore(ctx, "test_agent", score)
	require.NoError(t, err)

	parentSpan.End()

	// Verify span events were recorded
	spans := spanRecorder.Ended()
	require.Len(t, spans, 1)

	span := spans[0]
	events := span.Events()
	require.Len(t, events, 1)

	event := events[0]
	assert.Equal(t, "eval.partial_score", event.Name)

	// Verify event attributes
	attrs := event.Attributes
	attrMap := make(map[string]interface{})
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value.AsInterface()
	}

	assert.Equal(t, "test_agent", attrMap["agent.name"])
	assert.Equal(t, 0.85, attrMap["score.value"])
	assert.Equal(t, 0.9, attrMap["score.confidence"])
	assert.Equal(t, string(eval.ScoreStatusPartial), attrMap["score.status"])
}

// TestExportPartialScore_OTelNoActiveSpan tests OTel export with no active span
func TestExportPartialScore_OTelNoActiveSpan(t *testing.T) {
	tracer := otel.Tracer("test")

	opts := &EvalOptions{
		Enabled:        true,
		ExportLangfuse: false,
		ExportOTel:     true,
	}

	exporter, err := NewExternalExporter(opts, tracer, "mission-123")
	require.NoError(t, err)

	// Use context without an active span
	ctx := context.Background()

	score := eval.PartialScore{
		Score:      0.85,
		Confidence: 0.9,
		Status:     eval.ScoreStatusPartial,
	}

	// Should not error even without active span
	err = exporter.ExportPartialScore(ctx, "test_agent", score)
	assert.NoError(t, err)
}

// TestClose_NoExporters tests closing with no exporters
func TestClose_NoExporters(t *testing.T) {
	opts := &EvalOptions{
		Enabled:        true,
		ExportLangfuse: false,
		ExportOTel:     false,
	}

	exporter, err := NewExternalExporter(opts, nil, "mission-123")
	require.NoError(t, err)

	err = exporter.Close()
	assert.NoError(t, err)
}

// TestClose_WithLangfuse tests closing with Langfuse exporter
func TestClose_WithLangfuse(t *testing.T) {
	// Save original env vars
	origPublic := os.Getenv("LANGFUSE_PUBLIC_KEY")
	origSecret := os.Getenv("LANGFUSE_SECRET_KEY")
	defer func() {
		os.Setenv("LANGFUSE_PUBLIC_KEY", origPublic)
		os.Setenv("LANGFUSE_SECRET_KEY", origSecret)
	}()

	// Set test credentials
	os.Setenv("LANGFUSE_PUBLIC_KEY", "pk-test-123")
	os.Setenv("LANGFUSE_SECRET_KEY", "sk-test-456")

	opts := &EvalOptions{
		Enabled:        true,
		ExportLangfuse: true,
		ExportOTel:     false,
	}

	exporter, err := NewExternalExporter(opts, nil, "mission-123")
	require.NoError(t, err)

	err = exporter.Close()
	assert.NoError(t, err)
}

// TestExportToOTel_CriticalAlerts tests span status with critical alerts
func TestExportToOTel_CriticalAlerts(t *testing.T) {
	// Create a test span recorder
	spanRecorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	tracer := tracerProvider.Tracer("test")

	opts := &EvalOptions{
		Enabled:        true,
		ExportLangfuse: false,
		ExportOTel:     true,
	}

	exporter, err := NewExternalExporter(opts, tracer, "mission-123")
	require.NoError(t, err)

	// Create a summary with critical alerts
	summary := NewEvalSummary("mission-123")
	summary.CriticalCount = 2
	summary.OverallScore = 0.15

	ctx := context.Background()
	err = exporter.ExportResults(ctx, summary)
	require.NoError(t, err)

	// Verify span status is error
	spans := spanRecorder.Ended()
	require.Len(t, spans, 1)

	span := spans[0]
	assert.Equal(t, "eval.results", span.Name())
	// Status code should indicate error
	status := span.Status()
	assert.NotEqual(t, 0, status.Code) // Not OK
}

// TestExportToOTel_WarningsOnly tests span with warnings but no critical alerts
func TestExportToOTel_WarningsOnly(t *testing.T) {
	// Create a test span recorder
	spanRecorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	tracer := tracerProvider.Tracer("test")

	opts := &EvalOptions{
		Enabled:        true,
		ExportLangfuse: false,
		ExportOTel:     true,
	}

	exporter, err := NewExternalExporter(opts, tracer, "mission-123")
	require.NoError(t, err)

	// Create a summary with warnings only
	summary := NewEvalSummary("mission-123")
	summary.WarningCount = 1
	summary.CriticalCount = 0
	summary.OverallScore = 0.65

	ctx := context.Background()
	err = exporter.ExportResults(ctx, summary)
	require.NoError(t, err)

	// Verify span was created
	spans := spanRecorder.Ended()
	require.Len(t, spans, 1)

	span := spans[0]
	assert.Equal(t, "eval.results", span.Name())

	// Verify warning event
	events := span.Events()
	found := false
	for _, event := range events {
		if event.Name == "eval.warnings" {
			found = true
			break
		}
	}
	assert.True(t, found, "Expected eval.warnings event")
}
