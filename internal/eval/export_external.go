package eval

import (
	"context"
	"fmt"
	"os"

	"github.com/zeroroot-ai/sdk/eval"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// ExternalExporter handles exporting evaluation results to external observability platforms.
// It supports both Langfuse (for LLM evaluation tracking) and OpenTelemetry (for distributed tracing).
//
// The exporter is configured based on EvalOptions and environment variables:
//   - Langfuse: Requires LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY, and optionally LANGFUSE_HOST
//   - OpenTelemetry: Uses the provided tracer if ExportOTel is enabled
//
// Example usage:
//
//	exporter, err := NewExternalExporter(evalOpts, tracer)
//	if err != nil {
//	    return err
//	}
//	defer exporter.Close()
//
//	// Export final results
//	if err := exporter.ExportResults(ctx, summary); err != nil {
//	    log.Printf("Failed to export results: %v", err)
//	}
//
//	// Export partial scores during execution
//	partialScore := eval.PartialScore{Score: 0.85, Confidence: 0.9}
//	if err := exporter.ExportPartialScore(ctx, "my_agent", partialScore); err != nil {
//	    log.Printf("Failed to export partial score: %v", err)
//	}
type ExternalExporter struct {
	// langfuseExporter is the SDK Langfuse exporter for sending scores to Langfuse
	langfuseExporter *eval.LangfuseExporter

	// otelEnabled controls whether OpenTelemetry tracing is active
	otelEnabled bool

	// tracer is the OpenTelemetry tracer for creating spans
	tracer trace.Tracer

	// missionID is the unique identifier for this mission (used as trace ID)
	missionID string
}

// NewExternalExporter creates a new exporter based on the provided options.
// It initializes Langfuse and/or OpenTelemetry exporters based on configuration.
//
// Parameters:
//   - opts: Evaluation options controlling export behavior
//   - tracer: OpenTelemetry tracer for creating spans (can be nil if OTel is disabled)
//   - missionID: Unique identifier for the mission (used as Langfuse trace ID)
//
// Returns:
//   - *ExternalExporter: Configured exporter ready for use
//   - error: Non-nil if initialization fails
//
// Langfuse Configuration:
// The exporter checks environment variables for Langfuse credentials:
//   - LANGFUSE_PUBLIC_KEY: Required public API key
//   - LANGFUSE_SECRET_KEY: Required secret API key
//   - LANGFUSE_HOST: Optional host URL (defaults to https://cloud.langfuse.com)
//
// If ExportLangfuse is true but credentials are missing, an error is returned.
func NewExternalExporter(opts *EvalOptions, tracer trace.Tracer, missionID string) (*ExternalExporter, error) {
	if opts == nil {
		return nil, fmt.Errorf("evaluation options cannot be nil")
	}

	exporter := &ExternalExporter{
		otelEnabled: opts.ExportOTel,
		tracer:      tracer,
		missionID:   missionID,
	}

	// Initialize Langfuse exporter if enabled
	if opts.ExportLangfuse {
		publicKey := os.Getenv("LANGFUSE_PUBLIC_KEY")
		secretKey := os.Getenv("LANGFUSE_SECRET_KEY")
		host := os.Getenv("LANGFUSE_HOST")

		// Validate required credentials
		if publicKey == "" || secretKey == "" {
			return nil, fmt.Errorf("langfuse export enabled but missing credentials: LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY must be set")
		}

		// Default to Langfuse cloud if no host specified
		if host == "" {
			host = "https://cloud.langfuse.com"
		}

		// Create Langfuse exporter from SDK
		exporter.langfuseExporter = eval.NewLangfuseExporter(eval.LangfuseOptions{
			BaseURL:   host,
			PublicKey: publicKey,
			SecretKey: secretKey,
		})

		// Enable real-time export for partial scores
		// Use a minimum confidence of 0.5 to avoid exporting low-quality partial scores
		exporter.langfuseExporter.EnableRealTimeExport(eval.RealTimeExportOptions{
			ExportPartialScores: true,
			MinConfidence:       0.5,
		})
	}

	// Validate OpenTelemetry configuration
	if opts.ExportOTel && tracer == nil {
		return nil, fmt.Errorf("otel export enabled but tracer is nil")
	}

	return exporter, nil
}

// ExportResults exports the final evaluation summary to configured destinations.
// This should be called once at the end of mission execution with the complete results.
//
// For Langfuse:
//   - Exports individual scorer scores
//   - Exports overall aggregated score
//   - Links all scores to the mission ID as trace ID
//
// For OpenTelemetry:
//   - Creates a span for the evaluation event
//   - Adds span attributes for scores, alerts, and metrics
//   - Links to the parent mission span if available
//
// Parameters:
//   - ctx: Context for the export operation (respects cancellation)
//   - summary: Complete evaluation summary with all scores and metrics
//
// Returns:
//   - error: Non-nil if export fails (errors are logged but don't fail the mission)
func (e *ExternalExporter) ExportResults(ctx context.Context, summary *EvalSummary) error {
	if summary == nil {
		return fmt.Errorf("summary cannot be nil")
	}

	// Export to Langfuse if enabled
	if e.langfuseExporter != nil {
		if err := e.exportToLangfuse(ctx, summary); err != nil {
			return fmt.Errorf("langfuse export failed: %w", err)
		}
	}

	// Export to OpenTelemetry if enabled
	if e.otelEnabled && e.tracer != nil {
		if err := e.exportToOTel(ctx, summary); err != nil {
			return fmt.Errorf("otel export failed: %w", err)
		}
	}

	return nil
}

// ExportPartialScore exports a real-time score update to configured destinations.
// This is called during execution to provide streaming feedback to observability platforms.
//
// For Langfuse:
//   - Exports the partial score with "_partial" suffix
//   - Only exported if confidence exceeds threshold (0.5)
//   - Non-blocking: queued for background processing
//
// For OpenTelemetry:
//   - Creates a span event for the partial score
//   - Adds attributes for agent, score, confidence, and status
//
// Parameters:
//   - ctx: Context for the export operation
//   - agentName: Name of the agent that generated this score
//   - score: Partial score with confidence and status
//
// Returns:
//   - error: Non-nil if export fails (non-fatal, logged but doesn't stop execution)
func (e *ExternalExporter) ExportPartialScore(ctx context.Context, agentName string, score eval.PartialScore) error {
	if agentName == "" {
		return fmt.Errorf("agent name cannot be empty")
	}

	// Export to Langfuse if enabled
	if e.langfuseExporter != nil {
		// Use mission ID as trace ID for grouping all scores
		if err := e.langfuseExporter.ExportPartialScore(ctx, e.missionID, agentName, score); err != nil {
			return fmt.Errorf("langfuse partial score export failed: %w", err)
		}
	}

	// Export to OpenTelemetry if enabled
	if e.otelEnabled && e.tracer != nil {
		if err := e.exportPartialScoreToOTel(ctx, agentName, score); err != nil {
			return fmt.Errorf("otel partial score export failed: %w", err)
		}
	}

	return nil
}

// Close flushes pending exports and shuts down the exporter.
// This should be called when evaluation is complete to ensure all data is exported.
//
// For Langfuse:
//   - Blocks until all pending exports are flushed (30 second timeout)
//   - Gracefully shuts down background workers
//
// Returns:
//   - error: Non-nil if shutdown fails or times out
func (e *ExternalExporter) Close() error {
	if e.langfuseExporter != nil {
		if err := e.langfuseExporter.Close(); err != nil {
			return fmt.Errorf("failed to close langfuse exporter: %w", err)
		}
	}
	return nil
}

// exportToLangfuse exports evaluation results to Langfuse.
// It converts the Gibson EvalSummary format to SDK eval.Result format.
func (e *ExternalExporter) exportToLangfuse(ctx context.Context, summary *EvalSummary) error {
	// Convert scorer scores to SDK ScoreResult format
	scores := make(map[string]eval.ScoreResult, len(summary.ScorerScores))
	for name, score := range summary.ScorerScores {
		scores[name] = eval.ScoreResult{
			Score: score,
			// No reason or metadata available in summary
		}
	}

	// Create SDK Result format for export
	result := eval.Result{
		SampleID:     string(summary.MissionID),
		Scores:       scores,
		OverallScore: summary.OverallScore,
		Duration:     summary.Duration,
		Timestamp:    summary.FeedbackHistory[len(summary.FeedbackHistory)-1].Timestamp,
	}

	// Export to Langfuse using mission ID as trace ID
	if err := e.langfuseExporter.ExportResult(ctx, e.missionID, result); err != nil {
		return fmt.Errorf("failed to export result to langfuse: %w", err)
	}

	return nil
}

// exportToOTel exports evaluation results as OpenTelemetry spans and events.
// It creates a span for the evaluation with detailed attributes.
func (e *ExternalExporter) exportToOTel(ctx context.Context, summary *EvalSummary) error {
	// Create a span for the evaluation event
	ctx, span := e.tracer.Start(ctx, "eval.results",
		trace.WithAttributes(
			attribute.String("mission.id", string(summary.MissionID)),
			attribute.Float64("eval.overall_score", summary.OverallScore),
			attribute.Int("eval.total_steps", summary.TotalSteps),
			attribute.Int("eval.total_alerts", summary.TotalAlerts),
			attribute.Int("eval.warning_count", summary.WarningCount),
			attribute.Int("eval.critical_count", summary.CriticalCount),
			attribute.Int("eval.tokens_used", summary.TokensUsed),
			attribute.String("eval.duration", summary.Duration.String()),
		),
	)
	defer span.End()

	// Add individual scorer scores as span attributes
	for name, score := range summary.ScorerScores {
		span.SetAttributes(attribute.Float64(fmt.Sprintf("eval.scorer.%s", name), score))
	}

	// Add alert information as span events
	for i, feedback := range summary.FeedbackHistory {
		for j, alert := range feedback.Alerts {
			span.AddEvent(fmt.Sprintf("eval.alert.%d.%d", i, j),
				trace.WithAttributes(
					attribute.String("alert.level", string(alert.Level)),
					attribute.String("alert.scorer", alert.Scorer),
					attribute.Float64("alert.score", alert.Score),
					attribute.Float64("alert.threshold", alert.Threshold),
					attribute.String("alert.message", alert.Message),
				),
			)
		}
	}

	// Set span status based on critical alerts
	if summary.HasCriticalAlerts() {
		span.SetStatus(codes.Error, fmt.Sprintf("%d critical alerts detected", summary.CriticalCount))
	} else if summary.HasWarnings() {
		// Warnings don't fail the span, just add a note
		span.AddEvent("eval.warnings",
			trace.WithAttributes(
				attribute.Int("warning_count", summary.WarningCount),
			),
		)
	}

	return nil
}

// exportPartialScoreToOTel exports a partial score as an OpenTelemetry span event.
func (e *ExternalExporter) exportPartialScoreToOTel(ctx context.Context, agentName string, score eval.PartialScore) error {
	// Get the current span from context
	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		// No active span, skip OTel export
		return nil
	}

	// Add partial score as a span event
	span.AddEvent("eval.partial_score",
		trace.WithAttributes(
			attribute.String("agent.name", agentName),
			attribute.Float64("score.value", score.Score),
			attribute.Float64("score.confidence", score.Confidence),
			attribute.String("score.status", string(score.Status)),
		),
	)

	return nil
}
