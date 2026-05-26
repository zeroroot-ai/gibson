package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/config"
	"github.com/zeroroot-ai/gibson/internal/observability"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// ShutdownCoordinator orchestrates the graceful shutdown of the daemon.
// It executes shutdown phases in order, respecting timeouts and logging progress.
type ShutdownCoordinator struct {
	// config contains shutdown timeout configuration
	config config.ShutdownConfig

	// logger for structured shutdown logging
	logger *observability.Logger

	// phases is the ordered list of shutdown phases to execute
	phases []ShutdownPhase

	// metrics tracks shutdown progress and statistics
	metrics *ShutdownMetrics

	// tracer for distributed tracing (optional)
	tracer trace.Tracer
}

// NewShutdownCoordinator creates a new ShutdownCoordinator.
func NewShutdownCoordinator(cfg config.ShutdownConfig, logger *observability.Logger) *ShutdownCoordinator {
	return &ShutdownCoordinator{
		config:  cfg,
		logger:  logger,
		phases:  make([]ShutdownPhase, 0),
		metrics: NewShutdownMetrics(),
		tracer:  nil, // Will be set if tracing is available
	}
}

// SetTracer sets the tracer for distributed tracing of shutdown operations.
func (sc *ShutdownCoordinator) SetTracer(tracer trace.Tracer) {
	sc.tracer = tracer
}

// RegisterPhase adds a shutdown phase to the execution sequence.
// Phases are executed in the order they are registered.
func (sc *ShutdownCoordinator) RegisterPhase(phase ShutdownPhase) {
	sc.phases = append(sc.phases, phase)
}

// Shutdown executes all registered shutdown phases in order.
// Returns an error if the total shutdown timeout is exceeded or if a critical phase fails.
func (sc *ShutdownCoordinator) Shutdown(ctx context.Context) error {
	// Create trace span for shutdown if tracer is available
	var span trace.Span
	if sc.tracer != nil {
		ctx, span = sc.tracer.Start(ctx, "daemon.shutdown",
			trace.WithAttributes(
				attribute.Int("phases.count", len(sc.phases)),
				attribute.String("shutdown.timeout", sc.config.Timeout.String()),
			))
		defer span.End()
	}

	sc.logger.Info(ctx, "graceful shutdown initiated",
		"total_timeout", sc.config.Timeout,
		"phases", len(sc.phases))

	// Create a context with the total shutdown timeout
	shutdownCtx, cancel := context.WithTimeout(ctx, sc.config.Timeout)
	defer cancel()

	// Execute each phase in order
	for _, phase := range sc.phases {
		phaseName := phase.Name()
		phaseTimeout := phase.Timeout()

		sc.logger.Info(shutdownCtx, "starting shutdown phase",
			"phase", phaseName,
			"timeout", phaseTimeout)

		phaseStart := time.Now()

		// Create a context for this specific phase with its timeout
		phaseCtx, phaseCancel := context.WithTimeout(shutdownCtx, phaseTimeout)

		// Execute the phase
		err := phase.Execute(phaseCtx)
		phaseCancel() // Clean up phase context

		phaseDuration := time.Since(phaseStart)
		sc.metrics.RecordPhase(phaseName, phaseDuration)

		// Add phase span event if tracing is enabled
		if span != nil {
			span.AddEvent(fmt.Sprintf("phase.%s.completed", phaseName),
				trace.WithAttributes(
					attribute.String("phase.name", phaseName),
					attribute.String("phase.duration", phaseDuration.String()),
					attribute.Bool("phase.error", err != nil),
				))
		}

		if err != nil {
			sc.logger.Warn(shutdownCtx, "shutdown phase failed",
				"phase", phaseName,
				"duration", phaseDuration,
				"error", err)
			sc.metrics.AddError(fmt.Errorf("%s: %w", phaseName, err))

			// Check if the total shutdown context was cancelled
			if shutdownCtx.Err() != nil {
				sc.logger.Error(shutdownCtx, "shutdown timeout exceeded during phase",
					"phase", phaseName,
					"total_timeout", sc.config.Timeout)
				sc.metrics.ForcedExit = true

				if span != nil {
					span.SetStatus(codes.Error, "shutdown timeout exceeded")
					span.RecordError(shutdownCtx.Err())
				}

				return fmt.Errorf("shutdown timeout exceeded during %s: %w", phaseName, shutdownCtx.Err())
			}

			// Continue to next phase despite error
			continue
		}

		sc.logger.Info(shutdownCtx, "shutdown phase completed",
			"phase", phaseName,
			"duration", phaseDuration)
	}

	totalDuration := sc.metrics.TotalDuration()
	errorCount := sc.metrics.ErrorCount()

	// Emit shutdown metrics and trace attributes
	if span != nil {
		span.SetAttributes(
			attribute.String("shutdown.total_duration", totalDuration.String()),
			attribute.Int("shutdown.phases_completed", len(sc.phases)),
			attribute.Int("shutdown.errors", errorCount),
			attribute.Int("shutdown.missions_checkpointed", sc.metrics.MissionsCheckpointed),
			attribute.Int("shutdown.agents_disconnected", sc.metrics.AgentsDisconnected),
			attribute.Int("shutdown.requests_drained", sc.metrics.RequestsDrained),
			attribute.Bool("shutdown.forced_exit", sc.metrics.ForcedExit),
		)

		// Add phase durations as attributes
		sc.metrics.mu.Lock()
		for phaseName, duration := range sc.metrics.PhasesDuration {
			span.SetAttributes(
				attribute.String(fmt.Sprintf("phase.%s.duration", phaseName), duration.String()),
			)
		}
		sc.metrics.mu.Unlock()

		if errorCount > 0 {
			span.SetStatus(codes.Error, fmt.Sprintf("%d errors during shutdown", errorCount))
		} else {
			span.SetStatus(codes.Ok, "shutdown completed successfully")
		}
	}

	// Log final metrics as JSON for structured logging and monitoring
	sc.emitMetrics(ctx)

	sc.logger.Info(ctx, "graceful shutdown completed",
		"total_duration", totalDuration,
		"phases_completed", len(sc.phases),
		"errors", errorCount,
		"missions_checkpointed", sc.metrics.MissionsCheckpointed,
		"agents_disconnected", sc.metrics.AgentsDisconnected,
		"requests_drained", sc.metrics.RequestsDrained)

	return nil
}

// emitMetrics logs the final shutdown metrics as JSON for monitoring and observability.
func (sc *ShutdownCoordinator) emitMetrics(ctx context.Context) {
	// Create a metrics snapshot for JSON serialization
	sc.metrics.mu.Lock()
	defer sc.metrics.mu.Unlock()

	metricsSnapshot := map[string]interface{}{
		"start_time":            sc.metrics.StartTime,
		"total_duration_ms":     sc.metrics.TotalDuration().Milliseconds(),
		"phases_duration":       sc.metrics.PhasesDuration,
		"missions_checkpointed": sc.metrics.MissionsCheckpointed,
		"agents_disconnected":   sc.metrics.AgentsDisconnected,
		"requests_drained":      sc.metrics.RequestsDrained,
		"error_count":           len(sc.metrics.Errors),
		"forced_exit":           sc.metrics.ForcedExit,
	}

	// Marshal to JSON
	metricsJSON, err := json.Marshal(metricsSnapshot)
	if err != nil {
		sc.logger.Warn(ctx, "failed to marshal shutdown metrics", "error", err)
		return
	}

	// Log metrics as structured JSON
	sc.logger.Info(ctx, "shutdown metrics",
		"metrics_json", string(metricsJSON))
}

// Metrics returns the shutdown metrics for observability.
func (sc *ShutdownCoordinator) Metrics() *ShutdownMetrics {
	return sc.metrics
}
