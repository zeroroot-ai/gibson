// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package observability

import (
	"log/slog"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
)

// ObservabilityErrorCode represents error codes specific to observability operations.
type ObservabilityErrorCode string

// Observability error codes following the Gibson error pattern.
const (
	// ErrExporterConnection indicates failure to connect to an observability exporter.
	ErrExporterConnection ObservabilityErrorCode = "OBSERVABILITY_EXPORTER_CONNECTION"

	// ErrAuthenticationFailed indicates authentication failure with an observability backend.
	ErrAuthenticationFailed ObservabilityErrorCode = "OBSERVABILITY_AUTHENTICATION_FAILED"

	// ErrSpanContextMissing indicates a required span context is missing from the request.
	ErrSpanContextMissing ObservabilityErrorCode = "OBSERVABILITY_SPAN_CONTEXT_MISSING"

	// ErrMetricsRegistration indicates failure to register a metric with the metrics backend.
	ErrMetricsRegistration ObservabilityErrorCode = "OBSERVABILITY_METRICS_REGISTRATION"

	// ErrBufferOverflow indicates the observability buffer has overflowed.
	ErrBufferOverflow ObservabilityErrorCode = "OBSERVABILITY_BUFFER_OVERFLOW"

	// ErrShutdownTimeout indicates a timeout occurred during graceful shutdown.
	ErrShutdownTimeout ObservabilityErrorCode = "OBSERVABILITY_SHUTDOWN_TIMEOUT"
)

// Helper constructors for common observability errors.

// ErrorStrategy defines how observability errors should be handled when they occur.
// This allows the system to continue operating even when observability infrastructure fails.
type ErrorStrategy int

const (
	// StrategyLog logs the error at warn level and continues execution (default).
	// This is the safest default strategy as it never silently fails.
	StrategyLog ErrorStrategy = iota

	// StrategyMetric emits a metric about the error and continues execution.
	// Useful for tracking observability failures in the metrics system itself.
	StrategyMetric

	// StrategyIgnore silently discards the error and continues execution.
	// Use with caution - only when you explicitly want to suppress observability failures.
	StrategyIgnore

	// StrategyFailFast returns the error immediately, failing the operation.
	// Use in critical contexts where observability failures must not be ignored.
	StrategyFailFast
)

// ErrorHandler provides centralized handling of observability failures.
// It allows the system to continue operating even when observability infrastructure fails,
// with configurable strategies for different failure modes.
//
// Thread-safety: All methods are safe for concurrent use.
//
// Example usage:
//
//	handler := NewErrorHandler(
//	    WithErrorStrategy(StrategyLog),
//	    WithErrorLogger(slog.Default()),
//	    WithErrorMetrics(metricsRecorder),
//	)
//
//	if err := handler.Handle(ctx, "event_emission", err); err != nil {
//	    // Only non-nil if strategy is StrategyFailFast
//	    return err
//	}
type ErrorHandler struct {
	strategy ErrorStrategy
	logger   *slog.Logger
	metrics  harness.MetricsRecorder
	mu       sync.RWMutex
}

// ErrorHandlerOption is a functional option for configuring ErrorHandler.
type ErrorHandlerOption func(*ErrorHandler)

// NewErrorHandler creates a new ErrorHandler with the given options.
// Defaults to StrategyLog with slog.Default() logger.
func NewErrorHandler(opts ...ErrorHandlerOption) *ErrorHandler {
	h := &ErrorHandler{
		strategy: StrategyLog,
		logger:   slog.Default(),
		metrics:  nil,
	}

	for _, opt := range opts {
		opt(h)
	}

	return h
}

// DefaultErrorHandler is the package-level default error handler.
// It uses StrategyLog to ensure no errors are silently ignored by default.
// Applications can replace this with a custom handler if needed.
var DefaultErrorHandler = NewErrorHandler()
