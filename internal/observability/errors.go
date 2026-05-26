package observability

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/harness"
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

// ObservabilityError represents a structured error for observability operations.
// It follows the GibsonError pattern with code, message, retryability, and optional cause.
type ObservabilityError struct {
	Code      ObservabilityErrorCode
	Message   string
	Retryable bool
	Cause     error
}

// Error implements the error interface, returning a formatted error message.
// Format: "[CODE] message" or "[CODE] message: cause" if cause exists.
func (e *ObservabilityError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap returns the underlying cause error for error unwrapping chains.
// This enables using errors.Is() and errors.As() with wrapped errors.
func (e *ObservabilityError) Unwrap() error {
	return e.Cause
}

// Is checks if the target error matches this error by error code.
// Returns true if target is an ObservabilityError with the same Code.
func (e *ObservabilityError) Is(target error) bool {
	var obsErr *ObservabilityError
	if errors.As(target, &obsErr) {
		return e.Code == obsErr.Code
	}
	return false
}

// NewObservabilityError creates a new non-retryable ObservabilityError.
func NewObservabilityError(code ObservabilityErrorCode, message string) *ObservabilityError {
	return &ObservabilityError{
		Code:      code,
		Message:   message,
		Retryable: false,
		Cause:     nil,
	}
}

// NewRetryableObservabilityError creates a new retryable ObservabilityError.
func NewRetryableObservabilityError(code ObservabilityErrorCode, message string) *ObservabilityError {
	return &ObservabilityError{
		Code:      code,
		Message:   message,
		Retryable: true,
		Cause:     nil,
	}
}

// WrapObservabilityError creates a new ObservabilityError that wraps an existing error.
func WrapObservabilityError(code ObservabilityErrorCode, message string, cause error) *ObservabilityError {
	return &ObservabilityError{
		Code:      code,
		Message:   message,
		Retryable: false,
		Cause:     cause,
	}
}

// Helper constructors for common observability errors.

// NewExporterConnectionError creates an error for exporter connection failures.
// This error is retryable as network issues are often transient.
func NewExporterConnectionError(endpoint string, cause error) *ObservabilityError {
	return &ObservabilityError{
		Code:      ErrExporterConnection,
		Message:   fmt.Sprintf("failed to connect to exporter at %s", endpoint),
		Retryable: true,
		Cause:     cause,
	}
}

// NewAuthenticationError creates an error for authentication failures.
// This error is not retryable as credentials need to be corrected.
func NewAuthenticationError(service string, cause error) *ObservabilityError {
	return &ObservabilityError{
		Code:      ErrAuthenticationFailed,
		Message:   fmt.Sprintf("authentication failed for %s", service),
		Retryable: false,
		Cause:     cause,
	}
}

// NewSpanContextMissingError creates an error for missing span context.
// This error is not retryable as it indicates a programming error.
func NewSpanContextMissingError() *ObservabilityError {
	return &ObservabilityError{
		Code:      ErrSpanContextMissing,
		Message:   "span context is missing from request",
		Retryable: false,
		Cause:     nil,
	}
}

// NewMetricsRegistrationError creates an error for metric registration failures.
// This error is not retryable as it indicates a configuration or naming issue.
func NewMetricsRegistrationError(metricName string, cause error) *ObservabilityError {
	return &ObservabilityError{
		Code:      ErrMetricsRegistration,
		Message:   fmt.Sprintf("failed to register metric '%s'", metricName),
		Retryable: false,
		Cause:     cause,
	}
}

// NewBufferOverflowError creates an error for buffer overflow conditions.
// This error is retryable as it may resolve after buffer drains.
func NewBufferOverflowError(bufferType string) *ObservabilityError {
	return &ObservabilityError{
		Code:      ErrBufferOverflow,
		Message:   fmt.Sprintf("%s buffer overflow: too many events", bufferType),
		Retryable: true,
		Cause:     nil,
	}
}

// NewShutdownTimeoutError creates an error for shutdown timeout conditions.
// This error is not retryable as shutdown is a one-time operation.
func NewShutdownTimeoutError(component string) *ObservabilityError {
	return &ObservabilityError{
		Code:      ErrShutdownTimeout,
		Message:   fmt.Sprintf("%s shutdown timed out", component),
		Retryable: false,
		Cause:     nil,
	}
}

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

// WithErrorStrategy sets the error handling strategy.
func WithErrorStrategy(s ErrorStrategy) ErrorHandlerOption {
	return func(h *ErrorHandler) {
		h.strategy = s
	}
}

// WithErrorLogger sets the fallback logger for StrategyLog.
func WithErrorLogger(l *slog.Logger) ErrorHandlerOption {
	return func(h *ErrorHandler) {
		h.logger = l
	}
}

// WithErrorMetrics sets the metrics recorder for StrategyMetric.
func WithErrorMetrics(m harness.MetricsRecorder) ErrorHandlerOption {
	return func(h *ErrorHandler) {
		h.metrics = m
	}
}

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

// Handle processes an observability error according to the configured strategy.
//
// Parameters:
//   - ctx: Context for logging and metrics (may contain trace information)
//   - operation: Name of the operation that failed (e.g., "event_emission", "log_emission", "trace_recording")
//   - err: The error that occurred
//
// Returns:
//   - nil for StrategyLog, StrategyMetric, and StrategyIgnore
//   - the original error for StrategyFailFast
//
// Thread-safe: Safe to call from multiple goroutines.
func (h *ErrorHandler) Handle(ctx context.Context, operation string, err error) error {
	if err == nil {
		return nil
	}

	h.mu.RLock()
	strategy := h.strategy
	logger := h.logger
	metrics := h.metrics
	h.mu.RUnlock()

	switch strategy {
	case StrategyLog:
		if logger != nil {
			logger.WarnContext(ctx, "observability operation failed",
				"operation", operation,
				"error", err.Error(),
			)
		}
		return nil

	case StrategyMetric:
		if metrics != nil {
			metrics.RecordCounter("observability_error", 1, map[string]string{
				"operation": operation,
			})
		}
		return nil

	case StrategyIgnore:
		return nil

	case StrategyFailFast:
		return err

	default:
		// Fallback to log strategy for unknown strategies
		if logger != nil {
			logger.WarnContext(ctx, "observability operation failed (unknown strategy)",
				"operation", operation,
				"error", err.Error(),
				"strategy", strategy,
			)
		}
		return nil
	}
}

// DefaultErrorHandler is the package-level default error handler.
// It uses StrategyLog to ensure no errors are silently ignored by default.
// Applications can replace this with a custom handler if needed.
var DefaultErrorHandler = NewErrorHandler()

// HandleEventEmissionError is a convenience function for handling event emission failures.
// It uses the DefaultErrorHandler to process the error.
//
// Example:
//
//	if err := bus.Emit(ctx, event); err != nil {
//	    _ = HandleEventEmissionError(ctx, err)
//	}
func HandleEventEmissionError(ctx context.Context, err error) error {
	return DefaultErrorHandler.Handle(ctx, "event_emission", err)
}

// HandleLogEmissionError is a convenience function for handling log emission failures.
// It uses the DefaultErrorHandler to process the error.
//
// Example:
//
//	if err := logger.Emit(ctx, record); err != nil {
//	    _ = HandleLogEmissionError(ctx, err)
//	}
func HandleLogEmissionError(ctx context.Context, err error) error {
	return DefaultErrorHandler.Handle(ctx, "log_emission", err)
}

// HandleTraceError is a convenience function for handling trace recording failures.
// It uses the DefaultErrorHandler to process the error.
//
// Example:
//
//	if err := tracer.RecordSpan(ctx, span); err != nil {
//	    _ = HandleTraceError(ctx, err)
//	}
func HandleTraceError(ctx context.Context, err error) error {
	return DefaultErrorHandler.Handle(ctx, "trace_recording", err)
}
