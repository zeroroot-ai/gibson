package observability

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/harness"
)

// TestObservabilityErrorCode_Constants verifies all error codes are defined correctly.
func TestObservabilityErrorCode_Constants(t *testing.T) {
	tests := []struct {
		name     string
		code     ObservabilityErrorCode
		expected string
	}{
		{"ErrExporterConnection", ErrExporterConnection, "OBSERVABILITY_EXPORTER_CONNECTION"},
		{"ErrAuthenticationFailed", ErrAuthenticationFailed, "OBSERVABILITY_AUTHENTICATION_FAILED"},
		{"ErrSpanContextMissing", ErrSpanContextMissing, "OBSERVABILITY_SPAN_CONTEXT_MISSING"},
		{"ErrMetricsRegistration", ErrMetricsRegistration, "OBSERVABILITY_METRICS_REGISTRATION"},
		{"ErrBufferOverflow", ErrBufferOverflow, "OBSERVABILITY_BUFFER_OVERFLOW"},
		{"ErrShutdownTimeout", ErrShutdownTimeout, "OBSERVABILITY_SHUTDOWN_TIMEOUT"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.code))
		})
	}
}

// TestObservabilityError_Error tests error message formatting.
func TestObservabilityError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ObservabilityError
		contains []string
	}{
		{
			name: "simple error without cause",
			err:  NewObservabilityError(ErrExporterConnection, "failed to connect"),
			contains: []string{
				"[OBSERVABILITY_EXPORTER_CONNECTION]",
				"failed to connect",
			},
		},
		{
			name: "error with cause",
			err: WrapObservabilityError(
				ErrAuthenticationFailed,
				"authentication failed",
				errors.New("invalid credentials"),
			),
			contains: []string{
				"[OBSERVABILITY_AUTHENTICATION_FAILED]",
				"authentication failed",
				"invalid credentials",
			},
		},
		{
			name: "retryable error",
			err:  NewRetryableObservabilityError(ErrBufferOverflow, "buffer full"),
			contains: []string{
				"[OBSERVABILITY_BUFFER_OVERFLOW]",
				"buffer full",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errMsg := tt.err.Error()
			for _, substring := range tt.contains {
				assert.Contains(t, errMsg, substring)
			}
		})
	}
}

// TestObservabilityError_Unwrap tests error unwrapping.
func TestObservabilityError_Unwrap(t *testing.T) {
	tests := []struct {
		name      string
		err       *ObservabilityError
		wantCause bool
	}{
		{
			name:      "error without cause",
			err:       NewObservabilityError(ErrSpanContextMissing, "span missing"),
			wantCause: false,
		},
		{
			name: "error with cause",
			err: WrapObservabilityError(
				ErrMetricsRegistration,
				"registration failed",
				errors.New("duplicate metric"),
			),
			wantCause: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cause := tt.err.Unwrap()
			if tt.wantCause {
				assert.NotNil(t, cause)
			} else {
				assert.Nil(t, cause)
			}
		})
	}
}

// TestObservabilityError_Is tests error comparison by code.
func TestObservabilityError_Is(t *testing.T) {
	baseErr := NewObservabilityError(ErrExporterConnection, "connection failed")
	sameCodeErr := NewObservabilityError(ErrExporterConnection, "different message")
	differentCodeErr := NewObservabilityError(ErrAuthenticationFailed, "auth failed")
	standardErr := errors.New("standard error")

	tests := []struct {
		name   string
		err    *ObservabilityError
		target error
		want   bool
	}{
		{
			name:   "same error code matches",
			err:    baseErr,
			target: sameCodeErr,
			want:   true,
		},
		{
			name:   "different error code does not match",
			err:    baseErr,
			target: differentCodeErr,
			want:   false,
		},
		{
			name:   "standard error does not match",
			err:    baseErr,
			target: standardErr,
			want:   false,
		},
		{
			name: "wrapped error with same code matches",
			err: WrapObservabilityError(
				ErrExporterConnection,
				"wrapped",
				standardErr,
			),
			target: baseErr,
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Is(tt.target)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestNewObservabilityError tests basic error creation.
func TestNewObservabilityError(t *testing.T) {
	err := NewObservabilityError(ErrSpanContextMissing, "context missing")

	assert.Equal(t, ErrSpanContextMissing, err.Code)
	assert.Equal(t, "context missing", err.Message)
	assert.False(t, err.Retryable)
	assert.Nil(t, err.Cause)
}

// TestNewRetryableObservabilityError tests retryable error creation.
func TestNewRetryableObservabilityError(t *testing.T) {
	err := NewRetryableObservabilityError(ErrBufferOverflow, "buffer overflow")

	assert.Equal(t, ErrBufferOverflow, err.Code)
	assert.Equal(t, "buffer overflow", err.Message)
	assert.True(t, err.Retryable)
	assert.Nil(t, err.Cause)
}

// TestWrapObservabilityError tests error wrapping.
func TestWrapObservabilityError(t *testing.T) {
	cause := errors.New("underlying error")
	err := WrapObservabilityError(ErrMetricsRegistration, "registration failed", cause)

	assert.Equal(t, ErrMetricsRegistration, err.Code)
	assert.Equal(t, "registration failed", err.Message)
	assert.False(t, err.Retryable)
	assert.Equal(t, cause, err.Cause)
}

// TestNewExporterConnectionError tests exporter connection error helper.
func TestNewExporterConnectionError(t *testing.T) {
	cause := errors.New("connection refused")
	err := NewExporterConnectionError("http://localhost:4318", cause)

	assert.Equal(t, ErrExporterConnection, err.Code)
	assert.Contains(t, err.Message, "http://localhost:4318")
	assert.True(t, err.Retryable)
	assert.Equal(t, cause, err.Cause)
}

// TestNewAuthenticationError tests authentication error helper.
func TestNewAuthenticationError(t *testing.T) {
	cause := errors.New("invalid api key")
	err := NewAuthenticationError("langfuse", cause)

	assert.Equal(t, ErrAuthenticationFailed, err.Code)
	assert.Contains(t, err.Message, "langfuse")
	assert.False(t, err.Retryable)
	assert.Equal(t, cause, err.Cause)
}

// TestNewSpanContextMissingError tests span context missing error helper.
func TestNewSpanContextMissingError(t *testing.T) {
	err := NewSpanContextMissingError()

	assert.Equal(t, ErrSpanContextMissing, err.Code)
	assert.Contains(t, err.Message, "span context")
	assert.False(t, err.Retryable)
	assert.Nil(t, err.Cause)
}

// TestNewMetricsRegistrationError tests metrics registration error helper.
func TestNewMetricsRegistrationError(t *testing.T) {
	cause := errors.New("duplicate registration")
	err := NewMetricsRegistrationError("request_count", cause)

	assert.Equal(t, ErrMetricsRegistration, err.Code)
	assert.Contains(t, err.Message, "request_count")
	assert.False(t, err.Retryable)
	assert.Equal(t, cause, err.Cause)
}

// TestNewBufferOverflowError tests buffer overflow error helper.
func TestNewBufferOverflowError(t *testing.T) {
	err := NewBufferOverflowError("trace")

	assert.Equal(t, ErrBufferOverflow, err.Code)
	assert.Contains(t, err.Message, "trace")
	assert.True(t, err.Retryable)
	assert.Nil(t, err.Cause)
}

// TestNewShutdownTimeoutError tests shutdown timeout error helper.
func TestNewShutdownTimeoutError(t *testing.T) {
	err := NewShutdownTimeoutError("tracer")

	assert.Equal(t, ErrShutdownTimeout, err.Code)
	assert.Contains(t, err.Message, "tracer")
	assert.False(t, err.Retryable)
	assert.Nil(t, err.Cause)
}

// TestObservabilityError_ErrorsIsCompatibility tests errors.Is() compatibility.
func TestObservabilityError_ErrorsIsCompatibility(t *testing.T) {
	originalErr := errors.New("original error")
	wrappedErr := WrapObservabilityError(
		ErrExporterConnection,
		"connection failed",
		originalErr,
	)

	// Should be able to unwrap to original error
	assert.True(t, errors.Is(wrappedErr, originalErr))

	// Should match by error code
	sameCodeErr := NewObservabilityError(ErrExporterConnection, "different message")
	assert.True(t, errors.Is(wrappedErr, sameCodeErr))

	// Should not match different code
	differentCodeErr := NewObservabilityError(ErrAuthenticationFailed, "auth failed")
	assert.False(t, errors.Is(wrappedErr, differentCodeErr))
}

// TestObservabilityError_ErrorsAsCompatibility tests errors.As() compatibility.
func TestObservabilityError_ErrorsAsCompatibility(t *testing.T) {
	err := WrapObservabilityError(
		ErrShutdownTimeout,
		"timeout occurred",
		errors.New("deadline exceeded"),
	)

	var obsErr *ObservabilityError
	require.True(t, errors.As(err, &obsErr))

	assert.Equal(t, ErrShutdownTimeout, obsErr.Code)
	assert.Equal(t, "timeout occurred", obsErr.Message)
}

// TestObservabilityError_RetryableFlag tests retryable flag behavior.
func TestObservabilityError_RetryableFlag(t *testing.T) {
	tests := []struct {
		name      string
		err       *ObservabilityError
		retryable bool
	}{
		{
			name:      "exporter connection is retryable",
			err:       NewExporterConnectionError("localhost:4318", errors.New("refused")),
			retryable: true,
		},
		{
			name:      "authentication is not retryable",
			err:       NewAuthenticationError("service", errors.New("invalid key")),
			retryable: false,
		},
		{
			name:      "buffer overflow is retryable",
			err:       NewBufferOverflowError("trace"),
			retryable: true,
		},
		{
			name:      "shutdown timeout is not retryable",
			err:       NewShutdownTimeoutError("component"),
			retryable: false,
		},
		{
			name:      "span context missing is not retryable",
			err:       NewSpanContextMissingError(),
			retryable: false,
		},
		{
			name:      "metrics registration is not retryable",
			err:       NewMetricsRegistrationError("metric", errors.New("duplicate")),
			retryable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.retryable, tt.err.Retryable)
		})
	}
}

// TestObservabilityError_MessageFormatting tests message formatting for all helpers.
func TestObservabilityError_MessageFormatting(t *testing.T) {
	tests := []struct {
		name     string
		err      *ObservabilityError
		contains string
	}{
		{
			name:     "exporter connection includes endpoint",
			err:      NewExporterConnectionError("http://jaeger:14268", nil),
			contains: "http://jaeger:14268",
		},
		{
			name:     "authentication includes service name",
			err:      NewAuthenticationError("prometheus", nil),
			contains: "prometheus",
		},
		{
			name:     "metrics registration includes metric name",
			err:      NewMetricsRegistrationError("http_requests_total", nil),
			contains: "http_requests_total",
		},
		{
			name:     "buffer overflow includes buffer type",
			err:      NewBufferOverflowError("metrics"),
			contains: "metrics",
		},
		{
			name:     "shutdown timeout includes component name",
			err:      NewShutdownTimeoutError("exporter"),
			contains: "exporter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Contains(t, tt.err.Error(), tt.contains)
		})
	}
}

// TestObservabilityError_ErrorChaining tests complex error chains.
func TestObservabilityError_ErrorChaining(t *testing.T) {
	// Create a chain of errors
	rootErr := errors.New("network unreachable")
	wrappedErr := WrapObservabilityError(
		ErrExporterConnection,
		"failed to connect to exporter",
		rootErr,
	)

	// Test unwrapping works correctly
	unwrapped := errors.Unwrap(wrappedErr)
	assert.Equal(t, rootErr, unwrapped)

	// Test errors.Is works through the chain
	assert.True(t, errors.Is(wrappedErr, rootErr))

	// Test error message contains both parts
	errMsg := wrappedErr.Error()
	assert.Contains(t, errMsg, "failed to connect to exporter")
	assert.Contains(t, errMsg, "network unreachable")
}

// TestObservabilityError_NilCause tests error behavior with nil cause.
func TestObservabilityError_NilCause(t *testing.T) {
	err := NewObservabilityError(ErrSpanContextMissing, "context missing")

	// Unwrap should return nil
	assert.Nil(t, err.Unwrap())

	// Error message should not contain colon separator
	errMsg := err.Error()
	assert.NotContains(t, errMsg, ": ")
	assert.Contains(t, errMsg, "[OBSERVABILITY_SPAN_CONTEXT_MISSING]")
	assert.Contains(t, errMsg, "context missing")
}

// TestObservabilityError_MultipleWrapping tests multiple levels of wrapping.
func TestObservabilityError_MultipleWrapping(t *testing.T) {
	// Create nested error chain
	level1 := errors.New("tcp connection refused")
	level2 := WrapObservabilityError(
		ErrExporterConnection,
		"failed to establish connection",
		level1,
	)

	// Verify both errors are in the chain
	assert.True(t, errors.Is(level2, level1))

	// Verify error message includes nested information
	errMsg := level2.Error()
	assert.Contains(t, errMsg, "failed to establish connection")
	assert.Contains(t, errMsg, "tcp connection refused")
}

// Benchmark error creation and formatting
func BenchmarkNewObservabilityError(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewObservabilityError(ErrExporterConnection, "connection failed")
	}
}

func BenchmarkWrapObservabilityError(b *testing.B) {
	cause := errors.New("underlying error")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = WrapObservabilityError(ErrMetricsRegistration, "registration failed", cause)
	}
}

func BenchmarkObservabilityError_Error(b *testing.B) {
	err := WrapObservabilityError(
		ErrAuthenticationFailed,
		"authentication failed",
		errors.New("invalid credentials"),
	)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = err.Error()
	}
}

func BenchmarkNewExporterConnectionError(b *testing.B) {
	cause := errors.New("connection refused")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewExporterConnectionError("http://localhost:4318", cause)
	}
}

// TestHelperConstructors_Consistency tests all helper constructors follow patterns.
func TestHelperConstructors_Consistency(t *testing.T) {
	tests := []struct {
		name      string
		createErr func() *ObservabilityError
		wantCode  ObservabilityErrorCode
	}{
		{
			name:      "exporter connection error",
			createErr: func() *ObservabilityError { return NewExporterConnectionError("endpoint", nil) },
			wantCode:  ErrExporterConnection,
		},
		{
			name:      "authentication error",
			createErr: func() *ObservabilityError { return NewAuthenticationError("service", nil) },
			wantCode:  ErrAuthenticationFailed,
		},
		{
			name:      "span context missing error",
			createErr: func() *ObservabilityError { return NewSpanContextMissingError() },
			wantCode:  ErrSpanContextMissing,
		},
		{
			name:      "metrics registration error",
			createErr: func() *ObservabilityError { return NewMetricsRegistrationError("metric", nil) },
			wantCode:  ErrMetricsRegistration,
		},
		{
			name:      "buffer overflow error",
			createErr: func() *ObservabilityError { return NewBufferOverflowError("type") },
			wantCode:  ErrBufferOverflow,
		},
		{
			name:      "shutdown timeout error",
			createErr: func() *ObservabilityError { return NewShutdownTimeoutError("component") },
			wantCode:  ErrShutdownTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.createErr()
			assert.Equal(t, tt.wantCode, err.Code)
			assert.NotEmpty(t, err.Message)
		})
	}
}

// TestErrorMessage_ContainsCode tests that all error messages include the error code.
func TestErrorMessage_ContainsCode(t *testing.T) {
	errors := []*ObservabilityError{
		NewExporterConnectionError("endpoint", nil),
		NewAuthenticationError("service", nil),
		NewSpanContextMissingError(),
		NewMetricsRegistrationError("metric", nil),
		NewBufferOverflowError("buffer"),
		NewShutdownTimeoutError("component"),
	}

	for _, err := range errors {
		t.Run(string(err.Code), func(t *testing.T) {
			errMsg := err.Error()
			assert.True(t, strings.HasPrefix(errMsg, "[OBSERVABILITY_"))
			assert.Contains(t, errMsg, string(err.Code))
		})
	}
}

// --- ErrorHandler Tests ---

// errorHandlerMockMetrics is a test double for harness.MetricsRecorder.
type errorHandlerMockMetrics struct {
	mu       sync.Mutex
	counters map[string]int64
	labels   map[string]map[string]string
}

func newErrorHandlerMockMetrics() *errorHandlerMockMetrics {
	return &errorHandlerMockMetrics{
		counters: make(map[string]int64),
		labels:   make(map[string]map[string]string),
	}
}

func (m *errorHandlerMockMetrics) RecordCounter(name string, value int64, labels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counters[name] += value
	m.labels[name] = labels
}

func (m *errorHandlerMockMetrics) RecordGauge(name string, value float64, labels map[string]string) {}

func (m *errorHandlerMockMetrics) RecordHistogram(name string, value float64, labels map[string]string) {
}

func (m *errorHandlerMockMetrics) getCounter(name string) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counters[name]
}

func (m *errorHandlerMockMetrics) getLabels(name string) map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.labels[name]
}

var _ harness.MetricsRecorder = (*errorHandlerMockMetrics)(nil)

// TestNewErrorHandler tests default ErrorHandler creation.
func TestNewErrorHandler(t *testing.T) {
	handler := NewErrorHandler()

	assert.NotNil(t, handler)
	assert.Equal(t, StrategyLog, handler.strategy)
	assert.NotNil(t, handler.logger)
}

// TestNewErrorHandler_WithOptions tests ErrorHandler creation with options.
func TestNewErrorHandler_WithOptions(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	metrics := newErrorHandlerMockMetrics()

	handler := NewErrorHandler(
		WithErrorStrategy(StrategyMetric),
		WithErrorLogger(logger),
		WithErrorMetrics(metrics),
	)

	assert.Equal(t, StrategyMetric, handler.strategy)
	assert.Equal(t, logger, handler.logger)
	assert.Equal(t, metrics, handler.metrics)
}

// TestErrorHandler_Handle_StrategyLog tests StrategyLog behavior.
func TestErrorHandler_Handle_StrategyLog(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	handler := NewErrorHandler(
		WithErrorStrategy(StrategyLog),
		WithErrorLogger(logger),
	)

	testErr := errors.New("test error")
	result := handler.Handle(context.Background(), "event_emission", testErr)

	// Should return nil (continue execution)
	assert.Nil(t, result)

	// Should have logged the error
	logOutput := buf.String()
	assert.Contains(t, logOutput, "observability operation failed")
	assert.Contains(t, logOutput, "event_emission")
	assert.Contains(t, logOutput, "test error")
}

// TestErrorHandler_Handle_StrategyMetric tests StrategyMetric behavior.
func TestErrorHandler_Handle_StrategyMetric(t *testing.T) {
	metrics := newErrorHandlerMockMetrics()

	handler := NewErrorHandler(
		WithErrorStrategy(StrategyMetric),
		WithErrorMetrics(metrics),
	)

	testErr := errors.New("test error")
	result := handler.Handle(context.Background(), "log_emission", testErr)

	// Should return nil (continue execution)
	assert.Nil(t, result)

	// Should have recorded a metric
	assert.Equal(t, int64(1), metrics.getCounter("observability_error"))
	labels := metrics.getLabels("observability_error")
	assert.Equal(t, "log_emission", labels["operation"])
}

// TestErrorHandler_Handle_StrategyIgnore tests StrategyIgnore behavior.
func TestErrorHandler_Handle_StrategyIgnore(t *testing.T) {
	handler := NewErrorHandler(WithErrorStrategy(StrategyIgnore))

	testErr := errors.New("test error")
	result := handler.Handle(context.Background(), "trace_recording", testErr)

	// Should return nil and do nothing
	assert.Nil(t, result)
}

// TestErrorHandler_Handle_StrategyFailFast tests StrategyFailFast behavior.
func TestErrorHandler_Handle_StrategyFailFast(t *testing.T) {
	handler := NewErrorHandler(WithErrorStrategy(StrategyFailFast))

	testErr := errors.New("test error")
	result := handler.Handle(context.Background(), "event_emission", testErr)

	// Should return the original error
	assert.Equal(t, testErr, result)
}

// TestErrorHandler_Handle_NilError tests handling of nil errors.
func TestErrorHandler_Handle_NilError(t *testing.T) {
	handler := NewErrorHandler(WithErrorStrategy(StrategyFailFast))

	result := handler.Handle(context.Background(), "operation", nil)

	// Should return nil for nil input
	assert.Nil(t, result)
}

// TestErrorHandler_Handle_Concurrent tests thread-safety.
func TestErrorHandler_Handle_Concurrent(t *testing.T) {
	metrics := newErrorHandlerMockMetrics()
	handler := NewErrorHandler(
		WithErrorStrategy(StrategyMetric),
		WithErrorMetrics(metrics),
	)

	const goroutines = 100
	const errorsPerGoroutine = 10

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < errorsPerGoroutine; j++ {
				testErr := errors.New("concurrent error")
				_ = handler.Handle(context.Background(), "test_op", testErr)
			}
		}()
	}

	wg.Wait()

	// Should have recorded all errors
	expected := int64(goroutines * errorsPerGoroutine)
	assert.Equal(t, expected, metrics.getCounter("observability_error"))
}

// TestErrorHandler_DefaultErrorHandler tests the package-level default.
func TestErrorHandler_DefaultErrorHandler(t *testing.T) {
	assert.NotNil(t, DefaultErrorHandler)
	assert.Equal(t, StrategyLog, DefaultErrorHandler.strategy)
}

// TestHandleEventEmissionError tests the convenience function.
func TestHandleEventEmissionError(t *testing.T) {
	testErr := errors.New("event emission failed")
	result := HandleEventEmissionError(context.Background(), testErr)

	// Should use default handler (StrategyLog) and return nil
	assert.Nil(t, result)
}

// TestHandleLogEmissionError tests the convenience function.
func TestHandleLogEmissionError(t *testing.T) {
	testErr := errors.New("log emission failed")
	result := HandleLogEmissionError(context.Background(), testErr)

	// Should use default handler (StrategyLog) and return nil
	assert.Nil(t, result)
}

// TestHandleTraceError tests the convenience function.
func TestHandleTraceError(t *testing.T) {
	testErr := errors.New("trace recording failed")
	result := HandleTraceError(context.Background(), testErr)

	// Should use default handler (StrategyLog) and return nil
	assert.Nil(t, result)
}

// TestErrorHandler_Handle_StrategyMetric_NilMetrics tests metric strategy with nil recorder.
func TestErrorHandler_Handle_StrategyMetric_NilMetrics(t *testing.T) {
	handler := NewErrorHandler(
		WithErrorStrategy(StrategyMetric),
		WithErrorMetrics(nil),
	)

	testErr := errors.New("test error")
	result := handler.Handle(context.Background(), "operation", testErr)

	// Should handle nil metrics gracefully and return nil
	assert.Nil(t, result)
}

// TestErrorHandler_Handle_StrategyLog_NilLogger tests log strategy with nil logger.
func TestErrorHandler_Handle_StrategyLog_NilLogger(t *testing.T) {
	handler := NewErrorHandler(
		WithErrorStrategy(StrategyLog),
		WithErrorLogger(nil),
	)

	testErr := errors.New("test error")
	result := handler.Handle(context.Background(), "operation", testErr)

	// Should handle nil logger gracefully and return nil
	assert.Nil(t, result)
}

// TestErrorHandler_Handle_MultipleStrategies tests switching strategies.
func TestErrorHandler_Handle_MultipleStrategies(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	metrics := newErrorHandlerMockMetrics()

	tests := []struct {
		name     string
		strategy ErrorStrategy
		wantLog  bool
		wantErr  bool
	}{
		{
			name:     "log strategy logs",
			strategy: StrategyLog,
			wantLog:  true,
			wantErr:  false,
		},
		{
			name:     "metric strategy does not log",
			strategy: StrategyMetric,
			wantLog:  false,
			wantErr:  false,
		},
		{
			name:     "ignore strategy does nothing",
			strategy: StrategyIgnore,
			wantLog:  false,
			wantErr:  false,
		},
		{
			name:     "failfast strategy returns error",
			strategy: StrategyFailFast,
			wantLog:  false,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			handler := NewErrorHandler(
				WithErrorStrategy(tt.strategy),
				WithErrorLogger(logger),
				WithErrorMetrics(metrics),
			)

			testErr := errors.New("test error")
			result := handler.Handle(context.Background(), "operation", testErr)

			if tt.wantErr {
				assert.Equal(t, testErr, result)
			} else {
				assert.Nil(t, result)
			}

			if tt.wantLog {
				assert.Contains(t, buf.String(), "observability operation failed")
			} else {
				assert.Empty(t, buf.String())
			}
		})
	}
}

// TestErrorHandler_Handle_WithContext tests context propagation.
func TestErrorHandler_Handle_WithContext(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	handler := NewErrorHandler(
		WithErrorStrategy(StrategyLog),
		WithErrorLogger(logger),
	)

	ctx := context.Background()
	testErr := errors.New("test error")
	result := handler.Handle(ctx, "operation_with_context", testErr)

	assert.Nil(t, result)
	logOutput := buf.String()
	assert.Contains(t, logOutput, "operation_with_context")
}

// BenchmarkErrorHandler_Handle_StrategyLog benchmarks log strategy.
func BenchmarkErrorHandler_Handle_StrategyLog(b *testing.B) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	handler := NewErrorHandler(
		WithErrorStrategy(StrategyLog),
		WithErrorLogger(logger),
	)
	testErr := errors.New("benchmark error")
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = handler.Handle(ctx, "operation", testErr)
	}
}

// BenchmarkErrorHandler_Handle_StrategyMetric benchmarks metric strategy.
func BenchmarkErrorHandler_Handle_StrategyMetric(b *testing.B) {
	metrics := newErrorHandlerMockMetrics()
	handler := NewErrorHandler(
		WithErrorStrategy(StrategyMetric),
		WithErrorMetrics(metrics),
	)
	testErr := errors.New("benchmark error")
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = handler.Handle(ctx, "operation", testErr)
	}
}

// BenchmarkErrorHandler_Handle_StrategyIgnore benchmarks ignore strategy.
func BenchmarkErrorHandler_Handle_StrategyIgnore(b *testing.B) {
	handler := NewErrorHandler(WithErrorStrategy(StrategyIgnore))
	testErr := errors.New("benchmark error")
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = handler.Handle(ctx, "operation", testErr)
	}
}

// BenchmarkErrorHandler_Handle_StrategyFailFast benchmarks failfast strategy.
func BenchmarkErrorHandler_Handle_StrategyFailFast(b *testing.B) {
	handler := NewErrorHandler(WithErrorStrategy(StrategyFailFast))
	testErr := errors.New("benchmark error")
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = handler.Handle(ctx, "operation", testErr)
	}
}

// BenchmarkConvenienceFunctions benchmarks the package-level convenience functions.
func BenchmarkConvenienceFunctions(b *testing.B) {
	testErr := errors.New("benchmark error")
	ctx := context.Background()

	b.Run("HandleEventEmissionError", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = HandleEventEmissionError(ctx, testErr)
		}
	})

	b.Run("HandleLogEmissionError", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = HandleLogEmissionError(ctx, testErr)
		}
	})

	b.Run("HandleTraceError", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = HandleTraceError(ctx, testErr)
		}
	})
}
