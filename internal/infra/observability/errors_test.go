// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package observability

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
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

// TestErrorHandler_DefaultErrorHandler tests the package-level default.
func TestErrorHandler_DefaultErrorHandler(t *testing.T) {
	assert.NotNil(t, DefaultErrorHandler)
	assert.Equal(t, StrategyLog, DefaultErrorHandler.strategy)
}
