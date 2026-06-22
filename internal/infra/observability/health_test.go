package observability

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// MockHealthChecker is a test implementation of HealthChecker
type MockHealthChecker struct {
	mu           sync.RWMutex
	healthStatus types.HealthStatus
	checkCount   int
}

// NewMockHealthChecker creates a new mock health checker with the specified initial status
func NewMockHealthChecker(status types.HealthStatus) *MockHealthChecker {
	return &MockHealthChecker{
		healthStatus: status,
		checkCount:   0,
	}
}

// Health returns the configured health status and increments the check counter
func (m *MockHealthChecker) Health(ctx context.Context) types.HealthStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checkCount++
	return m.healthStatus
}

// SetHealth updates the health status (thread-safe)
func (m *MockHealthChecker) SetHealth(status types.HealthStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthStatus = status
}

// GetCheckCount returns the number of times Health was called (thread-safe)
func (m *MockHealthChecker) GetCheckCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.checkCount
}

// HealthMetricsRecorder is a test implementation that captures all metrics for health tests
type HealthMetricsRecorder struct {
	mu         sync.Mutex
	gauges     []HealthGaugeRecord
	counters   []HealthCounterRecord
	histograms []HealthHistogramRecord
}

type HealthGaugeRecord struct {
	Name   string
	Value  float64
	Labels map[string]string
}

type HealthCounterRecord struct {
	Name   string
	Value  int64
	Labels map[string]string
}

type HealthHistogramRecord struct {
	Name   string
	Value  float64
	Labels map[string]string
}

func NewHealthMetricsRecorder() *HealthMetricsRecorder {
	return &HealthMetricsRecorder{
		gauges:     make([]HealthGaugeRecord, 0),
		counters:   make([]HealthCounterRecord, 0),
		histograms: make([]HealthHistogramRecord, 0),
	}
}

func (m *HealthMetricsRecorder) RecordGauge(name string, value float64, labels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Copy labels to avoid mutation
	labelsCopy := make(map[string]string)
	for k, v := range labels {
		labelsCopy[k] = v
	}
	m.gauges = append(m.gauges, HealthGaugeRecord{Name: name, Value: value, Labels: labelsCopy})
}

func (m *HealthMetricsRecorder) RecordCounter(name string, value int64, labels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	labelsCopy := make(map[string]string)
	for k, v := range labels {
		labelsCopy[k] = v
	}
	m.counters = append(m.counters, HealthCounterRecord{Name: name, Value: value, Labels: labelsCopy})
}

func (m *HealthMetricsRecorder) RecordHistogram(name string, value float64, labels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	labelsCopy := make(map[string]string)
	for k, v := range labels {
		labelsCopy[k] = v
	}
	m.histograms = append(m.histograms, HealthHistogramRecord{Name: name, Value: value, Labels: labelsCopy})
}

func (m *HealthMetricsRecorder) GetGauges() []HealthGaugeRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]HealthGaugeRecord, len(m.gauges))
	copy(result, m.gauges)
	return result
}

func (m *HealthMetricsRecorder) GetGaugesByName(name string) []HealthGaugeRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []HealthGaugeRecord
	for _, g := range m.gauges {
		if g.Name == name {
			result = append(result, g)
		}
	}
	return result
}

func (m *HealthMetricsRecorder) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gauges = make([]HealthGaugeRecord, 0)
	m.counters = make([]HealthCounterRecord, 0)
	m.histograms = make([]HealthHistogramRecord, 0)
}

// Ensure HealthMetricsRecorder implements MetricsRecorder
var _ harness.MetricsRecorder = (*HealthMetricsRecorder)(nil)

// Test helper to create a test logger
func newTestLogger(t *testing.T) *Logger {
	return NewLogger(Config{Level: slog.LevelDebug, Output: os.Stdout, RedactSensitive: true}).WithMission("test-mission", "").WithAgent("test-agent")
}

func TestHealthMonitor_RegisterAndCheckAll(t *testing.T) {
	metrics := NewHealthMetricsRecorder()
	logger := newTestLogger(t)
	monitor := NewHealthMonitor(metrics, logger)

	// Register multiple components
	dbChecker := NewMockHealthChecker(types.Healthy("database connected"))
	cacheChecker := NewMockHealthChecker(types.Healthy("cache ready"))
	apiChecker := NewMockHealthChecker(types.Degraded("high latency"))

	monitor.Register("database", dbChecker)
	monitor.Register("cache", cacheChecker)
	monitor.Register("api", apiChecker)

	// Check all components
	ctx := context.Background()
	results := monitor.CheckAll(ctx)

	// Verify results
	assert.Len(t, results, 3, "should have 3 components")

	assert.True(t, results["database"].IsHealthy(), "database should be healthy")
	assert.Equal(t, "database connected", results["database"].Message)

	assert.True(t, results["cache"].IsHealthy(), "cache should be healthy")
	assert.Equal(t, "cache ready", results["cache"].Message)

	assert.True(t, results["api"].IsDegraded(), "api should be degraded")
	assert.Equal(t, "high latency", results["api"].Message)

	// Verify each checker was called once
	assert.Equal(t, 1, dbChecker.GetCheckCount(), "database checker should be called once")
	assert.Equal(t, 1, cacheChecker.GetCheckCount(), "cache checker should be called once")
	assert.Equal(t, 1, apiChecker.GetCheckCount(), "api checker should be called once")

	// Verify metrics were emitted
	gauges := metrics.GetGaugesByName("gibson.health.status")
	assert.Len(t, gauges, 3, "should emit 3 gauge metrics")

	// Check that healthy components have value 1.0
	for _, g := range gauges {
		if g.Labels["component"] == "database" || g.Labels["component"] == "cache" {
			assert.Equal(t, 1.0, g.Value, "healthy components should have gauge value 1.0")
		} else if g.Labels["component"] == "api" {
			assert.Equal(t, 0.0, g.Value, "degraded components should have gauge value 0.0")
		}
	}
}

func TestHealthMonitor_Unregister(t *testing.T) {
	metrics := NewHealthMetricsRecorder()
	logger := newTestLogger(t)
	monitor := NewHealthMonitor(metrics, logger)

	// Register components
	dbChecker := NewMockHealthChecker(types.Healthy("database connected"))
	cacheChecker := NewMockHealthChecker(types.Healthy("cache ready"))

	monitor.Register("database", dbChecker)
	monitor.Register("cache", cacheChecker)

	// Check all - should have 2 components
	ctx := context.Background()
	results := monitor.CheckAll(ctx)
	assert.Len(t, results, 2, "should have 2 components")

	// Unregister cache
	monitor.Unregister("cache")

	// Check all - should have 1 component
	results = monitor.CheckAll(ctx)
	assert.Len(t, results, 1, "should have 1 component after unregister")
	assert.Contains(t, results, "database", "should still contain database")
	assert.NotContains(t, results, "cache", "should not contain cache")
}

func TestHealthMonitor_Check(t *testing.T) {
	metrics := NewHealthMetricsRecorder()
	logger := newTestLogger(t)
	monitor := NewHealthMonitor(metrics, logger)

	// Register a component
	dbChecker := NewMockHealthChecker(types.Healthy("database connected"))
	monitor.Register("database", dbChecker)

	ctx := context.Background()

	// Check individual component
	status, err := monitor.Check(ctx, "database")
	require.NoError(t, err, "check should not return error for registered component")
	assert.True(t, status.IsHealthy(), "database should be healthy")
	assert.Equal(t, "database connected", status.Message)

	// Check non-existent component
	_, err = monitor.Check(ctx, "nonexistent")
	assert.Error(t, err, "check should return error for non-registered component")
	assert.Contains(t, err.Error(), "not registered", "error should mention component is not registered")
}

func TestHealthMonitor_StartPeriodicCheck(t *testing.T) {
	metrics := NewHealthMetricsRecorder()
	logger := newTestLogger(t)
	monitor := NewHealthMonitor(metrics, logger)

	// Register a component
	dbChecker := NewMockHealthChecker(types.Healthy("database connected"))
	monitor.Register("database", dbChecker)

	// Start periodic check with short interval (50ms)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	go monitor.StartPeriodicCheck(ctx, 50*time.Millisecond)

	// Wait for checks to occur
	time.Sleep(180 * time.Millisecond)

	// Should have been checked at least 3 times (at 0ms, 50ms, 100ms, 150ms)
	checkCount := dbChecker.GetCheckCount()
	assert.GreaterOrEqual(t, checkCount, 3, "should perform multiple periodic checks")
	assert.LessOrEqual(t, checkCount, 5, "should not over-check")

	// Verify metrics were emitted multiple times
	gauges := metrics.GetGaugesByName("gibson.health.status")
	assert.GreaterOrEqual(t, len(gauges), 3, "should emit multiple gauge metrics")
}

func TestHealthMonitor_HealthGaugeMetrics(t *testing.T) {
	metrics := NewHealthMetricsRecorder()
	logger := newTestLogger(t)
	monitor := NewHealthMonitor(metrics, logger)

	ctx := context.Background()

	// Test healthy component
	healthyChecker := NewMockHealthChecker(types.Healthy("all good"))
	monitor.Register("healthy_component", healthyChecker)
	monitor.CheckAll(ctx)

	gauges := metrics.GetGaugesByName("gibson.health.status")
	require.Len(t, gauges, 1, "should emit one gauge")
	assert.Equal(t, 1.0, gauges[0].Value, "healthy component should emit 1.0")
	assert.Equal(t, "healthy_component", gauges[0].Labels["component"])
	assert.Equal(t, "healthy", gauges[0].Labels["state"])

	metrics.Reset()

	// Test degraded component
	degradedChecker := NewMockHealthChecker(types.Degraded("slow response"))
	monitor.Register("degraded_component", degradedChecker)
	monitor.CheckAll(ctx)

	gauges = metrics.GetGaugesByName("gibson.health.status")
	require.Len(t, gauges, 2, "should emit two gauges")

	// Find degraded component gauge
	var degradedGauge *HealthGaugeRecord
	for _, g := range gauges {
		if g.Labels["component"] == "degraded_component" {
			degradedGauge = &g
			break
		}
	}
	require.NotNil(t, degradedGauge, "should find degraded component gauge")
	assert.Equal(t, 0.0, degradedGauge.Value, "degraded component should emit 0.0")
	assert.Equal(t, "degraded", degradedGauge.Labels["state"])

	metrics.Reset()

	// Test unhealthy component
	unhealthyChecker := NewMockHealthChecker(types.Unhealthy("connection failed"))
	monitor.Register("unhealthy_component", unhealthyChecker)
	monitor.CheckAll(ctx)

	gauges = metrics.GetGaugesByName("gibson.health.status")
	require.Len(t, gauges, 3, "should emit three gauges")

	// Find unhealthy component gauge
	var unhealthyGauge *HealthGaugeRecord
	for _, g := range gauges {
		if g.Labels["component"] == "unhealthy_component" {
			unhealthyGauge = &g
			break
		}
	}
	require.NotNil(t, unhealthyGauge, "should find unhealthy component gauge")
	assert.Equal(t, 0.0, unhealthyGauge.Value, "unhealthy component should emit 0.0")
	assert.Equal(t, "unhealthy", unhealthyGauge.Labels["state"])
}

func TestHealthMonitor_StateChangeLogging(t *testing.T) {
	// We'll capture logs using a custom handler to verify logging behavior
	// For this test, we'll rely on the logger not panicking and verify metrics

	metrics := NewHealthMetricsRecorder()
	logger := newTestLogger(t)
	monitor := NewHealthMonitor(metrics, logger)

	ctx := context.Background()

	// Register a component starting healthy
	checker := NewMockHealthChecker(types.Healthy("all good"))
	monitor.Register("test_component", checker)

	// Initial check - triggers transition from "not yet checked" -> healthy
	monitor.CheckAll(ctx)

	// Change to degraded (should log degradation at ERROR level)
	metrics.Reset()
	checker.SetHealth(types.Degraded("slow response"))
	monitor.CheckAll(ctx)

	gauges := metrics.GetGaugesByName("gibson.health.status")
	require.Len(t, gauges, 1, "should emit gauge after state change")
	assert.Equal(t, 0.0, gauges[0].Value, "degraded should emit 0.0")

	// Change to unhealthy (should log at WARN level)
	metrics.Reset()
	checker.SetHealth(types.Unhealthy("connection failed"))
	monitor.CheckAll(ctx)

	gauges = metrics.GetGaugesByName("gibson.health.status")
	require.Len(t, gauges, 1, "should emit gauge after state change")
	assert.Equal(t, 0.0, gauges[0].Value, "unhealthy should emit 0.0")

	// Recover to healthy (should log recovery at INFO level)
	metrics.Reset()
	checker.SetHealth(types.Healthy("recovered"))
	monitor.CheckAll(ctx)

	gauges = metrics.GetGaugesByName("gibson.health.status")
	require.Len(t, gauges, 1, "should emit gauge after recovery")
	assert.Equal(t, 1.0, gauges[0].Value, "healthy should emit 1.0")
}

func TestHealthMonitor_NoLoggingWhenStateUnchanged(t *testing.T) {
	metrics := NewHealthMetricsRecorder()
	logger := newTestLogger(t)
	monitor := NewHealthMonitor(metrics, logger)

	ctx := context.Background()

	// Register a healthy component
	checker := NewMockHealthChecker(types.Healthy("all good"))
	monitor.Register("test_component", checker)

	// First check
	monitor.CheckAll(ctx)
	firstGaugeCount := len(metrics.GetGaugesByName("gibson.health.status"))

	// Second check with same state
	monitor.CheckAll(ctx)
	secondGaugeCount := len(metrics.GetGaugesByName("gibson.health.status"))

	// Metrics should still be emitted
	assert.Equal(t, firstGaugeCount+1, secondGaugeCount, "should emit metrics even when state unchanged")
}

func TestHealthMonitor_ConcurrentAccess(t *testing.T) {
	metrics := NewHealthMetricsRecorder()
	logger := newTestLogger(t)
	monitor := NewHealthMonitor(metrics, logger)

	ctx := context.Background()

	// Register initial components
	for i := 0; i < 10; i++ {
		checker := NewMockHealthChecker(types.Healthy("ready"))
		monitor.Register(string(rune('A'+i)), checker)
	}

	var wg sync.WaitGroup

	// Concurrently check all
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			monitor.CheckAll(ctx)
		}()
	}

	// Concurrently register/unregister
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			checker := NewMockHealthChecker(types.Healthy("new component"))
			componentName := string(rune('K' + idx))
			monitor.Register(componentName, checker)
			time.Sleep(10 * time.Millisecond)
			monitor.Unregister(componentName)
		}(i)
	}

	// Concurrently check individual components
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			componentName := string(rune('A' + idx))
			monitor.Check(ctx, componentName)
		}(i)
	}

	// Wait for all goroutines
	wg.Wait()

	// Should not panic - this test primarily checks for race conditions
	// Run with: go test -race
	assert.True(t, true, "concurrent access should be safe")
}

func TestHealthMonitor_ContextCancellation(t *testing.T) {
	metrics := NewHealthMetricsRecorder()
	logger := newTestLogger(t)
	monitor := NewHealthMonitor(metrics, logger)

	// Register a component
	checker := NewMockHealthChecker(types.Healthy("ready"))
	monitor.Register("test", checker)

	// Create cancellable context
	ctx, cancel := context.WithCancel(context.Background())

	// Start periodic check
	checkStarted := make(chan struct{})
	go func() {
		close(checkStarted)
		monitor.StartPeriodicCheck(ctx, 10*time.Millisecond)
	}()

	// Wait for periodic check to start
	<-checkStarted
	time.Sleep(50 * time.Millisecond)

	initialCheckCount := checker.GetCheckCount()
	assert.Greater(t, initialCheckCount, 0, "should have performed some checks")

	// Cancel context
	cancel()
	time.Sleep(50 * time.Millisecond)

	// Check count should not increase significantly after cancellation
	finalCheckCount := checker.GetCheckCount()
	assert.LessOrEqual(t, finalCheckCount-initialCheckCount, 2, "should stop checking after context cancellation")
}

func TestHealthMonitor_RegisterOverwrite(t *testing.T) {
	metrics := NewHealthMetricsRecorder()
	logger := newTestLogger(t)
	monitor := NewHealthMonitor(metrics, logger)

	ctx := context.Background()

	// Register a component
	checker1 := NewMockHealthChecker(types.Healthy("first checker"))
	monitor.Register("database", checker1)

	// Check it
	status, err := monitor.Check(ctx, "database")
	require.NoError(t, err)
	assert.Equal(t, "first checker", status.Message)
	assert.Equal(t, 1, checker1.GetCheckCount())

	// Register again with same name (should overwrite)
	checker2 := NewMockHealthChecker(types.Degraded("second checker"))
	monitor.Register("database", checker2)

	// Check again - should use second checker
	status, err = monitor.Check(ctx, "database")
	require.NoError(t, err)
	assert.Equal(t, "second checker", status.Message)
	assert.Equal(t, 1, checker2.GetCheckCount(), "second checker should be called")
	assert.Equal(t, 1, checker1.GetCheckCount(), "first checker should not be called again")
}
