package observability

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zero-day-ai/gibson/internal/harness"
	"github.com/zero-day-ai/gibson/internal/types"
)

// HealthChecker defines the interface that components must implement to be monitored.
// Components provide their current health status when queried.
type HealthChecker interface {
	// Health returns the current health status of the component.
	// The context can be used for timeout control and cancellation.
	Health(ctx context.Context) types.HealthStatus
}

// componentState tracks the current and previous health status of a component
// to detect state transitions (healthy -> degraded, degraded -> healthy, etc.)
type componentState struct {
	checker       HealthChecker
	lastStatus    types.HealthStatus
	lastCheckedAt time.Time
}

// HealthMonitor coordinates health checking across multiple system components.
// It tracks component health, emits metrics, logs state changes, and supports
// both on-demand and periodic health checks.
//
// The monitor is safe for concurrent use and supports dynamic component registration.
type HealthMonitor struct {
	metrics    harness.MetricsRecorder
	logger     *Logger
	components map[string]*componentState
	mu         sync.RWMutex
}

// NewHealthMonitor creates a new health monitor with the specified dependencies.
//
// Parameters:
//   - metrics: Recorder for emitting health status metrics
//   - logger: Logger for recording health state changes
//
// Returns:
//   - *HealthMonitor: A configured health monitor ready for use
func NewHealthMonitor(metrics harness.MetricsRecorder, logger *Logger) *HealthMonitor {
	return &HealthMonitor{
		metrics:    metrics,
		logger:     logger,
		components: make(map[string]*componentState),
	}
}

// Register adds a component to the health monitoring system.
// The component will be included in all future health checks.
//
// If a component with the same name already exists, it will be replaced.
//
// Parameters:
//   - name: Unique identifier for the component (e.g., "database", "cache", "llm_provider")
//   - checker: The health checker implementation for the component
//
// Thread-safety: Safe for concurrent use.
func (h *HealthMonitor) Register(name string, checker HealthChecker) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.components[name] = &componentState{
		checker: checker,
		// Initialize with unhealthy status to detect first transition to healthy
		lastStatus:    types.NewHealthStatus(types.HealthStateUnhealthy, "not yet checked"),
		lastCheckedAt: time.Time{}, // Zero time indicates never checked
	}
}

// Unregister removes a component from health monitoring.
// After removal, the component will no longer be included in health checks.
//
// Parameters:
//   - name: The name of the component to remove
//
// Thread-safety: Safe for concurrent use.
func (h *HealthMonitor) Unregister(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	delete(h.components, name)
}

// Check performs a health check on a specific component.
//
// Parameters:
//   - ctx: Context for timeout control and cancellation
//   - name: The name of the component to check
//
// Returns:
//   - types.HealthStatus: The current health status of the component
//   - error: An error if the component is not registered
//
// Thread-safety: Safe for concurrent use.
func (h *HealthMonitor) Check(ctx context.Context, name string) (types.HealthStatus, error) {
	h.mu.RLock()
	state, exists := h.components[name]
	h.mu.RUnlock()

	if !exists {
		return types.HealthStatus{}, fmt.Errorf("component %q is not registered", name)
	}

	// Perform the health check
	status := state.checker.Health(ctx)

	// Update state and emit metrics/logs
	h.updateComponentState(ctx, name, state, status)

	return status, nil
}

// CheckAll performs health checks on all registered components.
//
// Parameters:
//   - ctx: Context for timeout control and cancellation
//
// Returns:
//   - map[string]types.HealthStatus: Map of component names to their health status
//
// Thread-safety: Safe for concurrent use.
func (h *HealthMonitor) CheckAll(ctx context.Context) map[string]types.HealthStatus {
	h.mu.RLock()
	// Create a snapshot of components to avoid holding the lock during checks
	snapshot := make(map[string]*componentState, len(h.components))
	for name, state := range h.components {
		snapshot[name] = state
	}
	h.mu.RUnlock()

	// Perform health checks without holding the lock
	results := make(map[string]types.HealthStatus, len(snapshot))
	for name, state := range snapshot {
		status := state.checker.Health(ctx)
		results[name] = status

		// Update state and emit metrics/logs
		h.updateComponentState(ctx, name, state, status)
	}

	return results
}

// StartPeriodicCheck starts a background goroutine that periodically checks
// all components at the specified interval.
//
// The goroutine will run until the context is cancelled. Health checks are
// performed concurrently but state updates are synchronized.
//
// Parameters:
//   - ctx: Context for controlling the periodic check lifecycle
//   - interval: Time between health checks
//
// Usage:
//
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//	monitor.StartPeriodicCheck(ctx, 30*time.Second)
//
// Thread-safety: Safe for concurrent use. Multiple periodic checks can run simultaneously.
func (h *HealthMonitor) StartPeriodicCheck(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Perform health checks on all components
			h.CheckAll(ctx)
		}
	}
}

// updateComponentState updates the component's state and emits metrics/logs
// if the health state has changed.
//
// Parameters:
//   - ctx: Context for logging
//   - name: Component name
//   - state: Component state to update
//   - newStatus: New health status
//
// Thread-safety: This method is thread-safe and manages its own locking.
func (h *HealthMonitor) updateComponentState(ctx context.Context, name string, state *componentState, newStatus types.HealthStatus) {
	// Acquire lock to read previous state and update
	h.mu.Lock()
	previousState := state.lastStatus.State
	currentState := newStatus.State
	stateChanged := previousState != currentState

	// Update state while holding lock
	state.lastStatus = newStatus
	state.lastCheckedAt = time.Now()
	h.mu.Unlock()

	// Emit gauge metric: 1 for healthy, 0 for degraded/unhealthy
	var healthValue float64
	if newStatus.IsHealthy() {
		healthValue = 1.0
	} else {
		healthValue = 0.0
	}

	h.metrics.RecordGauge("gibson.health.status", healthValue, map[string]string{
		"component": name,
		"state":     string(currentState),
	})

	// Log state changes
	if stateChanged {
		h.logStateChange(ctx, name, previousState, currentState, newStatus.Message)
	}
}

// logStateChange logs health state transitions with appropriate severity.
//
// Degradation events (healthy -> degraded/unhealthy) are logged at ERROR level.
// Recovery events (degraded/unhealthy -> healthy) are logged at INFO level.
// Other transitions are logged at WARN level.
//
// Parameters:
//   - ctx: Context for logging
//   - component: Component name
//   - previousState: Previous health state
//   - currentState: Current health state
//   - message: Health status message
func (h *HealthMonitor) logStateChange(ctx context.Context, component string, previousState, currentState types.HealthState, message string) {
	logArgs := []any{
		"component", component,
		"previous_state", string(previousState),
		"current_state", string(currentState),
		"message", message,
	}

	// Detect degradation (healthy -> degraded or unhealthy)
	if previousState == types.HealthStateHealthy && currentState != types.HealthStateHealthy {
		h.logger.Error(ctx, "Component health degraded", logArgs...)
		return
	}

	// Detect recovery (degraded or unhealthy -> healthy)
	if previousState != types.HealthStateHealthy && currentState == types.HealthStateHealthy {
		h.logger.Info(ctx, "Component health recovered", logArgs...)
		return
	}

	// Other transitions (e.g., degraded -> unhealthy)
	h.logger.Warn(ctx, "Component health state changed", logArgs...)
}
