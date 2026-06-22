package daemon

import (
	"context"
	"sync"

	sdktypes "github.com/zeroroot-ai/sdk/types"
)

// healthStateManager implements the HealthStateManager interface.
// It tracks the daemon's health state and integrates with the health server
// to signal when the daemon is shutting down.
type healthStateManager struct {
	mu             sync.RWMutex
	shuttingDown   bool
	shutdownReason string
}

// newHealthStateManager creates a new health state manager.
func newHealthStateManager() *healthStateManager {
	return &healthStateManager{
		shuttingDown:   false,
		shutdownReason: "",
	}
}

// SetHealthy marks the service as healthy and ready to receive traffic.
func (h *healthStateManager) SetHealthy() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.shuttingDown = false
	h.shutdownReason = ""
}

// SetShuttingDown marks the service as shutting down with a reason.
// The health endpoint should return HTTP 503 when in this state.
func (h *healthStateManager) SetShuttingDown(reason string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.shuttingDown = true
	h.shutdownReason = reason
}

// IsHealthy returns true if the service is healthy and not shutting down.
func (h *healthStateManager) IsHealthy() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return !h.shuttingDown
}

// CheckFunc returns a health check function compatible with the SDK health server.
// This function can be registered as a readiness check to signal Kubernetes
// when the daemon is shutting down.
func (h *healthStateManager) CheckFunc() func(ctx context.Context) sdktypes.HealthStatus {
	return func(ctx context.Context) sdktypes.HealthStatus {
		h.mu.RLock()
		shuttingDown := h.shuttingDown
		reason := h.shutdownReason
		h.mu.RUnlock()

		if shuttingDown {
			// Return degraded status with shutdown reason
			// This causes Kubernetes to remove the pod from service endpoints
			// but doesn't trigger a restart (unlike unhealthy)
			return sdktypes.NewDegradedStatus("shutting down: "+reason, nil)
		}

		return sdktypes.NewHealthyStatus("ready")
	}
}
