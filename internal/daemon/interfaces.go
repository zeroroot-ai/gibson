package daemon

import (
	"context"
	"time"
)

// Shutdownable represents a component that can be gracefully shut down.
// Components implementing this interface can participate in the coordinated
// shutdown sequence managed by the ShutdownCoordinator.
type Shutdownable interface {
	// Shutdown performs cleanup and graceful termination of the component.
	// The context may have a deadline to enforce shutdown timeouts.
	// Returns an error if shutdown fails.
	Shutdown(ctx context.Context) error
}

// ShutdownPhase represents a single phase in the shutdown sequence.
// Each phase is executed in order by the ShutdownCoordinator.
type ShutdownPhase interface {
	// Name returns a human-readable name for this shutdown phase.
	Name() string

	// Timeout returns the maximum duration allowed for this phase.
	// If the phase exceeds this timeout, the coordinator will log a warning
	// and proceed to the next phase.
	Timeout() time.Duration

	// Execute performs the shutdown logic for this phase.
	// The context will be cancelled if the phase timeout is exceeded.
	// Returns an error if the phase fails.
	Execute(ctx context.Context) error
}

// HealthStateManager manages the health state of the daemon during shutdown.
// This allows the health endpoint to signal to Kubernetes that the daemon
// is shutting down and should not receive new traffic.
type HealthStateManager interface {
	// SetHealthy marks the service as healthy and ready to receive traffic.
	SetHealthy()

	// SetShuttingDown marks the service as shutting down with a reason.
	// The health endpoint should return HTTP 503 when in this state.
	SetShuttingDown(reason string)

	// IsHealthy returns true if the service is healthy and not shutting down.
	IsHealthy() bool
}
