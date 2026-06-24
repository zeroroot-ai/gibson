package component

import (
	"context"
)

// LifecycleManager manages the lifecycle of external components.
// It handles starting, stopping, restarting, and status monitoring.
type LifecycleManager interface {
	// StartComponent starts a component and waits for it to become healthy.
	// Returns the assigned port and an error if startup fails or times out.
	StartComponent(ctx context.Context, comp *Component) (int, error)

	// StopComponent gracefully stops a running component.
	// Sends SIGTERM, waits for ShutdownTimeout, then sends SIGKILL if still running.
	StopComponent(ctx context.Context, comp *Component) error

	// RestartComponent stops and then starts a component.
	// Returns the new port assignment and an error if restart fails.
	RestartComponent(ctx context.Context, comp *Component) (int, error)

	// GetStatus returns the current status of a component.
	// Checks process status and updates component state accordingly.
	GetStatus(ctx context.Context, comp *Component) (ComponentStatus, error)
}
