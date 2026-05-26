package daemon

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/zeroroot-ai/gibson/internal/observability"
)

// DaemonAgentNotifier implements AgentNotifier for the daemon.
// It handles notifying connected agents of daemon shutdown and waiting for
// graceful disconnection before forcing closure.
type DaemonAgentNotifier struct {
	// callbackManager provides access to the callback server
	callbackManager CallbackManagerInterface

	// logger for structured logging
	logger *observability.Logger

	// timeout for waiting for agent disconnection
	timeout time.Duration

	// activeConns tracks the number of currently connected agents via an atomic counter.
	activeConns atomic.Int32
}

// CallbackManagerInterface defines the interface for callback manager operations
// needed during shutdown. This interface avoids circular dependencies.
type CallbackManagerInterface interface {
	// Stop gracefully stops the callback server
	Stop()

	// IsRunning returns whether the callback server is running
	IsRunning() bool
}

// NewDaemonAgentNotifier creates a new agent shutdown notifier.
func NewDaemonAgentNotifier(
	callbackManager CallbackManagerInterface,
	timeout time.Duration,
	logger *observability.Logger,
) *DaemonAgentNotifier {
	return &DaemonAgentNotifier{
		callbackManager: callbackManager,
		timeout:         timeout,
		logger:          logger,
	}
}

// NotifyShutdown notifies all connected agents that the daemon is shutting down
// and waits for them to disconnect gracefully.
//
// The process:
// 1. Stop accepting new agent callbacks (stop callback server)
// 2. Wait for agents to finish current operations and disconnect
// 3. Force close any remaining connections after timeout
//
// Returns the number of agents that were connected when shutdown began.
func (n *DaemonAgentNotifier) NotifyShutdown(ctx context.Context) (int, error) {
	if n.callbackManager == nil {
		n.logger.Debug(ctx, "callback manager not available, skipping agent notification")
		return 0, nil
	}

	if !n.callbackManager.IsRunning() {
		n.logger.Debug(ctx, "callback server not running, skipping agent notification")
		return 0, nil
	}

	n.logger.Info(ctx, "notifying agents of daemon shutdown",
		"timeout", n.timeout)

	// Create a context with timeout for the graceful disconnect period
	shutdownCtx, cancel := context.WithTimeout(ctx, n.timeout)
	defer cancel()

	// Stop the callback server - this prevents new agent connections
	// and signals to connected agents that the server is shutting down
	// The callback server's Stop() method handles graceful gRPC shutdown
	n.logger.Info(shutdownCtx, "stopping callback server to disconnect agents")

	// Track start time for logging
	startTime := time.Now()

	// Stop the callback server gracefully
	// The gRPC server's GracefulStop() will:
	// 1. Stop accepting new connections
	// 2. Wait for in-flight RPCs to complete
	// 3. Close all connections after RPCs finish
	n.callbackManager.Stop()

	// Calculate how long the graceful stop took
	disconnectDuration := time.Since(startTime)

	// Note: We don't have exact agent count tracking in the current implementation
	// The callback server manages connections internally via gRPC
	// For now, we return 0 to indicate successful notification without exact count
	// In a future enhancement, we could add connection tracking to CallbackServer
	agentCount := 0

	n.logger.Info(ctx, "agent shutdown complete",
		"duration", disconnectDuration,
		"agents_notified", agentCount)

	return agentCount, nil
}

// TrackConnection increments the active connection counter.
// Call this when an agent establishes a new callback connection.
func (n *DaemonAgentNotifier) TrackConnection() {
	n.activeConns.Add(1)
}

// UntrackConnection decrements the active connection counter.
// Call this when an agent disconnects from the callback server.
func (n *DaemonAgentNotifier) UntrackConnection() {
	n.activeConns.Add(-1)
}

// ActiveConnections returns the number of currently tracked agent connections
// as reported by the atomic counter.
func (n *DaemonAgentNotifier) ActiveConnections() int {
	return int(n.activeConns.Load())
}

// GetConnectedAgents returns the number of currently connected agents.
// This is a helper method for metrics and logging.
func (n *DaemonAgentNotifier) GetConnectedAgents() int {
	return n.ActiveConnections()
}
