package daemon

import (
	"context"
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/observability"
)

// HealthPhase sets the health endpoint to unhealthy/shutting down state.
// This allows Kubernetes to stop routing traffic before connections are closed.
type HealthPhase struct {
	healthManager HealthStateManager
	logger        *observability.Logger
}

// NewHealthPhase creates a new HealthPhase.
func NewHealthPhase(healthManager HealthStateManager, logger *observability.Logger) *HealthPhase {
	return &HealthPhase{
		healthManager: healthManager,
		logger:        logger,
	}
}

// Name returns the phase name.
func (p *HealthPhase) Name() string {
	return "health_unhealthy"
}

// Timeout returns the phase timeout.
func (p *HealthPhase) Timeout() time.Duration {
	return 1 * time.Second
}

// Execute sets health to shutting down.
func (p *HealthPhase) Execute(ctx context.Context) error {
	p.healthManager.SetShuttingDown("graceful_shutdown")
	p.logger.Info(ctx, "health endpoint set to shutting down")
	return nil
}

// DrainPhase stops accepting new requests and waits for in-flight requests to complete.
type DrainPhase struct {
	grpcServer interface{ GracefulStop() }
	timeout    time.Duration
	logger     *observability.Logger
}

// NewDrainPhase creates a new DrainPhase.
func NewDrainPhase(grpcServer interface{ GracefulStop() }, timeout time.Duration, logger *observability.Logger) *DrainPhase {
	return &DrainPhase{
		grpcServer: grpcServer,
		timeout:    timeout,
		logger:     logger,
	}
}

// Name returns the phase name.
func (p *DrainPhase) Name() string {
	return "drain_requests"
}

// Timeout returns the phase timeout.
func (p *DrainPhase) Timeout() time.Duration {
	return p.timeout
}

// Execute stops accepting new gRPC connections and waits for in-flight requests.
func (p *DrainPhase) Execute(ctx context.Context) error {
	if p.grpcServer == nil {
		p.logger.Debug(ctx, "gRPC server not initialized, skipping drain")
		return nil
	}

	p.logger.Info(ctx, "draining in-flight requests")

	// GracefulStop waits for all RPCs to finish
	// We run it in a goroutine to respect the context timeout
	done := make(chan struct{})
	go func() {
		p.grpcServer.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		p.logger.Info(ctx, "all requests drained successfully")
		return nil
	case <-ctx.Done():
		p.logger.Warn(ctx, "drain timeout exceeded, forcing stop")
		return ctx.Err()
	}
}

// AgentPhase notifies connected agents of shutdown and waits for disconnection.
type AgentPhase struct {
	notifier AgentNotifier
	timeout  time.Duration
	logger   *observability.Logger
	metrics  *ShutdownMetrics
}

// NewAgentPhase creates a new AgentPhase.
func NewAgentPhase(notifier AgentNotifier, timeout time.Duration, logger *observability.Logger, metrics *ShutdownMetrics) *AgentPhase {
	return &AgentPhase{
		notifier: notifier,
		timeout:  timeout,
		logger:   logger,
		metrics:  metrics,
	}
}

// Name returns the phase name.
func (p *AgentPhase) Name() string {
	return "notify_agents"
}

// Timeout returns the phase timeout.
func (p *AgentPhase) Timeout() time.Duration {
	return p.timeout
}

// Execute notifies agents and waits for disconnection.
func (p *AgentPhase) Execute(ctx context.Context) error {
	if p.notifier == nil {
		p.logger.Debug(ctx, "no agent notifier configured, skipping agent notification")
		return nil
	}

	count, err := p.notifier.NotifyShutdown(ctx)
	if err != nil {
		p.logger.Warn(ctx, "failed to notify all agents", "error", err)
		return err
	}

	p.metrics.AgentsDisconnected = count
	p.logger.Info(ctx, "agents notified and disconnected", "count", count)
	return nil
}

// ConnectionPhase closes database and service connections.
type ConnectionPhase struct {
	infrastructure  *Infrastructure
	stateClient     interface{ Close() error }
	callback        interface{ Stop() }
	eventBus        interface{ Close() error }
	registry        interface{ Stop(context.Context) error }
	credentialStore interface{ Close() error }
	logger          *observability.Logger
}

// NewConnectionPhase creates a new ConnectionPhase.
func NewConnectionPhase(
	infrastructure *Infrastructure,
	stateClient interface{ Close() error },
	callback interface{ Stop() },
	eventBus interface{ Close() error },
	registry interface{ Stop(context.Context) error },
	credentialStore interface{ Close() error },
	logger *observability.Logger,
) *ConnectionPhase {
	return &ConnectionPhase{
		infrastructure:  infrastructure,
		stateClient:     stateClient,
		callback:        callback,
		eventBus:        eventBus,
		registry:        registry,
		credentialStore: credentialStore,
		logger:          logger,
	}
}

// Name returns the phase name.
func (p *ConnectionPhase) Name() string {
	return "close_connections"
}

// Timeout returns the phase timeout.
func (p *ConnectionPhase) Timeout() time.Duration {
	return 5 * time.Second
}

// Execute closes all database and service connections.
func (p *ConnectionPhase) Execute(ctx context.Context) error {
	var firstErr error

	// Stop callback server
	if p.callback != nil {
		p.logger.Info(ctx, "stopping callback server")
		p.callback.Stop()
	}

	// Close event bus
	if p.eventBus != nil {
		p.logger.Info(ctx, "closing event bus")
		if err := p.eventBus.Close(); err != nil {
			p.logger.Warn(ctx, "error closing event bus", "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	// Shutdown OTel observability stack
	if p.infrastructure != nil && p.infrastructure.otelStack != nil {
		p.logger.Info(ctx, "shutting down OTel observability stack")
		if err := p.infrastructure.otelStack.Close(ctx); err != nil {
			p.logger.Warn(ctx, "failed to shutdown OTel observability stack", "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	// No shared Neo4j client to close. Per-tenant sessions are managed by
	// the data-plane Pool which is closed in a separate shutdown phase.

	// Close Redis tool execution queue
	if p.infrastructure != nil && p.infrastructure.redisClient != nil {
		p.logger.Info(ctx, "closing Redis queue connection")
		if err := p.infrastructure.redisClient.Close(); err != nil {
			p.logger.Warn(ctx, "failed to close Redis queue connection", "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	// Close StateClient (Redis state stores)
	if p.stateClient != nil {
		p.logger.Info(ctx, "closing StateClient connection")
		if err := p.stateClient.Close(); err != nil {
			p.logger.Warn(ctx, "failed to close StateClient connection", "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	// Close credential store (and its KeyProvider)
	if p.credentialStore != nil {
		p.logger.Info(ctx, "closing credential store")
		if err := p.credentialStore.Close(); err != nil {
			p.logger.Warn(ctx, "failed to close credential store", "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	// Stop registry last
	if p.registry != nil {
		p.logger.Info(ctx, "stopping registry manager")
		if err := p.registry.Stop(ctx); err != nil {
			p.logger.Warn(ctx, "error stopping registry", "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	p.logger.Info(ctx, "all connections closed")
	return firstErr
}

// AgentNotifier is the interface for notifying agents of daemon shutdown.
// The actual implementation will be created in task 7.1.
type AgentNotifier interface {
	NotifyShutdown(ctx context.Context) (int, error)
}
