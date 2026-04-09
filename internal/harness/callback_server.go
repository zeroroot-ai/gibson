package harness

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/gibson/internal/graphrag/loader"
	harnesspb "github.com/zero-day-ai/sdk/api/gen/gibson/harness/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
)

// CallbackServer wraps the gRPC server and HarnessCallbackService.
// It provides a simple way to start and stop the callback server that
// standalone agents connect to for harness operations.
type CallbackServer struct {
	server  *grpc.Server
	service *HarnessCallbackService
	logger  *slog.Logger
	port    int
}

// NewCallbackServerWithRegistry creates a new callback server with the given
// logger and harness registry.
//
// The registry enables mission-based harness lookup for external agents,
// allowing the same agent to run concurrently in different missions without
// conflicts.
//
// Parameters:
//   - logger: Structured logger for server events
//   - port: The port to listen on for gRPC connections
//   - registry: The harness registry for mission-based lookups
//   - opts: Optional callback service configuration options (e.g., WithTracerProvider)
//
// Returns:
//   - *CallbackServer: A new server instance ready to be started
func NewCallbackServerWithRegistry(logger *slog.Logger, port int, registry *CallbackHarnessRegistry, opts ...CallbackServiceOption) *CallbackServer {
	if logger == nil {
		logger = slog.Default()
	}

	return &CallbackServer{
		service: NewHarnessCallbackServiceWithRegistry(logger, registry, opts...),
		logger:  logger.With("component", "callback_server"),
		port:    port,
	}
}

// Service returns the underlying HarnessCallbackService for registering harnesses.
func (s *CallbackServer) Service() *HarnessCallbackService {
	return s.service
}

// Start starts the gRPC server on the configured port.
// This is a blocking call that runs until Stop() is called or an error occurs.
func (s *CallbackServer) Start(ctx context.Context) error {
	// Create TCP listener
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", s.port, err)
	}

	// Create gRPC server with keepalive options
	serverOpts := []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    10 * time.Second,
			Timeout: 5 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             5 * time.Second,
			PermitWithoutStream: true,
		}),
	}
	s.server = grpc.NewServer(serverOpts...)

	// Register HarnessCallbackService
	harnesspb.RegisterHarnessCallbackServiceServer(s.server, s.service)

	// Register health service
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(s.server, healthServer)
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	// Register reflection service for debugging
	reflection.Register(s.server)

	s.logger.Info("callback server starting", "port", s.port)

	// Start serving in a goroutine
	errCh := make(chan error, 1)
	go func() {
		if err := s.server.Serve(listener); err != nil {
			errCh <- err
		}
	}()

	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		s.logger.Info("callback server shutting down")
		s.server.GracefulStop()
		return ctx.Err()
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	}
}

// Stop gracefully stops the gRPC server.
func (s *CallbackServer) Stop() {
	if s.server != nil {
		s.logger.Info("stopping callback server")
		s.server.GracefulStop()
	}
}


// UnregisterHarness removes a harness registration when a task completes.
func (s *CallbackServer) UnregisterHarness(taskID string) {
	s.service.UnregisterHarness(taskID)
}

// SetCredentialStore sets the credential store for secure credential retrieval.
// This must be called before starting the server.
func (s *CallbackServer) SetCredentialStore(store CredentialStore) {
	s.service.credentialStore = store
}

// SetGraphLoader sets the GraphLoader for processing DiscoveryResult tool outputs.
// This must be called before starting the server.
func (s *CallbackServer) SetGraphLoader(gl *loader.GraphLoader) {
	s.service.graphLoader = gl
}

// SetDiscoveryProcessor sets the DiscoveryProcessor for automatic graph storage.
// This must be called before starting the server.
func (s *CallbackServer) SetDiscoveryProcessor(processor DiscoveryProcessor) {
	s.service.discoveryProcessor = processor
}

// SetQueueManager sets the QueueManager for Redis-based work queue operations.
// This must be called before starting the server.
func (s *CallbackServer) SetQueueManager(queueMgr *QueueManager) {
	s.service.queueManager = queueMgr
}

// SetAuthzStore sets the RunAuthzLookup for per-run authz state retrieval.
// Required for the Authorize RPC handler. When not set, Authorize returns
// codes.Unimplemented (SDK degrades to allow — rolling upgrade path).
func (s *CallbackServer) SetAuthzStore(store RunAuthzLookup) {
	s.service.authzStore = store
}

// SetComponentAuthorizer sets the FGA Authorizer for component authz decisions.
// When not set, all active-mission Authorize requests return allowed=true (dev mode).
func (s *CallbackServer) SetComponentAuthorizer(a authz.Authorizer) {
	s.service.componentAuthorizer = a
}

// SetComponentAuthzMetrics wires a metrics recorder into the Authorize handler.
// When not set, no authz counters are emitted (no-op). Call after server creation.
func (s *CallbackServer) SetComponentAuthzMetrics(m ComponentAuthzMetrics) {
	s.service.componentAuthzMetrics = m
}

// SetMissionManager wires a MissionOperator into the callback service, enabling
// agents to create, run, wait for, list, cancel, and retrieve results of
// sub-missions via the harness callback. Must be called before Start().
func (s *CallbackServer) SetMissionManager(op MissionOperator) {
	s.service.missionManager = op
}
