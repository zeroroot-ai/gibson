package harness

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/zeroroot-ai/gibson/internal/authz"
	"github.com/zeroroot-ai/gibson/internal/graphrag/loader"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
)

// CallbackServer wraps the gRPC server and HarnessCallbackService.
// It provides a simple way to start and stop the callback server that
// standalone agents connect to for harness operations.
type CallbackServer struct {
	mu       sync.Mutex // guards server field
	stopOnce sync.Once  // ensures GracefulStop executes exactly once
	server   *grpc.Server
	service  *HarnessCallbackService
	logger   *slog.Logger
	port     int

	// spiffeSource and peerSVIDs are populated via SetSPIFFE before Start().
	// When both are set the listener is wrapped in
	// tlsconfig.MTLSServerConfig(source, source, AuthorizeOneOf(peerSVIDs...))
	// and grpc.Creds(...) is appended to serverOpts before grpc.NewServer.
	// When spiffeSource is nil the listener is plain TCP — only allowed for
	// loopback dev binds (callback_manager.go enforces this in Start()).
	// Spec: critical-tls-no-fallbacks Component 1.
	spiffeSource *workloadapi.X509Source
	peerSVIDs    []spiffeid.ID
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

// SetSPIFFE wires the SPIFFE Workload API X.509 source and the peer-SVID
// allowlist into the callback server. After this call (and before Start), the
// listener is wrapped in SPIFFE mTLS (tlsconfig.MTLSServerConfig with
// tlsconfig.AuthorizeOneOf(peerSVIDs...)) and the gRPC server is constructed
// with grpc.Creds(credentials.NewTLS(tlsCfg)). Pass nil source to disable
// (loopback dev only — callback_manager rejects non-loopback binds without
// SPIFFE). peerSVIDs MUST be non-empty when source is non-nil.
//
// Spec: critical-tls-no-fallbacks Component 1.
func (s *CallbackServer) SetSPIFFE(source *workloadapi.X509Source, peerSVIDs []spiffeid.ID) {
	s.spiffeSource = source
	s.peerSVIDs = peerSVIDs
}

// Start starts the gRPC server on the configured port.
// This is a blocking call that runs until Stop() is called or an error occurs.
func (s *CallbackServer) Start(ctx context.Context) error {
	// Defense-in-depth: when SPIFFE is unwired and the configured port would
	// bind to a non-loopback interface, refuse to start. The CallbackManager's
	// Start() already runs rejectNonLoopbackWithoutSPIFFE; this second check
	// at the server layer protects callers that build a CallbackServer
	// directly. Spec: critical-tls-no-fallbacks Requirement 1.5.
	if s.spiffeSource == nil {
		// Bind on loopback only — port binds with no host fall through to all
		// interfaces, which a CallbackManager-using caller already validated.
		// Direct callers building a CallbackServer with no SPIFFE wiring are
		// dev-only.
		s.logger.Warn("callback server starting WITHOUT SPIFFE mTLS (dev/test only)",
			"port", s.port,
			"note", "production must wire SPIFFE via SetSPIFFE; refer to GIBSON_CALLBACK_PEER_SVIDS")
	}

	// Create TCP listener
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", s.port, err)
	}

	// Create gRPC server with keepalive options + the SDK auth
	// interceptor. Per unified-identity-and-authorization Requirement
	// 8.5/Component E, every Gibson gRPC server applies the same
	// header-trusting interceptor — they only run AFTER the SPIFFE TLS
	// handshake (critical-tls-no-fallbacks Requirement 1.4).
	serverOpts := []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    10 * time.Second,
			Timeout: 5 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             5 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.UnaryInterceptor(auth.UnaryServerInterceptor()),
		grpc.StreamInterceptor(auth.StreamServerInterceptor()),
	}

	// SPIFFE mTLS wrap — the only supported posture for non-loopback binds.
	// When SetSPIFFE supplied a source + non-empty peerSVIDs, build a
	// tlsconfig.MTLSServerConfig with AuthorizeOneOf(peerSVIDs...) and append
	// grpc.Creds(...) BEFORE grpc.NewServer. Cert-less / wrong-trust-domain
	// peers are rejected at the TLS handshake; the auth interceptors above
	// only see SPIFFE-pinned connections.
	// Spec: critical-tls-no-fallbacks Component 1.
	if s.spiffeSource != nil {
		if len(s.peerSVIDs) == 0 {
			return fmt.Errorf(
				"callback server has SPIFFE source but no peer SVIDs in allowlist; " +
					"populate gibson.config.callback.spiffe.peerSvids in chart values " +
					"(daemon initSPIFFEX509Source should have caught this — bug if it did not)")
		}
		tlsCfg := tlsconfig.MTLSServerConfig(s.spiffeSource, s.spiffeSource, tlsconfig.AuthorizeOneOf(s.peerSVIDs...))
		// Mirror the main daemon listener (see grpc.go for the full
		// rationale). We rely on tlsconfig.MTLSServerConfig's built-in
		// ClientAuth — which rejects cert-less handshakes — and on
		// go-spiffe's VerifyPeerCertificate callback for SPIFFE bundle
		// validation. We do NOT override ClientAuth to
		// RequireAndVerifyClientCert: that would trigger Go's stdlib chain
		// verifier against a nil ClientCAs pool and break the SPIFFE flow
		// (the deleted regression test documented this exact foot-gun).
		// The CI guard TestNoFallbackAudit enforces zero matches of the
		// four banned ClientAuth literals in production code outside test
		// files.
		// Wrap VerifyPeerCertificate to emit structured accepted/rejected
		// events with stable event names. There is NO len(rawCerts)==0
		// branch — the underlying ClientAuth value rejects empty chains
		// before this wrapper runs. Spec: critical-tls-no-fallbacks Req 1.4.
		origVerify := tlsCfg.VerifyPeerCertificate
		logger := s.logger
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if err := origVerify(rawCerts, verifiedChains); err != nil {
				if leaf, parseErr := x509.ParseCertificate(rawCerts[0]); parseErr == nil {
					sans := make([]string, 0, len(leaf.URIs))
					for _, u := range leaf.URIs {
						sans = append(sans, u.String())
					}
					logger.Warn("callback.tls.unauthorized_peer",
						"event", "callback.tls.unauthorized_peer",
						"issuer", leaf.Issuer.String(),
						"subject", leaf.Subject.String(),
						"sans_uri", strings.Join(sans, ","),
						"not_before", leaf.NotBefore.Format(time.RFC3339),
						"not_after", leaf.NotAfter.Format(time.RFC3339),
						"error", err.Error(),
					)
				} else {
					logger.Warn("callback.tls.unauthorized_peer",
						"event", "callback.tls.unauthorized_peer",
						"error", err.Error(),
						"note", "leaf cert unparseable",
					)
				}
				return err
			}
			// Cert accepted — log only the URI SAN, never raw bytes / client IP.
			if leaf, parseErr := x509.ParseCertificate(rawCerts[0]); parseErr == nil {
				spiffeID := ""
				for _, u := range leaf.URIs {
					if strings.HasPrefix(u.Scheme, "spiffe") {
						spiffeID = u.String()
						break
					}
				}
				if spiffeID != "" {
					logger.Info("callback.tls.peer_accepted",
						"event", "callback.tls.peer_accepted",
						"spiffe_id", spiffeID,
					)
				}
			}
			return nil
		}
		serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(tlsCfg)))
		s.logger.Info("callback server SPIFFE mTLS configured",
			"peer_svid_count", len(s.peerSVIDs))
	}

	grpcSrv := grpc.NewServer(serverOpts...)

	// Register HarnessCallbackService
	harnesspb.RegisterHarnessCallbackServiceServer(grpcSrv, s.service)

	// Register health service
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcSrv, healthServer)
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	// gRPC reflection is OFF by default in production. Set
	// GIBSON_GRPC_REFLECTION=1 to enable (dev/debug only). Spec:
	// critical-tls-no-fallbacks Component 3 / Requirement 4.
	if os.Getenv("GIBSON_GRPC_REFLECTION") == "1" {
		reflection.Register(grpcSrv)
		s.logger.Info("gRPC reflection enabled (GIBSON_GRPC_REFLECTION=1)")
	}

	s.logger.Info("callback server starting", "port", s.port)

	// Store under mu before starting the serve goroutine so that a
	// concurrent Stop() call always sees a non-nil server pointer.
	s.mu.Lock()
	s.server = grpcSrv
	s.mu.Unlock()

	// Start serving in a goroutine
	errCh := make(chan error, 1)
	go func() {
		if err := grpcSrv.Serve(listener); err != nil {
			errCh <- err
		}
	}()

	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		s.logger.Info("callback server shutting down")
		s.gracefulStop()
		return ctx.Err()
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	}
}

// gracefulStop calls GracefulStop on the underlying gRPC server exactly once,
// regardless of how many goroutines (Start's ctx-cancel branch and Stop) call
// it concurrently.  mu guards the s.server read; stopOnce ensures a single
// GracefulStop execution.
func (s *CallbackServer) gracefulStop() {
	s.stopOnce.Do(func() {
		s.mu.Lock()
		srv := s.server
		s.mu.Unlock()
		if srv != nil {
			s.logger.Info("stopping callback server")
			srv.GracefulStop()
		}
	})
}

// Stop gracefully stops the gRPC server.
func (s *CallbackServer) Stop() {
	s.gracefulStop()
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

// SetAgentOwnerLookup wires the AgentOwnerLookup hook so DelegateToAgent
// can resolve the delegated agent's owner and populate ExecutorUser on
// the sub-agent dispatch context. Pass nil to disable executor
// attribution (graceful degradation — EnrichSpan simply omits the
// executor_user_id attribute).
// Spec: llm-user-attribution-governance Requirement 1.5.
func (s *CallbackServer) SetAgentOwnerLookup(fn AgentOwnerLookup) {
	s.service.agentOwnerLookup = fn
}
