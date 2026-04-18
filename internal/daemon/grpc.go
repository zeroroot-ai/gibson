package daemon

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/zero-day-ai/gibson/internal/agentauth"
	discoverysvc "github.com/zero-day-ai/gibson/internal/api/discovery"
	"github.com/zero-day-ai/gibson/internal/audit"
	"github.com/zero-day-ai/gibson/internal/auth"
	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/daemon/api"
	"github.com/zero-day-ai/gibson/internal/finding"
	"github.com/zero-day-ai/gibson/internal/graphrag/intelligence"
	"github.com/zero-day-ai/gibson/internal/memory"
	componentpb "github.com/zero-day-ai/sdk/api/gen/gibson/component/v1"
	discoverypb "github.com/zero-day-ai/sdk/api/gen/gibson/daemon/discovery/v1"
	daemonpb "github.com/zero-day-ai/sdk/api/gen/gibson/daemon/v1"
	intelligencepb "github.com/zero-day-ai/sdk/api/gen/intelligence/v1"

	"github.com/zero-day-ai/gibson/internal/impersonation"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/missiondraft"
	"github.com/zero-day-ai/gibson/internal/onboarding"
	"github.com/zero-day-ai/gibson/internal/types"
	"go.opentelemetry.io/otel/metric"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// daemonMemoryStore wraps a single DefaultWorkingMemory so ComponentServiceServer
// can satisfy the memory.MemoryStore interface with a daemon-wide shared instance.
// Mission-tier and long-term-tier operations are handled by the per-mission
// MemoryResolver wired separately (compSvc.WithMemoryResolver); only Working() is
// used from this shared store.
type daemonMemoryStore struct {
	working memory.WorkingMemory
}

func (s *daemonMemoryStore) Working() memory.WorkingMemory   { return s.working }
func (s *daemonMemoryStore) Mission() memory.MissionMemory   { return nil }
func (s *daemonMemoryStore) LongTerm() memory.LongTermMemory { return nil }

// startGRPCServer creates and starts the gRPC server.
//
// This method creates a gRPC server, registers the daemon service,
// and starts listening on the configured address in a goroutine.
//
// If authentication is enabled in config, auth interceptors are installed
// to enforce authentication on all gRPC endpoints.
func (d *daemonImpl) startGRPCServer(ctx context.Context) error {
	// Create listener
	listener, err := net.Listen("tcp", d.grpcAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", d.grpcAddr, err)
	}

	// Build interceptor chains. Recovery is always first (outermost).
	var unaryInterceptors []grpc.UnaryServerInterceptor
	var streamInterceptors []grpc.StreamServerInterceptor

	// 1. Panic recovery (outermost — catches panics from all inner interceptors)
	var recoveryMeter metric.Meter
	if d.infrastructure != nil && d.infrastructure.otelStack != nil &&
		d.infrastructure.otelStack.MeterProvider != nil {
		recoveryMeter = d.infrastructure.otelStack.MeterProvider.Meter("gibson.grpc.recovery")
	}
	unaryRecovery, streamRecovery, err := panicRecoveryInterceptors(d.logger.Slog(), recoveryMeter)
	if err != nil {
		return fmt.Errorf("failed to create recovery interceptors: %w", err)
	}
	unaryInterceptors = append(unaryInterceptors, unaryRecovery)
	streamInterceptors = append(streamInterceptors, streamRecovery)

	// 2. Error scrubbing (strips internal paths, YAML parse details, Go types from responses)
	var scrubMeter metric.Meter
	if d.infrastructure != nil && d.infrastructure.otelStack != nil &&
		d.infrastructure.otelStack.MeterProvider != nil {
		scrubMeter = d.infrastructure.otelStack.MeterProvider.Meter("gibson.grpc.error_scrub")
	}
	unaryScrub, streamScrub, err := errorScrubInterceptors(d.logger.Slog(), scrubMeter)
	if err != nil {
		return fmt.Errorf("failed to create error scrub interceptors: %w", err)
	}
	unaryInterceptors = append(unaryInterceptors, unaryScrub)
	streamInterceptors = append(streamInterceptors, streamScrub)

	// 3. Auth interceptors (if enabled)
	if d.config.Auth.IsAuthEnabled() {
		d.logger.Info(ctx, "authentication enabled, installing auth interceptors",
			"mode", d.config.Auth.Mode,
		)

		apiKeyAuth, jwtVerifier, baValidator, buildErr := d.buildAuthValidators(ctx)
		if buildErr != nil {
			return fmt.Errorf("failed to build auth validators: %w", buildErr)
		}

		unaryInterceptors = append(unaryInterceptors, auth.UnaryAuthInterceptor(apiKeyAuth, jwtVerifier, baValidator, &d.config.Auth, d.logger.Slog()))
		streamInterceptors = append(streamInterceptors, auth.StreamAuthInterceptor(apiKeyAuth, jwtVerifier, baValidator, &d.config.Auth, d.logger.Slog()))

		d.logger.Info(ctx, "auth interceptors installed",
			"trust_localhost", d.config.Auth.TrustLocalhost,
		)
	} else {
		d.logger.Warn(ctx, "auth interceptors not installed - auth mode not configured")
	}

	// 4. User context forwarding — extracts x-gibson-user-id and x-gibson-tenant
	// from gRPC metadata for callers with the platform-service role (dashboard).
	// Must run after auth (identity available) and before FGA (tenant context needed).
	unaryInterceptors = append(unaryInterceptors, auth.UserContextInterceptor())
	streamInterceptors = append(streamInterceptors, auth.UserContextStreamInterceptor())

	// 5. Authorization interceptor — OpenFGA is the sole enforcement backend.
	//
	// Load FGA registry from the embedded YAML
	// (core/gibson/internal/auth/rpc_registry.yaml). Operators may override
	// via GIBSON_AUTHZ_RPC_REGISTRY_PATH (typically wired through the Helm
	// value gibson.authz.rpcRegistry.override). A missing or invalid override
	// fails boot loudly — there is NO silent fallback to the embedded default.
	fgaRegistry, err := auth.LoadRegistry(
		auth.EmbeddedRpcRegistry,
		os.Getenv("GIBSON_AUTHZ_RPC_REGISTRY_PATH"),
	)
	if err != nil {
		return fmt.Errorf("rpc registry load: %w", err)
	}
	if err := fgaRegistry.Validate(ctx, d.authorizer); err != nil {
		return fmt.Errorf("fga registry validation failed at startup: %w", err)
	}
	d.logger.Info(ctx, "fga rpc registry validated against authorization model")

	fgaInterceptor := auth.NewFgaAuthzInterceptor(
		d.authorizer,
		fgaRegistry,
		d.logger.Slog(),
		d.GetOTelMetricsRecorder(),
	)
	unaryInterceptors = append(unaryInterceptors, fgaInterceptor.Unary())
	streamInterceptors = append(streamInterceptors, fgaInterceptor.Stream())
	d.logger.Info(ctx, "fga authz interceptor installed (fga-only mode)")

	// Build server options with chained interceptors
	serverOpts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(unaryInterceptors...),
		grpc.ChainStreamInterceptor(streamInterceptors...),
	}

	// SPIFFE mTLS — initialize X509Source and configure TLS when SPIFFE is configured.
	// tls.VerifyClientCertIfGiven allows both mTLS clients (in-cluster SPIFFE workloads)
	// and standard TLS clients (Agent Auth, API key, Better Auth) to connect.
	if d.config.Auth.SPIFFE != nil && d.config.Auth.SPIFFE.WorkloadAPISocket != "" {
		socketAddr := "unix://" + d.config.Auth.SPIFFE.WorkloadAPISocket
		x509Source, sourceErr := workloadapi.NewX509Source(ctx,
			workloadapi.WithClientOptions(
				workloadapi.WithAddr(socketAddr),
			),
		)
		if sourceErr != nil {
			d.logger.Warn(ctx, "failed to initialize SPIFFE X509Source; running without mTLS",
				"socket", d.config.Auth.SPIFFE.WorkloadAPISocket,
				"error", sourceErr,
			)
		} else {
			tlsCfg := tlsconfig.MTLSServerConfig(x509Source, x509Source, tlsconfig.AuthorizeAny())
			tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
			serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(tlsCfg)))
			// Store source on daemon for graceful shutdown close.
			d.spiffeX509Source = x509Source
			d.logger.Info(ctx, "SPIFFE mTLS configured on gRPC server",
				"socket", d.config.Auth.SPIFFE.WorkloadAPISocket,
				"trust_domain", d.config.Auth.SPIFFE.TrustDomain,
			)
		}
	}

	// Create gRPC server with options
	srv := grpc.NewServer(serverOpts...)
	d.grpcServer = srv

	// Create and register daemon service.
	// Attach the quota manager so RunMission enforces per-tenant mission limits.
	daemonSvc := api.NewDaemonServer(d, d.credentialHandler, d.logger.Slog())
	if d.authorizer != nil {
		daemonSvc.WithAuthorizer(d.authorizer)
		d.logger.Info(ctx, "FGA authorizer wired into DaemonServer for admin RPCs")
	}
	if d.dashboardDB != nil {
		daemonSvc.WithDashboardDB(d.dashboardDB)
		d.logger.Info(ctx, "dashboard Postgres pool wired into DaemonServer for entitlements RPCs")
	}
	if d.quotaManager != nil {
		daemonSvc.WithQuotaManager(d.quotaManager)
		d.logger.Info(ctx, "quota manager wired into DaemonServer for mission quota enforcement")
	}
	// Wire daemon dependencies that require the Redis state client.
	// Tenant lifecycle (create/provision/deprovision) has moved out of the daemon
	// to the standalone gibson-tenant-operator; this block only wires the
	// remaining runtime services (AgentAuth, onboarding, mission drafts,
	// impersonation, and the API key store).
	if d.stateClient != nil {
		if redisClient, ok := d.stateClient.Client().(*goredis.Client); ok {
			_ = redisClient // retained for future wiring

			// Create APIKeyAuthenticator for the CreateAPIKey/ListAPIKeys/RevokeAPIKey RPCs.
			// API keys are stored in the dashboard Postgres instance.
			var apiKeyAuth *auth.APIKeyAuthenticator
			if d.dashboardDB != nil {
				var akErr error
				apiKeyAuth, akErr = auth.NewAPIKeyAuthenticator(d.dashboardDB)
				if akErr != nil {
					d.logger.Warn(ctx, "failed to create API key authenticator", "error", akErr)
				}
			} else {
				d.logger.Warn(ctx, "API key authenticator not wired: dashboard Postgres unavailable")
			}

			if apiKeyAuth != nil {
				daemonSvc.WithAPIKeyStore(apiKeyAuth)
				d.logger.Info(ctx, "API key store wired into DaemonServer (Postgres-backed)")
			}

			// Wire the AgentAuthService for the Agent Auth Protocol RPCs.
			// Requires dashboardDB (for store + apiKeys) and the FGA authorizer.
			if d.dashboardDB != nil && apiKeyAuth != nil && d.authorizer != nil {
				agentStore := agentauth.NewAgentAuthStore(d.dashboardDB)
				auditWriter := audit.NewWriter(d.dashboardDB, d.logger.Slog())
				auditWriter.Start(ctx)
				auditQuery := audit.NewQuery(d.dashboardDB)

				fgaBridge := agentauth.NewFGABridge(d.authorizer, d.compRegistry, d.logger.Slog())

				agentAuthDispatcher := newWorkQueueDispatcher(
					component.NewRedisWorkQueue(d.stateClient.Client()),
				)

				agentAuthSvc := agentauth.NewAgentAuthService(agentauth.AgentAuthServiceConfig{
					Store:       agentStore,
					FGABridge:   fgaBridge,
					Authorizer:  d.authorizer,
					APIKeys:     apiKeyAuth,
					AuditWriter: auditWriter,
					AuditQuery:  auditQuery,
					Dispatcher:  agentAuthDispatcher,
					Logger:      d.logger.Slog(),
				})
				daemonSvc.WithAgentAuthService(agentAuthSvc)
				d.logger.Info(ctx, "AgentAuthService wired into DaemonServer")
			} else {
				d.logger.Warn(ctx, "AgentAuthService not wired: requires dashboardDB, apiKeyAuth, and authorizer")
			}

			// Wire the onboarding store backed by Redis.
			onboardingStore := onboarding.New(redisClient, d.logger.Slog())
			daemonSvc.WithOnboardingStore(onboardingStore)
			d.logger.Info(ctx, "onboarding store wired into DaemonServer")

			// Wire the mission draft store backed by Redis.
			draftStore := missiondraft.New(redisClient, d.logger.Slog())
			daemonSvc.WithMissionDraftStore(draftStore)
			d.logger.Info(ctx, "mission draft store wired into DaemonServer")

			// Wire the impersonation token issuer.
			var impersonationKey []byte
			if envKey := os.Getenv("GIBSON_IMPERSONATION_KEY"); envKey != "" {
				impersonationKey = []byte(envKey)
			}
			issuer := impersonation.New(impersonationKey, 15*time.Minute, d.logger.Slog())
			daemonSvc.WithImpersonationIssuer(issuer)
			d.logger.Info(ctx, "impersonation issuer wired into DaemonServer")

		} else {
			d.logger.Warn(ctx, "daemon runtime services not wired: Redis client is not standalone mode")
		}
	} else {
		d.logger.Warn(ctx, "daemon runtime services not wired: stateClient is nil")
	}

	daemonpb.RegisterDaemonServiceServer(srv, daemonSvc)
	api.RegisterDaemonAdminServiceServer(srv, daemonSvc)

	// Register DiscoveryService — the read-only introspection surface
	// consumed by opensource/adk/cmd/gibson-mcp and the dashboard's
	// permissions-bridge migration. Wiring only depends on the authorizer
	// and component registry, so it comes up even when state/runtime
	// services are still bootstrapping.
	if d.authorizer != nil && d.compRegistry != nil {
		discoverySrv := discoverysvc.NewServer(d.authorizer, d.compRegistry, d.logger.Slog())
		discoverypb.RegisterDiscoveryServiceServer(srv, discoverySrv)
		d.logger.Info(ctx, "registered DiscoveryService gRPC endpoint")
	} else {
		d.logger.Warn(ctx, "DiscoveryService not registered: authorizer or compRegistry unavailable")
	}

	// Register IntelligenceService for cross-mission analytics RPCs
	// (GetRecurringVulnerabilities, GetRemediationMetrics, GetAssetRiskScore,
	// GetAttackPatterns, GetSimilarTargets). The SDK's
	// platformIntelligenceProxy is the canonical client; agents and operators
	// reach this endpoint indirectly via SDK PlatformHarness.
	// Per spec productionize-graph-intelligence Task 2, this fills the
	// long-missing daemon-side endpoint that the SDK proxy was always
	// degrading against (Unimplemented fallback).
	if d.infrastructure != nil && d.infrastructure.intelligenceService != nil {
		intelligencepb.RegisterIntelligenceServiceServer(srv, intelligence.NewGRPCServer(d.infrastructure.intelligenceService))
		d.logger.Info(ctx, "registered IntelligenceService gRPC endpoint")
	} else {
		d.logger.Warn(ctx, "IntelligenceService gRPC endpoint not registered: intelligence service unavailable (likely no neo4j driver)")
	}

	// Initialize and register the ComponentService on the same gRPC port.
	//
	// ComponentService is the ingress point for all Gibson components (agents,
	// tools, plugins). It handles registration, heartbeat, work dispatch, and
	// harness proxy RPCs. All three dependencies require the shared Redis client
	// from stateClient so that component data is co-located with mission state.
	//
	// The registry uses a 30-second TTL: components that stop heartbeating within
	// that window are automatically deregistered by Redis key expiry.
	//
	// Harness proxy dependencies (llmCompleter, memStore) are wired as nil until
	// task 5.4 connects those subsystems. findingSubmitter is wired here using
	// GraphRAGFindingSubmitter when infrastructure is available.
	if d.stateClient != nil {
		if redisClient, ok := d.stateClient.Client().(*goredis.Client); ok {
			compRegistry := component.NewRedisComponentRegistry(redisClient, 30*time.Second)
			compQueue := component.NewRedisWorkQueue(d.stateClient.Client())

			auditLogger := audit.NewAuditLogger(d.stateClient, d.logger.Slog())

			// Wire GraphRAGFindingSubmitter when infrastructure is available.
			// It routes findings to both Redis (tenant-scoped indexes) and Neo4j
			// (via GraphRAGBridge.StoreAsync, fire-and-forget). Falls back to nil
			// when the finding store or bridge has not been initialized, in which
			// case ComponentServiceServer logs and returns a generated finding_id.
			var findingSubmitter component.FindingSubmitter
			if d.infrastructure != nil &&
				d.infrastructure.findingStore != nil &&
				d.infrastructure.graphRAGBridge != nil {
				if redisStore, ok := d.infrastructure.findingStore.(*finding.RedisFindingStore); ok {
					findingSubmitter = component.NewGraphRAGFindingSubmitter(
						d.infrastructure.graphRAGBridge,
						redisStore,
						d.stateClient,
						d.logger.WithComponent("finding-submitter").Slog(),
					)
					d.logger.Info(ctx, "GraphRAGFindingSubmitter wired: findings routed to Redis and Neo4j")
				} else {
					d.logger.Warn(ctx, "finding store is not *finding.RedisFindingStore; finding submitter not wired")
				}
			} else {
				d.logger.Warn(ctx, "infrastructure not ready; finding submitter not wired (findings will be logged only)")
			}

			// Build LLM adapter when the infrastructure (registry + slot manager) is ready.
			// The adapter bridges the narrow LLMCompleter/LLMToolCompleter interfaces to
			// the full provider resolution chain.
			var llmAdapter *component.LLMRegistryAdapter
			if d.infrastructure != nil &&
				d.infrastructure.llmRegistry != nil &&
				d.infrastructure.slotManager != nil {
				llmAdapter = component.NewLLMRegistryAdapter(
					d.infrastructure.llmRegistry,
					d.infrastructure.slotManager,
					d.logger.WithComponent("llm-adapter").Slog(),
				)
				d.logger.Info(ctx, "LLM adapter wired into ComponentService")
			} else {
				d.logger.Warn(ctx, "LLM adapter not wired: infrastructure or LLM registry not ready; LLM completion RPCs will return Unimplemented")
			}

			// Build a daemon-wide shared memory store for the working memory tier.
			// Mission-tier and long-term-tier operations are handled by the per-mission
			// MemoryResolver (wired below); only Working() is served from this shared store.
			sharedMemStore := &daemonMemoryStore{
				working: memory.NewWorkingMemory(100_000),
			}

			var llmCompleterIface component.LLMCompleter
			var llmToolCompleterIface component.LLMToolCompleter
			if llmAdapter != nil {
				llmCompleterIface = llmAdapter
				llmToolCompleterIface = llmAdapter
			}

			compSvc := component.NewComponentServiceServer(
				compRegistry,
				compQueue,
				d.logger.Slog(),
				llmCompleterIface,   // LLMRegistryAdapter or nil
				sharedMemStore,      // daemon-wide shared working memory
				findingSubmitter,    // GraphRAGFindingSubmitter or nil
				d.pluginAccessStore, // nil when no KeyProvider configured
				auditLogger,
			)

			// Wire LLMToolCompleter for tool-calling and structured output support.
			if llmToolCompleterIface != nil {
				compSvc.WithLLMToolCompleter(llmToolCompleterIface)
				d.logger.Info(ctx, "LLMToolCompleter wired into ComponentService")
			}

			// Wire MemoryResolver so that MemoryGet/MemorySet/MemorySearch route
			// mission-tier operations to the per-agent mission namespace.
			// RedisMemoryResolver caches MissionMemory instances in a sync.Map and
			// resolves work_id → mission_id via short-lived Redis hash keys written
			// by PollWork when work items carrying mission_id context are dispatched.
			compSvc.WithMemoryResolver(component.NewRedisMemoryResolver(d.stateClient))

			// Wire the quota manager so RegisterComponent enforces per-tenant
			// agent quotas before the agent is admitted to the registry.
			if d.quotaManager != nil {
				compSvc.WithQuotaManager(d.quotaManager)
				d.logger.Info(ctx, "quota manager wired into ComponentService for agent quota enforcement")
			}

			// Wire the FGA authorizer so RegisterComponent writes component
			// ownership tuples. This enables the "admin from owner" computed
			// relation: tenant admins automatically have access to all
			// components owned by their tenant. The authorizer is always
			// non-nil here (noop when authz.enabled=false), so the nil guard
			// inside WithAuthorizer / RegisterComponent handles the disabled case.
			compSvc.WithAuthorizer(d.authorizer)
			d.logger.Info(ctx, "FGA authorizer wired into ComponentService for ownership tuple writes")

			componentpb.RegisterComponentServiceServer(srv, compSvc)
			d.logger.Info(ctx, "ComponentService initialized",
				"registry_ttl", "30s",
				"redis_mode", "standalone",
				"memory_resolver", "redis",
			)
		} else {
			d.logger.Warn(ctx, "ComponentService unavailable: Redis client is not standalone mode; requires *redis.Client")
		}
	} else {
		d.logger.Warn(ctx, "ComponentService unavailable: stateClient is nil, Redis not configured")
	}

	// Start serving in goroutine
	go func() {
		d.logger.Info(ctx, "gRPC server listening", "address", d.grpcAddr)
		if err := srv.Serve(listener); err != nil {
			d.logger.Error(ctx, "gRPC server error", "error", err)
		}
	}()

	return nil
}

// agentJWTAdapter wraps agentauth.JWTVerifier to satisfy auth.AgentJWTValidator.
//
// The adapter converts agentauth.AgentClaims → auth.AgentAuthClaims so that the
// auth package never imports agentauth (which would create an import cycle).
type agentJWTAdapter struct {
	inner *agentauth.JWTVerifier
}

// VerifyAgentJWT implements auth.AgentJWTValidator.
func (a *agentJWTAdapter) VerifyAgentJWT(ctx context.Context, tokenStr, expectedAud string) (*auth.AgentAuthClaims, error) {
	claims, err := a.inner.VerifyAgentJWT(ctx, tokenStr, expectedAud)
	if err != nil {
		return nil, err
	}
	return &auth.AgentAuthClaims{
		AgentID:        claims.AgentID,
		HostID:         claims.HostID,
		TenantID:       claims.TenantID,
		OwnerUserID:    claims.OwnerUserID,
		ComponentScope: claims.ComponentScope,
		ExpiresAt:      claims.ExpiresAt,
	}, nil
}

// buildAuthValidators constructs the authentication validators used by the
// interceptor. SPIFFE auth is handled at the TLS layer (no validator needed here).
//
// Validators are constructed on a best-effort basis: if a dependency (Postgres,
// Better Auth secret) is unavailable the corresponding validator is nil and its
// path is effectively disabled. The interceptor handles nil validators gracefully.
//
// Returns:
//
//	apiKeyAuth  — Postgres-backed API key authenticator (nil when dashboardDB unavailable)
//	jwtVerifier — Ed25519 Agent Auth JWT verifier adapter (nil when dashboardDB unavailable)
//	baValidator — HMAC-SHA256 Better Auth validator (nil when secret is not configured)
func (d *daemonImpl) buildAuthValidators(ctx context.Context) (
	apiKeyAuth *auth.APIKeyAuthenticator,
	jwtValidator auth.AgentJWTValidator,
	baValidator *auth.BetterAuthValidator,
	err error,
) {
	mode := d.config.Auth.Mode

	// --- Path 1 (token): API key (gsk_ prefix) ---
	// Postgres-backed; requires dashboardDB.
	if (mode == "enterprise" || mode == "saas") && d.dashboardDB != nil {
		apiKeyAuth, err = auth.NewAPIKeyAuthenticator(d.dashboardDB)
		if err != nil {
			d.logger.Warn(ctx, "failed to create API key authenticator, continuing without it",
				"error", err,
			)
			apiKeyAuth = nil
			err = nil // non-fatal
		} else {
			d.logger.Info(ctx, "API key authenticator initialised (gsk_ path)")
		}
	} else if mode == "enterprise" || mode == "saas" {
		d.logger.Warn(ctx, "API key auth unavailable: dashboard Postgres not initialised")
	}

	// --- Path 2 (token): Agent Auth JWT (agent+jwt / host+jwt) ---
	// Requires dashboardDB for agent record lookup.
	// Wrapped in agentJWTAdapter to satisfy auth.AgentJWTValidator without
	// introducing an import cycle between auth and agentauth packages.
	if d.dashboardDB != nil {
		agentStore := agentauth.NewAgentAuthStore(d.dashboardDB)
		inner := agentauth.NewJWTVerifier(agentStore)
		jwtValidator = &agentJWTAdapter{inner: inner}
		d.logger.Info(ctx, "agent auth JWT verifier initialised (agent+jwt path)")
	} else {
		d.logger.Warn(ctx, "agent auth JWT verifier unavailable: dashboard Postgres not initialised")
	}

	// --- Path 3 (token): Better Auth (HMAC-SHA256, default path) ---
	// Requires BETTER_AUTH_SECRET in config. If the secret is absent the default
	// path is disabled and unauthenticated requests will fail at the interceptor.
	if d.config.Auth.BetterAuth.Secret != "" {
		baValidator, err = auth.NewBetterAuthValidator(d.config.Auth.BetterAuth.Secret)
		if err != nil {
			// The only reason NewBetterAuthValidator can fail is an empty secret,
			// which we already guarded against above. Log and treat as non-fatal.
			d.logger.Warn(ctx, "failed to create Better Auth validator, continuing without it",
				"error", err,
			)
			baValidator = nil
			err = nil
		} else {
			d.logger.Info(ctx, "Better Auth validator initialised (default path)")
		}
	} else {
		d.logger.Warn(ctx, "Better Auth validator unavailable: auth.better_auth_secret not configured")
	}

	methods := make([]string, 0, 4)
	methods = append(methods, "spiffe(mtls)")
	if apiKeyAuth != nil {
		methods = append(methods, "apikey(gsk_)")
	}
	if jwtValidator != nil {
		methods = append(methods, "agent-auth-jwt")
	}
	if baValidator != nil {
		methods = append(methods, "better-auth")
	}
	d.logger.Info(ctx, "auth validators built", "active_methods", methods)
	return apiKeyAuth, jwtValidator, baValidator, nil
}

// Implementation of api.DaemonInterface for delegation from gRPC server.
// These methods delegate to the daemon's internal services.

// updateAgentHeartbeat updates the last heartbeat time for an agent.
// This should be called whenever an agent communicates with the daemon.
//
// Integration points (to be implemented in future):
//   - During mission execution when agents send task results
//   - During attack execution when agents report findings
//   - When agents register or re-register with the registry
//   - When agents respond to health checks
func (d *daemonImpl) updateAgentHeartbeat(agentName string) {
	d.agentStateMu.Lock()
	defer d.agentStateMu.Unlock()

	state, exists := d.agentState[agentName]
	if !exists {
		state = &AgentRuntimeState{}
		d.agentState[agentName] = state
	}
	state.LastHeartbeat = time.Now()
}

// setAgentCurrentTask updates the current task for an agent.
// This should be called when a task is assigned to or completed by an agent.
//
// Integration points (to be implemented in future):
//   - In orchestrator when assigning mission nodes to agents
//   - In attack runner when starting agent operations
//   - When tasks complete (set to empty string to clear)
func (d *daemonImpl) setAgentCurrentTask(agentName string, taskID string) {
	d.agentStateMu.Lock()
	defer d.agentStateMu.Unlock()

	state, exists := d.agentState[agentName]
	if !exists {
		state = &AgentRuntimeState{
			LastHeartbeat: time.Now(),
		}
		d.agentState[agentName] = state
	}

	// If setting a new task (non-empty), update start time
	if taskID != "" {
		state.CurrentTask = taskID
		state.TaskStartTime = time.Now()
	} else {
		// Clearing the task
		state.CurrentTask = ""
		state.TaskStartTime = time.Time{}
	}
}

// getAgentState retrieves the runtime state for an agent.
// Returns nil if no state exists for the agent.
func (d *daemonImpl) getAgentState(agentName string) *AgentRuntimeState {
	d.agentStateMu.RLock()
	defer d.agentStateMu.RUnlock()

	state, exists := d.agentState[agentName]
	if !exists {
		return nil
	}

	// Return a copy to avoid race conditions
	stateCopy := *state
	return &stateCopy
}

// Status implements the api.DaemonInterface.Status method.
// It returns the daemon status in the format expected by the gRPC API.
func (d *daemonImpl) Status() (api.DaemonStatus, error) {
	// Get the internal status
	internalStatus, err := d.status()
	if err != nil {
		return api.DaemonStatus{}, err
	}

	// Convert to API status format
	return api.DaemonStatus{
		Running:            internalStatus.Running,
		PID:                int32(internalStatus.PID),
		StartTime:          internalStatus.StartTime,
		Uptime:             internalStatus.Uptime,
		GRPCAddress:        internalStatus.GRPCAddress,
		RegistryType:       internalStatus.RegistryType,
		RegistryAddr:       internalStatus.RegistryAddr,
		CallbackAddr:       internalStatus.CallbackAddr,
		AgentCount:         int32(internalStatus.AgentCount),
		MissionCount:       int32(internalStatus.MissionCount),
		ActiveMissionCount: int32(internalStatus.ActiveCount),
	}, nil
}

// ListAgents returns all registered agents from the registry adapter.
func (d *daemonImpl) ListAgents(ctx context.Context, kind string) ([]api.AgentInfoInternal, error) {
	d.logger.Debug(ctx, "ListAgents called", "kind", kind)

	agents, err := d.registryAdapter.ListAgents(ctx)
	if err != nil {
		return nil, fmt.Errorf("list agents: %w", err)
	}

	result := make([]api.AgentInfoInternal, len(agents))
	for i, a := range agents {
		endpoint := ""
		if len(a.Endpoints) > 0 {
			endpoint = a.Endpoints[0]
		}

		health := a.Health
		if health == "" {
			health = "healthy"
		}

		// Get runtime state for last seen time
		runtimeState := d.getAgentState(a.Name)
		lastSeen := time.Now()
		if runtimeState != nil && !runtimeState.LastHeartbeat.IsZero() {
			lastSeen = runtimeState.LastHeartbeat
		}

		result[i] = api.AgentInfoInternal{
			ID:           a.Name,
			Name:         a.Name,
			Kind:         "agent",
			Version:      a.Version,
			Endpoint:     endpoint,
			Capabilities: a.Capabilities,
			Health:       health,
			LastSeen:     lastSeen,
		}
	}

	d.logger.Debug(ctx, "listed agents", "count", len(result))
	return result, nil
}

// GetAgentStatus returns status for a specific agent.
func (d *daemonImpl) GetAgentStatus(ctx context.Context, agentID string) (api.AgentStatusInternal, error) {
	d.logger.Debug(ctx, "GetAgentStatus called", "agent_id", agentID)

	// Query registry for all agents
	agents, err := d.registryAdapter.ListAgents(ctx)
	if err != nil {
		d.logger.Error(ctx, "failed to query registry for agent status", "error", err, "agent_id", agentID)
		return api.AgentStatusInternal{}, fmt.Errorf("failed to query registry: %w", err)
	}

	// Find the specific agent by ID (using name as ID)
	for _, agent := range agents {
		if agent.Name == agentID {
			// Use first endpoint if available
			endpoint := ""
			if len(agent.Endpoints) > 0 {
				endpoint = agent.Endpoints[0]
			}

			// Determine health status
			health := "healthy"
			if agent.Instances == 0 {
				health = "unknown"
			}

			// Get runtime state for the agent (last heartbeat, current task)
			runtimeState := d.getAgentState(agent.Name)
			lastSeen := time.Now()
			if runtimeState != nil && !runtimeState.LastHeartbeat.IsZero() {
				lastSeen = runtimeState.LastHeartbeat
			}

			// Build agent info
			agentInfo := api.AgentInfoInternal{
				ID:           agent.Name,
				Name:         agent.Name,
				Kind:         "agent",
				Version:      agent.Version,
				Endpoint:     endpoint,
				Capabilities: agent.Capabilities,
				Health:       health,
				LastSeen:     lastSeen,
			}

			// Get current task from runtime state
			currentTask := ""
			taskStartTime := time.Time{}
			if runtimeState != nil {
				currentTask = runtimeState.CurrentTask
				taskStartTime = runtimeState.TaskStartTime
			}

			// Build agent status
			status := api.AgentStatusInternal{
				Agent:         agentInfo,
				Active:        agent.Instances > 0,
				CurrentTask:   currentTask,
				TaskStartTime: taskStartTime,
			}

			d.logger.Debug(ctx, "found agent status", "agent_id", agentID, "instances", agent.Instances)
			return status, nil
		}
	}

	// Agent not found
	d.logger.Debug(ctx, "agent not found in registry", "agent_id", agentID)
	return api.AgentStatusInternal{}, fmt.Errorf("agent not found: %s", agentID)
}

// ListTools returns all registered tools from the registry adapter.
func (d *daemonImpl) ListTools(ctx context.Context) ([]api.ToolInfoInternal, error) {
	d.logger.Debug(ctx, "ListTools called")

	tools, err := d.registryAdapter.ListTools(ctx)
	if err != nil {
		return nil, fmt.Errorf("list tools: %w", err)
	}

	result := make([]api.ToolInfoInternal, len(tools))
	for i, t := range tools {
		endpoint := ""
		if len(t.Endpoints) > 0 {
			endpoint = t.Endpoints[0]
		}

		var caps *daemonpb.Capabilities
		if t.Capabilities != nil {
			caps = &daemonpb.Capabilities{
				HasRoot:         t.Capabilities.HasRoot,
				HasSudo:         t.Capabilities.HasSudo,
				CanRawSocket:    t.Capabilities.CanRawSocket,
				Features:        t.Capabilities.Features,
				BlockedArgs:     t.Capabilities.BlockedArgs,
				ArgAlternatives: t.Capabilities.ArgAlternatives,
			}
		}

		result[i] = api.ToolInfoInternal{
			ID:           t.Name,
			Name:         t.Name,
			Version:      t.Version,
			Endpoint:     endpoint,
			Description:  t.Description,
			Health:       t.Health,
			LastSeen:     time.Now(),
			Capabilities: caps,
		}
	}

	d.logger.Debug(ctx, "listed tools", "count", len(result))
	return result, nil
}

// ListPlugins returns all registered plugins from the registry adapter.
func (d *daemonImpl) ListPlugins(ctx context.Context) ([]api.PluginInfoInternal, error) {
	d.logger.Debug(ctx, "ListPlugins called")

	plugins, err := d.registryAdapter.ListPlugins(ctx)
	if err != nil {
		return nil, fmt.Errorf("list plugins: %w", err)
	}

	result := make([]api.PluginInfoInternal, len(plugins))
	for i, p := range plugins {
		endpoint := ""
		if len(p.Endpoints) > 0 {
			endpoint = p.Endpoints[0]
		}

		health := p.Health
		if health == "" {
			if p.Instances > 0 {
				health = "healthy"
			} else {
				health = "unknown"
			}
		}

		result[i] = api.PluginInfoInternal{
			ID:          p.Name,
			Name:        p.Name,
			Version:     p.Version,
			Endpoint:    endpoint,
			Description: p.Description,
			Health:      health,
			LastSeen:    time.Now(),
		}
	}

	d.logger.Debug(ctx, "listed plugins", "count", len(result))
	return result, nil
}

// QueryPlugin executes a method on a plugin via the registry adapter.
func (d *daemonImpl) QueryPlugin(ctx context.Context, name, method string, params map[string]any) (any, error) {
	d.logger.Debug(ctx, "QueryPlugin called", "plugin", name, "method", method)

	// Discover and connect to plugin via registry adapter
	pluginClient, err := d.registryAdapter.DiscoverPlugin(ctx, name)
	if err != nil {
		d.logger.Error(ctx, "failed to discover plugin", "plugin", name, "error", err)
		return nil, fmt.Errorf("failed to discover plugin %s: %w", name, err)
	}

	// Execute query via gRPC
	result, err := pluginClient.Query(ctx, method, params)
	if err != nil {
		d.logger.Error(ctx, "plugin query failed", "plugin", name, "method", method, "error", err)
		return nil, fmt.Errorf("plugin query failed: %w", err)
	}

	d.logger.Debug(ctx, "plugin query completed", "plugin", name, "method", method)
	return result, nil
}

// RunMission starts a mission by reference and returns an event channel.
// The mission definition and target must already be registered — inline
// construction and YAML paths were removed under spec mission-api-only-cleanup.
func (d *daemonImpl) RunMission(ctx context.Context, missionDefinitionID string, targetID string, variables map[string]string, memoryContinuity string) (<-chan api.MissionEventData, error) {
	return d.RunMissionWithManager(ctx, missionDefinitionID, targetID, variables, memoryContinuity)
}

// StopMission stops a running mission.
func (d *daemonImpl) StopMission(ctx context.Context, missionID string, force bool) error {
	d.logger.Info(ctx, "StopMission called", "mission_id", missionID, "force", force)

	// Validate mission ID
	if missionID == "" {
		return fmt.Errorf("mission ID cannot be empty")
	}

	// Lock the missions map to check if mission is running
	d.missionsMu.Lock()
	cancelFunc, exists := d.activeMissions[missionID]
	if !exists {
		d.missionsMu.Unlock()
		// Mission is not running in memory - check if it exists in the store
		missionObj, err := d.missionStore.Get(ctx, types.ID(missionID))
		if err != nil {
			// Mission not found in store either
			d.logger.Warn(ctx, "mission not found", "mission_id", missionID)
			return fmt.Errorf("mission not found: %s", missionID)
		}

		// If mission is paused (orphaned), mark it as failed to unblock future runs
		// This preserves memory for inheritance while allowing new runs to proceed
		if missionObj.Status == mission.MissionStatusPaused {
			d.logger.Info(ctx, "marking orphaned paused mission as failed", "mission_id", missionID)
			missionObj.Status = mission.MissionStatusFailed
			missionObj.CompletedAt = mission.NewUnixTimePtrNow()
			if missionObj.Metadata == nil {
				missionObj.Metadata = make(map[string]any)
			}
			missionObj.Metadata["failure_reason"] = "Orphaned paused mission - failed to resume"

			if err := d.missionStore.Update(ctx, missionObj); err != nil {
				d.logger.Error(ctx, "failed to update orphaned mission status", "error", err, "mission_id", missionID)
				return fmt.Errorf("failed to mark orphaned mission as failed: %w", err)
			}

			// Emit event for the status change
			d.publishEvent(ctx, api.EventData{
				EventType: "mission_failed",
				Timestamp: time.Now(),
				Source:    "daemon",
				MissionEvent: &api.MissionEventData{
					EventType: "mission_failed",
					Timestamp: time.Now(),
					MissionID: missionID,
					Message:   "Orphaned paused mission marked as failed",
				},
			})

			d.logger.Info(ctx, "orphaned paused mission marked as failed", "mission_id", missionID)
			return nil
		}

		// Mission exists but is not running and not paused (already terminal)
		d.logger.Info(ctx, "mission is not currently running", "mission_id", missionID)
		return fmt.Errorf("mission is not currently running: %s", missionID)
	}

	// Remove from active missions immediately to prevent duplicate stop requests
	delete(d.activeMissions, missionID)
	d.missionsMu.Unlock()

	// Cancel the mission context to trigger graceful shutdown
	d.logger.Info(ctx, "cancelling mission execution", "mission_id", missionID, "force", force)
	cancelFunc()

	// Update mission status in the store
	missionObj, err := d.missionStore.Get(ctx, types.ID(missionID))
	if err != nil {
		d.logger.Error(ctx, "failed to get mission for status update", "error", err, "mission_id", missionID)
		// Continue anyway - the cancellation was successful
	} else {
		// Update mission status to cancelled
		missionObj.Status = mission.MissionStatusCancelled
		completedAt := time.Now()
		missionObj.CompletedAt = mission.NewUnixTimePtr(&completedAt)
		if missionObj.Metrics != nil {
			missionObj.Metrics.Duration = completedAt.Sub(missionObj.Metrics.StartedAt)
		}

		if err := d.missionStore.Update(ctx, missionObj); err != nil {
			d.logger.Error(ctx, "failed to update mission status", "error", err, "mission_id", missionID)
		}
	}

	// Emit mission stopped event to all transports.
	d.publishEvent(ctx, api.EventData{
		EventType: "mission_stopped",
		Timestamp: time.Now(),
		Source:    "daemon",
		MissionEvent: &api.MissionEventData{
			EventType: "mission_stopped",
			Timestamp: time.Now(),
			MissionID: missionID,
			Message:   fmt.Sprintf("Mission %s stopped (force=%t)", missionID, force),
		},
	})

	d.logger.Info(ctx, "mission stopped successfully", "mission_id", missionID)
	return nil
}

// ListMissions returns mission list.

// Subscribe establishes an event stream.
//
// When redisEventStream is available it uses Redis Streams (XREAD BLOCK) as
// the transport, which allows events to survive daemon restarts and be shared
// across multiple daemon pods. The tenant is extracted from the request context
// via auth.TenantFromContext; "default" is used when no tenant is present.
//
// When redisEventStream is nil (e.g., during unit tests that use a lightweight
// daemon without Redis) the implementation falls back to the in-process
// EventBus for full backwards compatibility.
func (d *daemonImpl) Subscribe(ctx context.Context, eventTypes []string, missionID string) (<-chan api.EventData, error) {
	d.logger.Info(ctx, "Subscribe called", "event_types", eventTypes, "mission_id", missionID)

	// Use Redis Streams when available: this is the production path.
	if d.redisEventStream != nil {
		tenant := auth.TenantFromContext(ctx)
		if tenant == "" {
			tenant = "default"
		}

		redisChan, err := d.redisEventStream.SubscribeStream(ctx, tenant, eventTypes, missionID)
		if err != nil {
			// Log and fall through to EventBus fallback.
			d.logger.Warn(ctx, "redis stream subscribe failed, falling back to eventbus",
				"error", err)
		} else {
			d.logger.Info(ctx, "subscription established via redis streams",
				"tenant", tenant, "mission_id", missionID)
			return redisChan, nil
		}
	}

	// Fallback: in-process EventBus (no Redis, unit-test scenario).
	eventChan, cleanup := d.eventBus.Subscribe(ctx, eventTypes, missionID)

	go func() {
		<-ctx.Done()
		cleanup()
		d.logger.Info(ctx, "eventbus subscription cleanup completed", "mission_id", missionID)
	}()

	return eventChan, nil
}

// publishEvent writes an event to both the in-process EventBus and, when
// redisEventStream is available, the tenant-scoped Redis Stream.
//
// It extracts the tenant from the context (auth.TenantFromContext) and falls
// back to "default" when none is present.  Errors from either transport are
// logged as warnings but do not propagate — event publishing is best-effort.
func (d *daemonImpl) publishEvent(ctx context.Context, event api.EventData) {
	// In-process EventBus (always present; used by in-process subscribers and tests).
	if d.eventBus != nil {
		if err := d.eventBus.Publish(ctx, event); err != nil {
			d.logger.Warn(ctx, "failed to publish to eventbus", "error", err, "event_type", event.EventType)
		}
	}

	// Redis Streams (optional; available after stateClient is initialized).
	if d.redisEventStream != nil {
		tenant := auth.TenantFromContext(ctx)
		if tenant == "" {
			tenant = "default"
		}
		if err := d.redisEventStream.PublishEvent(ctx, tenant, event); err != nil {
			d.logger.Warn(ctx, "failed to publish to redis stream", "error", err, "event_type", event.EventType)
		}
	}
}

// StartComponent is not supported; component lifecycle management has been removed.
func (d *daemonImpl) StartComponent(ctx context.Context, kind string, name string) (api.StartComponentResult, error) {
	d.logger.Warn(ctx, "StartComponent called but component store has been removed", "kind", kind, "name", name)
	return api.StartComponentResult{}, fmt.Errorf("component lifecycle management is not available")
}

// StopComponent is not supported; component lifecycle management has been removed.
func (d *daemonImpl) StopComponent(ctx context.Context, kind string, name string, force bool) (api.StopComponentResult, error) {
	d.logger.Warn(ctx, "StopComponent called but component store has been removed", "kind", kind, "name", name)
	return api.StopComponentResult{}, fmt.Errorf("component lifecycle management is not available")
}

// PauseMission pauses a running mission at the next clean checkpoint boundary.
func (d *daemonImpl) PauseMission(ctx context.Context, missionID string, force bool) error {
	d.logger.Info(ctx, "PauseMission called", "mission_id", missionID, "force", force)

	// Validate mission ID
	if missionID == "" {
		return fmt.Errorf("mission ID cannot be empty")
	}

	// Initialize mission manager if not already done
	if err := d.ensureMissionManager(); err != nil {
		d.logger.Error(ctx, "failed to initialize mission manager", "error", err)
		return fmt.Errorf("failed to initialize mission manager: %w", err)
	}

	// Call mission manager's pause method
	if err := d.missionManager.Pause(ctx, missionID, force); err != nil {
		d.logger.Error(ctx, "failed to pause mission", "error", err, "mission_id", missionID)
		return fmt.Errorf("failed to pause mission: %w", err)
	}

	d.logger.Info(ctx, "mission paused successfully", "mission_id", missionID)
	return nil
}

// ResumeMission resumes a paused mission from its last checkpoint.
func (d *daemonImpl) ResumeMission(ctx context.Context, missionID string) (<-chan api.MissionEventData, error) {
	d.logger.Info(ctx, "ResumeMission called", "mission_id", missionID)

	// Validate mission ID
	if missionID == "" {
		return nil, fmt.Errorf("mission ID cannot be empty")
	}

	// Initialize mission manager if not already done
	if err := d.ensureMissionManager(); err != nil {
		d.logger.Error(ctx, "failed to initialize mission manager", "error", err)
		return nil, fmt.Errorf("failed to initialize mission manager: %w", err)
	}

	// Call mission manager's resume method
	eventChan, err := d.missionManager.Resume(ctx, missionID)
	if err != nil {
		d.logger.Error(ctx, "failed to resume mission", "error", err, "mission_id", missionID)
		return nil, fmt.Errorf("failed to resume mission: %w", err)
	}

	d.logger.Info(ctx, "mission resume started", "mission_id", missionID)
	return eventChan, nil
}

// GetMissionHistory returns all runs for a mission name.
func (d *daemonImpl) GetMissionHistory(ctx context.Context, name string, limit int, offset int) ([]api.MissionRunData, int, error) {
	d.logger.Debug(ctx, "GetMissionHistory called", "name", name, "limit", limit, "offset", offset)

	// Validate name
	if name == "" {
		return nil, 0, fmt.Errorf("mission name cannot be empty")
	}

	// Check if run store is available
	if d.missionRunStore == nil {
		d.logger.Warn(ctx, "mission run store not initialized")
		return []api.MissionRunData{}, 0, nil
	}

	// Get the mission by name to find its ID
	m, err := d.missionStore.GetByName(ctx, name)
	if err != nil {
		if mission.IsNotFoundError(err) {
			d.logger.Debug(ctx, "mission not found", "name", name)
			return []api.MissionRunData{}, 0, nil
		}
		d.logger.Error(ctx, "failed to get mission", "error", err, "name", name)
		return nil, 0, fmt.Errorf("failed to get mission: %w", err)
	}

	// Get all runs for this mission
	missionRuns, err := d.missionRunStore.ListByMission(ctx, m.ID)
	if err != nil {
		d.logger.Error(ctx, "failed to list mission runs", "error", err, "mission_id", m.ID)
		return nil, 0, fmt.Errorf("failed to list mission runs: %w", err)
	}

	// Apply pagination
	total := len(missionRuns)
	if offset >= total {
		return []api.MissionRunData{}, total, nil
	}

	end := offset + limit
	if end > total {
		end = total
	}
	if limit == 0 {
		end = total
	}

	pagedRuns := missionRuns[offset:end]

	// Extract trace ID from mission metadata (written at mission start)
	traceID := ""
	if m.Metadata != nil {
		if v, ok := m.Metadata["trace_id"].(string); ok {
			traceID = v
		}
	}

	// Convert to API format
	runs := make([]api.MissionRunData, len(pagedRuns))
	for i, r := range pagedRuns {
		completedAt := int64(0)
		if r.CompletedAt != nil {
			completedAt = r.CompletedAt.Unix()
		}

		startedAt := int64(0)
		if r.StartedAt != nil {
			startedAt = r.StartedAt.Unix()
		}

		runs[i] = api.MissionRunData{
			RunID:         r.ID.String(),
			MissionID:     r.MissionID.String(),
			RunNumber:     r.RunNumber,
			Status:        string(r.Status),
			Progress:      r.Progress,
			CreatedAt:     r.CreatedAt.Unix(),
			StartedAt:     startedAt,
			CompletedAt:   completedAt,
			FindingsCount: r.FindingsCount,
			Error:         r.Error,
			TraceID:       traceID,
		}
	}

	d.logger.Debug(ctx, "mission history retrieved", "name", name, "count", len(runs), "total", total)
	return runs, total, nil
}

// GetMissionCheckpoints returns all checkpoints for a mission.
func (d *daemonImpl) GetMissionCheckpoints(ctx context.Context, missionID string) ([]api.CheckpointData, error) {
	d.logger.Debug(ctx, "GetMissionCheckpoints called", "mission_id", missionID)

	// Validate mission ID
	if missionID == "" {
		return nil, fmt.Errorf("mission ID cannot be empty")
	}

	// Get the mission from the store
	m, err := d.missionStore.Get(ctx, types.ID(missionID))
	if err != nil {
		d.logger.Error(ctx, "failed to get mission", "error", err, "mission_id", missionID)
		return nil, fmt.Errorf("failed to get mission: %w", err)
	}

	// Check if mission has a checkpoint
	if m.Checkpoint == nil {
		d.logger.Debug(ctx, "no checkpoints found for mission", "mission_id", missionID)
		return []api.CheckpointData{}, nil
	}

	// Convert checkpoint to CheckpointData
	// Calculate total nodes from metrics if available
	totalNodes := 0
	findingsCount := 0
	if m.Metrics != nil {
		totalNodes = m.Metrics.TotalNodes
		findingsCount = m.Metrics.TotalFindings
	}

	checkpoint := api.CheckpointData{
		CheckpointID:   m.Checkpoint.ID.String(),
		CreatedAt:      m.Checkpoint.CheckpointedAt.Unix(),
		CompletedNodes: len(m.Checkpoint.CompletedNodes),
		TotalNodes:     totalNodes,
		FindingsCount:  findingsCount,
		Version:        m.Checkpoint.Version,
	}

	d.logger.Debug(ctx, "mission checkpoints retrieved", "mission_id", missionID, "count", 1)
	return []api.CheckpointData{checkpoint}, nil
}

// BuildComponent is not supported; component store has been removed.
func (d *daemonImpl) BuildComponent(ctx context.Context, kind string, name string) (api.BuildComponentResult, error) {
	d.logger.Warn(ctx, "BuildComponent called but component store has been removed", "kind", kind, "name", name)
	return api.BuildComponentResult{}, fmt.Errorf("component build is not available")
}

// ShowComponent is not supported; component store has been removed.
func (d *daemonImpl) ShowComponent(ctx context.Context, kind string, name string) (api.ComponentInfoInternal, error) {
	d.logger.Warn(ctx, "ShowComponent called but component store has been removed", "kind", kind, "name", name)
	return api.ComponentInfoInternal{}, fmt.Errorf("component store is not available")
}

// GetComponentLogs streams log entries for a component using the log tailer.
func (d *daemonImpl) GetComponentLogs(ctx context.Context, kind string, name string, follow bool, lines int) (<-chan api.LogEntryData, error) {
	d.logger.Debug(ctx, "GetComponentLogs called", "kind", kind, "name", name, "follow", follow, "lines", lines)

	// Construct log file path: ~/.gibson/logs/<component-name>.log
	logDir := filepath.Join(d.config.Core.HomeDir, "logs")
	logFilePath := filepath.Join(logDir, fmt.Sprintf("%s.log", name))

	// Check if log file exists
	if _, err := os.Stat(logFilePath); os.IsNotExist(err) {
		d.logger.Warn(ctx, "log file does not exist", "path", logFilePath)
		return nil, fmt.Errorf("log file not found for component '%s'", name)
	}

	// Use LogTailer if available, otherwise fall back to simple implementation
	if d.logTailer != nil {
		return d.getComponentLogsWithTailer(ctx, name, logFilePath, follow, lines)
	}

	// Fallback: simple file reading (for backward compatibility)
	return d.getComponentLogsSimple(ctx, name, logFilePath, follow, lines)
}

// getComponentLogsWithTailer uses the LogTailer for efficient log streaming with fsnotify.
func (d *daemonImpl) getComponentLogsWithTailer(ctx context.Context, componentName string, logFilePath string, follow bool, lines int) (<-chan api.LogEntryData, error) {
	// Start watching this component if not already watching
	if !d.logTailer.IsWatching(componentName) {
		if err := d.logTailer.StartWatching(componentName, logFilePath); err != nil {
			d.logger.Error(ctx, "failed to start watching component logs", "error", err, "component", componentName)
			return nil, fmt.Errorf("failed to start watching logs: %w", err)
		}
	}

	// Create subscription options
	opts := SubscribeOptions{
		ComponentIDs: []string{componentName},
		Follow:       follow,
		TailLines:    lines,
	}

	// Subscribe to log entries
	sub, err := d.logTailer.Subscribe(ctx, opts)
	if err != nil {
		d.logger.Error(ctx, "failed to subscribe to component logs", "error", err, "component", componentName)
		return nil, fmt.Errorf("failed to subscribe to logs: %w", err)
	}

	// Create output channel
	logChan := make(chan api.LogEntryData, 100)

	// Start goroutine to convert LogEntry to api.LogEntryData
	go func() {
		defer close(logChan)
		defer d.logTailer.Unsubscribe(sub)

		for {
			select {
			case <-ctx.Done():
				return
			case entry, ok := <-sub.Output:
				if !ok {
					// Subscription closed
					return
				}

				// Convert LogEntry to api.LogEntryData
				logChan <- api.LogEntryData{
					Timestamp: entry.Timestamp.Unix(),
					Level:     entry.Level,
					Message:   entry.Message,
				}
			}
		}
	}()

	return logChan, nil
}

// getComponentLogsSimple provides a simple fallback implementation without LogTailer.
func (d *daemonImpl) getComponentLogsSimple(ctx context.Context, componentName string, logFilePath string, follow bool, lines int) (<-chan api.LogEntryData, error) {
	// Create channel for streaming logs
	logChan := make(chan api.LogEntryData, 100)

	// Start goroutine to read and stream logs
	go func() {
		defer close(logChan)

		// Open log file
		file, err := os.Open(logFilePath)
		if err != nil {
			d.logger.Error(ctx, "failed to open log file", "error", err, "path", logFilePath)
			return
		}
		defer file.Close()

		// Read all lines
		scanner := bufio.NewScanner(file)
		var logLines []string
		for scanner.Scan() {
			logLines = append(logLines, scanner.Text())
		}

		if err := scanner.Err(); err != nil {
			d.logger.Error(ctx, "error reading log file", "error", err, "path", logFilePath)
			return
		}

		// Determine which lines to send based on lines parameter
		startIdx := 0
		if lines > 0 && len(logLines) > lines {
			startIdx = len(logLines) - lines
		}

		// Send initial lines
		for i := startIdx; i < len(logLines); i++ {
			select {
			case <-ctx.Done():
				return
			case logChan <- api.LogEntryData{
				Timestamp: time.Now().Unix(),
				Level:     "info",
				Message:   logLines[i],
			}:
			}
		}

		// If follow mode not requested, we're done
		if !follow {
			return
		}

		// Simple polling for follow mode
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		lastSize, _ := file.Seek(0, io.SeekCurrent)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Check if file has grown
				fileInfo, err := os.Stat(logFilePath)
				if err != nil {
					d.logger.Error(ctx, "error checking log file", "error", err)
					return
				}

				currentSize := fileInfo.Size()
				if currentSize > lastSize {
					// Read new content
					file.Seek(lastSize, 0)
					scanner := bufio.NewScanner(file)
					for scanner.Scan() {
						select {
						case <-ctx.Done():
							return
						case logChan <- api.LogEntryData{
							Timestamp: time.Now().Unix(),
							Level:     "info",
							Message:   scanner.Text(),
						}:
						}
					}
					lastSize = currentSize
				}
			}
		}
	}()

	return logChan, nil
}

// ListMissionDefinitions returns all installed mission definitions.
func (d *daemonImpl) ListMissionDefinitions(ctx context.Context, limit int, offset int) ([]api.MissionDefinitionData, int, error) {
	d.logger.Debug(ctx, "ListMissionDefinitions called", "limit", limit, "offset", offset)

	if d.missionStore == nil {
		d.logger.Warn(ctx, "mission store not available, returning empty list")
		return []api.MissionDefinitionData{}, 0, nil
	}

	defs, err := d.missionStore.ListDefinitions(ctx)
	if err != nil {
		d.logger.Error(ctx, "failed to list mission definitions", "error", err)
		return nil, 0, fmt.Errorf("failed to list mission definitions: %w", err)
	}

	total := len(defs)

	// Apply offset and limit for pagination
	if offset > total {
		offset = total
	}
	defs = defs[offset:]
	if limit > 0 && len(defs) > limit {
		defs = defs[:limit]
	}

	result := make([]api.MissionDefinitionData, 0, len(defs))
	for _, def := range defs {
		nodeCount := len(def.Nodes)
		result = append(result, api.MissionDefinitionData{
			Name:        def.Name,
			Version:     def.Version,
			Description: def.Description,
			Source:      def.Source,
			InstalledAt: def.InstalledAt,
			NodeCount:   nodeCount,
		})
	}

	d.logger.Debug(ctx, "listed mission definitions", "count", len(result), "total", total)
	return result, total, nil
}

// CreateMission creates a new mission by reference. The mission definition
// and target must already be registered (via CreateMissionDefinition and the
// target API respectively). Inline construction was removed under spec
// mission-api-only-cleanup.
func (d *daemonImpl) CreateMission(ctx context.Context, req api.CreateMissionData) (api.CreateMissionResultData, error) {
	d.logger.Info(ctx, "CreateMission called",
		"name", req.Name,
		"target_id", req.TargetID,
		"mission_definition_id", req.MissionDefinitionID,
	)

	if d.missionService == nil {
		d.logger.Error(ctx, "mission service not available")
		return api.CreateMissionResultData{}, fmt.Errorf("mission service not initialized")
	}

	if req.Name == "" {
		return api.CreateMissionResultData{}, fmt.Errorf("mission name is required")
	}
	if req.TargetID == "" {
		return api.CreateMissionResultData{}, fmt.Errorf("target_id is required")
	}
	if req.MissionDefinitionID == "" {
		return api.CreateMissionResultData{}, fmt.Errorf("mission_definition_id is required")
	}

	targetID, err := types.ParseID(req.TargetID)
	if err != nil {
		return api.CreateMissionResultData{}, fmt.Errorf("invalid target_id: %w", err)
	}
	missionDefinitionID, err := types.ParseID(req.MissionDefinitionID)
	if err != nil {
		return api.CreateMissionResultData{}, fmt.Errorf("invalid mission_definition_id: %w", err)
	}

	m, err := d.missionService.CreateByReference(ctx, mission.CreateMissionByReferenceRequest{
		Name:                req.Name,
		Description:         req.Description,
		TargetID:            targetID,
		MissionDefinitionID: missionDefinitionID,
		Metadata:            req.Metadata,
	})
	if err != nil {
		d.logger.Error(ctx, "failed to create mission", "error", err, "name", req.Name)
		return api.CreateMissionResultData{}, fmt.Errorf("failed to create mission: %w", err)
	}

	d.logger.Info(ctx, "mission created successfully",
		"mission_id", m.ID.String(),
		"target_id", m.TargetID.String(),
		"mission_definition_id", m.MissionDefinitionID.String(),
	)

	return api.CreateMissionResultData{
		MissionID:           m.ID.String(),
		TargetID:            m.TargetID.String(),
		MissionDefinitionID: m.MissionDefinitionID.String(),
		Name:                m.Name,
		Description:         m.Description,
		Status:              string(m.Status),
		CreatedAt:           m.CreatedAt.Time,
	}, nil
}

// CreateMissionDefinition registers a structured mission definition with the
// daemon. This is the API-only replacement for the removed InstallMission RPC;
// no git cloning, no YAML parsing, no dependency resolution — just validate and
// persist.
func (d *daemonImpl) CreateMissionDefinition(ctx context.Context, req api.CreateMissionDefinitionData) (api.CreateMissionDefinitionResultData, error) {
	if req.Definition == nil {
		return api.CreateMissionDefinitionResultData{}, fmt.Errorf("definition is required")
	}
	def := req.Definition
	if def.Name == "" {
		return api.CreateMissionDefinitionResultData{}, fmt.Errorf("definition name is required")
	}

	if d.missionStore == nil {
		return api.CreateMissionDefinitionResultData{}, fmt.Errorf("mission store not initialized")
	}

	if def.ID.IsZero() {
		def.ID = types.NewID()
	}
	if def.CreatedAt.IsZero() {
		def.CreatedAt = time.Now()
	}
	if def.Nodes == nil {
		def.Nodes = make(map[string]*mission.MissionNode)
	}

	if err := d.missionStore.CreateDefinition(ctx, def); err != nil {
		d.logger.Error(ctx, "failed to create mission definition", "error", err, "name", def.Name)
		return api.CreateMissionDefinitionResultData{}, fmt.Errorf("failed to create mission definition: %w", err)
	}

	d.logger.Info(ctx, "mission definition registered",
		"mission_definition_id", def.ID.String(),
		"name", def.Name,
	)

	return api.CreateMissionDefinitionResultData{
		MissionDefinitionID: def.ID.String(),
		Info: api.MissionDefinitionData{
			Name:        def.Name,
			Version:     def.Version,
			Description: def.Description,
			Source:      def.Source,
			InstalledAt: def.InstalledAt,
			UpdatedAt:   def.InstalledAt,
			NodeCount:   len(def.Nodes),
		},
	}, nil
}
