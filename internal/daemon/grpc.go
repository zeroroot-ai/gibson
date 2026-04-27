package daemon

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	discoverysvc "github.com/zero-day-ai/gibson/internal/api/discovery"
	"github.com/zero-day-ai/gibson/internal/apikeys"
	"github.com/zero-day-ai/gibson/internal/audit"
	"github.com/zero-day-ai/gibson/internal/budget"
	"github.com/zero-day-ai/gibson/internal/capabilitygrant"
	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/daemon/api"
	"github.com/zero-day-ai/gibson/internal/finding"
	"github.com/zero-day-ai/gibson/internal/graphrag/intelligence"
	"github.com/zero-day-ai/sdk/auth"
	sdkregistry "github.com/zero-day-ai/sdk/auth/registry"
	"github.com/zero-day-ai/gibson/internal/llm/modelgate"
	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/providerconfig"
	"github.com/zero-day-ai/gibson/internal/ratelimit"
	componentpb "github.com/zero-day-ai/sdk/api/gen/gibson/component/v1"
	discoverypb "github.com/zero-day-ai/sdk/api/gen/gibson/daemon/discovery/v1"
	daemonpb "github.com/zero-day-ai/sdk/api/gen/gibson/daemon/v1"
	intelligencepb "github.com/zero-day-ai/sdk/api/gen/intelligence/v1"

	"github.com/zero-day-ai/gibson/internal/impersonation"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/missiondraft"
	"github.com/zero-day-ai/gibson/internal/observability"
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

// grpcSubsystem owns the lifecycle of the gRPC server. It is constructed by
// buildGRPCServer and exposes a Serve(ctx) error method that can be launched
// in an errgroup or a plain goroutine.
type grpcSubsystem struct {
	srv                 *grpc.Server
	listener            net.Listener
	logger              *observability.Logger
	gracefulStopTimeout time.Duration
}

// Serve starts serving gRPC requests and blocks until ctx is cancelled.
// On cancellation it calls GracefulStop with a bounded timeout, then
// falls back to Stop if the timeout is exceeded. Returns nil on clean
// shutdown; returns a non-nil error only if srv.Serve itself fails with
// an unexpected error (grpc.ErrServerStopped is treated as clean shutdown).
func (s *grpcSubsystem) Serve(ctx context.Context) error {
	serveErr := make(chan error, 1)
	go func() {
		s.logger.Info(ctx, "gRPC server listening", "address", s.listener.Addr().String())
		if err := s.srv.Serve(s.listener); err != nil && err.Error() != "use of closed network connection" {
			serveErr <- err
		} else {
			serveErr <- nil
		}
	}()

	select {
	case err := <-serveErr:
		// Serve returned before ctx was cancelled — propagate the error.
		return err
	case <-ctx.Done():
		// Initiate graceful shutdown with a bounded timeout.
		stopCtx, stopCancel := context.WithTimeout(context.Background(), s.gracefulStopTimeout)
		defer stopCancel()

		gracefulDone := make(chan struct{})
		go func() {
			s.srv.GracefulStop()
			close(gracefulDone)
		}()

		select {
		case <-gracefulDone:
			s.logger.Info(ctx, "gRPC server drained gracefully")
		case <-stopCtx.Done():
			s.logger.Warn(ctx, "gRPC graceful stop timed out, forcing stop",
				"timeout", s.gracefulStopTimeout)
			s.srv.Stop()
		}
		// Wait for Serve goroutine to exit.
		<-serveErr
		return nil
	}
}

// buildGRPCServer creates the gRPC server, registers all services, and returns
// a grpcSubsystem ready to serve via Serve(ctx). The server is NOT started until
// Serve is called.
//
// All interceptor wiring, service registration, and SPIFFE mTLS setup is unchanged
// from the original startGRPCServer; only the launch goroutine has been moved to Serve.
func (d *daemonImpl) buildGRPCServer(ctx context.Context) (*grpcSubsystem, error) {
	// Create listener
	listener, err := net.Listen("tcp", d.grpcAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", d.grpcAddr, err)
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
		return nil, fmt.Errorf("failed to create recovery interceptors: %w", err)
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
		return nil, fmt.Errorf("failed to create error scrub interceptors: %w", err)
	}
	unaryInterceptors = append(unaryInterceptors, unaryScrub)
	streamInterceptors = append(streamInterceptors, streamScrub)

	// 3. Identity interceptor — reads x-gibson-identity-* headers ext-authz
	// emits and injects a typed Identity into the request context.
	// Authorization (FGA) is enforced upstream by Envoy + ext_authz; the daemon
	// trusts the headers because the Envoy↔daemon channel is SPIFFE-pinned mTLS.
	// HMAC signing was removed (Spec: unified-identity-and-authorization
	// Requirement 8.4); the secret-loading dance is gone with it.
	unaryInterceptors = append(unaryInterceptors, auth.UnaryServerInterceptor())
	streamInterceptors = append(streamInterceptors, auth.StreamServerInterceptor())
	d.logger.Info(ctx, "identity interceptor installed (header-trusting; channel security via SPIFFE mTLS)")

	// Build server options with chained interceptors
	serverOpts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(unaryInterceptors...),
		grpc.ChainStreamInterceptor(streamInterceptors...),
	}

	// SPIFFE mTLS — initialize X509Source and configure TLS when SPIFFE is configured.
	// tls.RequestClientCert allows both mTLS clients (in-cluster SPIFFE workloads)
	// and standard TLS clients (Agent Auth, API key, Better Auth) to connect on the
	// same listener. See the comment block below for why this specific value is used.
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
			// tls.RequestClientCert: ask for the client cert but DO NOT let Go's
			// stdlib chain verifier run on it. We rely entirely on go-spiffe's
			// VerifyPeerCertificate callback (installed by tlsconfig.MTLSServerConfig
			// above) for SPIFFE chain validation against the SPIRE bundle.
			//
			// DO NOT change to tls.VerifyClientCertIfGiven (the prior broken state):
			// stdlib verifier finds no acceptable issuer (ClientCAs is unset) and
			// emits `tlsv1 alert unknown_ca` post-handshake, killing the SPIFFE
			// callback before it runs. See spec daemon-tls-clientauth-fix and the
			// B-bug 1 entry in in-cluster-mtls-restoration/design.md.
			//
			// DO NOT change to tls.RequireAnyClientCert: would reject Bearer-only
			// clients (Agent Auth, API key, Auth.js / Better Auth callers) that
			// don't present a cert at all.
			tlsCfg.ClientAuth = tls.RequestClientCert
			// Go calls VerifyPeerCertificate even when no cert is presented (rawCerts
			// is empty) under RequestClientCert. go-spiffe's callback returns an error
			// for empty chains. Wrap it to:
			//   (a) pass through the no-cert case so Bearer-only clients reach the
			//       identity interceptor (original intent of the override),
			//   (b) log accepted mTLS handshakes at INFO with the client's SPIFFE ID
			//       (Requirement 1.4 — operators confirm mTLS is live without tcpdump),
			//   (c) log rejected handshakes at WARN with structured detail
			//       (NFR Usability — speeds up debugging vs opaque TLS alert 48).
			origVerify := tlsCfg.VerifyPeerCertificate
			logger := d.logger
			tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return nil // no cert presented — fall through to Bearer-token path
				}
				if err := origVerify(rawCerts, verifiedChains); err != nil {
					// Parse the leaf cert for structured rejection detail.
					// Best-effort: if parsing fails, log what we can.
					logCtx := context.Background()
					if leaf, parseErr := x509.ParseCertificate(rawCerts[0]); parseErr == nil {
						sans := make([]string, 0, len(leaf.URIs))
						for _, u := range leaf.URIs {
							sans = append(sans, u.String())
						}
						logger.Warn(logCtx, "SPIFFE mTLS: rejected client cert",
							"issuer", leaf.Issuer.String(),
							"subject", leaf.Subject.String(),
							"sans_uri", strings.Join(sans, ","),
							"not_before", leaf.NotBefore.Format(time.RFC3339),
							"not_after", leaf.NotAfter.Format(time.RFC3339),
							"error", err.Error(),
						)
					} else {
						logger.Warn(logCtx, "SPIFFE mTLS: rejected client cert (unparseable)",
							"error", err.Error(),
						)
					}
					return err
				}
				// Cert accepted — log the SPIFFE ID (URI SAN) from the leaf cert.
				// Log ONLY the URI SAN — never raw cert bytes, never client IP.
				if leaf, parseErr := x509.ParseCertificate(rawCerts[0]); parseErr == nil {
					spiffeID := ""
					for _, u := range leaf.URIs {
						if strings.HasPrefix(u.Scheme, "spiffe") {
							spiffeID = u.String()
							break
						}
					}
					if spiffeID != "" {
						logger.Info(context.Background(), "mTLS handshake accepted",
							"spiffe_id", spiffeID,
						)
					}
				}
				return nil
			}
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

	// Wire provider-config store (Phase C: Postgres-backed with envelope encryption).
	// Falls back gracefully when the credential Postgres pool is not yet configured.
	if d.credentialPGPool != nil && d.keyProvider != nil {
		masterKey, mkErr := d.keyProvider.GetEncryptionKey(ctx)
		if mkErr != nil {
			d.logger.Warn(ctx, "provider-config store not wired: could not get master key", "error", mkErr)
		} else {
			provStore, provStoreErr := providerconfig.NewPostgresStore(d.credentialPGPool, masterKey)
			if provStoreErr != nil {
				d.logger.Warn(ctx, "provider-config store not wired", "error", provStoreErr)
			} else {
				daemonSvc.WithProviderConfigStore(provStore)
				d.logger.Info(ctx, "provider-config store wired into DaemonServer (Phase C Postgres)")
			}
		}
	} else if d.keyProvider == nil {
		d.logger.Info(ctx, "provider-config store not wired: no key provider configured (set security.key_provider)")
	} else {
		d.logger.Info(ctx, "provider-config store not wired: dashboard Postgres not configured")
	}

	if d.stateClient != nil && d.stateClient.Client() != nil {
		// Build limits from config, falling back to DefaultLimits() for any
		// absent key so partial overrides work.
		limits := ratelimit.DefaultLimits()
		for rpcName, rpm := range d.config.LLM.ExecRateLimits {
			limits[rpcName] = ratelimit.RateLimit{RequestsPerMinute: rpm}
		}
		execLimiter := ratelimit.NewRedisLimiter(d.stateClient.Client(), limits)
		daemonSvc.WithExecLimiter(execLimiter)
		d.logger.Info(ctx, "execution rate limiter wired into DaemonServer (spec 25)")

		// Budget enforcer — per-user/team/tenant token + spend ceilings
		// around ExecuteLLM / StreamLLM. Clock is nil so the enforcer
		// uses time.Now. Absent budget configs = unlimited, so this
		// degrades to today's behavior until a tenant admin sets
		// budgets via the dashboard.
		//
		// TeamMembershipResolver is wired against FGA: `team#member@user`
		// tuples are the source of truth for team membership. Calls fall
		// back to tenant+user scopes (no teams) on authorizer absence or
		// transient error — the enforcer itself downgrades to no team
		// check when the resolver returns nil.
		// Spec: llm-user-attribution-governance (Requirement 3).
		var teamResolver budget.TeamMembershipResolver
		if d.authorizer != nil {
			authorizer := d.authorizer
			logger := d.logger.Slog()
			teamResolver = func(ctx context.Context, _, userID string) ([]string, error) {
				if userID == "" {
					return nil, nil
				}
				teams, err := authorizer.ListObjects(ctx, "user:"+userID, "member", "team")
				if err != nil {
					logger.WarnContext(ctx, "budget: team membership lookup failed; falling back to tenant+user scopes only",
						slog.String("user_id", userID),
						slog.String("error", err.Error()),
					)
					return nil, nil
				}
				// ListObjects returns entries like "team:engineering"; strip the prefix.
				ids := make([]string, 0, len(teams))
				for _, t := range teams {
					if strings.HasPrefix(t, "team:") {
						ids = append(ids, strings.TrimPrefix(t, "team:"))
					} else {
						ids = append(ids, t)
					}
				}
				return ids, nil
			}
		}
		budgetEnforcer := budget.NewEnforcer(d.stateClient.Client(), d.logger.Slog(), teamResolver, nil)
		daemonSvc.WithBudgetEnforcer(budgetEnforcer)
		d.budgetEnforcer = budgetEnforcer
		d.logger.Info(ctx, "budget enforcer wired into DaemonServer (spec: llm-user-attribution-governance)")

		// Launch the period-rollover job. SETNX-locked so only one
		// replica emits the boundary marker. Cancellation via ctx.
		// Spec: llm-user-attribution-governance (Requirement 3.8).
		rollover := budget.NewPeriodRolloverJob(d.stateClient.Client(), d.logger.Slog(), nil, nil)
		go func() {
			if err := rollover.Run(ctx); err != nil && err != context.Canceled {
				d.logger.Warn(ctx, "budget rollover subsystem exited with error (non-fatal)", "error", err)
			}
		}()
		d.logger.Info(ctx, "budget period-rollover subsystem launched")
	}

	// Model-access gate on the slot resolver + audit emission on every
	// slot resolution. Both degrade gracefully when their dependencies
	// are absent (nil authorizer = permit-all, nil auditWriter = no
	// events emitted).
	// Spec: llm-user-attribution-governance (Requirement 4).
	if d.infrastructure != nil {
		if dsm, ok := d.infrastructure.slotManager.(*DaemonSlotManager); ok {
			if d.authorizer != nil {
				filter := modelgate.NewFGAFilter(d.authorizer, d.logger.Slog(), 0)
				dsm.WithModelFilter(filter)
				// Expose the filter's cache-invalidation hook so
				// grant/revoke take effect within milliseconds rather
				// than the filter's 30s TTL. The Filter interface
				// requires InvalidateCache so this is always safe.
				daemonSvc.WithModelGateInvalidator(filter)
				d.logger.Info(ctx, "modelgate filter wired into slot resolver (spec: llm-user-attribution-governance)")
			}
			// Emit model_resolved events even when no filter is wired —
			// the audit trail captures every resolution regardless of
			// gating status.
			if d.auditWriter != nil {
				emitter := d.auditWriter
				logger := d.logger.Slog()
				dsm.WithResolveCallback(func(ctx context.Context, picked modelgate.Candidate, allowed bool) {
					tenantID := auth.TenantStringFromContext(ctx)
					userID := ""
					if uid, ok := auth.ActingUserFromContext(ctx); ok {
						userID = uid
					} else if uid, ok := auth.InitiatorUserFromContext(ctx); ok {
						userID = uid
					}
					audit.EmitModelResolved(ctx, emitter, logger, audit.ModelResolutionEvent{
						TenantID:       tenantID,
						UserID:         userID,
						ChosenProvider: picked.Provider,
						ChosenModel:    picked.Model,
						Considered: []audit.CandidateOutcome{{
							Provider: picked.Provider,
							Model:    picked.Model,
							Allowed:  allowed,
							Reason: func() string {
								if allowed {
									return "allowed"
								}
								return "fga_denied"
							}(),
						}},
					})
				})
				d.logger.Info(ctx, "model_resolved audit emitter wired into slot resolver")
			}
		}
	}

	// Agent-owner lookup on the callback service so DelegateToAgent
	// populates ExecutorUser on sub-agent dispatch. Uses Discover to
	// read the registered-component instance's Metadata map — the
	// ComponentMetadataOwnerUserID key is written at registration from
	// the caller's Identity.Subject. Returns empty string (graceful
	// degradation: EnrichSpan omits executor_user_id) when the registry
	// has no live instance, when the caller was anonymous at
	// registration, or when every instance lacks the metadata key
	// (e.g., pre-spec registrations).
	// Spec: llm-user-attribution-governance (Requirement 1.5).
	if d.callback != nil && d.compRegistry != nil {
		registry := d.compRegistry
		logger := d.logger.Slog()
		d.callback.SetAgentOwnerLookup(func(ctx context.Context, agentName string) (string, error) {
			if agentName == "" {
				return "", nil
			}
			tenant := auth.TenantStringFromContext(ctx)
			instances, err := registry.Discover(ctx, tenant, "agent", agentName)
			if err != nil {
				logger.WarnContext(ctx, "agent owner lookup: registry discover failed; executor_user_id omitted",
					slog.String("agent", agentName),
					slog.String("tenant", tenant),
					slog.String("error", err.Error()),
				)
				return "", nil
			}
			for _, inst := range instances {
				if owner, ok := inst.Metadata[component.ComponentMetadataOwnerUserID]; ok && owner != "" {
					return owner, nil
				}
			}
			return "", nil
		})
		d.logger.Info(ctx, "agent owner lookup wired on callback service (reads registry ComponentInfo.Metadata owner_user_id)")
	}

	// Wire daemon dependencies that require the Redis state client.
	// Tenant lifecycle (create/provision/deprovision) has moved out of the daemon
	// to the standalone gibson-tenant-operator; this block only wires the
	// remaining runtime services (CapabilityGrant, onboarding, mission drafts,
	// impersonation, and the API key store).
	if d.stateClient != nil {
		if redisClient, ok := d.stateClient.Client().(*goredis.Client); ok {
			_ = redisClient // retained for future wiring

			// Create apikeys.Store for the CreateAPIKey/ListAPIKeys/RevokeAPIKey RPCs.
			// API keys are stored in the dashboard Postgres instance.
			// Validation (authentication) of API keys has moved to the ext_authz service;
			// only management operations remain in the daemon.
			var apiKeyStore *apikeys.Store
			if d.dashboardDB != nil {
				var akErr error
				apiKeyStore, akErr = apikeys.New(d.dashboardDB)
				if akErr != nil {
					d.logger.Warn(ctx, "failed to create API key store", "error", akErr)
				}
			} else {
				d.logger.Warn(ctx, "API key store not wired: dashboard Postgres unavailable")
			}

			if apiKeyStore != nil {
				daemonSvc.WithAPIKeyStore(apiKeyStore)
				d.logger.Info(ctx, "API key store wired into DaemonServer (Postgres-backed)")
			}

			// Wire the CapabilityGrantService for the Agent Auth Protocol RPCs.
			// Requires dashboardDB (for store + apiKeys) and the FGA authorizer.
			if d.dashboardDB != nil && apiKeyStore != nil && d.authorizer != nil {
				agentStore := capabilitygrant.NewCapabilityGrantStore(d.dashboardDB)
				auditWriter := audit.NewWriter(d.dashboardDB, d.logger.Slog())
				auditWriter.Start(ctx)
				d.auditWriter = auditWriter
				auditQuery := audit.NewQuery(d.dashboardDB)
				// Wire the audit read path into ModelAccessService so the
				// dashboard's audit drawer renders real model_resolved
				// events. Spec: llm-user-attribution-governance R4.9.
				daemonSvc.WithAuditQuery(auditQuery)
				d.logger.Info(ctx, "audit query wired into DaemonServer for ListModelResolutionEvents")

				fgaBridge := capabilitygrant.NewFGABridge(d.authorizer, d.compRegistry, d.logger.Slog())

				capabilityGrantDispatcher := newWorkQueueDispatcher(
					component.NewRedisWorkQueue(d.stateClient.Client()),
				)

				capabilityGrantSvc := capabilitygrant.NewCapabilityGrantService(capabilitygrant.CapabilityGrantServiceConfig{
					Store:       agentStore,
					FGABridge:   fgaBridge,
					Authorizer:  d.authorizer,
					APIKeys:     apiKeyStore,
					AuditWriter: auditWriter,
					AuditQuery:  auditQuery,
					Dispatcher:  capabilityGrantDispatcher,
					Logger:      d.logger.Slog(),
				})
				daemonSvc.WithCapabilityGrantService(capabilityGrantSvc)
				d.logger.Info(ctx, "CapabilityGrantService wired into DaemonServer")
			} else {
				d.logger.Warn(ctx, "CapabilityGrantService not wired: requires dashboardDB, apiKeyStore, and authorizer")
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

	// Determine graceful stop timeout. Use half the configured shutdown timeout
	// (minimum 5s) so the drain phase has a bounded window while leaving the
	// other shutdown phases their share of the total budget.
	gracefulStopTimeout := 10 * time.Second
	if d.config != nil {
		if half := d.config.Shutdown.DrainTimeout / 2; half > 0 {
			gracefulStopTimeout = half
		}
	}

	// Spec: unified-identity-and-authorization Requirement 14.3.
	// Verify every gRPC method registered on this server has a
	// matching entry in the SDK-generated registry. A drift here
	// means the daemon would accept a method that ext-authz cannot
	// authorize — fail closed at startup so deployment is blocked.
	if err := assertRegistryCoverage(srv); err != nil {
		return nil, fmt.Errorf("daemon: registry coverage check failed: %w", err)
	}

	return &grpcSubsystem{
		srv:                 srv,
		listener:            listener,
		logger:              d.logger,
		gracefulStopTimeout: gracefulStopTimeout,
	}, nil
}

// assertRegistryCoverage walks every registered service+method on
// srv and verifies it has an entry in sdkregistry.Registry. Returns
// an error listing missing methods on mismatch. Called once at
// daemon startup; safe to skip for tests via the daemon test scaffold.
//
// Spec: unified-identity-and-authorization Requirement 14.3.
func assertRegistryCoverage(srv *grpc.Server) error {
	var missing []string
	for svcName, info := range srv.GetServiceInfo() {
		for _, m := range info.Methods {
			full := "/" + svcName + "/" + m.Name
			if _, ok := sdkregistry.Registry[full]; !ok {
				missing = append(missing, full)
			}
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf(
		"the following gRPC methods are registered on the daemon but missing from the SDK auth registry — regenerate sdk/auth/registry by running `make proto` in zero-day-ai/sdk and bumping the gibson SDK pin:\n  - %s",
		strings.Join(missing, "\n  - "),
	)
}

// loadHMACSecret reads the HMAC secret used to verify Envoy-signed
// x-gibson-identity-* headers.
//
// Resolution order:
//  1. File path from GIBSON_IDENTITY_HMAC_SECRET_PATH env (default /etc/gibson/hmac/secret)
//  2. Contents must be at least 32 bytes — fail-fast if shorter.
//
// The secret must never be logged.
func loadHMACSecret() ([]byte, error) {
	path := os.Getenv("GIBSON_IDENTITY_HMAC_SECRET_PATH")
	if path == "" {
		path = "/etc/gibson/hmac/secret"
	}
	secret, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read HMAC secret from %q: %w", path, err)
	}
	if len(secret) < 32 {
		return nil, fmt.Errorf("HMAC secret at %q is too short (%d bytes, minimum 32)", path, len(secret))
	}
	return secret, nil
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
// via auth.TenantStringFromContext; "default" is used when no tenant is present.
//
// When redisEventStream is nil (e.g., during unit tests that use a lightweight
// daemon without Redis) the implementation falls back to the in-process
// EventBus for full backwards compatibility.
func (d *daemonImpl) Subscribe(ctx context.Context, eventTypes []string, missionID string) (<-chan api.EventData, error) {
	d.logger.Info(ctx, "Subscribe called", "event_types", eventTypes, "mission_id", missionID)

	// Use Redis Streams when available: this is the production path.
	if d.redisEventStream != nil {
		tenant := auth.TenantStringFromContext(ctx)
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
// It extracts the tenant from the context (auth.TenantStringFromContext) and falls
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
		tenant := auth.TenantStringFromContext(ctx)
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
