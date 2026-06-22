package daemon

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver for database/sql
	"github.com/prometheus/client_golang/prometheus"
	goredis "github.com/redis/go-redis/v9"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/zeroroot-ai/gibson/internal/billing/entitlements"
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/gibson/internal/infra/config"
	dbredis "github.com/zeroroot-ai/gibson/internal/infra/database/redis"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/idempotency"
	"github.com/zeroroot-ai/gibson/internal/infra/observability"
	"github.com/zeroroot-ai/gibson/internal/infra/reconciler"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/budget"
	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/gibson/internal/platform/crypto"
	"github.com/zeroroot-ai/gibson/internal/platform/crypto/providers"
	"github.com/zeroroot-ai/gibson/internal/platform/secrets"
	"github.com/zeroroot-ai/gibson/internal/platform/secrets/jwtsource"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	pdataplane "github.com/zeroroot-ai/gibson/pkg/platform/dataplane"
	"github.com/zeroroot-ai/gibson/pkg/version"
	"github.com/zeroroot-ai/sdk/auth"
	healthhttp "github.com/zeroroot-ai/sdk/health/http"
	sdktypes "github.com/zeroroot-ai/sdk/types"
)

// targetStore is an interface for target data access. It is satisfied by
// *dbredis.RedisTargetDAO. Widened (target-management epic) to expose the
// full CRUD surface the target service drives; mission resolution uses the
// read methods only.
type targetStore interface {
	Get(ctx context.Context, id types.ID) (*types.Target, error)
	GetByName(ctx context.Context, name string) (*types.Target, error)
	Create(ctx context.Context, target *types.Target) error
	List(ctx context.Context, filter *types.TargetFilter) ([]*types.Target, error)
	Update(ctx context.Context, target *types.Target) error
	Delete(ctx context.Context, id types.ID) error
}

// AgentRuntimeState tracks runtime state for a single agent.
// This includes last heartbeat time and current task information.
type AgentRuntimeState struct {
	// LastHeartbeat is the last time the agent communicated with the daemon
	LastHeartbeat time.Time

	// CurrentTask is the ID of the task the agent is currently working on
	CurrentTask string

	// TaskStartTime is when the current task was assigned
	TaskStartTime time.Time
}

// daemonImpl is the concrete implementation of the Daemon interface.
//
// It manages the lifecycle of all Gibson daemon services and coordinates
// their startup, operation, and shutdown. The daemon owns:
//   - Redis-backed component registry for runtime service discovery
//   - Callback manager (harness callback server for agents)
//   - Redis daemon registration for client discovery
type daemonImpl struct {
	// config is the loaded Gibson configuration
	config *config.Config

	// homeDir is the resolved Gibson home directory (e.g. ~/.gibson).
	// Set via WithHomeDir option; falls back to cfg.Core.HomeDir, then $HOME/.gibson.
	homeDir string

	// injectedLogger is the slog.Logger provided via WithLogger option.
	// When nil, New falls back to slog.Default().
	injectedLogger *slog.Logger

	// metricsRegisterer is the Prometheus registerer for daemon metrics.
	// Defaults to prometheus.DefaultRegisterer.
	metricsRegisterer prometheus.Registerer

	// logger is the structured logger for daemon operations
	logger *observability.Logger

	// compRegistry is the Redis-backed component registry for runtime service discovery
	compRegistry component.ComponentRegistry

	// brainRegistry holds the per-tenant ECS brain engines (epic ecs-brain); the
	// WorldService read path reads through it. Lazily created at gRPC registration.
	brainRegistry *brain.Registry
	brainExecutor *brainExecutor
	// beliefProvider scores the belief field (ADR-0005). The pgmpy sidecar when
	// GIBSON_BELIEF_SIDECAR_URL is set, else the deterministic placeholder. Held
	// here so the mission launch path can pin its model version (ADR-0005 §5).
	beliefProvider brain.BeliefProvider

	// registryTenant is the tenant scope used for component registry discovery
	registryTenant string

	// registryAdapter provides component discovery and listing via Redis registry
	registryAdapter component.ComponentDiscovery

	// callback manages the harness callback server
	callback *harness.CallbackManager

	// eventBus manages event distribution to subscribers
	eventBus *EventBus

	// stateClient provides unified Redis client for state stores
	// This is initialized when GIBSON_USE_REDIS_STORES=true
	stateClient *state.StateClient

	// idempotencyStore deduplicates mutating RPCs by `idempotency_key`.
	// Set in buildGRPCServer when stateClient is a *redis.Client; nil
	// otherwise. Held on the daemon so future subsystems (e.g.
	// background workers replaying a paused mission) can reuse the
	// same store. Spec: gibson#228 / zeroroot-ai/.github#101.
	idempotencyStore idempotency.Store

	// missionAuthzStore tracks the owning user per run for component authz callback resolution.
	// One-code-path slice deploy#195: required; set unconditionally in the
	// Redis init phase of Start().
	missionAuthzStore mission.MissionAuthzStore

	// checkpointStore provides checkpoint persistence for pause/resume
	checkpointStore mission.CheckpointStore

	// missionService provides mission business logic operations
	missionService mission.MissionService

	// targetStore provides access to target persistence
	targetStore targetStore

	// infrastructure holds shared components (DAG executor, finding store, LLM registry)
	infrastructure *Infrastructure

	// missionManager manages mission lifecycle and execution
	missionManager *missionManager

	// missionsMu protects access to activeMissions map
	missionsMu sync.RWMutex

	// activeMissions tracks currently running missions by mission ID
	// The value is a context.CancelFunc that can be called to stop the mission
	activeMissions map[string]context.CancelFunc

	// agentStateMu protects access to agentState map
	agentStateMu sync.RWMutex

	// agentState tracks runtime state for each agent (last heartbeat, current task)
	// Key is agent name, value is AgentRuntimeState
	agentState map[string]*AgentRuntimeState

	// grpcServer is the gRPC server for client connections. This field exists for
	// backward-compat with DrainPhase; prefer grpcSubsystem for new code.
	grpcServer interface{}

	// grpcSubsystem owns the gRPC server lifecycle. Constructed by buildGRPCServer;
	// Serve(ctx) launched in a goroutine from Start. Wire into eg.Go in task 7.3.
	grpcSubsystem *grpcSubsystem

	// grpcAddr is the address the gRPC server listens on (added in Phase 3)
	grpcAddr string

	// redisDaemonInfo provides Redis-based daemon discovery and registration
	redisDaemonInfo *RedisDaemonInfo

	// healthServer provides HTTP health endpoints for Kubernetes probes.
	// Prefer healthSubsystem for lifecycle management; this field is kept for
	// backward-compat with stopServices cleanup.
	healthServer *healthhttp.Server

	// healthSubsystem wraps healthServer with a Serve(ctx) error lifecycle.
	// Constructed after all readiness checks are registered.
	healthSys *healthSubsystem

	// healthState tracks shutdown state for health endpoints
	healthState *healthStateManager

	// metricsSrv owns the daemon's :9090 mTLS Prometheus listener.
	// Constructed during Start when config.Metrics.Enabled=true; nil
	// otherwise. Lifecycle is driven by Serve(ctx) on its own goroutine
	// — cancellation of the parent ctx triggers a graceful shutdown.
	// Spec: security-hardening R20.
	metricsSrv *observability.MetricsServer

	// checkpointer manages mission checkpointing during graceful shutdown
	checkpointer *DaemonMissionCheckpointer

	// logTailer manages component log tailing with fsnotify
	logTailer *LogTailer

	// keyProvider provides access to encryption keys from secure storage
	keyProvider crypto.KeyProvider

	// cgMinter signs and verifies Capability-Grant bootstrap tokens (gibson#648,
	// ADR-0045). Constructed from keyProvider during Start; nil when no key
	// provider is configured, in which case the CG register endpoint reports 503.
	cgMinter *capabilitygrant.Minter

	// capabilityGrantSvc is hoisted out of buildGRPCServer so the pre-auth :8085
	// listener can serve the Capability-Grant host-registration endpoint
	// (gibson#648). Nil until buildGRPCServer wires it (needs the FGA authorizer).
	capabilityGrantSvc *capabilitygrant.CapabilityGrantService

	// connectorSandboxReconciler eagerly launches a per-tenant setec sandbox for
	// every connector a tenant has enabled (gibson#721). Constructed in
	// buildGRPCServer (needs the connector launcher + principal minter) and
	// started by Start alongside the catalog fan-out. Nil when connector
	// hosting is unavailable on this daemon.
	connectorSandboxReconciler *reconciler.ConnectorSandboxReconciler

	// credentialStore provides credential access with encryption
	credentialStore *DaemonCredentialStore

	// credentialHandler provides CRUD operations for credentials (used by dashboard API)
	credentialHandler *api.CredentialHandler

	// secretsRegistry is the broker registry; held on the daemon so /readyz can
	// call Health() for the system tenant (Task 30).
	secretsRegistry *secrets.Registry

	// secretsService is the secrets.Service; held so LLM provider re-registration
	// on config reload can pass it to NewProviderWithContext.
	secretsService *secrets.Service

	// configStore is the per-tenant broker configuration store. Held on the
	// daemon so grpc.go can construct the SDK admin v1 TenantAdminService
	// against it. nil when initBrokerStack failed to build it (no KEK or
	// dashboard Postgres) — grpc.go uses that as the "broker stack not
	// initialised" sentinel and registers the unavailable stub instead.
	// Spec: tenant-secrets-broker-completion (Task 10, 11).
	configStore *secrets.ConfigStore

	// brokerAuditWriter is the broker-stack audit writer. Held on the
	// daemon so grpc.go can pass it to admin.NewTenantAdminServer.
	// Spec: tenant-secrets-broker-completion (Task 10, 11).
	brokerAuditWriter *secrets.AuditWriter

	// brokerFactories maps each provider name (postgres/vault/awssm/gcpsm/
	// azurekv) to its ProviderFactory. Held on the daemon so grpc.go can
	// build the ProviderProbeFactory adapter for admin.NewTenantAdminServer.
	// Spec: tenant-secrets-broker-completion (Task 10, 11).
	brokerFactories map[string]secrets.ProviderFactory

	// vaultAuthCache caches Vault auth tokens per (tenant, provider) to prevent
	// auth churn during registry Reload events. Constructed in initBrokerStack.
	// Full per-call refresh wiring is a follow-up (see broker_init.go TODO).
	vaultAuthCache *secrets.AuthCache

	// vaultJWTSource mints SPIRE JWT-SVIDs the daemon stamps onto every
	// per-tenant Vault auth/jwt login. Wired via WithVaultJWTSource.
	// Defaults to jwtsource.DisabledJWTSource{} (any tenant whose broker
	// config selects AuthMethodJWT will get a clear "no source" error
	// until gibson#169 lands SPIREJWTSource).
	//
	// After initBrokerStack runs, this field is replaced by the JWTCache
	// wrapper so stampVaultJWTOnConfig reads from the cache instead of
	// calling the underlying SPIRE source on every Vault auth round-trip.
	//
	// Spec: gibson#167 PRD; ADR-0009 amendment (docs#34); gibson#321.
	vaultJWTSource jwtsource.JWTSource

	// vaultJWTCache is the running JWTCache that wraps d.vaultJWTSource.
	// Held separately so stopServices can call Close() without a type
	// assertion on d.vaultJWTSource. Nil when the source is a
	// DisabledJWTSource (no cache is started for the disabled stub).
	// Spec: gibson#321.
	vaultJWTCache *jwtsource.JWTCache

	// vaultJWTAudience is the SPIRE JWT-SVID audience the daemon requests
	// when minting tokens for Vault. It must match bound_audiences on the
	// per-tenant Vault role written by tenant-operator#148. Sourced from
	// GIBSON_DAEMON_VAULT_JWT_AUDIENCE in cmd/gibson/main.go; empty when
	// no real JWTSource is wired (DisabledJWTSource always errors before
	// audience matters).
	vaultJWTAudience string

	// llmConfigHandler provides LLM provider configuration management (used by dashboard API)
	llmConfigHandler *api.LLMConfigHandler

	// pluginAccessStore manages tenant opt-in and encrypted configuration for platform plugins.
	// Initialized alongside credentialStore when a KeyProvider is configured.
	// May be nil when no key provider is set (plugin access RPCs will return Unimplemented).
	pluginAccessStore component.ComponentAccessStore

	// toolAccessStore manages tenant opt-in for tools.
	// Initialized when a standalone Redis client is available.
	toolAccessStore *component.RedisToolAccessStore

	// agentAccessStore manages tenant opt-in for agents.
	// Initialized when a standalone Redis client is available.
	agentAccessStore *component.RedisAgentAccessStore

	// quotaManager enforces per-tenant resource quotas (missions, agents, memory).
	// Initialized after stateClient is available. May be nil until then; quota
	// enforcement is a no-op while nil.
	quotaManager *component.QuotaManager

	// entitlementsProvider is the ADR-0003 seam: it answers "what are this
	// tenant's limits?" for the OSS enforcers (QuotaManager, budget). The OSS
	// build wires the config-driven default; the commercial layer swaps in a
	// plan/subscription provider behind the same interface (gibson#798).
	entitlementsProvider entitlements.Provider

	// redisEventStream bridges the in-process EventBus to per-tenant Redis Streams.
	// It is initialised after stateClient is available. May be nil before that;
	// event publishing gracefully no-ops when nil.
	redisEventStream *RedisEventStream

	// startTime tracks when the daemon started
	startTime time.Time

	// schemaMigrationErr holds the last error returned by SchemaMigrator.Run.
	// A non-nil value means at least one migration had a constraint violation
	// on existing data (legacy rows missing tenant_id). The daemon continues
	// running but the /readyz probe returns Degraded until an operator cleans
	// the offending rows and restarts (or the migrator is re-run via CLI).
	// Liveness (/healthz) is NOT affected.
	schemaMigrationErr error

	// onRegistryReady is called during startup before other services are initialized.
	// This allows CLI to set up verbose logging during startup.
	onRegistryReady func()

	// authorizer is the authorization service client.
	// Set during initAuthorizer() in Start(). Always a real fgaAuthorizer
	// after startup — one-code-path slice deploy#195 deleted the noop
	// fallback. If FGA is unreachable, the daemon exits.
	authorizer authz.Authorizer

	// budgetEnforcer is the per-user/team/tenant LLM budget enforcer.
	// Wired in grpcSubsystem alongside the rate limiter when a Redis
	// client is available. Also used by the PeriodRolloverJob as the
	// backing counter source.
	// Spec: llm-user-attribution-governance (Requirement 3).
	budgetEnforcer budget.Enforcer

	// auditWriter is the tenant-scoped audit event stream writer.
	// Wired in grpcSubsystem when a dashboard Postgres pool is
	// available. Used by capability-grant RPCs and by the slot
	// resolver's onResolve callback for model_resolved events.
	auditWriter *audit.Writer

	// platformDB is the connection pool for the shared dashboard PostgreSQL instance.
	// It is used to read and write the tenant_provisioning table. After a
	// successful Start() this is always non-nil: initPlatformPostgres returns a
	// fatal error (gibson#246) when the connection, migrations, or schema gate
	// fail, so the daemon never serves traffic with platformDB=nil.
	platformDB *sql.DB

	// pool is the per-tenant data-plane connection pool introduced in Phase B/C/D.
	// It provides tenant-isolated Postgres, Redis, Neo4j, and vector store connections
	// via Pool.For(ctx, tenant). Nil when keyProvider is not configured (no security.key_provider).
	// Initialized after the keyProvider is resolved during Start().
	// Shutdown via pool.Close() in stopServices().
	pool datapool.Pool

	// graphBus is the in-process per-tenant graph-update bus.
	// Created during buildGRPCServer and shared between graphServer (for
	// WatchGraphUpdates SSE) and CreateMission (for NODE_ADDED publish).
	// Spec: dashboard-neo4j-crud-removal (Task 8).
	graphBus *graph.Bus

	// spiffeX509Source is the SPIFFE Workload API X.509 SVID source used by the
	// gRPC server for mTLS. It must be closed on daemon shutdown to release the
	// socket connection. Nil when SPIFFE is not configured.
	//
	// Initialized exactly once by initSPIFFEX509Source (called from Start before
	// the callback manager and the main gRPC server are wired) and shared by
	// both listeners. Spec: critical-tls-no-fallbacks Component 4.
	spiffeX509Source spiffeX509Closer

	// callbackPeerSVIDs is the parsed allowlist of peer SPIFFE IDs the harness
	// callback listener accepts, sourced from GIBSON_CALLBACK_PEER_SVIDS at
	// startup. Empty when SPIFFE is not configured. When SPIFFE IS configured
	// initSPIFFEX509Source fails-closed if this list is empty (critical-tls-no-fallbacks
	// Requirement 1.5). Each ID must be in cfg.Auth.SPIFFE.TrustDomain.
	callbackPeerSVIDs []spiffeid.ID

	// toolCatalogRefresher periodically launches gibson-runner --list-tools
	// in a Setec microVM and writes the resulting catalog to ComponentRegistry.
	// Nil when ToolRunner.Enabled is false. Started asynchronously during
	// daemon.Start so startup does not block on Setec health.
	toolCatalogRefresher *CatalogRefresher

	// reasoner is the singleton in-process ontology reasoner. Constructed
	// during initOntologyReasoner (called from newInfrastructure) and shared
	// by the intelligence service (for hierarchy-rollup queries) and the
	// component service (for RegisterExtension at enrollment time). Never nil
	// after a successful Start; may be nil during unit tests that bypass
	// newInfrastructure.
	reasoner *ontology.Reasoner
}

// spiffeX509Closer is the narrow interface for closing an X.509 source on shutdown.
// workloadapi.X509Source satisfies this interface.
type spiffeX509Closer interface {
	Close() error
}

// New creates a new daemon instance with the provided configuration and options.
//
// New initializes the daemon structure and prepares service managers but does not
// start any services. Call [Daemon.Start] to begin daemon operations.
//
// Parameters:
//   - cfg: The loaded Gibson configuration (must not be nil).
//     Returns an error wrapping [ErrInvalidConfig] if cfg is nil.
//   - opts: Zero or more functional options (see [WithLogger], [WithHomeDir],
//     [WithMetricsRegisterer]).
//
// Example:
//
//	cfg, err := config.NewConfigLoader(...).LoadWithDefaults(cfgPath)
//	if err != nil { ... }
//
//	d, err := daemon.New(cfg,
//	    daemon.WithLogger(slog.Default()),
//	    daemon.WithHomeDir("/opt/gibson"),
//	)
//	if err != nil { ... }
//	if err := d.Start(ctx); err != nil { ... }
func New(cfg *config.Config, opts ...Option) (Daemon, error) {
	if cfg == nil {
		return nil, fmt.Errorf("daemon: %w", ErrInvalidConfig)
	}

	// Apply options to a temporary impl to collect option values before
	// any expensive initialization.
	d := &daemonImpl{
		config:            cfg,
		activeMissions:    make(map[string]context.CancelFunc),
		agentState:        make(map[string]*AgentRuntimeState),
		metricsRegisterer: prometheus.DefaultRegisterer,
		// Default vault JWT source: DisabledJWTSource{}. cmd/gibson/main.go
		// replaces this with SPIREJWTSource once gibson#169 lands. Using
		// a typed-value sentinel rather than nil avoids nil-dereference
		// panics if a code path mistakenly forgets to wire the option;
		// instead callers see a clear ErrJWTSourceDisabled. Spec: gibson#168.
		vaultJWTSource: jwtsource.DisabledJWTSource{},
	}
	for _, opt := range opts {
		opt(d)
	}

	// Resolve home directory: option > cfg.Core.HomeDir > $HOME/.gibson > /var/lib/gibson
	if d.homeDir == "" {
		d.homeDir = resolveHomeDir(cfg)
	}

	// Resolve logger: WithLogger option > slog.Default() fallback.
	// Passing nil to WithLogger is treated the same as not calling WithLogger.
	var slogLogger *slog.Logger
	if d.injectedLogger != nil {
		slogLogger = d.injectedLogger
	} else {
		slogLogger = slog.Default()
	}
	// Wrap in observability.Logger so existing code that calls logger.Info(ctx, ...) works.
	logCfg := observability.ConfigFromEnv()
	logCfg.Component = "daemon"
	d.logger = observability.NewLoggerFromSlog(slogLogger, logCfg)

	// Initialize callback manager
	callbackMgr := harness.NewCallbackManager(harness.CallbackConfig{
		ListenAddress:    cfg.Callback.ListenAddress,
		AdvertiseAddress: cfg.Callback.AdvertiseAddress,
		Enabled:          cfg.Callback.Enabled,
	}, d.logger.Slog())

	d.callback = callbackMgr

	// Initialize event bus
	d.eventBus = NewEventBus(d.logger.Slog(), WithEventBufferSize(100))

	// Determine gRPC address from config or default.
	// Note: environment variable override (GIBSON_DAEMON_GRPC_ADDR) is intentionally
	// read at the entry point (cmd/gibson/main.go) and applied to cfg before New() is
	// called, so that environment reading stays in the process entry point.
	grpcAddr := cfg.Daemon.GRPCAddress
	if grpcAddr == "" {
		grpcAddr = "localhost:50002"
	}

	d.grpcAddr = grpcAddr
	d.healthState = newHealthStateManager()

	d.logger.Info(nil, "Redis stores will be initialized on startup",
		"note", "Gibson requires Redis for state persistence")

	return d, nil
}

// initSPIFFEX509Source opens the SPIRE Workload API X.509 source exactly once
// at daemon startup and stores it on d.spiffeX509Source so both the main gRPC
// listener (buildGRPCServer) and the harness callback listener (callback_server)
// can share a single Workload API connection. It also parses and validates the
// peer SVID allowlist from GIBSON_CALLBACK_PEER_SVIDS.
//
// Fail-closed semantics:
//   - If cfg.Auth.SPIFFE is nil (or WorkloadAPISocket is empty) the helper
//     returns nil without opening anything; the daemon may then bind only to
//     loopback addresses (rejectNonLoopbackWithoutSPIFFE enforces this on both
//     listeners as defense-in-depth).
//   - If SPIFFE IS configured but the Workload API socket is unreachable the
//     helper returns an error; the daemon refuses to start (critical-tls-no-fallbacks
//     Requirement 1.5 — no silent downgrade to plaintext).
//   - If SPIFFE IS configured but cfg.Auth.SPIFFE.EnvoyID is empty (and the env
//     var GIBSON_SPIFFE_ENVOY_ID is not set either) the helper returns an
//     error.
//   - If SPIFFE IS configured but GIBSON_CALLBACK_PEER_SVIDS is empty or
//     contains invalid SPIFFE IDs / IDs from a wrong trust domain, the helper
//     returns an error naming the chart values key the operator must populate.
//
// Idempotent: calling twice is a no-op the second time (the source is opened
// only when d.spiffeX509Source is nil). Closing happens in Close()/stopServices.
//
// Spec: critical-tls-no-fallbacks Component 4.
func (d *daemonImpl) initSPIFFEX509Source(ctx context.Context) error {
	if d.spiffeX509Source != nil {
		return nil // already initialized
	}
	if d.config.Auth.SPIFFE == nil || d.config.Auth.SPIFFE.WorkloadAPISocket == "" {
		// SPIFFE not configured — loopback-only mode is permitted; the per-listener
		// rejectNonLoopbackWithoutSPIFFE guards block any non-loopback bind.
		return nil
	}

	socketAddr := "unix://" + d.config.Auth.SPIFFE.WorkloadAPISocket
	source, err := workloadapi.NewX509Source(ctx,
		workloadapi.WithClientOptions(
			workloadapi.WithAddr(socketAddr),
		),
	)
	if err != nil {
		return fmt.Errorf(
			"SPIFFE workload API unreachable: %w (socket=%s); "+
				"daemon will not start without mTLS — "+
				"spec: critical-tls-no-fallbacks Requirement 1.5",
			err, d.config.Auth.SPIFFE.WorkloadAPISocket,
		)
	}

	// Validate the configured Envoy SVID — the daemon refuses to start without
	// it (mirrors the previous in-line validation at grpc.go:330-342 before
	// Component 4 hoisted the source open out of buildGRPCServer).
	envoyID := d.config.Auth.SPIFFE.EnvoyID
	if envoyID == "" {
		envoyID = os.Getenv("GIBSON_SPIFFE_ENVOY_ID")
	}
	if envoyID == "" {
		_ = source.Close()
		return fmt.Errorf(
			"SPIFFE mTLS is enabled but GIBSON_SPIFFE_ENVOY_ID is not set; " +
				"the daemon will not accept any mTLS connections. " +
				"Set GIBSON_SPIFFE_ENVOY_ID to the Envoy sidecar's SPIFFE SVID " +
				"(e.g. spiffe://zeroroot.ai/ns/gibson/sa/envoy). " +
				"Spec: admin-services-completion Requirement 6.1")
	}
	parsedEnvoyID, parseErr := spiffeid.FromString(envoyID)
	if parseErr != nil {
		_ = source.Close()
		return fmt.Errorf(
			"SPIFFE mTLS is enabled but GIBSON_SPIFFE_ENVOY_ID=%q is not a valid SPIFFE ID: %w",
			envoyID, parseErr)
	}

	// Validate trust domain: every peer SVID and the Envoy SVID must live under
	// the configured trust domain. An empty TrustDomain config is allowed for
	// backward compat — when set, mismatches are rejected.
	configuredTD := strings.TrimSpace(d.config.Auth.SPIFFE.TrustDomain)
	if configuredTD != "" {
		td, tdErr := spiffeid.TrustDomainFromString(configuredTD)
		if tdErr != nil {
			_ = source.Close()
			return fmt.Errorf(
				"cfg.Auth.SPIFFE.TrustDomain=%q is not a valid SPIFFE trust domain: %w",
				configuredTD, tdErr)
		}
		if !parsedEnvoyID.MemberOf(td) {
			_ = source.Close()
			return fmt.Errorf(
				"GIBSON_SPIFFE_ENVOY_ID=%q is not in the configured trust domain %q",
				envoyID, configuredTD)
		}
	}

	// ADR-0002: read the additional inbound-peer-SVID allow-list (today: the
	// tenant-operator). Comma-separated, each entry validated against the
	// trust domain. Empty is fine — Envoy is always accepted.
	if rawAllowed := strings.TrimSpace(os.Getenv("GIBSON_SPIFFE_ALLOWED_PEER_IDS")); rawAllowed != "" {
		td, tdErr := spiffeid.TrustDomainFromString(configuredTD)
		hasTD := tdErr == nil && configuredTD != ""
		for _, raw := range strings.Split(rawAllowed, ",") {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			id, err := spiffeid.FromString(raw)
			if err != nil {
				_ = source.Close()
				return fmt.Errorf(
					"GIBSON_SPIFFE_ALLOWED_PEER_IDS entry %q is not a parseable SPIFFE ID: %w",
					raw, err)
			}
			if hasTD && !id.MemberOf(td) {
				_ = source.Close()
				return fmt.Errorf(
					"GIBSON_SPIFFE_ALLOWED_PEER_IDS entry %q is not in the configured trust domain %q",
					raw, configuredTD)
			}
			d.config.Auth.SPIFFE.AllowedPeerIDs = append(d.config.Auth.SPIFFE.AllowedPeerIDs, raw)
		}
	}

	// Parse and validate the callback listener peer-SVID allowlist.
	rawPeers := strings.TrimSpace(os.Getenv("GIBSON_CALLBACK_PEER_SVIDS"))
	if rawPeers == "" {
		_ = source.Close()
		return fmt.Errorf(
			"SPIFFE mTLS is enabled but GIBSON_CALLBACK_PEER_SVIDS is empty; " +
				"the harness callback listener will not accept any peer. " +
				"Populate gibson.config.callback.spiffe.peerSvids in the chart values " +
				"with the SPIFFE IDs of agents/tools/dashboards that legitimately call " +
				"the harness callback listener. " +
				"Spec: critical-tls-no-fallbacks Component 4.")
	}

	peerSVIDs := make([]spiffeid.ID, 0, 4)
	for _, raw := range strings.Split(rawPeers, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		id, err := spiffeid.FromString(raw)
		if err != nil {
			_ = source.Close()
			return fmt.Errorf(
				"GIBSON_CALLBACK_PEER_SVIDS contains invalid SPIFFE ID %q: %w",
				raw, err)
		}
		if configuredTD != "" {
			td, _ := spiffeid.TrustDomainFromString(configuredTD)
			if !id.MemberOf(td) {
				_ = source.Close()
				return fmt.Errorf(
					"GIBSON_CALLBACK_PEER_SVIDS entry %q is not in the configured trust domain %q",
					raw, configuredTD)
			}
		}
		peerSVIDs = append(peerSVIDs, id)
	}
	if len(peerSVIDs) == 0 {
		_ = source.Close()
		return fmt.Errorf(
			"GIBSON_CALLBACK_PEER_SVIDS parsed to an empty allowlist after trimming; " +
				"populate gibson.config.callback.spiffe.peerSvids in the chart values")
	}

	d.spiffeX509Source = source
	d.callbackPeerSVIDs = peerSVIDs
	d.logger.Info(ctx, "SPIFFE X509 source initialized",
		"socket", d.config.Auth.SPIFFE.WorkloadAPISocket,
		"trust_domain", configuredTD,
		"envoy_id", envoyID,
		"callback_peer_count", len(peerSVIDs),
	)
	return nil
}

// resolveHomeDir derives the Gibson home directory from config and environment.
// Fallback: cfg.Core.HomeDir → $HOME/.gibson → /var/lib/gibson.
func resolveHomeDir(cfg *config.Config) string {
	if cfg.Core.HomeDir != "" {
		return cfg.Core.HomeDir
	}
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h + "/.gibson"
	}
	return "/var/lib/gibson"
}

// SetOnRegistryReady sets a callback that will be called during startup
// before other services are initialized. This is used by the CLI to set up
// verbose logging during startup.
func (d *daemonImpl) SetOnRegistryReady(fn func()) {
	d.onRegistryReady = fn
}

// Start begins the daemon process and all managed services.
//
// This method performs the following operations:
// 1. Check for existing daemon (prevent multiple instances)
// 2. Start registry manager
// 3. Start callback server
// 4. Write PID and daemon.json files
// 5. Block until context cancellation or shutdown signal
//
// Parameters:
//   - ctx: Context for daemon lifetime (cancellation triggers shutdown)
//
// Returns:
//   - error: Non-nil if startup fails or daemon already running
func (d *daemonImpl) Start(ctx context.Context) error {
	d.logger.Info(ctx, "starting Gibson daemon",
		"callback_enabled", d.config.Callback.Enabled,
		"strict_tenant", d.config.StrictTenant(),
	)

	// Record start time
	d.startTime = time.Now()

	// Per unified-identity-and-authorization Requirement 8.4 the
	// daemon no longer talks to ext-authz directly: ext-authz lives
	// upstream of the daemon and consults the SDK-rendered registry +
	// the daemon's published JWKS. The legacy outbound client is
	// removed. Capability-grant minting now happens locally via
	// internal/capabilitygrant.Minter.

	// Call the startup callback if set
	if d.onRegistryReady != nil {
		d.onRegistryReady()
	}

	// Initialize SPIFFE X.509 source once, before any listener is wired. Both
	// the main gRPC listener (buildGRPCServer) and the harness callback
	// listener (callback_server) consume d.spiffeX509Source. Fail-closed if
	// SPIFFE is configured but the Workload API socket / EnvoyID /
	// GIBSON_CALLBACK_PEER_SVIDS are missing or invalid.
	// Spec: critical-tls-no-fallbacks Component 4.
	if err := d.initSPIFFEX509Source(ctx); err != nil {
		return fmt.Errorf("init SPIFFE X509 source: %w", err)
	}
	// Wire the SPIFFE source and peer-SVID allowlist onto the callback
	// manager so that when callback.Start() runs the listener is wrapped in
	// SPIFFE mTLS. d.spiffeX509Source is *workloadapi.X509Source — type-assert
	// here for the manager's typed setter.
	if d.spiffeX509Source != nil {
		if src, ok := d.spiffeX509Source.(*workloadapi.X509Source); ok {
			d.callback.SetSPIFFE(src, d.callbackPeerSVIDs)
		} else {
			return fmt.Errorf(
				"daemon.spiffeX509Source is not a *workloadapi.X509Source (got %T); "+
					"unable to wire SPIFFE mTLS onto callback listener",
				d.spiffeX509Source)
		}
	}

	// Initialize StateClient and Redis stores (required for Gibson)
	d.logger.Info(ctx, "initializing Redis stores")

	// Initialize StateClient with retry logic (3 attempts with exponential backoff)
	stateClient, err := d.initStateClient(ctx)
	if err != nil {
		d.stopServices(ctx)
		return fmt.Errorf("failed to initialize StateClient (required): %w", err)
	}
	d.stateClient = stateClient

	// Initialize Redis event stream bridge for tenant-scoped event persistence.
	d.redisEventStream = NewRedisEventStream(stateClient, d.logger.Slog())
	d.logger.Info(ctx, "redis event stream initialized")

	// Initialize the per-tenant ECS brain registry (epic ecs-brain). Engines run
	// for the daemon's lifetime; the orchestrator event-bus adapter feeds each
	// tenant's World from its live mission event stream (ADR-0001 capture path).
	d.beliefProvider = resolveBeliefProvider()
	d.brainRegistry = brain.NewRegistry(ctx, append(
		[]brain.System{brain.BeliefSystem(d.beliefProvider)},
		brain.ExecutorSystems()..., // scheduler/condition/decider-gate/budget/retry/completion (gibson#851)
	)...)
	d.logger.Info(ctx, "ECS brain registry initialized", "belief_model", d.beliefProvider.Version())

	// Project each tenant's World into its Neo4j knowledge graph (ADR-0007): the
	// graph is a read-model of the World, written only by this projector. Runs
	// async (never in the brain tick) so Neo4j I/O never blocks the reducer; the
	// pool is resolved lazily since it is initialized after this point.
	go NewGraphProjector(
		d.brainRegistry,
		newNeo4jGraphWriter(func() datapool.Pool { return d.pool }),
		0, // default interval
		d.logger.WithComponent("graph-projector").Slog(),
	).Run(ctx)

	// Initialize Redis stores (mission/run stores have been migrated to the
	// per-tenant Pool path; only non-mission stores are initialized here).
	d.checkpointStore = mission.NewRedisCheckpointStore(stateClient)
	d.missionAuthzStore = mission.NewRedisMissionAuthzStore(stateClient.Client())
	d.targetStore = dbredis.NewRedisTargetDAO(stateClient)

	d.logger.Info(ctx, "Redis stores initialized successfully",
		"checkpoint_store", "RedisCheckpointStore",
		"mission_authz_store", "RedisMissionAuthzStore",
		"target_store", "RedisTargetDAO",
	)

	// Authorization Service phase — must run AFTER State Client and BEFORE Component Registry.
	// One-code-path slice deploy#195: FGA is a hard dependency.
	// Daemon exits 1 if FGA is unreachable at startup (no more noop fallback).
	if err := d.initAuthorizer(ctx); err != nil {
		d.stopServices(ctx)
		return fmt.Errorf("failed to initialize authorization service: %w", err)
	}

	// Note: envelope HMAC signing removed (admin-services-completion Req 6.4).
	// Work items now carry unsigned queue.AuthzContext (run_id + issued_at + ttl_seconds).
	// Authorization is fully covered by FGA tuples binding agent_principal to mission.

	// Dashboard PostgreSQL connection pool — runs AFTER Authorization Service and
	// BEFORE Component Registry. A connection failure is FATAL (gibson#246,
	// one-code-path discipline): the daemon refuses to boot without a usable
	// platform-postgres connection so downstream RPCs never mask a missing
	// connection behind misleading "not found" / "not implemented" errors.
	if err := d.initPlatformPostgres(ctx); err != nil {
		d.stopServices(ctx)
		return fmt.Errorf("failed to initialize platform-postgres: %w", err)
	}

	// Initialize Redis-backed component registry and registry adapter.
	// The component registry uses Redis for runtime service discovery (registrations with TTL).
	// The tenant is scoped per-daemon; use "default" as the tenant for the daemon's own discovery.
	compRegistry := component.NewRedisComponentRegistry(stateClient.Client(), 0)
	tenant := d.config.Registry.Namespace
	if tenant == "" {
		tenant = "default"
	}
	d.compRegistry = compRegistry
	d.registryTenant = tenant
	regAdapter := component.NewRegistryAdapter(compRegistry, tenant)
	d.registryAdapter = regAdapter
	d.logger.Info(ctx, "initialized Redis-backed component registry adapter", "tenant", tenant)

	// Wire the ECS brain as the mission execution engine (gibson#851): build the
	// concrete Dispatcher + DeciderLLM bindings over the component registry, and
	// install them onto every per-tenant engine via WireExecutor. Registered
	// before any engine is created (engines fault in lazily on the first event).
	if d.brainRegistry != nil {
		d.brainExecutor = newBrainExecutor(d.registryAdapter, d.logger.WithComponent("brain-executor").Slog())
		d.brainRegistry.OnEngine(func(e *brain.Engine) {
			brain.WireExecutor(ctx, e, brain.ExecutorDeps{
				Dispatcher: d.brainExecutor,
				Decider:    d.brainExecutor,
				Catalog:    d.brainExecutor.catalog,
			})
		})
		d.logger.Info(ctx, "ECS brain executor wired (brain is the mission engine)")
	}

	// Wire callback manager to registry adapter for external agent callback support
	regAdapter.SetCallbackManager(d.callback)
	d.logger.Info(ctx, "wired callback manager to registry adapter")

	// Share proto resolver between registry adapter and callback manager for unified caching
	d.callback.SetProtoResolver(regAdapter.GetResolver())
	d.logger.Info(ctx, "shared proto resolver with callback manager")

	// Initialize log tailer for component log streaming
	d.logTailer = NewLogTailer(ctx, 10000, *d.logger)
	d.logger.Info(ctx, "initialized log tailer")

	// Initialize mission service — reference-only after spec mission-api-only-cleanup.
	// Missions reference a registered target and mission definition by ID; inline
	// construction and YAML parsing are no longer supported.
	// The mission service uses a nil store here; actual mission persistence goes through
	// the per-tenant Pool (d.pool) acquired by individual RPC handlers.
	missionService := mission.NewMissionService(nil, nil) // stores wired via pool at handler level
	missionService.SetTargetStore(d.targetStore)
	d.missionService = missionService
	d.logger.Info(ctx, "initialized mission service (reference-only, pool-backed)")

	// Initialize QuotaManager for per-tenant resource enforcement.
	// The TenantScopedStore wraps stateClient so that all quota counters are
	// automatically namespaced by tenant — no cross-tenant data leakage.
	if d.stateClient != nil {
		tenantStoreCfg := &state.TenantStoreConfig{
			AuthMode:      d.config.Auth.Mode,
			DefaultTenant: "default",
			RequireTenant: d.config.Auth.Mode == "saas",
		}
		tenantStore := state.NewTenantScopedStore(d.stateClient, tenantStoreCfg)
		// platformDB is guaranteed non-nil here: initPlatformPostgres ran
		// earlier in Start() and is fatal on failure (gibson#246).
		//
		// Limits flow through the entitlements seam (ADR-0003): the OSS
		// default provider derives per-tenant limits from admin-set quota
		// config; the QuotaManager never reads plans/Stripe directly. The
		// commercial layer swaps in a plan/subscription provider behind the
		// same interface (gibson#798).
		d.entitlementsProvider = entitlements.NewConfigProvider(d.platformDB)
		d.quotaManager = component.NewQuotaManager(tenantStore, d.entitlementsProvider, d.logger.Slog())
		d.logger.Info(ctx, "quota manager initialized (entitlements provider: oss config-driven)")

		// Single-use sweep of legacy quota Redis keys deleted by spec
		// plans-and-quotas-simplification (quota:config / quota:memory /
		// quota:*:count). Gated by an internal sentinel; later boots are
		// no-ops. Failure is non-fatal — keys persist but production code
		// never reads them.
		if redisClient, ok := d.stateClient.Client().(*goredis.Client); ok {
			if err := component.CleanupLegacyQuotaKeys(ctx, redisClient, d.logger.Slog()); err != nil {
				d.logger.Warn(ctx, "legacy quota key cleanup failed (non-fatal)", "error", err)
			}
		}
	} else {
		d.logger.Warn(ctx, "quota manager not initialized - state client unavailable")
	}

	// Initialize infrastructure components (DAG executor, finding store, LLM registry, harness factory)
	// This must happen before creating the orchestrator because the orchestrator needs the harness factory
	d.logger.Info(ctx, "initializing infrastructure components")
	infra, err := d.newInfrastructure(ctx)
	if err != nil {
		d.stopServices(ctx)
		return fmt.Errorf("failed to initialize infrastructure: %w", err)
	}
	d.infrastructure = infra
	d.logger.Info(ctx, "infrastructure components initialized")

	// Catalog refresher: when toolRunner.enabled, start the goroutine that
	// periodically launches gibson-runner --list-tools via Setec and writes
	// ComponentRegistry entries. Runs asynchronously so daemon startup is
	// never blocked on Setec being healthy. See gibson-tool-runner spec
	// Requirements 2 + 3 for the full contract.
	if d.config.ToolRunner.Enabled {
		if err := d.startToolCatalogRefresher(ctx); err != nil {
			d.logger.Warn(ctx, "tool catalog refresher failed to start; sandboxed-tool catalog will not be dynamic",
				"error", err)
		}
	}

	// Configure callback service with TracerProvider for proxy span creation (from OTel stack)
	if infra.otelStack != nil && infra.otelStack.TracerProvider != nil {
		d.callback.SetTracerProvider(infra.otelStack.TracerProvider)
		d.logger.Info(ctx, "configured callback service with OTel tracer provider")
	}

	// Configure callback service with credential store for secure credential retrieval
	// Initialize KeyProvider from config if available
	if d.config.Security.KeyProvider != nil {
		d.logger.Info(ctx, "initializing key provider", "type", d.config.Security.KeyProvider.Type)
		keyProvider, err := providers.NewKeyProvider(d.config.Security.KeyProvider)
		if err != nil {
			d.logger.Warn(ctx, "failed to initialize key provider (credentials will not be available)",
				"error", err)
		} else {
			d.keyProvider = keyProvider

			// Construct the Capability-Grant Minter for bootstrap-token
			// mint/verify (gibson#648, ADR-0045). Best-effort: a failure only
			// disables the CG register endpoint, never the daemon.
			if minter, mErr := capabilitygrant.NewMinter(ctx, capabilitygrant.Config{
				Issuer:      cgJWTIssuer(),
				Audience:    cgJWTAudience(),
				KeyProvider: keyProvider,
				KeyID:       cgJWTKeyID(),
			}); mErr != nil {
				d.logger.Warn(ctx, "CG Minter init failed; capability-grant registration disabled", "error", mErr)
			} else {
				d.cgMinter = minter
			}

			// Phase D: instantiate the per-tenant data-plane Pool now that the
			// keyProvider is available. The pool provides tenant-isolated Postgres,
			// Redis, Neo4j, and vector store connections via Pool.For(ctx, tenant).
			// provisioningChecker is nil here — Phase F will wire the K8s client.
			// Without a checker, Pool.For bypasses the Tenant CRD readiness gate,
			// which is acceptable for Phase D (fail-open until F lands).
			poolCfg := datapool.DefaultConfig()
			if d.config.Redis.URL != "" {
				// Redis.URL is a full URL (redis://:pass@host:port); RedisAddr wants host:port only.
				if u, err := url.Parse(d.config.Redis.URL); err == nil && u.Host != "" {
					poolCfg.RedisAddr = u.Host
					poolCfg.RedisPassword, _ = u.User.Password()
				} else {
					poolCfg.RedisAddr = d.config.Redis.URL
				}
			}
			// Wire Neo4j per-tenant resolver based on TenantMode.
			// Spec: per-tenant-data-plane-completion Task 16 / Req 5.5.
			if d.config.GraphRAG.Neo4j.TenantMode == "multi-db" {
				// multi-db: shared Enterprise cluster, tenant isolation via named databases.
				// Credentials for the shared cluster are resolved from Vault (not config fields).
				poolCfg.Neo4jResolver = datapool.NewMultiDBResolver(
					d.config.GraphRAG.Neo4j.SharedClusterURI,
					"", // username: resolved at runtime from Vault
					"", // password: resolved at runtime from Vault
				)
				d.logger.Info(ctx, "neo4j resolver: multi-db mode configured",
					"shared_cluster_uri", d.config.GraphRAG.Neo4j.SharedClusterURI)
			} else {
				// instance mode: one StatefulSet per tenant, provisioned by the
				// tenant-operator. Credentials are read from the per-tenant Vault
				// namespace as a unified JSON payload (infra/neo4j).
				// Use a FuncSecretsReader so the resolver captures d.secretsService
				// lazily. initBrokerStack runs after NewPool and sets d.secretsService;
				// the resolver is only called at tenant-RPC time, well after startup.
				// Spec: per-tenant-data-plane-completion Task 13a (D3 amended).
				poolCfg.Neo4jResolver = datapool.NewInstanceResolver(
					datapool.FuncSecretsReader(func(ctx context.Context, name string) ([]byte, error) {
						if d.secretsService == nil {
							return nil, fmt.Errorf("instanceResolver: secrets broker not yet initialized")
						}
						return d.secretsService.Resolve(ctx, name)
					}),
				)
				d.logger.Info(ctx, "neo4j resolver: instance mode configured")
			}
			// Wire TenantPostgres admin coordinates into the pool config so that
			// pgxpool_per_tenant can connect to the per-tenant admin Postgres and
			// bootstrap per-tenant databases on demand.
			// Spec: per-tenant-data-plane-completion Req 2.1, 2.5.
			if d.config.TenantPostgres.Host != "" {
				port := d.config.TenantPostgres.Port
				if port == 0 {
					port = 5432
				}
				poolCfg.PostgresHost = fmt.Sprintf("%s:%d", d.config.TenantPostgres.Host, port)
				poolCfg.PostgresUser = d.config.TenantPostgres.AdminUsername
			} else {
				d.logger.Warn(ctx, "tenant_postgres.host is not configured; per-tenant Postgres bootstrap will be unavailable — set dataPlane.postgres.host in helm values")
			}

			// Wire a DSN resolver so pgxpool_per_tenant can obtain the
			// per-tenant Postgres DSN without depending on the
			// secrets-broker abstraction at the datapool layer
			// (gibson#106). The closure below is the ONLY place that
			// knows the DSN currently comes from Vault via the broker;
			// the datapool sees a narrow "give me a DSN for tenant"
			// contract and nothing more.
			//
			// Lazy resolution: secretsService is initialised AFTER
			// NewPool, so we capture d by reference and defer the
			// lookup until the first ForTenant call (same pattern as
			// the Neo4j FuncSecretsReader above).
			//
			// Spec: tenant-provisioning-unification-phase2 Requirement
			// 1.6 (Vault as the credential source); gibson#106 (layer
			// boundary between datapool and secrets broker).
			poolCfg.PostgresDSNResolver = datapool.PostgresDSNResolverFunc(func(ctx context.Context, tenant auth.TenantID) (string, string, error) {
				if d.secretsService == nil {
					return "", "", &datapool.NotProvisionedError{
						Tenant: tenant.String(),
						Reason: "postgres DSN resolver: secrets broker not yet initialized",
					}
				}
				// Push the tenant onto ctx so the broker's per-tenant
				// routing resolves to the correct Vault path.
				ctxWithTenant := auth.WithTenant(ctx, tenant)
				raw, getErr := d.secretsService.Resolve(ctxWithTenant, pdataplane.VaultPathInfraPostgres)
				if getErr != nil {
					return "", "", &datapool.NotProvisionedError{
						Tenant: tenant.String(),
						Reason: fmt.Sprintf("vault read of %s failed: %v", pdataplane.VaultPathInfraPostgres, getErr),
					}
				}
				var creds pdataplane.PostgresCredentials
				if jsonErr := json.Unmarshal(raw, &creds); jsonErr != nil {
					return "", "", fmt.Errorf("postgres DSN resolver: malformed PostgresCredentials JSON in Vault: %w", jsonErr)
				}
				if creds.DSN == "" {
					return "", "", &datapool.NotProvisionedError{
						Tenant: tenant.String(),
						Reason: "vault entry for infra/postgres has empty dsn field",
					}
				}
				return creds.DSN, creds.Database, nil
			})
			p, poolErr := datapool.NewPool(ctx, poolCfg, keyProvider, nil)
			if poolErr != nil {
				d.logger.Warn(ctx, "data-plane pool initialization failed (per-tenant store ops will be unavailable)",
					"error", poolErr)
			} else {
				d.pool = p
				d.logger.Info(ctx, "data-plane pool initialized (Phase D)")
			}

			// Phase 11 (secrets-broker, Task 29): initialize the broker stack now
			// that the key provider and data-plane pool are both available.
			// The ComponentService is built later in buildGRPCServer; we pass
			// nil for compSvc here and wire it separately in grpc.go after the
			// ComponentServiceServer is constructed.
			if p != nil {
				if brokerErr := d.initBrokerStack(ctx, nil); brokerErr != nil {
					d.logger.Warn(ctx, "broker stack initialization failed; credential RPCs will be unavailable",
						"error", brokerErr)
					// Non-fatal: daemon continues without credential operations.
				}
			} else {
				d.logger.Info(ctx, "data-plane pool not available — broker stack initialization skipped; credential RPCs unavailable")
			}

			// Plugin access store still uses Redis (plugin store migration is Phase D).
			if redisClient, ok := d.stateClient.Client().(*goredis.Client); ok {
				d.pluginAccessStore = component.NewRedisPluginAccessStore(
					redisClient,
					crypto.NewAESGCMEncryptor(),
					keyProvider,
					d.compRegistry,
					d.logger.Slog(),
				)
				d.logger.Info(ctx, "initialized plugin access store")

				// Patch the harness factory that was built before the key provider was
				// available. The factory stores config by value so we use SetPluginAccess
				// to inject the store without rebuilding the entire factory.
				if d.infrastructure != nil && d.infrastructure.harnessFactory != nil {
					if df, ok := d.infrastructure.harnessFactory.(*harness.DefaultHarnessFactory); ok {
						df.SetPluginAccess(d.pluginAccessStore)
						d.logger.Info(ctx, "wired plugin access store into harness factory")
					}
				}

				// Initialize tool and agent access stores.
				d.toolAccessStore = component.NewRedisToolAccessStore(redisClient, d.logger.Slog())
				d.agentAccessStore = component.NewRedisAgentAccessStore(redisClient, d.logger.Slog())
				d.logger.Info(ctx, "initialized tool and agent access stores")

			} else {
				d.logger.Warn(ctx, "plugin access store unavailable: Redis client is not standalone mode")
			}
		}
	} else {
		d.logger.Info(ctx, "credential store disabled - no key provider configured (set security.key_provider in config)")
	}

	// Configure callback service with event bus for tool/LLM event publishing
	if d.eventBus != nil {
		d.callback.SetEventBus(NewEventBusAdapter(d.eventBus))
		d.logger.Info(ctx, "configured callback service with event bus")
	}

	// Wire the Observe RPC to the per-tenant brain (ADR-0007): typed agent
	// observations become Timeline events the reducer folds into the World, where
	// scope-relative identity (ADR-0002) resolves entities + topology. Scope is
	// derived from mission context.
	if d.brainRegistry != nil {
		d.callback.SetObservationSink(ingestObservation(d.brainRegistry, d.registryTenant))
		d.logger.Info(ctx, "wired callback Observe RPC to the ECS brain")
	}

	// GraphLoader is no longer wired at startup. Domain node persistence via the
	// graph is handled per-call by GraphRAGBridgeAdapter (spec graphrag-tenant-scope).

	// Configure callback service with QueueManager for Redis-based tool execution
	if d.infrastructure.redisClient != nil {
		queueMgr := harness.NewQueueManagerWithClient(d.infrastructure.redisClient, d.logger.Slog())
		d.callback.SetQueueManager(queueMgr)
		d.logger.Info(ctx, "configured callback service with QueueManager for Redis-based tool execution")
	}

	// Configure callback service with MissionOperator so agents can create, run,
	// wait for, list, cancel, and retrieve results of sub-missions via the harness
	// callback RPC surface. The missionHarnessAdapter lazily resolves the
	// missionManager on first lifecycle call, so it is safe to wire before
	// ensureMissionManager() runs.
	// Wire mission operator adapter unconditionally — the adapter now delegates
	// to the pool-backed mission manager rather than the legacy global store.
	missionAdapter := newMissionHarnessAdapter(d)
	missionOperator := harness.NewMissionOperatorAdapter(missionAdapter)
	d.callback.SetMissionManager(missionOperator)
	d.logger.Info(ctx, "configured callback service with MissionOperator adapter")

	// Configure callback service with authz store for component authorization callbacks.
	// The adapter bridges mission.MissionAuthzStore → harness.RunAuthzLookup to break
	// the import cycle (harness→mission→eval→harness).
	// One-code-path slice deploy#195: missionAuthzStore is wired unconditionally
	// during Redis init; no more nil-guard.
	d.callback.SetAuthzStore(newMissionAuthzStoreAdapter(d.missionAuthzStore))
	d.logger.Info(ctx, "configured callback service with mission authz store")

	// Wire the FGA Authorizer into the callback service for component-level authz.
	// One-code-path slice deploy#195: d.authorizer is always a real FGA client
	// after initAuthorizer (the noop fallback was deleted), so no more nil-guard.
	d.callback.SetComponentAuthorizer(d.authorizer)
	d.logger.Info(ctx, "configured callback service with FGA component authorizer")
	d.callback.SetComponentRegistry(d.compRegistry)

	// Wire the OTel metrics recorder into the Authorize handler so that each
	// component authz decision increments gibson_component_authz_total.
	if rec := d.GetOTelMetricsRecorder(); rec != nil {
		d.callback.SetComponentAuthzMetrics(rec)
		d.logger.Info(ctx, "configured callback service with component authz metrics recorder")
	}

	// Mission crash recovery is now lazy and per-tenant: the datapool's
	// RecoveryHook fires on the first Pool.For dial of each tenant per
	// process, transitioning any missions left `running` by the previous
	// daemon process to `paused`. This replaces the eager startup
	// enumeration of Tenant CRDs that crashed the daemon on 2026-05-19
	// (testa123 incident). See ADR-0023 and gibson#207.
	d.logger.Info(ctx, "lazy mission recovery armed; will fire per-tenant on first Pool.For dial")

	// Initialize mission checkpointer for graceful shutdown.
	// The checkpointer uses the pool to acquire per-tenant connections for mission updates.
	if d.stateClient != nil && d.stateClient.Client() != nil {
		d.checkpointer = NewDaemonMissionCheckpointer(
			d.stateClient.Client(),
			func() map[string]context.CancelFunc {
				d.missionsMu.RLock()
				defer d.missionsMu.RUnlock()
				// Return a copy to avoid holding the lock
				missions := make(map[string]context.CancelFunc)
				for k, v := range d.activeMissions {
					missions[k] = v
				}
				return missions
			},
			d.pool,
			d.logger,
		)
		d.logger.Info(ctx, "mission checkpointer initialized")

		// Discover checkpoints from previous shutdown
		d.discoverCheckpoints(ctx)
	} else {
		d.logger.Warn(ctx, "mission checkpointer not initialized - state client not available")
	}

	// Start callback server via Serve (blocking lifecycle in goroutine).
	if d.config.Callback.Enabled {
		d.logger.Info(ctx, "starting callback server")
		// Probe start synchronously so any port-in-use error surfaces here
		// before the daemon continues initializing.
		if err := d.callback.Start(ctx); err != nil {
			d.stopServices(ctx)
			return fmt.Errorf("failed to start callback server: %w", err)
		}
		// Run Serve in the background so it blocks until ctx.Done() then
		// calls Stop(). The Stop() call from ConnectionPhase is idempotent.
		go func() {
			<-ctx.Done()
			d.callback.Stop()
		}()
	}

	// Migration-pending observation moved out of the daemon per ADR-0023.
	// The tenant-operator's Tenant reconciler now emits metricMigrationPending
	// per Tenant (follow-up to S6 of gibson#202 PRD). The daemon no longer
	// enumerates Tenant CRDs at startup — the same eager loop that crashed
	// on 2026-05-19 (testa123 incident). See gibson#208 for the operator
	// emission slice.

	// Build and start gRPC server.
	d.logger.Info(ctx, "starting gRPC server", "address", d.grpcAddr)
	grpcSys, err := d.buildGRPCServer(ctx)
	if err != nil {
		d.stopServices(ctx)
		return fmt.Errorf("failed to build gRPC server: %w", err)
	}
	d.grpcSubsystem = grpcSys
	d.grpcServer = grpcSys.srv // retained for DrainPhase in stopServices
	go func() {
		if serveErr := grpcSys.Serve(ctx); serveErr != nil {
			d.logger.Error(ctx, "gRPC server error", "error", serveErr)
		}
	}()

	// Start health server
	// Health port defaults to 8080, can be overridden via config or GIBSON_HEALTH_PORT env var
	healthPort := d.config.Health.Port
	if healthPort == 0 {
		healthPort = 8080
	}
	// Override with environment variable if set
	if envPort := os.Getenv("GIBSON_HEALTH_PORT"); envPort != "" {
		if port, err := fmt.Sscanf(envPort, "%d", &healthPort); err == nil && port == 1 {
			// Successfully parsed environment variable
		}
	}

	d.logger.Info(ctx, "starting health server", "port", healthPort)
	d.healthServer = healthhttp.NewServer(&healthhttp.Config{
		Port:         healthPort,
		CheckTimeout: 10 * time.Second, // Allow more time for DNS resolution in K8s
	})

	// Register readiness checks for all dependencies
	// Redis check - use function wrapper to avoid interface type mismatch
	if d.stateClient != nil && d.stateClient.Client() != nil {
		redisClient := d.stateClient.Client()
		d.healthServer.RegisterReadinessCheck("redis", healthhttp.RedisPingFunc(func(ctx context.Context) (string, error) {
			return redisClient.Ping(ctx).Result()
		}))
		d.logger.Debug(ctx, "registered redis readiness check")
	}

	// No shared Neo4j readiness check. Per-tenant Neo4j connectivity is verified
	// lazily by Pool.For(tenant) at request time (spec graphrag-tenant-scope).

	// Register shutdown state check - this signals Kubernetes to stop routing traffic during shutdown
	d.healthServer.RegisterReadinessCheck("shutdown", d.healthState.CheckFunc())
	d.logger.Debug(ctx, "registered shutdown state readiness check")

	// Register Neo4j schema migration readiness check.
	// Fails (Degraded, not Unhealthy) when the migrator encountered a
	// constraint violation — meaning legacy rows without tenant_id exist.
	// Liveness is NOT affected. Only readiness fails so the pod is removed
	// from service endpoints without triggering a restart loop.
	d.healthServer.RegisterReadinessCheck("neo4j_schema_migrations", func(_ context.Context) sdktypes.HealthStatus {
		if d.schemaMigrationErr != nil {
			return sdktypes.NewDegradedStatus(
				"Neo4j schema migration has constraint violations on existing data — "+
					"legacy rows missing tenant_id must be cleaned up; "+
					"see metric gibson_graphrag_tenant_constraint_violations_total",
				nil,
			)
		}
		return sdktypes.NewHealthyStatus("Neo4j schema migrations applied")
	})
	d.logger.Debug(ctx, "registered neo4j schema migrations readiness check")

	// Register key provider health check if available
	if d.keyProvider != nil {
		keyProvider := d.keyProvider
		d.healthServer.RegisterReadinessCheck("key_provider", func(ctx context.Context) sdktypes.HealthStatus {
			status := keyProvider.Health(ctx)
			// Convert internal types.HealthStatus to SDK types.HealthStatus
			if status.IsHealthy() {
				return sdktypes.NewHealthyStatus(status.Message)
			} else if status.IsDegraded() {
				return sdktypes.NewDegradedStatus(status.Message, nil)
			}
			return sdktypes.NewUnhealthyStatus(status.Message, nil)
		})
		d.logger.Debug(ctx, "registered key provider readiness check")
	}

	// Register broker health check for /readyz (Task 30, secrets-broker Phase 11).
	//
	// SYSTEM-TENANT RULE: if the system-tenant (Postgres) broker is unreachable,
	// flip readiness to 503 — the daemon cannot serve any tenant secrets.
	//
	// PER-TENANT RULE: per-tenant broker outages must NOT flip readiness; they
	// only emit the gibson_secrets_broker_health{tenant,provider} Prometheus gauge
	// so SRE can see which tenant's backend is unhealthy. The system-tenant health
	// check is the sole gating condition here.
	if d.secretsRegistry != nil {
		brokerReg := d.secretsRegistry
		sysTenant := auth.SystemTenant

		// Background goroutine emits per-tenant health gauges periodically.
		// It iterates only the cached registry entries (tenants that have done
		// at least one secret operation since daemon start) to avoid enumerating
		// all tenants on every scrape cycle.
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(30 * time.Second):
					healthMap := brokerReg.Health(ctx)
					for tenant, healthErr := range healthMap {
						var gaugeValue float64 // 0 = healthy
						if healthErr != nil {
							gaugeValue = 1 // unhealthy
						}
						// Use the provider name via the tenant string as label proxy.
						// Full (tenant, provider) labeling requires the registry to
						// expose which provider is active per tenant; for now we label
						// by tenant + "cached". A future Task 34 auth-token cache
						// enhancement can surface the provider name properly.
						brokerHealthGauge.WithLabelValues(tenant.String(), "cached").Set(gaugeValue)
					}
				}
			}
		}()

		d.healthServer.RegisterReadinessCheck("secrets_broker", func(checkCtx context.Context) sdktypes.HealthStatus {
			// Probe system tenant health. The Postgres provider's Health() checks
			// connectivity (nil = healthy). Any non-nil error means the daemon's
			// own secrets backend is unreachable; flip readiness to unhealthy.
			healthMap := brokerReg.Health(checkCtx)
			sysTenantErr, ok := healthMap[sysTenant]
			if !ok {
				// System tenant not yet in the cache (no secret operation issued yet) —
				// attempt an eager probe by forcing a For() call which will populate the
				// cache and run Health on the next tick. For now, report healthy.
				return sdktypes.NewHealthyStatus("broker: system tenant not yet accessed; assuming healthy")
			}
			if sysTenantErr != nil {
				return sdktypes.NewUnhealthyStatus("broker: system-tenant provider unhealthy: "+sysTenantErr.Error(), nil)
			}
			return sdktypes.NewHealthyStatus("broker: system-tenant provider healthy")
		})
		d.logger.Debug(ctx, "registered secrets broker readiness check (system-tenant gates /readyz; per-tenant emits gauge only)")
	}

	// Register FGA readiness check. After one-code-path slice deploy#195
	// d.authorizer is always a real FGA client (no more noop fallback) —
	// startup would have failed if FGA was unreachable. The nil-guard is
	// kept defensively for parallel-test daemon constructions that skip
	// initAuthorizer.
	// Uses a 10s TTL cached result to avoid hammering FGA on every scrape.
	// Returns Degraded (not Unhealthy) so Kubernetes removes the pod from
	// service endpoints without triggering a restart.
	if d.authorizer != nil {
		a := d.authorizer
		var (
			cacheMu      sync.Mutex
			cachedAt     time.Time
			cachedResult sdktypes.HealthStatus
		)
		const fgaCacheTTL = 10 * time.Second

		d.healthServer.RegisterReadinessCheck("authz_fga", func(ctx context.Context) sdktypes.HealthStatus {
			cacheMu.Lock()
			if time.Since(cachedAt) < fgaCacheTTL && !cachedAt.IsZero() {
				result := cachedResult
				cacheMu.Unlock()
				return result
			}
			cacheMu.Unlock()

			// Probe FGA: both allowed=true and allowed=false are valid — we only
			// care that the RPC succeeds, meaning FGA is reachable.
			_, probeErr := a.Check(ctx, "user:_system", "platform_operator", "system_tenant:_system")
			var result sdktypes.HealthStatus
			if authz.IsUnavailable(probeErr) || authz.IsTimeout(probeErr) {
				result = sdktypes.NewDegradedStatus("authz: FGA unreachable: "+probeErr.Error(), nil)
			} else {
				result = sdktypes.NewHealthyStatus("authz: FGA reachable")
			}

			cacheMu.Lock()
			cachedAt = time.Now()
			cachedResult = result
			cacheMu.Unlock()

			return result
		})
		d.logger.Debug(ctx, "registered authz FGA readiness check")
	}

	// Wire platform-clients/readiness probe implementations into the existing
	// /readyz handler (audit P1 finding, zeroroot-ai/.github#101).
	//
	// Each probe produced by newPlatformReadinessProbes() is registered with
	// the "pc_" prefix so it appears distinctly in /readyz JSON output without
	// conflicting with the existing "authz_fga" SDK probe.
	//
	// The local readinessProber interface matches pcreadiness.Probe without
	// requiring daemon.go to import platform-clients/readiness directly.
	type readinessProber interface {
		Name() string
		Check(ctx context.Context) error
	}
	for _, probe := range d.newPlatformReadinessProbes() {
		var p readinessProber = probe
		name := p.Name()
		d.healthServer.RegisterReadinessCheck("pc_"+name, func(checkCtx context.Context) sdktypes.HealthStatus {
			if err := p.Check(checkCtx); err != nil {
				return sdktypes.NewDegradedStatus(
					"platform-clients/readiness probe '"+name+"' failed: "+err.Error(),
					nil,
				)
			}
			return sdktypes.NewHealthyStatus("platform-clients/readiness probe '" + name + "' passed")
		})
	}
	d.logger.Debug(ctx, "registered platform-clients readiness probes (pc_postgres, pc_authz_fga)")

	// Start health server via healthSubsystem.
	d.healthSys = newHealthSubsystem(d.healthServer, d.logger)
	go func() {
		if err := d.healthSys.Serve(ctx); err != nil {
			d.logger.Warn(ctx, "health subsystem error (non-fatal)", "error", err)
		}
	}()

	// Start the unauthenticated native-login bootstrap server (gibson#623). It
	// publishes {issuer, client_id, scopes} for `gibson login` (and any future
	// native client) device-grant bootstrap, plus the Capability-Grant
	// discovery + host-registration + per-kid key endpoints (gibson#648).
	// Best-effort: a failure here never takes the daemon down.
	//
	// The CG register + key routes mount only when both the Minter and the
	// CapabilityGrantService exist (the subsystem nil-checks the concrete
	// pointers); otherwise those routes are absent.
	go func() {
		if err := newNativeLoginSubsystem(nativeLoginConfigFromEnv(), d.logger, d.cgMinter, d.capabilityGrantSvc).Serve(ctx); err != nil {
			d.logger.Warn(ctx, "native-login subsystem error (non-fatal)", "error", err)
		}
	}()

	// Start the authz-registry mTLS listener so ext-authz fetches the daemon's
	// compiled-in authz policy at runtime instead of a separately-versioned OCI
	// artifact (deploy#852). The daemon is the single source of truth, so the
	// version-pin skew that silently default-denied newly-added RPCs is gone.
	// Served only over SPIFFE mTLS to an explicit reader allow-list; skipped
	// (with a warning) when no SPIFFE source is available, in which case
	// ext-authz uses its file fallback. A misconfigured reader allow-list is
	// fatal here (fail-closed, never silently-open).
	if x509Src, ok := d.spiffeX509Source.(*workloadapi.X509Source); ok && x509Src != nil {
		authzRegSys, arErr := newAuthzRegistrySubsystem(x509Src, d.logger)
		if arErr != nil {
			return fmt.Errorf("authz-registry subsystem: %w", arErr)
		}
		if authzRegSys != nil {
			go func() {
				if err := authzRegSys.Serve(ctx); err != nil {
					d.logger.Warn(ctx, "authz-registry subsystem error (non-fatal)", "error", err)
				}
			}()
		}
	} else {
		d.logger.Warn(ctx, "authz-registry mTLS endpoint not started: no SPIFFE X.509 source (ext-authz will use its file fallback)")
	}

	// Start :9090 mTLS metrics listener (Spec security-hardening R20 / Week-2
	// task 18 — Option (a), daemon-owned listener). Fail fast if cert
	// material is missing — there is no plaintext fallback.
	if d.config.Metrics.Enabled {
		metricsAddr := d.config.Metrics.ListenAddress
		if metricsAddr == "" {
			port := d.config.Metrics.Port
			if port == 0 {
				port = 9090
			}
			metricsAddr = fmt.Sprintf(":%d", port)
		}
		metricsSrv, mErr := observability.NewMetricsServer(observability.MetricsServerConfig{
			Addr:         metricsAddr,
			CertPath:     d.config.Metrics.TLS.CertPath,
			KeyPath:      d.config.Metrics.TLS.KeyPath,
			ClientCAPath: d.config.Metrics.TLS.ClientCAPath,
			Handler:      observability.DefaultPrometheusHandler(),
		})
		if mErr != nil {
			d.stopServices(ctx)
			return fmt.Errorf("failed to construct metrics TLS listener: %w", mErr)
		}
		d.metricsSrv = metricsSrv
		d.logger.Info(ctx, "starting metrics TLS listener",
			"addr", metricsSrv.Addr(),
			"cert", d.config.Metrics.TLS.CertPath)
		go func() {
			if err := metricsSrv.Serve(ctx); err != nil {
				d.logger.Error(ctx, "metrics TLS listener error", "error", err)
			}
		}()
	} else {
		d.logger.Info(ctx, "metrics listener disabled (config.metrics.enabled=false)")
	}

	// Prepare daemon info for registration
	pid := os.Getpid()
	info := &DaemonInfo{
		PID:         pid,
		StartTime:   d.startTime,
		GRPCAddress: d.grpcAddr,
		Version:     version.Version,
	}

	// Register daemon info in Redis for daemon discovery
	if d.stateClient == nil || d.stateClient.Client() == nil {
		d.stopServices(ctx)
		return fmt.Errorf("Redis state client not available - Redis required for daemon coordination")
	}

	d.redisDaemonInfo = NewRedisDaemonInfo(d.stateClient.Client(), d.logger)
	if err := d.redisDaemonInfo.Register(ctx, info); err != nil {
		d.stopServices(ctx)
		return fmt.Errorf("failed to register daemon info in Redis: %w", err)
	}

	d.logger.Info(ctx, "daemon started successfully",
		"pid", pid,
		"instance_id", d.redisDaemonInfo.InstanceID(),
		"callback_endpoint", d.callback.CallbackEndpoint(),
	)

	// NetworkPolicy presence audit moved out of the daemon per ADR-0023.
	// Observing the cluster's NetworkPolicy resources is a control-plane
	// concern; it belongs in the tenant-operator's startup audit or a
	// chart-managed CronJob, not in the daemon's hot path. Tracked at
	// gibson#209.

	// Start the catalog-fan-out reconciler — ensures every platform_enabled
	// catalog item has a tenant_enabled tuple on every existing tenant so
	// new marketplace publishes propagate without a Tenant-CR edit. Runs
	// best-effort; failures are logged, not fatal. Spec R4 AC 7.
	if d.authorizer != nil {
		fanout := reconciler.NewCatalogFanout(reconciler.CatalogFanoutConfig{
			Authorizer: d.authorizer,
			Logger:     d.logger.Slog(),
		})
		catalogSys := newCatalogRefresherSubsystem(fanout)
		go func() {
			if err := catalogSys.Serve(ctx); err != nil {
				d.logger.Warn(ctx, "catalog refresher subsystem error (non-fatal)", "error", err)
			}
		}()
		d.logger.Info(ctx, "catalog fan-out reconciler started (60s interval)")
	}

	// Start the connector on-enable sandbox reconciler — eagerly launches a
	// per-tenant setec sandbox for every connector a tenant has enabled, so an
	// enabled shared/BYO connector is warm before the tenant's agents need it
	// (gibson#721/#722). Built in buildGRPCServer; nil when hosted connector
	// launch is unavailable on this daemon. Runs best-effort; failures are
	// logged per-connector, not fatal.
	if d.connectorSandboxReconciler != nil {
		go d.connectorSandboxReconciler.Run(ctx)
		d.logger.Info(ctx, "connector on-enable sandbox reconciler started (30s interval)")
	}

	// Block until context cancellation (signal.NotifyContext in main() handles SIGTERM/SIGINT).
	// The second-signal force-exit goroutine is in cmd/gibson/main.go.
	d.logger.Info(ctx, "daemon running (press Ctrl+C to stop)")
	<-ctx.Done()
	d.logger.Info(ctx, "shutdown signal received, stopping daemon")

	return d.Stop(context.Background())
}

// Stop gracefully shuts down the daemon and all managed services.
//
// This method performs the following operations:
// 1. Stop callback server (no new agent callbacks)
// 2. Stop registry manager (Redis cleanup)
// 3. Remove PID and daemon.json files
//
// The method is idempotent and safe to call multiple times.
//
// Parameters:
//   - ctx: Context with timeout for shutdown operations
//
// Returns:
//   - error: Non-nil if shutdown encounters errors
func (d *daemonImpl) Stop(ctx context.Context) error {
	d.logger.Info(ctx, "stopping Gibson daemon")

	// Create shutdown context with timeout if the passed context doesn't have one
	shutdownCtx := ctx
	if ctx.Err() == nil {
		// Use a reasonable timeout for graceful shutdown (10 seconds)
		var cancel context.CancelFunc
		shutdownCtx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}

	// Stop services
	d.stopServices(shutdownCtx)

	// Deregister from Redis
	if d.redisDaemonInfo != nil {
		d.logger.Info(ctx, "deregistering daemon from Redis")
		if err := d.redisDaemonInfo.Deregister(shutdownCtx); err != nil {
			d.logger.Warn(ctx, "failed to deregister from Redis", "error", err)
		}
	}

	d.logger.Info(ctx, "daemon stopped successfully")
	return nil
}

// Run bootstraps all daemon subsystems and blocks until ctx is cancelled or a
// subsystem returns a non-nil error.
//
// This is the preferred entry point for production use (called by cmd/gibson/main.go).
// Internally it delegates to Start(ctx) for now; tasks 7.3–7.7 will migrate each
// subsystem to a native Serve(ctx) error implementation and remove that delegation.
//
// When ctx is cancelled cleanly (e.g. SIGTERM via signal.NotifyContext), Run
// returns nil. Any startup failure propagates as a non-nil error.
func (d *daemonImpl) Run(ctx context.Context) error {
	return d.Start(ctx)
}

// stopServices stops all daemon services using the ShutdownCoordinator.
//
// This is a helper method used by Stop() and error cleanup paths.
// It executes shutdown phases in order through the coordinator to ensure clean shutdown.
func (d *daemonImpl) stopServices(ctx context.Context) {
	// Stop all running missions before coordinator
	d.missionsMu.Lock()
	if len(d.activeMissions) > 0 {
		d.logger.Info(ctx, "stopping active missions", "count", len(d.activeMissions))
		for missionID, cancel := range d.activeMissions {
			d.logger.Info(ctx, "cancelling mission", "mission_id", missionID)
			cancel()
		}
		// Clear the map
		d.activeMissions = make(map[string]context.CancelFunc)
	}
	d.missionsMu.Unlock()

	// Close log tailer before coordinator
	if d.logTailer != nil {
		d.logger.Info(ctx, "closing log tailer")
		if err := d.logTailer.Close(); err != nil {
			d.logger.Warn(ctx, "error closing log tailer", "error", err)
		}
		d.logTailer = nil
	}

	// Create and execute shutdown coordinator with all phases
	coordinator := NewShutdownCoordinator(d.config.Shutdown, d.logger)

	// Register shutdown phases in execution order

	// Phase 1: Set health endpoint to unhealthy
	if d.healthState != nil {
		coordinator.RegisterPhase(NewHealthPhase(d.healthState, d.logger))
	}

	// Phase 2: Drain in-flight requests
	if d.grpcServer != nil {
		if srv, ok := d.grpcServer.(interface{ GracefulStop() }); ok {
			coordinator.RegisterPhase(NewDrainPhase(srv, d.config.Shutdown.DrainTimeout, d.logger))
		}
	}

	// Phase 3: Checkpoint running missions (already stopped above, but maintain phase)
	if d.checkpointer != nil {
		coordinator.RegisterPhase(NewCheckpointPhase(d.checkpointer, d.config.Shutdown.CheckpointTimeout, d.logger, coordinator.metrics))
	}

	// Phase 4: Notify and disconnect agents
	if d.callback != nil {
		agentNotifier := NewDaemonAgentNotifier(d.callback, d.config.Shutdown.AgentTimeout, d.logger)
		coordinator.RegisterPhase(NewAgentPhase(agentNotifier, d.config.Shutdown.AgentTimeout, d.logger, coordinator.metrics))
	}

	// Phase 5: Close all connections.
	// Concrete-pointer-to-interface conversion: a nil concrete pointer stored in an
	// interface{} creates a non-nil interface (type descriptor present, data nil).
	// The nil check inside ConnectionPhase would pass but Close() would panic on the
	// nil receiver. Guard both stateClient and credentialStore so ConnectionPhase
	// always receives a true nil interface value when the resource was never opened.
	var stateClientCloser interface{ Close() error }
	if d.stateClient != nil {
		stateClientCloser = d.stateClient
	}
	var credStoreCloser interface{ Close() error }
	if d.credentialStore != nil {
		credStoreCloser = d.credentialStore
	}
	coordinator.RegisterPhase(NewConnectionPhase(
		d.infrastructure,
		stateClientCloser,
		d.callback,
		d.eventBus,
		nil, // registry stopper: was etcd; now nil (Redis cleanup handled by redisDaemonInfo.Deregister)
		credStoreCloser,
		d.logger,
	))

	// Execute shutdown phases
	if err := coordinator.Shutdown(ctx); err != nil {
		d.logger.Warn(ctx, "shutdown coordinator encountered errors", "error", err)
	}

	// Health server is already stopped by healthSubsystem.Serve on ctx cancellation.
	// Clear references for GC.
	d.healthSys = nil
	d.healthServer = nil

	// Clear gRPC server references (already stopped by DrainPhase / grpcSubsystem.Serve).
	d.grpcServer = nil
	d.grpcSubsystem = nil

	// Close dashboard PostgreSQL connection pool.
	if d.platformDB != nil {
		d.logger.Info(ctx, "closing dashboard PostgreSQL connection pool")
		if err := d.platformDB.Close(); err != nil {
			d.logger.Warn(ctx, "error closing dashboard PostgreSQL pool", "error", err)
		}
		d.platformDB = nil
	}

	// Close Phase D data-plane pool.
	if d.pool != nil {
		d.logger.Info(ctx, "closing data-plane pool")
		if err := d.pool.Close(); err != nil {
			d.logger.Warn(ctx, "error closing data-plane pool", "error", err)
		}
		d.pool = nil
	}

	// Close SPIFFE X509Source to release the Workload API socket connection.
	if d.spiffeX509Source != nil {
		d.logger.Info(ctx, "closing SPIFFE X509Source")
		if err := d.spiffeX509Source.Close(); err != nil {
			d.logger.Warn(ctx, "error closing SPIFFE X509Source", "error", err)
		}
		d.spiffeX509Source = nil
	}

	// Stop the JWTCache background goroutine (gibson#321).
	if d.vaultJWTCache != nil {
		d.logger.Info(ctx, "closing JWT source cache")
		if err := d.vaultJWTCache.Close(); err != nil {
			d.logger.Warn(ctx, "error closing JWT source cache", "error", err)
		}
		d.vaultJWTCache = nil
	}
}

// initPlatformPostgres establishes the dashboard PostgreSQL connection pool and
// runs the tenant_provisioning schema migration.
//
// Invariant (gibson#246, one-code-path discipline): the daemon fails to start
// when platform-postgres is unreachable. There is no degraded mode — a missing
// or unhealthy platform-postgres connection is a terminal startup error so that
// downstream RPCs never return misleading "not found" / "not implemented"
// errors that mask a missing connection. If a deployment genuinely needs to run
// without platform-postgres, that is a deployment-shape mistake to surface in
// the bootstrap saga, not a fallback the daemon silently absorbs.
//
// On any failure this returns a non-nil error; Start() propagates it so the
// process exits non-zero and Kubernetes restarts with exponential backoff.
func (d *daemonImpl) initPlatformPostgres(ctx context.Context) error {
	pgCfg := d.config.PlatformPostgres

	// A missing host is a fatal configuration error: the chart always wires
	// platform-postgres-rw (deploy require_platform_postgres cross-chart
	// check), so an empty host means the deployment is misconfigured.
	if pgCfg.Host == "" {
		return fmt.Errorf("platform-postgres host is not configured: the daemon cannot start without a usable dashboard Postgres connection (set dashboard_postgres.host)")
	}

	// Apply defaults.
	if pgCfg.Port == 0 {
		pgCfg.Port = 5432
	}
	if pgCfg.SSLMode == "" {
		pgCfg.SSLMode = "require"
	}
	if pgCfg.MaxConns == 0 {
		pgCfg.MaxConns = 5
	}
	if pgCfg.Database == "" {
		pgCfg.Database = "gibson_dashboard"
	}

	dsn := fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		pgCfg.Host,
		pgCfg.Port,
		pgCfg.Database,
		pgCfg.Username,
		pgCfg.Password,
		pgCfg.SSLMode,
	)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("platform-postgres: failed to open connection pool (host=%s db=%s sslmode=%s): %w",
			pgCfg.Host, pgCfg.Database, pgCfg.SSLMode, err)
	}

	db.SetMaxOpenConns(pgCfg.MaxConns)

	// Verify connectivity with a short timeout.
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return fmt.Errorf("platform-postgres: ping failed (host=%s port=%d db=%s sslmode=%s): %w",
			pgCfg.Host, pgCfg.Port, pgCfg.Database, pgCfg.SSLMode, err)
	}

	d.logger.Info(ctx, "dashboard PostgreSQL: connection pool established",
		"host", pgCfg.Host,
		"port", pgCfg.Port,
		"database", pgCfg.Database,
		"max_conns", pgCfg.MaxConns,
	)

	// Phase 6.1 (deploy-architecture-refactor): run any pending platform
	// migrations before serving traffic. This replaces the Helm
	// pre-install platform-db-migrate Job. On failure the daemon exits
	// non-zero; K8s restarts with backoff. Set SKIP_MIGRATIONS=true
	// for emergencies.
	if err := runPlatformMigrations(ctx, db, d.logger.Slog()); err != nil {
		_ = db.Close()
		return fmt.Errorf("platform-postgres: migrations failed (host=%s db=%s): %w",
			pgCfg.Host, pgCfg.Database, err)
	}

	// Spec gibson-postgres-migrations Requirement 5: after running
	// migrations, assert version >= embedded MAX to catch any residual
	// skew (e.g. SKIP_MIGRATIONS was set, or the source driver returned
	// an unexpected version).
	if err := assertPlatformSchemaVersion(ctx, db, d.logger.Slog()); err != nil {
		_ = db.Close()
		return fmt.Errorf("platform-postgres: schema gate failed after migrations (host=%s db=%s): %w",
			pgCfg.Host, pgCfg.Database, err)
	}

	d.platformDB = db

	return nil
}

// status returns the current daemon status and health information.
//
// This is the internal status method that returns the daemon.DaemonStatus type.
// For the gRPC API implementation, see Status() in grpc.go.
//
// Returns:
//   - *DaemonStatus: Complete daemon status information
//   - error: Non-nil if status check fails
func (d *daemonImpl) status() (*DaemonStatus, error) {
	// Check if daemon is running by checking Redis registration
	running := d.redisDaemonInfo != nil
	pid := os.Getpid()

	// Calculate uptime
	var uptime string
	if running && !d.startTime.IsZero() {
		duration := time.Since(d.startTime)
		uptime = formatDuration(duration)
	}

	// Query mission counts from database
	totalMissions, activeMissions := d.queryMissionCounts(context.Background())

	// Determine Redis endpoint for status reporting
	redisAddr := d.config.Redis.URL

	// Build status struct
	status := &DaemonStatus{
		Running:      running,
		PID:          pid,
		StartTime:    d.startTime,
		Uptime:       uptime,
		GRPCAddress:  d.grpcAddr,
		RegistryType: "redis",
		RegistryAddr: redisAddr,
		CallbackAddr: d.callback.CallbackEndpoint(),
		AgentCount:   d.countRegisteredAgents(context.Background()),
		MissionCount: totalMissions,
		ActiveCount:  activeMissions,
	}

	return status, nil
}

// countRegisteredAgents returns the number of agent-kind components currently
// registered in the component registry. Returns 0 on error or if the registry
// is unavailable.
func (d *daemonImpl) countRegisteredAgents(ctx context.Context) int {
	if d.compRegistry == nil {
		return 0
	}
	agents, err := d.compRegistry.DiscoverAll(ctx, d.registryTenant, "agent")
	if err != nil {
		d.logger.Warn(ctx, "failed to count registered agents", "error", err)
		return 0
	}
	return len(agents)
}

// formatDuration formats a duration into a human-readable string.
//
// Examples:
//   - 1h 30m 45s
//   - 2m 15s
//   - 45s
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// discoverCheckpoints scans Redis for mission checkpoints from a previous shutdown.
// It logs discovered checkpoints but does not automatically resume them.
// This allows operators to inspect and manually resume missions as needed.
func (d *daemonImpl) discoverCheckpoints(ctx context.Context) {
	if d.checkpointer == nil {
		d.logger.Debug(ctx, "checkpointer not available, skipping checkpoint discovery")
		return
	}

	checkpoints, err := d.checkpointer.ListCheckpoints(ctx)
	if err != nil {
		d.logger.Warn(ctx, "failed to discover checkpoints", "error", err)
		return
	}

	if len(checkpoints) == 0 {
		d.logger.Info(ctx, "no suspended missions found")
		return
	}

	d.logger.Info(ctx, "discovered suspended missions from previous shutdown",
		"count", len(checkpoints))

	// Log each checkpoint for operator visibility
	for _, missionID := range checkpoints {
		checkpoint, err := d.checkpointer.GetCheckpoint(ctx, missionID)
		if err != nil {
			d.logger.Warn(ctx, "failed to load checkpoint details",
				"mission_id", missionID,
				"error", err)
			continue
		}

		d.logger.Info(ctx, "suspended mission available for resumption",
			"mission_id", missionID,
			"checkpoint_id", checkpoint.ID,
			"created_at", checkpoint.CreatedAt,
			"label", checkpoint.Label)
	}
}

// GetSuspendedMissions returns a list of mission IDs that have checkpoints from a previous shutdown.
// These missions can be resumed using the appropriate API or CLI commands.
//
// Returns:
//   - []types.ID: List of mission IDs with available checkpoints
//   - error: Non-nil if checkpoint discovery fails
func (d *daemonImpl) GetSuspendedMissions(ctx context.Context) ([]types.ID, error) {
	if d.checkpointer == nil {
		return nil, fmt.Errorf("checkpointer not available")
	}

	return d.checkpointer.ListCheckpoints(ctx)
}

// RequestShutdown initiates graceful shutdown of the daemon.
// This is called by the gRPC Shutdown endpoint to allow remote shutdown requests.
//
// Parameters:
//   - ctx: Context with timeout for shutdown operations
//   - force: If true, skip graceful drain and shutdown immediately
//   - timeoutSeconds: Maximum time to wait for graceful shutdown
//
// Returns:
//   - error: Non-nil if shutdown fails
func (d *daemonImpl) RequestShutdown(ctx context.Context, force bool, timeoutSeconds int32) error {
	d.logger.Info(ctx, "shutdown requested",
		"force", force,
		"timeout_seconds", timeoutSeconds,
	)

	// Send SIGTERM to ourselves to trigger graceful shutdown
	// This uses the same signal handling path as Ctrl+C
	process, err := os.FindProcess(os.Getpid())
	if err != nil {
		return fmt.Errorf("failed to find own process: %w", err)
	}

	// Send SIGTERM to trigger graceful shutdown
	if err := process.Signal(os.Interrupt); err != nil {
		return fmt.Errorf("failed to send interrupt signal: %w", err)
	}

	return nil
}

// CredentialHandler returns the credential handler for dashboard API operations.
// Returns nil if the credential handler was not initialized (missing key provider).
func (d *daemonImpl) CredentialHandler() *api.CredentialHandler {
	return d.credentialHandler
}

// RefreshToolCatalog signals the catalog refresher on this replica to
// immediately poll every configured gibson-tool-runner image for --list-tools
// output. When the refresher is not running (feature flag off, or this
// replica is not the refresh leader), returns queued=false with a
// human-readable message rather than an error — the admin caller always
// wants to know the outcome without interpreting gRPC status codes.
func (d *daemonImpl) RefreshToolCatalog(ctx context.Context) (bool, string, error) {
	if d.toolCatalogRefresher == nil {
		return false, "tool catalog refresher is not running on this replica (tool_runner.enabled=false or follower)", nil
	}
	if err := d.toolCatalogRefresher.RefreshNow(ctx); err != nil {
		return false, err.Error(), nil
	}
	return true, "refresh signal queued; next tick will ingest the latest --list-tools output from every configured runner image", nil
}

// LLMConfigHandler returns the LLM config handler for dashboard API operations.
// Returns nil if the LLM config handler was not initialized.
func (d *daemonImpl) LLMConfigHandler() *api.LLMConfigHandler {
	return d.llmConfigHandler
}

// buildTenantPostgresDSN constructs a pgxpool-compatible DSN for the admin
// Postgres pool used by the Neo4j instanceResolver's endpoint registry.
//
// Returns an empty string when TenantPostgres.Host is not set.
// Spec: per-tenant-data-plane-completion Task 16.
func buildTenantPostgresDSN(cfg *config.Config) string {
	if cfg.TenantPostgres.Host == "" {
		return ""
	}
	port := cfg.TenantPostgres.Port
	if port == 0 {
		port = 5432
	}
	db := cfg.TenantPostgres.AdminDatabase
	if db == "" {
		db = "postgres"
	}
	sslMode := cfg.TenantPostgres.SSLMode
	if sslMode == "" {
		sslMode = "disable"
	}
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		cfg.TenantPostgres.AdminUsername,
		cfg.TenantPostgres.AdminPassword,
		cfg.TenantPostgres.Host,
		port,
		db,
		sslMode,
	)
}
