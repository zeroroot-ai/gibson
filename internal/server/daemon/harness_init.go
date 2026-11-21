// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/middleware"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/gibson/internal/platform/modelgate"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
	"go.opentelemetry.io/otel/trace"
)

// newHarnessFactory creates a new HarnessFactory with all required dependencies.
//
// The factory is configured with middleware for observability (tracing, logging, events)
// and all necessary registries for agent execution.
//
// Middleware Selection:
// The factory uses OTel middleware when available for observability integration.
//
// Returns:
//   - harness.HarnessFactoryInterface: Configured factory ready to create harnesses
//   - error: Non-nil if factory creation fails
func (d *daemonImpl) newHarnessFactory(ctx context.Context) (harness.HarnessFactoryInterface, error) {
	d.logger.Debug(ctx, "creating harness factory")

	// Configure OTel middleware when OTel stack is available
	var middlewareChain middleware.Middleware
	if d.infrastructure != nil && d.infrastructure.otelStack != nil {
		d.logger.Info(ctx, "using OpenTelemetry tracing middleware for harness operations")

		// OTel middleware will be configured per-harness with agentSpan
		// Here we just note that OTel is available - actual middleware is created
		// when each harness is instantiated with its specific agent context
		// The middleware factory will check for otelStack availability
		middlewareChain = nil // Configured per-harness in agent execution context
	} else {
		d.logger.Info(ctx, "no tracing middleware configured (OTel disabled)")
	}

	// Build a Redis-backed WorkQueue for remote component dispatch.
	// This enables the harness to route tool/plugin calls to pull-based workers
	// (components registered in ComponentRegistry without a direct gRPC endpoint).
	var workQueue component.WorkQueue
	if d.stateClient != nil {
		workQueue = component.NewRedisWorkQueue(d.stateClient.Client())
		d.logger.Info(ctx, "initialized Redis work queue for remote component dispatch")
	}

	// Per-tenant LLM provider scoping (gibson#526): resolve each mission's slot
	// manager + registry from the calling tenant's configured providers.
	// Shared with the ComponentService LLM adapter (grpc.go) so an enrolled
	// component's completion resolves through the identical path as a mission.
	slotManagerForTenant := d.newSlotManagerForTenant()

	// Build HarnessConfig with all required dependencies
	config := harness.HarnessConfig{
		// Slot resolution reads the provider records of the tenant.
		SlotManagerForTenant: slotManagerForTenant,

		// Component registries
		// ComponentInstallRegistry field was removed in plugin-runtime Spec 2 Phase 7;
		// plugin dispatch goes through ComponentRegistry + WorkQueue
		// (PluginInvokeService, see internal/platform/component/plugin_dispatch.go).
		ComponentAccess: d.componentAccessStore, // nil when no KeyProvider configured; harness skips opt-in checks

		// ComponentAuthorizer gates AGENT dispatch on can_execute (gibson#1595).
		// The SAME FGA authorizer the callback service gets (daemon.go
		// SetComponentAuthorizer), so a dispatch-time check matches the
		// invocation-time check. initAuthorizer runs before newInfrastructure,
		// so d.authorizer is always a real FGA client here.
		ComponentAuthorizer: d.authorizer,

		// ComponentRegistry enables tenant-scoped discovery for CallToolProto and QueryPlugin.
		// RegistryAdapter reads registry entries only. The daemon dials no component:
		// work reaches a component through the work queue or a sandbox (ADR-0110).
		// EnvelopeSigner removed (admin-services-completion Req 6.4): AuthzContext is now
		// populated unsigned; FGA tuples binding agent_principal to mission are the auth gate.
		ComponentRegistry: d.compRegistry,

		// Knowledge-graph reads for a dispatched agent. The same querier
		// ComponentService gets, so both surfaces answer identically; nil when
		// the daemon cannot serve graph reads, and the harness then reports
		// ErrKnowledgeUnavailable rather than an empty result.
		GraphRAGQuerier: func() component.GraphRAGQuerier { return d.graphragQuerier },

		// What a dispatched tool is acting against (gibson#485). A provider, not
		// a value: d.targetStore is assigned during the Redis init phase, after
		// this factory is built, so reading it here would capture nil forever.
		TargetFacts: d.targetFactsLookup,

		// The VALUE of a secret a mission declared (gibson#485). The daemon
		// resolves it as itself, so no FGA relation reaches the component and
		// secret.can_resolve stays plugin-only.
		MissionSecrets:  d.missionSecretsStore,
		RegistryAdapter: d.registryAdapter,

		// The files of an Agent Skill that a skill-script call places in its
		// sandbox, and the deny list of the mission that the call checks.
		SkillFiles: func() harness.SkillFileStore {
			if store := d.agentSkillStore(); store != nil {
				return store
			}
			return nil
		},
		MissionDenyList: d.storedBlockedTools,
		WorkQueue:       workQueue,

		// Finding storage: the findings table of the database of the tenant.
		// The pool starts after this factory, so the store reads it on first use.
		FindingStore: harness.NewPostgresFindingStore(func() datapool.Pool { return d.pool }),

		// Observability
		Logger: d.logger.WithComponent("harness").Slog(),
		Tracer: func() trace.Tracer {
			if d.infrastructure != nil && d.infrastructure.otelStack != nil {
				return d.infrastructure.otelStack.TracerProvider.Tracer("gibson.harness")
			}
			return nil // No tracer available - harness will use no-op tracer
		}(),
		Metrics: nil, // Defaulted to no-op

		// Middleware chain for cross-cutting concerns
		Middleware: middlewareChain,

		// Memory wrapper for tracing

		// Run-provenance: agent delegations fold into the World; the graph
		// projector (sole writer, ADR-0107) materializes :AgentRun + DELEGATED_TO.
		DelegationSink: ingestDelegation(d.brainRegistry),

		// A submitted finding gets a graph node with the ID of its Postgres row.
		FindingSink: ingestHarnessFinding(d.brainRegistry),
	}
	// Queue-dispatched agents call back through HarnessCallbackService; their
	// harness must be findable by (mission, agent), as a direct-gRPC agent's is
	// (gibson#1633). A nil manager must stay a nil interface.
	if d.callback != nil {
		config.CallbackManager = d.callback
	}
	// The minter is created after this factory (daemon Start), so hand the
	// factory a getter; each harness reads it when it is built.
	config.CGMinter = func() *capabilitygrant.Minter { return d.cgMinter }

	// Sandboxed tool executor (Setec microVM dispatch). The sandbox fleet is
	// required (ADR-0142): every published image is built with
	// -tags=setec_integration, and a failed executor build stops the start.
	// The no-op constructor of an un-tagged build returns (nil, nil), which
	// logs a warning; per-call failures surface at tool invocation time
	// (design Requirement 5.4).
	if d.config != nil {
		if err := d.config.Sandbox.RequireSetec(); err != nil {
			return nil, fmt.Errorf("daemon start: %w", err)
		}
		sandboxTracer := func() trace.Tracer {
			if d.infrastructure != nil && d.infrastructure.otelStack != nil {
				return d.infrastructure.otelStack.TracerProvider.Tracer("gibson.sandboxed")
			}
			return nil
		}()
		sandboxLogger := d.logger.WithComponent("sandboxed").Slog()
		// Field-100 DiscoveryResult from a sandboxed tool response is folded into
		// the tenant's World, which the graph projector materializes (ADR-0107 /
		// ADR-0112). This used to be a permanently-nil variable with a comment
		// explaining why — the ingest path was imported everywhere and wired
		// nowhere, so sandboxed discoveries were silently discarded (gibson#1266).
		sbxDiscovery := d.newDiscoveryProcessor()
		execer, err := NewSetecSandboxedExecutor(d.config.Sandbox, daemonSVIDSource{d: d}, sandboxTracer, sandboxLogger, sbxDiscovery, newLiveEventPublisher(d.liveAgents))
		if err != nil {
			// The sandbox fleet is required (ADR-0142): a daemon that cannot
			// build its executor does not start.
			return nil, fmt.Errorf("sandboxed tool executor: %w", err)
		} else if execer == nil {
			d.logger.Warn(ctx, "the setec_integration build tag is not set; sandboxed tool calls will fail at invocation time (rebuild with -tags=setec_integration to enable)")
		} else {
			config.SandboxedExecutor = execer
			d.logger.Info(ctx, "sandboxed tool executor wired",
				"setec_address", d.config.Sandbox.Setec.Address,
				"catalog_source", "component_registry")
		}

		// Ephemeral agent launcher (ADR-0116 / gibson#1596). Same setec
		// frontend as the tool executor; an untrusted agent is launched as a
		// per-mission-run sandbox instead of denied. The no-op constructor for
		// the un-tagged build returns (nil, nil), so an untrusted agent stays
		// denied fail-closed when setec_integration is not built.
		// The platform edge CA every sandboxed agent and member is handed
		// (gibson#13): read once, from the chart's projection of the Envoy
		// TLS Secret, and empty when the edge chains to public roots.
		platformCA := platformCAPEM(d.config.Sandbox.Setec.PlatformCAFile, sandboxLogger)
		launcher, launchErr := NewSetecAgentLauncher(d.config.Sandbox, daemonSVIDSource{d: d}, sandboxTracer, sandboxLogger, newLiveEventPublisher(d.liveAgents), platformCA)
		if wire, warn := agentLauncherWiring(launcher, launchErr); !wire {
			d.logger.Warn(ctx, warn, "error", launchErr)
		} else {
			config.AgentLauncher = launcher
			config.Forks = d.forks
			// AgentLaunchSpecResolver reads a sandboxed agent's launch spec
			// (image, sandbox class, egress ceiling, model) from its signed
			// catalog manifest (gibson#1597, ADR-0136/0116). An agent with no
			// manifest is a clear error, so the harness denies the dispatch
			// fail-closed rather than launching an unknown image.
			// Tenant credentials a manifest declares (gibson#1621) come from the
			// per-tenant provider store. Without pool/secrets the source is nil
			// and such a dispatch is refused at resolve time, never launched.
			// The pool and the broker stack are initialized AFTER this factory
			// (daemon Start), so the store is resolved on first dispatch, not here.
			credentials := &providerCredentialSource{resolve: d.tenantCredentialResolver()}
			// A manifest may declare a minimum context window (gibson#1692).
			// It is checked against the SAME per-tenant slot resolution a
			// mission uses, so a dispatched agent and a mission never disagree
			// about what the tenant's model is. Reusing slotManagerForTenant
			// rather than resolving a second way is the point.
			config.AgentLaunchSpecResolver = harness.
				NewCatalogAgentResolver(d.config.Sandbox.Setec.AgentSandboxClass, credentials).
				WithTenantModelResolver(&slotModelResolver{forTenant: slotManagerForTenant}).
				// The enrollment runtime caps the tenant-operator reports
				// (gibson#597) bound each agent's sandboxed run.
				WithRunLimits(&enrollmentRunLimits{db: func() *sql.DB { return d.platformDB }})
			config.AgentCallbackEndpoint = d.config.Callback.AdvertiseAddress
			// The bank reconciler launches members outside any mission harness,
			// so it needs the same three seams the harness gets (gibson#1709).
			d.agentLauncher = launcher
			// The bank reconciler suspends an idle member and resumes it
			// when jobs wait (ADR-0119, gibson#809).
			suspender, susErr := newSetecSuspender(d.config.Sandbox, daemonSVIDSource{d: d})
			if susErr != nil {
				return nil, fmt.Errorf("setec suspender: %w", susErr)
			}
			d.sandboxSuspender = suspender
			d.agentLaunchSpecResolver = config.AgentLaunchSpecResolver
			d.agentCallbackEndpoint = config.AgentCallbackEndpoint
			d.logger.Info(ctx, "sandboxed agent launcher wired",
				"setec_address", d.config.Sandbox.Setec.Address,
				"agent_sandbox_class", d.config.Sandbox.Setec.AgentSandboxClass)
		}
	}

	// Create the factory
	factory, err := harness.NewHarnessFactory(config)
	if err != nil {
		return nil, err
	}

	d.logger.Info(ctx, "harness factory created successfully")
	return factory, nil
}

// newSlotManagerForTenant builds the per-tenant slot manager resolver
// (gibson#526). It is the single source of per-tenant slot resolution: the
// harness config (mission path), the agent model floor and ResolveModel on both
// services use it. It reads the provider records of the tenant from the
// provider record store and calls no provider and no secret store. The record
// store is built on first use, so the broker stack is wired by then.
func (d *daemonImpl) newSlotManagerForTenant() func(context.Context, string) (harness.SlotManager, error) {
	var (
		storeOnce sync.Once
		store     providerconfig.ProviderConfigStore
		storeErr  error
	)
	return func(rctx context.Context, tenantID string) (harness.SlotManager, error) {
		storeOnce.Do(func() {
			if d.pool == nil || d.secretsService == nil {
				storeErr = errors.New("per-tenant provider store unavailable (pool/secretsService nil)")
				return
			}
			store = providerconfig.NewBrokerBackedStore(d.pool, d.secretsService)
		})
		if storeErr != nil {
			return nil, storeErr
		}
		recs, err := store.List(rctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("list provider records for %q: %w", tenantID, err)
		}
		sm, err := d.buildSlotManagerForRecords(rctx, tenantID, recs)
		if err != nil {
			return nil, err
		}
		return sm, nil
	}
}

// buildSlotManagerForRecords turns the provider records of a tenant into a slot
// manager: it prefers the default provider of the tenant for unpinned slots
// (gibson#531), gives the members of the tenant the default grant on each
// provider (hosted#358), and installs the FGA model access gate on every
// resolution (gibson#527). It is split out so a test can pass hand built
// records.
//
// The gate is always installed. A daemon with no authorizer gets a gate that
// denies every model, never a slot manager with no gate.
func (d *daemonImpl) buildSlotManagerForRecords(ctx context.Context, tenantID string, recs []*providerconfig.ProviderConfig) (*DaemonSlotManager, error) {
	providers, defaultName := SlotProvidersFromRecords(recs)
	names := make([]string, 0, len(providers))
	for _, p := range providers {
		names = append(names, p.Name)
	}
	if err := d.ensureDefaultModelGrants(ctx, tenantID, names); err != nil {
		return nil, err
	}
	sm := NewDaemonSlotManager(providers, d.logger.WithComponent("slot-manager").Slog())
	sm.WithDefaultProvider(defaultName)
	sm.WithModelFilter(modelgate.NewFGAFilter(d.authorizer, d.logger.Slog(), 0))
	sm.WithResolveCallback(d.modelResolvedCallback())
	return sm, nil
}

// ensureDefaultModelGrants gives the members of a tenant the default grant on
// each named provider, once per provider (modelgate.EnsureDefaultGrant). It
// runs before the tenant's first slot resolution, so a new tenant can run a
// mission with no manual grant, and a provider configured before the default
// existed gets it on first use.
//
// A provider that this process already handled is skipped without a call to
// FGA. An error stops the build: without the default, the gate would deny the
// tenant's members, and the cause would read as a denial and not as an FGA
// failure.
func (d *daemonImpl) ensureDefaultModelGrants(ctx context.Context, tenantID string, names []string) error {
	if len(names) == 0 {
		return nil
	}
	if d.authorizer == nil {
		return errors.New("model access: no authorizer is configured, so the default grant cannot be written")
	}
	for _, name := range names {
		key := tenantID + "|" + name
		if _, done := d.defaultModelGrants.Load(key); done {
			continue
		}
		wrote, err := modelgate.EnsureDefaultGrant(ctx, d.authorizer, tenantID, name)
		if err != nil {
			return fmt.Errorf("model access for tenant %q: %w", tenantID, err)
		}
		if wrote {
			d.logger.Slog().InfoContext(ctx, "model access: wrote the default grant for the tenant's members",
				"tenant", tenantID, "provider", name)
		}
		d.defaultModelGrants.Store(key, struct{}{})
	}
	return nil
}

// agentLauncherWiring decides whether a constructed sandboxed-agent launcher is
// installed, and the warning to log when it is not. It is pure so its three
// build-tag-independent outcomes — construction error, no-op disabled build
// (nil launcher), and a real launcher — are unit-testable; the daemon init that
// calls it is not. A nil launcher is the un-tagged build's fail-closed default
// (ADR-0116 / gibson#1596): an untrusted agent is denied rather than run.
func agentLauncherWiring(launcher *sandboxed.AgentLauncher, launchErr error) (wire bool, warn string) {
	switch {
	case launchErr != nil:
		return false, "sandboxed agent launcher construction failed; untrusted agents will be denied"
	case launcher == nil:
		return false, "sandbox.enabled=true but setec_integration build tag is not set; untrusted agents will be denied (rebuild with -tags=setec_integration to enable sandboxed agent dispatch)"
	default:
		return true, ""
	}
}

// taskGrantVerifier returns the in-process verifier the harness callback
// listener uses to bind a request to the task grant it carries (gibson#1605).
//
// The verifier reads the Minter per call, because the Minter is constructed
// during Start, after the callback service options are assembled. Until it
// exists the verifier answers ErrNoSigningKey, so a presented grant is REFUSED
// rather than let through unchecked.
func (d *daemonImpl) taskGrantVerifier() harness.TaskGrantVerifier {
	return capabilitygrant.NewLocalVerifier(func() *capabilitygrant.Minter { return d.cgMinter })
}

// targetFactsLookup is what a dispatched tool's target facts are read through,
// read at harness creation rather than captured at factory construction.
//
// A nil store returns a nil INTERFACE and not a typed nil: the harness factory
// refuses a nil lookup (gibson#681), and a typed nil wrapped in a non-nil
// interface passes that check and then panics on the call. Start sets the
// store before any dispatch, so the refusal shows a wiring defect.
func (d *daemonImpl) targetFactsLookup() harness.TargetFactsLookup {
	if d.targetStore == nil {
		return nil
	}
	return d.targetStore
}

// missionSecretsStore is how a declared secret's value is resolved at dispatch,
// read at harness creation rather than captured at factory construction: the
// broker stack that backs d.credentialStore is built later in boot.
//
// Returns a nil INTERFACE and not a typed nil when the store is absent, for the
// reason targetFactsLookup does — the harness checks `h.missionSecrets == nil`,
// and a typed nil passes that check and then panics on the call. Here the
// consequence would be worse than a panic on dispatch: a mission that declared
// a secret must be REFUSED, and refusing needs the nil to be visible.
func (d *daemonImpl) missionSecretsStore() harness.CredentialStore {
	if d.credentialStore == nil {
		return nil
	}
	return d.credentialStore
}
