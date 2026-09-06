// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/config"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/observability"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// targetStoreLookup is the target read surface used by mission resolution.
// Targets are referenced by UUID only — name resolution (GetByName) was
// removed under the target-management epic, so only Get remains.
type targetStoreLookup interface {
	Get(ctx context.Context, id types.ID) (*types.Target, error)
}

// targetGetter is the minimal read surface needed to resolve a target by UUID.
// Satisfied by both the mission manager's targetStoreLookup and the daemon's
// targetStore, so CreateMission and RunMission share one resolution path.
type targetGetter interface {
	Get(ctx context.Context, id types.ID) (*types.Target, error)
}

// resolveTargetCallerTenant returns the caller-tenant string resolveTargetUUID
// should compare against, for a target-read caller. A missing tenant on the
// context is reported here as "" — it never defaults to
// auth.SystemTenant.String(). (The daemon-wide tenantFromCtx helper in
// tenant_context.go refuses outright in the same situation; this one returns ""
// because resolveTargetUUID's own tenant comparison is the refusal.)
//
// This is the actual enforcement of the "system tenant has no
// wire path" invariant, not merely a comment asserting it: auth.TenantFromContext
// returns (auth.SystemTenant, true) only when something has EXPLICITLY
// constructed an Identity with Tenant set to auth.SystemTenant (e.g.
// auth.WithTenant(ctx, auth.SystemTenant)) — SystemTenant.IsZero() is false,
// so TenantFromContext does not collapse it with "absent". An Identity with
// no tenant set at all — which is what every tenant-less wire-identity
// constructor in this package produces today (looseIdentityFromMD and
// spiffePlatformBypass in grpc.go both build auth.Identity{} without a
// Tenant field) — reports ok=false and this function returns "". "" can
// never equal auth.SystemTenant.String() ("_system"), so such a caller falls
// straight through to resolveTargetUUID's ordinary tenant-mismatch
// rejection. A caller cannot forge the SystemTenant branch by sending a
// literal "_system" tenant header either: auth.NewTenantID refuses to parse
// the reserved string from any external input, by design. So the exemption
// in resolveTargetUUID can only ever be reached by genuinely-internal Go
// code that calls auth.WithTenant(ctx, auth.SystemTenant) (or equivalent)
// directly — never by anything that arrived over the wire, today or after a
// future registry change.
func resolveTargetCallerTenant(ctx context.Context) string {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return ""
	}
	return tenant.String()
}

// resolveTargetUUID enforces the UUID-only, tenant-scoped target contract shared
// by CreateMission and RunMission. The target_id MUST be a UUID — a non-UUID is
// a hard invalid-argument, never a name to look up. A missing or cross-tenant
// target is reported as not-found.
//
// The backing target store is daemon-wide (one Redis namespace keyed by UUID
// only), so this comparison is the ONLY tenant boundary on the target read
// path. It is therefore fail-closed: a stored target with no stamped tenant is
// not resolvable by a tenant caller. Every target is stamped at creation
// (DaemonServer.CreateTarget takes the tenant from the authenticated context
// and rejects an empty one), so an unstamped row is malformed data, not a
// legitimate legacy shape.
//
// The one remaining exemption is the reserved system tenant. callerTenant
// MUST come from resolveTargetCallerTenant (see its doc comment for why a
// merely-absent context tenant can never satisfy this branch).
func resolveTargetUUID(ctx context.Context, store targetGetter, targetID, callerTenant string) (*types.Target, error) {
	parsed, err := types.ParseID(targetID)
	if err != nil {
		return nil, fmt.Errorf("invalid target_id %q: a target UUID is required: %w", targetID, err)
	}
	t, err := store.Get(ctx, parsed)
	if err != nil || t == nil {
		return nil, fmt.Errorf("target %q not found", targetID)
	}
	if callerTenant == auth.SystemTenant.String() {
		return t, nil
	}
	if t.TenantID == "" || callerTenant != t.TenantID {
		return nil, fmt.Errorf("target %q not found", targetID)
	}
	return t, nil
}

// missionManager implements the MissionManager interface for daemon operations.
// It orchestrates mission lifecycle including mission loading, execution, tracking,
// and event emission.
//
// After the mission-finding-per-tenant-cutover spec, mission and run data is stored
// in per-tenant databases. Each method that needs to persist or read mission data
// acquires a short-lived *datapool.Conn from the pool using the calling tenant's ID.
type missionManager struct {
	config          *config.Config
	logger          *slog.Logger
	registry        component.ComponentDiscovery
	pool            datapool.Pool // per-tenant data-plane pool (replaces missionStore, missionRunStore, findingStore)
	llmRegistry     llm.LLMRegistry
	callbackManager *harness.CallbackManager
	harnessFactory  harness.HarnessFactoryInterface
	targetStore     targetStoreLookup
	runLinker       mission.MissionRunLinker
	infrastructure  *Infrastructure
	otelStack       *observability.OTelObservabilityStack // nil when OTel is disabled
	eventBus        eventPublisher                        // emits orchestration events to the brain + Redis stream

	// brainRegistry + brainExecutor make the ECS brain the mission execution
	// engine (gibson#851): executeMission projects the CUE mission into the
	// tenant's World and the brain (scheduler + Decider) drives it.
	brainRegistry *brain.Registry
	brainExecutor *brainExecutor
	// beliefVersion is the belief-model version the brain currently scores against
	// (ADR-0005 §5). Stamped onto each mission at projection so the mission records
	// the model it ran under and replay reproduces. Empty → no pinned model.
	beliefVersion string

	// authzStore records the owning user per run so that HarnessCallbackService.Authorize
	// can resolve run_id → (user_id, tenant_id) during component callbacks.
	// One-code-path slice deploy#195: required, never nil after daemon startup.
	authzStore mission.MissionAuthzStore

	// quotaCounter maintains the per-tenant concurrent_missions Redis
	// counter. INCR fires when execution begins (queued → running);
	// DECR fires when the mission reaches a terminal state. nil-safe.
	// Spec plans-and-quotas-simplification.
	quotaCounter mission.QuotaCounter

	// activeMissions tracks running missions keyed by (tenant, missionID).
	// The outer key is the tenant; the inner key is the mission ID string.
	// Pause/Resume/Stop operations traverse only the calling tenant's submap
	// (audit C9 closure — a tenant cannot affect another tenant's missions).
	mu             sync.RWMutex
	activeMissions map[auth.TenantID]map[string]*activeMission
	completedCount int
}

// activeMission tracks a running mission's context and cancellation. All
// caller-observable lifecycle flows through the brain -> lifecycle projector
// (gibson#1112 PR 3); there is no per-run event channel.
type activeMission struct {
	mission      *mission.Mission
	missionRun   *mission.MissionRun // The specific run instance
	ctx          context.Context
	cancel       context.CancelFunc
	missionState *mission.MissionState
	startTime    time.Time
	tenantID     auth.TenantID // tenant this mission belongs to (C9 isolation key)
}

// newMissionManager creates a new mission manager instance.
// The pool parameter provides per-tenant data-plane connections; it replaces the
// former missionStore, missionRunStore, and findingStore parameters. When pool is nil
// (dev mode, no security.key_provider), persistence operations are skipped gracefully.
func newMissionManager(
	cfg *config.Config,
	logger *slog.Logger,
	reg component.ComponentDiscovery,
	pool datapool.Pool,
	llmRegistry llm.LLMRegistry,
	callbackMgr *harness.CallbackManager,
	harnessFactory harness.HarnessFactoryInterface,
	targetStore targetStoreLookup,
	runLinker mission.MissionRunLinker,
	infrastructure *Infrastructure,
	otelStack *observability.OTelObservabilityStack,
	eventBus eventPublisher,
	authzStore mission.MissionAuthzStore,
	quotaCounter mission.QuotaCounter,
	brainRegistry *brain.Registry,
	brainExecutor *brainExecutor,
) *missionManager {
	return &missionManager{
		config:          cfg,
		logger:          logger.With("component", "mission-manager"),
		registry:        reg,
		pool:            pool,
		llmRegistry:     llmRegistry,
		callbackManager: callbackMgr,
		harnessFactory:  harnessFactory,
		targetStore:     targetStore,
		runLinker:       runLinker,
		infrastructure:  infrastructure,
		otelStack:       otelStack,
		eventBus:        eventBus,
		authzStore:      authzStore,
		quotaCounter:    quotaCounter,
		brainRegistry:   brainRegistry,
		brainExecutor:   brainExecutor,
		activeMissions:  make(map[auth.TenantID]map[string]*activeMission),
	}
}

// missionStoreFor acquires a per-tenant Conn from the pool and returns a
// ConnBoundMissionStore. The caller MUST call release() exactly once (use defer).
// Returns (nil, nil, nil) when pool is not configured (dev mode).
func (m *missionManager) missionStoreFor(ctx context.Context, tenant auth.TenantID) (mission.MissionStore, func(), error) {
	if m.pool == nil {
		return nil, func() {}, nil
	}
	conn, err := m.pool.For(ctx, tenant)
	if err != nil {
		var npErr *datapool.NotProvisionedError
		if errors.As(err, &npErr) {
			m.logger.WarnContext(ctx, "mission manager: tenant not provisioned",
				slog.String("tenant", tenant.String()))
			return nil, func() {}, nil
		}
		return nil, func() {}, fmt.Errorf("mission manager: acquire conn for tenant %s: %w", tenant, err)
	}
	store := mission.NewConnBoundMissionStore(conn.Redis)
	return store, func() { conn.Release() }, nil
}

// runStoreFor acquires a per-tenant Conn from the pool and returns a
// ConnBoundRunStore. The caller MUST call release() exactly once (use defer).
// Returns (nil, nil, nil) when pool is not configured (dev mode).
func (m *missionManager) runStoreFor(ctx context.Context, tenant auth.TenantID) (mission.MissionRunStore, func(), error) {
	if m.pool == nil {
		return nil, func() {}, nil
	}
	conn, err := m.pool.For(ctx, tenant)
	if err != nil {
		var npErr *datapool.NotProvisionedError
		if errors.As(err, &npErr) {
			return nil, func() {}, nil
		}
		return nil, func() {}, fmt.Errorf("mission manager: acquire conn (run store) for tenant %s: %w", tenant, err)
	}
	store := mission.NewConnBoundRunStore(conn.Redis)
	return store, func() { conn.Release() }, nil
}

// newMissionContext builds the context a mission run executes under.
//
// Detached from the caller's cancellation on purpose (WithoutCancel): a mission
// outlives the RPC that started it, so closing the RunMission stream must not
// kill the run. Values (trace context, deadlineless metadata) are inherited.
// The tenant is re-set explicitly rather than trusted from the parent, because
// every tenant-scoped lookup the run makes (component discovery, secrets,
// per-tenant stores) reads the tenant off the context. Without it, a mission
// node that dispatches to a registered remote component silently finds nothing
// to dispatch to (gibson#1196).
func newMissionContext(ctx context.Context, tenant auth.TenantID) (context.Context, context.CancelFunc) {
	return context.WithCancel(auth.ContextWithTenant(context.WithoutCancel(ctx), tenant))
}

// setActive registers a mission in the tenant-partitioned active map (C9 closure).
func (mm *missionManager) setActive(tenant auth.TenantID, missionID string, am *activeMission) {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	if mm.activeMissions[tenant] == nil {
		mm.activeMissions[tenant] = make(map[string]*activeMission)
	}
	mm.activeMissions[tenant][missionID] = am
}

// getActive retrieves an active mission scoped to the given tenant (C9 closure).
// Returns nil, false if not found.
func (mm *missionManager) getActive(tenant auth.TenantID, missionID string) (*activeMission, bool) {
	mm.mu.RLock()
	defer mm.mu.RUnlock()
	if sub, ok := mm.activeMissions[tenant]; ok {
		am, exists := sub[missionID]
		return am, exists
	}
	return nil, false
}

// deleteActive removes a mission from the active map (C9 closure).
func (mm *missionManager) deleteActive(tenant auth.TenantID, missionID string) {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	if sub, ok := mm.activeMissions[tenant]; ok {
		delete(sub, missionID)
		if len(sub) == 0 {
			delete(mm.activeMissions, tenant)
		}
	}
	mm.completedCount++
}

// Run starts a mission by reference and returns an event channel for progress
// updates. Missions are invoked by reference only — the mission definition and
// target must already be registered. File-path / inline-YAML invocation was
// removed under spec mission-api-only-cleanup.
func (m *missionManager) Run(ctx context.Context, missionDefinitionID, targetID string, variables map[string]string, memoryContinuity string) (string, error) {
	m.logger.Info("starting mission",
		"mission_definition_id", missionDefinitionID,
		"target_id", targetID,
		"variables", len(variables),
		"memory_continuity", memoryContinuity,
	)

	if missionDefinitionID == "" {
		return "", errors.New("mission_definition_id is required")
	}
	if targetID == "" {
		return "", errors.New("target_id is required")
	}

	// Load mission definition from the calling tenant's store. A run with no
	// tenant on its context is refused, not run as the system tenant.
	callingTenantForDef, tenantErr := tenantFromCtx(ctx)
	if tenantErr != nil {
		return "", tenantErr
	}
	defStore, defRelease, defStoreErr := m.missionStoreFor(ctx, callingTenantForDef)
	if defStoreErr != nil {
		return "", fmt.Errorf("mission run: get store for definition: %w", defStoreErr)
	}
	defer defRelease()

	if defStore == nil {
		return "", errors.New("mission store not initialized (pool not configured)")
	}

	def, err := m.loadRunDefinition(ctx, defStore, missionDefinitionID)
	if err != nil {
		return "", err
	}

	m.logger.Debug("mission definition loaded",
		"mission_name", def.GetName(),
		"node_count", len(def.GetNodes()),
	)

	// Shared-Neo4j-backed mission graph storage removed (spec graphrag-tenant-scope).
	// Per-tenant mission graph storage via Pool will be added in a follow-up spec.

	// Resolve the target by UUID only (no name resolution) and enforce tenant
	// ownership. The shared resolveTargetUUID path is identical to the one
	// CreateMission uses, so the two entry points cannot diverge.
	//
	// Deliberately NOT callingTenantForDef.String() (that helper defaults an
	// absent context tenant to auth.SystemTenant, which would hand an
	// unconditional cross-tenant target read to any caller reaching this
	// method with no tenant on its context — see resolveTargetCallerTenant's
	// doc comment).
	if m.targetStore == nil {
		return "", fmt.Errorf("target_id '%s' supplied but target store not available", targetID)
	}
	target, err := resolveTargetUUID(ctx, m.targetStore, targetID, resolveTargetCallerTenant(ctx))
	if err != nil {
		return "", err
	}
	resolvedTargetID := target.ID
	targetRef := runTargetRef(target)
	m.logger.Debug("resolved target", "target_id", resolvedTargetID, "target_ref", targetRef)

	// Build an internal mission ID for tracking this run.
	missionID := types.NewID().String()

	// The calling tenant (C9 isolation key) is the one already resolved for the
	// definition store above — reused rather than re-derived so the isolation
	// key and the store selection cannot diverge.
	callingTenant := callingTenantForDef

	// Check if mission ID already exists (defensive — should not be possible with fresh IDs)
	if _, exists := m.getActive(callingTenant, missionID); exists {
		return "", fmt.Errorf("mission %s is already running", missionID)
	}

	// Serialize mission definition to canonical protojson for storage.
	definitionJSON, err := mission.MarshalDefinitionJSON(def)
	if err != nil {
		m.logger.Error("failed to serialize mission definition", "error", err)
		return "", fmt.Errorf("failed to serialize mission definition: %w", err)
	}

	// Find or create stable mission record (one per mission name)
	now := mission.NewUnixTimeNow()
	missionTemplate := &mission.Mission{
		ID:                    types.NewID(),          // Template ID, may be replaced by existing
		TenantID:              callingTenant.String(), // required: ListMissions filters by tenant
		Name:                  def.GetName(),
		Description:           def.GetDescription(),
		Status:                mission.MissionStatusPending,
		MissionDefinitionID:   types.ID(def.GetId()),
		MissionDefinitionJSON: string(definitionJSON),
		TargetID:              resolvedTargetID,
		MemoryContinuity:      memoryContinuity,
		CreatedAt:             now,
		UpdatedAt:             now,
		FindingsCount:         0,
		Metrics: &mission.MissionMetrics{
			TotalNodes:     len(def.GetNodes()),
			CompletedNodes: 0,
		},
		Metadata: make(map[string]any),
	}

	// Store variables in metadata
	if len(variables) > 0 {
		missionTemplate.Metadata["variables"] = variables
	}

	// Store target URL/reference in metadata for agent context injection
	// This preserves the original target reference (URL or name) separate from TargetID
	if targetRef != "" {
		missionTemplate.Metadata["target_ref"] = targetRef
	}

	// Acquire the mission store for this tenant (callingTenant resolved above).
	mStore, mStoreRelease, mStoreErr := m.missionStoreFor(ctx, callingTenant)
	if mStoreErr != nil {
		return "", fmt.Errorf("mission run: acquire mission store: %w", mStoreErr)
	}
	defer mStoreRelease()

	missionRecord, err := m.findOrCreateRecord(ctx, mStore, missionTemplate, targetRef)
	if err != nil {
		return "", err
	}

	// Create new MissionRun for this execution
	rStore, rStoreRelease, rStoreErr := m.runStoreFor(ctx, callingTenant)
	defer rStoreRelease()
	if rStoreErr != nil {
		m.logger.Warn("failed to acquire run store; using ephemeral run", "error", rStoreErr)
	}
	missionRun, err := m.createRunRecord(ctx, rStore, missionRecord.ID)
	if err != nil {
		return "", err
	}

	// Record authz state so HarnessCallbackService.Authorize can resolve
	// run_id → (user_id, tenant_id) during component callbacks. Errors are
	// logged and do not abort mission start — authz state is advisory.
	// One-code-path slice deploy#195: authzStore is required (no more nil
	// guard).
	{
		userID := ""
		tenantID := auth.TenantStringFromContext(ctx)
		if id, err := auth.IdentityFromContext(ctx); err == nil {
			userID = id.Subject
		}
		if putErr := m.authzStore.Put(ctx, missionRun.ID.String(), userID, tenantID); putErr != nil {
			m.logger.Warn("failed to record authz state on mission start",
				slog.String("mission_id", missionRecord.ID.String()),
				slog.String("run_id", missionRun.ID.String()),
				slog.String("error", putErr.Error()),
			)
		}
	}

	// Create mission context with cancellation.
	missionCtx, cancel := newMissionContext(ctx, callingTenant)

	// Create active mission entry - use mission.ID (stable) for tracking
	active := &activeMission{
		mission:    missionRecord,
		missionRun: missionRun,
		ctx:        missionCtx,
		cancel:     cancel,
		startTime:  time.Now(),
		tenantID:   callingTenant,
	}

	// Register active mission under the calling tenant's partition (C9 closure).
	m.setActive(callingTenant, missionRecord.ID.String(), active)

	// Launch mission executor in goroutine - pass mission ID (stable).
	// Every lifecycle event the caller can observe flows brain → lifecycle
	// projector → EventBus + Redis stream (ADR-0011 decision 4, gibson#1116;
	// the per-run event channel was retired in gibson#1112 PR 3). Callers
	// stream via Subscribe filtered on the returned mission ID.
	go m.executeMission(missionCtx, missionRecord.ID.String(), def)

	return missionRecord.ID.String(), nil
}

// loadRunDefinition loads a mission definition by friendly name, falling back
// to an ID-based lookup across all definitions (the caller may supply either).
func (m *missionManager) loadRunDefinition(ctx context.Context, defStore mission.MissionStore, missionDefinitionID string) (*missionpb.MissionDefinition, error) {
	def, err := defStore.GetDefinition(ctx, missionDefinitionID)
	if err != nil {
		m.logger.Error("failed to load mission definition", "error", err, "mission_definition_id", missionDefinitionID)
		return nil, fmt.Errorf("failed to load mission definition %s: %w", missionDefinitionID, err)
	}
	if def == nil {
		// Fall back to ID-based lookup across all definitions.
		defs, listErr := defStore.ListDefinitions(ctx)
		if listErr == nil {
			for _, candidate := range defs {
				if candidate.GetId() == missionDefinitionID {
					def = candidate
					break
				}
			}
		}
		if def == nil {
			return nil, fmt.Errorf("mission definition not found: %s", missionDefinitionID)
		}
	}
	return def, nil
}

// runTargetRef picks the reference string stored in mission metadata for agent
// context injection: URL wins, then a connection URL, then the target name.
func runTargetRef(target *types.Target) string {
	if target.URL != "" {
		return target.URL
	}
	if conn, ok := target.Connection["url"].(string); ok && conn != "" {
		return conn
	}
	return target.Name
}

// findOrCreateRecord resolves the stable mission record (one per mission name)
// and refreshes run-specific metadata (target_ref, variables) on an existing
// record. A nil store (pool not configured) falls back to the template itself.
func (m *missionManager) findOrCreateRecord(ctx context.Context, mStore mission.MissionStore, missionTemplate *mission.Mission, targetRef string) (*mission.Mission, error) {
	if mStore == nil {
		// No store available (pool not configured), use template directly.
		return missionTemplate, nil
	}
	missionRecord, isNewMission, err := mStore.FindOrCreateByName(ctx, missionTemplate)
	if err != nil {
		m.logger.Error("failed to find or create mission", "error", err, "mission_name", missionTemplate.Name)
		return nil, fmt.Errorf("failed to find or create mission: %w", err)
	}
	m.logger.Info("mission lookup result",
		"mission_id", missionRecord.ID,
		"mission_name", missionRecord.Name,
		"is_new", isNewMission,
	)
	// For existing missions, ensure metadata is updated with current run's
	// values — the template metadata carries run-specific data like target_ref.
	if !isNewMission {
		if missionRecord.Metadata == nil {
			missionRecord.Metadata = make(map[string]any)
		}
		if targetRef != "" {
			missionRecord.Metadata["target_ref"] = targetRef
		}
		if vars, ok := missionTemplate.Metadata["variables"]; ok {
			missionRecord.Metadata["variables"] = vars
		}
	}
	return missionRecord, nil
}

// createRunRecord allocates and persists the MissionRun for this execution.
// A nil store (pool not configured) yields an ephemeral run.
func (m *missionManager) createRunRecord(ctx context.Context, rStore mission.MissionRunStore, missionID types.ID) (*mission.MissionRun, error) {
	if rStore == nil {
		// Fallback: create ephemeral run when pool is not configured.
		missionRun := mission.NewMissionRun(missionID, 1)
		missionRun.MarkStarted()
		m.logger.Warn("mission run store not available (pool not configured), using ephemeral run")
		return missionRun, nil
	}
	runNumber, err := rStore.GetNextRunNumber(ctx, missionID)
	if err != nil {
		m.logger.Error("failed to get next run number", "error", err)
		return nil, fmt.Errorf("failed to get next run number: %w", err)
	}
	missionRun := mission.NewMissionRun(missionID, runNumber)
	missionRun.MarkStarted()
	if err := rStore.Save(ctx, missionRun); err != nil {
		m.logger.Error("failed to save mission run", "error", err)
		return nil, fmt.Errorf("failed to save mission run: %w", err)
	}
	m.logger.Info("created mission run",
		"mission_id", missionID,
		"run_id", missionRun.ID,
		"run_number", runNumber,
	)
	return missionRun, nil
}

// recordMissionOutcomeSpan stamps the terminal mission status and duration
// onto the execution span. No-op when tracing is disabled (nil span).
func recordMissionOutcomeSpan(span trace.Span, finalStatus mission.MissionStatus, errorMsg string, missionDuration time.Duration) {
	if span == nil {
		return
	}
	if finalStatus == mission.MissionStatusCompleted {
		span.SetStatus(codes.Ok, "mission completed")
	} else {
		span.SetStatus(codes.Error, errorMsg)
	}
	span.SetAttributes(attribute.Int("gibson.mission.duration_ms", int(missionDuration.Milliseconds())))
}

// startMissionSpan opens the mission-execution span when OTel tracing is
// enabled; returns the unchanged context and a nil span otherwise.
func (m *missionManager) startMissionSpan(ctx context.Context, missionID, missionName string) (context.Context, trace.Span) {
	if m.otelStack == nil || m.otelStack.TracerProvider == nil {
		return ctx, nil
	}
	tracer := m.otelStack.TracerProvider.Tracer("gibson")
	return tracer.Start(ctx, observability.SpanMissionExecute,
		trace.WithAttributes(
			attribute.String(observability.GibsonMissionID, missionID),
			attribute.String(observability.GibsonMissionName, missionName),
		),
	)
}

// findActiveAnyTenant scans every tenant partition for the given mission ID.
// The mission-execution goroutine runs without a tenant-carrying context, so
// it cannot use the tenant-keyed getActive; the tenant is read back off the
// returned entry instead.
func (m *missionManager) findActiveAnyTenant(missionID string) (*activeMission, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, sub := range m.activeMissions {
		if am, ok := sub[missionID]; ok {
			return am, true
		}
	}
	return nil, false
}

// persistTraceID stamps the current OTel trace ID into mission metadata for
// distributed-trace lookup. No-op when tracing is disabled.
func (m *missionManager) persistTraceID(ctx context.Context, missionID string, mi *mission.Mission) {
	activeSpan := trace.SpanFromContext(ctx)
	if !activeSpan.SpanContext().HasTraceID() {
		return
	}
	if mi.Metadata == nil {
		mi.Metadata = make(map[string]any)
	}
	mi.Metadata["trace_id"] = activeSpan.SpanContext().TraceID().String()
	m.logger.Debug("persisted trace ID to mission metadata",
		"mission_id", missionID,
		"trace_id", mi.Metadata["trace_id"],
	)
}

// resolveRunTargetInfo builds the harness TargetInfo for a mission's target.
// The reserved discovery UUID yields a synthetic target; a full TargetStore
// yields connection details; anything else falls back to an ID-only stub.
func (m *missionManager) resolveRunTargetInfo(ctx context.Context, targetID types.ID) (harness.TargetInfo, error) {
	if targetID == "00000000-0000-0000-0000-d15c00e00000" {
		// Synthetic target for discovery/orchestration missions
		return harness.NewTargetInfo(targetID, "discovery-mission", "", "discovery"), nil
	}
	ts, ok := m.targetStore.(mission.TargetStore)
	if !ok {
		return harness.NewTargetInfo(targetID, "mission-target", "", ""), nil
	}
	target, err := ts.Get(ctx, targetID)
	if err != nil {
		m.logger.Error("failed to load target", "error", err, "target_id", targetID)
		return harness.TargetInfo{}, fmt.Errorf("load target %s: %w", targetID, err)
	}
	return harness.NewTargetInfoFull(
		target.ID,
		target.Name,
		target.URL,
		target.Type,
		target.Connection,
	), nil
}

// finalizeAuthzState transitions the run's authz record to its terminal state
// so late-arriving component callbacks get a proper inactive-mission error
// rather than stale "active" state. Errors are logged and never block mission
// lifecycle cleanup. missionRun may be nil if the mission failed before a run
// row was allocated.
func (m *missionManager) finalizeAuthzState(ctx context.Context, missionRun *mission.MissionRun, finalStatus mission.MissionStatus) {
	if missionRun == nil {
		return
	}
	// Detach cancellation but keep trace/values: cleanup must complete even
	// after the mission context is cancelled (context.WithoutCancel).
	bgCtx := context.WithoutCancel(ctx)
	runIDStr := missionRun.ID.String()
	if finalStatus == mission.MissionStatusCompleted {
		if markErr := m.authzStore.MarkCompleted(bgCtx, runIDStr); markErr != nil {
			m.logger.Warn("failed to mark authz state completed",
				slog.String("run_id", runIDStr),
				slog.String("error", markErr.Error()),
			)
		}
		return
	}
	if markErr := m.authzStore.MarkCancelled(bgCtx, runIDStr); markErr != nil {
		m.logger.Warn("failed to mark authz state cancelled",
			slog.String("run_id", runIDStr),
			slog.String("error", markErr.Error()),
		)
	}
}

// releaseChildReservation returns a child mission's reserved budget to its
// parent on the child's terminal transition (gibson#1358). A mission with no
// parent reserved nothing, so this is a no-op for it. The reservation ledger is
// built from the same per-tenant Redis the run executed against (poolConn), so
// the release lands in the tenant's own namespace. Cancellation is detached
// (context.WithoutCancel) so a Stop-cancelled mission still returns the budget;
// HDEL of an absent field is a no-op, so a double release is harmless. Errors
// are logged, never propagated — cleanup must not block lifecycle teardown.
func (m *missionManager) releaseChildReservation(ctx context.Context, poolConn *datapool.Conn, mi *mission.Mission) {
	// Only a child mission — one with a parent — reserved anything against a
	// parent envelope, so only a child has something to release. A root mission
	// (no parent) reserved nothing and needs no release. The caller
	// (executeMission) reaches here only with a live active mission and an
	// acquired poolConn, so neither is defensively nil-checked (ADR-0003: no
	// graceful-nil in request paths).
	if parentID := mi.ParentMissionID; parentID != nil {
		ledger := mission.NewRedisReservationLedger(poolConn.Redis)
		if err := ledger.Release(context.WithoutCancel(ctx), *parentID, mi.ID); err != nil {
			m.logger.Warn("mission manager: failed to release child budget reservation (non-fatal)",
				"mission_id", mi.ID.String(),
				"parent_mission_id", parentID.String(),
				"error", err.Error())
		}
	}
}

// executeMission runs the mission execution using the orchestrator.
// This handles the full mission lifecycle including setup, execution via
// the Observe → Think → Act loop, and cleanup.
// failBeforeStart records a pre-flight failure in the brain Timeline so the
// World — and every Subscribe stream, via the lifecycle projector — sees the
// run start and immediately fail (gibson#1112 PR 3, ADR-0011: the World is
// the single source of mission state, including runs that never got off the
// ground). These failures occur before the mission is projected into the
// engine, so MissionDone alone would be a silent no-op: applyMissionDone
// ignores unknown IDs. The Started/Done pair encodes exactly what happened.
func (m *missionManager) failBeforeStart(tenantID auth.TenantID, missionID, name, reason string) {
	eng := m.brainRegistry.For(tenantID.String())
	eng.Submit(brain.MissionStarted{ID: missionID, Name: name})
	eng.Submit(brain.MissionDone{ID: missionID, Outcome: brain.MissionFailed, Reason: reason})
}

func (m *missionManager) executeMission(ctx context.Context, missionID string, def *missionpb.MissionDefinition) {
	// Create mission execution span if OTel tracing is enabled
	ctx, span := m.startMissionSpan(ctx, missionID, def.GetName())
	if span != nil {
		defer span.End()
	}

	m.logger.Info("executing mission with orchestrator", "mission_id", missionID)

	// Find the active mission across all tenants (this goroutine runs without
	// a tenant-carrying context; use the stored tenantID on the active entry).
	active, exists := m.findActiveAnyTenant(missionID)
	// Defer cleanup using the tenant from the active entry (C9 closure).
	defer func() {
		if active != nil {
			m.deleteActive(active.tenantID, missionID)
		}
	}()

	if !exists {
		m.logger.Error("active mission not found", "mission_id", missionID)

		// Record error on span
		if span != nil {
			span.RecordError(fmt.Errorf("active mission not found"))
			span.SetStatus(codes.Error, "mission not found")
		}

		// No active entry means no tenant, so there is no brain engine to
		// record this against — and Run registers the entry before spawning
		// this goroutine, so reaching here is an internal invariant failure,
		// not a user-visible mission outcome. The log + span above are the
		// full signal (gibson#1112 PR 3).
		return
	}

	// Add mission name to span now that we have the active mission
	if span != nil {
		span.SetAttributes(attribute.String(observability.GibsonMissionName, active.mission.Name))
	}

	// Persist the OTel trace ID into mission metadata for distributed-trace lookup
	m.persistTraceID(ctx, missionID, active.mission)

	// Set StartedAt timestamp now that execution is beginning
	active.mission.StartedAt = mission.NewUnixTimePtrNow()

	// Status is now World-derived (ADR-0011/gibson#1118): the brain's MissionStarted
	// event sets status=running in the World. No store write here.

	// Increment the concurrent_missions counter on dispatch (queued → running).
	// DECR fires from the terminal-state block below. Failure is non-fatal:
	// counter mismatches self-correct via floor-at-zero. Spec
	// plans-and-quotas-simplification.
	if m.quotaCounter != nil {
		if incErr := m.quotaCounter.IncrementMissionCount(ctx); incErr != nil {
			m.logger.Warn("mission manager: increment concurrent_missions failed (non-fatal)",
				"mission_id", missionID, "error", incErr.Error())
		}
	}

	// Acquire the per-tenant Neo4j session from the data-plane Pool.
	// The pool is required for mission execution (per-call Neo4j).
	if m.pool == nil {
		m.logger.Error("data-plane pool not available - mission execution requires Neo4j",
			"mission_id", missionID)
		m.failBeforeStart(active.tenantID, missionID, def.GetName(), "data-plane pool is required for mission execution but not configured")
		return
	}
	poolConn, poolErr := m.pool.For(ctx, active.tenantID)
	if poolErr != nil {
		m.logger.Error("failed to acquire per-tenant Neo4j session",
			"mission_id", missionID,
			"tenant_id", active.tenantID,
			"error", poolErr)
		m.failBeforeStart(active.tenantID, missionID, def.GetName(), fmt.Sprintf("failed to acquire tenant Neo4j session: %v", poolErr))
		return
	}
	defer poolConn.Release()

	// Wrap the per-tenant session as a GraphClient for the mission graph bootstrap.
	graphClient := graph.NewSessionGraphClient(poolConn.Neo4j)

	// Use the MissionRun from active mission (already created in Run())
	missionRun := active.missionRun
	if missionRun == nil {
		m.logger.Error("mission run not found in active mission", "mission_id", missionID)
		m.failBeforeStart(active.tenantID, missionID, def.GetName(), "internal error: mission run not initialized")
		return
	}

	// Bootstrap mission graph structure before execution.
	bootstrapper := NewGraphBootstrapper(graphClient, m.logger)
	bootstrapResult, err := bootstrapper.Bootstrap(ctx, active.mission, def, missionRun)
	if err != nil {
		m.logger.Error("failed to bootstrap mission graph", "error", err, "mission_id", missionID)
		m.failBeforeStart(active.tenantID, missionID, def.GetName(), fmt.Sprintf("failed to initialize mission graph: %v", err))
		return
	}

	// Create mission context and target info for harness
	// Include MissionRunID for GraphRAG mission-scoped storage
	missionCtx := harness.NewMissionContext(active.mission.ID, active.mission.Name, "").
		WithMissionRunID(bootstrapResult.MissionRunID).
		WithRunNumber(missionRun.RunNumber).
		WithTenant(active.mission.TenantID)

	// Load target entity to get connection details
	targetInfo, targetInfoErr := m.resolveRunTargetInfo(ctx, active.mission.TargetID)
	if targetInfoErr != nil {
		m.failBeforeStart(active.tenantID, missionID, def.GetName(), targetInfoErr.Error())
		return
	}

	// Create harness for agent execution
	agentHarness, err := m.harnessFactory.Create("orchestrator", missionCtx, targetInfo)
	if err != nil {
		m.logger.Error("failed to create harness", "error", err)
		m.failBeforeStart(active.tenantID, missionID, def.GetName(), fmt.Sprintf("failed to create harness: %v", err))
		return
	}

	// === ECS brain mission execution (gibson#851) ===
	// The brain is the engine: project the CUE mission into the tenant's World and
	// let the scheduler (scripted graph) + Decider (goal-directed) drive it. Agents
	// are dispatched via the mission harness; observations/findings flow back through
	// the harness callback path into the same World (ADR-0001/0007).
	var finalStatus mission.MissionStatus
	var errorMsg string
	var missionDuration time.Duration

	eng := m.brainRegistry.For(active.tenantID.String())

	// Register the per-mission binding so the brain executor can dispatch this
	// mission's agents and run its Decider on this mission's harness.
	m.brainExecutor.register(missionID, &missionBinding{
		ctx:     ctx,
		tenant:  active.tenantID.String(),
		eng:     eng,
		harness: agentHarness,
		slot:    deciderSlot,
	})
	defer m.brainExecutor.unregister(missionID)

	// Project the mission. A goal (if any) drives the Decider; absent → the scripted
	// graph runs deterministically and the mission completes mechanically.
	proj, projErr := missionDefinitionToProjected(def, missionGoal(active.mission))
	// Pin the belief-model version onto the mission (ADR-0005 §5): the mission
	// records the model it ran under so replay re-loads the exact artifact.
	proj.BeliefModel = m.beliefVersion
	// Carry display metadata so the World is the single source of truth for
	// mission status + identity (ADR-0011/gibson#1118).
	proj.Name = active.mission.Name
	proj.Description = active.mission.Description
	proj.TargetID = active.mission.TargetID.String()
	proj.TenantID = active.mission.TenantID
	if projErr != nil {
		finalStatus = mission.MissionStatusFailed
		errorMsg = fmt.Sprintf("failed to project mission into the World: %v", projErr)
		if span != nil {
			span.RecordError(projErr)
			span.SetStatus(codes.Error, errorMsg)
		}
		m.failBeforeStart(active.tenantID, missionID, def.GetName(), errorMsg)
	} else {
		// Key the projected mission by the RUN id (missionID) — the same id the
		// per-mission binding, awaitBrainMission, and the Decider lookup all use.
		// missionDefinitionToProjected defaults ID to the mission DEFINITION id,
		// which made the engine dispatch/decide under an id no binding is
		// registered for ("brain dispatch for unknown mission") and stranded the
		// terminal-state wait. Unify on missionID so execution actually resolves.
		proj.ID = missionID
		eng.Submit(proj)

		// Emit MissionStarted into the brain Timeline so the lifecycle projector
		// derives "status:running" on the Subscribe stream (ADR-0011 decision 4,
		// gibson#1116). Carry display metadata so that even the minimal-launch
		// path has the full mission identity in the World (gibson#1118).
		eng.Submit(brain.MissionStarted{
			ID:          missionID,
			BeliefModel: m.beliefVersion,
			Name:        active.mission.Name,
			Description: active.mission.Description,
			TargetID:    active.mission.TargetID.String(),
			TenantID:    active.mission.TenantID,
		})

		// Block until the brain reaches a terminal mission state (or ctx is cancelled).
		// The projector derives status:completed/failed from brain.MissionDone —
		// no emitEvent calls here (ADR-0011 decision 4, gibson#1116).
		finalStatus, errorMsg = m.awaitBrainMission(ctx, eng, missionID)
		missionDuration = time.Since(active.startTime)

		m.logger.Info("brain mission execution finished",
			"mission_id", missionID, "status", finalStatus, "duration", missionDuration)

		recordMissionOutcomeSpan(span, finalStatus, errorMsg, missionDuration)
	}
	_ = missionDuration

	// Transition authz state so that late-arriving component callbacks receive a
	// proper inactive-mission error rather than stale "active" state. Errors are
	// logged and do not block mission lifecycle cleanup.
	// One-code-path slice deploy#195: authzStore is required (no more nil
	// guard). missionRun may still be nil if the mission failed before a run
	// row was allocated.
	m.finalizeAuthzState(ctx, missionRun, finalStatus)

	// Give a child mission's reserved budget back to its parent now that the
	// child is terminal (gibson#1358). This used to hang off the store's
	// UpdateStatus write, but mission status became World-derived (gibson#1112)
	// and the store no longer writes a terminal transition — so the release
	// moved here, to the one place a run actually reaches terminal. A missed
	// release is not a leak that heals: it is budget the parent never gets back.
	m.releaseChildReservation(ctx, poolConn, active.mission)

	// Decrement the concurrent_missions counter on terminal-state transition.
	// Floored at zero. Spec plans-and-quotas-simplification.
	if m.quotaCounter != nil {
		if decErr := m.quotaCounter.DecrementMissionCount(ctx); decErr != nil {
			m.logger.Warn("mission manager: decrement concurrent_missions failed (non-fatal)",
				"mission_id", missionID, "error", decErr.Error())
		}
	}

	// Status is World-derived (ADR-0011/gibson#1118): the brain's MissionDone event
	// already set the terminal status in the World via Reduce. No store write.
	active.mission.Error = errorMsg
	active.mission.CompletedAt = mission.NewUnixTimePtrNow()

	m.logger.Info("mission execution completed",
		"mission_id", missionID,
		"status", finalStatus,
		"duration", time.Since(active.startTime),
	)
}

// Pause pauses a running mission at the next clean checkpoint.
// Only the calling tenant's missions may be paused (C9 closure).
// Pause halts a running mission. Brain-native (gibson#851): the engine stops
// dispatching/deciding for the mission until Resume; the mission goroutine stays
// alive and the World holds its state (the Timeline is the durable record — no
// checkpoint store). force is accepted for API compatibility.
func (m *missionManager) Pause(ctx context.Context, missionID string, force bool) error {
	m.logger.Info("pausing mission", "mission_id", missionID, "force", force)

	tenant, tenantErr := tenantFromCtx(ctx)
	if tenantErr != nil {
		return tenantErr
	}
	active, exists := m.getActive(tenant, missionID)
	if !exists {
		return fmt.Errorf("mission %s not found or not running", missionID)
	}

	m.brainRegistry.For(active.tenantID.String()).Submit(brain.MissionPauseRequested{ID: missionID})
	// Status is World-derived (ADR-0011/gibson#1118): MissionPauseRequested sets
	// status=paused in the World via Reduce. No store write.

	// mission.paused reaches the bus + Redis stream via the lifecycle
	// projector's MissionPauseRequested mapping (gibson#1112 PR 3).
	return nil
}

// Resume resumes a paused mission. Brain-native: the mission goroutine is still
// alive (paused in the engine), so Resume un-halts it in the World and returns the
// existing event stream. Cross-restart resume is not yet supported — the brain
// Timeline is in-memory (durable Timeline persistence is a follow-up).
func (m *missionManager) Resume(ctx context.Context, missionID string) error {
	m.logger.Info("resuming mission", "mission_id", missionID)

	tenant, tenantErr := tenantFromCtx(ctx)
	if tenantErr != nil {
		return tenantErr
	}
	active, exists := m.getActive(tenant, missionID)
	if !exists {
		return fmt.Errorf("mission %s is not active (resume requires a paused, in-memory mission)", missionID)
	}
	// Read mission status from the folded World (ADR-0011/gibson#1118).
	eng := m.brainRegistry.For(active.tenantID.String())
	worldStatus := worldMissionStatus(eng, missionID)
	if worldStatus != string(brain.MissionPaused) {
		return fmt.Errorf("cannot resume mission %s: status is %s (expected paused)", missionID, worldStatus)
	}

	eng.Submit(brain.MissionResumed{ID: missionID})
	// Status is World-derived (ADR-0011/gibson#1118): MissionResumed sets
	// status=running in the World via Reduce. No store write.

	// mission.resumed reaches the bus + Redis stream via the lifecycle
	// projector's MissionResumed mapping (gibson#1112 PR 3).
	return nil
}

// Stop stops a running mission with optional force flag.
// Only the calling tenant's missions may be stopped (C9 closure).
func (m *missionManager) Stop(ctx context.Context, missionID string, force bool) error {
	m.logger.Info("stopping mission", "mission_id", missionID, "force", force)

	tenant, tenantErr := tenantFromCtx(ctx)
	if tenantErr != nil {
		return tenantErr
	}
	active, exists := m.getActive(tenant, missionID)
	if !exists {
		return fmt.Errorf("mission %s not found or not running", missionID)
	}

	// Tell the brain the mission is terminal (so the World/projector reflect it),
	// then cancel the mission context (awaitBrainMission returns).
	m.brainRegistry.For(active.tenantID.String()).Submit(brain.MissionDone{
		ID:      missionID,
		Outcome: brain.MissionFailed,
		Reason:  "stopped by user",
	})
	active.cancel()

	// The MissionDone(fail, "stopped by user") submitted above reaches the
	// bus as status:failed via the lifecycle projector. The separate
	// "mission.stopped" wire event had no consumer outside the retired
	// per-run channel (gibson#1112 PR 3).

	// Status is World-derived (ADR-0011/gibson#1118): MissionDone above set
	// status=failed in the World via Reduce. No store write.
	active.mission.CompletedAt = mission.NewUnixTimePtrNow()

	m.logger.Info("mission stopped", "mission_id", missionID)
	return nil
}

// List returns a list of missions with optional filtering.
// Status and progress are World-derived (ADR-0011/gibson#1118): the brain's
// folded World is the authoritative source — no Redis store reads for status.
func (m *missionManager) List(ctx context.Context, activeOnly bool, limit, offset int) ([]api.MissionData, int, error) {
	m.logger.Debug("listing missions", "active_only", activeOnly, "limit", limit, "offset", offset)

	tenant, tenantErr := tenantFromCtx(ctx)
	if tenantErr != nil {
		return nil, 0, tenantErr
	}
	eng := m.brainRegistry.For(tenant.String())
	snapshots := eng.Missions()

	var result []api.MissionData
	for _, ms := range snapshots {
		// C9 closure: only return missions belonging to the calling tenant.
		if ms.TenantID != "" && ms.TenantID != tenant.String() {
			continue
		}
		if activeOnly && ms.Status != brain.MissionRunning && ms.Status != brain.MissionPaused {
			continue
		}
		result = append(result, missionSnapshotToData(ms))
	}

	total := len(result)

	// Apply pagination
	if offset > 0 {
		if offset >= len(result) {
			result = []api.MissionData{}
		} else {
			result = result[offset:]
		}
	}
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}

	m.logger.Debug("listed missions", "total", total, "returned", len(result))
	return result, total, nil
}

// Get returns a specific mission by ID, scoped to the calling tenant.
// Status is World-derived (ADR-0011/gibson#1118).
func (m *missionManager) Get(ctx context.Context, missionID string) (*api.MissionData, error) {
	m.logger.Debug("getting mission", "mission_id", missionID)

	tenant, tenantErr := tenantFromCtx(ctx)
	if tenantErr != nil {
		return nil, tenantErr
	}
	eng := m.brainRegistry.For(tenant.String())
	for _, ms := range eng.Missions() {
		if ms.ID != missionID {
			continue
		}
		// C9 closure: a caller cannot read another tenant's mission.
		if ms.TenantID != "" && ms.TenantID != tenant.String() {
			break
		}
		data := missionSnapshotToData(ms)
		return &data, nil
	}
	return nil, fmt.Errorf("mission %s not found", missionID)
}

// missionSnapshotToData converts a brain.MissionSnapshot (World-derived, ADR-0011)
// to api.MissionData. Status and progress are authoritative — they come from the
// folded World, not a secondary store.
func missionSnapshotToData(ms brain.MissionSnapshot) api.MissionData {
	return api.MissionData{
		ID:           ms.ID,
		TenantID:     ms.TenantID,
		Name:         ms.Name,
		Description:  ms.Description,
		TargetID:     ms.TargetID,
		Status:       string(ms.Status),
		Progress:     ms.Progress,
		FindingCount: ms.FindingsCount,
	}
}

// worldMissionStatus returns the current status string for missionID from the
// brain's folded World (ADR-0011/gibson#1118). Returns "" if the mission is not
// in the World yet (it may still be initialising on the intake queue).
func worldMissionStatus(eng *brain.Engine, missionID string) string {
	for _, ms := range eng.Missions() {
		if ms.ID == missionID {
			return string(ms.Status)
		}
	}
	return ""
}

// GetActiveMissionCount returns the number of currently active missions.
func (m *missionManager) GetActiveMissionCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.activeMissions)
}

// GetTotalMissionCount returns the total number of missions (active + completed).
func (m *missionManager) GetTotalMissionCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.activeMissions) + m.completedCount
}

// missionGoal returns the mission's Decider goal. A mission carries it in
// metadata["goal"]; absent → empty, meaning a purely scripted mission that the
// brain scheduler runs to completion without invoking the Decider (gibson#851).
func missionGoal(m *mission.Mission) string {
	if m == nil || m.Metadata == nil {
		return ""
	}
	if g, ok := m.Metadata["goal"].(string); ok {
		return g
	}
	return ""
}

// awaitBrainMission blocks until the brain reaches a terminal state for the given
// mission, or ctx is cancelled. It polls the engine's mission snapshots (the
// engine's own tick + drain loops drive execution). Returns the mapped mission
// status and an error message (empty on success).
func (m *missionManager) awaitBrainMission(ctx context.Context, eng *brain.Engine, missionID string) (mission.MissionStatus, string) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return mission.MissionStatusCancelled, "mission cancelled"
		case <-ticker.C:
			for _, ms := range eng.Missions() {
				if ms.ID != missionID {
					continue
				}
				switch ms.Status {
				case brain.MissionCompleted:
					return mission.MissionStatusCompleted, ""
				case brain.MissionFailed:
					reason := ms.Reason
					if reason == "" {
						reason = "mission failed"
					}
					return mission.MissionStatusFailed, reason
				}
			}
		}
	}
}
