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

// resolveTargetUUID enforces the UUID-only, tenant-scoped target contract shared
// by CreateMission and RunMission. The target_id MUST be a UUID — a non-UUID is
// a hard invalid-argument, never a name to look up. A missing or cross-tenant
// target is reported as not-found. System/internal callers (no real tenant) and
// legacy targets carrying no stamped tenant are exempt from the tenant check to
// preserve existing internal flows.
func resolveTargetUUID(ctx context.Context, store targetGetter, targetID, callerTenant string) (*types.Target, error) {
	parsed, err := types.ParseID(targetID)
	if err != nil {
		return nil, fmt.Errorf("invalid target_id %q: a target UUID is required: %w", targetID, err)
	}
	t, err := store.Get(ctx, parsed)
	if err != nil || t == nil {
		return nil, fmt.Errorf("target %q not found", targetID)
	}
	if t.TenantID != "" && callerTenant != auth.SystemTenant.String() && callerTenant != t.TenantID {
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
	pool            datapool.Pool           // per-tenant data-plane pool (replaces missionStore, missionRunStore, findingStore)
	checkpointStore mission.CheckpointStore // Stores mission checkpoints for pause/resume
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

// activeMission tracks a running mission with its context and event channel
type activeMission struct {
	mission      *mission.Mission
	missionRun   *mission.MissionRun // The specific run instance
	ctx          context.Context
	cancel       context.CancelFunc
	eventChan    chan api.MissionEventData
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
	checkpointStore mission.CheckpointStore,
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
		checkpointStore: checkpointStore,
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

// tenantFromCtxOrSystem extracts the tenant from the context; returns SystemTenant
// when none is present (e.g., admin or unauthed internal callers).
func tenantFromCtxOrSystem(ctx context.Context) auth.TenantID {
	t, ok := auth.TenantFromContext(ctx)
	if !ok {
		return auth.SystemTenant
	}
	return t
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

// tenantActive returns all active missions for a specific tenant (C9 closure).
func (mm *missionManager) tenantActive(tenant auth.TenantID) []*activeMission {
	mm.mu.RLock()
	defer mm.mu.RUnlock()
	sub := mm.activeMissions[tenant]
	result := make([]*activeMission, 0, len(sub))
	for _, am := range sub {
		result = append(result, am)
	}
	return result
}

// Run starts a mission by reference and returns an event channel for progress
// updates. Missions are invoked by reference only — the mission definition and
// target must already be registered. File-path / inline-YAML invocation was
// removed under spec mission-api-only-cleanup.
func (m *missionManager) Run(ctx context.Context, missionDefinitionID string, targetID string, variables map[string]string, memoryContinuity string) (<-chan api.MissionEventData, error) {
	m.logger.Info("starting mission",
		"mission_definition_id", missionDefinitionID,
		"target_id", targetID,
		"variables", len(variables),
		"memory_continuity", memoryContinuity,
	)

	if missionDefinitionID == "" {
		return nil, fmt.Errorf("mission_definition_id is required")
	}
	if targetID == "" {
		return nil, fmt.Errorf("target_id is required")
	}

	// Load mission definition from the calling tenant's store.
	callingTenantForDef := tenantFromCtxOrSystem(ctx)
	defStore, defRelease, defStoreErr := m.missionStoreFor(ctx, callingTenantForDef)
	if defStoreErr != nil {
		return nil, fmt.Errorf("mission run: get store for definition: %w", defStoreErr)
	}
	defer defRelease()

	if defStore == nil {
		return nil, fmt.Errorf("mission store not initialized (pool not configured)")
	}

	// Load mission definition from the registered-definition store. The caller
	// may supply either the name (friendly ID used in Redis key) or the parsed
	// ID — try name first, fall back to ID lookup across all definitions.
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

	m.logger.Debug("mission definition loaded",
		"mission_name", def.GetName(),
		"node_count", len(def.GetNodes()),
	)

	// Shared-Neo4j-backed mission graph storage removed (spec graphrag-tenant-scope).
	// Per-tenant mission graph storage via Pool will be added in a follow-up spec.

	// Resolve the target by UUID only (no name resolution) and enforce tenant
	// ownership. The shared resolveTargetUUID path is identical to the one
	// CreateMission uses, so the two entry points cannot diverge.
	if m.targetStore == nil {
		return nil, fmt.Errorf("target_id '%s' supplied but target store not available", targetID)
	}
	target, err := resolveTargetUUID(ctx, m.targetStore, targetID, callingTenantForDef.String())
	if err != nil {
		return nil, err
	}
	resolvedTargetID := target.ID
	targetRef := target.Name
	if target.URL != "" {
		targetRef = target.URL
	} else if conn, ok := target.Connection["url"].(string); ok && conn != "" {
		targetRef = conn
	}
	m.logger.Debug("resolved target", "target_id", resolvedTargetID, "target_ref", targetRef)

	// Build an internal mission ID for tracking this run.
	missionID := types.NewID().String()

	// Resolve the calling tenant (C9 isolation key).
	callingTenant := tenantFromCtxOrSystem(ctx)

	// Check if mission ID already exists (defensive — should not be possible with fresh IDs)
	if _, exists := m.getActive(callingTenant, missionID); exists {
		return nil, fmt.Errorf("mission %s is already running", missionID)
	}

	// Serialize mission definition to canonical protojson for storage.
	definitionJSON, err := mission.MarshalDefinitionJSON(def)
	if err != nil {
		m.logger.Error("failed to serialize mission definition", "error", err)
		return nil, fmt.Errorf("failed to serialize mission definition: %w", err)
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
		return nil, fmt.Errorf("mission run: acquire mission store: %w", mStoreErr)
	}
	defer mStoreRelease()

	// Use FindOrCreateByName to get stable mission ID
	var missionRecord *mission.Mission
	var isNewMission bool
	if mStore != nil {
		missionRecord, isNewMission, err = mStore.FindOrCreateByName(ctx, missionTemplate)
		if err != nil {
			m.logger.Error("failed to find or create mission", "error", err, "mission_name", def.GetName())
			return nil, fmt.Errorf("failed to find or create mission: %w", err)
		}
		m.logger.Info("mission lookup result",
			"mission_id", missionRecord.ID,
			"mission_name", missionRecord.Name,
			"is_new", isNewMission,
		)

		// For existing missions, ensure metadata is updated with current run's values
		// The metadata from missionTemplate contains run-specific data like target_ref
		if !isNewMission {
			if missionRecord.Metadata == nil {
				missionRecord.Metadata = make(map[string]any)
			}
			// Copy target_ref from template to record (run-specific target)
			if targetRef != "" {
				missionRecord.Metadata["target_ref"] = targetRef
				m.logger.Debug("updated mission metadata with target_ref",
					"mission_id", missionRecord.ID,
					"target_ref", targetRef,
				)
			}
			// Copy variables from template to record (run-specific variables)
			if vars, ok := missionTemplate.Metadata["variables"]; ok {
				missionRecord.Metadata["variables"] = vars
			}
		}
	} else {
		// No store available (pool not configured), use template directly
		missionRecord = missionTemplate
		isNewMission = true
	}

	// Create new MissionRun for this execution
	var missionRun *mission.MissionRun
	rStore, rStoreRelease, rStoreErr := m.runStoreFor(ctx, callingTenant)
	defer rStoreRelease()
	if rStoreErr != nil {
		m.logger.Warn("failed to acquire run store; using ephemeral run", "error", rStoreErr)
	}
	if rStore != nil {
		// Get next run number
		runNumber, err := rStore.GetNextRunNumber(ctx, missionRecord.ID)
		if err != nil {
			m.logger.Error("failed to get next run number", "error", err)
			return nil, fmt.Errorf("failed to get next run number: %w", err)
		}

		// Create the run record
		missionRun = mission.NewMissionRun(missionRecord.ID, runNumber)
		missionRun.MarkStarted()

		if err := rStore.Save(ctx, missionRun); err != nil {
			m.logger.Error("failed to save mission run", "error", err)
			return nil, fmt.Errorf("failed to save mission run: %w", err)
		}

		m.logger.Info("created mission run",
			"mission_id", missionRecord.ID,
			"run_id", missionRun.ID,
			"run_number", runNumber,
		)
	} else {
		// Fallback: create ephemeral run when pool is not configured
		missionRun = mission.NewMissionRun(missionRecord.ID, 1)
		missionRun.MarkStarted()
		m.logger.Warn("mission run store not available (pool not configured), using ephemeral run")
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

	// Create event channel for mission updates
	eventChan := make(chan api.MissionEventData, 100)

	// Create mission context with cancellation
	missionCtx, cancel := context.WithCancel(context.Background())

	// Create active mission entry - use mission.ID (stable) for tracking
	active := &activeMission{
		mission:    missionRecord,
		missionRun: missionRun,
		ctx:        missionCtx,
		cancel:     cancel,
		eventChan:  eventChan,
		startTime:  time.Now(),
		tenantID:   callingTenant,
	}

	// Register active mission under the calling tenant's partition (C9 closure).
	m.setActive(callingTenant, missionRecord.ID.String(), active)

	// Emit mission started event
	m.emitEvent(eventChan, api.MissionEventData{
		EventType: "mission.started",
		Timestamp: time.Now(),
		MissionID: missionRecord.ID.String(),
		Message:   fmt.Sprintf("Mission %s run #%d started", missionRecord.Name, missionRun.RunNumber),
	})

	// Launch mission executor in goroutine - pass mission ID (stable)
	go m.executeMission(missionCtx, missionRecord.ID.String(), def, eventChan)

	return eventChan, nil
}

// executeMission runs the mission execution using the orchestrator.
// This handles the full mission lifecycle including setup, execution via
// the Observe → Think → Act loop, and cleanup.
func (m *missionManager) executeMission(ctx context.Context, missionID string, def *missionpb.MissionDefinition, eventChan chan api.MissionEventData) {
	defer close(eventChan)

	// Create mission execution span if OTel tracing is enabled
	var span trace.Span
	if m.otelStack != nil && m.otelStack.TracerProvider != nil {
		tracer := m.otelStack.TracerProvider.Tracer("gibson")
		ctx, span = tracer.Start(ctx, observability.SpanMissionExecute,
			trace.WithAttributes(
				attribute.String(observability.GibsonMissionID, missionID),
				attribute.String(observability.GibsonMissionName, def.GetName()),
			),
		)
		defer span.End()
	}

	m.logger.Info("executing mission with orchestrator", "mission_id", missionID)

	// Find the active mission across all tenants (this goroutine runs without
	// a tenant-carrying context; use the stored tenantID on the active entry).
	var active *activeMission
	var exists bool
	m.mu.RLock()
	for _, sub := range m.activeMissions {
		if am, ok := sub[missionID]; ok {
			active = am
			exists = true
			break
		}
	}
	m.mu.RUnlock()
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

		m.emitEvent(eventChan, api.MissionEventData{
			EventType: "mission.failed",
			Timestamp: time.Now(),
			MissionID: missionID,
			Error:     "internal error: mission not found",
		})
		return
	}

	// Add mission name to span now that we have the active mission
	if span != nil {
		span.SetAttributes(attribute.String(observability.GibsonMissionName, active.mission.Name))
	}

	// Persist the OTel trace ID into mission metadata for Langfuse lookup
	activeSpan := trace.SpanFromContext(ctx)
	if activeSpan.SpanContext().HasTraceID() {
		if active.mission.Metadata == nil {
			active.mission.Metadata = make(map[string]any)
		}
		active.mission.Metadata["trace_id"] = activeSpan.SpanContext().TraceID().String()
		m.logger.Debug("persisted trace ID to mission metadata",
			"mission_id", missionID,
			"trace_id", active.mission.Metadata["trace_id"],
		)
	}

	// Set StartedAt timestamp now that execution is beginning
	active.mission.StartedAt = mission.NewUnixTimePtrNow()

	// Update mission status to Running in the per-tenant store.
	active.mission.Status = mission.MissionStatusRunning
	if mStore, release, storeErr := m.missionStoreFor(ctx, active.tenantID); storeErr == nil && mStore != nil {
		defer release()
		if err := mStore.Update(ctx, active.mission); err != nil {
			m.logger.Warn("failed to update mission status in store", "error", err, "mission_id", missionID)
			// Continue execution - not critical
		}
	} else if storeErr != nil {
		m.logger.Warn("failed to acquire store for status update", "error", storeErr, "mission_id", missionID)
	}

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
		m.emitEvent(eventChan, api.MissionEventData{
			EventType: "mission.failed",
			Timestamp: time.Now(),
			MissionID: missionID,
			Error:     "data-plane pool is required for mission execution but not configured",
		})
		return
	}
	poolConn, poolErr := m.pool.For(ctx, active.tenantID)
	if poolErr != nil {
		m.logger.Error("failed to acquire per-tenant Neo4j session",
			"mission_id", missionID,
			"tenant_id", active.tenantID,
			"error", poolErr)
		m.emitEvent(eventChan, api.MissionEventData{
			EventType: "mission.failed",
			Timestamp: time.Now(),
			MissionID: missionID,
			Error:     fmt.Sprintf("failed to acquire tenant Neo4j session: %v", poolErr),
		})
		return
	}
	defer poolConn.Release()

	// Wrap the per-tenant session as a GraphClient for the mission graph bootstrap.
	graphClient := graph.NewSessionGraphClient(poolConn.Neo4j)

	// Use the MissionRun from active mission (already created in Run())
	missionRun := active.missionRun
	if missionRun == nil {
		m.logger.Error("mission run not found in active mission", "mission_id", missionID)
		m.emitEvent(eventChan, api.MissionEventData{
			EventType: "mission.failed",
			Timestamp: time.Now(),
			MissionID: missionID,
			Error:     "internal error: mission run not initialized",
		})
		return
	}

	// Bootstrap mission graph structure before execution.
	bootstrapper := NewGraphBootstrapper(graphClient, m.logger)
	bootstrapResult, err := bootstrapper.Bootstrap(ctx, active.mission, def, missionRun)
	if err != nil {
		m.logger.Error("failed to bootstrap mission graph", "error", err, "mission_id", missionID)
		m.emitEvent(eventChan, api.MissionEventData{
			EventType: "mission.failed",
			Timestamp: time.Now(),
			MissionID: missionID,
			Error:     fmt.Sprintf("failed to initialize mission graph: %v", err),
		})
		return
	}

	// Create mission context and target info for harness
	// Include MissionRunID for GraphRAG mission-scoped storage
	missionCtx := harness.NewMissionContext(active.mission.ID, active.mission.Name, "").
		WithMissionRunID(bootstrapResult.MissionRunID).
		WithRunNumber(missionRun.RunNumber).
		WithTenant(active.mission.TenantID)

	// Load target entity to get connection details
	var targetInfo harness.TargetInfo
	if active.mission.TargetID == "00000000-0000-0000-0000-d15c00e00000" {
		// Synthetic target for discovery/orchestration missions
		targetInfo = harness.NewTargetInfo(active.mission.TargetID, "discovery-mission", "", "discovery")
	} else if ts, ok := m.targetStore.(mission.TargetStore); ok {
		target, err := ts.Get(ctx, active.mission.TargetID)
		if err != nil {
			m.logger.Error("failed to load target", "error", err, "target_id", active.mission.TargetID)
			m.emitEvent(eventChan, api.MissionEventData{
				EventType: "mission.failed",
				Timestamp: time.Now(),
				MissionID: missionID,
				Error:     fmt.Sprintf("failed to load target: %v", err),
			})
			return
		}
		targetInfo = harness.NewTargetInfoFull(
			target.ID,
			target.Name,
			target.URL,
			target.Type,
			target.Connection,
		)
	} else {
		targetInfo = harness.NewTargetInfo(active.mission.TargetID, "mission-target", "", "")
	}

	// Create harness for agent execution
	agentHarness, err := m.harnessFactory.Create("orchestrator", missionCtx, targetInfo)
	if err != nil {
		m.logger.Error("failed to create harness", "error", err)
		m.emitEvent(eventChan, api.MissionEventData{
			EventType: "mission.failed",
			Timestamp: time.Now(),
			MissionID: missionID,
			Error:     fmt.Sprintf("failed to create harness: %v", err),
		})
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
	if projErr != nil {
		finalStatus = mission.MissionStatusFailed
		errorMsg = fmt.Sprintf("failed to project mission into the World: %v", projErr)
		if span != nil {
			span.RecordError(projErr)
			span.SetStatus(codes.Error, errorMsg)
		}
		m.emitEvent(eventChan, api.MissionEventData{EventType: "mission.failed", Timestamp: time.Now(), MissionID: missionID, Error: errorMsg})
	} else {
		eng.Submit(proj)
		m.emitEvent(eventChan, api.MissionEventData{EventType: "mission.started", Timestamp: time.Now(), MissionID: missionID, Message: fmt.Sprintf("Brain executing mission %s", missionID)})

		// Block until the brain reaches a terminal mission state (or ctx is cancelled).
		finalStatus, errorMsg = m.awaitBrainMission(ctx, eng, missionID)
		missionDuration = time.Since(active.startTime)

		m.logger.Info("brain mission execution finished",
			"mission_id", missionID, "status", finalStatus, "duration", missionDuration)

		if finalStatus == mission.MissionStatusCompleted {
			if span != nil {
				span.SetStatus(codes.Ok, "mission completed")
				span.SetAttributes(attribute.Int("gibson.mission.duration_ms", int(missionDuration.Milliseconds())))
			}
			m.emitEvent(eventChan, api.MissionEventData{EventType: "mission.completed", Timestamp: time.Now(), MissionID: missionID, Message: fmt.Sprintf("Mission completed with status: %s", finalStatus)})
		} else {
			if span != nil {
				span.SetStatus(codes.Error, errorMsg)
				span.SetAttributes(attribute.Int("gibson.mission.duration_ms", int(missionDuration.Milliseconds())))
			}
			m.emitEvent(eventChan, api.MissionEventData{EventType: "mission.failed", Timestamp: time.Now(), MissionID: missionID, Error: errorMsg})
		}
	}
	_ = missionDuration

	// Transition authz state so that late-arriving component callbacks receive a
	// proper inactive-mission error rather than stale "active" state. Errors are
	// logged and do not block mission lifecycle cleanup.
	// One-code-path slice deploy#195: authzStore is required (no more nil
	// guard). missionRun may still be nil if the mission failed before a run
	// row was allocated.
	if missionRun != nil {
		bgCtx := context.Background()
		runIDStr := missionRun.ID.String()
		if finalStatus == mission.MissionStatusCompleted {
			if markErr := m.authzStore.MarkCompleted(bgCtx, runIDStr); markErr != nil {
				m.logger.Warn("failed to mark authz state completed",
					slog.String("run_id", runIDStr),
					slog.String("error", markErr.Error()),
				)
			}
		} else {
			if markErr := m.authzStore.MarkCancelled(bgCtx, runIDStr); markErr != nil {
				m.logger.Warn("failed to mark authz state cancelled",
					slog.String("run_id", runIDStr),
					slog.String("error", markErr.Error()),
				)
			}
		}
	}

	// Decrement the concurrent_missions counter on terminal-state transition.
	// Floored at zero. Spec plans-and-quotas-simplification.
	if m.quotaCounter != nil {
		if decErr := m.quotaCounter.DecrementMissionCount(ctx); decErr != nil {
			m.logger.Warn("mission manager: decrement concurrent_missions failed (non-fatal)",
				"mission_id", missionID, "error", decErr.Error())
		}
	}

	// Update mission in the per-tenant store.
	active.mission.Status = finalStatus
	active.mission.Error = errorMsg
	active.mission.CompletedAt = mission.NewUnixTimePtrNow()

	if mStore, release, storeErr := m.missionStoreFor(ctx, active.tenantID); storeErr == nil && mStore != nil {
		defer release()
		if saveErr := mStore.Update(ctx, active.mission); saveErr != nil {
			m.logger.Warn("failed to update mission in store", "error", saveErr)
		}
	} else if storeErr != nil {
		m.logger.Warn("failed to acquire store to save final mission status", "error", storeErr)
	}

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

	tenant := tenantFromCtxOrSystem(ctx)
	active, exists := m.getActive(tenant, missionID)
	if !exists {
		return fmt.Errorf("mission %s not found or not running", missionID)
	}

	m.brainRegistry.For(active.tenantID.String()).Submit(brain.MissionPauseRequested{ID: missionID})

	active.mission.Status = mission.MissionStatusPaused
	if mStore, release, storeErr := m.missionStoreFor(ctx, active.tenantID); storeErr == nil && mStore != nil {
		defer release()
		if err := mStore.Update(ctx, active.mission); err != nil {
			m.logger.Warn("failed to persist paused status", "error", err, "mission_id", missionID)
		}
	}

	m.emitEvent(active.eventChan, api.MissionEventData{
		EventType: "mission.paused",
		Timestamp: time.Now(),
		MissionID: missionID,
		Message:   "Mission paused",
	})
	return nil
}

// Resume resumes a paused mission. Brain-native: the mission goroutine is still
// alive (paused in the engine), so Resume un-halts it in the World and returns the
// existing event stream. Cross-restart resume is not yet supported — the brain
// Timeline is in-memory (durable Timeline persistence is a follow-up).
func (m *missionManager) Resume(ctx context.Context, missionID string) (<-chan api.MissionEventData, error) {
	m.logger.Info("resuming mission", "mission_id", missionID)

	tenant := tenantFromCtxOrSystem(ctx)
	active, exists := m.getActive(tenant, missionID)
	if !exists {
		return nil, fmt.Errorf("mission %s is not active (resume requires a paused, in-memory mission)", missionID)
	}
	if active.mission.Status != mission.MissionStatusPaused {
		return nil, fmt.Errorf("cannot resume mission %s: status is %s (expected paused)", missionID, active.mission.Status)
	}

	m.brainRegistry.For(active.tenantID.String()).Submit(brain.MissionResumed{ID: missionID})

	active.mission.Status = mission.MissionStatusRunning
	if mStore, release, storeErr := m.missionStoreFor(ctx, active.tenantID); storeErr == nil && mStore != nil {
		defer release()
		if err := mStore.Update(ctx, active.mission); err != nil {
			m.logger.Warn("failed to persist running status on resume", "error", err, "mission_id", missionID)
		}
	}

	m.emitEvent(active.eventChan, api.MissionEventData{
		EventType: "mission.resumed",
		Timestamp: time.Now(),
		MissionID: missionID,
		Message:   "Mission resumed",
	})
	return active.eventChan, nil
}

// Stop stops a running mission with optional force flag.
// Only the calling tenant's missions may be stopped (C9 closure).
func (m *missionManager) Stop(ctx context.Context, missionID string, force bool) error {
	m.logger.Info("stopping mission", "mission_id", missionID, "force", force)

	tenant := tenantFromCtxOrSystem(ctx)
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

	// Emit stop event
	m.emitEvent(active.eventChan, api.MissionEventData{
		EventType: "mission.stopped",
		Timestamp: time.Now(),
		MissionID: missionID,
		Message:   "Mission stopped by user",
	})

	// Update mission status in the per-tenant store.
	active.mission.Status = mission.MissionStatusCancelled
	active.mission.CompletedAt = mission.NewUnixTimePtrNow()

	if mStore, release, storeErr := m.missionStoreFor(ctx, active.tenantID); storeErr == nil && mStore != nil {
		defer release()
		if err := mStore.Update(ctx, active.mission); err != nil {
			m.logger.Warn("failed to update mission in store", "error", err)
		}
	} else if storeErr != nil {
		m.logger.Warn("failed to acquire store to stop mission", "error", storeErr)
	}

	m.logger.Info("mission stopped", "mission_id", missionID)
	return nil
}

// List returns a list of missions with optional filtering.
func (m *missionManager) List(ctx context.Context, activeOnly bool, limit, offset int) ([]api.MissionData, int, error) {
	m.logger.Debug("listing missions", "active_only", activeOnly, "limit", limit, "offset", offset)

	var result []api.MissionData

	// Get active missions scoped to the calling tenant (C9 closure).
	tenant := tenantFromCtxOrSystem(ctx)
	tenantActives := m.tenantActive(tenant)
	activeMissions := make([]*mission.Mission, 0, len(tenantActives))
	for _, am := range tenantActives {
		activeMissions = append(activeMissions, am.mission)
	}

	// Add active missions to result
	for _, m := range activeMissions {
		result = append(result, missionToData(m))
	}

	// If not active-only, also fetch from the per-tenant store.
	if !activeOnly {
		if mStore, release, storeErr := m.missionStoreFor(ctx, tenant); storeErr == nil && mStore != nil {
			defer release()
			filter := mission.NewMissionFilter()
			filter.Limit = 1000 // Get a reasonable number
			filter.Offset = 0

			stored, listErr := mStore.List(ctx, filter)
			if listErr != nil {
				m.logger.Warn("failed to list missions from store", "error", listErr)
			} else {
				// Add completed missions that aren't already in active list
				for _, storedMission := range stored {
					isActive := false
					for _, active := range activeMissions {
						if active.ID == storedMission.ID {
							isActive = true
							break
						}
					}
					if !isActive && storedMission.Status.IsTerminal() {
						result = append(result, missionToData(storedMission))
					}
				}
			}
		}
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
func (m *missionManager) Get(ctx context.Context, missionID string) (*api.MissionData, error) {
	m.logger.Debug("getting mission", "mission_id", missionID)

	tenant := tenantFromCtxOrSystem(ctx)
	// Check active missions for the calling tenant first (C9 closure).
	if active, exists := m.getActive(tenant, missionID); exists {
		data := missionToData(active.mission)
		return &data, nil
	}

	// Check the per-tenant store.
	if mStore, release, storeErr := m.missionStoreFor(ctx, tenant); storeErr == nil && mStore != nil {
		defer release()
		missionRecord, err := mStore.Get(ctx, types.ID(missionID))
		if err == nil {
			data := missionToData(missionRecord)
			return &data, nil
		}
	}

	return nil, fmt.Errorf("mission %s not found", missionID)
}

// emitEvent safely sends an event to the event channel without blocking.
func (m *missionManager) emitEvent(eventChan chan api.MissionEventData, event api.MissionEventData) {
	select {
	case eventChan <- event:
		// Event sent successfully
	default:
		// Channel full or closed, log and skip
		m.logger.Warn("failed to emit mission event: channel full or closed",
			"event_type", event.EventType,
			"mission_id", event.MissionID,
		)
	}
}

// missionToData converts a mission.Mission to api.MissionData.
func missionToData(m *mission.Mission) api.MissionData {
	data := api.MissionData{
		ID:                  m.ID.String(),
		MissionDefinitionID: m.MissionDefinitionID.String(),
		TargetID:            m.TargetID.String(),
		Status:              string(m.Status),
		StartTime:           m.CreatedAt.Time,
		FindingCount:        int32(m.FindingsCount),
	}

	if !m.CompletedAt.IsNil() {
		data.EndTime = *m.CompletedAt.Time
	}

	return data
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
