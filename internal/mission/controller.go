package mission

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/zeroroot-ai/gibson/internal/checkpoint"
	"github.com/zeroroot-ai/gibson/internal/component"
	"github.com/zeroroot-ai/gibson/internal/types"
	"github.com/zeroroot-ai/sdk/auth"
)

// MissionController provides high-level mission control operations.
type MissionController interface {
	// CreateByReference creates a new mission that references a pre-registered
	// target and mission definition. Inline construction is not supported —
	// callers register the definition via the daemon's CreateMissionDefinition
	// RPC first, then call this method with the resulting IDs.
	CreateByReference(ctx context.Context, req CreateMissionByReferenceRequest) (*Mission, error)

	// Start transitions mission to running and begins execution
	Start(ctx context.Context, missionID types.ID) error

	// Stop gracefully cancels mission execution
	Stop(ctx context.Context, missionID types.ID) error

	// Pause suspends mission at next checkpoint
	Pause(ctx context.Context, missionID types.ID) error

	// Resume continues mission from checkpoint
	Resume(ctx context.Context, missionID types.ID) error

	// Delete removes mission (only terminal states)
	Delete(ctx context.Context, missionID types.ID) error

	// Get retrieves a mission by ID
	Get(ctx context.Context, missionID types.ID) (*Mission, error)

	// List retrieves missions with filtering
	List(ctx context.Context, filter *MissionFilter) ([]*Mission, error)

	// GetProgress returns real-time progress for a mission
	GetProgress(ctx context.Context, missionID types.ID) (*MissionProgress, error)
}

// QuotaCounter is the narrow interface the controller uses to maintain
// per-tenant concurrent-mission counters. Spec
// plans-and-quotas-simplification: INCR fires when the controller commits
// to executing a mission (immediately before the orchestrator goroutine
// launches), DECR fires from the deferred terminal-state block. Implemented
// by *component.QuotaManager.
type QuotaCounter interface {
	IncrementMissionCount(ctx context.Context) error
	DecrementMissionCount(ctx context.Context) error
}

// DefaultMissionController implements MissionController.
type DefaultMissionController struct {
	store             MissionStore
	service           MissionService
	orchestrator      MissionOrchestrator
	checkpointManager CheckpointManager
	checkpointStore   CheckpointStore // New checkpoint store for pause/resume
	runStore          MissionRunStore // Optional: tracks mission runs

	// componentRegistry provides Redis-backed component discovery for agent dispatch.
	// When non-nil, it is used as the primary discovery path for agents. The legacy
	// etcd-based path (inside the orchestrator's harness registryAdapter) remains
	// active as the fallback during the transition period (task 11.1 removes it).
	componentRegistry component.ComponentRegistry

	// workQueue provides pull-based work dispatch over Redis Streams.
	// Used in conjunction with componentRegistry to route work to remote agents
	// that have no direct gRPC endpoint.
	workQueue component.WorkQueue

	// authzStore tracks which user owns each running mission run so that
	// HarnessCallbackService.Authorize can resolve run_id → (user_id, tenant_id).
	// One-code-path slice deploy#195: every running daemon has FGA wired and
	// a real authzStore. Callsites assume non-nil. Tests that construct a
	// DefaultMissionController directly must inject a (real or fake) store
	// via WithAuthzStore.
	authzStore MissionAuthzStore

	// quotaCounter increments concurrent_missions when execution begins and
	// decrements on terminal-state transitions. Optional; when nil, the
	// counter is not maintained (dev / no-quota deployments).
	// Spec plans-and-quotas-simplification.
	quotaCounter QuotaCounter

	// checkpointPolicy applies retention rules to a mission's checkpoint
	// threads when the mission reaches a terminal state. Optional — when nil,
	// terminal-state retention is skipped (the threaded checkpointer's own
	// background TTL still applies).
	checkpointPolicy checkpoint.CheckpointPolicy

	// threadManager resolves the threads associated with a mission so that
	// retention can be applied per-thread. Optional — when nil, terminal-
	// state retention is skipped.
	threadManager checkpoint.ThreadManager

	// logger for structured mission controller logging.
	logger *slog.Logger

	// executionMu protects concurrent mission operations
	executionMu sync.RWMutex
	// activeMissions tracks currently executing missions
	activeMissions map[types.ID]context.CancelFunc
	// activeRuns tracks the current run ID for each active mission
	activeRuns map[types.ID]types.ID

	// operationLocksMu protects access to the operationLocks map
	operationLocksMu sync.Mutex
	// operationLocks provides per-mission mutexes to prevent concurrent operations
	// on the same mission (e.g., simultaneous pause and resume)
	operationLocks map[types.ID]*sync.Mutex
}

// ControllerOption is a functional option for configuring the controller.
type ControllerOption func(*DefaultMissionController)

// WithCheckpointManager sets the checkpoint manager for pause/resume capability.
func WithCheckpointManager(cm CheckpointManager) ControllerOption {
	return func(c *DefaultMissionController) {
		c.checkpointManager = cm
	}
}

// WithCheckpointStore sets the checkpoint store for pause/resume capability.
// This is the new checkpoint system that stores full execution state.
func WithCheckpointStore(cs CheckpointStore) ControllerOption {
	return func(c *DefaultMissionController) {
		c.checkpointStore = cs
	}
}

// WithRunStore sets the run store for mission run tracking.
func WithRunStore(rs MissionRunStore) ControllerOption {
	return func(c *DefaultMissionController) {
		c.runStore = rs
	}
}

// WithComponentRegistry sets the Redis-backed ComponentRegistry for agent dispatch.
// When configured, the controller uses this as the primary agent discovery path,
// with the orchestrator's built-in etcd adapter as the fallback.
// This is part of the unified multi-tenancy migration (task 8.1).
func WithComponentRegistry(reg component.ComponentRegistry) ControllerOption {
	return func(c *DefaultMissionController) {
		c.componentRegistry = reg
	}
}

// WithWorkQueue sets the WorkQueue used for pull-based remote agent dispatch.
// Must be configured together with WithComponentRegistry to enable the remote
// work-queue routing path.
func WithWorkQueue(q component.WorkQueue) ControllerOption {
	return func(c *DefaultMissionController) {
		c.workQueue = q
	}
}

// WithControllerLogger sets the structured logger for the mission controller.
func WithControllerLogger(l *slog.Logger) ControllerOption {
	return func(c *DefaultMissionController) {
		c.logger = l
	}
}

// WithAuthzStore wires the MissionAuthzStore so that the controller records
// the owning user for each run. This enables HarnessCallbackService.Authorize
// to resolve run_id → (user_id, tenant_id) during component callbacks.
//
// One-code-path slice deploy#195: required for every running daemon.
// Tests that construct a controller without it will get panics from
// downstream callsites that assume non-nil.
func WithAuthzStore(store MissionAuthzStore) ControllerOption {
	return func(c *DefaultMissionController) {
		c.authzStore = store
	}
}

// WithCheckpointRetention wires a CheckpointPolicy + ThreadManager into the
// controller so that terminal-state mission transitions trigger
// policy.ApplyRetention(ctx, threadID, status) for every thread of the
// mission. Spec 4 R6 (TTL retention).
//
// Both arguments are required for retention to fire — if either is nil the
// option is a no-op.
func WithCheckpointRetention(policy checkpoint.CheckpointPolicy, tm checkpoint.ThreadManager) ControllerOption {
	return func(c *DefaultMissionController) {
		c.checkpointPolicy = policy
		c.threadManager = tm
	}
}

// WithQuotaCounter wires a QuotaCounter so that the controller maintains
// the concurrent_missions Redis counter on Start/Resume/terminal
// transitions. Spec plans-and-quotas-simplification.
func WithQuotaCounter(qc QuotaCounter) ControllerOption {
	return func(c *DefaultMissionController) {
		c.quotaCounter = qc
	}
}

// NewMissionController creates a new mission controller.
func NewMissionController(
	store MissionStore,
	service MissionService,
	orchestrator MissionOrchestrator,
	opts ...ControllerOption,
) *DefaultMissionController {
	c := &DefaultMissionController{
		store:          store,
		service:        service,
		orchestrator:   orchestrator,
		logger:         slog.Default(),
		activeMissions: make(map[types.ID]context.CancelFunc),
		activeRuns:     make(map[types.ID]types.ID),
		operationLocks: make(map[types.ID]*sync.Mutex),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// applyRetention invokes the configured CheckpointPolicy.ApplyRetention for
// every thread belonging to the mission. Errors are logged at WARN and never
// propagate — retention is best-effort and must not affect mission lifecycle.
//
// Spec 4 R6 (TTL retention via per-mode policy at terminal-state transition).
func (c *DefaultMissionController) applyRetention(ctx context.Context, missionID types.ID, status MissionStatus) {
	if c == nil || c.checkpointPolicy == nil || c.threadManager == nil {
		return
	}
	threads, err := c.threadManager.ListThreads(ctx, missionID)
	if err != nil {
		c.logger.Warn("checkpoint retention: failed to list threads",
			slog.String("mission_id", missionID.String()),
			slog.String("error", err.Error()),
		)
		return
	}
	cpStatus := mapMissionStatusToCheckpointStatus(status)
	for _, t := range threads {
		if t == nil {
			continue
		}
		if err := c.checkpointPolicy.ApplyRetention(ctx, t.ID, cpStatus); err != nil {
			c.logger.Warn("checkpoint retention: ApplyRetention failed",
				slog.String("mission_id", missionID.String()),
				slog.String("thread_id", t.ID),
				slog.String("status", string(status)),
				slog.String("error", err.Error()),
			)
		}
	}
}

// mapMissionStatusToCheckpointStatus translates the mission package's terminal
// status enum into the checkpoint package's equivalent. Both packages have
// parallel constants so the mapping is direct.
func mapMissionStatusToCheckpointStatus(s MissionStatus) checkpoint.MissionStatus {
	switch s {
	case MissionStatusCompleted:
		return checkpoint.MissionStatusCompleted
	case MissionStatusFailed:
		return checkpoint.MissionStatusFailed
	case MissionStatusCancelled:
		return checkpoint.MissionStatusCancelled
	case MissionStatusPaused:
		return checkpoint.MissionStatusPaused
	default:
		return checkpoint.MissionStatusRunning
	}
}

// acquireOperationLock attempts to acquire a lock for the specified mission to prevent
// concurrent operations. Returns an error if another operation is already in progress.
func (c *DefaultMissionController) acquireOperationLock(missionID types.ID) (*sync.Mutex, error) {
	c.operationLocksMu.Lock()
	defer c.operationLocksMu.Unlock()

	// Get or create the mutex for this mission
	mu, exists := c.operationLocks[missionID]
	if !exists {
		mu = &sync.Mutex{}
		c.operationLocks[missionID] = mu
	}

	// Try to acquire the lock (non-blocking)
	locked := mu.TryLock()
	if !locked {
		return nil, NewMissionError(
			ErrMissionInternal,
			fmt.Sprintf("operation already in progress for mission %s", missionID.String()),
		).WithContext("mission_id", missionID.String())
	}

	return mu, nil
}

// releaseOperationLock releases the operation lock for the specified mission.
func (c *DefaultMissionController) releaseOperationLock(missionID types.ID) {
	c.operationLocksMu.Lock()
	defer c.operationLocksMu.Unlock()

	if mu, exists := c.operationLocks[missionID]; exists {
		mu.Unlock()
		// Note: We keep the mutex in the map rather than deleting it
		// to avoid repeated allocations for frequently accessed missions
	}
}

// CreateByReference creates a new mission that references a pre-registered
// target and mission definition.
func (c *DefaultMissionController) CreateByReference(ctx context.Context, req CreateMissionByReferenceRequest) (*Mission, error) {
	return c.service.CreateByReference(ctx, req)
}

// Start transitions mission to running and begins execution.
func (c *DefaultMissionController) Start(ctx context.Context, missionID types.ID) error {
	c.executionMu.Lock()
	defer c.executionMu.Unlock()

	// Get mission
	mission, err := c.store.Get(ctx, missionID)
	if err != nil {
		return err
	}

	// Validate state transition
	if !mission.Status.CanTransitionTo(MissionStatusRunning) {
		return NewInvalidStateError(mission.Status, MissionStatusRunning)
	}

	// Check if already running
	if _, exists := c.activeMissions[missionID]; exists {
		return fmt.Errorf("mission is already running")
	}

	// Create a new run if run store is available
	var runID types.ID
	if c.runStore != nil {
		runNumber, err := c.runStore.GetNextRunNumber(ctx, missionID)
		if err != nil {
			return fmt.Errorf("failed to get next run number: %w", err)
		}

		run := NewMissionRun(missionID, runNumber)
		run.MarkStarted()

		if err := c.runStore.Save(ctx, run); err != nil {
			return fmt.Errorf("failed to create mission run: %w", err)
		}

		runID = run.ID
		c.activeRuns[missionID] = runID
	}

	// Resolve the initiating user once — used both for authz state and for
	// InitiatorUser context propagation below. Empty string is valid
	// (system-scheduled runs have no human initiator).
	initiatorUserID := ""
	if id, err := auth.IdentityFromContext(ctx); err == nil {
		initiatorUserID = id.Subject
	}

	// Record authz state so that HarnessCallbackService.Authorize can look up
	// the owning user during component callbacks. Errors are logged but do not
	// abort the mission start — authz state is advisory.
	// One-code-path slice deploy#195: authzStore is required (no more nil
	// guard). The runID check remains because some code paths can produce a
	// zero runID early in startup before a run row has been allocated.
	if !runID.IsZero() {
		tenantID := auth.TenantStringFromContext(ctx)
		if putErr := c.authzStore.Put(ctx, runID.String(), initiatorUserID, tenantID); putErr != nil {
			c.logger.Warn("mission controller: failed to record authz state on start",
				slog.String("mission_id", missionID.String()),
				slog.String("run_id", runID.String()),
				slog.String("error", putErr.Error()),
			)
		}
	}

	// Build the base execution context.
	// Propagate any tenant present in the caller's context so that the
	// orchestrator's harness can use it for ComponentRegistry lookups.
	// Also propagate the InitiatorUser so every descendant span and LLM
	// call on this mission carries the stable initiator identity through
	// Langfuse (spec: llm-user-attribution-governance, Requirement 1.2,
	// 1.4, 1.5). The caller's synchronous ActingUser is deliberately NOT
	// propagated — this is an autonomous goroutine, there is no longer
	// a synchronous caller.
	baseCtx := context.Background()
	if tenant := auth.TenantStringFromContext(ctx); tenant != "" {
		baseCtx = auth.ContextWithTenantString(baseCtx, tenant)
	}
	if initiatorUserID != "" {
		baseCtx = auth.ContextWithInitiatorUser(baseCtx, initiatorUserID)
	}

	// Log which discovery path will be used for agent dispatch.
	if c.componentRegistry != nil {
		c.logger.Info("mission controller: using ComponentRegistry as primary agent discovery path",
			slog.String("mission_id", missionID.String()),
			slog.Bool("work_queue_configured", c.workQueue != nil),
			slog.String("discovery", "component_registry"),
		)
	} else {
		c.logger.Info("mission controller: ComponentRegistry not configured, using legacy etcd discovery path",
			slog.String("mission_id", missionID.String()),
			slog.String("discovery", "registry_adapter_etcd"),
		)
	}

	// Log pre-flight agent availability if ComponentRegistry is configured.
	// This is informational — failure to list agents does not abort the mission start.
	if c.componentRegistry != nil {
		if tenant := auth.TenantStringFromContext(ctx); tenant != "" {
			agents, listErr := c.componentRegistry.DiscoverAll(ctx, tenant, "agent")
			if listErr != nil {
				c.logger.Warn("mission controller: failed to list available agents via ComponentRegistry",
					slog.String("mission_id", missionID.String()),
					slog.String("tenant", tenant),
					slog.String("error", listErr.Error()),
				)
			} else {
				c.logger.Info("mission controller: pre-flight agent availability check",
					slog.String("mission_id", missionID.String()),
					slog.String("tenant", tenant),
					slog.Int("component_registry_agents", len(agents)),
				)
			}
		}
	}

	// Create cancellable context for execution
	execCtx, cancel := context.WithCancel(baseCtx)
	c.activeMissions[missionID] = cancel

	// Increment the concurrent_missions counter as the mission transitions
	// queued → running (the goroutine below is the dispatch). DECR fires in
	// the deferred terminal block. Failure here is non-fatal: the mission
	// is already committed to executing and a counter mismatch self-corrects
	// via decrementCounter's floor-at-zero. Spec plans-and-quotas-simplification.
	if c.quotaCounter != nil {
		if incErr := c.quotaCounter.IncrementMissionCount(baseCtx); incErr != nil {
			c.logger.Warn("mission controller: increment concurrent_missions failed (non-fatal)",
				slog.String("mission_id", missionID.String()),
				slog.String("error", incErr.Error()),
			)
		}
	}

	// Start mission execution in background
	go func() {
		defer func() {
			c.executionMu.Lock()
			delete(c.activeMissions, missionID)
			delete(c.activeRuns, missionID)
			c.executionMu.Unlock()

			// Decrement the concurrent_missions counter as the mission
			// transitions to a terminal state. baseCtx still carries the
			// tenant identity. Failure floors at zero. Spec
			// plans-and-quotas-simplification.
			if c.quotaCounter != nil {
				if decErr := c.quotaCounter.DecrementMissionCount(baseCtx); decErr != nil {
					c.logger.Warn("mission controller: decrement concurrent_missions failed (non-fatal)",
						slog.String("mission_id", missionID.String()),
						slog.String("error", decErr.Error()),
					)
				}
			}
		}()

		result, err := c.orchestrator.Execute(execCtx, mission)

		// Transition authz state so that late-arriving callbacks get a clean
		// inactive-mission error rather than stale "active" state. Log and
		// continue on errors — mission lifecycle must not be blocked.
		// One-code-path slice deploy#195: authzStore is required (no more nil
		// guard).
		if !runID.IsZero() {
			bgCtx := context.Background()
			if err != nil {
				if markErr := c.authzStore.MarkCancelled(bgCtx, runID.String()); markErr != nil {
					c.logger.Warn("mission controller: failed to mark authz state cancelled",
						slog.String("run_id", runID.String()),
						slog.String("error", markErr.Error()),
					)
				}
			} else {
				if markErr := c.authzStore.MarkCompleted(bgCtx, runID.String()); markErr != nil {
					c.logger.Warn("mission controller: failed to mark authz state completed",
						slog.String("run_id", runID.String()),
						slog.String("error", markErr.Error()),
					)
				}
			}
		}

		// Update the run if run store is available
		if c.runStore != nil && !runID.IsZero() {
			run, getErr := c.runStore.Get(context.Background(), runID)
			if getErr == nil && run != nil {
				if err != nil {
					run.MarkFailed(err.Error())
				} else if result != nil {
					run.MarkCompleted()
					// Update findings count if available in result
					if result.FindingIDs != nil {
						run.FindingsCount = len(result.FindingIDs)
					}
				}
				c.runStore.Update(context.Background(), run)
			}
		}

		// Update mission status
		if err != nil {
			// Update mission with error
			mission.Status = MissionStatusFailed
			mission.Error = err.Error()
			mission.CompletedAt = NewUnixTimePtrNow()
			c.store.Update(context.Background(), mission)
			c.applyRetention(context.Background(), missionID, MissionStatusFailed)
		} else if result != nil {
			// Mission terminated successfully — propagate the result status
			// to retention. The controller already updated the store
			// elsewhere; here we only fire the retention hook.
			c.applyRetention(context.Background(), missionID, result.Status)
		} else {
			c.applyRetention(context.Background(), missionID, MissionStatusCompleted)
		}
	}()

	return nil
}

// Stop gracefully cancels mission execution.
func (c *DefaultMissionController) Stop(ctx context.Context, missionID types.ID) error {
	// Acquire operation lock to prevent concurrent operations
	_, err := c.acquireOperationLock(missionID)
	if err != nil {
		return err
	}
	defer c.releaseOperationLock(missionID)

	c.executionMu.Lock()
	defer c.executionMu.Unlock()

	// Get mission
	mission, err := c.store.Get(ctx, missionID)
	if err != nil {
		return err
	}

	// Check if mission is running
	cancel, exists := c.activeMissions[missionID]
	if !exists {
		return fmt.Errorf("mission is not running")
	}

	// Cancel execution
	cancel()

	// Update the run if run store is available
	if c.runStore != nil {
		if runID, hasRun := c.activeRuns[missionID]; hasRun {
			run, getErr := c.runStore.Get(ctx, runID)
			if getErr == nil && run != nil {
				run.MarkCancelled()
				c.runStore.Update(ctx, run)
			}
		}
	}

	// Mark authz state cancelled so that late-arriving component callbacks
	// receive a proper inactive-mission error. Log and continue on failure.
	// One-code-path slice deploy#195: authzStore is required (no more nil
	// guard).
	if runID, hasRun := c.activeRuns[missionID]; hasRun {
		if markErr := c.authzStore.MarkCancelled(ctx, runID.String()); markErr != nil {
			c.logger.Warn("mission controller: failed to mark authz state cancelled on stop",
				slog.String("mission_id", missionID.String()),
				slog.String("run_id", runID.String()),
				slog.String("error", markErr.Error()),
			)
		}
	}

	// Update mission status
	mission.Status = MissionStatusCancelled
	mission.CompletedAt = NewUnixTimePtrNow()

	if err := c.store.Update(ctx, mission); err != nil {
		return err
	}
	c.applyRetention(ctx, missionID, MissionStatusCancelled)
	return nil
}

// Pause suspends mission at next checkpoint.
func (c *DefaultMissionController) Pause(ctx context.Context, missionID types.ID) error {
	// Acquire operation lock to prevent concurrent operations
	_, err := c.acquireOperationLock(missionID)
	if err != nil {
		return err
	}
	defer c.releaseOperationLock(missionID)

	c.executionMu.RLock()
	cancelFunc, isRunning := c.activeMissions[missionID]
	c.executionMu.RUnlock()

	// Get mission
	mission, err := c.store.Get(ctx, missionID)
	if err != nil {
		return err
	}

	// Validate state transition
	if !mission.Status.CanTransitionTo(MissionStatusPaused) {
		return NewInvalidStateError(mission.Status, MissionStatusPaused)
	}

	// If mission is running, request pause via orchestrator
	if isRunning {
		// For now, we'll cancel execution which will be picked up by orchestrator
		// The orchestrator should detect cancellation and save checkpoint before transitioning to paused
		cancelFunc()

		// Wait for mission to reach paused state (with timeout)
		timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-timeoutCtx.Done():
				return fmt.Errorf("timeout waiting for mission to pause")
			case <-ticker.C:
				// Re-fetch mission to check status
				mission, err = c.store.Get(ctx, missionID)
				if err != nil {
					return fmt.Errorf("failed to check mission status: %w", err)
				}
				if mission.Status == MissionStatusPaused || mission.Status.IsTerminal() {
					return nil
				}
			}
		}
	}

	// Mission is not running, directly update status to paused
	mission.Status = MissionStatusPaused
	return c.store.Update(ctx, mission)
}

// Resume continues mission from checkpoint.
func (c *DefaultMissionController) Resume(ctx context.Context, missionID types.ID) error {
	// Acquire operation lock to prevent concurrent operations
	_, err := c.acquireOperationLock(missionID)
	if err != nil {
		return err
	}
	defer c.releaseOperationLock(missionID)

	c.executionMu.Lock()
	defer c.executionMu.Unlock()

	// Get mission
	mission, err := c.store.Get(ctx, missionID)
	if err != nil {
		return err
	}

	// Validate state transition
	if !mission.Status.CanTransitionTo(MissionStatusRunning) {
		return NewInvalidStateError(mission.Status, MissionStatusRunning)
	}

	// Check if already running
	if _, exists := c.activeMissions[missionID]; exists {
		return fmt.Errorf("mission is already running")
	}

	// Load checkpoint if checkpoint manager is available
	var checkpoint *MissionCheckpoint
	if c.checkpointManager != nil {
		checkpoint, err = c.checkpointManager.Restore(ctx, missionID)
		if err != nil {
			return fmt.Errorf("failed to restore checkpoint: %w", err)
		}
	}

	// Update mission status to running
	mission.Status = MissionStatusRunning
	mission.StartedAt = NewUnixTimePtrNow()
	if err := c.store.Update(ctx, mission); err != nil {
		return fmt.Errorf("failed to update mission status: %w", err)
	}

	// Propagate tenant from caller context into the resumed execution context.
	resumeBaseCtx := context.Background()
	if tenant := auth.TenantStringFromContext(ctx); tenant != "" {
		resumeBaseCtx = auth.ContextWithTenantString(resumeBaseCtx, tenant)
	}

	if c.componentRegistry != nil {
		c.logger.Info("mission controller: resuming with ComponentRegistry as primary agent discovery path",
			slog.String("mission_id", missionID.String()),
			slog.String("discovery", "component_registry"),
		)
	}

	// Create cancellable context for execution
	execCtx, cancel := context.WithCancel(resumeBaseCtx)
	c.activeMissions[missionID] = cancel

	// Start mission execution in background
	go func() {
		defer func() {
			c.executionMu.Lock()
			delete(c.activeMissions, missionID)
			c.executionMu.Unlock()
		}()

		var result *MissionResult
		var err error

		// Execute from checkpoint if available, otherwise execute normally.
		// ExecuteFromCheckpoint pre-marks completed nodes so the scheduler
		// skips them, enabling the mission to resume from where it paused.
		if checkpoint != nil {
			result, err = c.orchestrator.ExecuteFromCheckpoint(execCtx, mission, checkpoint)
		} else {
			result, err = c.orchestrator.Execute(execCtx, mission)
		}

		if err != nil {
			// Update mission with error
			mission.Status = MissionStatusFailed
			mission.Error = err.Error()
			mission.CompletedAt = NewUnixTimePtrNow()
			c.store.Update(context.Background(), mission)
			c.applyRetention(context.Background(), missionID, MissionStatusFailed)
		} else if result != nil {
			// Update mission with result status
			mission.Status = result.Status
			mission.CompletedAt = NewUnixTimePtrNow()
			mission.Metrics = result.Metrics
			c.store.Update(context.Background(), mission)
			c.applyRetention(context.Background(), missionID, result.Status)
		}
	}()

	return nil
}

// Delete removes mission (only terminal states).
func (c *DefaultMissionController) Delete(ctx context.Context, missionID types.ID) error {
	return c.store.Delete(ctx, missionID)
}

// Get retrieves a mission by ID.
func (c *DefaultMissionController) Get(ctx context.Context, missionID types.ID) (*Mission, error) {
	return c.store.Get(ctx, missionID)
}

// List retrieves missions with filtering.
func (c *DefaultMissionController) List(ctx context.Context, filter *MissionFilter) ([]*Mission, error) {
	return c.store.List(ctx, filter)
}

// GetProgress returns real-time progress for a mission.
func (c *DefaultMissionController) GetProgress(ctx context.Context, missionID types.ID) (*MissionProgress, error) {
	mission, err := c.store.Get(ctx, missionID)
	if err != nil {
		return nil, err
	}

	return mission.GetProgress(), nil
}

// Ensure DefaultMissionController implements MissionController.
var _ MissionController = (*DefaultMissionController)(nil)
