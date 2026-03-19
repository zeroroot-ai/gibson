package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/config"
	"github.com/zero-day-ai/gibson/internal/daemon/api"
	"github.com/zero-day-ai/gibson/internal/finding"
	"github.com/zero-day-ai/gibson/internal/graphrag/queries"
	"github.com/zero-day-ai/gibson/internal/graphrag/schema"
	"github.com/zero-day-ai/gibson/internal/harness"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/observability"
	"github.com/zero-day-ai/gibson/internal/orchestrator"
	"github.com/zero-day-ai/gibson/internal/registry"
	"github.com/zero-day-ai/gibson/internal/types"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// targetStore is an interface for target lookup in mission manager
type targetStoreLookup interface {
	GetByName(ctx context.Context, name string) (*types.Target, error)
}

// missionManager implements the MissionManager interface for daemon operations.
// It orchestrates mission lifecycle including workflow loading, execution, tracking,
// and event emission.
type missionManager struct {
	config          *config.Config
	logger          *slog.Logger
	registry        registry.ComponentDiscovery
	missionStore    mission.MissionStore
	missionRunStore mission.MissionRunStore   // Stores individual run records
	checkpointStore mission.CheckpointStore   // Stores mission checkpoints for pause/resume
	findingStore    finding.FindingStore
	llmRegistry     llm.LLMRegistry
	callbackManager *harness.CallbackManager
	harnessFactory  harness.HarnessFactoryInterface
	targetStore     targetStoreLookup
	runLinker       mission.MissionRunLinker
	infrastructure  *Infrastructure
	otelStack       *observability.OTelObservabilityStack // nil when OTel is disabled
	eventBus        orchestrator.EventBus                 // EventBus for emitting orchestration events
	// TODO(workflow-migration): Re-enable GraphRAG storage for mission definitions
	// graphLoader will store mission definitions in Neo4j for cross-mission analysis
	// Currently disabled during workflow -> mission migration
	// graphLoader     *MissionGraphLoader

	// Track active missions with their contexts and event channels
	mu             sync.RWMutex
	activeMissions map[string]*activeMission
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
}

// newMissionManager creates a new mission manager instance.
func newMissionManager(
	cfg *config.Config,
	logger *slog.Logger,
	reg registry.ComponentDiscovery,
	missionStore mission.MissionStore,
	missionRunStore mission.MissionRunStore,
	checkpointStore mission.CheckpointStore,
	findingStore finding.FindingStore,
	llmRegistry llm.LLMRegistry,
	callbackMgr *harness.CallbackManager,
	harnessFactory harness.HarnessFactoryInterface,
	targetStore targetStoreLookup,
	runLinker mission.MissionRunLinker,
	infrastructure *Infrastructure,
	otelStack *observability.OTelObservabilityStack,
	eventBus orchestrator.EventBus,
) *missionManager {
	// TODO(workflow-migration): Re-enable GraphRAG storage for mission definitions
	// GraphLoader initialization disabled during workflow -> mission migration
	// Will be replaced with MissionGraphLoader that works with mission.MissionDefinition
	// if infrastructure != nil && infrastructure.graphRAGClient != nil {
	//     graphLoader = mission.NewGraphLoader(infrastructure.graphRAGClient)
	//     logger.Info("initialized GraphLoader for mission persistence to Neo4j")
	// }

	return &missionManager{
		config:          cfg,
		logger:          logger.With("component", "mission-manager"),
		registry:        reg,
		missionStore:    missionStore,
		missionRunStore: missionRunStore,
		checkpointStore: checkpointStore,
		findingStore:    findingStore,
		llmRegistry:     llmRegistry,
		callbackManager: callbackMgr,
		harnessFactory:  harnessFactory,
		targetStore:     targetStore,
		runLinker:       runLinker,
		infrastructure:  infrastructure,
		otelStack:       otelStack,
		eventBus:        eventBus,
		activeMissions:  make(map[string]*activeMission),
	}
}

// Run starts a mission and returns an event channel for progress updates.
// This implements the core mission execution flow:
// 1. Load workflow from file
// 2. Create mission context and stores
// 3. Launch workflow executor in goroutine
// 4. Return event channel for streaming updates
func (m *missionManager) Run(ctx context.Context, workflowPath string, missionID string, variables map[string]string, memoryContinuity string) (<-chan api.MissionEventData, error) {
	m.logger.Info("starting mission",
		"workflow_path", workflowPath,
		"mission_id", missionID,
		"variables", len(variables),
		"memory_continuity", memoryContinuity,
	)

	// Load mission definition from YAML file
	def, err := mission.ParseDefinition(workflowPath)
	if err != nil {
		m.logger.Error("failed to load mission definition", "error", err, "path", workflowPath)
		return nil, fmt.Errorf("failed to load mission definition from %s: %w", workflowPath, err)
	}

	m.logger.Debug("mission definition loaded",
		"mission_name", def.Name,
		"node_count", len(def.Nodes),
	)

	// Generate mission ID if not provided
	if missionID == "" {
		missionID = types.NewID().String()
	}

	// Parse mission ID
	missionIDTyped, err := types.ParseID(missionID)
	if err != nil {
		m.logger.Error("invalid mission ID format", "error", err, "mission_id", missionID)
		return nil, fmt.Errorf("invalid mission ID format: %w", err)
	}
	def.ID = missionIDTyped

	// Store mission definition in GraphRAG for cross-mission analysis
	if err := m.storeMissionInGraphRAG(ctx, def); err != nil {
		m.logger.Warn("failed to store mission in GraphRAG, continuing without graph persistence",
			"error", err,
			"mission_id", missionID,
			"mission_name", def.Name,
		)
	}

	// Check if mission ID already exists
	m.mu.RLock()
	if _, exists := m.activeMissions[missionID]; exists {
		m.mu.RUnlock()
		return nil, fmt.Errorf("mission %s is already running", missionID)
	}
	m.mu.RUnlock()

	// Resolve target from mission definition
	var targetID types.ID
	var targetRef string // Store original target ref (URL or name) for injection into agent context
	if def.TargetRef != "" {
		// Check if target is a direct URL (ad-hoc target without pre-registration)
		isURL := strings.HasPrefix(def.TargetRef, "http://") || strings.HasPrefix(def.TargetRef, "https://")

		if isURL {
			// Direct URL target - use a synthetic ID and preserve the URL for injection
			// Generate a deterministic ID from the URL for consistency
			targetID = types.ID("00000000-0000-0000-0000-u17006d15c0") // Marker for URL-based targets
			targetRef = def.TargetRef                                  // Preserve URL for agent context injection
			m.logger.Debug("using direct URL target", "target_url", def.TargetRef, "target_id", targetID)
		} else {
			// Named target - look up in target store
			if m.targetStore == nil {
				return nil, fmt.Errorf("target '%s' specified but target store not available", def.TargetRef)
			}
			target, err := m.targetStore.GetByName(ctx, def.TargetRef)
			if err != nil {
				m.logger.Error("failed to lookup target", "error", err, "target_ref", def.TargetRef)
				return nil, fmt.Errorf("failed to lookup target '%s': %w", def.TargetRef, err)
			}
			if target == nil {
				return nil, fmt.Errorf("target '%s' not found", def.TargetRef)
			}
			targetID = target.ID
			// Use target URL or name as the ref for agent context
			if target.URL != "" {
				targetRef = target.URL
			} else if conn, ok := target.Connection["url"].(string); ok {
				targetRef = conn
			} else {
				targetRef = def.TargetRef
			}
			m.logger.Debug("resolved target", "target_ref", def.TargetRef, "target_id", targetID, "target_url", targetRef)
		}
	} else {
		// No target specified - use a synthetic "discovery" target ID
		// This allows orchestration/discovery missions that don't target a specific system
		// Use a well-known UUID that signals this is a discovery mission
		targetID = types.ID("00000000-0000-0000-0000-d15c00e00000")
		m.logger.Debug("no target specified, using discovery target", "target_id", targetID)
	}

	// Serialize mission definition to JSON for storage
	definitionJSON, err := json.Marshal(def)
	if err != nil {
		m.logger.Error("failed to serialize mission definition", "error", err)
		return nil, fmt.Errorf("failed to serialize mission definition: %w", err)
	}

	// Find or create stable mission record (one per workflow name)
	now := mission.NewUnixTimeNow()
	missionTemplate := &mission.Mission{
		ID:               types.NewID(), // Template ID, may be replaced by existing
		Name:             def.Name,
		Description:      def.Description,
		Status:           mission.MissionStatusPending,
		WorkflowID:       def.ID,
		WorkflowJSON:     string(definitionJSON),
		TargetID:         targetID,
		MemoryContinuity: memoryContinuity,
		CreatedAt:        now,
		UpdatedAt:        now,
		FindingsCount:    0,
		Metrics: &mission.MissionMetrics{
			TotalNodes:     len(def.Nodes),
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

	// Use FindOrCreateByName to get stable mission ID
	var missionRecord *mission.Mission
	var isNewMission bool
	if m.missionStore != nil {
		missionRecord, isNewMission, err = m.missionStore.FindOrCreateByName(ctx, missionTemplate)
		if err != nil {
			m.logger.Error("failed to find or create mission", "error", err, "mission_name", def.Name)
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
		// No store available, use template directly
		missionRecord = missionTemplate
		isNewMission = true
	}

	// Create new MissionRun for this execution
	var missionRun *mission.MissionRun
	if m.missionRunStore != nil {
		// Get next run number
		runNumber, err := m.missionRunStore.GetNextRunNumber(ctx, missionRecord.ID)
		if err != nil {
			m.logger.Error("failed to get next run number", "error", err)
			return nil, fmt.Errorf("failed to get next run number: %w", err)
		}

		// Create the run record
		missionRun = mission.NewMissionRun(missionRecord.ID, runNumber)
		missionRun.MarkStarted()

		if err := m.missionRunStore.Save(ctx, missionRun); err != nil {
			m.logger.Error("failed to save mission run", "error", err)
			return nil, fmt.Errorf("failed to save mission run: %w", err)
		}

		m.logger.Info("created mission run",
			"mission_id", missionRecord.ID,
			"run_id", missionRun.ID,
			"run_number", runNumber,
		)
	} else {
		// Fallback: create ephemeral run for graph bootstrap
		missionRun = mission.NewMissionRun(missionRecord.ID, 1)
		missionRun.MarkStarted()
		m.logger.Warn("mission run store not available, using ephemeral run")
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
	}

	// Register active mission by stable mission ID
	m.mu.Lock()
	m.activeMissions[missionRecord.ID.String()] = active
	m.mu.Unlock()

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
func (m *missionManager) executeMission(ctx context.Context, missionID string, def *mission.MissionDefinition, eventChan chan api.MissionEventData) {
	defer close(eventChan)
	defer m.cleanupMission(missionID)

	// Create mission execution span if OTel tracing is enabled
	var span trace.Span
	if m.otelStack != nil && m.otelStack.TracerProvider != nil {
		tracer := m.otelStack.TracerProvider.Tracer("gibson")
		ctx, span = tracer.Start(ctx, observability.SpanMissionExecute,
			trace.WithAttributes(
				attribute.String(observability.GibsonMissionID, missionID),
				attribute.String(observability.GibsonWorkflowName, def.Name),
			),
		)
		defer span.End()
	}

	m.logger.Info("executing mission with orchestrator", "mission_id", missionID)

	// Get active mission
	m.mu.RLock()
	active, exists := m.activeMissions[missionID]
	m.mu.RUnlock()

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

	// Set StartedAt timestamp now that execution is beginning
	active.mission.StartedAt = mission.NewUnixTimePtrNow()

	// Update mission status to Running in SQLite
	if m.missionStore != nil {
		active.mission.Status = mission.MissionStatusRunning
		if err := m.missionStore.Update(ctx, active.mission); err != nil {
			m.logger.Warn("failed to update mission status in store", "error", err, "mission_id", missionID)
			// Continue execution - this is not critical
		}
	}

	// Check if GraphRAG is available - required for orchestrator
	if m.infrastructure == nil || m.infrastructure.graphRAGClient == nil {
		m.logger.Error("GraphRAG not available - orchestrator requires Neo4j",
			"mission_id", missionID)

		m.emitEvent(eventChan, api.MissionEventData{
			EventType: "mission.failed",
			Timestamp: time.Now(),
			MissionID: missionID,
			Error:     "GraphRAG (Neo4j) is required for mission execution but not configured",
		})
		return
	}

	// Create query handlers for graph operations
	graphClient := m.infrastructure.graphRAGClient
	missionQueries := queries.NewMissionQueries(graphClient)
	executionQueries := queries.NewExecutionQueries(graphClient)

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

	// Bootstrap mission graph structure before execution
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
		WithRunNumber(missionRun.RunNumber)

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

	// Create LLM client adapter for the Thinker
	llmClient := &llmClientAdapter{harness: agentHarness}

	// Create harness adapter for the Actor
	harnessAdapter := &orchestratorHarnessAdapter{harness: agentHarness}

	// Build component inventory for validation
	// Use a reasonable timeout for inventory building
	inventoryCtx, inventoryCancel := context.WithTimeout(ctx, 5*time.Second)
	defer inventoryCancel()

	inventoryBuilder := orchestrator.NewInventoryBuilder(m.registry)
	inventory, err := inventoryBuilder.Build(inventoryCtx)
	if err != nil {
		m.logger.Warn("failed to build component inventory, validation will be skipped",
			"mission_id", missionID,
			"error", err)
		inventory = nil // Continue without inventory
	}

	// Create orchestrator components
	// Pass inventoryBuilder to Observer so it can include available components in observations
	observer := orchestrator.NewObserver(missionQueries, executionQueries,
		orchestrator.WithInventoryBuilder(inventoryBuilder),
	)
	thinker := orchestrator.NewThinker(llmClient,
		orchestrator.WithMaxRetries(3),
		orchestrator.WithThinkerTemperature(0.2),
	)

	// Create PolicyChecker for data policy enforcement
	policySource := orchestrator.NewMissionPolicySource(def)
	nodeStore := orchestrator.NewGraphNodeStore(graphClient, active.missionRun.ID.String())
	policyChecker := orchestrator.NewPolicyChecker(policySource, nodeStore, m.logger)

	// Pass DiscoveryProcessor from infrastructure to enable automatic storage of discovered
	// hosts, ports, services, etc. from agent outputs to Neo4j for use by downstream agents.
	// ApprovalManager, EscalationManager, CheckpointManager, ReflectionEngine, and MemoryRecaller are nil for now - they will be configured later
	actor := orchestrator.NewActor(harnessAdapter, executionQueries, missionQueries, graphClient, inventory, policyChecker, m.infrastructure.discoveryProcessor, nil, nil, nil, nil, nil, m.logger)

	// Create OTel DecisionLogWriterAdapter for tracing if OTel stack is available
	var decisionLogWriter orchestrator.DecisionLogWriter
	var otelDecisionLogAdapter *observability.OTelDecisionLogWriterAdapter // Keep reference for Close
	if m.otelStack != nil && m.otelStack.MissionTracer != nil {
		// Convert mission state to schema format for OTel
		schemaMission := convertToSchemaMission(active.mission, def)

		// Create OTel adapter with tracer and schema mission
		logAdapter, err := observability.NewOTelDecisionLogWriterAdapter(ctx, m.otelStack.MissionTracer, schemaMission)
		if err != nil {
			// Log warning but continue without tracing - don't fail mission
			m.logger.Warn("failed to create OTelDecisionLogWriterAdapter, continuing without decision tracing",
				"mission_id", missionID,
				"error", err,
			)
		} else {
			decisionLogWriter = logAdapter
			otelDecisionLogAdapter = logAdapter
			m.logger.Info("created OTelDecisionLogWriterAdapter for mission tracing",
				"mission_id", missionID,
			)
		}
	}

	// Create the orchestrator with optional decision log writer and event bus
	orchOptions := []orchestrator.OrchestratorOption{
		orchestrator.WithMaxIterations(100),
		orchestrator.WithMaxConcurrent(10),
		orchestrator.WithLogger(orchestrator.WrapSlogLogger(m.logger.With("component", "orchestrator"))),
	}

	// Add decision log writer if available
	if decisionLogWriter != nil {
		orchOptions = append(orchOptions, orchestrator.WithDecisionLogWriter(decisionLogWriter))
	}

	// Add event bus for publishing orchestration events to daemon event bus
	if m.eventBus != nil {
		orchOptions = append(orchOptions, orchestrator.WithEventBus(m.eventBus))
		m.logger.Info("orchestrator configured with event bus", "mission_id", missionID)
	}

	orch := orchestrator.NewOrchestrator(observer, thinker, actor, orchOptions...)

	// Emit workflow execution started event
	m.emitEvent(eventChan, api.MissionEventData{
		EventType: "workflow.started",
		Timestamp: time.Now(),
		MissionID: missionID,
		Message:   fmt.Sprintf("Starting orchestrator for mission %s", missionID),
	})

	// Execute mission through orchestrator's Observe → Think → Act loop
	// Use defer to ensure decision log adapter is closed even on panic
	var result *orchestrator.OrchestratorResult
	var finalStatus mission.MissionStatus
	var errorMsg string
	var missionDuration time.Duration

	defer func() {
		if otelDecisionLogAdapter != nil {
			// Build summary from execution results
			summary := buildMissionTraceSummary(result, finalStatus, missionDuration, errorMsg)
			if closeErr := otelDecisionLogAdapter.Close(ctx, summary); closeErr != nil {
				m.logger.Warn("failed to close OTel decision log adapter",
					"mission_id", missionID,
					"error", closeErr,
				)
			}
		}
	}()

	result, err = orch.Run(ctx, missionID)

	// Calculate mission duration
	missionDuration = time.Since(active.startTime)

	if err != nil {
		m.logger.Error("mission execution failed", "mission_id", missionID, "error", err)
		finalStatus = mission.MissionStatusFailed
		errorMsg = err.Error()

		// Record error on span
		if span != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, errorMsg)
			span.SetAttributes(
				attribute.Int("gibson.mission.duration_ms", int(missionDuration.Milliseconds())),
			)
		}

		m.emitEvent(eventChan, api.MissionEventData{
			EventType: "mission.failed",
			Timestamp: time.Now(),
			MissionID: missionID,
			Error:     errorMsg,
		})
	} else if result != nil {
		// Map orchestrator status to mission status
		switch result.Status {
		case orchestrator.StatusCompleted:
			finalStatus = mission.MissionStatusCompleted
		case orchestrator.StatusFailed:
			finalStatus = mission.MissionStatusFailed
			errorMsg = "orchestrator reported failure"
			if result.Error != nil {
				errorMsg = result.Error.Error()
			}
		case orchestrator.StatusCancelled:
			finalStatus = mission.MissionStatusCancelled
			errorMsg = "mission was cancelled"
		case orchestrator.StatusMaxIterations:
			finalStatus = mission.MissionStatusFailed
			errorMsg = "max iterations reached"
		case orchestrator.StatusTimeout:
			finalStatus = mission.MissionStatusFailed
			errorMsg = "orchestrator timed out"
		case orchestrator.StatusBudgetExceeded:
			finalStatus = mission.MissionStatusFailed
			errorMsg = "token budget exceeded"
		default:
			finalStatus = mission.MissionStatusFailed
			errorMsg = fmt.Sprintf("unknown orchestrator status: %s", result.Status)
		}

		// Log orchestrator statistics
		m.logger.Info("orchestrator completed",
			"mission_id", missionID,
			"status", result.Status,
			"iterations", result.TotalIterations,
			"decisions", result.TotalDecisions,
			"tokens_used", result.TotalTokensUsed,
			"completed_nodes", result.CompletedNodes,
			"failed_nodes", result.FailedNodes,
			"duration", result.Duration,
			"stop_reason", result.StopReason,
		)

		if finalStatus == mission.MissionStatusFailed {
			// Record error on span
			if span != nil {
				span.SetStatus(codes.Error, errorMsg)
				span.SetAttributes(
					attribute.Int("gibson.mission.iterations", result.TotalIterations),
					attribute.Int("gibson.mission.decisions", result.TotalDecisions),
					attribute.Int("gibson.mission.tokens_used", result.TotalTokensUsed),
					attribute.Int("gibson.mission.duration_ms", int(missionDuration.Milliseconds())),
				)
			}
		} else {
			// Mission completed successfully
			if span != nil {
				span.SetStatus(codes.Ok, "mission completed")
				span.SetAttributes(
					attribute.Int("gibson.mission.iterations", result.TotalIterations),
					attribute.Int("gibson.mission.decisions", result.TotalDecisions),
					attribute.Int("gibson.mission.tokens_used", result.TotalTokensUsed),
					attribute.Int("gibson.mission.completed_nodes", result.CompletedNodes),
					attribute.Int("gibson.mission.failed_nodes", result.FailedNodes),
					attribute.Int("gibson.mission.duration_ms", int(missionDuration.Milliseconds())),
				)
			}
		}

		m.emitEvent(eventChan, api.MissionEventData{
			EventType: "mission.completed",
			Timestamp: time.Now(),
			MissionID: missionID,
			Message:   fmt.Sprintf("Mission completed with status: %s (iterations: %d, decisions: %d)", finalStatus, result.TotalIterations, result.TotalDecisions),
		})
	} else {
		// No result returned - treat as failed
		finalStatus = mission.MissionStatusFailed
		errorMsg = "no result returned from orchestrator"

		// Record error on span
		if span != nil {
			span.RecordError(fmt.Errorf("%s", errorMsg))
			span.SetStatus(codes.Error, errorMsg)
			span.SetAttributes(
				attribute.Int("gibson.mission.duration_ms", int(missionDuration.Milliseconds())),
			)
		}

		m.emitEvent(eventChan, api.MissionEventData{
			EventType: "mission.failed",
			Timestamp: time.Now(),
			MissionID: missionID,
			Error:     errorMsg,
		})
	}

	// Update mission in store
	active.mission.Status = finalStatus
	active.mission.Error = errorMsg
	active.mission.CompletedAt = mission.NewUnixTimePtrNow()

	if m.missionStore != nil {
		if saveErr := m.missionStore.Update(ctx, active.mission); saveErr != nil {
			m.logger.Warn("failed to update mission in store", "error", saveErr)
		}
	}

	m.logger.Info("mission execution completed",
		"mission_id", missionID,
		"status", finalStatus,
		"duration", time.Since(active.startTime),
	)
}

// Pause pauses a running mission at the next clean checkpoint.
func (m *missionManager) Pause(ctx context.Context, missionID string, force bool) error {
	m.logger.Info("pausing mission", "mission_id", missionID, "force", force)

	m.mu.RLock()
	active, exists := m.activeMissions[missionID]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("mission %s not found or not running", missionID)
	}

	// If force is true, immediately cancel the mission context
	// Otherwise, we let the mission detect the pause request gracefully
	if force {
		active.cancel()
	} else {
		// Cancel the mission context to signal pause request
		// The orchestrator should detect this and save a checkpoint before transitioning to paused
		active.cancel()
	}

	// Emit pause event
	m.emitEvent(active.eventChan, api.MissionEventData{
		EventType: "mission.pausing",
		Timestamp: time.Now(),
		MissionID: missionID,
		Message:   "Mission pause requested",
	})

	// Wait for mission to transition to paused state (with timeout)
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeoutCtx.Done():
			m.logger.Warn("timeout waiting for mission to pause", "mission_id", missionID)
			// Update status to paused anyway
			active.mission.Status = mission.MissionStatusPaused
			active.mission.CompletedAt = mission.NewUnixTimePtrNow()
			if m.missionStore != nil {
				if err := m.missionStore.Update(ctx, active.mission); err != nil {
					m.logger.Warn("failed to update mission status to paused", "error", err)
				}
			}
			return fmt.Errorf("timeout waiting for mission to pause")

		case <-ticker.C:
			// Check if mission is still active
			m.mu.RLock()
			_, stillActive := m.activeMissions[missionID]
			m.mu.RUnlock()

			// If mission is no longer active, it has completed or failed
			if !stillActive {
				// Fetch mission from store to get final status
				if m.missionStore != nil {
					finalMission, err := m.missionStore.Get(ctx, types.ID(missionID))
					if err == nil {
						if finalMission.Status == mission.MissionStatusPaused {
							m.logger.Info("mission paused successfully", "mission_id", missionID)
							return nil
						}
						return fmt.Errorf("mission transitioned to unexpected status: %s", finalMission.Status)
					}
				}
				// If we can't get the mission, assume it's paused
				return nil
			}
		}
	}
}

// Resume resumes a paused mission from its last checkpoint.
func (m *missionManager) Resume(ctx context.Context, missionID string) (<-chan api.MissionEventData, error) {
	m.logger.Info("resuming mission", "mission_id", missionID)

	// Check if mission is already running
	m.mu.RLock()
	if _, exists := m.activeMissions[missionID]; exists {
		m.mu.RUnlock()
		return nil, fmt.Errorf("mission %s is already running", missionID)
	}
	m.mu.RUnlock()

	// Get mission from store
	if m.missionStore == nil {
		return nil, fmt.Errorf("mission store not available")
	}

	missionRecord, err := m.missionStore.Get(ctx, types.ID(missionID))
	if err != nil {
		m.logger.Error("failed to get mission", "error", err, "mission_id", missionID)
		return nil, fmt.Errorf("failed to get mission %s: %w", missionID, err)
	}

	// Validate mission can be resumed
	if missionRecord.Status != mission.MissionStatusPaused {
		return nil, fmt.Errorf("cannot resume mission %s: status is %s (expected paused)", missionID, missionRecord.Status)
	}

	// Parse mission definition from stored JSON
	var def *mission.MissionDefinition
	if missionRecord.WorkflowJSON != "" {
		def, err = mission.ParseDefinitionFromJSON([]byte(missionRecord.WorkflowJSON))
		if err != nil {
			m.logger.Error("failed to parse mission definition", "error", err)
			return nil, fmt.Errorf("failed to parse mission definition: %w", err)
		}
	} else {
		return nil, fmt.Errorf("mission %s has no definition", missionID)
	}

	// Create event channel for mission updates
	eventChan := make(chan api.MissionEventData, 100)

	// Create mission context with cancellation
	missionCtx, cancel := context.WithCancel(context.Background())

	// Update mission status to running
	missionRecord.Status = mission.MissionStatusRunning
	missionRecord.StartedAt = mission.NewUnixTimePtrNow()

	if err := m.missionStore.Update(ctx, missionRecord); err != nil {
		m.logger.Warn("failed to update mission status", "error", err)
	}

	// Create new MissionRun for resumed execution
	var missionRun *mission.MissionRun
	if m.missionRunStore != nil {
		runNumber, err := m.missionRunStore.GetNextRunNumber(ctx, missionRecord.ID)
		if err != nil {
			m.logger.Error("failed to get next run number", "error", err)
			return nil, fmt.Errorf("failed to get next run number: %w", err)
		}

		missionRun = mission.NewMissionRun(missionRecord.ID, runNumber)
		missionRun.MarkStarted()

		if err := m.missionRunStore.Save(ctx, missionRun); err != nil {
			m.logger.Error("failed to save mission run", "error", err)
			return nil, fmt.Errorf("failed to save mission run: %w", err)
		}
	} else {
		// Fallback: create ephemeral run
		missionRun = mission.NewMissionRun(missionRecord.ID, 1)
		missionRun.MarkStarted()
	}

	// Create active mission entry
	active := &activeMission{
		mission:    missionRecord,
		missionRun: missionRun,
		ctx:        missionCtx,
		cancel:     cancel,
		eventChan:  eventChan,
		startTime:  time.Now(),
	}

	// Register active mission
	m.mu.Lock()
	m.activeMissions[missionID] = active
	m.mu.Unlock()

	// Emit mission resumed event
	m.emitEvent(eventChan, api.MissionEventData{
		EventType: "mission.resumed",
		Timestamp: time.Now(),
		MissionID: missionID,
		Message:   fmt.Sprintf("Mission %s run #%d resumed from checkpoint", missionRecord.Name, missionRun.RunNumber),
	})

	// Launch mission executor in goroutine
	// Note: This will execute from the beginning - checkpoint restoration would be handled
	// by the orchestrator if ExecuteFromCheckpoint were implemented
	go m.executeMission(missionCtx, missionID, def, eventChan)

	return eventChan, nil
}

// Stop stops a running mission with optional force flag.
func (m *missionManager) Stop(ctx context.Context, missionID string, force bool) error {
	m.logger.Info("stopping mission", "mission_id", missionID, "force", force)

	m.mu.RLock()
	active, exists := m.activeMissions[missionID]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("mission %s not found or not running", missionID)
	}

	// Cancel the mission context
	active.cancel()

	// Emit stop event
	m.emitEvent(active.eventChan, api.MissionEventData{
		EventType: "mission.stopped",
		Timestamp: time.Now(),
		MissionID: missionID,
		Message:   "Mission stopped by user",
	})

	// Update mission status
	active.mission.Status = mission.MissionStatusCancelled
	active.mission.CompletedAt = mission.NewUnixTimePtrNow()

	if m.missionStore != nil {
		if err := m.missionStore.Update(ctx, active.mission); err != nil {
			m.logger.Warn("failed to update mission in store", "error", err)
		}
	}

	m.logger.Info("mission stopped", "mission_id", missionID)
	return nil
}

// List returns a list of missions with optional filtering.
func (m *missionManager) List(ctx context.Context, activeOnly bool, limit, offset int) ([]api.MissionData, int, error) {
	m.logger.Debug("listing missions", "active_only", activeOnly, "limit", limit, "offset", offset)

	var result []api.MissionData

	// Get active missions
	m.mu.RLock()
	activeMissions := make([]*mission.Mission, 0, len(m.activeMissions))
	for _, active := range m.activeMissions {
		activeMissions = append(activeMissions, active.mission)
	}
	m.mu.RUnlock()

	// Add active missions to result
	for _, m := range activeMissions {
		result = append(result, missionToData(m))
	}

	// If not active-only, also fetch from store
	if !activeOnly && m.missionStore != nil {
		filter := mission.NewMissionFilter()
		filter.Limit = 1000 // Get a reasonable number
		filter.Offset = 0

		stored, err := m.missionStore.List(ctx, filter)
		if err != nil {
			m.logger.Warn("failed to list missions from store", "error", err)
		} else {
			// Add completed missions that aren't already in active list
			for _, storedMission := range stored {
				// Check if already in active list
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

// Get returns a specific mission by ID.
func (m *missionManager) Get(ctx context.Context, missionID string) (*api.MissionData, error) {
	m.logger.Debug("getting mission", "mission_id", missionID)

	// Check active missions first
	m.mu.RLock()
	active, exists := m.activeMissions[missionID]
	m.mu.RUnlock()

	if exists {
		data := missionToData(active.mission)
		return &data, nil
	}

	// Check mission store
	if m.missionStore != nil {
		missionRecord, err := m.missionStore.Get(ctx, types.ID(missionID))
		if err == nil {
			data := missionToData(missionRecord)
			return &data, nil
		}
	}

	return nil, fmt.Errorf("mission %s not found", missionID)
}

// cleanupMission removes a mission from active tracking after completion.
func (m *missionManager) cleanupMission(missionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.activeMissions, missionID)
	m.completedCount++

	m.logger.Debug("mission cleaned up", "mission_id", missionID)
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
		ID:           m.ID.String(),
		WorkflowPath: "", // Not tracked in Mission struct
		Status:       string(m.Status),
		StartTime:    m.CreatedAt.Time,
		FindingCount: int32(m.FindingsCount),
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

// containsStr checks if a string contains a substring (case-sensitive).
func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}

// llmClientAdapter adapts an AgentHarness to the orchestrator.LLMClient interface.
// This allows the orchestrator's Thinker to use the harness for LLM operations.
type llmClientAdapter struct {
	harness harness.AgentHarness
}

// Complete performs a synchronous LLM completion using the harness.
func (a *llmClientAdapter) Complete(ctx context.Context, slot string, messages []llm.Message, opts ...orchestrator.CompletionOption) (*llm.CompletionResponse, error) {
	// Convert orchestrator options to harness options
	harnessOpts := make([]harness.CompletionOption, 0, len(opts))
	compOpts := &orchestrator.CompletionOptions{}
	for _, opt := range opts {
		opt(compOpts)
	}
	if compOpts.Temperature > 0 {
		harnessOpts = append(harnessOpts, harness.WithTemperature(compOpts.Temperature))
	}
	if compOpts.MaxTokens > 0 {
		harnessOpts = append(harnessOpts, harness.WithMaxTokens(compOpts.MaxTokens))
	}
	if compOpts.TopP > 0 {
		harnessOpts = append(harnessOpts, harness.WithTopP(compOpts.TopP))
	}

	return a.harness.Complete(ctx, slot, messages, harnessOpts...)
}

// CompleteStructuredAny performs a completion with provider-native structured output.
func (a *llmClientAdapter) CompleteStructuredAny(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...orchestrator.CompletionOption) (any, error) {
	// Convert orchestrator options to harness options
	harnessOpts := make([]harness.CompletionOption, 0, len(opts))
	compOpts := &orchestrator.CompletionOptions{}
	for _, opt := range opts {
		opt(compOpts)
	}
	if compOpts.Temperature > 0 {
		harnessOpts = append(harnessOpts, harness.WithTemperature(compOpts.Temperature))
	}
	if compOpts.MaxTokens > 0 {
		harnessOpts = append(harnessOpts, harness.WithMaxTokens(compOpts.MaxTokens))
	}
	if compOpts.TopP > 0 {
		harnessOpts = append(harnessOpts, harness.WithTopP(compOpts.TopP))
	}

	return a.harness.CompleteStructuredAny(ctx, slot, messages, schemaType, harnessOpts...)
}

// CompleteStructuredAnyWithUsage performs structured completion and returns token usage.
func (a *llmClientAdapter) CompleteStructuredAnyWithUsage(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...orchestrator.CompletionOption) (*orchestrator.StructuredCompletionResult, error) {
	// Convert orchestrator options to harness options
	harnessOpts := make([]harness.CompletionOption, 0, len(opts))
	compOpts := &orchestrator.CompletionOptions{}
	for _, opt := range opts {
		opt(compOpts)
	}
	if compOpts.Temperature > 0 {
		harnessOpts = append(harnessOpts, harness.WithTemperature(compOpts.Temperature))
	}
	if compOpts.MaxTokens > 0 {
		harnessOpts = append(harnessOpts, harness.WithMaxTokens(compOpts.MaxTokens))
	}
	if compOpts.TopP > 0 {
		harnessOpts = append(harnessOpts, harness.WithTopP(compOpts.TopP))
	}

	harnessResult, err := a.harness.CompleteStructuredAnyWithUsage(ctx, slot, messages, schemaType, harnessOpts...)
	if err != nil {
		return nil, err
	}

	// Convert harness.StructuredCompletionResult to orchestrator.StructuredCompletionResult
	return &orchestrator.StructuredCompletionResult{
		Result:           harnessResult.Result,
		Model:            harnessResult.Model,
		RawJSON:          harnessResult.RawJSON,
		PromptTokens:     harnessResult.PromptTokens,
		CompletionTokens: harnessResult.CompletionTokens,
		TotalTokens:      harnessResult.TotalTokens,
	}, nil
}

// orchestratorHarnessAdapter adapts an AgentHarness to the orchestrator.Harness interface.
// This allows the orchestrator's Actor to delegate to agents.
type orchestratorHarnessAdapter struct {
	harness harness.AgentHarness
}

// DelegateToAgent delegates a task to another agent via the harness.
func (a *orchestratorHarnessAdapter) DelegateToAgent(ctx context.Context, agentName string, task agent.Task) (agent.Result, error) {
	return a.harness.DelegateToAgent(ctx, agentName, task)
}

// buildMissionTraceSummary constructs a MissionTraceSummary from orchestrator results.
// This is used when closing the decision log adapter to provide final statistics.
func buildMissionTraceSummary(result *orchestrator.OrchestratorResult, status mission.MissionStatus, duration time.Duration, errorMsg string) *observability.MissionTraceSummary {
	summary := &observability.MissionTraceSummary{
		Duration:   duration,
		Outcome:    string(status),
		GraphStats: make(map[string]int),
	}

	// Map mission status to schema status string
	switch status {
	case mission.MissionStatusCompleted:
		summary.Status = string(schema.MissionStatusCompleted)
	case mission.MissionStatusFailed:
		summary.Status = string(schema.MissionStatusFailed)
	case mission.MissionStatusCancelled:
		summary.Status = string(schema.MissionStatusFailed) // Treat cancelled as failed for tracing
	case mission.MissionStatusPaused:
		summary.Status = string(schema.MissionStatusFailed) // Treat paused as failed for tracing
	default:
		summary.Status = string(schema.MissionStatusFailed)
	}

	// Extract statistics from orchestrator result if available
	if result != nil {
		summary.TotalDecisions = result.TotalDecisions
		summary.TotalTokens = result.TotalTokensUsed
		summary.Outcome = result.StopReason
		if summary.Outcome == "" {
			summary.Outcome = string(result.Status)
		}

		// Add graph statistics
		summary.GraphStats["completed_nodes"] = result.CompletedNodes
		summary.GraphStats["failed_nodes"] = result.FailedNodes
		summary.GraphStats["total_iterations"] = result.TotalIterations
	}

	// Add error message to outcome if present
	if errorMsg != "" {
		if summary.Outcome != "" {
			summary.Outcome = fmt.Sprintf("%s: %s", summary.Outcome, errorMsg)
		} else {
			summary.Outcome = errorMsg
		}
	}

	return summary
}

// storeMissionInGraphRAG stores a mission definition in the Neo4j knowledge graph.
// This allows for cross-mission analysis and relationship discovery.
func (m *missionManager) storeMissionInGraphRAG(ctx context.Context, def *mission.MissionDefinition) error {
	// Check if GraphRAG is configured
	if m.infrastructure == nil || m.infrastructure.graphRAGClient == nil {
		m.logger.Debug("GraphRAG not configured, skipping mission storage")
		return nil // GraphRAG not configured, skip storage
	}

	m.logger.Info("storing mission in GraphRAG",
		"mission_id", def.ID,
		"mission_name", def.Name,
		"node_count", len(def.Nodes),
		"edge_count", len(def.Edges))

	// Convert mission definition to graph nodes
	nodes := m.convertToGraphNodes(def)

	// Store nodes in GraphRAG
	for _, node := range nodes {
		_, err := m.infrastructure.graphRAGClient.CreateNode(ctx, []string{node.Label}, node.Properties)
		if err != nil {
			m.logger.Warn("failed to add node to graph",
				"error", err,
				"node_label", node.Label,
				"node_id", node.Properties["id"])
			// Continue with other nodes even if one fails
		}
	}

	// Convert mission definition to graph edges
	edges := m.convertToGraphEdges(def)

	// Store edges in GraphRAG
	for _, edge := range edges {
		if err := m.infrastructure.graphRAGClient.CreateRelationship(ctx,
			edge.FromNode, edge.ToNode, edge.RelType, edge.Properties); err != nil {
			m.logger.Warn("failed to add edge to graph",
				"error", err,
				"edge_type", edge.RelType,
				"from", edge.FromNode,
				"to", edge.ToNode)
			// Continue with other edges even if one fails
		}
	}

	m.logger.Info("mission stored in GraphRAG successfully",
		"mission_id", def.ID,
		"mission_name", def.Name,
		"nodes_created", len(nodes),
		"edges_created", len(edges))

	return nil
}

// graphNode represents a node to be stored in Neo4j
type graphNode struct {
	Label      string
	Properties map[string]any
}

// graphEdge represents an edge to be stored in Neo4j
type graphEdge struct {
	FromNode   string
	ToNode     string
	RelType    string
	Properties map[string]any
}

// convertToGraphNodes converts a mission definition to graph nodes.
// This creates nodes for the mission itself, steps, agents, and tools.
func (m *missionManager) convertToGraphNodes(def *mission.MissionDefinition) []graphNode {
	var nodes []graphNode

	// Create mission node
	missionNode := graphNode{
		Label: "Mission",
		Properties: map[string]any{
			"id":          def.ID.String(),
			"name":        def.Name,
			"description": def.Description,
			"version":     def.Version,
			"target_ref":  def.TargetRef,
			"created_at":  def.CreatedAt.Unix(),
		},
	}
	nodes = append(nodes, missionNode)

	// Create nodes for each mission node (steps)
	for nodeID, node := range def.Nodes {
		stepNode := graphNode{
			Label: "MissionStep",
			Properties: map[string]any{
				"id":          nodeID,
				"mission_id":  def.ID.String(),
				"type":        string(node.Type),
				"description": node.Description,
			},
		}

		// Add agent-specific properties
		if node.Type == mission.NodeTypeAgent && node.AgentName != "" {
			stepNode.Properties["agent_name"] = node.AgentName
			if node.AgentTask != nil {
				stepNode.Properties["agent_goal"] = node.AgentTask.Goal
				stepNode.Properties["agent_description"] = node.AgentTask.Description
			}
		}

		// Add tool-specific properties
		if node.Type == mission.NodeTypeTool && node.ToolName != "" {
			stepNode.Properties["tool_name"] = node.ToolName
			if node.ToolInput != nil {
				// Store tool input as JSON string
				if inputJSON, err := json.Marshal(node.ToolInput); err == nil {
					stepNode.Properties["tool_input"] = string(inputJSON)
				}
			}
		}

		nodes = append(nodes, stepNode)
	}

	return nodes
}

// convertToGraphEdges converts a mission definition to graph edges.
// This creates relationships for dependencies and usage patterns.
func (m *missionManager) convertToGraphEdges(def *mission.MissionDefinition) []graphEdge {
	var edges []graphEdge

	// Create edges for mission -> step relationships
	for nodeID := range def.Nodes {
		edge := graphEdge{
			FromNode: def.ID.String(),
			ToNode:   nodeID,
			RelType:  "HAS_STEP",
			Properties: map[string]any{
				"mission_id": def.ID.String(),
			},
		}
		edges = append(edges, edge)
	}

	// Create edges for step dependencies (mission edges)
	for _, missionEdge := range def.Edges {
		edge := graphEdge{
			FromNode: missionEdge.From,
			ToNode:   missionEdge.To,
			RelType:  "DEPENDS_ON",
			Properties: map[string]any{
				"mission_id": def.ID.String(),
			},
		}

		// Add condition if present
		if missionEdge.Condition != "" {
			edge.Properties["condition"] = missionEdge.Condition
		}

		edges = append(edges, edge)
	}

	return edges
}
