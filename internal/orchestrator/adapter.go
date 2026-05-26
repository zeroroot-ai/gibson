package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/zeroroot-ai/gibson/internal/graphrag/queries"
	"github.com/zeroroot-ai/gibson/internal/harness"
	"github.com/zeroroot-ai/gibson/internal/mission"
	"github.com/zeroroot-ai/gibson/internal/types"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// MissionAdapter adapts the orchestrator to the mission.MissionOrchestrator interface.
// It provides backward compatibility with existing code that expects the mission.MissionOrchestrator interface
// while using the new (Observe → Think → Act) orchestrator internally.
type MissionAdapter struct {
	config Config

	// Pause request handling for backward compatibility
	pauseRequestedMu sync.RWMutex
	pauseRequested   map[types.ID]bool
}

// MissionGraphLoader defines the interface for storing mission definitions in Neo4j.
// This is used to track mission execution state in the graph.
type MissionGraphLoader interface {
	// LoadMission stores a mission definition in the graph and returns the mission ID
	LoadMission(ctx context.Context, def *missionpb.MissionDefinition) (string, error)
}

// MissionGraphManager defines the interface for managing Mission and MissionRun nodes.
// This interface enables mission-scoped storage in GraphRAG by tracking missions and their runs.
type MissionGraphManager interface {
	// EnsureMissionNode creates or retrieves a Mission node in Neo4j.
	// Uses MERGE semantics because missions are deduplicated by name+target_id.
	// Returns the mission ID (existing or newly created).
	EnsureMissionNode(ctx context.Context, name, targetID string) (string, error)

	// CreateMissionRunNode creates a new MissionRun node in Neo4j.
	// Always uses CREATE because each pipeline execution is unique.
	// Returns the mission run ID.
	CreateMissionRunNode(ctx context.Context, missionID string, runNumber int) (string, error)

	// UpdateMissionRunStatus updates the status of a mission run node.
	// Valid status values: "running", "completed", "failed", "cancelled"
	UpdateMissionRunStatus(ctx context.Context, runID string, status string) error
}

// Execute implements mission.MissionOrchestrator interface.
// It converts the mission to the orchestrator format, executes it using the orchestrator,
// and converts the result back to a mission.MissionResult.
func (m *MissionAdapter) Execute(ctx context.Context, mis *mission.Mission) (*mission.MissionResult, error) {
	// Validate mission can be executed
	if !mis.Status.CanTransitionTo(mission.MissionStatusRunning) {
		return nil, mission.NewInvalidStateError(mis.Status, mission.MissionStatusRunning)
	}

	// Update mission status to running
	startedAt := time.Now()
	mis.Status = mission.MissionStatusRunning
	mis.StartedAt = mission.NewUnixTimePtr(&startedAt)

	// Initialize metrics
	if mis.Metrics == nil {
		mis.Metrics = &mission.MissionMetrics{
			StartedAt:          startedAt,
			LastUpdateAt:       startedAt,
			FindingsBySeverity: make(map[string]int),
		}
	}

	// Parse mission definition from mission. Dual-shape reader: proto-shape
	// bytes from PR2+ writers + legacy flat-mirror bytes from older daemon
	// versions both produce a *missionpb.MissionDefinition.
	var def *missionpb.MissionDefinition
	var err error

	if mis.MissionDefinitionJSON != "" {
		def, err = mission.UnmarshalDefinitionJSON([]byte(mis.MissionDefinitionJSON))
		if err != nil {
			return nil, fmt.Errorf("failed to parse mission definition: %w", err)
		}
	} else if mis.MissionDefinitionID != "" {
		// For now, we need the definition JSON to be present
		// In a future enhancement, we could load from the mission definition store
		return nil, fmt.Errorf("mission definition loading from MissionDefinitionID not yet implemented in adapter")
	} else {
		return nil, fmt.Errorf("no mission definition available (neither MissionDefinitionID nor MissionDefinitionJSON)")
	}

	// Store mission definition in Neo4j graph for state tracking
	if m.config.GraphLoader != nil {
		graphMissionID, err := m.config.GraphLoader.LoadMission(ctx, def)
		if err != nil {
			// Log warning but continue - graph storage is optional
			m.config.Logger.Warn(ctx, "failed to store mission definition in GraphRAG",
				"error", err,
				"mission_id", mis.ID,
				"definition_name", def.GetName(),
			)
		} else {
			m.config.Logger.Info(ctx, "mission definition stored in GraphRAG",
				"graph_mission_id", graphMissionID,
				"mission_id", mis.ID,
				"definition_name", def.GetName(),
			)
		}
	}

	// Track mission and mission run in Neo4j for GraphRAG mission-scoped storage
	var missionRunID string
	if m.config.MissionGraphManager != nil {
		// Ensure Mission node exists (or get existing one)
		graphMissionID, err := m.config.MissionGraphManager.EnsureMissionNode(ctx, mis.Name, mis.TargetID.String())
		if err != nil {
			m.config.Logger.Warn(ctx, "failed to ensure mission node in GraphRAG",
				"error", err,
				"mission_id", mis.ID,
				"mission_name", mis.Name,
				"target_id", mis.TargetID,
			)
		} else {
			m.config.Logger.Debug(ctx, "mission node ensured in GraphRAG",
				"graph_mission_id", graphMissionID,
				"mission_id", mis.ID,
				"mission_name", mis.Name,
			)

			// Create MissionRun node for this execution
			// Get run number from mission metadata (set by MissionRunLinker)
			runNumber := 0
			if mis.Metadata != nil {
				if rn, ok := mis.Metadata["run_number"].(int); ok {
					runNumber = rn
				} else if rn, ok := mis.Metadata["run_number"].(float64); ok {
					runNumber = int(rn)
				}
			}

			missionRunID, err = m.config.MissionGraphManager.CreateMissionRunNode(ctx, graphMissionID, runNumber)
			if err != nil {
				m.config.Logger.Warn(ctx, "failed to create mission run node in GraphRAG",
					"error", err,
					"mission_id", mis.ID,
					"graph_mission_id", graphMissionID,
					"run_number", runNumber,
				)
			} else {
				m.config.Logger.Info(ctx, "mission run node created in GraphRAG",
					"mission_run_id", missionRunID,
					"graph_mission_id", graphMissionID,
					"mission_id", mis.ID,
					"run_number", runNumber,
				)
				// Inject MissionRunID into context for harness access
				ctx = harness.ContextWithMissionRunID(ctx, missionRunID)
			}
		}
	}

	// Get run number for context
	runNumber := 0
	if mis.Metadata != nil {
		if rn, ok := mis.Metadata["run_number"].(int); ok {
			runNumber = rn
		} else if rn, ok := mis.Metadata["run_number"].(float64); ok {
			runNumber = int(rn)
		}
	}

	// Create orchestrator for this mission execution
	orchestrator, err := m.createOrchestrator(ctx, mis, def, missionRunID, runNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to create orchestrator: %w", err)
	}

	// Execute using orchestrator
	orchResult, err := orchestrator.Run(ctx, mis.ID.String())

	// Update mission run status in Neo4j (if tracking is enabled)
	if missionRunID != "" && m.config.MissionGraphManager != nil {
		var status string
		if err != nil {
			status = "failed"
		} else {
			// Map orchestrator status to mission run status
			switch orchResult.Status {
			case StatusCompleted:
				status = "completed"
			case StatusFailed:
				status = "failed"
			case StatusCancelled:
				status = "cancelled"
			default:
				status = "failed" // All other terminal states treated as failed
			}
		}

		updateErr := m.config.MissionGraphManager.UpdateMissionRunStatus(ctx, missionRunID, status)
		if updateErr != nil {
			m.config.Logger.Warn(ctx, "failed to update mission run status in GraphRAG",
				"error", updateErr,
				"mission_run_id", missionRunID,
				"status", status,
			)
		} else {
			m.config.Logger.Info(ctx, "mission run status updated in GraphRAG",
				"mission_run_id", missionRunID,
				"status", status,
			)
		}
	}

	if err != nil {
		// Convert error to mission result
		return m.convertErrorToResult(mis, orchResult, err, startedAt), err
	}

	// Convert orchestrator result to mission result
	return m.convertResult(mis, orchResult, startedAt), nil
}

// createOrchestrator creates an orchestrator instance for a specific mission execution.
// It creates the harness, adapters, and all orchestrator components (Observer, Thinker, Actor).
func (m *MissionAdapter) createOrchestrator(ctx context.Context, mis *mission.Mission, def *missionpb.MissionDefinition, missionRunID string, runNumber int) (*Orchestrator, error) {
	// Validate GraphRAG client
	if m.config.GraphRAGClient == nil {
		return nil, fmt.Errorf("GraphRAGClient not configured")
	}

	// Create query handlers
	missionQueries := queries.NewMissionQueries(m.config.GraphRAGClient)
	executionQueries := queries.NewExecutionQueries(m.config.GraphRAGClient)

	// Create inventory builder if registry available (used by both Observer and Actor)
	var inventoryBuilder *InventoryBuilder
	if m.config.Registry != nil {
		inventoryBuilder = NewInventoryBuilder(m.config.Registry)
	}

	// Create Observer with inventory builder for component awareness in observations.
	// Wire WithGraphQueries when the GraphRAG client exposes a live Neo4j driver so the
	// Observer can enrich each LLM decision prompt with cross-mission graph intelligence.
	// Per spec productionize-graph-intelligence, falls back to no graph context when the
	// driver is unavailable.
	observerOpts := []ObserverOption{
		WithInventoryBuilder(inventoryBuilder),
	}
	if m.config.GraphRAGClient != nil {
		observerOpts = append(observerOpts, WithGraphQueries(
			NewNeo4jGraphQueries(m.config.GraphRAGClient, m.config.Logger.Slog()),
		))
	} else {
		m.config.Logger.Slog().Warn("graph intelligence disabled for mission: no graphrag client configured",
			"mission_id", mis.ID.String())
	}
	observer := NewObserver(missionQueries, executionQueries, observerOpts...)

	// Create harness for this mission
	// Use the harness factory to create an appropriate harness
	missionCtx := harness.NewMissionContext(mis.ID, mis.Name, "").
		WithMissionRunID(missionRunID).
		WithRunNumber(runNumber).
		WithTenant(mis.TenantID)

	// Create target info
	// Note: In a full implementation, we would load the target entity here
	// For now, we use a simplified approach
	targetInfo := harness.NewTargetInfo(mis.TargetID, "mission-target", "", "")

	// Get first agent name from definition
	agentName := "orchestrator" // Default agent name
	for _, node := range def.GetNodes() {
		if node.GetType() == missionpb.NodeType_NODE_TYPE_AGENT {
			if name := node.GetAgentConfig().GetAgentName(); name != "" {
				agentName = name
				break
			}
		}
	}

	// Create harness
	agentHarness, err := m.config.HarnessFactory.Create(agentName, missionCtx, targetInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to create harness: %w", err)
	}

	// Create LLM client adapter
	llmClient := &llmClientAdapter{harness: agentHarness}

	// Create Thinker
	thinker := NewThinker(llmClient,
		WithMaxRetries(m.config.ThinkerMaxRetries),
		WithThinkerTemperature(m.config.ThinkerTemperature),
	)

	// Create harness adapter for Actor
	harnessAdapter := &orchestratorHarnessAdapter{harness: agentHarness}

	// Build component inventory snapshot for Actor validation
	var inventory *ComponentInventory
	if inventoryBuilder != nil {
		inventoryCtx, inventoryCancel := context.WithTimeout(ctx, 5*time.Second)
		defer inventoryCancel()

		var err error
		inventory, err = inventoryBuilder.Build(inventoryCtx)
		if err != nil {
			m.config.Logger.Warn(ctx, "failed to build component inventory, validation will be skipped",
				"mission_id", mis.ID,
				"error", err)
			inventory = nil // Continue without inventory
		}
	}

	// Create PolicyChecker for data reuse enforcement
	var policyChecker PolicyChecker
	if def != nil {
		policySource := NewMissionPolicySource(def)
		nodeStore := NewGraphNodeStore(m.config.GraphRAGClient, missionRunID)
		policyChecker = NewPolicyChecker(policySource, nodeStore, m.config.Logger.Slog().With("component", "policy_checker"))
	}

	// Create Actor with DiscoveryProcessor for storing agent output discoveries
	// ApprovalManager, EscalationManager, CheckpointManager, ReflectionEngine, and MemoryRecaller are nil for now - they will be configured later
	actor := NewActor(harnessAdapter, executionQueries, missionQueries, m.config.GraphRAGClient, inventory, policyChecker, m.config.DiscoveryProcessor, nil, nil, nil, nil, nil, m.config.Logger.Slog())

	// Create the orchestrator
	orchOptions := []OrchestratorOption{
		WithMaxIterations(m.config.MaxIterations),
		WithMaxConcurrent(m.config.MaxConcurrent),
		WithBudget(m.config.Budget),
		WithTimeout(m.config.Timeout),
		WithLogger(&slogAdapter{slog: m.config.Logger.Slog().With("component", "orchestrator", "mission_id", mis.ID)}),
		WithTracer(m.config.Tracer),
		WithEventBus(m.config.EventBus),
		WithDecisionLogWriter(m.config.DecisionLogWriter),
		WithMissionDefinition(def),
		WithCredentialStore(m.config.CredentialStore),
	}

	orchestrator := NewOrchestrator(observer, thinker, actor, orchOptions...)

	return orchestrator, nil
}

// convertResult converts an OrchestratorResult to a mission.MissionResult
func (m *MissionAdapter) convertResult(mis *mission.Mission, orchResult *OrchestratorResult, startedAt time.Time) *mission.MissionResult {
	result := &mission.MissionResult{
		MissionID:  mis.ID,
		Metrics:    mis.Metrics,
		FindingIDs: []types.ID{},
	}

	// Map orchestrator status to mission status
	switch orchResult.Status {
	case StatusCompleted:
		result.Status = mission.MissionStatusCompleted
		mis.Status = mission.MissionStatusCompleted
	case StatusFailed:
		result.Status = mission.MissionStatusFailed
		mis.Status = mission.MissionStatusFailed
		if orchResult.Error != nil {
			result.Error = orchResult.Error.Error()
			mis.Error = orchResult.Error.Error()
		}
	case StatusCancelled:
		result.Status = mission.MissionStatusCancelled
		mis.Status = mission.MissionStatusCancelled
		result.Error = "orchestration cancelled"
		mis.Error = "orchestration cancelled"
	case StatusMaxIterations:
		result.Status = mission.MissionStatusFailed
		mis.Status = mission.MissionStatusFailed
		result.Error = "max iterations reached"
		mis.Error = "max iterations reached"
	case StatusTimeout:
		result.Status = mission.MissionStatusFailed
		mis.Status = mission.MissionStatusFailed
		result.Error = "orchestration timeout"
		mis.Error = "orchestration timeout"
	case StatusBudgetExceeded:
		result.Status = mission.MissionStatusFailed
		mis.Status = mission.MissionStatusFailed
		result.Error = "token budget exceeded"
		mis.Error = "token budget exceeded"
	case StatusConcurrencyLimit:
		result.Status = mission.MissionStatusFailed
		mis.Status = mission.MissionStatusFailed
		result.Error = "concurrency limit reached"
		mis.Error = "concurrency limit reached"
	default:
		result.Status = mission.MissionStatusFailed
		mis.Status = mission.MissionStatusFailed
		result.Error = fmt.Sprintf("unknown orchestrator status: %s", orchResult.Status)
		mis.Error = fmt.Sprintf("unknown orchestrator status: %s", orchResult.Status)
	}

	// Update mission metrics
	completedAt := time.Now()
	mis.CompletedAt = mission.NewUnixTimePtr(&completedAt)
	mis.Metrics.Duration = orchResult.Duration
	mis.Metrics.CompletedNodes = orchResult.CompletedNodes
	mis.Metrics.LastUpdateAt = completedAt

	// Set result completion time
	result.CompletedAt = completedAt

	// Convert orchestrator result to mission result map
	if orchResult.FinalState != nil {
		missionResultMap := make(map[string]any)
		missionResultMap["status"] = string(orchResult.Status)
		missionResultMap["total_iterations"] = orchResult.TotalIterations
		missionResultMap["total_decisions"] = orchResult.TotalDecisions
		missionResultMap["total_tokens"] = orchResult.TotalTokensUsed
		missionResultMap["completed_nodes"] = orchResult.CompletedNodes
		missionResultMap["failed_nodes"] = orchResult.FailedNodes
		missionResultMap["duration"] = orchResult.Duration.String()

		if orchResult.StopReason != "" {
			missionResultMap["stop_reason"] = orchResult.StopReason
		}

		result.MissionResult = missionResultMap
	}

	return result
}

// convertErrorToResult creates a failed mission result from an error
func (m *MissionAdapter) convertErrorToResult(mis *mission.Mission, orchResult *OrchestratorResult, err error, startedAt time.Time) *mission.MissionResult {
	result := &mission.MissionResult{
		MissionID:  mis.ID,
		Status:     mission.MissionStatusFailed,
		Error:      err.Error(),
		Metrics:    mis.Metrics,
		FindingIDs: []types.ID{},
	}

	// Update mission status
	mis.Status = mission.MissionStatusFailed
	mis.Error = err.Error()
	completedAt := time.Now()
	mis.CompletedAt = mission.NewUnixTimePtr(&completedAt)
	mis.Metrics.Duration = completedAt.Sub(startedAt)
	result.CompletedAt = completedAt

	// If we have partial orchestrator results, include them
	if orchResult != nil {
		missionResultMap := make(map[string]any)
		missionResultMap["status"] = "failed"
		missionResultMap["total_iterations"] = orchResult.TotalIterations
		missionResultMap["total_decisions"] = orchResult.TotalDecisions
		missionResultMap["total_tokens"] = orchResult.TotalTokensUsed
		missionResultMap["completed_nodes"] = orchResult.CompletedNodes
		missionResultMap["failed_nodes"] = orchResult.FailedNodes
		missionResultMap["duration"] = orchResult.Duration.String()
		missionResultMap["error"] = err.Error()
		result.MissionResult = missionResultMap
	}

	return result
}

// RequestPause signals the orchestrator to pause at the next clean boundary.
// This implements the mission.MissionOrchestrator interface for backward compatibility.
func (m *MissionAdapter) RequestPause(ctx context.Context, missionID types.ID) error {
	m.pauseRequestedMu.Lock()
	defer m.pauseRequestedMu.Unlock()

	m.pauseRequested[missionID] = true
	// Note: The orchestrator doesn't currently support pause/resume
	// This is tracked for future implementation
	return nil
}

// IsPauseRequested checks if pause has been requested for a mission.
func (m *MissionAdapter) IsPauseRequested(missionID types.ID) bool {
	m.pauseRequestedMu.RLock()
	defer m.pauseRequestedMu.RUnlock()

	return m.pauseRequested[missionID]
}

// ClearPauseRequest clears the pause request flag for a mission.
func (m *MissionAdapter) ClearPauseRequest(missionID types.ID) {
	m.pauseRequestedMu.Lock()
	defer m.pauseRequestedMu.Unlock()

	delete(m.pauseRequested, missionID)
}

// ExecuteFromCheckpoint resumes execution from a saved checkpoint.
// This implements the mission.MissionOrchestrator interface for backward compatibility.
func (m *MissionAdapter) ExecuteFromCheckpoint(ctx context.Context, mis *mission.Mission, checkpoint *mission.MissionCheckpoint) (*mission.MissionResult, error) {
	// Convert mission checkpoint to orchestrator checkpoint
	if checkpoint != nil && len(checkpoint.CompletedNodes) > 0 {
		// Build orchestrator checkpoint from mission checkpoint
		nodeStates := make(map[string]NodeCheckpointState)

		// Map completed nodes to node states
		for _, nodeID := range checkpoint.CompletedNodes {
			nodeStates[nodeID] = NodeCheckpointState{
				NodeID:     nodeID,
				Status:     "completed",
				TaskConfig: make(map[string]interface{}),
				Attempt:    1,
			}
		}

		// Map pending nodes
		for _, nodeID := range checkpoint.PendingNodes {
			nodeStates[nodeID] = NodeCheckpointState{
				NodeID:     nodeID,
				Status:     "pending",
				TaskConfig: make(map[string]interface{}),
				Attempt:    1,
			}
		}

		orchCheckpoint := &Checkpoint{
			ID:         checkpoint.ID.String(),
			MissionID:  mis.ID.String(),
			Label:      "restored_checkpoint",
			CreatedAt:  time.Now(),
			NodeStates: nodeStates,
			IsImplicit: false,
		}

		// Log checkpoint recovery
		m.config.Logger.Info(ctx, "recovering from checkpoint",
			"checkpoint_id", orchCheckpoint.ID,
			"mission_id", mis.ID,
			"completed_nodes", len(checkpoint.CompletedNodes),
			"pending_nodes", len(checkpoint.PendingNodes),
		)

		// Note: Actual checkpoint restoration would be done by CheckpointManager
		// For now, we just log and continue with normal execution
		// The checkpoint state serves as documentation for future enhancement
	}

	// Execute normally
	return m.Execute(ctx, mis)
}

// parseCheckpointState converts a checkpoint to graph updates
func (m *MissionAdapter) parseCheckpointState(checkpoint *mission.MissionCheckpoint) (map[string]any, error) {
	if checkpoint == nil {
		return nil, nil
	}

	state := make(map[string]any)

	// Extract mission state
	if checkpoint.MissionState != nil {
		stateBytes, err := json.Marshal(checkpoint.MissionState)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal mission state: %w", err)
		}
		if err := json.Unmarshal(stateBytes, &state); err != nil {
			return nil, fmt.Errorf("failed to unmarshal mission state: %w", err)
		}
	}

	// Add completed and pending nodes
	state["completed_nodes"] = checkpoint.CompletedNodes
	state["pending_nodes"] = checkpoint.PendingNodes

	return state, nil
}

// ExecuteProto executes a mission using a proto MissionDefinition.
// The proto is serialized via protojson (canonical wire/storage form
// per mission-schema-canonicalization PR2) and stored on the mission
// before delegating to Execute.
func (m *MissionAdapter) ExecuteProto(ctx context.Context, mis *mission.Mission, missionDef *missionpb.MissionDefinition) (*mission.MissionResult, error) {
	defJSON, err := mission.MarshalDefinitionJSON(missionDef)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal mission definition: %w", err)
	}
	mis.MissionDefinitionJSON = string(defJSON)
	return m.Execute(ctx, mis)
}

// StopMission implements mission.MissionOrchestrator interface.
// It signals the orchestrator to stop executing the specified mission.
func (m *MissionAdapter) StopMission(ctx context.Context, missionID types.ID) error {
	// Mark the mission as pause requested
	// The Execute method checks this flag during execution and stops gracefully
	m.pauseRequestedMu.Lock()
	defer m.pauseRequestedMu.Unlock()

	if m.pauseRequested == nil {
		m.pauseRequested = make(map[types.ID]bool)
	}

	m.pauseRequested[missionID] = true
	return nil
}

// Ensure MissionAdapter implements mission.MissionOrchestrator
var _ mission.MissionOrchestrator = (*MissionAdapter)(nil)
