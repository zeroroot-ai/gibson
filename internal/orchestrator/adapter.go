package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/graphrag/queries"
	"github.com/zero-day-ai/gibson/internal/harness"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/types"
	commonpb "github.com/zero-day-ai/sdk/api/gen/commonpb"
	pb "github.com/zero-day-ai/sdk/api/gen/proto"
	"github.com/zero-day-ai/sdk/api/gen/workflowpb"
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
	LoadMission(ctx context.Context, def *mission.MissionDefinition) (string, error)
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
	mis.StartedAt = &startedAt

	// Initialize metrics
	if mis.Metrics == nil {
		mis.Metrics = &mission.MissionMetrics{
			StartedAt:          startedAt,
			LastUpdateAt:       startedAt,
			FindingsBySeverity: make(map[string]int),
		}
	}

	// Parse mission definition from mission
	var def *mission.MissionDefinition
	var err error

	if mis.WorkflowJSON != "" {
		// Parse mission definition from inline JSON
		def = &mission.MissionDefinition{}
		if err = json.Unmarshal([]byte(mis.WorkflowJSON), def); err != nil {
			return nil, fmt.Errorf("failed to parse mission definition: %w", err)
		}
	} else if mis.WorkflowID != "" {
		// For now, we need the definition JSON to be present
		// In a future enhancement, we could load from the mission definition store
		return nil, fmt.Errorf("mission definition loading from WorkflowID not yet implemented in adapter")
	} else {
		return nil, fmt.Errorf("no mission definition available (neither WorkflowID nor WorkflowJSON)")
	}

	// Store mission definition in Neo4j graph for state tracking
	if m.config.GraphLoader != nil {
		graphMissionID, err := m.config.GraphLoader.LoadMission(ctx, def)
		if err != nil {
			// Log warning but continue - graph storage is optional
			m.config.Logger.Warn("failed to store mission definition in GraphRAG",
				"error", err,
				"mission_id", mis.ID,
				"definition_name", def.Name,
			)
		} else {
			m.config.Logger.Info("mission definition stored in GraphRAG",
				"graph_mission_id", graphMissionID,
				"mission_id", mis.ID,
				"definition_name", def.Name,
			)
		}
	}

	// Track mission and mission run in Neo4j for GraphRAG mission-scoped storage
	var missionRunID string
	if m.config.MissionGraphManager != nil {
		// Ensure Mission node exists (or get existing one)
		graphMissionID, err := m.config.MissionGraphManager.EnsureMissionNode(ctx, mis.Name, mis.TargetID.String())
		if err != nil {
			m.config.Logger.Warn("failed to ensure mission node in GraphRAG",
				"error", err,
				"mission_id", mis.ID,
				"mission_name", mis.Name,
				"target_id", mis.TargetID,
			)
		} else {
			m.config.Logger.Debug("mission node ensured in GraphRAG",
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
				m.config.Logger.Warn("failed to create mission run node in GraphRAG",
					"error", err,
					"mission_id", mis.ID,
					"graph_mission_id", graphMissionID,
					"run_number", runNumber,
				)
			} else {
				m.config.Logger.Info("mission run node created in GraphRAG",
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
			m.config.Logger.Warn("failed to update mission run status in GraphRAG",
				"error", updateErr,
				"mission_run_id", missionRunID,
				"status", status,
			)
		} else {
			m.config.Logger.Info("mission run status updated in GraphRAG",
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
func (m *MissionAdapter) createOrchestrator(ctx context.Context, mis *mission.Mission, def *mission.MissionDefinition, missionRunID string, runNumber int) (*Orchestrator, error) {
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

	// Create Observer with inventory builder for component awareness in observations
	observer := NewObserver(missionQueries, executionQueries,
		WithInventoryBuilder(inventoryBuilder),
	)

	// Create harness for this mission
	// Use the harness factory to create an appropriate harness
	missionCtx := harness.NewMissionContext(mis.ID, mis.Name, "")
	missionCtx.MissionRunID = missionRunID
	missionCtx.RunNumber = runNumber

	// Create target info
	// Note: In a full implementation, we would load the target entity here
	// For now, we use a simplified approach
	targetInfo := harness.NewTargetInfo(mis.TargetID, "mission-target", "", "")

	// Get first agent name from definition
	agentName := "orchestrator" // Default agent name
	if len(def.Nodes) > 0 {
		for _, node := range def.Nodes {
			if node.Type == mission.NodeTypeAgent && node.AgentName != "" {
				agentName = node.AgentName
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
			m.config.Logger.Warn("failed to build component inventory, validation will be skipped",
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
		policyChecker = NewPolicyChecker(policySource, nodeStore, m.config.Logger.With("component", "policy_checker"))
	}

	// Create Actor with DiscoveryProcessor for storing agent output discoveries
	actor := NewActor(harnessAdapter, executionQueries, missionQueries, m.config.GraphRAGClient, inventory, m.config.MissionTracer, policyChecker, m.config.DiscoveryProcessor, m.config.Logger)

	// Create the orchestrator
	orchOptions := []OrchestratorOption{
		WithMaxIterations(m.config.MaxIterations),
		WithMaxConcurrent(m.config.MaxConcurrent),
		WithBudget(m.config.Budget),
		WithTimeout(m.config.Timeout),
		WithLogger(m.config.Logger.With("component", "orchestrator", "mission_id", mis.ID)),
		WithTracer(m.config.Tracer),
		WithEventBus(m.config.EventBus),
		WithDecisionLogWriter(m.config.DecisionLogWriter),
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
	mis.CompletedAt = &completedAt
	mis.Metrics.Duration = orchResult.Duration
	mis.Metrics.CompletedNodes = orchResult.CompletedNodes
	mis.Metrics.LastUpdateAt = completedAt

	// Set result completion time
	result.CompletedAt = completedAt

	// Convert orchestrator result to workflow result map
	if orchResult.FinalState != nil {
		workflowResultMap := make(map[string]any)
		workflowResultMap["status"] = string(orchResult.Status)
		workflowResultMap["total_iterations"] = orchResult.TotalIterations
		workflowResultMap["total_decisions"] = orchResult.TotalDecisions
		workflowResultMap["total_tokens"] = orchResult.TotalTokensUsed
		workflowResultMap["completed_nodes"] = orchResult.CompletedNodes
		workflowResultMap["failed_nodes"] = orchResult.FailedNodes
		workflowResultMap["duration"] = orchResult.Duration.String()

		if orchResult.StopReason != "" {
			workflowResultMap["stop_reason"] = orchResult.StopReason
		}

		result.WorkflowResult = workflowResultMap
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
	mis.CompletedAt = &completedAt
	mis.Metrics.Duration = completedAt.Sub(startedAt)
	result.CompletedAt = completedAt

	// If we have partial orchestrator results, include them
	if orchResult != nil {
		workflowResultMap := make(map[string]any)
		workflowResultMap["status"] = "failed"
		workflowResultMap["total_iterations"] = orchResult.TotalIterations
		workflowResultMap["total_decisions"] = orchResult.TotalDecisions
		workflowResultMap["total_tokens"] = orchResult.TotalTokensUsed
		workflowResultMap["completed_nodes"] = orchResult.CompletedNodes
		workflowResultMap["failed_nodes"] = orchResult.FailedNodes
		workflowResultMap["duration"] = orchResult.Duration.String()
		workflowResultMap["error"] = err.Error()
		result.WorkflowResult = workflowResultMap
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
	// For now, checkpoint recovery is not yet implemented in orchestrator
	// We'll execute from the beginning
	// TODO: Implement checkpoint recovery in orchestrator

	// Parse checkpoint state if available
	if checkpoint != nil && len(checkpoint.CompletedNodes) > 0 {
		// In a future enhancement, we would update the graph state to mark completed nodes
		// For now, we log a warning and execute normally
		_ = checkpoint // silence unused warning
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

	// Extract workflow state
	if checkpoint.WorkflowState != nil {
		stateBytes, err := json.Marshal(checkpoint.WorkflowState)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal workflow state: %w", err)
		}
		if err := json.Unmarshal(stateBytes, &state); err != nil {
			return nil, fmt.Errorf("failed to unmarshal workflow state: %w", err)
		}
	}

	// Add completed and pending nodes
	state["completed_nodes"] = checkpoint.CompletedNodes
	state["pending_nodes"] = checkpoint.PendingNodes

	return state, nil
}

// ExecuteProto executes a mission using a proto WorkflowDefinition instead of MissionDefinition.
// This provides type-safe workflow execution with proto enum validation and oneof accessors.
func (m *MissionAdapter) ExecuteProto(ctx context.Context, mis *mission.Mission, workflowDef *workflowpb.WorkflowDefinition) (*mission.MissionResult, error) {
	// Convert proto WorkflowDefinition to internal MissionDefinition
	def, err := protoWorkflowToMissionDefinition(workflowDef)
	if err != nil {
		return nil, fmt.Errorf("failed to convert proto workflow to mission definition: %w", err)
	}

	// Store converted definition in mission for existing Execute method
	defJSON, err := json.Marshal(def)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal mission definition: %w", err)
	}
	mis.WorkflowJSON = string(defJSON)

	// Use existing Execute method
	return m.Execute(ctx, mis)
}

// protoWorkflowToMissionDefinition converts a proto WorkflowDefinition to internal MissionDefinition.
// This function uses proto enum types and oneof accessors as specified in Phase 3 requirements.
func protoWorkflowToMissionDefinition(proto *workflowpb.WorkflowDefinition) (*mission.MissionDefinition, error) {
	if proto == nil {
		return nil, fmt.Errorf("proto workflow definition is nil")
	}

	// Convert proto nodes to mission nodes
	nodes := make(map[string]*mission.MissionNode)
	for nodeID, protoNode := range proto.Nodes {
		missionNode, err := protoNodeToMissionNode(nodeID, protoNode)
		if err != nil {
			return nil, fmt.Errorf("failed to convert node %s: %w", nodeID, err)
		}
		nodes[nodeID] = missionNode
	}

	// Convert proto edges to mission edges
	edges := make([]mission.MissionEdge, len(proto.Edges))
	for i, protoEdge := range proto.Edges {
		edges[i] = mission.MissionEdge{
			From:      protoEdge.From,
			To:        protoEdge.To,
			Condition: protoEdge.Condition,
		}
	}

	// Convert dependencies if present
	var deps *mission.MissionDependencies
	if proto.Dependencies != nil {
		deps = &mission.MissionDependencies{
			Agents:  proto.Dependencies.Agents,
			Tools:   proto.Dependencies.Tools,
			Plugins: proto.Dependencies.Plugins,
		}
	}

	// Convert metadata map
	metadata := make(map[string]any)
	for k, v := range proto.Metadata {
		metadata[k] = v
	}

	def := &mission.MissionDefinition{
		ID:           types.ID(proto.Id),
		Name:         proto.Name,
		Description:  proto.Description,
		Version:      proto.Version,
		TargetRef:    proto.TargetRef,
		Nodes:        nodes,
		Edges:        edges,
		EntryPoints:  proto.EntryPoints,
		ExitPoints:   proto.ExitPoints,
		Metadata:     metadata,
		Dependencies: deps,
		Source:       proto.Source,
	}

	if proto.InstalledAt != nil {
		def.InstalledAt = proto.InstalledAt.AsTime()
	}
	if proto.CreatedAt != nil {
		def.CreatedAt = proto.CreatedAt.AsTime()
	}

	return def, nil
}

// protoNodeToMissionNode converts a proto WorkflowNode to internal MissionNode.
// Uses proto enum types and oneof accessors for type-safe node configuration.
func protoNodeToMissionNode(nodeID string, protoNode *workflowpb.WorkflowNode) (*mission.MissionNode, error) {
	if protoNode == nil {
		return nil, fmt.Errorf("proto node is nil")
	}

	// Convert node type enum to internal type
	var nodeType mission.NodeType
	switch protoNode.Type {
	case workflowpb.NodeType_NODE_TYPE_AGENT:
		nodeType = mission.NodeTypeAgent
	case workflowpb.NodeType_NODE_TYPE_TOOL:
		nodeType = mission.NodeTypeTool
	case workflowpb.NodeType_NODE_TYPE_PLUGIN:
		nodeType = mission.NodeTypePlugin
	case workflowpb.NodeType_NODE_TYPE_CONDITION:
		nodeType = mission.NodeTypeCondition
	case workflowpb.NodeType_NODE_TYPE_PARALLEL:
		nodeType = mission.NodeTypeParallel
	case workflowpb.NodeType_NODE_TYPE_JOIN:
		nodeType = mission.NodeTypeJoin
	default:
		return nil, fmt.Errorf("unknown node type: %v", protoNode.Type)
	}

	node := &mission.MissionNode{
		ID:           nodeID,
		Type:         nodeType,
		Name:         protoNode.Name,
		Description:  protoNode.Description,
		Dependencies: protoNode.Dependencies,
	}

	// Convert timeout if present
	if protoNode.Timeout != nil {
		node.Timeout = protoNode.Timeout.AsDuration()
	}

	// Convert retry policy if present
	if protoNode.RetryPolicy != nil {
		node.RetryPolicy = &mission.RetryPolicy{
			MaxRetries: int(protoNode.RetryPolicy.MaxRetries),
		}

		// Convert backoff strategy enum
		switch protoNode.RetryPolicy.BackoffStrategy {
		case workflowpb.BackoffStrategy_BACKOFF_STRATEGY_CONSTANT:
			node.RetryPolicy.BackoffStrategy = mission.BackoffConstant
		case workflowpb.BackoffStrategy_BACKOFF_STRATEGY_LINEAR:
			node.RetryPolicy.BackoffStrategy = mission.BackoffLinear
		case workflowpb.BackoffStrategy_BACKOFF_STRATEGY_EXPONENTIAL:
			node.RetryPolicy.BackoffStrategy = mission.BackoffExponential
		}

		if protoNode.RetryPolicy.InitialDelay != nil {
			node.RetryPolicy.InitialDelay = protoNode.RetryPolicy.InitialDelay.AsDuration()
		}
		if protoNode.RetryPolicy.MaxDelay != nil {
			node.RetryPolicy.MaxDelay = protoNode.RetryPolicy.MaxDelay.AsDuration()
		}
		node.RetryPolicy.Multiplier = protoNode.RetryPolicy.Multiplier
	}

	// Convert metadata (string map to any map)
	if protoNode.Metadata != nil {
		node.Metadata = make(map[string]any, len(protoNode.Metadata))
		for k, v := range protoNode.Metadata {
			node.Metadata[k] = v
		}
	}

	// Use oneof accessors to get node-specific configuration
	switch nodeType {
	case mission.NodeTypeAgent:
		agentConfig := protoNode.GetAgentConfig()
		if agentConfig != nil {
			node.AgentName = agentConfig.AgentName
			if agentConfig.Task != nil {
				node.AgentTask = protoTaskToAgentTask(agentConfig.Task)
			}
		}

	case mission.NodeTypeTool:
		toolConfig := protoNode.GetToolConfig()
		if toolConfig != nil {
			node.ToolName = toolConfig.ToolName
			if toolConfig.Input != nil {
				node.ToolInput = make(map[string]any, len(toolConfig.Input))
				for k, v := range toolConfig.Input {
					node.ToolInput[k] = v
				}
			}
		}

	case mission.NodeTypePlugin:
		pluginConfig := protoNode.GetPluginConfig()
		if pluginConfig != nil {
			node.PluginName = pluginConfig.PluginName
			node.PluginMethod = pluginConfig.Method
			if pluginConfig.Params != nil {
				node.PluginParams = make(map[string]any, len(pluginConfig.Params))
				for k, v := range pluginConfig.Params {
					node.PluginParams[k] = v
				}
			}
		}

	case mission.NodeTypeCondition:
		condConfig := protoNode.GetConditionConfig()
		if condConfig != nil {
			node.Condition = &mission.NodeCondition{
				Expression:  condConfig.Expression,
				TrueBranch:  condConfig.TrueBranch,
				FalseBranch: condConfig.FalseBranch,
			}
		}

	case mission.NodeTypeParallel:
		parallelConfig := protoNode.GetParallelConfig()
		if parallelConfig != nil {
			// Convert sub-nodes
			subNodes := make([]*mission.MissionNode, len(parallelConfig.SubNodes))
			for i, subProtoNode := range parallelConfig.SubNodes {
				subNode, err := protoNodeToMissionNode(subProtoNode.Id, subProtoNode)
				if err != nil {
					return nil, fmt.Errorf("failed to convert sub-node %s: %w", subProtoNode.Id, err)
				}
				subNodes[i] = subNode
			}
			node.SubNodes = subNodes
		}
	}

	return node, nil
}

// protoTaskToAgentTask converts a proto Task to an internal agent.Task.
func protoTaskToAgentTask(protoTask *pb.Task) *agent.Task {
	if protoTask == nil {
		return nil
	}

	task := &agent.Task{
		ID:   types.ID(protoTask.Id),
		Goal: protoTask.Goal,
	}

	// Convert context (TypedValue map to any map)
	if protoTask.Context != nil {
		task.Context = make(map[string]any, len(protoTask.Context))
		for k, v := range protoTask.Context {
			task.Context[k] = typedValueToAny(v)
		}
	}

	return task
}

// typedValueToAny converts a proto TypedValue to any.
func typedValueToAny(tv *commonpb.TypedValue) any {
	if tv == nil {
		return nil
	}

	switch v := tv.GetKind().(type) {
	case *commonpb.TypedValue_StringValue:
		return v.StringValue
	case *commonpb.TypedValue_IntValue:
		return v.IntValue
	case *commonpb.TypedValue_DoubleValue:
		return v.DoubleValue
	case *commonpb.TypedValue_BoolValue:
		return v.BoolValue
	case *commonpb.TypedValue_BytesValue:
		return v.BytesValue
	case *commonpb.TypedValue_ArrayValue:
		if v.ArrayValue == nil {
			return nil
		}
		list := make([]any, len(v.ArrayValue.Items))
		for i, item := range v.ArrayValue.Items {
			list[i] = typedValueToAny(item)
		}
		return list
	case *commonpb.TypedValue_MapValue:
		if v.MapValue == nil {
			return nil
		}
		m := make(map[string]any, len(v.MapValue.Entries))
		for k, item := range v.MapValue.Entries {
			m[k] = typedValueToAny(item)
		}
		return m
	default:
		return nil
	}
}

// Ensure MissionAdapter implements mission.MissionOrchestrator
var _ mission.MissionOrchestrator = (*MissionAdapter)(nil)
