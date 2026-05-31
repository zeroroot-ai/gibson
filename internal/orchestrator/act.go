package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j/dbtype"
	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/graphrag/queries"
	"github.com/zeroroot-ai/gibson/internal/graphrag/schema"
	"github.com/zeroroot-ai/gibson/internal/harness"
	"github.com/zeroroot-ai/gibson/internal/types"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	"github.com/zeroroot-ai/sdk/toolerr"
	"google.golang.org/protobuf/encoding/protojson"
)

// Harness defines the interface for agent delegation and tool execution.
// This matches the SDK harness interface for seamless agent integration.
type Harness interface {
	// DelegateToAgent delegates a task to another agent and waits for the result
	DelegateToAgent(ctx context.Context, agentName string, task agent.Task) (agent.Result, error)
}

// DiscoveryProcessor processes DiscoveryResult from agent outputs and stores to Neo4j.
// This interface is implemented by the graphrag/processor package or an adapter.
type DiscoveryProcessor interface {
	// ProcessAgentDiscovery stores discovered nodes from a proto DiscoveryResult in the graph.
	// This is specifically for processing agent output (not tool output).
	// The missionRunID parameter identifies which MissionRun node the discovered entities should be attached to,
	// enabling mission-scoped data isolation and proper lineage tracking.
	// Returns statistics about nodes/relationships created and any errors.
	ProcessAgentDiscovery(ctx context.Context, missionID, missionRunID, agentName, agentRunID string, discovery *graphragpb.DiscoveryResult) (nodesCreated int, err error)
}

// Actor executes orchestrator decisions by performing the appropriate actions
// in the graph and delegating to agents as needed.
type Actor struct {
	harness            Harness
	execQueries        *queries.ExecutionQueries
	missionQueries     *queries.MissionQueries
	graphClient        graph.GraphClient
	inventory          *ComponentInventory    // Component inventory for validation
	policyChecker      PolicyChecker          // Policy checker for data reuse enforcement (optional, can be nil)
	discoveryProcessor DiscoveryProcessor     // Processes DiscoveryResult from agent outputs (optional, can be nil)
	approvalManager    ApprovalManager        // Manages approval request lifecycle (optional, can be nil)
	escalationManager  EscalationManager      // Manages escalation lifecycle (optional, can be nil)
	checkpointManager  CheckpointManager      // Manages mission checkpoints and rollback (optional, can be nil)
	reflectionEngine   ReflectionEngine       // Performs self-evaluation of strategy (optional, can be nil)
	memoryRecaller     MemoryRecaller         // Queries memory tiers for context (optional, can be nil)
	checkpointHook     *CheckpointIntegration // Spec 4 R5 — synchronous approval-pause checkpoint hook (optional)
	logger             *slog.Logger           // Logger for Actor operations
}

// SetCheckpointIntegration wires the Spec 4 mission-checkpointing integration
// into the actor so requestApproval can synchronously checkpoint the
// approval-paused state before persisting the approval request. Pass nil to
// disable approval checkpointing.
func (a *Actor) SetCheckpointIntegration(ci *CheckpointIntegration) {
	if a == nil {
		return
	}
	a.checkpointHook = ci
}

// ActorOption is a functional option for configuring Actor.
type ActorOption func(*Actor)

// WithApprovalManager sets the approval manager for human-in-the-loop approvals
func WithApprovalManager(am ApprovalManager) ActorOption {
	return func(a *Actor) {
		a.approvalManager = am
	}
}

// WithEscalationManager sets the escalation manager for formal escalations
func WithEscalationManager(em EscalationManager) ActorOption {
	return func(a *Actor) {
		a.escalationManager = em
	}
}

// WithCheckpointManager sets the checkpoint manager for rollback support
func WithCheckpointManager(cm CheckpointManager) ActorOption {
	return func(a *Actor) {
		a.checkpointManager = cm
	}
}

// WithReflectionEngine sets the reflection engine for self-evaluation
func WithReflectionEngine(re ReflectionEngine) ActorOption {
	return func(a *Actor) {
		a.reflectionEngine = re
	}
}

// WithMemoryRecaller sets the memory recaller for context queries
func WithMemoryRecaller(mr MemoryRecaller) ActorOption {
	return func(a *Actor) {
		a.memoryRecaller = mr
	}
}

// NewActor creates a new Actor with the given dependencies.
// The harness is used for agent delegation and tool execution.
// The queries provide graph operations for tracking execution state.
// The inventory parameter is optional and used for component validation.
// The policyChecker parameter is optional and enables data reuse policy enforcement when provided.
// The discoveryProcessor parameter is optional and enables automatic storage of DiscoveryResult from agent outputs.
// The approvalManager parameter is optional and enables approval request handling when provided.
// The escalationManager parameter is optional and enables escalation handling when provided.
// The checkpointManager parameter is optional and enables checkpoint/rollback functionality when provided.
// The reflectionEngine parameter is optional and enables reflection capability when provided.
// The memoryRecaller parameter is optional and enables memory recall functionality when provided.
func NewActor(harness Harness, execQueries *queries.ExecutionQueries, missionQueries *queries.MissionQueries, graphClient graph.GraphClient, inventory *ComponentInventory, policyChecker PolicyChecker, discoveryProcessor DiscoveryProcessor, approvalManager ApprovalManager, escalationManager EscalationManager, checkpointManager CheckpointManager, reflectionEngine ReflectionEngine, memoryRecaller MemoryRecaller, logger *slog.Logger) *Actor {
	if logger == nil {
		logger = slog.Default()
	}
	return &Actor{
		harness:            harness,
		execQueries:        execQueries,
		missionQueries:     missionQueries,
		graphClient:        graphClient,
		inventory:          inventory,
		policyChecker:      policyChecker,
		discoveryProcessor: discoveryProcessor,
		approvalManager:    approvalManager,
		escalationManager:  escalationManager,
		checkpointManager:  checkpointManager,
		reflectionEngine:   reflectionEngine,
		memoryRecaller:     memoryRecaller,
		logger:             logger.With("component", "actor"),
	}
}

// ActionResult contains the outcome of executing a decision action.
// It includes all relevant state changes, execution results, and metadata
// needed for logging to Langfuse and updating the graph.
type ActionResult struct {
	// Action is the decision action that was executed
	Action DecisionAction

	// AgentExecution contains execution details if an agent was run
	AgentExecution *schema.AgentExecution

	// NewNode contains the newly spawned node if spawn_agent was used
	NewNode *schema.MissionNode

	// Error contains any error that occurred during action execution
	Error error

	// IsTerminal indicates if this action ends the orchestration loop
	IsTerminal bool

	// TargetNodeID is the node that was acted upon
	TargetNodeID string

	// Metadata contains additional action-specific metadata
	Metadata map[string]interface{}
}

// Act executes the given decision and returns the result.
// This method orchestrates all the actions needed to fulfill the decision,
// including graph updates, agent delegation, and error handling.
func (a *Actor) Act(ctx context.Context, decision *Decision, missionID string) (*ActionResult, error) {
	if decision == nil {
		return nil, fmt.Errorf("decision cannot be nil")
	}

	// Validate decision before acting
	if err := decision.Validate(); err != nil {
		return nil, fmt.Errorf("invalid decision: %w", err)
	}

	// Parse mission ID
	parsedMissionID, err := types.ParseID(missionID)
	if err != nil {
		return nil, fmt.Errorf("invalid mission ID: %w", err)
	}

	// Route to appropriate action handler
	switch decision.Action {
	case ActionExecuteAgent:
		return a.executeAgent(ctx, decision, parsedMissionID)

	case ActionSkipAgent:
		return a.skipAgent(ctx, decision, parsedMissionID)

	case ActionModifyParams:
		return a.modifyParams(ctx, decision, parsedMissionID)

	case ActionRetry:
		return a.retryAgent(ctx, decision, parsedMissionID)

	case ActionSpawnAgent:
		return a.spawnAgent(ctx, decision, parsedMissionID)

	case ActionComplete:
		return a.completeMission(ctx, decision, parsedMissionID)

	case ActionRequestApproval:
		return a.requestApproval(ctx, decision, parsedMissionID)

	case ActionAbort:
		return a.abort(ctx, decision, parsedMissionID)

	case ActionEscalate:
		return a.escalate(ctx, decision, parsedMissionID)

	case ActionRollback:
		return a.rollback(ctx, decision, parsedMissionID)

	case ActionReflect:
		return a.reflect(ctx, decision, parsedMissionID)

	case ActionRecall:
		return a.recall(ctx, decision, parsedMissionID)

	default:
		return nil, fmt.Errorf("unknown decision action: %s", decision.Action)
	}
}

// executeAgent executes the mission node by delegating to the appropriate agent.
// This creates an execution node, delegates to the agent, and updates the graph
// with the execution results.
func (a *Actor) executeAgent(ctx context.Context, decision *Decision, missionID types.ID) (*ActionResult, error) {
	// Get the mission node
	node, err := a.getMissionNode(ctx, decision.TargetNodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get mission node: %w", err)
	}

	// Verify it's an agent node
	if node.Type != schema.MissionNodeTypeAgent {
		return nil, fmt.Errorf("node %s is not an agent node (type: %s)", node.ID, node.Type)
	}

	// Check data reuse policy if policy checker is configured
	if a.policyChecker != nil {
		shouldExecute, reason := a.policyChecker.ShouldExecute(ctx, node.AgentName)
		if !shouldExecute {
			// Policy check failed - skip this agent execution
			slog.Info("agent execution skipped by data reuse policy",
				"agent_name", node.AgentName,
				"node_id", node.ID.String(),
				"reason", reason)

			// Mark the node as skipped
			if err := a.updateNodeStatus(ctx, node.ID, schema.MissionNodeStatusSkipped); err != nil {
				return nil, fmt.Errorf("failed to update node status to skipped: %w", err)
			}

			// Return a result indicating the agent was skipped
			return &ActionResult{
				Action:       ActionExecuteAgent,
				Error:        nil,
				IsTerminal:   false,
				TargetNodeID: decision.TargetNodeID,
				Metadata: map[string]interface{}{
					"agent_name":   node.AgentName,
					"skipped":      true,
					"skip_reason":  reason,
					"policy_check": true,
				},
			}, nil
		}
	}

	// Create implicit checkpoint before execution (if checkpoint manager configured)
	if a.checkpointManager != nil {
		if err := a.checkpointManager.CreateImplicitCheckpoint(ctx, missionID.String(), node.ID.String()); err != nil {
			// Log but don't fail - checkpoint is optional
			a.logger.Warn("failed to create implicit checkpoint",
				"node_id", node.ID.String(),
				"error", err)
		}
	}

	// Determine attempt number by counting previous executions
	prevExecutions, err := a.execQueries.GetNodeExecutions(ctx, node.ID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get previous executions: %w", err)
	}
	attemptNum := len(prevExecutions) + 1

	// Create agent execution node
	execution := schema.NewAgentExecution(node.ID.String(), missionID)
	execution.WithAttempt(attemptNum)
	execution.WithConfig(node.TaskConfig)

	// Create execution in graph
	if err := a.execQueries.CreateAgentExecution(ctx, execution); err != nil {
		return nil, fmt.Errorf("failed to create agent execution: %w", err)
	}

	// Update mission node status to running
	if err := a.updateNodeStatus(ctx, node.ID, schema.MissionNodeStatusRunning); err != nil {
		return nil, fmt.Errorf("failed to update node status: %w", err)
	}

	// Build agent task from node's TaskConfig
	// TaskConfig contains: goal, context (merged with task config), input, name, description, etc.
	task := agent.Task{
		ID:        types.NewID(),
		Name:      node.Name,
		MissionID: &missionID,
		CreatedAt: time.Now(),
	}

	// Set timeout
	if node.Timeout > 0 {
		task.Timeout = node.Timeout
	} else {
		task.Timeout = 30 * time.Minute // Default
	}

	// Set description from node or TaskConfig
	task.Description = node.Description
	if desc, ok := node.TaskConfig["description"].(string); ok && desc != "" {
		task.Description = desc
	}

	// Set Goal from TaskConfig (populated by mission parser from YAML goal field)
	if goal, ok := node.TaskConfig["goal"].(string); ok {
		task.Goal = goal
	} else if task.Description != "" {
		task.Goal = task.Description // Fall back to description
	}

	// Set Context from TaskConfig (contains merged context + task config from YAML)
	if ctxMap, ok := node.TaskConfig["context"].(map[string]any); ok {
		task.Context = ctxMap
	} else {
		// If no context, use entire TaskConfig as context for backwards compatibility
		task.Context = node.TaskConfig
	}

	// Inject mission target into task context if not already set
	// This ensures agents receive the target from mission configuration
	if task.Context == nil {
		task.Context = make(map[string]any)
	}
	if _, hasTarget := task.Context["target"]; !hasTarget {
		// Fetch mission to get target reference
		if a.missionQueries != nil {
			if m, err := a.missionQueries.GetMission(ctx, missionID); err == nil && m.TargetRef != "" {
				task.Context["target"] = m.TargetRef
				a.logger.Debug("injected mission target into agent task context",
					"agent_name", node.AgentName,
					"target", m.TargetRef)
			}
		}
	}

	// Keep Input for backwards compatibility (deprecated)
	if input, ok := node.TaskConfig["input"].(map[string]any); ok {
		task.Input = input
	} else {
		task.Input = node.TaskConfig
	}

	// Build per-node LLM slot overrides from the sentinel key persisted by
	// graph_bootstrap.convertToSchemaNode. The "__llm_slots" entry may arrive in
	// two forms depending on whether it was read from Neo4j (JSON round-trip) or
	// used in-memory before a round-trip:
	//   • In-memory form (graph_bootstrap → executeAgent same call): []map[string]string
	//   • Post-Neo4j form (JSON.Unmarshal into map[string]any): []interface{} where
	//     each element is map[string]interface{} with string values.
	// Both forms are handled below. Entries with an empty provider are omitted at
	// write time so we never encounter them here.
	// Spec: per-node-slot-override (gibson#539).
	if rawSlots, ok := node.TaskConfig["__llm_slots"]; ok {
		overrides := decodeSlotOverrides(rawSlots)
		if len(overrides) > 0 {
			task.SlotOverrides = overrides
		}
	}

	// Inject agent execution ID into context for callback services
	// This allows the registry adapter to include AgentRunID in CallbackInfo
	// The execution.ID is used for provenance tracking (DISCOVERED relationships)
	ctx = harness.ContextWithAgentRunID(ctx, execution.ID.String())

	// Delegate to agent
	result, err := a.harness.DelegateToAgent(ctx, node.AgentName, task)

	// Update execution based on result
	if err != nil {
		// Extract structured error if available
		var toolErr *toolerr.Error
		if errors.As(err, &toolErr) {
			// Enrich error with registry hints
			toolErr = toolerr.EnrichError(toolErr)

			// Store structured error details
			execution.MarkFailedWithDetails(
				toolErr.Message,
				string(toolErr.Class),
				toolErr.Code,
				toolErr.Hints,
			)
		} else {
			// Fall back to existing behavior for non-toolerr errors
			execution.MarkFailed(err.Error())
		}

		if updateErr := a.execQueries.UpdateExecution(ctx, execution); updateErr != nil {
			return nil, fmt.Errorf("failed to update execution after error: %w", updateErr)
		}

		// Update node status to failed
		if updateErr := a.updateNodeStatus(ctx, node.ID, schema.MissionNodeStatusFailed); updateErr != nil {
			return nil, fmt.Errorf("failed to update node status: %w", updateErr)
		}

		return &ActionResult{
			Action:         ActionExecuteAgent,
			AgentExecution: execution,
			Error:          err,
			IsTerminal:     false,
			TargetNodeID:   decision.TargetNodeID,
		}, nil
	}

	// Check if agent execution failed
	if result.Status == agent.ResultStatusFailed {
		errMsg := "agent execution failed"
		var errCode string

		if result.Error != nil {
			errMsg = result.Error.Message
			errCode = result.Error.Code

			// Log detailed error info at debug level
			slog.Debug("agent execution failed with structured error",
				"agent_name", node.AgentName,
				"error_code", result.Error.Code,
				"error_message", result.Error.Message,
				"recoverable", result.Error.Recoverable,
			)

			// Store structured error details in execution if error code is available
			if errCode != "" {
				// Infer class from code and store structured error details
				errorClass := string(toolerr.DefaultClassForCode(errCode))
				execution.MarkFailedWithDetails(
					errMsg,
					errorClass,
					errCode,
					nil, // No hints available at this level
				)
			} else {
				// No error code, use basic MarkFailed
				execution.MarkFailed(errMsg)
			}
		} else {
			execution.MarkFailed(errMsg)
		}

		// Add error code to metadata if available
		if errCode != "" {
			if execution.Result == nil {
				execution.Result = make(map[string]any)
			}
			execution.Result["error_code"] = errCode
		}

		// Update node status to failed
		if updateErr := a.updateNodeStatus(ctx, node.ID, schema.MissionNodeStatusFailed); updateErr != nil {
			return nil, fmt.Errorf("failed to update node status: %w", updateErr)
		}
	} else {
		// Execution succeeded
		execution.MarkCompleted()
		execution.WithResult(result.Output)

		// Extract missionRunID from context for discovery processing
		missionRunID := harness.MissionRunIDFromContext(ctx)

		// Process DiscoveryResult from agent output if present
		// This stores discovered hosts, ports, services, etc. to Neo4j for use by downstream agents
		a.processAgentDiscovery(ctx, result.Output, node.AgentName, execution.ID.String(), missionID, missionRunID)

		// Update node status to completed
		if updateErr := a.updateNodeStatus(ctx, node.ID, schema.MissionNodeStatusCompleted); updateErr != nil {
			return nil, fmt.Errorf("failed to update node status: %w", updateErr)
		}

		// Update dependent nodes to ready if their dependencies are now satisfied
		if updateErr := a.updateDependentNodesToReady(ctx, node.ID); updateErr != nil {
			slog.Warn("failed to update dependent nodes to ready",
				"node_id", node.ID.String(),
				"error", updateErr,
			)
			// Don't fail the whole operation, just log the warning
		}
	}

	// Update execution in graph
	if updateErr := a.execQueries.UpdateExecution(ctx, execution); updateErr != nil {
		return nil, fmt.Errorf("failed to update execution: %w", updateErr)
	}

	return &ActionResult{
		Action:         ActionExecuteAgent,
		AgentExecution: execution,
		Error:          nil,
		IsTerminal:     false,
		TargetNodeID:   decision.TargetNodeID,
		Metadata: map[string]interface{}{
			"agent_name":     node.AgentName,
			"attempt":        attemptNum,
			"result_status":  string(result.Status),
			"findings_count": len(result.Findings),
		},
	}, nil
}

// skipAgent marks a mission node as skipped with the reasoning from the decision.
// This is used when the orchestrator determines a node doesn't need to execute.
func (a *Actor) skipAgent(ctx context.Context, decision *Decision, missionID types.ID) (*ActionResult, error) {
	// Get the mission node
	node, err := a.getMissionNode(ctx, decision.TargetNodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get mission node: %w", err)
	}

	// Update node status to skipped
	if err := a.updateNodeStatus(ctx, node.ID, schema.MissionNodeStatusSkipped); err != nil {
		return nil, fmt.Errorf("failed to update node status: %w", err)
	}

	return &ActionResult{
		Action:       ActionSkipAgent,
		Error:        nil,
		IsTerminal:   false,
		TargetNodeID: decision.TargetNodeID,
		Metadata: map[string]interface{}{
			"reasoning":  decision.Reasoning,
			"confidence": decision.Confidence,
		},
	}, nil
}

// modifyParams updates the task configuration for a mission node and then executes it.
// This allows the orchestrator to adapt agent parameters based on context.
func (a *Actor) modifyParams(ctx context.Context, decision *Decision, missionID types.ID) (*ActionResult, error) {
	// Get the mission node
	node, err := a.getMissionNode(ctx, decision.TargetNodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get mission node: %w", err)
	}

	// Merge modifications into task config
	mergedConfig := make(map[string]interface{})
	for k, v := range node.TaskConfig {
		mergedConfig[k] = v
	}
	for k, v := range decision.Modifications {
		mergedConfig[k] = v
	}

	// Update node task config in graph
	if err := a.updateNodeConfig(ctx, node.ID, mergedConfig); err != nil {
		return nil, fmt.Errorf("failed to update node config: %w", err)
	}

	// Reload node with updated config
	node.TaskConfig = mergedConfig

	// Now execute the agent with modified params
	// Create a new decision for execute_agent
	execDecision := &Decision{
		Reasoning:    fmt.Sprintf("Executing with modified params: %s", decision.Reasoning),
		Action:       ActionExecuteAgent,
		TargetNodeID: decision.TargetNodeID,
		Confidence:   decision.Confidence,
	}

	return a.executeAgent(ctx, execDecision, missionID)
}

// retryAgent re-executes a failed mission node, optionally with modified parameters.
// This implements retry logic based on the node's retry policy.
func (a *Actor) retryAgent(ctx context.Context, decision *Decision, missionID types.ID) (*ActionResult, error) {
	// Get the mission node
	node, err := a.getMissionNode(ctx, decision.TargetNodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get mission node: %w", err)
	}

	// Check retry policy
	if node.RetryPolicy != nil {
		prevExecutions, err := a.execQueries.GetNodeExecutions(ctx, node.ID.String())
		if err != nil {
			return nil, fmt.Errorf("failed to get previous executions: %w", err)
		}

		if len(prevExecutions) >= node.RetryPolicy.MaxRetries {
			return nil, fmt.Errorf("max retries (%d) exceeded for node %s", node.RetryPolicy.MaxRetries, node.ID)
		}
	}

	// If modifications are provided, apply them first
	if len(decision.Modifications) > 0 {
		mergedConfig := make(map[string]interface{})
		for k, v := range node.TaskConfig {
			mergedConfig[k] = v
		}
		for k, v := range decision.Modifications {
			mergedConfig[k] = v
		}

		if err := a.updateNodeConfig(ctx, node.ID, mergedConfig); err != nil {
			return nil, fmt.Errorf("failed to update node config: %w", err)
		}

		node.TaskConfig = mergedConfig
	}

	// Reset node status to ready for retry
	if err := a.updateNodeStatus(ctx, node.ID, schema.MissionNodeStatusReady); err != nil {
		return nil, fmt.Errorf("failed to reset node status: %w", err)
	}

	// Execute the agent
	execDecision := &Decision{
		Reasoning:    fmt.Sprintf("Retry attempt: %s", decision.Reasoning),
		Action:       ActionExecuteAgent,
		TargetNodeID: decision.TargetNodeID,
		Confidence:   decision.Confidence,
	}

	return a.executeAgent(ctx, execDecision, missionID)
}

// spawnAgent creates a new mission node dynamically and optionally executes it.
// This allows the orchestrator to adapt the mission at runtime.
func (a *Actor) spawnAgent(ctx context.Context, decision *Decision, missionID types.ID) (*ActionResult, error) {
	if decision.SpawnConfig == nil {
		return nil, fmt.Errorf("spawn_config is required for spawn_agent action")
	}

	// Validate agent exists in inventory before creating node
	if a.inventory != nil {
		validator := NewInventoryValidator(a.inventory)
		if err := validator.ValidateSpawnAgent(decision); err != nil {
			// Return validation error - don't create the mission node
			return &ActionResult{
				Action:       ActionSpawnAgent,
				Error:        err,
				IsTerminal:   false,
				TargetNodeID: "",
			}, nil // Return nil error - this is a validation failure, not a system error
		}
	}

	cfg := decision.SpawnConfig

	// Create new mission node
	nodeID := types.NewID()
	node := schema.NewAgentNode(
		nodeID,
		missionID,
		cfg.AgentName,
		cfg.Description,
		cfg.AgentName,
	)
	node.MarkDynamic("orchestrator") // Mark as dynamically spawned
	node.WithTaskConfig(cfg.TaskConfig)
	node.WithStatus(schema.MissionNodeStatusReady)

	// Create node in graph
	if err := a.createMissionNode(ctx, node); err != nil {
		return nil, fmt.Errorf("failed to create mission node: %w", err)
	}

	// Create dependencies if specified
	if len(cfg.DependsOn) > 0 {
		if err := a.createNodeDependencies(ctx, nodeID, cfg.DependsOn); err != nil {
			return nil, fmt.Errorf("failed to create node dependencies: %w", err)
		}
	}

	// Link to mission
	if err := a.linkNodeToMission(ctx, missionID, nodeID); err != nil {
		return nil, fmt.Errorf("failed to link node to mission: %w", err)
	}

	return &ActionResult{
		Action:       ActionSpawnAgent,
		NewNode:      node,
		Error:        nil,
		IsTerminal:   false,
		TargetNodeID: nodeID.String(),
		Metadata: map[string]interface{}{
			"agent_name":  cfg.AgentName,
			"description": cfg.Description,
			"depends_on":  cfg.DependsOn,
		},
	}, nil
}

// completeMission marks the mission as complete and returns a terminal result.
// This stops the orchestration loop.
func (a *Actor) completeMission(ctx context.Context, decision *Decision, missionID types.ID) (*ActionResult, error) {
	// Update mission status in graph
	cypher := `
		MATCH (m:Mission {id: $mission_id})
		SET m.status = 'completed',
			m.completed_at = datetime()
		RETURN m.id as id
	`

	params := map[string]interface{}{
		"mission_id": missionID.String(),
	}

	result, err := a.graphClient.Query(ctx, cypher, params)
	if err != nil {
		return nil, fmt.Errorf("failed to update mission status: %w", err)
	}

	if len(result.Records) == 0 {
		return nil, fmt.Errorf("mission %s not found", missionID)
	}

	return &ActionResult{
		Action:     ActionComplete,
		Error:      nil,
		IsTerminal: true,
		Metadata: map[string]interface{}{
			"stop_reason": decision.StopReason,
			"confidence":  decision.Confidence,
		},
	}, nil
}

// getMissionNode retrieves a mission node by ID from the graph.
func (a *Actor) getMissionNode(ctx context.Context, nodeID string) (*schema.MissionNode, error) {
	cypher := `
		MATCH (n:MissionNode {id: $node_id})
		RETURN n
	`

	params := map[string]interface{}{
		"node_id": nodeID,
	}

	result, err := a.graphClient.Query(ctx, cypher, params)
	if err != nil {
		return nil, fmt.Errorf("failed to query mission node: %w", err)
	}

	if len(result.Records) == 0 {
		return nil, fmt.Errorf("mission node %s not found", nodeID)
	}

	nodeData := result.Records[0]["n"]
	if nodeData == nil {
		return nil, fmt.Errorf("mission node data is nil")
	}

	// Handle different return types from Neo4j driver
	var dataMap map[string]any
	switch n := nodeData.(type) {
	case dbtype.Node:
		dataMap = n.Props
	case map[string]any:
		dataMap = n
	default:
		return nil, fmt.Errorf("invalid node data format: got %T", nodeData)
	}

	return a.parseMissionNode(dataMap)
}

// updateNodeStatus updates the status of a mission node in the graph.
func (a *Actor) updateNodeStatus(ctx context.Context, nodeID types.ID, status schema.MissionNodeStatus) error {
	cypher := `
		MATCH (n:MissionNode {id: $node_id})
		SET n.status = $status,
			n.updated_at = datetime()
		RETURN n.id as id
	`

	params := map[string]interface{}{
		"node_id": nodeID.String(),
		"status":  string(status),
	}

	result, err := a.graphClient.Query(ctx, cypher, params)
	if err != nil {
		return fmt.Errorf("failed to update node status: %w", err)
	}

	if len(result.Records) == 0 {
		return fmt.Errorf("node %s not found", nodeID)
	}

	return nil
}

// updateDependentNodesToReady marks nodes as "ready" if all their dependencies are completed.
// This should be called after a node completes to propagate readiness through the DAG.
func (a *Actor) updateDependentNodesToReady(ctx context.Context, completedNodeID types.ID) error {
	// Find all nodes that depend on the completed node and check if all their dependencies are satisfied
	// A node becomes ready if:
	// 1. It is currently "pending"
	// 2. All nodes it DEPENDS_ON are "completed"
	cypher := `
		MATCH (completed:MissionNode {id: $completed_node_id})
		MATCH (dependent:MissionNode)-[:DEPENDS_ON]->(completed)
		WHERE dependent.status = 'pending'
		WITH dependent
		OPTIONAL MATCH (dependent)-[:DEPENDS_ON]->(dep:MissionNode)
		WITH dependent, collect(dep) as dependencies
		WHERE ALL(d IN dependencies WHERE d.status = 'completed')
		SET dependent.status = 'ready', dependent.updated_at = datetime()
		RETURN dependent.id as id, dependent.name as name
	`

	params := map[string]interface{}{
		"completed_node_id": completedNodeID.String(),
	}

	result, err := a.graphClient.Query(ctx, cypher, params)
	if err != nil {
		return fmt.Errorf("failed to update dependent nodes: %w", err)
	}

	// Log which nodes were marked as ready
	for _, record := range result.Records {
		if id, ok := record["id"].(string); ok {
			name := record["name"]
			slog.Info("marked dependent node as ready",
				"node_id", id,
				"node_name", name,
				"triggered_by", completedNodeID.String(),
			)
		}
	}

	return nil
}

// updateNodeConfig updates the task configuration of a mission node in the graph.
func (a *Actor) updateNodeConfig(ctx context.Context, nodeID types.ID, config map[string]interface{}) error {
	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	cypher := `
		MATCH (n:MissionNode {id: $node_id})
		SET n.task_config = $config,
			n.updated_at = datetime()
		RETURN n.id as id
	`

	params := map[string]interface{}{
		"node_id": nodeID.String(),
		"config":  string(configJSON),
	}

	result, err := a.graphClient.Query(ctx, cypher, params)
	if err != nil {
		return fmt.Errorf("failed to update node config: %w", err)
	}

	if len(result.Records) == 0 {
		return fmt.Errorf("node %s not found", nodeID)
	}

	return nil
}

// createMissionNode creates a new mission node in the graph.
func (a *Actor) createMissionNode(ctx context.Context, node *schema.MissionNode) error {
	if err := node.Validate(); err != nil {
		return fmt.Errorf("invalid mission node: %w", err)
	}

	configJSON, err := node.TaskConfigJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal task config: %w", err)
	}

	retryPolicyJSON, err := node.RetryPolicyJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal retry policy: %w", err)
	}

	cypher := `
		CREATE (n:MissionNode)
		SET n.id = $id,
			n.mission_id = $mission_id,
			n.type = $type,
			n.name = $name,
			n.description = $description,
			n.agent_name = $agent_name,
			n.tool_name = $tool_name,
			n.timeout = $timeout,
			n.retry_policy = $retry_policy,
			n.task_config = $task_config,
			n.status = $status,
			n.is_dynamic = $is_dynamic,
			n.spawned_by = $spawned_by,
			n.created_at = datetime(),
			n.updated_at = datetime()
		RETURN n.id as id
	`

	params := map[string]interface{}{
		"id":           node.ID.String(),
		"mission_id":   node.MissionID.String(),
		"type":         string(node.Type),
		"name":         node.Name,
		"description":  node.Description,
		"agent_name":   node.AgentName,
		"tool_name":    node.ToolName,
		"timeout":      node.Timeout.Milliseconds(),
		"retry_policy": retryPolicyJSON,
		"task_config":  configJSON,
		"status":       string(node.Status),
		"is_dynamic":   node.IsDynamic,
		"spawned_by":   node.SpawnedBy,
	}

	result, err := a.graphClient.Query(ctx, cypher, params)
	if err != nil {
		return fmt.Errorf("failed to create mission node: %w", err)
	}

	if len(result.Records) == 0 {
		return fmt.Errorf("failed to create mission node")
	}

	return nil
}

// createNodeDependencies creates DEPENDS_ON relationships between nodes.
func (a *Actor) createNodeDependencies(ctx context.Context, nodeID types.ID, dependsOn []string) error {
	if len(dependsOn) == 0 {
		return nil
	}

	cypher := `
		MATCH (n:MissionNode {id: $node_id})
		WITH n
		UNWIND $depends_on as dep_id
		MATCH (dep:MissionNode {id: dep_id})
		MERGE (n)-[:DEPENDS_ON]->(dep)
		RETURN count(*) as count
	`

	params := map[string]interface{}{
		"node_id":    nodeID.String(),
		"depends_on": dependsOn,
	}

	result, err := a.graphClient.Query(ctx, cypher, params)
	if err != nil {
		return fmt.Errorf("failed to create dependencies: %w", err)
	}

	if len(result.Records) == 0 {
		return fmt.Errorf("failed to create dependencies")
	}

	return nil
}

// linkNodeToMission creates a PART_OF relationship from node to mission.
func (a *Actor) linkNodeToMission(ctx context.Context, missionID, nodeID types.ID) error {
	cypher := `
		MATCH (m:Mission {id: $mission_id})
		MATCH (n:MissionNode {id: $node_id})
		MERGE (n)-[:PART_OF]->(m)
		RETURN count(*) as count
	`

	params := map[string]interface{}{
		"mission_id": missionID.String(),
		"node_id":    nodeID.String(),
	}

	result, err := a.graphClient.Query(ctx, cypher, params)
	if err != nil {
		return fmt.Errorf("failed to link node to mission: %w", err)
	}

	if len(result.Records) == 0 {
		return fmt.Errorf("failed to link node to mission")
	}

	return nil
}

// parseMissionNode converts a Neo4j result map to a MissionNode struct.
func (a *Actor) parseMissionNode(data map[string]interface{}) (*schema.MissionNode, error) {
	id, err := types.ParseID(data["id"].(string))
	if err != nil {
		return nil, fmt.Errorf("invalid node ID: %w", err)
	}

	missionID, err := types.ParseID(data["mission_id"].(string))
	if err != nil {
		return nil, fmt.Errorf("invalid mission ID: %w", err)
	}

	node := &schema.MissionNode{
		ID:          id,
		MissionID:   missionID,
		Type:        schema.MissionNodeType(data["type"].(string)),
		Name:        data["name"].(string),
		Description: data["description"].(string),
		Status:      schema.MissionNodeStatus(data["status"].(string)),
		IsDynamic:   data["is_dynamic"].(bool),
		TaskConfig:  make(map[string]interface{}),
	}

	// Optional fields
	if agentName, ok := data["agent_name"].(string); ok && agentName != "" {
		node.AgentName = agentName
	}
	if toolName, ok := data["tool_name"].(string); ok && toolName != "" {
		node.ToolName = toolName
	}
	if spawnedBy, ok := data["spawned_by"].(string); ok && spawnedBy != "" {
		node.SpawnedBy = spawnedBy
	}
	if timeout, ok := data["timeout"].(int64); ok && timeout > 0 {
		node.Timeout = time.Duration(timeout) * time.Millisecond
	}
	if createdAt, ok := data["created_at"].(time.Time); ok {
		node.CreatedAt = createdAt
	}
	if updatedAt, ok := data["updated_at"].(time.Time); ok {
		node.UpdatedAt = updatedAt
	}

	// Parse JSON fields
	if taskConfigStr, ok := data["task_config"].(string); ok && taskConfigStr != "" && taskConfigStr != "{}" {
		if err := json.Unmarshal([]byte(taskConfigStr), &node.TaskConfig); err != nil {
			return nil, fmt.Errorf("failed to unmarshal task_config: %w", err)
		}
	}

	if retryPolicyStr, ok := data["retry_policy"].(string); ok && retryPolicyStr != "" && retryPolicyStr != "{}" {
		var retryPolicy schema.RetryPolicy
		if err := json.Unmarshal([]byte(retryPolicyStr), &retryPolicy); err != nil {
			return nil, fmt.Errorf("failed to unmarshal retry_policy: %w", err)
		}
		node.RetryPolicy = &retryPolicy
	}

	return node, nil
}

// requestApproval pauses execution and waits for human approval before executing the target node.
// This implements human-in-the-loop missions for sensitive operations.
func (a *Actor) requestApproval(ctx context.Context, decision *Decision, missionID types.ID) (*ActionResult, error) {
	// Check if approval manager is configured
	if a.approvalManager == nil {
		return nil, fmt.Errorf("approval manager not configured, cannot process request_approval action")
	}

	// Parse approval timeout duration (default to 24h if not specified)
	timeout := 24 * time.Hour
	if decision.ApprovalTimeout != "" {
		parsedTimeout, err := time.ParseDuration(decision.ApprovalTimeout)
		if err != nil {
			return nil, fmt.Errorf("invalid approval_timeout format: %w", err)
		}
		timeout = parsedTimeout
	}

	// Default timeout action to "reject" if not specified
	timeoutAction := decision.TimeoutAction
	if timeoutAction == "" {
		timeoutAction = "reject"
	}

	// Create approval request
	approvalReq := ApprovalRequest{
		MissionID:     missionID.String(),
		NodeID:        decision.TargetNodeID,
		Context:       decision.ApprovalContext,
		Timeout:       timeout,
		TimeoutAction: timeoutAction,
	}

	// Spec 4 R5.1, R5.2, R5.3 — synchronously checkpoint the approval-paused
	// mission state BEFORE persisting the approval request, so a daemon
	// restart between checkpoint write and approval-store write cannot leave
	// the mission "almost-paused-for-approval" without a recovery anchor.
	// Checkpoint failure is treated as fatal here: callers MUST surface the
	// error rather than proceed with an unsynchronized approval.
	if a.checkpointHook != nil {
		approvalState := &ExecutionState{
			CurrentNodeID: decision.TargetNodeID,
			Metadata: map[string]any{
				"mission_id":     missionID.String(),
				"approval_phase": "request_pending",
				"approval_node":  decision.TargetNodeID,
			},
		}
		if _, cpErr := a.checkpointHook.OnApprovalRequired(ctx, approvalState, decision.TargetNodeID, approvalReq); cpErr != nil {
			return nil, fmt.Errorf("approval-pause checkpoint failed (refusing to persist approval request without durable state): %w", cpErr)
		}
	}

	approvalID, err := a.approvalManager.CreateRequest(ctx, approvalReq)
	if err != nil {
		return nil, fmt.Errorf("failed to create approval request: %w", err)
	}

	a.logger.Info("approval request created, waiting for response",
		"approval_id", approvalID,
		"node_id", decision.TargetNodeID,
		"timeout", timeout.String(),
		"timeout_action", timeoutAction,
	)

	// Wait for approval response
	response, err := a.approvalManager.WaitForApproval(ctx, approvalID, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed waiting for approval: %w", err)
	}

	a.logger.Info("approval response received",
		"approval_id", approvalID,
		"approved", response.Approved,
		"responded_by", response.RespondedBy,
	)

	// Handle approval response
	if response.Approved {
		// Approval granted - execute the target node
		execDecision := &Decision{
			Reasoning:    fmt.Sprintf("Executing approved node: %s", decision.Reasoning),
			Action:       ActionExecuteAgent,
			TargetNodeID: decision.TargetNodeID,
			Confidence:   decision.Confidence,
		}
		return a.executeAgent(ctx, execDecision, missionID)
	}

	// Approval rejected or timed out - skip the node
	node, err := a.getMissionNode(ctx, decision.TargetNodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get mission node: %w", err)
	}

	skipReason := "approval_rejected"
	if response.RespondedBy == "timeout" {
		skipReason = fmt.Sprintf("approval_timeout_%s", timeoutAction)
	}

	if err := a.updateNodeStatus(ctx, node.ID, schema.MissionNodeStatusSkipped); err != nil {
		return nil, fmt.Errorf("failed to update node status to skipped: %w", err)
	}

	return &ActionResult{
		Action:       ActionRequestApproval,
		Error:        nil,
		IsTerminal:   false,
		TargetNodeID: decision.TargetNodeID,
		Metadata: map[string]interface{}{
			"approval_id":  approvalID,
			"approved":     false,
			"skip_reason":  skipReason,
			"responded_by": response.RespondedBy,
			"comment":      response.Comment,
		},
	}, nil
}

// abort immediately stops the mission due to a safety violation or critical error.
// This is a terminal action that marks the mission as aborted and optionally triggers cleanup.
func (a *Actor) abort(ctx context.Context, decision *Decision, missionID types.ID) (*ActionResult, error) {
	a.logger.Warn("aborting mission",
		"mission_id", missionID.String(),
		"reason", decision.AbortReason,
		"severity", decision.AbortSeverity,
		"cleanup_required", decision.CleanupRequired,
	)

	// Update mission status to aborted in Neo4j
	cypher := `
		MATCH (m:Mission {id: $mission_id})
		SET m.status = 'aborted',
		    m.aborted_at = datetime(),
		    m.abort_reason = $abort_reason,
		    m.abort_severity = $abort_severity
		RETURN m.id as id, m.status as status
	`

	params := map[string]interface{}{
		"mission_id":     missionID.String(),
		"abort_reason":   decision.AbortReason,
		"abort_severity": decision.AbortSeverity,
	}

	result, err := a.graphClient.Query(ctx, cypher, params)
	if err != nil {
		// Log error but don't fail - abort should be fail-safe
		a.logger.Error("failed to update mission status to aborted",
			"error", err,
			"mission_id", missionID.String(),
		)
	} else if len(result.Records) == 0 {
		a.logger.Error("mission not found during abort",
			"mission_id", missionID.String(),
		)
	}

	// Emit cleanup required event if requested
	if decision.CleanupRequired {
		// EventCleanupRequired should be defined in events package
		// For now, we'll emit a custom event
		a.logger.Info("cleanup required after mission abort",
			"mission_id", missionID.String(),
		)
	}

	// Emit mission aborted event
	// EventMissionAborted should be defined in events package
	a.logger.Info("mission aborted",
		"mission_id", missionID.String(),
		"reason", decision.AbortReason,
		"severity", decision.AbortSeverity,
	)

	return &ActionResult{
		Action:     ActionAbort,
		Error:      nil,
		IsTerminal: true,
		Metadata: map[string]interface{}{
			"abort_reason":     decision.AbortReason,
			"abort_severity":   decision.AbortSeverity,
			"cleanup_required": decision.CleanupRequired,
		},
	}, nil
}

// escalate formally escalates to a human or specialist agent.
// For critical escalations to humans, this blocks until acknowledged.
// For senior_agent or specialist escalations, it spawns the appropriate agent.
func (a *Actor) escalate(ctx context.Context, decision *Decision, missionID types.ID) (*ActionResult, error) {
	// Check if escalation manager is configured
	if a.escalationManager == nil {
		return nil, fmt.Errorf("escalation manager not configured, cannot process escalate action")
	}

	// Create escalation
	escalation := Escalation{
		MissionID: missionID.String(),
		NodeID:    decision.TargetNodeID,
		Level:     decision.EscalationLevel,
		Urgency:   decision.EscalationUrgency,
		Context:   decision.EscalationContext,
	}

	escalationID, err := a.escalationManager.CreateEscalation(ctx, escalation)
	if err != nil {
		return nil, fmt.Errorf("failed to create escalation: %w", err)
	}

	a.logger.Info("escalation created",
		"escalation_id", escalationID,
		"level", decision.EscalationLevel,
		"urgency", decision.EscalationUrgency,
		"node_id", decision.TargetNodeID,
	)

	// Handle different escalation levels
	if decision.EscalationLevel == "human" && decision.EscalationUrgency == "critical" {
		// Block and wait for acknowledgment for critical human escalations
		a.logger.Info("waiting for critical escalation acknowledgment",
			"escalation_id", escalationID,
		)

		// Wait with a reasonable timeout (e.g., 1 hour for critical)
		waitTimeout := 1 * time.Hour
		if err := a.escalationManager.WaitForAcknowledgment(ctx, escalationID, waitTimeout); err != nil {
			a.logger.Warn("escalation acknowledgment timed out or failed",
				"escalation_id", escalationID,
				"error", err,
			)
			// Don't fail the escalation, just log the timeout
		} else {
			a.logger.Info("critical escalation acknowledged",
				"escalation_id", escalationID,
			)
		}
	} else if decision.EscalationLevel == "senior_agent" || decision.EscalationLevel == "specialist" {
		// For agent-level escalations, consider spawning an agent
		// This is similar to spawn_agent but with escalation metadata
		a.logger.Info("escalation to agent level - consider spawning specialist",
			"escalation_id", escalationID,
			"level", decision.EscalationLevel,
		)

		// Spawn agent with escalation metadata
		if err := a.spawnAgentWithEscalation(ctx, decision, missionID, escalation); err != nil {
			a.logger.Error("failed to spawn escalated agent",
				"escalation_id", escalationID,
				"error", err,
			)
			// Don't fail the escalation - the notification was delivered
		}
	}

	return &ActionResult{
		Action:       ActionEscalate,
		Error:        nil,
		IsTerminal:   false,
		TargetNodeID: decision.TargetNodeID,
		Metadata: map[string]interface{}{
			"escalation_id": escalationID,
			"level":         decision.EscalationLevel,
			"urgency":       decision.EscalationUrgency,
		},
	}, nil
}

// rollback reverts the mission to a previously captured checkpoint state.
// This resets node statuses and marks rolled-back executions as "rolled_back".
func (a *Actor) rollback(ctx context.Context, decision *Decision, missionID types.ID) (*ActionResult, error) {
	// Validate that checkpoint manager is configured
	if a.checkpointManager == nil {
		return nil, fmt.Errorf("checkpoint manager not configured, cannot process rollback action")
	}

	var checkpointID string
	var err error

	// Determine which checkpoint to restore
	if decision.CheckpointID != "" {
		// Explicit checkpoint ID provided
		checkpointID = decision.CheckpointID
		a.logger.Info("rolling back to explicit checkpoint",
			"checkpoint_id", checkpointID,
			"mission_id", missionID.String(),
		)
	} else if decision.RollbackToNode != "" {
		// Find the implicit checkpoint before the specified node
		a.logger.Info("rolling back to before node",
			"node_id", decision.RollbackToNode,
			"mission_id", missionID.String(),
		)

		// Query for the implicit checkpoint that was created BEFORE this node
		cypher := `
			MATCH (c:Checkpoint)-[:BEFORE_NODE]->(n:MissionNode {id: $node_id})
			WHERE c.mission_id = $mission_id AND c.is_implicit = true
			RETURN c.id as checkpoint_id
			ORDER BY c.created_at DESC
			LIMIT 1
		`

		params := map[string]interface{}{
			"node_id":    decision.RollbackToNode,
			"mission_id": missionID.String(),
		}

		result, err := a.graphClient.Query(ctx, cypher, params)
		if err != nil {
			return nil, fmt.Errorf("failed to find implicit checkpoint for node: %w", err)
		}

		if len(result.Records) == 0 {
			return nil, fmt.Errorf("no implicit checkpoint found before node %s", decision.RollbackToNode)
		}

		checkpointID, _ = result.Records[0]["checkpoint_id"].(string)
		a.logger.Info("found implicit checkpoint",
			"checkpoint_id", checkpointID,
			"node_id", decision.RollbackToNode,
		)
	} else {
		return nil, fmt.Errorf("either checkpoint_id or rollback_to_node must be specified for rollback action")
	}

	// Emit rollback started event
	// Note: EventRollbackStarted should be emitted here if eventBus is available
	a.logger.Info("starting rollback",
		"checkpoint_id", checkpointID,
		"mission_id", missionID.String(),
	)

	// Restore the checkpoint
	if err = a.checkpointManager.RestoreCheckpoint(ctx, checkpointID); err != nil {
		return nil, fmt.Errorf("failed to restore checkpoint: %w", err)
	}

	// Note: EventRollbackCompleted is emitted by CheckpointManager.RestoreCheckpoint

	return &ActionResult{
		Action:     ActionRollback,
		Error:      nil,
		IsTerminal: false,
		Metadata: map[string]interface{}{
			"checkpoint_id":       checkpointID,
			"rollback_to_node":    decision.RollbackToNode,
			"checkpoint_restored": true,
		},
	}, nil
}

// reflect performs a self-evaluation of the current mission strategy using the reflection engine.
// This does not count against the iteration limit and provides insights for future decisions.
func (a *Actor) reflect(ctx context.Context, decision *Decision, missionID types.ID) (*ActionResult, error) {
	// Validate that reflection engine is configured
	if a.reflectionEngine == nil {
		return nil, fmt.Errorf("reflection engine not configured, cannot process reflect action")
	}

	a.logger.Info("initiating reflection",
		"scope", decision.ReflectionScope,
		"mission_id", missionID.String(),
		"has_prompt", decision.ReflectionPrompt != "",
	)

	// Build a minimal observation state for the reflection engine.
	// The engine requires a non-nil state to emit events and construct prompts.
	// We populate what is cheaply available: mission identity, graph summary
	// from recent stats, and the component inventory if already loaded.
	// Failures in these queries are non-fatal: we degrade gracefully to empty fields.
	state := &ObservationState{
		ObservedAt: time.Now(),
		MissionInfo: MissionInfo{
			ID: missionID.String(),
		},
		ComponentInventory: a.inventory,
	}

	if a.missionQueries != nil {
		if mission, err := a.missionQueries.GetMission(ctx, missionID); err == nil && mission != nil {
			state.MissionInfo.Name = mission.Name
			state.MissionInfo.Objective = mission.Objective
			state.MissionInfo.Status = mission.Status.String()
			if mission.StartedAt != nil {
				state.MissionInfo.StartedAt = *mission.StartedAt
				state.MissionInfo.TimeElapsed = time.Since(*mission.StartedAt).Truncate(time.Second).String()
			}
		}

		if stats, err := a.missionQueries.GetMissionStats(ctx, missionID); err == nil && stats != nil {
			state.GraphSummary = GraphSummary{
				TotalNodes:      stats.TotalNodes,
				CompletedNodes:  stats.CompletedNodes,
				FailedNodes:     stats.FailedNodes,
				PendingNodes:    stats.PendingNodes,
				TotalDecisions:  stats.TotalDecisions,
				TotalExecutions: stats.TotalExecutions,
			}
		}

		// Include the most recent decisions for context, bounded to last 10 items.
		const maxRecentDecisions = 10
		if decisions, err := a.missionQueries.GetMissionDecisions(ctx, missionID); err == nil {
			start := 0
			if len(decisions) > maxRecentDecisions {
				start = len(decisions) - maxRecentDecisions
			}
			for _, d := range decisions[start:] {
				state.RecentDecisions = append(state.RecentDecisions, DecisionSummary{
					Iteration:  d.Iteration,
					Action:     string(d.Action),
					Target:     d.TargetNodeID,
					Reasoning:  d.Reasoning,
					Confidence: d.Confidence,
					Timestamp:  d.Timestamp.Format(time.RFC3339),
				})
			}
		}
	}

	// Parse reflection scope
	scope := ReflectionScope(decision.ReflectionScope)
	if decision.ReflectionScope == "" {
		scope = ReflectionScopeMission // Default to mission scope
	}

	// Call reflection engine
	result, err := a.reflectionEngine.Reflect(ctx, scope, decision.ReflectionPrompt, state)
	if err != nil {
		a.logger.Error("reflection failed",
			"error", err,
			"scope", decision.ReflectionScope,
			"mission_id", missionID.String(),
		)
		return nil, fmt.Errorf("reflection failed: %w", err)
	}

	a.logger.Info("reflection completed",
		"scope", decision.ReflectionScope,
		"issues_count", len(result.IssuesIdentified),
		"suggestions_count", len(result.SuggestedChanges),
		"confidence", result.ConfidenceInApproach,
		"tokens_used", result.TokensUsed,
	)

	// Note: Reflection events are emitted by the ReflectionEngine itself

	return &ActionResult{
		Action:     ActionReflect,
		Error:      nil,
		IsTerminal: false,
		Metadata: map[string]interface{}{
			"scope":                                  decision.ReflectionScope,
			"assessment":                             result.Assessment,
			"issues_count":                           len(result.IssuesIdentified),
			"suggestions_count":                      len(result.SuggestedChanges),
			"confidence_in_approach":                 result.ConfidenceInApproach,
			"tokens_used":                            result.TokensUsed,
			"does_not_count_against_iteration_limit": true,
		},
	}, nil
}

// recall queries memory tiers for relevant context and optionally injects it into future observations.
// This does not count against the iteration limit.
func (a *Actor) recall(ctx context.Context, decision *Decision, missionID types.ID) (*ActionResult, error) {
	// Validate that memory recaller is configured
	if a.memoryRecaller == nil {
		return nil, fmt.Errorf("memory recaller not configured, cannot process recall action")
	}

	a.logger.Info("initiating memory recall",
		"query", decision.RecallQuery,
		"memory_tier", decision.RecallMemoryTier,
		"mission_id", missionID.String(),
		"inject_into_context", decision.InjectIntoContext,
	)

	// Build RecallQuery from decision fields
	query := RecallQuery{
		Query:      decision.RecallQuery,
		MemoryTier: decision.RecallMemoryTier,
		MissionID:  missionID.String(),
		Filters:    decision.RecallFilters,
		MaxResults: 10, // Default max results
	}

	// Call memory recaller
	result, err := a.memoryRecaller.Recall(ctx, query)
	if err != nil {
		a.logger.Error("memory recall failed",
			"error", err,
			"query", decision.RecallQuery,
			"mission_id", missionID.String(),
		)
		return nil, fmt.Errorf("memory recall failed: %w", err)
	}

	totalResults := len(result.MissionResults) + len(result.LongTermResults)

	a.logger.Info("memory recall completed",
		"query", decision.RecallQuery,
		"memory_tier", decision.RecallMemoryTier,
		"mission_results", len(result.MissionResults),
		"long_term_results", len(result.LongTermResults),
		"total_results", totalResults,
		"query_time_ms", result.QueryTimeMs,
	)

	// Note: Recall events are emitted by the MemoryRecaller itself

	// If InjectIntoContext is true, store the formatted context for the next observation
	// For now, we return it in metadata. In a full implementation, we would store it
	// in the Actor or in a shared context that the Observer can access.
	// This is a simplified approach - the spec suggests:
	// "If InjectIntoContext is true, store the FormattedContext somewhere for the next observation
	//  (could add a field to Actor or return in ActionResult metadata)"
	metadata := map[string]interface{}{
		"query":                                  decision.RecallQuery,
		"memory_tier":                            decision.RecallMemoryTier,
		"mission_results_count":                  len(result.MissionResults),
		"long_term_results_count":                len(result.LongTermResults),
		"total_results":                          totalResults,
		"query_time_ms":                          result.QueryTimeMs,
		"inject_into_context":                    decision.InjectIntoContext,
		"does_not_count_against_iteration_limit": true,
	}

	if decision.InjectIntoContext {
		metadata["formatted_context"] = result.FormattedContext
	}

	return &ActionResult{
		Action:     ActionRecall,
		Error:      nil,
		IsTerminal: false,
		Metadata:   metadata,
	}, nil
}

// processAgentDiscovery processes DiscoveryResult from an agent's output and stores it in Neo4j.
// This enables downstream agents to query discovered hosts, ports, services, etc.
//
// The output can be:
// - *graphragpb.DiscoveryResult directly
// - map[string]any (when deserialized from gRPC TypedValue)
//
// This method is non-blocking and errors are logged but not propagated.
func (a *Actor) processAgentDiscovery(ctx context.Context, output any, agentName string, agentRunID string, missionID types.ID, missionRunID string) {
	a.logger.Info("processAgentDiscovery called",
		"agent_name", agentName,
		"has_discovery_processor", a.discoveryProcessor != nil,
		"has_output", output != nil,
		"output_type", fmt.Sprintf("%T", output),
	)

	if a.discoveryProcessor == nil {
		a.logger.Warn("discoveryProcessor is nil, skipping discovery processing")
		return // No processor configured
	}

	if output == nil {
		a.logger.Debug("output is nil, skipping discovery processing")
		return // No output to process
	}

	// Try to extract DiscoveryResult from output
	var discovery *graphragpb.DiscoveryResult

	switch v := output.(type) {
	case *graphragpb.DiscoveryResult:
		discovery = v
		a.logger.Info("received direct DiscoveryResult from agent output",
			"agent_name", agentName,
			"hosts", len(discovery.Hosts),
			"ports", len(discovery.Ports),
		)
	case map[string]any:
		// Output is a map (deserialized from gRPC TypedValue) - try to convert to DiscoveryResult
		// Log the map keys for debugging
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		a.logger.Info("processing agent output map for discovery data",
			"agent_name", agentName,
			"output_keys", keys,
			"output_type", fmt.Sprintf("%T", output),
		)

		// Check if the map looks like a DiscoveryResult by checking for expected fields
		if _, hasHosts := v["hosts"]; hasHosts {
			// Convert map to JSON, then unmarshal into DiscoveryResult proto
			jsonBytes, err := json.Marshal(v)
			if err != nil {
				a.logger.Debug("failed to marshal output map to JSON",
					"error", err,
					"agent_name", agentName,
				)
				return
			}

			discovery = &graphragpb.DiscoveryResult{}
			unmarshaler := protojson.UnmarshalOptions{
				DiscardUnknown: true,
			}
			if err := unmarshaler.Unmarshal(jsonBytes, discovery); err != nil {
				a.logger.Debug("failed to unmarshal output to DiscoveryResult",
					"error", err,
					"agent_name", agentName,
				)
				return
			}

			a.logger.Debug("converted map output to DiscoveryResult",
				"agent_name", agentName,
				"hosts", len(discovery.Hosts),
				"ports", len(discovery.Ports),
			)
		} else if _, hasPorts := v["ports"]; hasPorts {
			// Also check for ports field (some outputs may only have ports)
			jsonBytes, err := json.Marshal(v)
			if err != nil {
				return
			}
			discovery = &graphragpb.DiscoveryResult{}
			unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}
			if err := unmarshaler.Unmarshal(jsonBytes, discovery); err != nil {
				return
			}
		} else {
			// Map doesn't look like a DiscoveryResult
			a.logger.Debug("map output does not contain hosts or ports fields, skipping discovery processing",
				"agent_name", agentName,
				"keys", keys,
			)
			return
		}
	default:
		// Output is not a DiscoveryResult or convertible map, nothing to process
		a.logger.Debug("output is not DiscoveryResult or map, skipping discovery processing",
			"agent_name", agentName,
			"output_type", fmt.Sprintf("%T", output),
		)
		return
	}

	if discovery == nil {
		return
	}

	// Check if discovery has any data
	nodeCount := len(discovery.Hosts) + len(discovery.Ports) + len(discovery.Services) +
		len(discovery.Endpoints) + len(discovery.Domains) + len(discovery.Subdomains) +
		len(discovery.Technologies) + len(discovery.Certificates) + len(discovery.Findings) +
		len(discovery.Evidence) + len(discovery.CustomNodes)

	if nodeCount == 0 {
		return // Empty discovery
	}

	// Log warning if missionRunID is not provided
	if missionRunID == "" {
		a.logger.Warn("missionRunID not provided, discovery relationships will not be scoped to mission run",
			"agent_name", agentName,
			"mission_id", missionID.String(),
		)
	}

	a.logger.Info("processing discovery result from agent output",
		"agent_name", agentName,
		"mission_id", missionID.String(),
		"mission_run_id", missionRunID,
		"node_count", nodeCount,
		"hosts", len(discovery.Hosts),
		"ports", len(discovery.Ports),
		"services", len(discovery.Services),
		"endpoints", len(discovery.Endpoints),
	)

	// Process discovery asynchronously with timeout
	go func() {
		processCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		nodesCreated, err := a.discoveryProcessor.ProcessAgentDiscovery(processCtx, missionID.String(), missionRunID, agentName, agentRunID, discovery)
		if err != nil {
			a.logger.Error("failed to process agent discovery result",
				"error", err,
				"agent_name", agentName,
				"mission_id", missionID.String(),
				"mission_run_id", missionRunID,
			)
		} else {
			a.logger.Info("successfully stored agent discovery result",
				"agent_name", agentName,
				"mission_id", missionID.String(),
				"mission_run_id", missionRunID,
				"nodes_created", nodesCreated,
			)
		}
	}()
}

// spawnAgentWithEscalation spawns a specialized agent with escalation metadata.
// This is used when escalation level is "senior_agent" or "specialist".
func (a *Actor) spawnAgentWithEscalation(ctx context.Context, decision *Decision, missionID types.ID, escalation Escalation) error {
	// Determine which agent to spawn based on escalation level and context
	agentName := ""
	taskConfig := make(map[string]interface{})

	switch decision.EscalationLevel {
	case "senior_agent":
		// Spawn a more capable version of the current agent or a supervisor agent
		agentName = "orchestrator-supervisor"
		taskConfig["escalation_context"] = decision.EscalationContext
		taskConfig["escalation_level"] = decision.EscalationLevel
		taskConfig["escalation_urgency"] = decision.EscalationUrgency

	case "specialist":
		// Spawn a domain-specific expert agent based on context
		// Parse context to determine specialist type
		agentName = "security-specialist"
		taskConfig["escalation_context"] = decision.EscalationContext
		taskConfig["specialist_domain"] = "security"

	default:
		return fmt.Errorf("unsupported agent escalation level: %s", decision.EscalationLevel)
	}

	// Create spawn config
	spawnConfig := &SpawnNodeConfig{
		AgentName:   agentName,
		Description: fmt.Sprintf("Escalated agent for: %s", decision.EscalationContext),
		TaskConfig:  taskConfig,
		DependsOn:   []string{}, // No dependencies - run immediately
	}

	// Create spawn decision
	spawnDecision := &Decision{
		Reasoning:   fmt.Sprintf("Spawning escalated agent due to: %s", decision.EscalationContext),
		Action:      ActionSpawnAgent,
		SpawnConfig: spawnConfig,
		Confidence:  decision.Confidence,
	}

	// Spawn the agent
	_, err := a.spawnAgent(ctx, spawnDecision, missionID)
	return err
}

// EscalationMetadata contains privilege escalation context for agent spawning.
// This metadata is passed to spawned agents to provide escalation context.
type EscalationMetadata struct {
	// Level is the privilege level (0=normal, 1=elevated, 2=admin)
	Level int `json:"level"`

	// Reason explains why escalation is needed
	Reason string `json:"reason"`

	// ParentAgent is the agent that requested escalation
	ParentAgent string `json:"parent_agent"`

	// Scope limits what the escalated agent can access
	Scope []string `json:"scope"`

	// Timeout is how long escalation is valid
	Timeout time.Duration `json:"timeout"`

	// AuditTrail tracks escalation chain
	AuditTrail []EscalationEvent `json:"audit_trail"`
}

// EscalationEvent represents a single event in the escalation audit trail.
type EscalationEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Agent     string    `json:"agent"`
	Action    string    `json:"action"`
	Level     int       `json:"level"`
}

// validateEscalation validates an escalation request before processing.
// This checks level, permissions, and scope constraints.
func (a *Actor) validateEscalation(ctx context.Context, meta *EscalationMetadata) error {
	if meta == nil {
		return fmt.Errorf("escalation metadata is nil")
	}

	// Validate level
	if meta.Level < 0 || meta.Level > 2 {
		return fmt.Errorf("invalid escalation level: %d (must be 0-2)", meta.Level)
	}

	// Validate reason is provided
	if meta.Reason == "" {
		return fmt.Errorf("escalation reason is required")
	}

	// Validate timeout
	if meta.Timeout <= 0 {
		return fmt.Errorf("escalation timeout must be positive")
	}

	// Validate scope is not empty for elevated privileges
	if meta.Level > 0 && len(meta.Scope) == 0 {
		return fmt.Errorf("scope is required for elevated escalation")
	}

	return nil
}

// buildObservationState constructs an ObservationState for LLM reflection.
// This provides context about the current mission state for decision making.
func (a *Actor) buildObservationState(ctx context.Context, missionID types.ID) *ObservationState {
	state := &ObservationState{
		MissionInfo: MissionInfo{
			ID: missionID.String(),
		},
		GraphSummary:        GraphSummary{},
		ReadyNodes:          []NodeSummary{},
		RunningNodes:        []NodeSummary{},
		CompletedNodes:      []CompletedNodeSummary{},
		FailedNodes:         []NodeSummary{},
		RecentDecisions:     []DecisionSummary{},
		ResourceConstraints: ResourceConstraints{},
		ObservedAt:          time.Now(),
	}

	// Query mission info from Neo4j
	if a.missionQueries != nil {
		mission, err := a.missionQueries.GetMission(ctx, missionID)
		if err == nil && mission != nil {
			state.MissionInfo.Name = mission.Name
			state.MissionInfo.Objective = mission.Objective
			state.MissionInfo.Status = string(mission.Status)
			if mission.StartedAt != nil {
				state.MissionInfo.StartedAt = *mission.StartedAt
				state.MissionInfo.TimeElapsed = time.Since(*mission.StartedAt).String()
			}
		}
	}

	// Query mission nodes and build execution history
	if a.execQueries != nil {
		// Get all mission nodes for this mission
		cypher := `
			MATCH (n:MissionNode)-[:PART_OF]->(m:Mission {id: $mission_id})
			RETURN n.id as node_id,
			       n.name as name,
			       n.type as type,
			       n.status as status,
			       n.agent_name as agent_name
			ORDER BY n.created_at
			LIMIT 100
		`
		params := map[string]interface{}{
			"mission_id": missionID.String(),
		}

		result, err := a.graphClient.Query(ctx, cypher, params)
		if err == nil {
			for _, record := range result.Records {
				nodeID, _ := record["node_id"].(string)
				name, _ := record["name"].(string)
				nodeType, _ := record["type"].(string)
				status, _ := record["status"].(string)
				agentName, _ := record["agent_name"].(string)

				summary := NodeSummary{
					ID:        nodeID,
					Name:      name,
					Type:      nodeType,
					Status:    status,
					AgentName: agentName,
				}

				// Categorize by status
				switch status {
				case "ready":
					state.ReadyNodes = append(state.ReadyNodes, summary)
				case "running":
					state.RunningNodes = append(state.RunningNodes, summary)
				case "completed":
					state.CompletedNodes = append(state.CompletedNodes, CompletedNodeSummary{
						NodeSummary: summary,
					})
				case "failed":
					state.FailedNodes = append(state.FailedNodes, summary)
				}

				state.GraphSummary.TotalNodes++
			}
		}
	}

	// Calculate progress
	if state.GraphSummary.TotalNodes > 0 {
		state.GraphSummary.CompletedNodes = len(state.CompletedNodes)
		state.GraphSummary.FailedNodes = len(state.FailedNodes)
	}

	return state
}

// NodeExecution represents a completed node execution for observation state.
type NodeExecution struct {
	NodeID     string        `json:"node_id"`
	AgentName  string        `json:"agent_name"`
	Status     string        `json:"status"`
	Duration   time.Duration `json:"duration"`
	OutputKeys []string      `json:"output_keys"`
	ErrorBrief string        `json:"error_brief,omitempty"`
}

// FindingSummary represents a security finding for observation state.
type FindingSummary struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	Title    string `json:"title"`
}

// ErrorSummary represents an error that occurred during execution.
type ErrorSummary struct {
	NodeID    string    `json:"node_id"`
	Timestamp time.Time `json:"timestamp"`
	Message   string    `json:"message"`
	Retryable bool      `json:"retryable"`
}

// ResourceMetrics tracks resource consumption for observation state.
type ResourceMetrics struct {
	CPUUsage    float64 `json:"cpu_usage,omitempty"`
	MemoryUsage int64   `json:"memory_usage,omitempty"`
	NetworkIO   int64   `json:"network_io,omitempty"`
}

// decodeSlotOverrides converts the raw "__llm_slots" TaskConfig value into a
// map suitable for agent.Task.SlotOverrides. It handles two wire forms:
//
//   - In-memory (bootstrap → first dispatch, no Neo4j round-trip):
//     []map[string]string{{"slot":…,"provider":…,"model":…}, …}
//
//   - Post-Neo4j (JSON round-trip via json.Unmarshal into map[string]any):
//     []interface{} where each element is map[string]interface{} with string vals.
//
// Returns nil when rawSlots does not match either form or has no valid entries.
// Spec: per-node-slot-override (gibson#539).
func decodeSlotOverrides(rawSlots any) map[string]*agent.SlotConfig {
	// Helper that extracts string values from a single entry regardless of form.
	extractEntry := func(v any) (slot, provider, model string, ok bool) {
		switch e := v.(type) {
		case map[string]string:
			slot = e["slot"]
			provider = e["provider"]
			model = e["model"]
		case map[string]any:
			slot, _ = e["slot"].(string)
			provider, _ = e["provider"].(string)
			model, _ = e["model"].(string)
		default:
			return "", "", "", false
		}
		if slot == "" || provider == "" {
			return "", "", "", false
		}
		return slot, provider, model, true
	}

	switch entries := rawSlots.(type) {
	case []map[string]string:
		if len(entries) == 0 {
			return nil
		}
		overrides := make(map[string]*agent.SlotConfig, len(entries))
		for _, e := range entries {
			if slot, provider, model, ok := extractEntry(e); ok {
				overrides[slot] = &agent.SlotConfig{Provider: provider, Model: model}
			}
		}
		if len(overrides) == 0 {
			return nil
		}
		return overrides

	case []any:
		if len(entries) == 0 {
			return nil
		}
		overrides := make(map[string]*agent.SlotConfig, len(entries))
		for _, raw := range entries {
			if slot, provider, model, ok := extractEntry(raw); ok {
				overrides[slot] = &agent.SlotConfig{Provider: provider, Model: model}
			}
		}
		if len(overrides) == 0 {
			return nil
		}
		return overrides
	}

	return nil
}
