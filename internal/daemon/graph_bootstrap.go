package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	"github.com/zero-day-ai/gibson/internal/graphrag/queries"
	"github.com/zero-day-ai/gibson/internal/graphrag/schema"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/types"
)

// GraphBootstrapper handles bootstrapping mission data into Neo4j graph.
// It converts mission state from SQLite into graph nodes and relationships
// for semantic querying and graph-based reasoning.
type GraphBootstrapper struct {
	graphClient graph.GraphClient
	logger      *slog.Logger
}

// BootstrapResult contains the results of bootstrapping a mission graph.
type BootstrapResult struct {
	// MissionRunID is the unique ID of the created MissionRun node.
	// This should be used for all subsequent GraphRAG operations in this mission execution.
	MissionRunID string
}

// NewGraphBootstrapper creates a new GraphBootstrapper instance.
// The graph client must be connected before use.
func NewGraphBootstrapper(client graph.GraphClient, logger *slog.Logger) *GraphBootstrapper {
	return &GraphBootstrapper{
		graphClient: client,
		logger:      logger,
	}
}

// convertToSchemaMission converts mission state from SQLite format to graph schema format.
// This performs the data mapping needed to bootstrap mission data into Neo4j.
//
// Parameters:
//   - m: The mission state from SQLite
//   - def: The mission definition containing workflow metadata
//
// Returns a schema.Mission ready for insertion into Neo4j.
func convertToSchemaMission(m *mission.Mission, def *mission.MissionDefinition) *schema.Mission {
	// Extract objective from mission definition description
	// Use first sentence as objective, or full description if no sentence boundary
	objective := def.Description
	if idx := strings.Index(def.Description, "."); idx > 0 {
		objective = strings.TrimSpace(def.Description[:idx+1])
	}

	// Get target reference - prefer metadata value (URL) over TargetID
	targetRef := ""
	if m.Metadata != nil {
		if ref, ok := m.Metadata["target_ref"].(string); ok && ref != "" {
			targetRef = ref
		}
	}
	// Fallback to TargetID as string if no metadata target_ref
	if targetRef == "" && !m.TargetID.IsZero() {
		targetRef = string(m.TargetID)
	}

	// Use WorkflowJSON as YAML source (it contains the original workflow definition)
	yamlSource := m.WorkflowJSON
	if yamlSource == "" {
		yamlSource = "{}" // Empty JSON object as fallback
	}

	// Create new schema mission with core fields
	schemaMission := schema.NewMission(
		m.ID,
		m.Name,
		m.Description,
		objective,
		targetRef,
		yamlSource,
	)

	// Set status to running since bootstrap happens at execution time
	// The mission is being bootstrapped because it's actively executing
	schemaMission.Status = schema.MissionStatusRunning

	// Mark as started and set start timestamp
	// Bootstrap occurs when mission begins execution, so we mark it started
	if m.StartedAt != nil {
		schemaMission.StartedAt = m.StartedAt
	} else {
		// If somehow StartedAt is nil, use current time
		now := time.Now()
		schemaMission.StartedAt = &now
	}

	// If mission is already completed/failed in SQLite, reflect that state
	if m.Status == mission.MissionStatusCompleted {
		schemaMission.MarkCompleted()
		if m.CompletedAt != nil {
			schemaMission.CompletedAt = m.CompletedAt
		}
	} else if m.Status == mission.MissionStatusFailed {
		schemaMission.MarkFailed()
		if m.CompletedAt != nil {
			schemaMission.CompletedAt = m.CompletedAt
		}
	}

	return schemaMission
}

// convertToSchemaNode converts a MissionNode from the workflow definition to a schema.WorkflowNode
// for insertion into the Neo4j graph. This handles the data mapping between mission definitions
// and the graph schema.
//
// Parameters:
//   - missionID: The ID of the parent mission (stable SQLite ID)
//   - nodeDef: The node definition from the mission workflow
//   - hasDependencies: Whether this node has dependencies (determines initial status)
//
// Returns:
//   - *schema.WorkflowNode: A workflow node ready for insertion into Neo4j
//
// The function generates a new unique ID for the node, determines the node type (agent or tool),
// and sets up all execution parameters including timeout, retry policy, and task configuration.
// Nodes with dependencies start in "pending" status, while nodes without dependencies (entry points)
// start in "ready" status.
func convertToSchemaNode(missionID types.ID, nodeDef *mission.MissionNode, hasDependencies bool) *schema.WorkflowNode {
	// Generate a new unique ID for this workflow node instance
	nodeID := types.NewID()

	// Determine the node type and create the appropriate schema node
	var node *schema.WorkflowNode
	switch nodeDef.Type {
	case mission.NodeTypeAgent:
		// Create an agent node with agent name
		node = schema.NewAgentNode(
			nodeID,
			missionID,
			nodeDef.ID, // Use definition ID as the name
			nodeDef.Description,
			nodeDef.AgentName,
		)
	case mission.NodeTypeTool:
		// Create a tool node with tool name
		node = schema.NewToolNode(
			nodeID,
			missionID,
			nodeDef.ID, // Use definition ID as the name
			nodeDef.Description,
			nodeDef.ToolName,
		)
	default:
		// For other node types (plugin, condition, parallel, join), default to tool type
		// These are not currently supported in the graph schema but we'll map them as tools
		// to maintain consistency
		node = schema.NewToolNode(
			nodeID,
			missionID,
			nodeDef.ID,
			nodeDef.Description,
			string(nodeDef.Type), // Use the type name as the tool name
		)
	}

	// Set timeout if specified in the definition
	if nodeDef.Timeout > 0 {
		node.Timeout = nodeDef.Timeout
	}

	// Convert and set retry policy if present
	if nodeDef.RetryPolicy != nil {
		retryPolicy := &schema.RetryPolicy{
			MaxRetries: nodeDef.RetryPolicy.MaxRetries,
			Backoff:    nodeDef.RetryPolicy.InitialDelay,
			Strategy:   string(nodeDef.RetryPolicy.BackoffStrategy),
			MaxBackoff: nodeDef.RetryPolicy.MaxDelay,
		}
		node.RetryPolicy = retryPolicy
	}

	// Set task configuration based on node type
	// For agents, use the full task structure
	// For tools, use the tool input
	// For other types, use metadata or an empty map
	taskConfig := make(map[string]any)
	switch nodeDef.Type {
	case mission.NodeTypeAgent:
		if nodeDef.AgentTask != nil {
			// Convert agent task to map
			taskConfig = nodeDef.AgentTask.Input
			if taskConfig == nil {
				taskConfig = make(map[string]any)
			}
			// Add task metadata
			taskConfig["name"] = nodeDef.AgentTask.Name
			taskConfig["description"] = nodeDef.AgentTask.Description
			taskConfig["goal"] = nodeDef.AgentTask.Goal
			if nodeDef.AgentTask.Context != nil {
				taskConfig["context"] = nodeDef.AgentTask.Context
			}
		}
	case mission.NodeTypeTool:
		if nodeDef.ToolInput != nil {
			taskConfig = nodeDef.ToolInput
		}
	case mission.NodeTypePlugin:
		// For plugins, include method and params
		if nodeDef.PluginParams != nil {
			taskConfig = nodeDef.PluginParams
		}
		taskConfig["plugin_method"] = nodeDef.PluginMethod
	default:
		// For other types, use metadata if available
		if nodeDef.Metadata != nil {
			taskConfig = nodeDef.Metadata
		}
	}
	node.TaskConfig = taskConfig

	// Set initial status based on dependencies
	// Nodes without dependencies are entry points and can start immediately (ready)
	// Nodes with dependencies must wait for their dependencies to complete (pending)
	if hasDependencies {
		node.Status = schema.WorkflowNodeStatusPending
	} else {
		node.Status = schema.WorkflowNodeStatusReady
	}

	// Mark as static workflow node (not dynamically spawned)
	node.IsDynamic = false
	// SpawnedBy is intentionally left empty for static nodes
	// Only dynamic nodes spawned at runtime will have this field set

	return node
}

// Bootstrap creates the complete mission graph structure in Neo4j.
// This includes the Mission node (with full SQLite metadata), MissionRun node,
// all WorkflowNodes, and their dependency relationships.
//
// The method is idempotent for Mission/WorkflowNodes - calling it multiple times is safe.
// However, each call creates a NEW MissionRun node to track individual executions.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - m: The mission state from SQLite (has stable ID across runs)
//   - def: The mission definition containing workflow structure
//   - run: The mission run from SQLite (unique per execution)
//
// Returns:
//   - *BootstrapResult: Contains the MissionRunID for GraphRAG operations
//   - error: Any error encountered during bootstrapping
//
// The bootstrap process follows these steps:
//  1. Create/ensure the Mission node with full SQLite metadata (uses stable SQLite ID)
//  2. Create a new MissionRun node linked to Mission (uses SQLite run ID)
//  3. Create all WorkflowNodes and link them to Mission
//  4. Create dependency relationships between nodes based on DependsOn fields
//
// All operations use MERGE for Mission/WorkflowNodes to ensure idempotency.
// MissionRuns always use CREATE to ensure each execution is tracked uniquely.
func (b *GraphBootstrapper) Bootstrap(ctx context.Context, m *mission.Mission, def *mission.MissionDefinition, run *mission.MissionRun) (*BootstrapResult, error) {
	// Create MissionQueries instance for graph operations
	missionQueries := queries.NewMissionQueries(b.graphClient)

	b.logger.Info("bootstrapping mission to graph",
		"mission_id", m.ID,
		"mission_name", m.Name,
		"target_id", m.TargetID,
		"run_id", run.ID,
		"run_number", run.RunNumber)

	// Step 1: Create/ensure Mission node with full SQLite metadata
	// Uses MERGE on SQLite ID for idempotency - same mission returns same node
	schemaMission := convertToSchemaMission(m, def)
	if err := missionQueries.CreateMission(ctx, schemaMission); err != nil {
		return nil, fmt.Errorf("failed to create mission in graph: %w", err)
	}

	b.logger.Info("created/ensured Mission node in graph",
		"mission_id", m.ID)

	// Step 2: Create a new MissionRun node for this execution
	// Uses SQLite run ID for consistency between SQLite and Neo4j
	if err := missionQueries.CreateMissionRun(ctx, m.ID, run.ID, run.RunNumber); err != nil {
		return nil, fmt.Errorf("failed to create mission run node: %w", err)
	}

	b.logger.Info("created MissionRun node in graph",
		"mission_id", m.ID,
		"mission_run_id", run.ID,
		"run_number", run.RunNumber)

	// Step 3: Create WorkflowNodes and build ID mapping
	// Map YAML node IDs to generated types.IDs for dependency creation
	nodeIDMap := make(map[string]types.ID)

	for _, nodeDef := range def.Nodes {
		// Determine if node has dependencies
		hasDependencies := len(nodeDef.Dependencies) > 0

		// Convert to schema node
		schemaNode := convertToSchemaNode(m.ID, nodeDef, hasDependencies)

		// Create node in graph
		if err := missionQueries.CreateWorkflowNode(ctx, schemaNode); err != nil {
			return nil, fmt.Errorf("failed to create workflow node %s: %w", nodeDef.ID, err)
		}

		// Store mapping for dependency creation
		nodeIDMap[nodeDef.ID] = schemaNode.ID

		b.logger.Debug("created workflow node in graph",
			"node_yaml_id", nodeDef.ID,
			"node_graph_id", schemaNode.ID,
			"node_type", nodeDef.Type)
	}

	b.logger.Info("created workflow nodes in graph",
		"mission_id", m.ID,
		"node_count", len(def.Nodes))

	// Step 4: Create dependency relationships
	dependencyCount := 0
	for _, nodeDef := range def.Nodes {
		// Get the graph ID for this node
		fromNodeID, ok := nodeIDMap[nodeDef.ID]
		if !ok {
			return nil, fmt.Errorf("node ID %s not found in mapping", nodeDef.ID)
		}

		// Create dependency relationships for each dependency
		for _, depID := range nodeDef.Dependencies {
			// Look up the dependency's graph ID
			toNodeID, ok := nodeIDMap[depID]
			if !ok {
				return nil, fmt.Errorf("dependency node ID %s not found in mapping", depID)
			}

			// Create the DEPENDS_ON relationship
			if err := missionQueries.CreateNodeDependency(ctx, fromNodeID, toNodeID); err != nil {
				return nil, fmt.Errorf("failed to create dependency %s->%s: %w", nodeDef.ID, depID, err)
			}

			b.logger.Debug("created dependency relationship",
				"from_yaml_id", nodeDef.ID,
				"to_yaml_id", depID,
				"from_graph_id", fromNodeID,
				"to_graph_id", toNodeID)

			dependencyCount++
		}
	}

	b.logger.Info("created dependency relationships in graph",
		"mission_id", m.ID,
		"dependency_count", dependencyCount)

	b.logger.Info("bootstrap complete",
		"mission_id", m.ID,
		"mission_run_id", run.ID,
		"nodes_created", len(def.Nodes),
		"dependencies_created", dependencyCount)

	return &BootstrapResult{
		MissionRunID: run.ID.String(),
	}, nil
}
