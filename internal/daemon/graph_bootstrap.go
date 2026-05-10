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
	commonpb "github.com/zero-day-ai/sdk/api/gen/gibson/common/v1"
	missionpb "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
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
//   - def: The mission definition containing mission metadata
//
// Returns a schema.Mission ready for insertion into Neo4j.
func convertToSchemaMission(m *mission.Mission, def *missionpb.MissionDefinition) *schema.Mission {
	// Extract objective from mission definition description
	// Use first sentence as objective, or full description if no sentence boundary
	description := def.GetDescription()
	objective := description
	if idx := strings.Index(description, "."); idx > 0 {
		objective = strings.TrimSpace(description[:idx+1])
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

	// Use MissionDefinitionJSON as YAML source (it contains the original mission definition)
	yamlSource := m.MissionDefinitionJSON
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
	if !m.StartedAt.IsNil() {
		schemaMission.StartedAt = m.StartedAt.Time
	} else {
		// If somehow StartedAt is nil, use current time
		now := time.Now()
		schemaMission.StartedAt = &now
	}

	// If mission is already completed/failed in SQLite, reflect that state
	if m.Status == mission.MissionStatusCompleted {
		schemaMission.MarkCompleted()
		if !m.CompletedAt.IsNil() {
			schemaMission.CompletedAt = m.CompletedAt.Time
		}
	} else if m.Status == mission.MissionStatusFailed {
		schemaMission.MarkFailed()
		if !m.CompletedAt.IsNil() {
			schemaMission.CompletedAt = m.CompletedAt.Time
		}
	}

	return schemaMission
}

// convertToSchemaNode converts a MissionNode from the mission definition to a schema.MissionNode
// for insertion into the Neo4j graph. This handles the data mapping between mission definitions
// and the graph schema.
//
// Parameters:
//   - missionID: The ID of the parent mission (stable SQLite ID)
//   - nodeDef: The node definition from the mission
//   - hasDependencies: Whether this node has dependencies (determines initial status)
//
// Returns:
//   - *schema.MissionNode: A mission node ready for insertion into Neo4j
//
// The function generates a new unique ID for the node, determines the node type (agent or tool),
// and sets up all execution parameters including timeout, retry policy, and task configuration.
// Nodes with dependencies start in "pending" status, while nodes without dependencies (entry points)
// start in "ready" status.
func convertToSchemaNode(missionID types.ID, nodeDef *missionpb.MissionNode, hasDependencies bool) *schema.MissionNode {
	// Generate a new unique ID for this mission node instance
	nodeID := types.NewID()

	// Determine the node type and create the appropriate schema node
	var node *schema.MissionNode
	switch nodeDef.GetType() {
	case missionpb.NodeType_NODE_TYPE_AGENT:
		node = schema.NewAgentNode(
			nodeID,
			missionID,
			nodeDef.GetId(),
			nodeDef.GetDescription(),
			nodeDef.GetAgentConfig().GetAgentName(),
		)
	case missionpb.NodeType_NODE_TYPE_TOOL:
		node = schema.NewToolNode(
			nodeID,
			missionID,
			nodeDef.GetId(),
			nodeDef.GetDescription(),
			nodeDef.GetToolConfig().GetToolName(),
		)
	default:
		// For other node types (plugin, condition, parallel, join), default to tool type
		// These are not currently supported in the graph schema but we'll map them as tools
		// to maintain consistency.
		node = schema.NewToolNode(
			nodeID,
			missionID,
			nodeDef.GetId(),
			nodeDef.GetDescription(),
			nodeTypeName(nodeDef.GetType()),
		)
	}

	if t := nodeDef.GetTimeout(); t != nil {
		node.Timeout = t.AsDuration()
	}

	if rp := nodeDef.GetRetryPolicy(); rp != nil {
		retryPolicy := &schema.RetryPolicy{
			MaxRetries: int(rp.GetMaxRetries()),
			Strategy:   backoffStrategyName(rp.GetBackoffStrategy()),
		}
		if d := rp.GetInitialDelay(); d != nil {
			retryPolicy.Backoff = d.AsDuration()
		}
		if d := rp.GetMaxDelay(); d != nil {
			retryPolicy.MaxBackoff = d.AsDuration()
		}
		node.RetryPolicy = retryPolicy
	}

	// Set task configuration based on node type. The proto schema dropped
	// the legacy mirror's per-task Name/Description/Input fields when the
	// canonical types were lifted into the SDK; only Goal and Context
	// survive on the proto Task. Tool/plugin inputs are typed map<string,
	// string> on the proto so values flow through unchanged.
	taskConfig := make(map[string]any)
	switch nodeDef.GetType() {
	case missionpb.NodeType_NODE_TYPE_AGENT:
		if t := nodeDef.GetAgentConfig().GetTask(); t != nil {
			taskConfig["goal"] = t.GetGoal()
			if ctx := t.GetContext(); len(ctx) > 0 {
				taskConfig["context"] = typedValueMapToAnyMap(ctx)
			}
		}
	case missionpb.NodeType_NODE_TYPE_TOOL:
		for k, v := range nodeDef.GetToolConfig().GetInput() {
			taskConfig[k] = v
		}
	case missionpb.NodeType_NODE_TYPE_PLUGIN:
		for k, v := range nodeDef.GetPluginConfig().GetParams() {
			taskConfig[k] = v
		}
		taskConfig["plugin_method"] = nodeDef.GetPluginConfig().GetMethod()
	default:
		for k, v := range nodeDef.GetMetadata() {
			taskConfig[k] = v
		}
	}
	node.TaskConfig = taskConfig

	// Set initial status based on dependencies
	// Nodes without dependencies are entry points and can start immediately (ready)
	// Nodes with dependencies must wait for their dependencies to complete (pending)
	if hasDependencies {
		node.Status = schema.MissionNodeStatusPending
	} else {
		node.Status = schema.MissionNodeStatusReady
	}

	// Mark as static mission node (not dynamically spawned)
	node.IsDynamic = false
	// SpawnedBy is intentionally left empty for static nodes
	// Only dynamic nodes spawned at runtime will have this field set

	return node
}

// Bootstrap creates the complete mission graph structure in Neo4j.
// This includes the Mission node (with full SQLite metadata), MissionRun node,
// all MissionNodes, and their dependency relationships.
//
// The method is idempotent for Mission/MissionNodes - calling it multiple times is safe.
// However, each call creates a NEW MissionRun node to track individual executions.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - m: The mission state from SQLite (has stable ID across runs)
//   - def: The mission definition containing mission structure
//   - run: The mission run from SQLite (unique per execution)
//
// Returns:
//   - *BootstrapResult: Contains the MissionRunID for GraphRAG operations
//   - error: Any error encountered during bootstrapping
//
// The bootstrap process follows these steps:
//  1. Create/ensure the Mission node with full SQLite metadata (uses stable SQLite ID)
//  2. Create a new MissionRun node linked to Mission (uses SQLite run ID)
//  3. Create all MissionNodes and link them to Mission
//  4. Create dependency relationships between nodes based on DependsOn fields
//
// All operations use MERGE for Mission/MissionNodes to ensure idempotency.
// MissionRuns always use CREATE to ensure each execution is tracked uniquely.
func (b *GraphBootstrapper) Bootstrap(ctx context.Context, m *mission.Mission, def *missionpb.MissionDefinition, run *mission.MissionRun) (*BootstrapResult, error) {
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

	// Step 3: Create MissionNodes and build ID mapping
	// Map YAML node IDs to generated types.IDs for dependency creation
	nodeIDMap := make(map[string]types.ID)

	for _, nodeDef := range def.GetNodes() {
		hasDependencies := len(nodeDef.GetDependencies()) > 0

		schemaNode := convertToSchemaNode(m.ID, nodeDef, hasDependencies)

		if err := missionQueries.CreateMissionNode(ctx, schemaNode); err != nil {
			return nil, fmt.Errorf("failed to create mission node %s: %w", nodeDef.GetId(), err)
		}

		nodeIDMap[nodeDef.GetId()] = schemaNode.ID

		b.logger.Debug("created mission node in graph",
			"node_yaml_id", nodeDef.GetId(),
			"node_graph_id", schemaNode.ID,
			"node_type", nodeDef.GetType())
	}

	b.logger.Info("created mission nodes in graph",
		"mission_id", m.ID,
		"node_count", len(def.GetNodes()))

	// Step 4: Create dependency relationships
	dependencyCount := 0
	for _, nodeDef := range def.GetNodes() {
		fromNodeID, ok := nodeIDMap[nodeDef.GetId()]
		if !ok {
			return nil, fmt.Errorf("node ID %s not found in mapping", nodeDef.GetId())
		}

		for _, depID := range nodeDef.GetDependencies() {
			toNodeID, ok := nodeIDMap[depID]
			if !ok {
				return nil, fmt.Errorf("dependency node ID %s not found in mapping", depID)
			}

			if err := missionQueries.CreateNodeDependency(ctx, fromNodeID, toNodeID); err != nil {
				return nil, fmt.Errorf("failed to create dependency %s->%s: %w", nodeDef.GetId(), depID, err)
			}

			b.logger.Debug("created dependency relationship",
				"from_yaml_id", nodeDef.GetId(),
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
		"nodes_created", len(def.GetNodes()),
		"dependencies_created", dependencyCount)

	return &BootstrapResult{
		MissionRunID: run.ID.String(),
	}, nil
}

// nodeTypeName returns a stable lower-case label for a proto NodeType,
// matching the legacy mirror's NodeType string values that downstream
// graph queries used to filter on.
func nodeTypeName(t missionpb.NodeType) string {
	switch t {
	case missionpb.NodeType_NODE_TYPE_AGENT:
		return "agent"
	case missionpb.NodeType_NODE_TYPE_TOOL:
		return "tool"
	case missionpb.NodeType_NODE_TYPE_PLUGIN:
		return "plugin"
	case missionpb.NodeType_NODE_TYPE_CONDITION:
		return "condition"
	case missionpb.NodeType_NODE_TYPE_PARALLEL:
		return "parallel"
	case missionpb.NodeType_NODE_TYPE_JOIN:
		return "join"
	default:
		return "unspecified"
	}
}

// backoffStrategyName returns a stable lower-case label matching the
// mirror's BackoffStrategy string constants ("constant", "linear",
// "exponential") for downstream consumers.
func backoffStrategyName(s missionpb.BackoffStrategy) string {
	switch s {
	case missionpb.BackoffStrategy_BACKOFF_STRATEGY_CONSTANT:
		return "constant"
	case missionpb.BackoffStrategy_BACKOFF_STRATEGY_LINEAR:
		return "linear"
	case missionpb.BackoffStrategy_BACKOFF_STRATEGY_EXPONENTIAL:
		return "exponential"
	default:
		return ""
	}
}

// typedValueMapToAnyMap projects a proto map<string,TypedValue> down to
// a Go-native map[string]any for storage in schema.MissionNode.TaskConfig.
// Only the kinds the orchestrator actually emits are unwrapped; unknown
// kinds fall through to nil rather than crashing.
func typedValueMapToAnyMap(in map[string]*commonpb.TypedValue) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = typedValueToAny(v)
	}
	return out
}

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
	default:
		return nil
	}
}
