// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/queries"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/schema"
	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// GraphBootstrapper handles bootstrapping mission data into Neo4j graph.
// It converts mission state from SQLite into graph nodes and relationships
// for semantic querying and graph-based reasoning.
type GraphBootstrapper struct {
	graphClient graph.GraphClient
	// graphWriter is the sole writer of a :Mission node (ADR-0112). The
	// bootstrap used to MERGE its own, on a different key and a different
	// property name than the projector's; see gibson#551.
	graphWriter GraphWriter
	logger      *slog.Logger
}

// BootstrapResult contains the results of bootstrapping a mission graph.
type BootstrapResult struct {
	// MissionRunID is the unique ID of the created MissionRun node.
	// This should be used for all subsequent GraphRAG operations in this mission execution.
	MissionRunID string
}

// bootstrapNodeLabels and bootstrapRelationshipTypes are the vocabulary the
// per-run graph writes materialize. They are declared here for the same reason
// the projector declares its own (graph_projector_neo4j.go): so the Taxonomy and
// the writer cannot drift apart unnoticed.
//
// The projector's drift check could not cover these. It reads the projector's
// list, and this writer is a different one — which is how MissionNode came to
// be MERGEd on every mission run while sitting outside the Taxonomy, with no
// uniqueness constraint behind the derived identity gibson#528 introduced
// (gibson#550).
var bootstrapNodeLabels = []string{"Mission", "MissionNode", "MissionRun"}

var bootstrapRelationshipTypes = []string{
	"BELONGS_TO", // MissionRun  -> Mission
	"DEPENDS_ON", // MissionNode -> MissionNode
	"PART_OF",    // MissionNode -> Mission
}

// NewGraphBootstrapper creates a new GraphBootstrapper instance.
// The graph client must be connected before use. writer is the graph projector,
// which owns every :Mission write; a nil writer makes Bootstrap fail rather than
// skip, because a run whose Mission node is missing cannot hang its MissionRun
// off anything.
func NewGraphBootstrapper(client graph.GraphClient, writer GraphWriter, logger *slog.Logger) *GraphBootstrapper {
	mustMatchTaxonomy("graph bootstrap", taxonomy.Global, bootstrapNodeLabels, bootstrapRelationshipTypes)
	return &GraphBootstrapper{
		graphClient: client,
		graphWriter: writer,
		logger:      logger,
	}
}

// missionObjective reduces a mission description to its first sentence, the
// node's `objective` property: enough for a graph reader to see what a mission
// was for without fetching the definition. A description with no sentence
// boundary is used whole.
func missionObjective(def *missionpb.MissionDefinition) string {
	description := def.GetDescription()
	if idx := strings.Index(description, "."); idx > 0 {
		return strings.TrimSpace(description[:idx+1])
	}
	return description
}

// missionYAMLSource is the definition the run was projected from, stored on the
// node so a graph reader can see the authored mission. An empty definition
// stores an empty JSON object rather than an empty string, so a reader that
// parses the property never has to special-case "".
func missionYAMLSource(m *mission.Mission) string {
	if m.MissionDefinitionJSON == "" {
		return "{}"
	}
	return m.MissionDefinitionJSON
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
func convertToSchemaNode(
	missionID types.ID,
	nodeDef *missionpb.MissionNode,
	workNodeID string,
	hasDependencies bool,
	origin fanOutOrigin,
	isInstance bool,
) *schema.MissionNode {
	// The node's identity is DERIVED from the mission and the projected work-node
	// id, not minted fresh.
	//
	// It used to be types.NewID() per call, so the MERGE on `id` never matched
	// anything: every run wrote a second :MissionNode for the same step, and a
	// uniqueness constraint on `id` would have covered nothing a reader could
	// use. A derived id is stable across runs and distinct per fan-out instance,
	// because the work-node id carries the target (gibson#528).
	nodeID := missionNodeGraphID(missionID, workNodeID)

	// Determine the node type and create the appropriate schema node
	var node *schema.MissionNode
	switch nodeDef.GetType() {
	case missionpb.NodeType_NODE_TYPE_AGENT:
		node = schema.NewAgentNode(
			nodeID,
			missionID,
			workNodeID,
			nodeDef.GetDescription(),
			nodeDef.GetAgentConfig().GetAgentName(),
		)
	case missionpb.NodeType_NODE_TYPE_TOOL:
		node = schema.NewToolNode(
			nodeID,
			missionID,
			workNodeID,
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
			workNodeID,
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
	node.TaskConfig = taskConfigFor(nodeDef)

	// Set initial status based on dependencies
	// Nodes without dependencies are entry points and can start immediately (ready)
	// Nodes with dependencies must wait for their dependencies to complete (pending)
	if hasDependencies {
		node.Status = schema.MissionNodeStatusPending
	} else {
		node.Status = schema.MissionNodeStatusReady
	}

	// A fan-out instance is a runtime-spawned node, which is exactly what
	// IsDynamic/SpawnedBy already describe — so it goes in that paradigm rather
	// than a new one. SpawnedBy names the for_each that produced it, and the
	// target is the instance's own, not the mission's (gibson#528).
	//
	// Everything else is a static definition node: IsDynamic stays false and
	// SpawnedBy stays empty, as it always has.
	if isInstance {
		node.MarkDynamic(origin.ForEachNodeID).WithTargetID(origin.TargetID)
	}

	return node
}

// missionNodeNamespace seeds the derivation of a :MissionNode's identity. It is a
// fixed, arbitrary UUID: its only job is to keep these derived ids from colliding
// with ids derived elsewhere from the same inputs.
var missionNodeNamespace = uuid.MustParse("6f1b9f9a-6c2a-4a1e-9a5e-2f7a1c3d4b50")

// missionNodeGraphID derives a :MissionNode's identity from the mission and the
// projected work-node id.
//
// Deterministic, so the MERGE on `id` matches the node a previous run wrote
// instead of adding another. A fan-out instance's work-node id carries its
// target, so instances derive distinct ids without the target being mixed in
// separately.
func missionNodeGraphID(missionID types.ID, workNodeID string) types.ID {
	return types.ID(uuid.NewSHA1(missionNodeNamespace, []byte(missionID.String()+"\x00"+workNodeID)).String())
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
//   - def: The mission definition, for the Mission node's own metadata
//   - run: The mission run from SQLite (unique per execution)
//   - proj: the PROJECTED work graph, which is the structure that actually runs
//   - origins: where each fan-out instance came from
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
// The node set comes from the PROJECTION, not from def.GetNodes(). The projection
// is what runs: it expands each for_each into one instance per target, flattens
// parallel sub-nodes, and resolves every dependency through joins and conditions.
// Writing def.GetNodes() instead recorded a graph that did not match the run — one
// node for a whole fan-out, with no target on it, and dependencies that ignored
// `edges`, a join's `wait_for` and a condition's branches because it read only
// each node's own `dependencies` list (gibson#528).
//
// All operations use MERGE for Mission/MissionNodes to ensure idempotency.
// MissionRuns always use CREATE to ensure each execution is tracked uniquely.
func (b *GraphBootstrapper) Bootstrap(
	ctx context.Context,
	tenant string,
	m *mission.Mission,
	def *missionpb.MissionDefinition,
	run *mission.MissionRun,
	proj brain.MissionProjected,
	origins fanOutOrigins,
	targets []forEachTarget,
) (*BootstrapResult, error) {
	// Create MissionQueries instance for graph operations
	missionQueries := queries.NewMissionQueries(b.graphClient)

	b.logger.Info("bootstrapping mission to graph",
		"mission_id", m.ID,
		"mission_name", m.Name,
		"target_id", m.TargetID,
		"run_id", run.ID,
		"run_number", run.RunNumber)

	// Step 1: ask the sole writer to ensure the :Mission node, so the
	// MissionRun below has something to hang off. The write is idempotent and
	// order-independent: the CreateMission RPC fires the same call from a
	// goroutine, and either may land first (gibson#551).
	if b.graphWriter == nil {
		return nil, fmt.Errorf("graph bootstrap: no graph writer — cannot ensure the :Mission node for %s", m.ID)
	}
	var startedAt *time.Time
	if !m.StartedAt.IsNil() {
		startedAt = m.StartedAt.Time
	} else {
		now := time.Now()
		startedAt = &now
	}
	if err := b.graphWriter.UpsertMission(ctx, tenant, MissionProjection{
		ID:          m.ID.String(),
		Name:        m.Name,
		Description: m.Description,
		TargetID:    m.TargetID.String(),
		// The mission is being bootstrapped because it is starting to run.
		Status:     string(mission.MissionStatusRunning),
		Objective:  missionObjective(def),
		YAMLSource: missionYAMLSource(m),
		StartedAt:  startedAt,
	}); err != nil {
		return nil, fmt.Errorf("failed to create mission in graph: %w", err)
	}

	b.logger.Info("created/ensured Mission node in graph",
		"mission_id", m.ID)

	// Step 1b: a :Target node per target the run resolved, each attached to the
	// mission that named it. A Target is a registered entity, not a World one,
	// so the projection tick never produces it and this is where it comes from
	// (gibson#550).
	//
	// The whole resolved set, not just the primary: a fan-out instance names its
	// own target, and a finding carries that target's UUID in Finding.scope, so
	// every target in the set has to exist as a node for the join to work.
	for _, tgt := range targets {
		if tgt.Target == nil {
			continue
		}
		if err := b.graphWriter.UpsertTarget(ctx, tenant, TargetProjection{
			ID:        tgt.ID,
			Name:      tgt.Target.Name,
			Type:      tgt.Target.Type,
			URL:       runTargetRef(tgt.Target),
			Status:    string(tgt.Target.Status),
			MissionID: m.ID.String(),
		}); err != nil {
			return nil, fmt.Errorf("failed to create target %s in graph: %w", tgt.ID, err)
		}
	}

	// Step 2: Create a new MissionRun node for this execution
	// Uses SQLite run ID for consistency between SQLite and Neo4j
	if err := missionQueries.CreateMissionRun(ctx, m.ID, run.ID, run.RunNumber); err != nil {
		return nil, fmt.Errorf("failed to create mission run node: %w", err)
	}

	b.logger.Info("created MissionRun node in graph",
		"mission_id", m.ID,
		"mission_run_id", run.ID,
		"run_number", run.RunNumber)

	// Step 3: Create one MissionNode per PROJECTED work node, and build the id
	// mapping the dependency edges need.
	nodeIDMap := make(map[string]types.ID, len(proj.Nodes))

	for _, wn := range proj.Nodes {
		origin, isInstance := origins[wn.ID]
		// An instance's definition is its for_each's template; every other work
		// node is its own definition node. A node with neither (a parallel
		// sub-node, which the projection promotes) falls back to an empty
		// definition, so the graph still records the node rather than dropping it.
		defNode := definitionNodeFor(def, wn.ID, origin, isInstance)

		schemaNode := convertToSchemaNode(m.ID, defNode, wn.ID, len(wn.DependsOn) > 0, origin, isInstance)

		if err := missionQueries.CreateMissionNode(ctx, schemaNode); err != nil {
			return nil, fmt.Errorf("failed to create mission node %s: %w", wn.ID, err)
		}

		nodeIDMap[wn.ID] = schemaNode.ID

		b.logger.Debug("created mission node in graph",
			"work_node_id", wn.ID,
			"node_graph_id", schemaNode.ID,
			"node_kind", wn.Kind,
			"is_instance", isInstance,
			"target_id", schemaNode.TargetID)
	}

	b.logger.Info("created mission nodes in graph",
		"mission_id", m.ID,
		"node_count", len(proj.Nodes))

	// Step 4: Create dependency relationships, from the projection's resolved
	// DependsOn. A dependency naming a node the projection did not produce is an
	// internal invariant failure, not a user error: the projection resolves every
	// dependency through joins, conditions and parallel groups before it returns.
	dependencyCount := 0
	for _, wn := range proj.Nodes {
		fromNodeID := nodeIDMap[wn.ID]
		for _, depID := range wn.DependsOn {
			toNodeID, ok := nodeIDMap[depID]
			if !ok {
				return nil, fmt.Errorf("projected node %s depends on %s, which the projection did not produce", wn.ID, depID)
			}

			if err := missionQueries.CreateNodeDependency(ctx, fromNodeID, toNodeID); err != nil {
				return nil, fmt.Errorf("failed to create dependency %s->%s: %w", wn.ID, depID, err)
			}

			dependencyCount++
		}
	}

	b.logger.Info("created dependency relationships in graph",
		"mission_id", m.ID,
		"dependency_count", dependencyCount)

	b.logger.Info("bootstrap complete",
		"mission_id", m.ID,
		"mission_run_id", run.ID,
		"nodes_created", len(proj.Nodes),
		"dependencies_created", dependencyCount)

	return &BootstrapResult{
		MissionRunID: run.ID.String(),
	}, nil
}

// taskConfigFor builds the graph node's task_config from the definition node.
//
// Split out of convertToSchemaNode because that function reached a cyclomatic
// complexity of 21 against a limit of 20: it was doing two jobs, mapping the
// node kind and encoding the node config, and this is the second one.
//
// The default branch carries metadata rather than nothing, so a kind the graph
// schema has no type for still records what the author attached to it.
func taskConfigFor(nodeDef *missionpb.MissionNode) map[string]any {
	taskConfig := make(map[string]any)
	switch nodeDef.GetType() {
	case missionpb.NodeType_NODE_TYPE_AGENT:
		if t := nodeDef.GetAgentConfig().GetTask(); t != nil {
			taskConfig["goal"] = t.GetGoal()
			if ctx := t.GetContext(); len(ctx) > 0 {
				taskConfig["context"] = typedValueMapToAnyMap(ctx)
			}
		}
		// Persist per-slot LLM bindings (AgentNodeConfig.llm_slots, field 5)
		// using a sentinel key so executeAgent can rebuild the override map at
		// dispatch time without touching the proto definition again.
		// Each entry is {"slot":…,"provider":…,"model":…}; entries with an
		// empty provider are omitted because they carry no override intent.
		// Spec: per-node-slot-override (gibson#539).
		if slots := nodeDef.GetAgentConfig().GetLlmSlots(); len(slots) > 0 {
			serialized := make([]map[string]string, 0, len(slots))
			for _, s := range slots {
				if s.GetProvider() == "" {
					continue // no override intent — skip
				}
				serialized = append(serialized, map[string]string{
					"slot":     s.GetSlot(),
					"provider": s.GetProvider(),
					"model":    s.GetModel(),
				})
			}
			if len(serialized) > 0 {
				taskConfig["__llm_slots"] = serialized
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
	// Every remaining kind, named rather than defaulted: the linter's
	// `default-signifies-exhaustive: false` means a new NodeType fails the build
	// here instead of landing silently in a default arm, which is the behaviour
	// worth having — a kind whose config this function does not know how to
	// encode should be a review conversation, not a quiet metadata copy.
	case missionpb.NodeType_NODE_TYPE_CONDITION,
		missionpb.NodeType_NODE_TYPE_PARALLEL,
		missionpb.NodeType_NODE_TYPE_JOIN,
		missionpb.NodeType_NODE_TYPE_JOB,
		missionpb.NodeType_NODE_TYPE_FOR_EACH,
		missionpb.NodeType_NODE_TYPE_UNSPECIFIED:
		for k, v := range nodeDef.GetMetadata() {
			taskConfig[k] = v
		}
	}
	return taskConfig
}

// definitionNodeFor returns the definition node a projected work node came from.
//
// A fan-out instance came from its for_each's template, which is the only node
// that holds its description, timeout and retry policy — the instance id names
// the template but the definition map is keyed by the for_each. Everything else
// is keyed by its own id.
//
// A missing entry returns an empty node rather than an error. A parallel
// sub-node is promoted by the projection and is not in def.GetNodes(), and a
// node absent from the graph is worse than a node with thin metadata.
func definitionNodeFor(
	def *missionpb.MissionDefinition,
	workNodeID string,
	origin fanOutOrigin,
	isInstance bool,
) *missionpb.MissionNode {
	if isInstance {
		if fe := def.GetNodes()[origin.ForEachNodeID]; fe != nil {
			if tpl := fe.GetForEachConfig().GetTemplate(); tpl != nil {
				return tpl
			}
		}
		return &missionpb.MissionNode{}
	}
	if n := def.GetNodes()[workNodeID]; n != nil {
		return n
	}
	return &missionpb.MissionNode{}
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
