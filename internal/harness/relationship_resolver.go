// Package harness provides the RelationshipResolver for centralized relationship creation.
//
// The RelationshipResolver handles all relationship creation in the GraphRAG system,
// consolidating logic that was previously scattered across multiple files. It supports
// three categories of relationships:
//
//   - Asset Parent Relationships: HAS_PORT, RUNS_SERVICE, HAS_ENDPOINT, etc.
//     These link child nodes to their parent nodes in the asset hierarchy.
//
//   - Execution Relationships: DISCOVERED, BELONGS_TO
//     These link execution context (agent runs) to discovered assets.
//
//   - Structural Relationships: PART_OF, EXECUTES, PRODUCED
//     These define the mission/execution structure.
//
// All relationships use MERGE semantics for idempotency.
package harness

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/zeroroot-ai/gibson/internal/graphrag/graph"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
	"github.com/zeroroot-ai/sdk/graphrag/taxonomy"
)

// isExecutionNodeType returns true if the node type represents a runtime
// activity (not a discovered asset). Used to skip DISCOVERED and BELONGS_TO
// relationship creation for execution-chain nodes.
//
// This replaces the removed taxonomy.IsExecutionNodeType — the classification
// is derived from the "meta" and "execution" categories in core.yaml.
func isExecutionNodeType(nodeType string) bool {
	switch nodeType {
	case sdkgraphrag.NodeTypeMission,
		sdkgraphrag.NodeTypeMissionRun,
		sdkgraphrag.NodeTypeAgentRun,
		sdkgraphrag.NodeTypeToolExecution,
		sdkgraphrag.NodeTypeLlmCall,
		sdkgraphrag.NodeTypeComplianceSignal:
		return true
	default:
		return false
	}
}

// structuralRelationships is the closed vocabulary of relationship types
// that CreateStructuralRelationship validates against. Sourced from the
// generated RelType* constants in the SDK.
var structuralRelationships = map[string]bool{
	sdkgraphrag.RelTypeUSEDTOOL:          true,
	sdkgraphrag.RelTypeDELEGATEDTO:       true,
	sdkgraphrag.RelTypeEMITTEDSIGNAL:     true,
	sdkgraphrag.RelTypeTRIGGERED:         true,
	sdkgraphrag.RelTypeHASSUBDOMAIN:      true,
	sdkgraphrag.RelTypeRESOLVESTO:        true,
	sdkgraphrag.RelTypeHASPORT:           true,
	sdkgraphrag.RelTypeRUNSSERVICE:       true,
	sdkgraphrag.RelTypeHASENDPOINT:       true,
	sdkgraphrag.RelTypeUSESTECHNOLOGY:    true,
	sdkgraphrag.RelTypeSERVESCERTIFICATE: true,
	sdkgraphrag.RelTypeAFFECTS:           true,
	sdkgraphrag.RelTypeHASEVIDENCE:       true,
	sdkgraphrag.RelTypeUSESTECHNIQUE:     true,
	sdkgraphrag.RelTypeLEADSTO:           true,
}

func isValidStructuralRelationship(relType string) bool {
	return structuralRelationships[relType]
}

func allowedStructuralRelationships() []string {
	out := make([]string, 0, len(structuralRelationships))
	for r := range structuralRelationships {
		out = append(out, r)
	}
	return out
}

// RelationshipResolver handles all relationship creation in the GraphRAG system.
// It consolidates relationship logic that was previously scattered across multiple files
// into a single, taxonomy-driven system.
//
// Thread-safety: RelationshipResolver is safe for concurrent use.
type RelationshipResolver struct {
	graphClient graph.GraphClient
}

// RelationshipAction records what relationship was created.
// Used for tracking and debugging relationship creation.
type RelationshipAction struct {
	// FromID is the ID of the source node
	FromID string
	// ToID is the ID of the target node
	ToID string
	// RelType is the relationship type (e.g., "HAS_PORT", "DISCOVERED")
	RelType string
	// Source indicates how the relationship was determined
	// Values: "explicit" (from _parent_* props), "taxonomy" (from ParentRelationships),
	//         "context" (from agent_run_id/mission_run_id), "structural" (explicit call)
	Source string
}

// ResolutionResult contains the outcome of relationship resolution.
type ResolutionResult struct {
	// Actions contains all relationship actions that were executed
	Actions []RelationshipAction
	// Errors contains any errors that occurred during resolution
	Errors []error
}

// HasErrors returns true if any errors occurred during resolution.
func (r *ResolutionResult) HasErrors() bool {
	return len(r.Errors) > 0
}

// Error returns a combined error message, or nil if no errors.
func (r *ResolutionResult) Error() error {
	if !r.HasErrors() {
		return nil
	}
	msgs := make([]string, len(r.Errors))
	for i, err := range r.Errors {
		msgs[i] = err.Error()
	}
	return fmt.Errorf("relationship resolution errors: %s", strings.Join(msgs, "; "))
}

// NewRelationshipResolver creates a new RelationshipResolver.
//
// Parameters:
//   - graphClient: The graph client for executing Cypher queries
func NewRelationshipResolver(graphClient graph.GraphClient) *RelationshipResolver {
	return &RelationshipResolver{
		graphClient: graphClient,
	}
}

// ResolveAndCreate determines what relationships a node needs and creates them.
// This is the main entry point for relationship creation.
//
// It handles:
//   - Asset parent relationships (HAS_PORT, RUNS_SERVICE, etc.) for non-root nodes
//   - DISCOVERED relationships from agent execution (if agent_run_id in context)
//   - BELONGS_TO relationships for root nodes (if mission_run_id in context)
//
// All relationship creation failures are collected, not returned immediately.
// The node storage should still succeed even if some relationships fail.
//
// Parameters:
//   - ctx: Context containing agent_run_id and mission_run_id
//   - node: The node that was stored
//   - nodeID: The ID of the stored node
//
// Returns:
//   - ResolutionResult containing all actions and errors
func (r *RelationshipResolver) ResolveAndCreate(ctx context.Context, node sdkgraphrag.GraphNode, nodeID string) *ResolutionResult {
	result := &ResolutionResult{
		Actions: make([]RelationshipAction, 0),
		Errors:  make([]error, 0),
	}

	nodeType := strings.ToLower(node.Type)

	// 1. Create asset parent relationship (for non-root nodes)
	if !taxonomy.IsRootNodeType(nodeType) {
		if err := r.CreateAssetParentRelationship(ctx, node, nodeID); err != nil {
			slog.Warn("asset parent relationship failed",
				"node_type", nodeType,
				"node_id", nodeID,
				"error", err)
			result.Errors = append(result.Errors, fmt.Errorf("asset parent: %w", err))
		} else {
			result.Actions = append(result.Actions, RelationshipAction{
				FromID:  "parent",
				ToID:    nodeID,
				RelType: "PARENT",
				Source:  "taxonomy",
			})
		}
	}

	// 2. Create DISCOVERED relationship (for non-execution nodes with agent_run_id)
	if !isExecutionNodeType(nodeType) {
		if err := r.CreateDiscoveredRelationship(ctx, nodeID, nodeType); err != nil {
			// Only log at debug level - missing agent_run_id is common and expected
			slog.Debug("discovered relationship skipped or failed",
				"node_type", nodeType,
				"node_id", nodeID,
				"error", err)
			// Don't add to errors - this is expected in many flows
		} else {
			agentRunID := AgentRunIDFromContext(ctx)
			if agentRunID != "" {
				result.Actions = append(result.Actions, RelationshipAction{
					FromID:  agentRunID,
					ToID:    nodeID,
					RelType: "DISCOVERED",
					Source:  "context",
				})
			}
		}
	}

	// 3. Create BELONGS_TO relationship (for root nodes with mission_run_id)
	if taxonomy.IsRootNodeType(nodeType) && !isExecutionNodeType(nodeType) {
		if err := r.CreateBelongsToRelationship(ctx, nodeID, nodeType); err != nil {
			slog.Debug("belongs_to relationship skipped or failed",
				"node_type", nodeType,
				"node_id", nodeID,
				"error", err)
			// Don't add to errors - missing mission_run_id is expected in some flows
		} else {
			missionRunID := MissionRunIDFromContext(ctx)
			if missionRunID != "" {
				result.Actions = append(result.Actions, RelationshipAction{
					FromID:  nodeID,
					ToID:    missionRunID,
					RelType: "BELONGS_TO",
					Source:  "context",
				})
			}
		}
	}

	if len(result.Actions) > 0 {
		slog.Debug("relationships resolved",
			"node_type", nodeType,
			"node_id", nodeID,
			"actions_count", len(result.Actions),
			"errors_count", len(result.Errors))
	}

	return result
}

// CreateAssetParentRelationship creates a parent relationship for an asset node.
// It first checks for explicit parent info in _parent_* properties, then falls
// back to taxonomy lookup.
//
// Resolution priority:
//  1. Explicit: _parent_id, _parent_type, _parent_relationship properties
//  2. Taxonomy: Look up ParentRelationship by node type
//
// Parent lookup:
//   - If _parent_id is a UUID, find parent by id property
//   - Otherwise, find parent by natural key (e.g., IP address for host)
//   - Always scope by mission_run_id if available
//
// Parameters:
//   - ctx: Context containing mission_run_id for scoping
//   - node: The child node with properties
//   - nodeID: The ID of the child node
func (r *RelationshipResolver) CreateAssetParentRelationship(ctx context.Context, node sdkgraphrag.GraphNode, nodeID string) error {
	nodeType := strings.ToLower(node.Type)

	// Check for explicit parent info in properties
	parentID, hasExplicitID := node.Properties["_parent_id"].(string)
	parentType, hasExplicitType := node.Properties["_parent_type"].(string)
	parentRel, hasExplicitRel := node.Properties["_parent_relationship"].(string)

	// If explicit parent info is provided, use it
	if hasExplicitID && parentID != "" {
		if !hasExplicitType || parentType == "" {
			// Try to infer from taxonomy
			if rel := taxonomy.GetParentRelationship(nodeType); rel != nil {
				parentType = rel.ParentType
			}
		}
		if !hasExplicitRel || parentRel == "" {
			// Try to infer from taxonomy
			if rel := taxonomy.GetParentRelationship(nodeType); rel != nil {
				parentRel = rel.Relationship
			}
		}

		if parentType != "" && parentRel != "" {
			return r.createParentRelationshipByID(ctx, nodeID, nodeType, parentID, parentType, parentRel)
		}
	}

	// Fall back to taxonomy lookup
	rel := taxonomy.GetParentRelationship(nodeType)
	if rel == nil {
		// This is a root type or unknown type - no parent relationship needed
		return nil
	}

	// Look for the reference field in properties (e.g., host_id, port_id)
	refValue, hasRef := node.Properties[rel.RefField]
	if !hasRef || refValue == nil {
		if rel.Required {
			return fmt.Errorf("required parent reference field %q not found for %s", rel.RefField, nodeType)
		}
		// Optional parent not provided
		return nil
	}

	refStr, ok := refValue.(string)
	if !ok {
		return fmt.Errorf("parent reference field %q is not a string", rel.RefField)
	}

	return r.createParentRelationshipByID(ctx, nodeID, nodeType, refStr, rel.ParentType, rel.Relationship)
}

// createParentRelationshipByID creates a parent relationship using the parent ID.
// It attempts to find the parent by UUID first, then by natural key.
func (r *RelationshipResolver) createParentRelationshipByID(ctx context.Context, childID, childType, parentID, parentType, relType string) error {
	// Determine if parentID is a UUID or a natural key
	isUUID := false
	if _, err := uuid.Parse(parentID); err == nil {
		isUUID = true
	}

	missionRunID := MissionRunIDFromContext(ctx)

	var cypher string
	params := map[string]any{
		"child_id":  childID,
		"parent_id": parentID,
	}

	if isUUID {
		// Parent ID is a UUID - match by id property
		cypher = fmt.Sprintf(`
			MATCH (child {id: $child_id})
			MATCH (parent:%s {id: $parent_id})
			MERGE (parent)-[r:%s]->(child)
			RETURN parent.id as parent_id
		`, parentType, relType)
	} else {
		// Parent ID is a natural key (e.g., IP address, hostname)
		// Determine which property to match on based on parent type
		matchProp := r.getNaturalKeyProperty(parentType)

		if missionRunID != "" {
			// Scope by mission_run_id
			cypher = fmt.Sprintf(`
				MATCH (child {id: $child_id})
				MATCH (parent:%s {%s: $parent_id, mission_run_id: $mission_run_id})
				MERGE (parent)-[r:%s]->(child)
				RETURN parent.id as parent_id
			`, parentType, matchProp, relType)
			params["mission_run_id"] = missionRunID
		} else {
			cypher = fmt.Sprintf(`
				MATCH (child {id: $child_id})
				MATCH (parent:%s {%s: $parent_id})
				MERGE (parent)-[r:%s]->(child)
				RETURN parent.id as parent_id
			`, parentType, matchProp, relType)
		}
	}

	result, err := r.graphClient.Query(ctx, cypher, params)
	if err != nil {
		return fmt.Errorf("failed to create %s relationship: %w", relType, err)
	}

	if len(result.Records) == 0 {
		slog.Warn("parent node not found for relationship",
			"child_id", childID,
			"child_type", childType,
			"parent_id", parentID,
			"parent_type", parentType,
			"rel_type", relType)
		return nil // Don't fail - parent may not exist yet
	}

	slog.Debug("asset parent relationship created",
		"child_id", childID,
		"parent_id", parentID,
		"rel_type", relType)

	return nil
}

// getNaturalKeyProperty returns the property name used as natural key for a node type.
func (r *RelationshipResolver) getNaturalKeyProperty(nodeType string) string {
	switch nodeType {
	case "host":
		return "ip"
	case "domain":
		return "name"
	case "subdomain":
		return "name"
	case "port":
		return "number" // Note: port also needs host context for uniqueness
	case "service":
		return "name"
	case "finding":
		return "title"
	default:
		return "id"
	}
}

// CreateDiscoveredRelationship creates a DISCOVERED relationship from AgentExecution to a node.
// This relationship indicates that an agent discovered an asset during execution.
//
// The relationship is only created if:
//   - agent_run_id is present in context
//   - The node is not an execution node type (mission, agent_run, etc.)
//
// Parameters:
//   - ctx: Context containing agent_run_id
//   - nodeID: The ID of the discovered node
//   - nodeType: The type of the discovered node
func (r *RelationshipResolver) CreateDiscoveredRelationship(ctx context.Context, nodeID, nodeType string) error {
	agentRunID := AgentRunIDFromContext(ctx)
	if agentRunID == "" {
		return nil // No agent run ID - skip silently
	}

	// Don't create DISCOVERED for execution nodes
	if isExecutionNodeType(nodeType) {
		return nil
	}

	cypher := `
		MATCH (node {id: $node_id})
		MERGE (ae:agent_run {id: $agent_run_id})
		MERGE (ae)-[r:DISCOVERED]->(node)
		ON CREATE SET r.discovered_at = timestamp()
		RETURN ae.id as agent_run_id
	`

	params := map[string]any{
		"node_id":      nodeID,
		"agent_run_id": agentRunID,
	}

	_, err := r.graphClient.Query(ctx, cypher, params)
	if err != nil {
		return fmt.Errorf("failed to create DISCOVERED relationship: %w", err)
	}

	slog.Debug("discovered relationship created",
		"agent_run_id", agentRunID,
		"node_id", nodeID,
		"node_type", nodeType)

	return nil
}

// CreateBelongsToRelationship creates a BELONGS_TO relationship from a root node to MissionRun.
// This relationship scopes root assets to a specific mission execution.
//
// The relationship is only created if:
//   - mission_run_id is present in context
//   - The node is a root node type (host, domain, finding, etc.)
//   - The node is not an execution node type
//
// Parameters:
//   - ctx: Context containing mission_run_id
//   - nodeID: The ID of the root node
//   - nodeType: The type of the root node
func (r *RelationshipResolver) CreateBelongsToRelationship(ctx context.Context, nodeID, nodeType string) error {
	missionRunID := MissionRunIDFromContext(ctx)
	if missionRunID == "" {
		return nil // No mission run ID - skip silently
	}

	// Only for root nodes that aren't execution types
	if !taxonomy.IsRootNodeType(nodeType) || isExecutionNodeType(nodeType) {
		return nil
	}

	cypher := `
		MATCH (node {id: $node_id})
		MATCH (mr:mission_run {id: $mission_run_id})
		MERGE (node)-[r:BELONGS_TO]->(mr)
		RETURN mr.id as mission_run_id
	`

	params := map[string]any{
		"node_id":        nodeID,
		"mission_run_id": missionRunID,
	}

	_, err := r.graphClient.Query(ctx, cypher, params)
	if err != nil {
		return fmt.Errorf("failed to create BELONGS_TO relationship: %w", err)
	}

	slog.Debug("belongs_to relationship created",
		"node_id", nodeID,
		"mission_run_id", missionRunID)

	return nil
}

// CreateStructuralRelationship creates a structural relationship (PART_OF, EXECUTES, PRODUCED).
// These relationships are created explicitly when mission/execution nodes are created.
//
// Valid relationship types:
//   - PART_OF: MissionNode → Mission
//   - EXECUTES: AgentExecution → MissionNode
//   - PRODUCED: AgentExecution → Finding
//   - RUN_OF: MissionRun → Mission
//
// Parameters:
//   - ctx: Context for the operation
//   - fromID: The ID of the source node
//   - toID: The ID of the target node
//   - relType: The relationship type (must be valid structural relationship)
func (r *RelationshipResolver) CreateStructuralRelationship(ctx context.Context, fromID, toID, relType string) error {
	// Validate relationship type
	if !isValidStructuralRelationship(relType) {
		return fmt.Errorf("invalid structural relationship type: %s (allowed: %v)",
			relType, allowedStructuralRelationships())
	}

	cypher := fmt.Sprintf(`
		MATCH (from {id: $from_id})
		MATCH (to {id: $to_id})
		MERGE (from)-[r:%s]->(to)
		RETURN from.id as from_id, to.id as to_id
	`, relType)

	params := map[string]any{
		"from_id": fromID,
		"to_id":   toID,
	}

	result, err := r.graphClient.Query(ctx, cypher, params)
	if err != nil {
		return fmt.Errorf("failed to create %s relationship: %w", relType, err)
	}

	if len(result.Records) == 0 {
		slog.Warn("structural relationship nodes not found",
			"from_id", fromID,
			"to_id", toID,
			"rel_type", relType)
		return nil // Don't fail - nodes may not exist yet
	}

	slog.Debug("structural relationship created",
		"from_id", fromID,
		"to_id", toID,
		"rel_type", relType)

	return nil
}
