// Package harness provides the agent execution environment.
package harness

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/zeroroot-ai/gibson/internal/graphrag"
	"github.com/zeroroot-ai/gibson/internal/types"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
)

// GraphRAGQueryBridge provides the query interface for GraphRAG operations.
// It bridges SDK types to internal GraphRAG store operations, enabling agents
// to query the knowledge graph, traverse relationships, and retrieve domain-specific
// data like attack patterns and security findings.
//
// All methods include OpenTelemetry instrumentation for observability.
// GraphRAG is a core requirement - the daemon will fail to start if GraphRAG is not configured.
//
// This is the agent EMIT surface (ECS-brain cutover, ADR-0007). The query/recall
// methods were removed — under ADR-0001 agents do not read the graph back; the
// brain is the sole reader. The store methods persist to Neo4j directly today;
// they are superseded by the World→graph projector (gibson#774) and cut in S4.
type GraphRAGQueryBridge interface {
	// StoreNode stores a single graph node with mission and agent context.
	// Returns the node ID. MissionID and agentName are auto-populated.
	StoreNode(ctx context.Context, node sdkgraphrag.GraphNode, missionID, agentName string) (string, error)

	// CreateRelationship creates a relationship between two nodes.
	CreateRelationship(ctx context.Context, rel sdkgraphrag.Relationship) error

	// StoreBatch stores multiple nodes and relationships in a single operation.
	// Returns node IDs for all created nodes. MissionID and agentName are auto-populated.
	StoreBatch(ctx context.Context, batch sdkgraphrag.Batch, missionID, agentName string) ([]string, error)

	// StoreSemantic stores a node with semantic search capabilities (requires Content).
	// Validates that node.Content is non-empty, then generates embeddings and stores.
	StoreSemantic(ctx context.Context, node sdkgraphrag.GraphNode, missionID, agentName string) (string, error)

	// StoreStructured stores a node without semantic search (no embedding required).
	// Used for structured data like hosts, ports, services.
	StoreStructured(ctx context.Context, node sdkgraphrag.GraphNode, missionID, agentName string) (string, error)

	// Health returns the health status of the GraphRAG bridge.
	Health(ctx context.Context) types.HealthStatus
}

// DefaultGraphRAGQueryBridge is the default implementation of GraphRAGQueryBridge.
// It wraps graphrag.GraphRAGStore and provides type conversion between SDK and internal types.
type DefaultGraphRAGQueryBridge struct {
	store  graphrag.GraphRAGStore
	tracer trace.Tracer
}

// NewGraphRAGQueryBridge creates a new DefaultGraphRAGQueryBridge.
// If store is nil, methods will return ErrGraphRAGNotEnabled.
// If policySource is nil, policy enforcement will be disabled (queries run unfiltered).
func NewGraphRAGQueryBridge(store graphrag.GraphRAGStore) *DefaultGraphRAGQueryBridge {
	return &DefaultGraphRAGQueryBridge{
		store:  store,
		tracer: otel.Tracer("gibson/harness/graphrag_query_bridge"),
	}
}

// StoreNode stores a single graph node.
func (b *DefaultGraphRAGQueryBridge) StoreNode(ctx context.Context, node sdkgraphrag.GraphNode, missionID, agentName string) (string, error) {
	ctx, span := b.tracer.Start(ctx, "GraphRAGQueryBridge.StoreNode",
		trace.WithAttributes(
			attribute.String("node.type", node.Type),
			attribute.String("mission_id", missionID),
			attribute.String("agent_name", agentName),
		))
	defer span.End()

	// Validate node
	if err := node.Validate(); err != nil {
		return "", fmt.Errorf("%w: %v", sdkgraphrag.ErrInvalidQuery, err)
	}

	// Get agent_run_id from context for provenance
	agentRunID := AgentRunIDFromContext(ctx)

	// Get mission_run_id from context for mission-scoped storage
	missionRunID := MissionRunIDFromContext(ctx)

	// Convert SDK node to internal node (with provenance metadata)
	internalNode := sdkNodeToInternal(node, missionID, missionRunID, agentName, agentRunID)

	// Create graph record
	record := graphrag.NewGraphRecord(*internalNode)
	if node.Content != "" {
		record.WithEmbedContent(node.Content)
	}

	// Store node
	if err := b.store.Store(ctx, record); err != nil {
		return "", fmt.Errorf("%w: %v", sdkgraphrag.ErrStorageFailed, err)
	}

	nodeID := internalNode.ID.String()
	span.SetAttributes(attribute.String("node.id", nodeID))

	// Create hierarchy relationships based on reference properties (host_id, port_id, etc)
	b.createHierarchyRelationships(ctx, node, nodeID)

	// Create DISCOVERED relationship from agent_run to this node (if applicable)
	// Skip execution nodes as they are part of the execution chain
	// Note: agentRunID was already retrieved above for provenance
	if agentRunID != "" && !isExecutionNode(node.Type) {
		discoveredRel := sdkgraphrag.Relationship{
			FromID: agentRunID,
			ToID:   nodeID,
			Type:   sdkgraphrag.RelTypeUSEDTOOL,
			Properties: map[string]any{
				"discovered_at":    time.Now().UTC(),
				"discovery_method": agentName,
			},
		}

		// Create the DISCOVERED relationship (log warning on failure but don't fail the operation)
		if err := b.CreateRelationship(ctx, discoveredRel); err != nil {
			// Log warning but don't fail the node creation
			slog.Warn("DISCOVERED relationship creation failed",
				"agent_run_id", agentRunID,
				"node_id", nodeID,
				"node_type", node.Type,
				"error", err.Error())
			span.AddEvent("discovered_relationship_failed",
				trace.WithAttributes(
					attribute.String("agent_run_id", agentRunID),
					attribute.String("error", err.Error()),
				))
		} else {
			slog.Debug("DISCOVERED relationship created",
				"agent_run_id", agentRunID,
				"node_id", nodeID,
				"node_type", node.Type)
			span.AddEvent("discovered_relationship_created",
				trace.WithAttributes(
					attribute.String("agent_run_id", agentRunID),
				))
		}
	}

	return nodeID, nil
}

// CreateRelationship creates a relationship between two nodes.
func (b *DefaultGraphRAGQueryBridge) CreateRelationship(ctx context.Context, rel sdkgraphrag.Relationship) error {
	ctx, span := b.tracer.Start(ctx, "GraphRAGQueryBridge.CreateRelationship",
		trace.WithAttributes(
			attribute.String("relationship.type", rel.Type),
			attribute.String("relationship.from", rel.FromID),
			attribute.String("relationship.to", rel.ToID),
		))
	defer span.End()

	// Validate relationship
	if err := rel.Validate(); err != nil {
		return fmt.Errorf("%w: %v", sdkgraphrag.ErrInvalidQuery, err)
	}

	// Convert SDK relationship to internal relationship (no batch mapping for standalone relationships)
	internalRel, err := sdkRelationshipToInternal(rel, nil)
	if err != nil {
		return fmt.Errorf("relationship conversion failed: %w", err)
	}

	// Store relationship directly via provider (don't create dummy node)
	if err := b.store.StoreRelationshipOnly(ctx, *internalRel); err != nil {
		return fmt.Errorf("%w: %v", sdkgraphrag.ErrRelationshipFailed, err)
	}

	return nil
}

// StoreBatch stores multiple nodes and relationships in a single operation.
func (b *DefaultGraphRAGQueryBridge) StoreBatch(ctx context.Context, batch sdkgraphrag.Batch, missionID, agentName string) ([]string, error) {
	ctx, span := b.tracer.Start(ctx, "GraphRAGQueryBridge.StoreBatch",
		trace.WithAttributes(
			attribute.Int("batch.nodes", len(batch.Nodes)),
			attribute.Int("batch.relationships", len(batch.Relationships)),
			attribute.String("mission_id", missionID),
			attribute.String("agent_name", agentName),
		))
	defer span.End()

	// Convert SDK batch to internal records
	records := make([]*graphrag.GraphRecord, len(batch.Nodes))
	nodeIDs := make([]string, len(batch.Nodes))

	// Get agent_run_id from context for provenance
	agentRunID := AgentRunIDFromContext(ctx)

	// Get mission_run_id from context for mission-scoped storage
	missionRunID := MissionRunIDFromContext(ctx)

	// Build maps for relationship mapping:
	// - nodeIDToIndex: SDK node ID -> record index (for attaching relationships)
	// - sdkIDToInternalID: SDK node ID -> internal UUID string (for ID translation)
	nodeIDToIndex := make(map[string]int, len(batch.Nodes))
	sdkIDToInternalID := make(map[string]types.ID, len(batch.Nodes))

	for i, sdkNode := range batch.Nodes {
		// Validate node
		if err := sdkNode.Validate(); err != nil {
			return nil, fmt.Errorf("%w: node %d validation failed: %v", sdkgraphrag.ErrInvalidQuery, i, err)
		}

		// Convert node (with provenance metadata)
		internalNode := sdkNodeToInternal(sdkNode, missionID, missionRunID, agentName, agentRunID)
		nodeIDs[i] = internalNode.ID.String()

		// Map SDK node ID to record index and internal UUID
		nodeIDToIndex[sdkNode.ID] = i
		nodeIDToIndex[internalNode.ID.String()] = i
		sdkIDToInternalID[sdkNode.ID] = internalNode.ID

		// Create record (take address for pointer receiver methods)
		record := graphrag.NewGraphRecord(*internalNode)
		recordPtr := &record
		if sdkNode.Content != "" {
			recordPtr.WithEmbedContent(sdkNode.Content)
		}
		records[i] = recordPtr
	}

	// Validate all relationships reference valid nodes BEFORE storage (Task 8)
	// Build a map of all node IDs in this batch (both SDK IDs and generated internal IDs)
	batchNodeIDs := make(map[string]bool, len(batch.Nodes)*2)
	for _, node := range batch.Nodes {
		// Add SDK node ID if it exists (may be empty if auto-generated)
		if node.ID != "" {
			batchNodeIDs[node.ID] = true
		}
	}
	// Also add all generated internal IDs
	for sdkID, internalID := range sdkIDToInternalID {
		batchNodeIDs[sdkID] = true
		batchNodeIDs[internalID.String()] = true
	}

	var invalidRels []string
	for i, rel := range batch.Relationships {
		fromExists := batchNodeIDs[rel.FromID]
		toExists := batchNodeIDs[rel.ToID]

		// Check graph if not in batch
		if !fromExists {
			fromExists = b.nodeExistsInGraph(ctx, rel.FromID)
		}
		if !toExists {
			toExists = b.nodeExistsInGraph(ctx, rel.ToID)
		}

		if !fromExists {
			invalidRels = append(invalidRels, fmt.Sprintf(
				"rel[%d] %s: from_id %q not found", i, rel.Type, rel.FromID))
		}
		if !toExists {
			invalidRels = append(invalidRels, fmt.Sprintf(
				"rel[%d] %s: to_id %q not found", i, rel.Type, rel.ToID))
		}
	}

	if len(invalidRels) > 0 {
		span.SetAttributes(attribute.StringSlice("invalid_relationships", invalidRels))
		return nil, fmt.Errorf("batch validation failed - invalid relationships:\n  %s",
			strings.Join(invalidRels, "\n  "))
	}

	// Add relationships to the appropriate records based on source node ID
	for _, sdkRel := range batch.Relationships {
		// Validate relationship
		if err := sdkRel.Validate(); err != nil {
			return nil, fmt.Errorf("%w: relationship validation failed: %v", sdkgraphrag.ErrInvalidQuery, err)
		}

		// Convert relationship with batch ID mapping
		internalRel, err := sdkRelationshipToInternal(sdkRel, sdkIDToInternalID)
		if err != nil {
			return nil, fmt.Errorf("relationship conversion failed: %w", err)
		}

		// Find the record for the source node and add the relationship
		if idx, ok := nodeIDToIndex[sdkRel.FromID]; ok {
			records[idx].WithRelationship(*internalRel)
		} else {
			// After validation (Task 8), this path should be unreachable.
			// If we get here, it's a bug in the validation logic.
			return nil, fmt.Errorf("BUG: relationship %s references node %q which passed validation but is not in nodeIDToIndex - this should never happen",
				sdkRel.Type, sdkRel.FromID)
		}
	}

	// Convert pointer slice back to value slice for StoreBatch
	valueRecords := make([]graphrag.GraphRecord, len(records))
	for i, r := range records {
		valueRecords[i] = *r
	}

	// Store batch
	if err := b.store.StoreBatch(ctx, valueRecords); err != nil {
		return nil, fmt.Errorf("%w: %v", sdkgraphrag.ErrStorageFailed, err)
	}

	span.SetAttributes(attribute.Int("stored.count", len(nodeIDs)))

	// Create hierarchy relationships for all nodes based on reference properties
	for i, sdkNode := range batch.Nodes {
		b.createHierarchyRelationships(ctx, sdkNode, nodeIDs[i])
	}

	// Create DISCOVERED relationships for non-execution nodes
	// Note: agentRunID was already retrieved above for provenance
	if agentRunID != "" {
		discoveredRels := make([]sdkgraphrag.Relationship, 0, len(batch.Nodes))
		discoveredCount := 0

		for i, sdkNode := range batch.Nodes {
			// Skip execution nodes as they are part of the execution chain
			if !isExecutionNode(sdkNode.Type) {
				discoveredRel := sdkgraphrag.Relationship{
					FromID: agentRunID,
					ToID:   nodeIDs[i],
					Type:   sdkgraphrag.RelTypeUSEDTOOL,
					Properties: map[string]any{
						"discovered_at":    time.Now().UTC(),
						"discovery_method": agentName,
					},
				}
				discoveredRels = append(discoveredRels, discoveredRel)
			}
		}

		// Store DISCOVERED relationships in batch
		if len(discoveredRels) > 0 {
			for _, rel := range discoveredRels {
				// Use CreateRelationship for each DISCOVERED relationship
				// Log warning on failure but don't fail the batch operation
				if err := b.CreateRelationship(ctx, rel); err != nil {
					slog.Warn("DISCOVERED relationship creation failed (batch)",
						"agent_run_id", rel.FromID,
						"node_id", rel.ToID,
						"error", err.Error())
					span.AddEvent("discovered_relationship_failed",
						trace.WithAttributes(
							attribute.String("to_node_id", rel.ToID),
							attribute.String("error", err.Error()),
						))
				} else {
					discoveredCount++
				}
			}

			span.SetAttributes(attribute.Int("discovered.count", discoveredCount))
			span.AddEvent("discovered_relationships_created",
				trace.WithAttributes(
					attribute.String("agent_run_id", agentRunID),
					attribute.Int("count", discoveredCount),
				))
		}
	}

	return nodeIDs, nil
}

// StoreSemantic stores a node with semantic search capabilities (requires Content).
// Validates that node.Content is non-empty, then generates embeddings and stores.
func (b *DefaultGraphRAGQueryBridge) StoreSemantic(ctx context.Context, node sdkgraphrag.GraphNode, missionID, agentName string) (string, error) {
	ctx, span := b.tracer.Start(ctx, "GraphRAGQueryBridge.StoreSemantic",
		trace.WithAttributes(
			attribute.String("node.type", node.Type),
			attribute.String("mission_id", missionID),
			attribute.String("agent_name", agentName),
		))
	defer span.End()

	// Validate that Content is present for semantic storage
	if node.Content == "" {
		return "", fmt.Errorf("%w: Content is required for semantic storage", sdkgraphrag.ErrInvalidQuery)
	}

	// Validate node
	if err := node.Validate(); err != nil {
		return "", fmt.Errorf("%w: %v", sdkgraphrag.ErrInvalidQuery, err)
	}

	// Use existing StoreNode which handles embedding generation
	return b.StoreNode(ctx, node, missionID, agentName)
}

// StoreStructured stores a node without semantic search (no embedding required).
// Used for structured data like hosts, ports, services.
func (b *DefaultGraphRAGQueryBridge) StoreStructured(ctx context.Context, node sdkgraphrag.GraphNode, missionID, agentName string) (string, error) {
	ctx, span := b.tracer.Start(ctx, "GraphRAGQueryBridge.StoreStructured",
		trace.WithAttributes(
			attribute.String("node.type", node.Type),
			attribute.String("mission_id", missionID),
			attribute.String("agent_name", agentName),
		))
	defer span.End()

	// Validate node
	if err := node.Validate(); err != nil {
		return "", fmt.Errorf("%w: %v", sdkgraphrag.ErrInvalidQuery, err)
	}

	// Get agent_run_id from context for provenance
	agentRunID := AgentRunIDFromContext(ctx)

	// Get mission_run_id from context for mission-scoped storage
	missionRunID := MissionRunIDFromContext(ctx)

	// Convert SDK node to internal node (with provenance metadata)
	internalNode := sdkNodeToInternal(node, missionID, missionRunID, agentName, agentRunID)

	// Create graph record without embedding content
	record := graphrag.NewGraphRecord(*internalNode)

	// Store node without embedding generation
	if err := b.store.StoreWithoutEmbedding(ctx, record); err != nil {
		return "", fmt.Errorf("%w: %v", sdkgraphrag.ErrStorageFailed, err)
	}

	nodeID := internalNode.ID.String()
	span.SetAttributes(attribute.String("node.id", nodeID))

	// Create hierarchy relationships based on reference properties (host_id, port_id, etc)
	b.createHierarchyRelationships(ctx, node, nodeID)

	// Create DISCOVERED relationship from agent_run to this node (if applicable)
	// Skip execution nodes as they are part of the execution chain
	if agentRunID != "" && !isExecutionNode(node.Type) {
		discoveredRel := sdkgraphrag.Relationship{
			FromID: agentRunID,
			ToID:   nodeID,
			Type:   sdkgraphrag.RelTypeUSEDTOOL,
			Properties: map[string]any{
				"discovered_at":    time.Now().UTC(),
				"discovery_method": agentName,
			},
		}

		// Create the DISCOVERED relationship (log warning on failure but don't fail the operation)
		if err := b.CreateRelationship(ctx, discoveredRel); err != nil {
			span.AddEvent("discovered_relationship_failed",
				trace.WithAttributes(
					attribute.String("agent_run_id", agentRunID),
					attribute.String("error", err.Error()),
				))
		} else {
			span.AddEvent("discovered_relationship_created",
				trace.WithAttributes(
					attribute.String("agent_run_id", agentRunID),
				))
		}
	}

	return nodeID, nil
}

// Health returns the health status of the GraphRAG bridge.
func (b *DefaultGraphRAGQueryBridge) Health(ctx context.Context) types.HealthStatus {
	return b.store.Health(ctx)
}

// Compile-time interface check
var _ GraphRAGQueryBridge = (*DefaultGraphRAGQueryBridge)(nil)

// Type conversion functions (adapters)

// internalNodeToSDK converts internal GraphNode to SDK GraphNode.
func internalNodeToSDK(n graphrag.GraphNode) sdkgraphrag.GraphNode {
	// Get primary node type (first label)
	var nodeType string
	if len(n.Labels) > 0 {
		nodeType = n.Labels[0].String()
	}

	sdkNode := sdkgraphrag.GraphNode{
		ID:         n.ID.String(),
		Type:       nodeType,
		Properties: n.Properties,
		CreatedAt:  n.CreatedAt,
		UpdatedAt:  n.UpdatedAt,
	}

	// Set mission ID and agent name if present
	if n.MissionID != nil {
		sdkNode.MissionID = n.MissionID.String()
	}

	return sdkNode
}

// sdkNodeToInternal converts SDK GraphNode to internal GraphNode.
// Adds provenance properties (created_in_run, discovery_method, discovered_at) if not already set.
// Also adds mission_run_id for mission-scoped storage and querying.
func sdkNodeToInternal(n sdkgraphrag.GraphNode, missionID, missionRunID, agentName, agentRunID string) *graphrag.GraphNode {
	// Generate or parse node ID
	var nodeID types.ID
	if n.ID != "" {
		if id, err := types.ParseID(n.ID); err == nil {
			nodeID = id
		} else {
			nodeID = types.NewID()
		}
	} else {
		nodeID = types.NewID()
	}

	// Parse mission ID
	var internalMissionID *types.ID
	if missionID != "" {
		if id, err := types.ParseID(missionID); err == nil {
			internalMissionID = &id
		}
	}

	// Create node with type as label
	// Normalize node type to lowercase to ensure consistent Neo4j labels
	nodeType := strings.ToLower(n.Type)
	node := graphrag.NewGraphNode(nodeID, graphrag.NodeType(nodeType))

	// Initialize properties map if not present
	props := n.Properties
	if props == nil {
		props = make(map[string]any)
	}

	// Add mission_run_id for mission-scoped storage
	// This is critical for query isolation between mission runs
	if _, exists := props["mission_run_id"]; !exists && missionRunID != "" {
		props["mission_run_id"] = missionRunID
	}

	// Add provenance properties if not already set
	// These track which agent run discovered this node and when
	if _, exists := props["created_in_run"]; !exists && agentRunID != "" {
		props["created_in_run"] = agentRunID
	}
	if _, exists := props["discovery_method"]; !exists && agentName != "" {
		props["discovery_method"] = agentName
	}
	if _, exists := props["discovered_at"]; !exists {
		props["discovered_at"] = time.Now().UTC()
	}

	// Add agent name to properties (legacy, kept for backward compatibility)
	if agentName != "" {
		props["agent_name"] = agentName
	}

	// Set all properties including provenance
	node.WithProperties(props)

	// Set mission ID
	if internalMissionID != nil {
		node.WithMission(*internalMissionID)
	}

	// Preserve timestamps if provided
	if !n.CreatedAt.IsZero() {
		node.CreatedAt = n.CreatedAt
	}
	if !n.UpdatedAt.IsZero() {
		node.UpdatedAt = n.UpdatedAt
	}

	return node
}

// sdkRelationshipToInternal converts SDK Relationship to internal Relationship.
// Uses the optional idMapping to resolve batch-local node IDs to their internal UUIDs.
// Pass nil for idMapping when creating standalone relationships (IDs must be valid UUIDs).
func sdkRelationshipToInternal(r sdkgraphrag.Relationship, idMapping map[string]types.ID) (*graphrag.Relationship, error) {
	fromID, err := resolveNodeID(r.FromID, idMapping)
	if err != nil {
		return nil, fmt.Errorf("invalid from_id: %w", err)
	}

	toID, err := resolveNodeID(r.ToID, idMapping)
	if err != nil {
		return nil, fmt.Errorf("invalid to_id: %w", err)
	}

	rel := graphrag.NewRelationship(fromID, toID, graphrag.RelationType(r.Type))

	if r.Properties != nil {
		for k, v := range r.Properties {
			rel.WithProperty(k, v)
		}
	}

	return rel, nil
}

// resolveNodeID resolves an SDK node ID to an internal UUID.
// First checks the idMapping for batch-local nodes, then parses as UUID.
func resolveNodeID(id string, idMapping map[string]types.ID) (types.ID, error) {
	if idMapping != nil {
		if mappedID, ok := idMapping[id]; ok {
			return mappedID, nil
		}
	}
	return types.ParseID(id)
}

// internalIDsToStrings converts internal ID slice to string slice.
func internalIDsToStrings(ids []types.ID) []string {
	result := make([]string, len(ids))
	for i, id := range ids {
		result[i] = id.String()
	}
	return result
}

// truncate truncates a string to maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// isExecutionNode returns true if the node type is part of the execution chain.
// Execution nodes (mission, agent_run, llm_call, tool_execution) should not have
// DISCOVERED relationships as they represent the execution itself rather than
// discovered assets.
func isExecutionNode(nodeType string) bool {
	switch nodeType {
	case sdkgraphrag.NodeTypeMission,
		sdkgraphrag.NodeTypeAgentRun,
		sdkgraphrag.NodeTypeLlmCall,
		sdkgraphrag.NodeTypeToolExecution:
		return true
	default:
		return false
	}
}

// createHierarchyRelationships creates asset hierarchy relationships based on reference properties.
// This enables automatic graph structure creation for asset dependencies:
//   - Port with host_id → (host)-[:HAS_PORT]->(port)
//   - Service with port_id → (port)-[:RUNS_SERVICE]->(service)
//   - Endpoint with service_id → (service)-[:HAS_ENDPOINT]->(endpoint)
//   - Subdomain with parent_domain → (domain)-[:HAS_SUBDOMAIN]->(subdomain)
//
// Errors are logged as warnings but don't fail the operation, allowing for partial
// graph construction when parent nodes may not exist yet.
func (b *DefaultGraphRAGQueryBridge) createHierarchyRelationships(ctx context.Context, node sdkgraphrag.GraphNode, nodeID string) {
	props := node.Properties
	if props == nil {
		return
	}

	var fromID, relType string

	// Detect parent reference based on node type and extract parent ID + relationship type
	switch node.Type {
	case sdkgraphrag.NodeTypePort:
		// Port references its host via host_id property
		if hostID, ok := props["parent_host_id"].(string); ok && hostID != "" {
			fromID = hostID
			relType = sdkgraphrag.RelTypeHASPORT
		}

	case sdkgraphrag.NodeTypeService:
		// Service references its port via port_id property
		if portID, ok := props["parent_port_id"].(string); ok && portID != "" {
			fromID = portID
			relType = sdkgraphrag.RelTypeRUNSSERVICE
		}

	case sdkgraphrag.NodeTypeEndpoint:
		// Endpoint references its service via service_id property
		if serviceID, ok := props["parent_service_id"].(string); ok && serviceID != "" {
			fromID = serviceID
			relType = sdkgraphrag.RelTypeHASENDPOINT
		}

	case sdkgraphrag.NodeTypeSubdomain:
		// Subdomain references its parent domain via parent_domain property
		if parentDomain, ok := props["parent_domain_id"].(string); ok && parentDomain != "" {
			fromID = parentDomain
			relType = sdkgraphrag.RelTypeHASSUBDOMAIN
		}
	}

	// Create relationship if we found a valid parent reference
	if fromID != "" && relType != "" {
		rel := sdkgraphrag.Relationship{
			FromID: fromID,
			ToID:   nodeID,
			Type:   relType,
		}

		// Create the relationship - log warning on failure but don't fail the operation
		// This allows for partial graph construction when parent nodes don't exist yet
		if err := b.CreateRelationship(ctx, rel); err != nil {
			// Use tracing to log the failure for observability
			if span := ctx.Value("span"); span != nil {
				if s, ok := span.(trace.Span); ok {
					s.AddEvent("hierarchy_relationship_failed",
						trace.WithAttributes(
							attribute.String("node_id", nodeID),
							attribute.String("node_type", node.Type),
							attribute.String("from_id", fromID),
							attribute.String("relationship_type", relType),
							attribute.String("error", err.Error()),
						))
				}
			}
		}
	}
}

// nodeExistsInGraph checks if a node exists in the graph by attempting to retrieve it.
// Returns true if the node exists, false otherwise.
// This is used during batch validation to check for cross-batch relationships.
func (b *DefaultGraphRAGQueryBridge) nodeExistsInGraph(ctx context.Context, nodeID string) bool {
	// Parse the node ID
	id, err := types.ParseID(nodeID)
	if err != nil {
		return false
	}

	// Use the store's GetNode method to check existence
	// GetNode returns an error if the node is not found
	_, err = b.store.GetNode(ctx, id)
	return err == nil
}
