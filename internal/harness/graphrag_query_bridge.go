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

	"github.com/zero-day-ai/gibson/internal/graphrag"
	"github.com/zero-day-ai/gibson/internal/types"
	sdkgraphrag "github.com/zero-day-ai/sdk/graphrag"
)

// GraphRAGQueryBridge provides the query interface for GraphRAG operations.
// It bridges SDK types to internal GraphRAG store operations, enabling agents
// to query the knowledge graph, traverse relationships, and retrieve domain-specific
// data like attack patterns and security findings.
//
// All methods include OpenTelemetry instrumentation for observability.
// GraphRAG is a core requirement - the daemon will fail to start if GraphRAG is not configured.
type GraphRAGQueryBridge interface {
	// Query executes a hybrid GraphRAG query combining semantic search and graph traversal.
	// Returns results ranked by combined vector and graph scores.
	Query(ctx context.Context, query sdkgraphrag.Query) ([]sdkgraphrag.Result, error)

	// FindSimilarAttacks finds attack patterns similar to the given content.
	// Uses vector similarity search on attack pattern descriptions.
	FindSimilarAttacks(ctx context.Context, content string, topK int) ([]sdkgraphrag.AttackPattern, error)

	// FindSimilarFindings finds findings similar to the specified finding.
	// Uses vector similarity search on finding descriptions.
	FindSimilarFindings(ctx context.Context, findingID string, topK int) ([]sdkgraphrag.FindingNode, error)

	// GetAttackChains discovers attack chains (technique sequences) from a starting technique.
	// Traverses USES_TECHNIQUE relationships to find multi-step attack patterns.
	GetAttackChains(ctx context.Context, techniqueID string, maxDepth int) ([]sdkgraphrag.AttackChain, error)

	// GetRelatedFindings retrieves findings related to the specified finding.
	// Traverses SIMILAR_TO and other relationship types.
	GetRelatedFindings(ctx context.Context, findingID string) ([]sdkgraphrag.FindingNode, error)

	// StoreNode stores a single graph node with mission and agent context.
	// Returns the node ID. MissionID and agentName are auto-populated.
	StoreNode(ctx context.Context, node sdkgraphrag.GraphNode, missionID, agentName string) (string, error)

	// CreateRelationship creates a relationship between two nodes.
	CreateRelationship(ctx context.Context, rel sdkgraphrag.Relationship) error

	// StoreBatch stores multiple nodes and relationships in a single operation.
	// Returns node IDs for all created nodes. MissionID and agentName are auto-populated.
	StoreBatch(ctx context.Context, batch sdkgraphrag.Batch, missionID, agentName string) ([]string, error)

	// Traverse performs graph traversal from a starting node with filtering options.
	// Returns all nodes visited during traversal with path information.
	Traverse(ctx context.Context, startNodeID string, opts sdkgraphrag.TraversalOptions) ([]sdkgraphrag.TraversalResult, error)

	// StoreSemantic stores a node with semantic search capabilities (requires Content).
	// Validates that node.Content is non-empty, then generates embeddings and stores.
	StoreSemantic(ctx context.Context, node sdkgraphrag.GraphNode, missionID, agentName string) (string, error)

	// StoreStructured stores a node without semantic search (no embedding required).
	// Used for structured data like hosts, ports, services.
	StoreStructured(ctx context.Context, node sdkgraphrag.GraphNode, missionID, agentName string) (string, error)

	// QuerySemantic performs a semantic-only query (no structured fallback).
	// Validates that Text or Embedding is present, sets ForceSemanticOnly=true.
	QuerySemantic(ctx context.Context, query sdkgraphrag.Query) ([]sdkgraphrag.Result, error)

	// QueryStructured performs a structured-only query (no vector search).
	// Validates that NodeTypes is present, sets ForceStructuredOnly=true.
	QueryStructured(ctx context.Context, query sdkgraphrag.Query) ([]sdkgraphrag.Result, error)

	// Health returns the health status of the GraphRAG bridge.
	Health(ctx context.Context) types.HealthStatus
}

// DefaultGraphRAGQueryBridge is the default implementation of GraphRAGQueryBridge.
// It wraps graphrag.GraphRAGStore and provides type conversion between SDK and internal types.
type DefaultGraphRAGQueryBridge struct {
	store          graphrag.GraphRAGStore
	tracer         trace.Tracer
	policyEnforcer DataPolicyEnforcer
}

// NewGraphRAGQueryBridge creates a new DefaultGraphRAGQueryBridge.
// If store is nil, methods will return ErrGraphRAGNotEnabled.
// If policySource is nil, policy enforcement will be disabled (queries run unfiltered).
func NewGraphRAGQueryBridge(store graphrag.GraphRAGStore, policySource PolicySource) *DefaultGraphRAGQueryBridge {
	var enforcer DataPolicyEnforcer
	if policySource != nil {
		enforcer = NewDataPolicyEnforcer(policySource)
	}

	return &DefaultGraphRAGQueryBridge{
		store:          store,
		tracer:         otel.Tracer("gibson/harness/graphrag_query_bridge"),
		policyEnforcer: enforcer,
	}
}

// Query executes a hybrid GraphRAG query.
func (b *DefaultGraphRAGQueryBridge) Query(ctx context.Context, query sdkgraphrag.Query) ([]sdkgraphrag.Result, error) {
	ctx, span := b.tracer.Start(ctx, "GraphRAGQueryBridge.Query",
		trace.WithAttributes(
			attribute.String("query.text", query.Text),
			attribute.Int("query.top_k", query.TopK),
			attribute.Int("query.max_hops", query.MaxHops),
		))
	defer span.End()

	// Apply data policy enforcement BEFORE query execution
	if b.policyEnforcer != nil {
		if err := b.policyEnforcer.ApplyInputScope(ctx, &query); err != nil {
			return nil, fmt.Errorf("policy enforcement failed: %w", err)
		}
	}

	// Validate query
	if err := query.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", sdkgraphrag.ErrInvalidQuery, err)
	}

	// Convert SDK query to internal query
	internalQuery := sdkQueryToInternal(query)

	// Execute query
	internalResults, err := b.store.Query(ctx, internalQuery)
	if err != nil {
		return nil, fmt.Errorf("query execution failed: %w", err)
	}

	// Convert results back to SDK types
	results := make([]sdkgraphrag.Result, len(internalResults))
	for i, r := range internalResults {
		results[i] = internalResultToSDK(r)
	}

	span.SetAttributes(attribute.Int("results.count", len(results)))
	return results, nil
}

// FindSimilarAttacks finds attack patterns similar to the given content.
func (b *DefaultGraphRAGQueryBridge) FindSimilarAttacks(ctx context.Context, content string, topK int) ([]sdkgraphrag.AttackPattern, error) {
	ctx, span := b.tracer.Start(ctx, "GraphRAGQueryBridge.FindSimilarAttacks",
		trace.WithAttributes(
			attribute.String("content.preview", truncate(content, 100)),
			attribute.Int("top_k", topK),
		))
	defer span.End()

	// Execute similarity search
	internalPatterns, err := b.store.FindSimilarAttacks(ctx, content, topK)
	if err != nil {
		return nil, fmt.Errorf("find similar attacks failed: %w", err)
	}

	// Convert to SDK types
	patterns := make([]sdkgraphrag.AttackPattern, len(internalPatterns))
	for i, p := range internalPatterns {
		patterns[i] = internalAttackPatternToSDK(p)
	}

	span.SetAttributes(attribute.Int("patterns.count", len(patterns)))
	return patterns, nil
}

// FindSimilarFindings finds findings similar to the specified finding.
func (b *DefaultGraphRAGQueryBridge) FindSimilarFindings(ctx context.Context, findingID string, topK int) ([]sdkgraphrag.FindingNode, error) {
	ctx, span := b.tracer.Start(ctx, "GraphRAGQueryBridge.FindSimilarFindings",
		trace.WithAttributes(
			attribute.String("finding_id", findingID),
			attribute.Int("top_k", topK),
		))
	defer span.End()

	// Execute similarity search
	internalFindings, err := b.store.FindSimilarFindings(ctx, findingID, topK)
	if err != nil {
		return nil, fmt.Errorf("find similar findings failed: %w", err)
	}

	// Convert to SDK types
	findings := make([]sdkgraphrag.FindingNode, len(internalFindings))
	for i, f := range internalFindings {
		findings[i] = internalFindingToSDK(f)
	}

	span.SetAttributes(attribute.Int("findings.count", len(findings)))
	return findings, nil
}

// GetAttackChains discovers attack chains from a starting technique.
func (b *DefaultGraphRAGQueryBridge) GetAttackChains(ctx context.Context, techniqueID string, maxDepth int) ([]sdkgraphrag.AttackChain, error) {
	ctx, span := b.tracer.Start(ctx, "GraphRAGQueryBridge.GetAttackChains",
		trace.WithAttributes(
			attribute.String("technique_id", techniqueID),
			attribute.Int("max_depth", maxDepth),
		))
	defer span.End()

	// Execute attack chain discovery
	internalChains, err := b.store.GetAttackChains(ctx, techniqueID, maxDepth)
	if err != nil {
		return nil, fmt.Errorf("get attack chains failed: %w", err)
	}

	// Convert to SDK types
	chains := make([]sdkgraphrag.AttackChain, len(internalChains))
	for i, c := range internalChains {
		chains[i] = internalAttackChainToSDK(c)
	}

	span.SetAttributes(attribute.Int("chains.count", len(chains)))
	return chains, nil
}

// GetRelatedFindings retrieves findings related to the specified finding.
func (b *DefaultGraphRAGQueryBridge) GetRelatedFindings(ctx context.Context, findingID string) ([]sdkgraphrag.FindingNode, error) {
	ctx, span := b.tracer.Start(ctx, "GraphRAGQueryBridge.GetRelatedFindings",
		trace.WithAttributes(
			attribute.String("finding_id", findingID),
		))
	defer span.End()

	// Execute relationship traversal
	internalFindings, err := b.store.GetRelatedFindings(ctx, findingID)
	if err != nil {
		return nil, fmt.Errorf("get related findings failed: %w", err)
	}

	// Convert to SDK types
	findings := make([]sdkgraphrag.FindingNode, len(internalFindings))
	for i, f := range internalFindings {
		findings[i] = internalFindingToSDK(f)
	}

	span.SetAttributes(attribute.Int("findings.count", len(findings)))
	return findings, nil
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

// Traverse performs graph traversal from a starting node.
func (b *DefaultGraphRAGQueryBridge) Traverse(ctx context.Context, startNodeID string, opts sdkgraphrag.TraversalOptions) ([]sdkgraphrag.TraversalResult, error) {
	ctx, span := b.tracer.Start(ctx, "GraphRAGQueryBridge.Traverse",
		trace.WithAttributes(
			attribute.String("start_node_id", startNodeID),
			attribute.Int("max_depth", opts.MaxDepth),
			attribute.String("direction", opts.Direction),
		))
	defer span.End()

	// Convert relationship types to internal types
	var relTypes []graphrag.RelationType
	for _, rt := range opts.RelationshipTypes {
		relTypes = append(relTypes, graphrag.RelationType(rt))
	}

	// Convert node types to internal types
	var nodeTypes []graphrag.NodeType
	for _, nt := range opts.NodeTypes {
		nodeTypes = append(nodeTypes, graphrag.NodeType(nt))
	}

	// Create traversal filters
	filters := graphrag.TraversalFilters{
		AllowedRelations: relTypes,
		AllowedNodeTypes: nodeTypes,
	}

	// Execute traversal
	// Note: The GraphRAGProvider interface has TraverseGraph method
	// We'll need to access the provider through the store
	// For now, we'll return an error indicating this needs provider access
	_ = filters
	return nil, fmt.Errorf("traverse not yet implemented: requires direct provider access")
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

// QuerySemantic performs a semantic-only query (no structured fallback).
// Validates that Text or Embedding is present, sets ForceSemanticOnly=true.
func (b *DefaultGraphRAGQueryBridge) QuerySemantic(ctx context.Context, query sdkgraphrag.Query) ([]sdkgraphrag.Result, error) {
	ctx, span := b.tracer.Start(ctx, "GraphRAGQueryBridge.QuerySemantic",
		trace.WithAttributes(
			attribute.String("query.text", query.Text),
			attribute.Int("query.top_k", query.TopK),
		))
	defer span.End()

	// Apply data policy enforcement BEFORE query execution
	if b.policyEnforcer != nil {
		if err := b.policyEnforcer.ApplyInputScope(ctx, &query); err != nil {
			return nil, fmt.Errorf("policy enforcement failed: %w", err)
		}
	}

	// Validate that Text or Embedding is present
	if query.Text == "" && len(query.Embedding) == 0 {
		return nil, fmt.Errorf("%w: Text or Embedding is required for semantic query", sdkgraphrag.ErrInvalidQuery)
	}

	// Validate query
	if err := query.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", sdkgraphrag.ErrInvalidQuery, err)
	}

	// Convert SDK query to internal query with ForceSemanticOnly=true
	internalQuery := sdkQueryToInternal(query)
	internalQuery.ForceSemanticOnly = true

	// Execute query
	internalResults, err := b.store.Query(ctx, internalQuery)
	if err != nil {
		return nil, fmt.Errorf("semantic query execution failed: %w", err)
	}

	// Convert results back to SDK types
	results := make([]sdkgraphrag.Result, len(internalResults))
	for i, r := range internalResults {
		results[i] = internalResultToSDK(r)
	}

	span.SetAttributes(attribute.Int("results.count", len(results)))
	return results, nil
}

// QueryStructured performs a structured-only query (no vector search).
// Validates that NodeTypes is present, sets ForceStructuredOnly=true.
func (b *DefaultGraphRAGQueryBridge) QueryStructured(ctx context.Context, query sdkgraphrag.Query) ([]sdkgraphrag.Result, error) {
	ctx, span := b.tracer.Start(ctx, "GraphRAGQueryBridge.QueryStructured",
		trace.WithAttributes(
			attribute.StringSlice("query.node_types", query.NodeTypes),
			attribute.Int("query.top_k", query.TopK),
		))
	defer span.End()

	// Apply data policy enforcement BEFORE query execution
	if b.policyEnforcer != nil {
		if err := b.policyEnforcer.ApplyInputScope(ctx, &query); err != nil {
			return nil, fmt.Errorf("policy enforcement failed: %w", err)
		}
	}

	// Validate that NodeTypes is present
	if len(query.NodeTypes) == 0 {
		return nil, fmt.Errorf("%w: NodeTypes is required for structured query", sdkgraphrag.ErrInvalidQuery)
	}

	// Validate query
	if err := query.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", sdkgraphrag.ErrInvalidQuery, err)
	}

	// Convert SDK query to internal query with ForceStructuredOnly=true
	internalQuery := sdkQueryToInternal(query)
	internalQuery.ForceStructuredOnly = true

	// Execute query
	internalResults, err := b.store.Query(ctx, internalQuery)
	if err != nil {
		return nil, fmt.Errorf("structured query execution failed: %w", err)
	}

	// Convert results back to SDK types
	results := make([]sdkgraphrag.Result, len(internalResults))
	for i, r := range internalResults {
		results[i] = internalResultToSDK(r)
	}

	span.SetAttributes(attribute.Int("results.count", len(results)))
	return results, nil
}

// Health returns the health status of the GraphRAG bridge.
func (b *DefaultGraphRAGQueryBridge) Health(ctx context.Context) types.HealthStatus {
	return b.store.Health(ctx)
}

// Compile-time interface check
var _ GraphRAGQueryBridge = (*DefaultGraphRAGQueryBridge)(nil)

// Type conversion functions (adapters)

// sdkQueryToInternal converts SDK Query to internal GraphRAGQuery.
func sdkQueryToInternal(q sdkgraphrag.Query) graphrag.GraphRAGQuery {
	// Convert mission ID if present
	var missionID *types.ID
	if q.MissionID != "" {
		if id, err := types.ParseID(q.MissionID); err == nil {
			missionID = &id
		}
	}

	// Convert node types
	var nodeTypes []graphrag.NodeType
	for _, nt := range q.NodeTypes {
		nodeTypes = append(nodeTypes, graphrag.NodeType(nt))
	}

	internalQuery := graphrag.GraphRAGQuery{
		Text:         q.Text,
		Embedding:    q.Embedding,
		TopK:         q.TopK,
		MaxHops:      q.MaxHops,
		MinScore:     q.MinScore,
		NodeTypes:    nodeTypes,
		MissionID:    missionID,
		MissionRunID: q.MissionRunID, // Pass through mission run ID for mission-run scoped queries
		MissionName:  q.MissionName,  // Pass through mission name for mission scoped queries
		VectorWeight: q.VectorWeight,
		GraphWeight:  q.GraphWeight,
	}

	return internalQuery
}

// internalResultToSDK converts internal GraphRAGResult to SDK Result.
func internalResultToSDK(r graphrag.GraphRAGResult) sdkgraphrag.Result {
	result := sdkgraphrag.Result{
		Node:        internalNodeToSDK(r.Node),
		Score:       r.Score,
		VectorScore: r.VectorScore,
		GraphScore:  r.GraphScore,
		Path:        internalIDsToStrings(r.Path),
		Distance:    r.Distance,
	}

	// Include run metadata if available
	// GetRunMetadata returns nil if no mission_name is set (backwards compatibility)
	if metadata := r.Node.GetRunMetadata(); metadata != nil {
		result.RunMetadata = &sdkgraphrag.RunMetadata{
			MissionName:  metadata.MissionName,
			RunNumber:    metadata.RunNumber,
			DiscoveredAt: metadata.DiscoveredAt,
		}
	}

	return result
}

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

// internalAttackPatternToSDK converts internal AttackPattern to SDK AttackPattern.
func internalAttackPatternToSDK(p graphrag.AttackPattern) sdkgraphrag.AttackPattern {
	return sdkgraphrag.AttackPattern{
		TechniqueID: p.TechniqueID,
		Name:        p.Name,
		Description: p.Description,
		Tactics:     p.Tactics,
		Platforms:   p.Platforms,
		Similarity:  0.0, // Will be set by vector search
	}
}

// internalFindingToSDK converts internal FindingNode to SDK FindingNode.
func internalFindingToSDK(f graphrag.FindingNode) sdkgraphrag.FindingNode {
	return sdkgraphrag.FindingNode{
		ID:          f.ID.String(),
		Title:       f.Title,
		Description: f.Description,
		Severity:    f.Severity,
		Category:    f.Category,
		Confidence:  f.Confidence,
		Similarity:  0.0, // Will be set by vector search
	}
}

// internalAttackChainToSDK converts internal AttackChain to SDK AttackChain.
func internalAttackChainToSDK(c graphrag.AttackChain) sdkgraphrag.AttackChain {
	steps := make([]sdkgraphrag.AttackStep, len(c.Steps))
	for i, s := range c.Steps {
		steps[i] = sdkgraphrag.AttackStep{
			Order:       s.Order,
			TechniqueID: s.TechniqueID,
			NodeID:      s.NodeID.String(),
			Description: s.Description,
			Confidence:  s.Confidence,
		}
	}

	return sdkgraphrag.AttackChain{
		ID:       c.ID.String(),
		Name:     c.Name,
		Severity: c.Severity,
		Steps:    steps,
	}
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
