// Package graphrag provides the GraphRAG store implementation.
// This file contains the unified GraphRAGStore interface and DefaultGraphRAGStore implementation
// for high-level GraphRAG operations combining graph storage, vector search, and hybrid queries.
//
// The store orchestrates:
// - Graph node and relationship storage
// - Embedding generation and vector indexing
// - Hybrid GraphRAG queries (semantic + structural retrieval)
// - Domain-specific operations (attack patterns, findings, attack chains)
//
// Usage:
//
//	config := GraphRAGConfig{Provider: "neo4j", ...}
//	embedder := embedder.NewOpenAIEmbedder(...)
//	prov, err := provider.NewProvider(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	store, err := NewGraphRAGStoreWithProvider(config, embedder, prov)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer store.Close()
//
//	// Store a finding
//	finding := NewFindingNode(id, "SQL Injection", "Found SQLi vulnerability", missionID)
//	if err := store.StoreFinding(ctx, *finding); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Query for similar findings
//	similar, err := store.FindSimilarFindings(ctx, finding.ID.String(), 5)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// The DefaultGraphRAGStore is thread-safe and can be used concurrently from multiple goroutines.
package graphrag

import (
	"context"
	"fmt"
	"time"

	"github.com/zero-day-ai/gibson/internal/memory/embedder"
	"github.com/zero-day-ai/gibson/internal/types"
	sdkgraphrag "github.com/zero-day-ai/gibson/sdk/graphrag"
)

// GraphRAGStore provides a unified, high-level interface for GraphRAG operations.
// It orchestrates the full GraphRAG stack: graph storage, vector search, and hybrid queries.
//
// The store abstracts away the complexity of coordinating between:
// - GraphRAGProvider for graph + vector operations
// - QueryProcessor for hybrid query execution
// - Embedder for embedding generation
//
// Thread-safety: All implementations must be safe for concurrent access.
type GraphRAGStore interface {
	// Store stores a single graph record (node + optional relationships).
	// Automatically generates embeddings if not provided and upserts to both
	// graph database and vector store.
	Store(ctx context.Context, record GraphRecord) error

	// StoreWithoutEmbedding stores a node directly without embedding generation.
	// Used for structured data that doesn't need semantic search (e.g., hosts, ports).
	// The node is stored in the graph but not indexed for vector search.
	StoreWithoutEmbedding(ctx context.Context, record GraphRecord) error

	// StoreBatch efficiently stores multiple graph records in a single operation.
	// Uses batch embedding generation and bulk upsert for optimal performance.
	StoreBatch(ctx context.Context, records []GraphRecord) error

	// Query executes a hybrid GraphRAG query combining vector similarity and graph traversal.
	// This is the primary query method for semantic + structural retrieval.
	Query(ctx context.Context, query GraphRAGQuery) ([]GraphRAGResult, error)

	// StoreAttackPattern stores a MITRE ATT&CK pattern with technique relationships.
	// Creates the attack pattern node and USES_TECHNIQUE relationships to techniques.
	// Automatically generates embeddings from pattern description.
	StoreAttackPattern(ctx context.Context, pattern AttackPattern) error

	// FindSimilarAttacks finds attack patterns similar to the given content.
	// Uses vector search filtered to AttackPattern node type.
	// Returns top-K most similar attack patterns ranked by similarity.
	FindSimilarAttacks(ctx context.Context, content string, topK int) ([]AttackPattern, error)

	// FindSimilarFindings finds findings similar to the given finding.
	// Uses vector search filtered to Finding node type.
	// Returns top-K most similar findings ranked by similarity.
	FindSimilarFindings(ctx context.Context, findingID string, topK int) ([]FindingNode, error)

	// GetAttackChains discovers attack chains (technique sequences) from a starting technique.
	// Traverses USES_TECHNIQUE relationships to find multi-step attack patterns.
	// Returns all discovered chains up to maxDepth steps.
	GetAttackChains(ctx context.Context, techniqueID string, maxDepth int) ([]AttackChain, error)

	// StoreFinding stores a security finding with contextual relationships.
	// Creates the finding node and relationships to targets/techniques.
	// Automatically generates embeddings from finding description.
	StoreFinding(ctx context.Context, finding FindingNode) error

	// StoreFindingWithRun stores a finding and links it to a mission run.
	// Creates the finding node and a DISCOVERED_IN relationship to the run.
	// Useful for tracking when findings were discovered across multiple runs.
	StoreFindingWithRun(ctx context.Context, finding FindingNode, runID types.ID) error

	// GetRelatedFindings retrieves findings related to the given finding.
	// Traverses SIMILAR_TO and other relationship types to find connected findings.
	// Useful for correlation and deduplication analysis.
	GetRelatedFindings(ctx context.Context, findingID string) ([]FindingNode, error)

	// GetNode retrieves a single node by ID.
	// Returns the node if found, or an error if not found or query fails.
	GetNode(ctx context.Context, nodeID types.ID) (*GraphNode, error)

	// StoreRelationshipOnly stores a relationship without creating any nodes.
	// Used when both nodes already exist and only a relationship needs to be added.
	StoreRelationshipOnly(ctx context.Context, rel Relationship) error

	// TraverseGraph walks the graph starting from startNodeID following relationships
	// that match the provided TraversalFilters. Returns all visited nodes up to
	// maxDepth hops from the start node.
	TraverseGraph(ctx context.Context, startNodeID string, maxDepth int, filters TraversalFilters) ([]GraphNode, error)

	// Health returns the current health status of the GraphRAG store.
	// Aggregates health from provider, embedder, and processor.
	Health(ctx context.Context) types.HealthStatus

	// Close releases all resources and closes connections.
	// Should be called during graceful shutdown.
	Close() error
}

// GraphRecord represents a unified input for storing graph data.
// Combines a node with optional relationships to be created atomically.
type GraphRecord struct {
	Node          GraphNode      // The graph node to store
	Relationships []Relationship // Optional relationships to create
	EmbedContent  string         // Content to embed (if Node.Embedding is empty)
}

// NewGraphRecord creates a new GraphRecord with the given node.
func NewGraphRecord(node GraphNode) GraphRecord {
	return GraphRecord{
		Node:          node,
		Relationships: []Relationship{},
	}
}

// WithRelationship adds a relationship to the record.
// Returns the record for method chaining.
func (gr *GraphRecord) WithRelationship(rel Relationship) *GraphRecord {
	gr.Relationships = append(gr.Relationships, rel)
	return gr
}

// WithRelationships adds multiple relationships to the record.
// Returns the record for method chaining.
func (gr *GraphRecord) WithRelationships(rels []Relationship) *GraphRecord {
	gr.Relationships = append(gr.Relationships, rels...)
	return gr
}

// WithEmbedContent sets the content to use for embedding generation.
// Returns the record for method chaining.
func (gr *GraphRecord) WithEmbedContent(content string) *GraphRecord {
	gr.EmbedContent = content
	return gr
}

// DefaultGraphRAGStore implements GraphRAGStore using a provider and processor.
type DefaultGraphRAGStore struct {
	provider  GraphRAGProvider
	processor QueryProcessor
	embedder  embedder.Embedder
	config    GraphRAGConfig
}


// Store stores a single graph record (node + relationships).
// Generates embedding if not provided, then upserts to provider.
func (s *DefaultGraphRAGStore) Store(ctx context.Context, record GraphRecord) error {
	// Generate embedding if not present
	if len(record.Node.Embedding) == 0 && record.EmbedContent != "" {
		embedding, err := s.embedder.Embed(ctx, record.EmbedContent)
		if err != nil {
			return NewEmbeddingError("failed to generate embedding for record", err, true)
		}
		record.Node.Embedding = embedding
	}

	// Validate node
	if err := record.Node.Validate(); err != nil {
		return NewInvalidQueryError(fmt.Sprintf("invalid graph node: %v", err))
	}

	// Store node
	if err := s.provider.StoreNode(ctx, record.Node); err != nil {
		return NewQueryError("failed to store node", err)
	}

	// Store relationships
	for _, rel := range record.Relationships {
		if err := rel.Validate(); err != nil {
			return NewInvalidQueryError(fmt.Sprintf("invalid relationship: %v", err))
		}
		if err := s.provider.StoreRelationship(ctx, rel); err != nil {
			return NewRelationshipError("failed to store relationship", err)
		}
	}

	return nil
}

// StoreWithoutEmbedding stores a node directly without embedding generation.
// Used for structured data that doesn't need semantic search (e.g., hosts, ports).
// The node is stored in the graph but not indexed for vector search.
func (s *DefaultGraphRAGStore) StoreWithoutEmbedding(ctx context.Context, record GraphRecord) error {
	// Validate node
	if err := record.Node.Validate(); err != nil {
		return NewInvalidQueryError(fmt.Sprintf("invalid graph node: %v", err))
	}

	// Store node directly without embedding
	if err := s.provider.StoreNode(ctx, record.Node); err != nil {
		return NewQueryError("failed to store node", err)
	}

	// Store relationships
	for _, rel := range record.Relationships {
		if err := rel.Validate(); err != nil {
			return NewInvalidQueryError(fmt.Sprintf("invalid relationship: %v", err))
		}
		if err := s.provider.StoreRelationship(ctx, rel); err != nil {
			return NewRelationshipError("failed to store relationship", err)
		}
	}

	return nil
}

// StoreBatch efficiently stores multiple graph records.
// Generates embeddings in batch, then stores nodes and relationships.
// IMPORTANT: Stores ALL nodes first, THEN all relationships to ensure
// relationship target nodes exist before creating relationships.
func (s *DefaultGraphRAGStore) StoreBatch(ctx context.Context, records []GraphRecord) error {
	if len(records) == 0 {
		return nil
	}

	// Collect records that need embeddings
	var embedTexts []string
	var embedIndices []int
	for i, record := range records {
		if len(record.Node.Embedding) == 0 && record.EmbedContent != "" {
			embedTexts = append(embedTexts, record.EmbedContent)
			embedIndices = append(embedIndices, i)
		}
	}

	// Generate embeddings in batch
	if len(embedTexts) > 0 {
		embeddings, err := s.embedder.EmbedBatch(ctx, embedTexts)
		if err != nil {
			return NewEmbeddingError("failed to generate batch embeddings", err, true)
		}

		// Assign embeddings to records
		for i, idx := range embedIndices {
			records[idx].Node.Embedding = embeddings[i]
		}
	}

	// Phase 1: Store ALL nodes first
	for _, record := range records {
		// Generate embedding if not present
		if len(record.Node.Embedding) == 0 && record.EmbedContent != "" {
			embedding, err := s.embedder.Embed(ctx, record.EmbedContent)
			if err != nil {
				return NewEmbeddingError("failed to generate embedding for record", err, true)
			}
			record.Node.Embedding = embedding
		}

		// Validate node
		if err := record.Node.Validate(); err != nil {
			return NewInvalidQueryError(fmt.Sprintf("invalid graph node: %v", err))
		}

		// Store node
		if err := s.provider.StoreNode(ctx, record.Node); err != nil {
			return NewQueryError("failed to store node", err)
		}
	}

	// Phase 2: Store ALL relationships after all nodes exist
	for _, record := range records {
		for _, rel := range record.Relationships {
			if err := rel.Validate(); err != nil {
				return NewInvalidQueryError(fmt.Sprintf("invalid relationship: %v", err))
			}
			if err := s.provider.StoreRelationship(ctx, rel); err != nil {
				return NewRelationshipError("failed to store relationship", err)
			}
		}
	}

	return nil
}

// Query executes a hybrid GraphRAG query.
// Delegates to the QueryProcessor for full pipeline execution.
func (s *DefaultGraphRAGStore) Query(ctx context.Context, query GraphRAGQuery) ([]GraphRAGResult, error) {
	return s.processor.ProcessQuery(ctx, query, s.provider)
}

// StoreAttackPattern stores a MITRE ATT&CK pattern with technique relationships.
// Creates the pattern node and USES_TECHNIQUE relationships.
func (s *DefaultGraphRAGStore) StoreAttackPattern(ctx context.Context, pattern AttackPattern) error {
	// Generate embedding from description
	if len(pattern.Embedding) == 0 && pattern.Description != "" {
		embedding, err := s.embedder.Embed(ctx, pattern.Description)
		if err != nil {
			return NewEmbeddingError("failed to generate embedding for attack pattern", err, true)
		}
		pattern.Embedding = embedding
	}

	// Convert to GraphNode
	node := pattern.ToGraphNode()

	// Store the node
	if err := s.provider.StoreNode(ctx, *node); err != nil {
		return NewQueryError("failed to store attack pattern node", err)
	}

	// Create USES_TECHNIQUE relationships for each tactic
	// Note: This assumes technique nodes already exist
	// In a real implementation, we'd either create technique nodes or query for them
	for _, tactic := range pattern.Tactics {
		// SIMPLIFIED: Current implementation generates placeholder technique IDs using types.NewID()
		// instead of querying for existing technique nodes in the graph.
		// Production implementation would:
		// 1. Query for existing technique nodes by MITRE technique ID (e.g., T1566)
		// 2. Create technique node if not found in the graph
		// 3. Use the actual node ID from query result or newly created node for the relationship
		// 4. Avoid creating duplicate technique nodes and orphaned relationships
		rel := NewRelationship(
			pattern.ID,
			types.NewID(), // Placeholder - should be actual technique ID from query or creation
			RelationType("uses_technique"),
		).WithProperty("tactic", tactic)

		if err := s.provider.StoreRelationship(ctx, *rel); err != nil {
			// Don't fail the entire operation if relationship creation fails
			// Log error in production
			continue
		}
	}

	return nil
}

// FindSimilarAttacks finds attack patterns similar to the given content.
// Uses vector search filtered to AttackPattern node type.
func (s *DefaultGraphRAGStore) FindSimilarAttacks(ctx context.Context, content string, topK int) ([]AttackPattern, error) {
	// Generate embedding for content
	embedding, err := s.embedder.Embed(ctx, content)
	if err != nil {
		return nil, NewEmbeddingError("failed to generate embedding for content", err, true)
	}

	// Execute vector search with AttackPattern filter
	filters := map[string]any{
		"node_type": NodeType("attack_pattern").String(),
	}
	vectorResults, err := s.provider.VectorSearch(ctx, embedding, topK, filters)
	if err != nil {
		return nil, NewQueryError("vector search for attack patterns failed", err)
	}

	// Fetch full nodes and convert to AttackPattern
	patterns := make([]AttackPattern, 0, len(vectorResults))
	for _, vr := range vectorResults {
		// Query for full node data
		nodeQuery := NewNodeQuery().
			WithNodeTypes(NodeType("attack_pattern")).
			WithProperty("id", vr.NodeID.String())

		nodes, err := s.provider.QueryNodes(ctx, *nodeQuery)
		if err != nil || len(nodes) == 0 {
			continue
		}

		// Convert GraphNode to AttackPattern
		pattern := graphNodeToAttackPattern(nodes[0])
		patterns = append(patterns, pattern)
	}

	return patterns, nil
}

// FindSimilarFindings finds findings similar to the given finding.
// Uses vector search filtered to Finding node type.
func (s *DefaultGraphRAGStore) FindSimilarFindings(ctx context.Context, findingID string, topK int) ([]FindingNode, error) {
	// Parse finding ID
	id, err := types.ParseID(findingID)
	if err != nil {
		return nil, NewInvalidQueryError(fmt.Sprintf("invalid finding ID: %v", err))
	}

	// Fetch the source finding
	nodeQuery := NewNodeQuery().
		WithNodeTypes(NodeType("finding")).
		WithProperty("id", id.String())

	nodes, err := s.provider.QueryNodes(ctx, *nodeQuery)
	if err != nil || len(nodes) == 0 {
		return nil, NewNodeNotFoundError(findingID)
	}

	sourceFinding := nodes[0]
	if len(sourceFinding.Embedding) == 0 {
		return nil, NewQueryError("source finding has no embedding", nil)
	}

	// Execute vector search with Finding filter
	filters := map[string]any{
		"node_type": NodeType("finding").String(),
	}
	vectorResults, err := s.provider.VectorSearch(ctx, sourceFinding.Embedding, topK+1, filters)
	if err != nil {
		return nil, NewQueryError("vector search for similar findings failed", err)
	}

	// Convert to FindingNode, excluding the source finding
	findings := make([]FindingNode, 0, topK)
	for _, vr := range vectorResults {
		// Skip the source finding itself
		if vr.NodeID == id {
			continue
		}

		// Query for full node data
		nodeQuery := NewNodeQuery().
			WithNodeTypes(NodeType("finding")).
			WithProperty("id", vr.NodeID.String())

		nodes, err := s.provider.QueryNodes(ctx, *nodeQuery)
		if err != nil || len(nodes) == 0 {
			continue
		}

		// Convert GraphNode to FindingNode
		finding := graphNodeToFindingNode(nodes[0])
		findings = append(findings, finding)

		if len(findings) >= topK {
			break
		}
	}

	return findings, nil
}

// GetAttackChains discovers attack chains (technique sequences) from a starting technique.
// Traverses USES_TECHNIQUE relationships to find multi-step attack patterns.
func (s *DefaultGraphRAGStore) GetAttackChains(ctx context.Context, techniqueID string, maxDepth int) ([]AttackChain, error) {
	// Query for the starting technique node
	nodeQuery := NewNodeQuery().
		WithNodeTypes(NodeType("technique")).
		WithProperty("technique_id", techniqueID)

	nodes, err := s.provider.QueryNodes(ctx, *nodeQuery)
	if err != nil || len(nodes) == 0 {
		return nil, NewNodeNotFoundError(techniqueID)
	}

	startNode := nodes[0]

	// Traverse graph from this technique following USES_TECHNIQUE relationships
	filters := TraversalFilters{
		AllowedRelations: []RelationType{RelationType("uses_technique")},
		AllowedNodeTypes: []NodeType{NodeType("technique"), NodeType("attack_pattern")},
	}

	traversedNodes, err := s.provider.TraverseGraph(ctx, startNode.ID.String(), maxDepth, filters)
	if err != nil {
		return nil, NewQueryError("graph traversal failed", err)
	}

	// Build attack chains from traversed nodes
	chains := buildAttackChainsFromNodes(startNode, traversedNodes, maxDepth)

	return chains, nil
}

// StoreFinding stores a security finding with contextual relationships.
// Creates the finding node and relationships to targets/techniques.
func (s *DefaultGraphRAGStore) StoreFinding(ctx context.Context, finding FindingNode) error {
	// Generate embedding from description
	if len(finding.Embedding) == 0 && finding.Description != "" {
		embedding, err := s.embedder.Embed(ctx, finding.Description)
		if err != nil {
			return NewEmbeddingError("failed to generate embedding for finding", err, true)
		}
		finding.Embedding = embedding
	}

	// Convert to GraphNode
	node := finding.ToGraphNode()

	// Store the node
	if err := s.provider.StoreNode(ctx, *node); err != nil {
		return NewQueryError("failed to store finding node", err)
	}

	// Create DISCOVERED_ON relationship if target is specified
	if finding.TargetID != nil {
		rel := NewRelationship(
			finding.ID,
			*finding.TargetID,
			RelationType("discovered_on"),
		).WithProperty(sdkgraphrag.PropSeverity, finding.Severity)

		if err := s.provider.StoreRelationship(ctx, *rel); err != nil {
			// Don't fail the entire operation
			// Log error in production
		}
	}

	return nil
}

// StoreFindingWithRun stores a finding and links it to a mission run.
// Creates the finding node and a DISCOVERED_IN relationship to the run.
func (s *DefaultGraphRAGStore) StoreFindingWithRun(ctx context.Context, finding FindingNode, runID types.ID) error {
	// Store the finding first
	if err := s.StoreFinding(ctx, finding); err != nil {
		return fmt.Errorf("failed to store finding: %w", err)
	}

	// Create DISCOVERED_IN relationship to the run
	rel := NewRelationship(
		finding.ID,
		runID,
		RelationType("DISCOVERED_IN"),
	).WithProperty("discovered_at", time.Now().Format(time.RFC3339))

	if err := s.provider.StoreRelationship(ctx, *rel); err != nil {
		return NewRelationshipError("failed to create DISCOVERED_IN relationship", err)
	}

	return nil
}

// GetRelatedFindings retrieves findings related to the given finding.
// Traverses SIMILAR_TO and other relationship types.
func (s *DefaultGraphRAGStore) GetRelatedFindings(ctx context.Context, findingID string) ([]FindingNode, error) {
	// Parse finding ID
	id, err := types.ParseID(findingID)
	if err != nil {
		return nil, NewInvalidQueryError(fmt.Sprintf("invalid finding ID: %v", err))
	}

	// Query for relationships from this finding
	relQuery := NewRelQuery().
		WithFromID(id).
		WithTypes(RelationType("similar_to"), RelationType("related_to"))

	rels, err := s.provider.QueryRelationships(ctx, *relQuery)
	if err != nil {
		return nil, NewQueryError("failed to query relationships", err)
	}

	// Fetch related finding nodes
	findings := make([]FindingNode, 0, len(rels))
	for _, rel := range rels {
		// Query for the target node
		nodeQuery := NewNodeQuery().
			WithNodeTypes(NodeType("finding")).
			WithProperty("id", rel.ToID.String())

		nodes, err := s.provider.QueryNodes(ctx, *nodeQuery)
		if err != nil || len(nodes) == 0 {
			continue
		}

		// Convert GraphNode to FindingNode
		finding := graphNodeToFindingNode(nodes[0])
		findings = append(findings, finding)
	}

	return findings, nil
}

// GetNode retrieves a single node by ID.
// Returns the node if found, or an error if not found or query fails.
func (s *DefaultGraphRAGStore) GetNode(ctx context.Context, nodeID types.ID) (*GraphNode, error) {
	// Use the provider's QueryNodes method to fetch the node by ID
	nodeQuery := NewNodeQuery().WithProperty("id", nodeID.String())

	nodes, err := s.provider.QueryNodes(ctx, *nodeQuery)
	if err != nil {
		return nil, NewQueryError("failed to query node", err)
	}

	if len(nodes) == 0 {
		return nil, NewNodeNotFoundError(nodeID.String())
	}

	return &nodes[0], nil
}

// StoreRelationshipOnly stores a relationship without creating any nodes.
// Used when both nodes already exist and only a relationship needs to be added.
func (s *DefaultGraphRAGStore) StoreRelationshipOnly(ctx context.Context, rel Relationship) error {
	// Validate the relationship
	if err := rel.Validate(); err != nil {
		return NewInvalidQueryError(fmt.Sprintf("invalid relationship: %v", err))
	}

	// Store relationship directly via provider
	if err := s.provider.StoreRelationship(ctx, rel); err != nil {
		return NewRelationshipError("failed to store relationship", err)
	}

	return nil
}

// TraverseGraph walks the graph from startNodeID following relationships that
// match the provided filters. Delegates to the underlying provider's TraverseGraph
// which performs the actual Neo4j/Cypher traversal.
func (s *DefaultGraphRAGStore) TraverseGraph(ctx context.Context, startNodeID string, maxDepth int, filters TraversalFilters) ([]GraphNode, error) {
	nodes, err := s.provider.TraverseGraph(ctx, startNodeID, maxDepth, filters)
	if err != nil {
		return nil, NewQueryError("graph traversal failed", err)
	}
	return nodes, nil
}

// Health returns the current health status of the GraphRAG store.
// Aggregates health from provider and embedder.
func (s *DefaultGraphRAGStore) Health(ctx context.Context) types.HealthStatus {
	// Check provider health
	providerHealth := s.provider.Health(ctx)
	if providerHealth.IsUnhealthy() {
		return types.Unhealthy(fmt.Sprintf("provider unhealthy: %s", providerHealth.Message))
	}

	// Check embedder health
	embedderHealth := s.embedder.Health(ctx)
	if embedderHealth.IsUnhealthy() {
		return types.Unhealthy(fmt.Sprintf("embedder unhealthy: %s", embedderHealth.Message))
	}

	// If either is degraded, return degraded
	if providerHealth.IsDegraded() || embedderHealth.IsDegraded() {
		return types.Degraded("GraphRAG store is degraded")
	}

	return types.Healthy("GraphRAG store is healthy")
}

// Close releases all resources and closes connections.
func (s *DefaultGraphRAGStore) Close() error {
	if s.provider != nil {
		return s.provider.Close()
	}
	return nil
}

// NewGraphRAGStoreWithProvider creates a new GraphRAGStore with an injected provider.
// This is the recommended constructor when GraphRAG is enabled, as it allows
// external creation of the provider via provider.NewProvider() to avoid import cycles.
//
// Usage:
//
//	import "github.com/zero-day-ai/gibson/internal/graphrag/provider"
//
//	prov, err := provider.NewProvider(config)
//	if err != nil {
//	    return err
//	}
//	store, err := NewGraphRAGStoreWithProvider(config, embedder, prov)
//
// Parameters:
//   - config: GraphRAG configuration
//   - emb: Embedder for generating embeddings
//   - prov: Pre-created GraphRAGProvider (from provider.NewProvider)
//
// Returns a GraphRAGStore ready for use, or an error if initialization fails.
func NewGraphRAGStoreWithProvider(config GraphRAGConfig, emb embedder.Embedder, prov GraphRAGProvider) (GraphRAGStore, error) {
	// Apply defaults and validate config
	config.ApplyDefaults()
	if err := config.Validate(); err != nil {
		return nil, NewConfigError("invalid GraphRAG configuration", err)
	}

	// Validate embedder
	if emb == nil {
		return nil, NewConfigError("embedder cannot be nil", nil)
	}

	// Validate provider
	if prov == nil {
		return nil, NewConfigError("provider cannot be nil", nil)
	}

	// Create query processor (nil logger defaults to slog.Default())
	processor, err := NewQueryProcessorFromConfig(config, emb, nil)
	if err != nil {
		return nil, NewConfigError("failed to create query processor", err)
	}

	return &DefaultGraphRAGStore{
		provider:  prov,
		processor: processor,
		embedder:  emb,
		config:    config,
	}, nil
}

// Helper functions for converting between types

// graphNodeToAttackPattern converts a GraphNode to an AttackPattern.
func graphNodeToAttackPattern(node GraphNode) AttackPattern {
	pattern := AttackPattern{
		ID:          node.ID,
		TechniqueID: node.GetStringProperty("technique_id"),
		Name:        node.GetStringProperty(sdkgraphrag.PropName),
		Description: node.GetStringProperty(sdkgraphrag.PropDescription),
		Embedding:   node.Embedding,
		CreatedAt:   node.CreatedAt,
		UpdatedAt:   node.UpdatedAt,
	}

	// Extract arrays from properties
	if tactics, ok := node.Properties[sdkgraphrag.PropTactics].([]string); ok {
		pattern.Tactics = tactics
	} else if tactics, ok := node.Properties[sdkgraphrag.PropTactics].([]interface{}); ok {
		pattern.Tactics = make([]string, 0, len(tactics))
		for _, t := range tactics {
			if str, ok := t.(string); ok {
				pattern.Tactics = append(pattern.Tactics, str)
			}
		}
	}

	if platforms, ok := node.Properties[sdkgraphrag.PropPlatforms].([]string); ok {
		pattern.Platforms = platforms
	} else if platforms, ok := node.Properties[sdkgraphrag.PropPlatforms].([]interface{}); ok {
		pattern.Platforms = make([]string, 0, len(platforms))
		for _, p := range platforms {
			if str, ok := p.(string); ok {
				pattern.Platforms = append(pattern.Platforms, str)
			}
		}
	}

	return pattern
}

// graphNodeToFindingNode converts a GraphNode to a FindingNode.
func graphNodeToFindingNode(node GraphNode) FindingNode {
	finding := FindingNode{
		ID:          node.ID,
		Title:       node.GetStringProperty("title"),
		Description: node.GetStringProperty(sdkgraphrag.PropDescription),
		Severity:    node.GetStringProperty(sdkgraphrag.PropSeverity),
		Category:    node.GetStringProperty(sdkgraphrag.PropCategory),
		Embedding:   node.Embedding,
		CreatedAt:   node.CreatedAt,
		UpdatedAt:   node.UpdatedAt,
	}

	// Extract confidence
	if conf, ok := node.Properties[sdkgraphrag.PropConfidence].(float64); ok {
		finding.Confidence = conf
	}

	// Extract mission ID
	if node.MissionID != nil {
		finding.MissionID = *node.MissionID
	}

	// Extract target ID
	if targetIDStr := node.GetStringProperty("target_id"); targetIDStr != "" {
		if targetID, err := types.ParseID(targetIDStr); err == nil {
			finding.TargetID = &targetID
		}
	}

	return finding
}

// buildAttackChainsFromNodes constructs attack chains from traversed nodes.
// Analyzes the graph structure to identify technique sequences.
func buildAttackChainsFromNodes(startNode GraphNode, traversedNodes []GraphNode, maxDepth int) []AttackChain {
	// SIMPLIFIED: Current implementation builds a single linear attack chain from traversed nodes
	// without analyzing actual graph paths, relationship sequences, or alternative attack paths.
	// Production implementation would:
	// 1. Use path analysis algorithms (e.g., DFS/BFS) to discover all possible attack chains
	// 2. Implement chain discovery algorithms to identify multi-step attack sequences
	// 3. Analyze relationship properties to determine valid technique sequences
	// 4. Calculate chain confidence scores based on evidence and relationship strength
	// 5. Return multiple chains representing different attack paths through the graph
	// 6. Filter and rank chains by likelihood, severity, and completeness

	if len(traversedNodes) == 0 {
		return []AttackChain{}
	}

	// Create a simple chain from the traversed nodes
	chain := NewAttackChain("Attack Chain", types.NewID())
	chain.Severity = "medium"

	// Add starting technique as first step
	chain.AddStep(AttackStep{
		TechniqueID: startNode.GetStringProperty("technique_id"),
		NodeID:      startNode.ID,
		Description: startNode.GetStringProperty("description"),
		Evidence:    []types.ID{},
		Confidence:  1.0,
	})

	// Add subsequent techniques from traversed nodes
	for i, node := range traversedNodes {
		if i >= maxDepth {
			break
		}
		if node.HasLabel(NodeType("technique")) {
			chain.AddStep(AttackStep{
				TechniqueID: node.GetStringProperty("technique_id"),
				NodeID:      node.ID,
				Description: node.GetStringProperty("description"),
				Evidence:    []types.ID{},
				Confidence:  0.8, // Decreasing confidence with depth
			})
		}
	}

	// Return the constructed chain
	return []AttackChain{*chain}
}
