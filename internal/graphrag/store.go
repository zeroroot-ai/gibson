package graphrag

// This file owns the DefaultGraphRAGStore concrete impl plus the lifecycle
// methods (Store / StoreWithoutEmbedding / StoreBatch / Query / GetNode /
// StoreRelationshipOnly / TraverseGraph / Health / Close).
//
// Domain-specific operations live in:
//   - store_findings.go: StoreFinding, StoreFindingWithRun, FindSimilarFindings, GetRelatedFindings
//   - store_attacks.go:  StoreAttackPattern, FindSimilarAttacks, GetAttackChains
//
// The public GraphRAGStore interface lives in api.go.

import (
	"context"
	"fmt"

	"github.com/zero-day-ai/gibson/internal/memory/embedder"
	"github.com/zero-day-ai/gibson/internal/types"
)

// DefaultGraphRAGStore implements GraphRAGStore using a provider and pipeline.
type DefaultGraphRAGStore struct {
	provider  GraphRAGProvider
	processor QueryPipeline
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
// Delegates to the QueryPipeline for full pipeline execution.
func (s *DefaultGraphRAGStore) Query(ctx context.Context, query GraphRAGQuery) ([]GraphRAGResult, error) {
	return s.processor.ProcessQuery(ctx, query, s.provider)
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
