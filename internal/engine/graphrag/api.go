// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package graphrag

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/engine/memory/embedder"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// GraphRAGStore provides a unified, high-level READ interface over the
// knowledge graph: vector search, graph traversal, and hybrid queries.
//
// It has no write methods. The projector is the graph's sole writer
// (ADR-0012); the store/provider write half was removed in gibson#1322 once
// sdk#451 took ComponentService/StoreNode off the wire.
//
// Thread-safety: All implementations must be safe for concurrent access.
type GraphRAGStore interface {
	// Query executes a hybrid GraphRAG query combining vector similarity and graph traversal.
	// This is the primary query method for semantic + structural retrieval.
	Query(ctx context.Context, query GraphRAGQuery) ([]GraphRAGResult, error)

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

	// GetRelatedFindings retrieves findings related to the given finding.
	// Traverses SIMILAR_TO and other relationship types to find connected findings.
	// Useful for correlation and deduplication analysis.
	GetRelatedFindings(ctx context.Context, findingID string) ([]FindingNode, error)

	// GetNode retrieves a single node by ID.
	// Returns the node if found, or an error if not found or query fails.
	GetNode(ctx context.Context, nodeID types.ID) (*GraphNode, error)

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

// NewGraphRAGStoreWithProvider creates a new GraphRAGStore with an injected provider.
// This is the recommended constructor when GraphRAG is enabled, as it allows
// external creation of the provider via provider.NewProvider() to avoid import cycles.
//
// Parameters:
//   - config: GraphRAG configuration
//   - emb: Embedder for generating embeddings
//   - prov: Pre-created GraphRAGProvider (from provider.NewProvider)
//
// Returns a GraphRAGStore ready for use, or an error if initialization fails.
// NewGraphRAGStoreForOwnedProvider builds a store over a provider whose
// connections the CALLER owns — the per-request, datapool-backed case
// (gibson#1190).
//
// It differs from NewGraphRAGStoreWithProvider in one way: it does not validate
// connection configuration. GraphRAGConfig.Validate requires a Neo4j URI,
// username and password, which describe how the store would dial for itself. A
// session-backed provider never dials; the tenant's connection arrives already
// open. Passing placeholder credentials to satisfy a validator that governs a
// code path this store does not take would be a lie in the config, and the
// first person to read it would believe it.
//
// Query configuration IS still validated and defaulted — that governs the
// pipeline this store really runs.
func NewGraphRAGStoreForOwnedProvider(
	queryConfig QueryConfig, emb embedder.Embedder, prov GraphRAGProvider,
) (GraphRAGStore, error) {
	if emb == nil {
		return nil, NewConfigError("embedder cannot be nil", nil)
	}
	if prov == nil {
		return nil, NewConfigError("provider cannot be nil", nil)
	}

	config := GraphRAGConfig{Query: queryConfig}
	config.Query.ApplyDefaults()

	pipeline, err := NewQueryPipelineFromConfig(config, emb, nil)
	if err != nil {
		return nil, NewConfigError("failed to create query pipeline", err)
	}

	return &DefaultGraphRAGStore{
		provider:  prov,
		processor: pipeline,
		embedder:  emb,
		config:    config,
	}, nil
}

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

	// Create query pipeline (nil logger defaults to slog.Default())
	pipeline, err := NewQueryPipelineFromConfig(config, emb, nil)
	if err != nil {
		return nil, NewConfigError("failed to create query pipeline", err)
	}

	return &DefaultGraphRAGStore{
		provider:  prov,
		processor: pipeline,
		embedder:  emb,
		config:    config,
	}, nil
}
