package graphrag

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/memory/embedder"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// GraphRAGStore provides a unified, high-level interface for GraphRAG operations.
// It orchestrates the full GraphRAG stack: graph storage, vector search, and hybrid queries.
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

// NewGraphRAGStoreForSession creates a GraphRAGStore backed by a pre-opened session provider.
// Unlike NewGraphRAGStoreWithProvider, it does NOT validate Neo4j URI/Username/Password
// because the session is already open (from datapool.Conn.Neo4j). This is the per-call
// construction path used by GraphRAGBridgeAdapter.
//
// The config's Neo4j fields are ignored; only the query pipeline defaults (TopK, weights,
// etc.) are applied via ApplyDefaults. All other validation (provider type, vector, embedder)
// is performed normally.
func NewGraphRAGStoreForSession(emb embedder.Embedder, prov GraphRAGProvider) (GraphRAGStore, error) {
	if emb == nil {
		return nil, NewConfigError("embedder cannot be nil", nil)
	}
	if prov == nil {
		return nil, NewConfigError("provider cannot be nil", nil)
	}

	// Build a minimal config sufficient for the query pipeline. Neo4j fields are
	// not required here because the provider is already session-backed.
	cfg := GraphRAGConfig{
		Provider: "neo4j",
		Vector: VectorConfig{
			IndexType:  "hnsw",
			Dimensions: emb.Dimensions(),
			Metric:     "cosine",
		},
		Embedder: EmbedderConfig{
			Provider:   "native",
			Dimensions: emb.Dimensions(),
		},
	}
	cfg.Query.ApplyDefaults()

	pipeline, err := NewQueryPipelineFromConfig(cfg, emb, nil)
	if err != nil {
		return nil, NewConfigError("failed to create query pipeline for session store", err)
	}

	return &DefaultGraphRAGStore{
		provider:  prov,
		processor: pipeline,
		embedder:  emb,
		config:    cfg,
	}, nil
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
