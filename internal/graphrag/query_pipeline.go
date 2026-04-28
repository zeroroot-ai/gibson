package graphrag

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zero-day-ai/gibson/internal/memory/embedder"
)

// QueryPipeline orchestrates the full GraphRAG query pipeline.
// Combines embedding generation, vector search, graph traversal,
// and hybrid reranking into a single high-level interface.
//
// Pipeline stages:
// 1. Embedding: Generate query embedding (if not provided)
// 2. Vector Search: Find semantically similar nodes
// 3. Graph Expansion: Traverse graph from vector results
// 4. Merge & Rerank: Combine and score hybrid results
//
// Thread-safety: Implementations must be safe for concurrent queries.
type QueryPipeline interface {
	// ProcessQuery executes the full GraphRAG query pipeline.
	// Returns ranked results combining vector similarity and graph structure.
	//
	// The processor handles:
	// - Query validation
	// - Embedding generation (if query.Text is set)
	// - Vector similarity search
	// - Graph traversal from top vector results
	// - Result merging and reranking
	// - Graceful degradation (returns vector-only results if graph fails)
	//
	// Returns an error if the query is invalid or both vector and graph fail.
	ProcessQuery(ctx context.Context, query GraphRAGQuery, provider GraphRAGProvider) ([]GraphRAGResult, error)
}

// DefaultQueryPipeline implements QueryPipeline with the standard pipeline.
// Uses an Embedder for query encoding and a MergeReranker for hybrid scoring.
type DefaultQueryPipeline struct {
	embedder embedder.Embedder // For generating query embeddings
	reranker MergeReranker     // For merging and scoring results
	logger   *slog.Logger      // For logging warnings and debug info
}

// NewDefaultQueryPipeline creates a new query processor.
// The embedder is used to generate embeddings from query text.
// The reranker combines vector and graph results with configured weights.
// The logger is used for warnings and debug info (pass slog.Default() if needed).
func NewDefaultQueryPipeline(emb embedder.Embedder, reranker MergeReranker, logger *slog.Logger) *DefaultQueryPipeline {
	if logger == nil {
		logger = slog.Default()
	}
	return &DefaultQueryPipeline{
		embedder: emb,
		reranker: reranker,
		logger:   logger,
	}
}

// NewQueryPipelineFromConfig creates a QueryPipeline from GraphRAG configuration.
// Automatically configures the reranker weights from config.Query settings.
// The logger is used for warnings and debug info (pass slog.Default() if needed).
func NewQueryPipelineFromConfig(config GraphRAGConfig, emb embedder.Embedder, logger *slog.Logger) (*DefaultQueryPipeline, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// Apply defaults to query config
	config.Query.ApplyDefaults()

	// Validate query config
	if err := config.Query.Validate(); err != nil {
		return nil, NewConfigError("invalid query config", err)
	}

	// Create reranker with weights from config
	reranker := NewDefaultMergeReranker(
		config.Query.VectorWeight,
		config.Query.GraphWeight,
	)

	return &DefaultQueryPipeline{
		embedder: emb,
		reranker: reranker,
		logger:   logger,
	}, nil
}

// ProcessQuery executes the full GraphRAG hybrid query pipeline.
//
// Query routing:
// - If query has NodeTypes but no Text/Embedding → structured query (direct Cypher)
// - If query has Text/Embedding but no NodeTypes → semantic query (vector search)
// - If query has both → hybrid query (vector search + type filter)
//
// Pipeline for semantic/hybrid queries:
// 1. Validate query
// 2. Generate embedding (if query.Text is set)
// 3. Execute vector search
// 4. Expand results via graph traversal
// 5. Merge and rerank results
// 6. Apply filters and return top-K
//
// Graceful degradation:
// - If graph traversal fails, returns vector-only results
// - If vector search fails but embedding exists, attempts graph-only search
// - Returns error only if both stages fail or query is invalid
func (p *DefaultQueryPipeline) ProcessQuery(ctx context.Context, query GraphRAGQuery, provider GraphRAGProvider) ([]GraphRAGResult, error) {
	// Step 1: Validate the query
	if err := query.Validate(); err != nil {
		return nil, NewInvalidQueryError(fmt.Sprintf("query validation failed: %v", err))
	}

	// Step 2: Check for explicit routing flags (SDK v0.26.0+)
	if query.ForceStructuredOnly {
		// Explicit structured-only query: skip vector search entirely
		return p.processStructuredQuery(ctx, query, provider)
	}

	// Step 3: Route query based on type
	// If query has NodeTypes but no semantic content (Text/Embedding), use direct graph query
	isStructuredQuery := len(query.NodeTypes) > 0 && query.Text == "" && len(query.Embedding) == 0
	if isStructuredQuery {
		return p.processStructuredQuery(ctx, query, provider)
	}

	// Continue with semantic/hybrid query pipeline...
	// Step 2: Generate embedding if needed (query has Text but no Embedding)
	queryEmbedding := query.Embedding
	if query.Text != "" && len(query.Embedding) == 0 {
		emb, err := p.embedder.Embed(ctx, query.Text)
		if err != nil {
			return nil, NewEmbeddingError(fmt.Sprintf("failed to generate query embedding: %v", err), err, false)
		}
		queryEmbedding = emb
	}

	// Prepare filters for vector search
	vectorFilters := make(map[string]any)

	// Apply mission ID filter if provided
	if query.MissionID != nil {
		vectorFilters["mission_id"] = query.MissionID.String()
	}

	if len(query.NodeTypes) > 0 {
		// Convert NodeTypes to strings for filter
		nodeTypeStrs := make([]string, len(query.NodeTypes))
		for i, nt := range query.NodeTypes {
			nodeTypeStrs[i] = nt.String()
		}
		vectorFilters["node_type"] = nodeTypeStrs
	}

	// Step 4: Execute vector similarity search
	vectorResults, err := provider.VectorSearch(ctx, queryEmbedding, query.TopK, vectorFilters)
	if err != nil {
		return nil, NewQueryError(fmt.Sprintf("vector search failed: %v", err), err)
	}

	// If no vector results but NodeTypes are specified, fall back to structured query.
	// This handles the case where nodes exist in the graph but don't have embeddings
	// (e.g., hosts/ports from network discovery that were stored without semantic content).
	// Skip fallback if ForceSemanticOnly is set (explicit semantic-only mode).
	if len(vectorResults) == 0 {
		if len(query.NodeTypes) > 0 && !query.ForceSemanticOnly {
			p.logger.Debug("vector search returned 0 results, falling back to structured query",
				"node_types", query.NodeTypes,
				"query_text", query.Text)
			return p.processStructuredQuery(ctx, query, provider)
		}
		// No NodeTypes specified or ForceSemanticOnly set, return empty
		return []GraphRAGResult{}, nil
	}

	// Apply MinScore filter to vector results
	filteredVectorResults := make([]VectorResult, 0, len(vectorResults))
	for _, vr := range vectorResults {
		if vr.Similarity >= query.MinScore {
			filteredVectorResults = append(filteredVectorResults, vr)
		}
	}

	// If all results filtered out by MinScore, return empty
	if len(filteredVectorResults) == 0 {
		return []GraphRAGResult{}, nil
	}

	// Step 5: Expand graph from vector results (if MaxHops > 0)
	var graphResults []GraphNode
	if query.MaxHops > 0 {
		graphResults, err = p.expandGraph(ctx, filteredVectorResults, query, provider)
		if err != nil {
			// Graceful degradation: if graph expansion fails, continue with vector-only results
			p.logger.Warn("graph expansion failed, falling back to vector-only results",
				"error", err)
			return p.vectorOnlyResults(ctx, filteredVectorResults, provider, query)
		}
	} else {
		// MaxHops == 0 means vector-only query
		return p.vectorOnlyResults(ctx, filteredVectorResults, provider, query)
	}

	// Step 6: Merge and rerank results
	merged := p.reranker.Merge(filteredVectorResults, graphResults)
	reranked := p.reranker.Rerank(merged, query.Text, query.TopK)

	// Step 7: Apply node type filter if specified
	if len(query.NodeTypes) > 0 {
		reranked = p.filterByNodeType(reranked, query.NodeTypes)
	}

	// Step 8: Ensure we don't exceed TopK
	if len(reranked) > query.TopK {
		reranked = reranked[:query.TopK]
	}

	return reranked, nil
}

// expandGraph performs graph traversal from vector search results.
// Expands the knowledge graph to discover related nodes not found by vector search.
//
// Strategy:
// - Start from each top vector result (up to first 5 to limit expansion)
// - Traverse up to MaxHops depth
// - Apply traversal filters
// - Collect all discovered nodes
// - Deduplicate across starting points
func (p *DefaultQueryPipeline) expandGraph(
	ctx context.Context,
	vectorResults []VectorResult,
	query GraphRAGQuery,
	provider GraphRAGProvider,
) ([]GraphNode, error) {
	// Limit expansion starting points to avoid exponential blowup
	// Use top 5 vector results as starting points (configurable in future)
	maxStartPoints := 5
	if len(vectorResults) < maxStartPoints {
		maxStartPoints = len(vectorResults)
	}

	// Track discovered nodes to avoid duplicates
	discoveredNodes := make(map[string]GraphNode)

	// Expand from each starting point
	for i := 0; i < maxStartPoints; i++ {
		startNodeID := vectorResults[i].NodeID.String()

		// Perform graph traversal
		nodes, err := provider.TraverseGraph(ctx, startNodeID, query.MaxHops, query.Filters)
		if err != nil {
			// Partial failure: log and continue with other starting points
			p.logger.Warn("graph traversal failed for starting point, continuing with others",
				"start_node_id", startNodeID,
				"error", err)
			continue
		}

		// Add nodes to discovered set (deduplication)
		for _, node := range nodes {
			nodeID := node.ID.String()
			if _, exists := discoveredNodes[nodeID]; !exists {
				discoveredNodes[nodeID] = node
			}
		}
	}

	// Convert map to slice
	results := make([]GraphNode, 0, len(discoveredNodes))
	for _, node := range discoveredNodes {
		results = append(results, node)
	}

	return results, nil
}

// vectorOnlyResults creates GraphRAGResults from vector search results only.
// Used when graph traversal is disabled (MaxHops=0) or fails.
//
// Fetches full node data from provider for each vector result.
func (p *DefaultQueryPipeline) vectorOnlyResults(
	ctx context.Context,
	vectorResults []VectorResult,
	provider GraphRAGProvider,
	query GraphRAGQuery,
) ([]GraphRAGResult, error) {
	results := make([]GraphRAGResult, 0, len(vectorResults))

	for _, vr := range vectorResults {
		// Fetch full node data
		node, err := provider.QueryNodes(ctx, *NewNodeQuery().WithProperty("id", vr.NodeID.String()))
		if err != nil || len(node) == 0 {
			// Skip nodes we can't fetch
			continue
		}

		// Create result with vector score only
		result := NewGraphRAGResult(node[0], vr.Similarity, 0.0)
		result.ComputeScore(1.0, 0.0) // Pure vector score
		results = append(results, *result)
	}

	// Apply node type filter if specified
	if len(query.NodeTypes) > 0 {
		results = p.filterByNodeType(results, query.NodeTypes)
	}

	// Limit to TopK
	if len(results) > query.TopK {
		results = results[:query.TopK]
	}

	return results, nil
}

// filterByNodeType filters results to only include specified node types.
func (p *DefaultQueryPipeline) filterByNodeType(results []GraphRAGResult, nodeTypes []NodeType) []GraphRAGResult {
	// Create a set of allowed types for O(1) lookup
	allowedTypes := make(map[NodeType]bool)
	for _, nt := range nodeTypes {
		allowedTypes[nt] = true
	}

	filtered := make([]GraphRAGResult, 0, len(results))
	for _, result := range results {
		// Check if node has any of the allowed labels
		hasAllowedType := false
		for _, label := range result.Node.Labels {
			if allowedTypes[label] {
				hasAllowedType = true
				break
			}
		}
		if hasAllowedType {
			filtered = append(filtered, result)
		}
	}

	return filtered
}

// QueryPipelineOptions contains advanced options for query processing.
// Allows fine-tuning of the pipeline behavior per-query.
type QueryPipelineOptions struct {
	// SkipEmbedding skips embedding generation (query must have pre-computed embedding).
	SkipEmbedding bool

	// SkipGraph disables graph traversal (vector-only query).
	SkipGraph bool

	// MaxGraphStartPoints limits the number of vector results to expand from.
	MaxGraphStartPoints int

	// EnableGracefulDegradation allows falling back to vector-only on graph errors.
	EnableGracefulDegradation bool

	// FetchFullNodes fetches complete node data (including all properties).
	FetchFullNodes bool

	// IncludeMetadata includes query metadata in results.
	IncludeMetadata bool
}

// DefaultPipelineOptions returns sensible defaults for query processing.
func DefaultPipelineOptions() QueryPipelineOptions {
	return QueryPipelineOptions{
		SkipEmbedding:             false,
		SkipGraph:                 false,
		MaxGraphStartPoints:       5,
		EnableGracefulDegradation: true,
		FetchFullNodes:            true,
		IncludeMetadata:           false,
	}
}

// WithOptions creates a new processor with custom pipeline options.
// This allows per-query customization of the processing pipeline.
func (p *DefaultQueryPipeline) WithOptions(opts QueryPipelineOptions) *DefaultQueryPipeline {
	// For now, return the same processor
	// In a production implementation, we might create a wrapper that applies options
	return p
}

// ValidateProvider checks if the provider is properly configured for queries.
// Should be called before processing queries to ensure provider is ready.
func ValidateProvider(ctx context.Context, provider GraphRAGProvider) error {
	if provider == nil {
		return NewProviderUnavailableError("unknown", fmt.Errorf("provider cannot be nil"))
	}

	// Check provider health
	health := provider.Health(ctx)
	if health.IsUnhealthy() {
		return NewProviderUnavailableError("unknown", fmt.Errorf("provider is unhealthy: %s", health.Message))
	}

	return nil
}

// EnsureEmbedderHealth checks if the embedder is operational.
// Returns an error if the embedder is not healthy.
func (p *DefaultQueryPipeline) EnsureEmbedderHealth(ctx context.Context) error {
	if p.embedder == nil {
		return NewEmbeddingError("embedder is not configured", nil, false)
	}

	health := p.embedder.Health(ctx)
	if health.IsUnhealthy() {
		return NewEmbeddingError(fmt.Sprintf("embedder is unhealthy: %s", health.Message), nil, false)
	}

	return nil
}

// processStructuredQuery handles queries that filter by NodeTypes without semantic search.
// This bypasses vector search entirely and uses direct Cypher queries against Neo4j.
//
// Use cases:
// - "Get all hosts" → NodeTypes=["host"]
// - "Get all ports for mission X" → NodeTypes=["port"], MissionID=X
// - "Get hosts and services" → NodeTypes=["host", "service"]
//
// This is more efficient than vector search for structured data retrieval
// where semantic similarity is not needed.
func (p *DefaultQueryPipeline) processStructuredQuery(ctx context.Context, query GraphRAGQuery, provider GraphRAGProvider) ([]GraphRAGResult, error) {
	p.logger.Debug("processing structured query (no vector search)",
		"node_types", query.NodeTypes,
		"top_k", query.TopK,
		"mission_id", query.MissionID,
		"mission_run_id", query.MissionRunID)

	// Build NodeQuery from GraphRAGQuery
	nodeQuery := NewNodeQuery().
		WithNodeTypes(query.NodeTypes...).
		WithLimit(query.TopK)

	// Apply mission filter if specified
	if query.MissionID != nil {
		nodeQuery.WithMission(*query.MissionID)
	}

	// Apply mission run ID for mission-scoped queries
	if query.MissionRunID != "" {
		nodeQuery.WithMissionRunID(query.MissionRunID)
	}
	if query.MissionName != "" {
		nodeQuery.WithMissionName(query.MissionName)
	}

	// Execute direct graph query
	nodes, err := provider.QueryNodes(ctx, *nodeQuery)
	if err != nil {
		return nil, NewQueryError(fmt.Sprintf("structured query failed: %v", err), err)
	}

	p.logger.Debug("structured query completed",
		"results_count", len(nodes))

	// Convert GraphNodes to GraphRAGResults
	// Score is 1.0 for all results (no ranking in structured queries)
	results := make([]GraphRAGResult, len(nodes))
	for i, node := range nodes {
		result := NewGraphRAGResult(node, 1.0, 1.0) // Full score for direct matches
		result.ComputeScore(0.5, 0.5)               // Equal weights since no semantic component
		results[i] = *result
	}

	// Apply TopK limit
	if len(results) > query.TopK {
		results = results[:query.TopK]
	}

	return results, nil
}
