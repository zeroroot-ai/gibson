// Package graphrag provides hybrid graph + semantic search capabilities for Gibson's security knowledge graph.
//
// GraphRAG combines graph database storage (Neo4j) with vector similarity search to enable
// powerful knowledge retrieval. It supports storing security findings, attack patterns, and
// MITRE ATT&CK techniques with automatic embedding generation and relationship tracking.
//
// # Architecture
//
// The GraphRAG package consists of several key layers:
//
//	┌─────────────────────────────────────────────────────────┐
//	│                   GraphRAGStore                         │
//	│  (High-level API for findings, patterns, queries)       │
//	└─────────────────────────────────────────────────────────┘
//	                          │
//	          ┌───────────────┴───────────────┐
//	          ▼                               ▼
//	┌──────────────────────┐      ┌──────────────────────┐
//	│   QueryProcessor     │      │  GraphRAGProvider    │
//	│  (Hybrid retrieval)  │◄─────┤  (Storage backend)   │
//	└──────────────────────┘      └──────────────────────┘
//	          │                               │
//	          ▼                               ▼
//	┌──────────────────────┐      ┌──────────────────────┐
//	│     Embedder         │      │    GraphClient       │
//	│  (Vector generation) │      │  (Neo4j/Vector DB)   │
//	└──────────────────────┘      └──────────────────────┘
//
// # Core Components
//
// GraphRAGStore: High-level interface for storing and querying security knowledge.
// Provides domain-specific methods for findings, attack patterns, and attack chains.
//
// GraphRAGProvider: Backend abstraction supporting multiple deployment modes:
//   - Local: In-memory graph and vector storage (development/testing)
//   - Cloud: Remote Neo4j + cloud vector database (production)
//   - Hybrid: Neo4j graph + local vector store (on-premise)
//   - Noop: No-op implementation for testing (zero overhead)
//
// QueryProcessor: Executes hybrid GraphRAG queries combining:
//   - Vector similarity search (semantic retrieval)
//   - Graph traversal (structural retrieval)
//   - Merge and reranking (unified results)
//
// # Configuration
//
// Configure GraphRAG with GraphRAGConfig:
//
//	config := GraphRAGConfig{
//	    Provider: ProviderConfig{
//	        Type: "cloud",  // "local", "cloud", "hybrid", "noop"
//	        Neo4j: Neo4jConfig{
//	            URI:      "neo4j://localhost:7687",
//	            Username: "neo4j",
//	            Password: "password",
//	        },
//	        VectorStore: VectorStoreConfig{
//	            Provider: "pgvector",  // "pgvector", "qdrant", "memory"
//	            Endpoint: "localhost:5432",
//	        },
//	    },
//	    Query: QueryConfig{
//	        DefaultTopK:    10,      // Number of results to return
//	        DefaultMaxHops: 3,       // Graph traversal depth
//	        MinScore:       0.7,     // Minimum similarity threshold
//	        VectorWeight:   0.6,     // Weight for vector similarity
//	        GraphWeight:    0.4,     // Weight for graph relevance
//	    },
//	}
//
// # Provider Modes
//
// Local Provider:
//   - In-memory graph and vector storage
//   - No external dependencies
//   - Ideal for development, testing, and demos
//   - Data lost on restart
//
// Cloud Provider:
//   - Remote Neo4j graph database
//   - Cloud vector database (pgvector, Qdrant, etc.)
//   - Production-ready with persistence
//   - Requires network connectivity
//
// Hybrid Provider:
//   - Neo4j for graph storage
//   - Local vector storage (in-memory or disk)
//   - On-premise deployment
//   - Network isolation for sensitive data
//
// Noop Provider:
//   - All operations succeed without storing data
//   - Zero performance overhead
//   - Used for testing when GraphRAG is disabled
//
// # Usage Examples
//
// Creating and Configuring GraphRAGStore:
//
//	import (
//	    "context"
//	    "github.com/zero-day-ai/gibson/internal/graphrag"
//	    "github.com/zero-day-ai/gibson/internal/memory/embedder"
//	)
//
//	func main() {
//	    ctx := context.Background()
//
//	    // Create embedder for generating vectors
//	    embedder := embedder.NewOpenAIEmbedder(apiKey)
//
//	    // Configure GraphRAG
//	    config := graphrag.GraphRAGConfig{
//	        Provider: graphrag.ProviderConfig{Type: "cloud"},
//	    }
//	    config.ApplyDefaults()
//
//	    // Create store with provider injection
//	    prov, err := provider.NewProvider(config)
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//	    store, err := graphrag.NewGraphRAGStoreWithProvider(config, embedder, prov)
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//	    defer store.Close()
//	}
//
// Storing Security Findings:
//
//	// Create a finding node
//	finding := graphrag.NewFindingNode(
//	    types.NewID(),
//	    "SQL Injection in Login Form",
//	    "Found SQL injection vulnerability in the login endpoint. "+
//	        "User input is directly concatenated into SQL query.",
//	    missionID,
//	)
//	finding.Severity = "high"
//	finding.Category = "injection"
//	finding.Confidence = 0.95
//
//	// Store the finding (embedding generated automatically)
//	if err := store.StoreFinding(ctx, *finding); err != nil {
//	    log.Printf("Failed to store finding: %v", err)
//	}
//
// Storing Attack Patterns:
//
//	// Create MITRE ATT&CK pattern
//	pattern := graphrag.NewAttackPattern(
//	    "T1566.001",  // Technique ID
//	    "Spearphishing Attachment",
//	    "Adversaries may send spearphishing emails with malicious attachments",
//	)
//	pattern.Tactics = []string{"Initial Access"}
//	pattern.Platforms = []string{"Linux", "macOS", "Windows", "Office 365"}
//	pattern.DataSources = []string{"Email Gateway", "File Monitoring"}
//
//	// Store the pattern
//	if err := store.StoreAttackPattern(ctx, *pattern); err != nil {
//	    log.Printf("Failed to store attack pattern: %v", err)
//	}
//
// Querying for Similar Content:
//
//	// Create a hybrid query
//	query := graphrag.NewGraphRAGQuery("SQL injection vulnerabilities").
//	    WithTopK(10).                  // Return top 10 results
//	    WithMaxHops(2).                // Traverse up to 2 hops in graph
//	    WithMinScore(0.75).            // Only return matches above 75% similarity
//	    WithNodeTypes(graphrag.NodeType("finding")).  // Filter to findings only
//	    WithFilters(map[string]any{
//	        "severity": "high",        // Additional property filters
//	    })
//
//	// Execute the query
//	results, err := store.Query(ctx, *query)
//	if err != nil {
//	    log.Printf("Query failed: %v", err)
//	    return
//	}
//
//	// Process results
//	for _, result := range results {
//	    fmt.Printf("Found: %s (score: %.2f)\n",
//	        result.Node.GetStringProperty("title"),
//	        result.Score)
//
//	    // Check if result came from vector search, graph traversal, or both
//	    if result.InVector && result.InGraph {
//	        fmt.Println("  → Found in both vector and graph search")
//	    } else if result.InVector {
//	        fmt.Println("  → Found via semantic similarity")
//	    } else if result.InGraph {
//	        fmt.Println("  → Found via graph traversal")
//	    }
//	}
//
// Finding Similar Findings:
//
//	// Find findings similar to a known finding
//	similar, err := store.FindSimilarFindings(ctx, findingID, 5)
//	if err != nil {
//	    log.Printf("Failed to find similar findings: %v", err)
//	    return
//	}
//
//	for _, finding := range similar {
//	    fmt.Printf("Similar: %s (category: %s, severity: %s)\n",
//	        finding.Title,
//	        finding.Category,
//	        finding.Severity)
//	}
//
// Getting Attack Chains:
//
//	// Discover multi-step attack chains starting from a technique
//	chains, err := store.GetAttackChains(ctx, "T1566", 5)
//	if err != nil {
//	    log.Printf("Failed to get attack chains: %v", err)
//	    return
//	}
//
//	for i, chain := range chains {
//	    fmt.Printf("Chain %d: %s (severity: %s)\n", i+1, chain.Name, chain.Severity)
//	    for j, step := range chain.Steps {
//	        fmt.Printf("  Step %d: %s (confidence: %.2f)\n",
//	            j+1,
//	            step.TechniqueID,
//	            step.Confidence)
//	    }
//	}
//
// # Query Types and Results
//
// GraphRAG supports several query types:
//
// 1. Semantic Query (Text-based):
//
//	query := graphrag.NewGraphRAGQuery("cross-site scripting vulnerability")
//	results, _ := store.Query(ctx, *query)
//
// 2. Vector Query (Pre-computed embedding):
//
//	embedding, _ := embedder.Embed(ctx, "malicious content")
//	query := graphrag.NewGraphRAGQueryFromEmbedding(embedding)
//	results, _ := store.Query(ctx, *query)
//
// 3. Hybrid Query (Vector + Graph):
//
//	query := graphrag.NewGraphRAGQuery("authentication bypass").
//	    WithMaxHops(3).      // Enable graph traversal
//	    WithWeights(0.7, 0.3)  // Prefer vector similarity
//	results, _ := store.Query(ctx, *query)
//
// 4. Filtered Query:
//
//	query := graphrag.NewGraphRAGQuery("privilege escalation").
//	    WithNodeTypes(graphrag.NodeType("finding")).
//	    WithFilters(map[string]any{
//	        "severity": "critical",
//	        "mission_id": missionID.String(),
//	    })
//	results, _ := store.Query(ctx, *query)
//
// GraphRAGResult structure:
//
//	type GraphRAGResult struct {
//	    Node        GraphNode  // The retrieved node
//	    Score       float64    // Hybrid relevance score (0.0-1.0)
//	    VectorScore float64    // Vector similarity score
//	    GraphScore  float64    // Graph relevance score
//	    InVector    bool       // Found via vector search
//	    InGraph     bool       // Found via graph traversal
//	    Explanation string     // Human-readable explanation
//	}
//
// # Result Ranking
//
// Results are ranked using a hybrid scoring algorithm:
//
//	hybrid_score = (vector_weight * vector_score) + (graph_weight * graph_score)
//
// Where:
//   - vector_score: Cosine similarity between query and node embeddings
//   - graph_score: Graph-based relevance (e.g., PageRank, shortest path)
//   - vector_weight: Configurable weight for semantic similarity (default: 0.6)
//   - graph_weight: Configurable weight for structural relevance (default: 0.4)
//
// Nodes found in both vector and graph searches receive a boost:
//
//	if in_vector && in_graph:
//	    hybrid_score *= boost_factor  // default: 1.2
//
// # Observability Integration
//
// GraphRAG operations are automatically traced when using TracedGraphRAGStore:
//
//	import (
//	    "go.opentelemetry.io/otel"
//	)
//
//	// Wrap store with tracing
//	tracer := otel.Tracer("gibson")
//	tracedStore := graphrag.NewTracedGraphRAGStore(store, tracer)
//
//	// All operations create spans with attributes
//	results, err := tracedStore.Query(ctx, query)
//
// Trace spans include:
//   - graphrag.store.finding: Finding storage operations
//   - graphrag.store.attack_pattern: Attack pattern storage
//   - graphrag.query: Hybrid query execution
//   - graphrag.query.vector: Vector search component
//   - graphrag.query.graph: Graph traversal component
//
// Span attributes:
//   - graphrag.node.type: Type of node being operated on
//   - graphrag.query.text: Query text (if applicable)
//   - graphrag.query.top_k: Number of results requested
//   - graphrag.query.max_hops: Maximum traversal depth
//   - graphrag.result.count: Number of results returned
//   - graphrag.result.vector_count: Results from vector search
//   - graphrag.result.graph_count: Results from graph traversal
//
// # Advanced Features
//
// Batch Storage:
//
//	// Store multiple findings efficiently
//	records := []graphrag.GraphRecord{
//	    *graphrag.NewGraphRecord(finding1.ToGraphNode()).
//	        WithEmbedContent(finding1.Description),
//	    *graphrag.NewGraphRecord(finding2.ToGraphNode()).
//	        WithEmbedContent(finding2.Description),
//	}
//
//	if err := store.StoreBatch(ctx, records); err != nil {
//	    log.Printf("Batch store failed: %v", err)
//	}
//
// Custom Relationships:
//
//	// Create relationship between findings
//	rel := graphrag.NewRelationship(
//	    finding1.ID,
//	    finding2.ID,
//	    graphrag.RelationType("similar_to"),
//	).WithWeight(0.85).WithProperty("reason", "same exploit technique")
//
//	record := graphrag.NewGraphRecord(*finding1.ToGraphNode()).
//	    WithRelationship(*rel)
//
//	store.Store(ctx, record)
//
// Related Findings:
//
//	// Get findings related through graph relationships
//	related, err := store.GetRelatedFindings(ctx, findingID)
//	if err != nil {
//	    log.Printf("Failed to get related findings: %v", err)
//	    return
//	}
//
// # Error Handling
//
// The package defines several error types for different failure scenarios:
//
// ConfigError: Invalid configuration
//
//	err := config.Validate()
//	if errors.Is(err, graphrag.ErrInvalidConfig) {
//	    // Handle invalid configuration
//	}
//
// EmbeddingError: Embedding generation failure
//
//	err := store.StoreFinding(ctx, finding)
//	var embErr *graphrag.EmbeddingError
//	if errors.As(err, &embErr) {
//	    if embErr.Retryable {
//	        // Retry the operation
//	    }
//	}
//
// QueryError: Query execution failure
//
//	results, err := store.Query(ctx, query)
//	if errors.Is(err, graphrag.ErrQueryFailed) {
//	    // Handle query failure
//	}
//
// NodeNotFoundError: Node doesn't exist
//
//	similar, err := store.FindSimilarFindings(ctx, "invalid-id", 5)
//	if errors.Is(err, graphrag.ErrNodeNotFound) {
//	    // Handle missing node
//	}
//
// # Best Practices
//
// 1. Always use defer store.Close() to ensure cleanup:
//
//	store, err := graphrag.NewGraphRAGStoreWithProvider(config, embedder, provider)
//	if err != nil {
//	    return err
//	}
//	defer store.Close()
//
// 2. Use batch operations for bulk inserts:
//
//	// Good: Single batch operation
//	store.StoreBatch(ctx, records)
//
//	// Bad: Multiple individual operations
//	for _, record := range records {
//	    store.Store(ctx, record)
//	}
//
// 3. Set appropriate query limits:
//
//	// Good: Reasonable top-K
//	query.WithTopK(10)
//
//	// Bad: Unbounded results
//	query.WithTopK(1000)
//
// 4. Use health checks before critical operations:
//
//	health := store.Health(ctx)
//	if !health.IsHealthy() {
//	    log.Printf("GraphRAG degraded: %s", health.Message)
//	    // Fall back to alternative approach
//	}
//
// 5. Configure weights based on use case:
//
//	// For semantic search: Prefer vector similarity
//	query.WithWeights(0.8, 0.2)
//
//	// For relationship discovery: Prefer graph structure
//	query.WithWeights(0.3, 0.7)
//
// # Performance Considerations
//
// Vector Search:
//   - Embedding generation: ~100-500ms per text (LLM API call)
//   - Vector search: ~10-50ms for 100K vectors (indexed)
//   - Use batch embedding for multiple texts
//   - Cache embeddings when possible
//
// Graph Traversal:
//   - Depth-first traversal: O(V + E) where V=vertices, E=edges
//   - Limit max_hops to prevent exponential growth
//   - Use relationship type filters to prune search space
//
// Hybrid Queries:
//   - Runs vector and graph searches in parallel
//   - Total latency ≈ max(vector_time, graph_time) + merge_time
//   - Merge and rerank: ~1-5ms for 100 results
//
// Optimization Tips:
//   - Use WithNodeTypes() to filter early
//   - Set MinScore to reduce result set
//   - Batch similar operations together
//   - Monitor health for degradation
//
// # Security Considerations
//
// 1. Embeddings may contain sensitive information:
//   - Store embeddings securely
//   - Consider encryption at rest
//   - Implement access controls
//
// 2. Query injection prevention:
//   - All queries use parameterized Cypher
//   - Property values are sanitized
//   - No raw query string execution
//
// 3. Data isolation:
//   - Filter by mission_id for multi-tenancy
//   - Use relationship-based access control
//   - Implement audit logging
//
// 4. Network security:
//   - Use TLS for Neo4j connections
//   - Secure vector database endpoints
//   - Implement authentication/authorization
//
// # See Also
//
//   - internal/graphrag/graph: Neo4j graph client
//   - internal/graphrag/provider: GraphRAG provider implementations
//   - internal/memory/embedder: Embedding generation
//   - internal/observability: Tracing and metrics
package graphrag
