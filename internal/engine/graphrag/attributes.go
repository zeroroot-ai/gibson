package graphrag

import (
	"go.opentelemetry.io/otel/attribute"
)

// GraphRAG attribute keys for observability.
// Following Gibson's "gibson.graphrag.*" convention for consistency.
const (
	// AttrGraphRAGProvider is the GraphRAG provider type (local, cloud, hybrid, noop)
	AttrGraphRAGProvider = "gibson.graphrag.provider"

	// AttrGraphRAGQueryType indicates the type of query operation
	// (hybrid, vector, traverse, node)
	AttrGraphRAGQueryType = "gibson.graphrag.query_type"

	// AttrGraphRAGResultCount is the number of results returned
	AttrGraphRAGResultCount = "gibson.graphrag.result_count"

	// AttrGraphRAGHops is the maximum traversal depth for graph queries
	AttrGraphRAGHops = "gibson.graphrag.hops"

	// AttrGraphRAGNodesVisited is the number of nodes visited during traversal
	AttrGraphRAGNodesVisited = "gibson.graphrag.nodes_visited"

	// AttrGraphRAGVectorScore is the vector similarity score (0-1)
	AttrGraphRAGVectorScore = "gibson.graphrag.vector_score"

	// AttrGraphRAGGraphScore is the graph proximity score (0-1)
	AttrGraphRAGGraphScore = "gibson.graphrag.graph_score"

	// AttrGraphRAGNodeType is the type of graph node
	AttrGraphRAGNodeType = "gibson.graphrag.node_type"

	// AttrGraphRAGRelationType is the type of graph relationship
	AttrGraphRAGRelationType = "gibson.graphrag.relationship_type"
)

// Span name constants for GraphRAG operations.
// Following Gibson's "gibson.graphrag.*" convention.
const (
	// SpanGraphRAGQuery represents a hybrid GraphRAG query operation
	SpanGraphRAGQuery = "gibson.graphrag.query"

	// SpanGraphRAGStore represents a node storage operation
	SpanGraphRAGStore = "gibson.graphrag.store"

	// SpanGraphRAGTraverse represents a graph traversal operation
	SpanGraphRAGTraverse = "gibson.graphrag.traverse"

	// SpanGraphRAGFindSimilar represents a vector similarity search
	SpanGraphRAGFindSimilar = "gibson.graphrag.find_similar"

	// SpanGraphRAGStorePattern represents storing an attack pattern
	SpanGraphRAGStorePattern = "gibson.graphrag.store_pattern"

	// SpanGraphRAGStoreFinding represents storing a finding node
	SpanGraphRAGStoreFinding = "gibson.graphrag.store_finding"

	// SpanGraphRAGGetChains represents retrieving attack chains
	SpanGraphRAGGetChains = "gibson.graphrag.get_chains"
)

// QueryAttributes creates OpenTelemetry attributes from a GraphRAGQuery.
// Includes query parameters, filters, and scoring weights.
func QueryAttributes(query GraphRAGQuery) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, 10)

	// Determine query type
	queryType := "hybrid"
	if query.Text != "" {
		queryType = "text"
	} else if len(query.Embedding) > 0 {
		queryType = "embedding"
	}
	attrs = append(attrs, attribute.String(AttrGraphRAGQueryType, queryType))

	// Add query parameters
	attrs = append(attrs,
		attribute.Int("gibson.graphrag.top_k", query.TopK),
		attribute.Int(AttrGraphRAGHops, query.MaxHops),
		attribute.Float64("gibson.graphrag.min_score", query.MinScore),
		attribute.Float64("gibson.graphrag.vector_weight", query.VectorWeight),
		attribute.Float64("gibson.graphrag.graph_weight", query.GraphWeight),
	)

	// Add node type filters if present
	if len(query.NodeTypes) > 0 {
		nodeTypes := make([]string, len(query.NodeTypes))
		for i, nt := range query.NodeTypes {
			nodeTypes[i] = nt.String()
		}
		attrs = append(attrs, attribute.StringSlice("gibson.graphrag.node_types", nodeTypes))
	}

	// Add mission filter if present
	if query.MissionID != nil {
		attrs = append(attrs, attribute.String("gibson.graphrag.mission_id", query.MissionID.String()))
	}

	// Add text query if present (avoid logging full embeddings)
	if query.Text != "" {
		attrs = append(attrs, attribute.String("gibson.graphrag.query_text", query.Text))
	}

	// Add embedding dimension if present
	if len(query.Embedding) > 0 {
		attrs = append(attrs, attribute.Int("gibson.graphrag.embedding_dim", len(query.Embedding)))
	}

	return attrs
}

// ResultAttributes creates OpenTelemetry attributes from GraphRAG results.
// Includes result count, scoring statistics, and traversal metrics.
func ResultAttributes(results []GraphRAGResult) []attribute.KeyValue {
	if len(results) == 0 {
		return []attribute.KeyValue{
			attribute.Int(AttrGraphRAGResultCount, 0),
		}
	}

	attrs := []attribute.KeyValue{
		attribute.Int(AttrGraphRAGResultCount, len(results)),
	}

	// Calculate aggregate scores
	var totalScore, totalVectorScore, totalGraphScore float64
	var maxDistance int
	nodeTypeCounts := make(map[string]int)

	for _, result := range results {
		totalScore += result.Score
		totalVectorScore += result.VectorScore
		totalGraphScore += result.GraphScore

		if result.Distance > maxDistance {
			maxDistance = result.Distance
		}

		// Count node types
		for _, label := range result.Node.Labels {
			nodeTypeCounts[label.String()]++
		}
	}

	// Add average scores
	count := float64(len(results))
	attrs = append(attrs,
		attribute.Float64("gibson.graphrag.avg_score", totalScore/count),
		attribute.Float64("gibson.graphrag.avg_vector_score", totalVectorScore/count),
		attribute.Float64("gibson.graphrag.avg_graph_score", totalGraphScore/count),
		attribute.Int("gibson.graphrag.max_distance", maxDistance),
	)

	// Add top result scores
	if len(results) > 0 {
		topResult := results[0]
		attrs = append(attrs,
			attribute.Float64("gibson.graphrag.top_score", topResult.Score),
			attribute.Float64(AttrGraphRAGVectorScore, topResult.VectorScore),
			attribute.Float64(AttrGraphRAGGraphScore, topResult.GraphScore),
		)
	}

	// Add node type distribution
	for nodeType, count := range nodeTypeCounts {
		key := "gibson.graphrag.result_types." + nodeType
		attrs = append(attrs, attribute.Int(key, count))
	}

	return attrs
}

// StoreAttributes creates OpenTelemetry attributes for a node storage operation.
// Includes node type and label information.
func StoreAttributes(nodeType NodeType) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String(AttrGraphRAGNodeType, nodeType.String()),
	}
}

// TraverseAttributes creates OpenTelemetry attributes for a graph traversal operation.
// Includes traversal parameters and filters.
func TraverseAttributes(startID string, maxHops int, filters TraversalFilters) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("gibson.graphrag.start_id", startID),
		attribute.Int(AttrGraphRAGHops, maxHops),
	}

	// Add filter information
	if len(filters.AllowedRelations) > 0 {
		relTypes := make([]string, len(filters.AllowedRelations))
		for i, rt := range filters.AllowedRelations {
			relTypes[i] = rt.String()
		}
		attrs = append(attrs, attribute.StringSlice("gibson.graphrag.allowed_relations", relTypes))
	}

	if len(filters.AllowedNodeTypes) > 0 {
		nodeTypes := make([]string, len(filters.AllowedNodeTypes))
		for i, nt := range filters.AllowedNodeTypes {
			nodeTypes[i] = nt.String()
		}
		attrs = append(attrs, attribute.StringSlice("gibson.graphrag.allowed_node_types", nodeTypes))
	}

	if filters.MinWeight > 0 {
		attrs = append(attrs, attribute.Float64("gibson.graphrag.min_weight", filters.MinWeight))
	}

	if filters.MaxDepth > 0 {
		attrs = append(attrs, attribute.Int("gibson.graphrag.max_depth", filters.MaxDepth))
	}

	return attrs
}

// VectorSearchAttributes creates OpenTelemetry attributes for a vector search operation.
// Includes embedding dimension and topK parameter.
func VectorSearchAttributes(embedding []float64, topK int) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String(AttrGraphRAGQueryType, "vector"),
		attribute.Int("gibson.graphrag.embedding_dim", len(embedding)),
		attribute.Int("gibson.graphrag.top_k", topK),
	}
}

// RelationshipAttributes creates OpenTelemetry attributes for a relationship.
// Includes relationship type and weight.
func RelationshipAttributes(rel Relationship) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String(AttrGraphRAGRelationType, rel.Type.String()),
		attribute.Float64("gibson.graphrag.relationship_weight", rel.Weight),
		attribute.String("gibson.graphrag.from_id", rel.FromID.String()),
		attribute.String("gibson.graphrag.to_id", rel.ToID.String()),
	}
}

// NodeAttributes creates OpenTelemetry attributes for a graph node.
// Includes node labels and property count.
func NodeAttributes(node GraphNode) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, 5)

	// Add labels
	if len(node.Labels) > 0 {
		labels := make([]string, len(node.Labels))
		for i, label := range node.Labels {
			labels[i] = label.String()
		}
		attrs = append(attrs, attribute.StringSlice("gibson.graphrag.labels", labels))

		// Add primary label
		attrs = append(attrs, attribute.String(AttrGraphRAGNodeType, node.Labels[0].String()))
	}

	// Add node ID
	attrs = append(attrs, attribute.String("gibson.graphrag.node_id", node.ID.String()))

	// Add property count
	attrs = append(attrs, attribute.Int("gibson.graphrag.property_count", len(node.Properties)))

	// Add embedding status
	hasEmbedding := len(node.Embedding) > 0
	attrs = append(attrs, attribute.Bool("gibson.graphrag.has_embedding", hasEmbedding))
	if hasEmbedding {
		attrs = append(attrs, attribute.Int("gibson.graphrag.embedding_dim", len(node.Embedding)))
	}

	// Add mission ID if present
	if node.MissionID != nil {
		attrs = append(attrs, attribute.String("gibson.graphrag.mission_id", node.MissionID.String()))
	}

	return attrs
}

// AttackChainAttributes creates OpenTelemetry attributes for an attack chain.
// Includes chain metadata and step count.
func AttackChainAttributes(chain AttackChain) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("gibson.graphrag.chain_id", chain.ID.String()),
		attribute.String("gibson.graphrag.chain_name", chain.Name),
		attribute.Int("gibson.graphrag.chain_steps", len(chain.Steps)),
		attribute.Float64("gibson.graphrag.chain_confidence", chain.Confidence),
		attribute.String("gibson.graphrag.chain_severity", chain.Severity),
		attribute.String("gibson.graphrag.mission_id", chain.MissionID.String()),
	}
}

// ProviderAttributes creates OpenTelemetry attributes for a GraphRAG provider.
// Includes provider type information.
func ProviderAttributes(providerType ProviderType) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String(AttrGraphRAGProvider, providerType.String()),
	}
}
