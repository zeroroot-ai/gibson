// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package graphrag

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
)

// Span name constants for GraphRAG operations.
// Following Gibson's "gibson.graphrag.*" convention.
const (
	// SpanGraphRAGQuery represents a hybrid GraphRAG query operation
	SpanGraphRAGQuery = "gibson.graphrag.query"

	// SpanGraphRAGTraverse represents a graph traversal operation
	SpanGraphRAGTraverse = "gibson.graphrag.traverse"

	// SpanGraphRAGFindSimilar represents a vector similarity search
	SpanGraphRAGFindSimilar = "gibson.graphrag.find_similar"

	// SpanGraphRAGGetChains represents retrieving attack chains
	SpanGraphRAGGetChains = "gibson.graphrag.get_chains"
)
