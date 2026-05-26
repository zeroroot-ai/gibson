package graphrag

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/types"
	"go.opentelemetry.io/otel/attribute"
)

func TestAttributeConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"provider", AttrGraphRAGProvider, "gibson.graphrag.provider"},
		{"query_type", AttrGraphRAGQueryType, "gibson.graphrag.query_type"},
		{"result_count", AttrGraphRAGResultCount, "gibson.graphrag.result_count"},
		{"hops", AttrGraphRAGHops, "gibson.graphrag.hops"},
		{"nodes_visited", AttrGraphRAGNodesVisited, "gibson.graphrag.nodes_visited"},
		{"vector_score", AttrGraphRAGVectorScore, "gibson.graphrag.vector_score"},
		{"graph_score", AttrGraphRAGGraphScore, "gibson.graphrag.graph_score"},
		{"node_type", AttrGraphRAGNodeType, "gibson.graphrag.node_type"},
		{"relationship_type", AttrGraphRAGRelationType, "gibson.graphrag.relationship_type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant, "attribute constant should match expected value")
		})
	}
}

func TestSpanNameConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"query", SpanGraphRAGQuery, "gibson.graphrag.query"},
		{"store", SpanGraphRAGStore, "gibson.graphrag.store"},
		{"traverse", SpanGraphRAGTraverse, "gibson.graphrag.traverse"},
		{"find_similar", SpanGraphRAGFindSimilar, "gibson.graphrag.find_similar"},
		{"store_pattern", SpanGraphRAGStorePattern, "gibson.graphrag.store_pattern"},
		{"store_finding", SpanGraphRAGStoreFinding, "gibson.graphrag.store_finding"},
		{"get_chains", SpanGraphRAGGetChains, "gibson.graphrag.get_chains"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant, "span name should follow gibson.graphrag.* convention")
		})
	}
}

func TestSpanNamesFollowConvention(t *testing.T) {
	spanNames := []string{
		SpanGraphRAGQuery,
		SpanGraphRAGStore,
		SpanGraphRAGTraverse,
		SpanGraphRAGFindSimilar,
		SpanGraphRAGStorePattern,
		SpanGraphRAGStoreFinding,
		SpanGraphRAGGetChains,
	}

	for _, spanName := range spanNames {
		assert.Contains(t, spanName, "gibson.graphrag.", "span name should use gibson.graphrag. prefix")
	}
}

func TestAttributeKeyUniqueness(t *testing.T) {
	// Ensure all attribute keys are unique
	keys := []string{
		AttrGraphRAGProvider,
		AttrGraphRAGQueryType,
		AttrGraphRAGResultCount,
		AttrGraphRAGHops,
		AttrGraphRAGNodesVisited,
		AttrGraphRAGVectorScore,
		AttrGraphRAGGraphScore,
		AttrGraphRAGNodeType,
		AttrGraphRAGRelationType,
	}

	seen := make(map[string]bool)
	for _, key := range keys {
		assert.False(t, seen[key], "attribute key %s should be unique", key)
		seen[key] = true
	}
}

func TestQueryAttributes(t *testing.T) {
	t.Run("text query", func(t *testing.T) {
		query := NewGraphRAGQuery("test query")

		attrs := QueryAttributes(*query)

		// Verify we have attributes
		require.NotEmpty(t, attrs)

		// Check for expected attributes
		attrMap := attributesToMap(attrs)
		assert.Equal(t, "text", attrMap[AttrGraphRAGQueryType])
		assert.Equal(t, int64(10), attrMap["gibson.graphrag.top_k"])
		assert.Equal(t, int64(3), attrMap[AttrGraphRAGHops])
		assert.Equal(t, 0.7, attrMap["gibson.graphrag.min_score"])
		assert.Equal(t, 0.6, attrMap["gibson.graphrag.vector_weight"])
		assert.Equal(t, 0.4, attrMap["gibson.graphrag.graph_weight"])
		assert.Equal(t, "test query", attrMap["gibson.graphrag.query_text"])
	})

	t.Run("embedding query", func(t *testing.T) {
		embedding := make([]float64, 768)
		query := NewGraphRAGQueryFromEmbedding(embedding)

		attrs := QueryAttributes(*query)

		attrMap := attributesToMap(attrs)
		assert.Equal(t, "embedding", attrMap[AttrGraphRAGQueryType])
		assert.Equal(t, int64(768), attrMap["gibson.graphrag.embedding_dim"])
	})

	t.Run("query with filters", func(t *testing.T) {
		missionID := types.NewID()
		query := NewGraphRAGQuery("test").
			WithNodeTypes(NodeType("finding"), NodeType("attack_pattern")).
			WithMission(missionID)

		attrs := QueryAttributes(*query)

		attrMap := attributesToMap(attrs)
		assert.Equal(t, missionID.String(), attrMap["gibson.graphrag.mission_id"])

		// Check node types slice
		nodeTypes, ok := attrMap["gibson.graphrag.node_types"].([]string)
		require.True(t, ok)
		assert.Len(t, nodeTypes, 2)
		assert.Contains(t, nodeTypes, "finding")
		assert.Contains(t, nodeTypes, "attack_pattern")
	})
}

func TestResultAttributes(t *testing.T) {
	t.Run("empty results", func(t *testing.T) {
		var results []GraphRAGResult

		attrs := ResultAttributes(results)

		attrMap := attributesToMap(attrs)
		assert.Equal(t, int64(0), attrMap[AttrGraphRAGResultCount])
	})

	t.Run("single result", func(t *testing.T) {
		node := NewGraphNode(types.NewID(), NodeType("finding"))
		result := NewGraphRAGResult(*node, 0.85, 0.75)
		result.ComputeScore(0.6, 0.4)

		results := []GraphRAGResult{*result}
		attrs := ResultAttributes(results)

		attrMap := attributesToMap(attrs)
		assert.Equal(t, int64(1), attrMap[AttrGraphRAGResultCount])
		assert.Equal(t, 0.85, attrMap[AttrGraphRAGVectorScore])
		assert.Equal(t, 0.75, attrMap[AttrGraphRAGGraphScore])
		assert.NotNil(t, attrMap["gibson.graphrag.avg_score"])
	})

	t.Run("multiple results with different node types", func(t *testing.T) {
		node1 := NewGraphNode(types.NewID(), NodeType("finding"))
		result1 := NewGraphRAGResult(*node1, 0.9, 0.8)
		result1.ComputeScore(0.6, 0.4)

		node2 := NewGraphNode(types.NewID(), NodeType("attack_pattern"))
		result2 := NewGraphRAGResult(*node2, 0.7, 0.6)
		result2.ComputeScore(0.6, 0.4)
		result2.WithPath([]types.ID{types.NewID(), types.NewID()}) // Distance of 1

		results := []GraphRAGResult{*result1, *result2}
		attrs := ResultAttributes(results)

		attrMap := attributesToMap(attrs)
		assert.Equal(t, int64(2), attrMap[AttrGraphRAGResultCount])
		assert.Equal(t, int64(1), attrMap["gibson.graphrag.max_distance"])

		// Check node type counts
		assert.Equal(t, int64(1), attrMap["gibson.graphrag.result_types.finding"])
		assert.Equal(t, int64(1), attrMap["gibson.graphrag.result_types.attack_pattern"])
	})
}

func TestStoreAttributes(t *testing.T) {
	tests := []struct {
		name     string
		nodeType NodeType
		expected string
	}{
		{"finding", NodeType("finding"), "finding"},
		{"attack_pattern", NodeType("attack_pattern"), "attack_pattern"},
		{"technique", NodeType("technique"), "technique"},
		{"target", NodeType("target"), "target"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := StoreAttributes(tt.nodeType)

			attrMap := attributesToMap(attrs)
			assert.Equal(t, tt.expected, attrMap[AttrGraphRAGNodeType])
		})
	}
}

func TestTraverseAttributes(t *testing.T) {
	startID := types.NewID().String()
	filters := TraversalFilters{
		AllowedRelations: []RelationType{RelationType("exploits"), RelationType("similar_to")},
		AllowedNodeTypes: []NodeType{NodeType("finding"), NodeType("attack_pattern")},
		MinWeight:        0.5,
		MaxDepth:         5,
	}

	attrs := TraverseAttributes(startID, 3, filters)

	attrMap := attributesToMap(attrs)
	assert.Equal(t, startID, attrMap["gibson.graphrag.start_id"])
	assert.Equal(t, int64(3), attrMap[AttrGraphRAGHops])
	assert.Equal(t, 0.5, attrMap["gibson.graphrag.min_weight"])
	assert.Equal(t, int64(5), attrMap["gibson.graphrag.max_depth"])

	// Check allowed relations
	allowedRels, ok := attrMap["gibson.graphrag.allowed_relations"].([]string)
	require.True(t, ok)
	assert.Len(t, allowedRels, 2)
	assert.Contains(t, allowedRels, "exploits")
	assert.Contains(t, allowedRels, "similar_to")

	// Check allowed node types
	allowedTypes, ok := attrMap["gibson.graphrag.allowed_node_types"].([]string)
	require.True(t, ok)
	assert.Len(t, allowedTypes, 2)
}

func TestVectorSearchAttributes(t *testing.T) {
	embedding := make([]float64, 1536)
	topK := 20

	attrs := VectorSearchAttributes(embedding, topK)

	attrMap := attributesToMap(attrs)
	assert.Equal(t, "vector", attrMap[AttrGraphRAGQueryType])
	assert.Equal(t, int64(1536), attrMap["gibson.graphrag.embedding_dim"])
	assert.Equal(t, int64(20), attrMap["gibson.graphrag.top_k"])
}

func TestRelationshipAttributes(t *testing.T) {
	fromID := types.NewID()
	toID := types.NewID()
	rel := NewRelationship(fromID, toID, RelationType("exploits")).
		WithWeight(0.85)

	attrs := RelationshipAttributes(*rel)

	attrMap := attributesToMap(attrs)
	assert.Equal(t, "exploits", attrMap[AttrGraphRAGRelationType])
	assert.Equal(t, 0.85, attrMap["gibson.graphrag.relationship_weight"])
	assert.Equal(t, fromID.String(), attrMap["gibson.graphrag.from_id"])
	assert.Equal(t, toID.String(), attrMap["gibson.graphrag.to_id"])
}

func TestNodeAttributes(t *testing.T) {
	t.Run("node with embedding", func(t *testing.T) {
		missionID := types.NewID()
		embedding := make([]float64, 768)
		node := NewGraphNode(types.NewID(), NodeType("finding"), NodeType("target")).
			WithEmbedding(embedding).
			WithMission(missionID).
			WithProperty("title", "Test Finding").
			WithProperty("severity", "high")

		attrs := NodeAttributes(*node)

		attrMap := attributesToMap(attrs)
		assert.Equal(t, "finding", attrMap[AttrGraphRAGNodeType])
		assert.Equal(t, true, attrMap["gibson.graphrag.has_embedding"])
		assert.Equal(t, int64(768), attrMap["gibson.graphrag.embedding_dim"])
		assert.Equal(t, int64(2), attrMap["gibson.graphrag.property_count"])
		assert.Equal(t, missionID.String(), attrMap["gibson.graphrag.mission_id"])

		// Check labels
		labels, ok := attrMap["gibson.graphrag.labels"].([]string)
		require.True(t, ok)
		assert.Len(t, labels, 2)
		assert.Contains(t, labels, "finding")
		assert.Contains(t, labels, "target")
	})

	t.Run("node without embedding", func(t *testing.T) {
		node := NewGraphNode(types.NewID(), NodeType("attack_pattern"))

		attrs := NodeAttributes(*node)

		attrMap := attributesToMap(attrs)
		assert.Equal(t, false, attrMap["gibson.graphrag.has_embedding"])
		assert.Nil(t, attrMap["gibson.graphrag.embedding_dim"])
	})
}

func TestAttackChainAttributes(t *testing.T) {
	missionID := types.NewID()
	chain := NewAttackChain("Credential Access Chain", missionID)
	chain.Severity = "high"
	chain.Confidence = 0.92

	// Add some steps
	chain.AddStep(AttackStep{
		TechniqueID: "T1078",
		NodeID:      types.NewID(),
		Description: "Valid Accounts",
		Confidence:  0.95,
	})
	chain.AddStep(AttackStep{
		TechniqueID: "T1003",
		NodeID:      types.NewID(),
		Description: "OS Credential Dumping",
		Confidence:  0.89,
	})

	attrs := AttackChainAttributes(*chain)

	attrMap := attributesToMap(attrs)
	assert.Equal(t, chain.ID.String(), attrMap["gibson.graphrag.chain_id"])
	assert.Equal(t, "Credential Access Chain", attrMap["gibson.graphrag.chain_name"])
	assert.Equal(t, int64(2), attrMap["gibson.graphrag.chain_steps"])
	assert.Equal(t, 0.92, attrMap["gibson.graphrag.chain_confidence"])
	assert.Equal(t, "high", attrMap["gibson.graphrag.chain_severity"])
	assert.Equal(t, missionID.String(), attrMap["gibson.graphrag.mission_id"])
}

func TestProviderAttributes(t *testing.T) {
	tests := []struct {
		name         string
		providerType ProviderType
		expected     string
	}{
		{"local", ProviderTypeLocal, "local"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := ProviderAttributes(tt.providerType)

			attrMap := attributesToMap(attrs)
			assert.Equal(t, tt.expected, attrMap[AttrGraphRAGProvider])
		})
	}
}

func TestAttributesFollowGibsonConvention(t *testing.T) {
	// All attribute keys should start with "gibson.graphrag."
	attributeKeys := []string{
		AttrGraphRAGProvider,
		AttrGraphRAGQueryType,
		AttrGraphRAGResultCount,
		AttrGraphRAGHops,
		AttrGraphRAGNodesVisited,
		AttrGraphRAGVectorScore,
		AttrGraphRAGGraphScore,
		AttrGraphRAGNodeType,
		AttrGraphRAGRelationType,
	}

	for _, key := range attributeKeys {
		assert.Contains(t, key, "gibson.graphrag.", "attribute key %s should use gibson.graphrag. prefix", key)
	}
}

// Helper function to convert attribute.KeyValue slice to map for easier testing
func attributesToMap(attrs []attribute.KeyValue) map[string]interface{} {
	m := make(map[string]interface{})
	for _, attr := range attrs {
		key := string(attr.Key)
		switch attr.Value.Type() {
		case attribute.STRING:
			m[key] = attr.Value.AsString()
		case attribute.INT64:
			m[key] = attr.Value.AsInt64()
		case attribute.FLOAT64:
			m[key] = attr.Value.AsFloat64()
		case attribute.BOOL:
			m[key] = attr.Value.AsBool()
		case attribute.STRINGSLICE:
			m[key] = attr.Value.AsStringSlice()
		case attribute.INT64SLICE:
			m[key] = attr.Value.AsInt64Slice()
		case attribute.FLOAT64SLICE:
			m[key] = attr.Value.AsFloat64Slice()
		case attribute.BOOLSLICE:
			m[key] = attr.Value.AsBoolSlice()
		}
	}
	return m
}
