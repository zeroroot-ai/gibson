// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package graphrag

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
		{"traverse", SpanGraphRAGTraverse, "gibson.graphrag.traverse"},
		{"find_similar", SpanGraphRAGFindSimilar, "gibson.graphrag.find_similar"},
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
		SpanGraphRAGTraverse,
		SpanGraphRAGFindSimilar,
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
	}

	seen := make(map[string]bool)
	for _, key := range keys {
		assert.False(t, seen[key], "attribute key %s should be unique", key)
		seen[key] = true
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
