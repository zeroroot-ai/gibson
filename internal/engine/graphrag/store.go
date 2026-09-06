// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package graphrag

// This file owns the DefaultGraphRAGStore concrete impl plus the lifecycle
// methods (Query / GetNode / TraverseGraph / Health / Close).
//
// Domain-specific reads live in:
//   - store_findings.go: FindSimilarFindings, GetRelatedFindings
//   - store_attacks.go:  FindSimilarAttacks, GetAttackChains
//
// There are no write methods: the projector is the graph's sole writer
// (ADR-0012) and the write half was removed in gibson#1322.
//
// The public GraphRAGStore interface lives in api.go.

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/memory/embedder"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// DefaultGraphRAGStore implements GraphRAGStore using a provider and pipeline.
type DefaultGraphRAGStore struct {
	provider  GraphRAGProvider
	processor QueryPipeline
	embedder  embedder.Embedder
	config    GraphRAGConfig
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
