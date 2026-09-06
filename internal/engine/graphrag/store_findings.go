// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package graphrag

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// FindSimilarFindings finds findings similar to the given finding.
// Uses vector search filtered to Finding node type.
func (s *DefaultGraphRAGStore) FindSimilarFindings(ctx context.Context, findingID string, topK int) ([]FindingNode, error) {
	// Parse finding ID
	id, err := types.ParseID(findingID)
	if err != nil {
		return nil, NewInvalidQueryError(fmt.Sprintf("invalid finding ID: %v", err))
	}

	// Fetch the source finding
	nodeQuery := NewNodeQuery().
		WithNodeTypes(NodeType("finding")).
		WithProperty("id", id.String())

	nodes, err := s.provider.QueryNodes(ctx, *nodeQuery)
	if err != nil || len(nodes) == 0 {
		return nil, NewNodeNotFoundError(findingID)
	}

	sourceFinding := nodes[0]
	if len(sourceFinding.Embedding) == 0 {
		return nil, NewQueryError("source finding has no embedding", nil)
	}

	// Execute vector search with Finding filter
	filters := map[string]any{
		"node_type": NodeType("finding").String(),
	}
	vectorResults, err := s.provider.VectorSearch(ctx, sourceFinding.Embedding, topK+1, filters)
	if err != nil {
		return nil, NewQueryError("vector search for similar findings failed", err)
	}

	// Convert to FindingNode, excluding the source finding
	findings := make([]FindingNode, 0, topK)
	for _, vr := range vectorResults {
		// Skip the source finding itself
		if vr.NodeID == id {
			continue
		}

		// Query for full node data
		nodeQuery := NewNodeQuery().
			WithNodeTypes(NodeType("finding")).
			WithProperty("id", vr.NodeID.String())

		nodes, err := s.provider.QueryNodes(ctx, *nodeQuery)
		if err != nil || len(nodes) == 0 {
			continue
		}

		// Convert GraphNode to FindingNode
		finding := graphNodeToFindingNode(nodes[0])
		findings = append(findings, finding)

		if len(findings) >= topK {
			break
		}
	}

	return findings, nil
}

// GetRelatedFindings retrieves findings related to the given finding.
// Traverses SIMILAR_TO and other relationship types.
func (s *DefaultGraphRAGStore) GetRelatedFindings(ctx context.Context, findingID string) ([]FindingNode, error) {
	// Parse finding ID
	id, err := types.ParseID(findingID)
	if err != nil {
		return nil, NewInvalidQueryError(fmt.Sprintf("invalid finding ID: %v", err))
	}

	// Query for relationships from this finding
	relQuery := NewRelQuery().
		WithFromID(id).
		WithTypes(RelationType("similar_to"), RelationType("related_to"))

	rels, err := s.provider.QueryRelationships(ctx, *relQuery)
	if err != nil {
		return nil, NewQueryError("failed to query relationships", err)
	}

	// Fetch related finding nodes
	findings := make([]FindingNode, 0, len(rels))
	for _, rel := range rels {
		// Query for the target node
		nodeQuery := NewNodeQuery().
			WithNodeTypes(NodeType("finding")).
			WithProperty("id", rel.ToID.String())

		nodes, err := s.provider.QueryNodes(ctx, *nodeQuery)
		if err != nil || len(nodes) == 0 {
			continue
		}

		// Convert GraphNode to FindingNode
		finding := graphNodeToFindingNode(nodes[0])
		findings = append(findings, finding)
	}

	return findings, nil
}

// graphNodeToFindingNode converts a GraphNode to a FindingNode.
func graphNodeToFindingNode(node GraphNode) FindingNode {
	finding := FindingNode{
		ID:          node.ID,
		Title:       node.GetStringProperty("title"),
		Description: node.GetStringProperty(PropDescription),
		Severity:    node.GetStringProperty(PropSeverity),
		Category:    node.GetStringProperty(PropCategory),
		Embedding:   node.Embedding,
		CreatedAt:   node.CreatedAt,
		UpdatedAt:   node.UpdatedAt,
	}

	// Extract confidence
	if conf, ok := node.Properties[PropConfidence].(float64); ok {
		finding.Confidence = conf
	}

	// Extract mission ID
	if node.MissionID != nil {
		finding.MissionID = *node.MissionID
	}

	// Extract target ID
	if targetIDStr := node.GetStringProperty("target_id"); targetIDStr != "" {
		if targetID, err := types.ParseID(targetIDStr); err == nil {
			finding.TargetID = &targetID
		}
	}

	return finding
}
