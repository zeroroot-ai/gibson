package graphrag

import (
	"context"
	"fmt"
	"time"

	"github.com/zero-day-ai/gibson/internal/types"
)

// StoreFinding stores a security finding with contextual relationships.
// Creates the finding node and relationships to targets/techniques.
func (s *DefaultGraphRAGStore) StoreFinding(ctx context.Context, finding FindingNode) error {
	// Generate embedding from description
	if len(finding.Embedding) == 0 && finding.Description != "" {
		embedding, err := s.embedder.Embed(ctx, finding.Description)
		if err != nil {
			return NewEmbeddingError("failed to generate embedding for finding", err, true)
		}
		finding.Embedding = embedding
	}

	// Convert to GraphNode
	node := finding.ToGraphNode()

	// Store the node
	if err := s.provider.StoreNode(ctx, *node); err != nil {
		return NewQueryError("failed to store finding node", err)
	}

	// Create DISCOVERED_ON relationship if target is specified
	if finding.TargetID != nil {
		rel := NewRelationship(
			finding.ID,
			*finding.TargetID,
			RelationType("discovered_on"),
		).WithProperty(PropSeverity, finding.Severity)

		if err := s.provider.StoreRelationship(ctx, *rel); err != nil {
			// Don't fail the entire operation
			// Log error in production
		}
	}

	return nil
}

// StoreFindingWithRun stores a finding and links it to a mission run.
// Creates the finding node and a DISCOVERED_IN relationship to the run.
func (s *DefaultGraphRAGStore) StoreFindingWithRun(ctx context.Context, finding FindingNode, runID types.ID) error {
	// Store the finding first
	if err := s.StoreFinding(ctx, finding); err != nil {
		return fmt.Errorf("failed to store finding: %w", err)
	}

	// Create DISCOVERED_IN relationship to the run
	rel := NewRelationship(
		finding.ID,
		runID,
		RelationType("DISCOVERED_IN"),
	).WithProperty("discovered_at", time.Now().Format(time.RFC3339))

	if err := s.provider.StoreRelationship(ctx, *rel); err != nil {
		return NewRelationshipError("failed to create DISCOVERED_IN relationship", err)
	}

	return nil
}

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
