package graphrag

import (
	"context"

	"github.com/zero-day-ai/gibson/internal/types"
)

// StoreAttackPattern stores a MITRE ATT&CK pattern with technique relationships.
// Creates the pattern node and USES_TECHNIQUE relationships.
func (s *DefaultGraphRAGStore) StoreAttackPattern(ctx context.Context, pattern AttackPattern) error {
	// Generate embedding from description
	if len(pattern.Embedding) == 0 && pattern.Description != "" {
		embedding, err := s.embedder.Embed(ctx, pattern.Description)
		if err != nil {
			return NewEmbeddingError("failed to generate embedding for attack pattern", err, true)
		}
		pattern.Embedding = embedding
	}

	// Convert to GraphNode
	node := pattern.ToGraphNode()

	// Store the node
	if err := s.provider.StoreNode(ctx, *node); err != nil {
		return NewQueryError("failed to store attack pattern node", err)
	}

	// Create USES_TECHNIQUE relationships for each tactic
	// Note: This assumes technique nodes already exist
	// In a real implementation, we'd either create technique nodes or query for them
	for _, tactic := range pattern.Tactics {
		// SIMPLIFIED: Current implementation generates placeholder technique IDs using types.NewID()
		// instead of querying for existing technique nodes in the graph.
		// Production implementation would:
		// 1. Query for existing technique nodes by MITRE technique ID (e.g., T1566)
		// 2. Create technique node if not found in the graph
		// 3. Use the actual node ID from query result or newly created node for the relationship
		// 4. Avoid creating duplicate technique nodes and orphaned relationships
		rel := NewRelationship(
			pattern.ID,
			types.NewID(), // Placeholder - should be actual technique ID from query or creation
			RelationType("uses_technique"),
		).WithProperty("tactic", tactic)

		if err := s.provider.StoreRelationship(ctx, *rel); err != nil {
			// Don't fail the entire operation if relationship creation fails
			// Log error in production
			continue
		}
	}

	return nil
}

// FindSimilarAttacks finds attack patterns similar to the given content.
// Uses vector search filtered to AttackPattern node type.
func (s *DefaultGraphRAGStore) FindSimilarAttacks(ctx context.Context, content string, topK int) ([]AttackPattern, error) {
	// Generate embedding for content
	embedding, err := s.embedder.Embed(ctx, content)
	if err != nil {
		return nil, NewEmbeddingError("failed to generate embedding for content", err, true)
	}

	// Execute vector search with AttackPattern filter
	filters := map[string]any{
		"node_type": NodeType("attack_pattern").String(),
	}
	vectorResults, err := s.provider.VectorSearch(ctx, embedding, topK, filters)
	if err != nil {
		return nil, NewQueryError("vector search for attack patterns failed", err)
	}

	// Fetch full nodes and convert to AttackPattern
	patterns := make([]AttackPattern, 0, len(vectorResults))
	for _, vr := range vectorResults {
		// Query for full node data
		nodeQuery := NewNodeQuery().
			WithNodeTypes(NodeType("attack_pattern")).
			WithProperty("id", vr.NodeID.String())

		nodes, err := s.provider.QueryNodes(ctx, *nodeQuery)
		if err != nil || len(nodes) == 0 {
			continue
		}

		// Convert GraphNode to AttackPattern
		pattern := graphNodeToAttackPattern(nodes[0])
		patterns = append(patterns, pattern)
	}

	return patterns, nil
}

// GetAttackChains discovers attack chains (technique sequences) from a starting technique.
// Traverses USES_TECHNIQUE relationships to find multi-step attack patterns.
func (s *DefaultGraphRAGStore) GetAttackChains(ctx context.Context, techniqueID string, maxDepth int) ([]AttackChain, error) {
	// Query for the starting technique node
	nodeQuery := NewNodeQuery().
		WithNodeTypes(NodeType("technique")).
		WithProperty("technique_id", techniqueID)

	nodes, err := s.provider.QueryNodes(ctx, *nodeQuery)
	if err != nil || len(nodes) == 0 {
		return nil, NewNodeNotFoundError(techniqueID)
	}

	startNode := nodes[0]

	// Traverse graph from this technique following USES_TECHNIQUE relationships
	filters := TraversalFilters{
		AllowedRelations: []RelationType{RelationType("uses_technique")},
		AllowedNodeTypes: []NodeType{NodeType("technique"), NodeType("attack_pattern")},
	}

	traversedNodes, err := s.provider.TraverseGraph(ctx, startNode.ID.String(), maxDepth, filters)
	if err != nil {
		return nil, NewQueryError("graph traversal failed", err)
	}

	// Build attack chains from traversed nodes
	chains := buildAttackChainsFromNodes(startNode, traversedNodes, maxDepth)

	return chains, nil
}

// graphNodeToAttackPattern converts a GraphNode to an AttackPattern.
func graphNodeToAttackPattern(node GraphNode) AttackPattern {
	pattern := AttackPattern{
		ID:          node.ID,
		TechniqueID: node.GetStringProperty("technique_id"),
		Name:        node.GetStringProperty(PropName),
		Description: node.GetStringProperty(PropDescription),
		Embedding:   node.Embedding,
		CreatedAt:   node.CreatedAt,
		UpdatedAt:   node.UpdatedAt,
	}

	// Extract arrays from properties
	if tactics, ok := node.Properties[PropTactics].([]string); ok {
		pattern.Tactics = tactics
	} else if tactics, ok := node.Properties[PropTactics].([]interface{}); ok {
		pattern.Tactics = make([]string, 0, len(tactics))
		for _, t := range tactics {
			if str, ok := t.(string); ok {
				pattern.Tactics = append(pattern.Tactics, str)
			}
		}
	}

	if platforms, ok := node.Properties[PropPlatforms].([]string); ok {
		pattern.Platforms = platforms
	} else if platforms, ok := node.Properties[PropPlatforms].([]interface{}); ok {
		pattern.Platforms = make([]string, 0, len(platforms))
		for _, p := range platforms {
			if str, ok := p.(string); ok {
				pattern.Platforms = append(pattern.Platforms, str)
			}
		}
	}

	return pattern
}

// buildAttackChainsFromNodes constructs attack chains from traversed nodes.
// Analyzes the graph structure to identify technique sequences.
func buildAttackChainsFromNodes(startNode GraphNode, traversedNodes []GraphNode, maxDepth int) []AttackChain {
	// SIMPLIFIED: Current implementation builds a single linear attack chain from traversed nodes
	// without analyzing actual graph paths, relationship sequences, or alternative attack paths.
	// Production implementation would:
	// 1. Use path analysis algorithms (e.g., DFS/BFS) to discover all possible attack chains
	// 2. Implement chain discovery algorithms to identify multi-step attack sequences
	// 3. Analyze relationship properties to determine valid technique sequences
	// 4. Calculate chain confidence scores based on evidence and relationship strength
	// 5. Return multiple chains representing different attack paths through the graph
	// 6. Filter and rank chains by likelihood, severity, and completeness

	if len(traversedNodes) == 0 {
		return []AttackChain{}
	}

	// Create a simple chain from the traversed nodes
	chain := NewAttackChain("Attack Chain", types.NewID())
	chain.Severity = "medium"

	// Add starting technique as first step
	chain.AddStep(AttackStep{
		TechniqueID: startNode.GetStringProperty("technique_id"),
		NodeID:      startNode.ID,
		Description: startNode.GetStringProperty("description"),
		Evidence:    []types.ID{},
		Confidence:  1.0,
	})

	// Add subsequent techniques from traversed nodes
	for i, node := range traversedNodes {
		if i >= maxDepth {
			break
		}
		if node.HasLabel(NodeType("technique")) {
			chain.AddStep(AttackStep{
				TechniqueID: node.GetStringProperty("technique_id"),
				NodeID:      node.ID,
				Description: node.GetStringProperty("description"),
				Evidence:    []types.ID{},
				Confidence:  0.8, // Decreasing confidence with depth
			})
		}
	}

	// Return the constructed chain
	return []AttackChain{*chain}
}
