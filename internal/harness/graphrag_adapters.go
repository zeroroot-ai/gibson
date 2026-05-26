package harness

import (
	"time"

	"github.com/zeroroot-ai/gibson/internal/graphrag"
	"github.com/zeroroot-ai/gibson/internal/types"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
)

// toInternalNode converts an SDK GraphNode to an internal GraphNode.
// It handles ID conversion from string to types.ID and maps the single SDK Type
// to internal Labels. Properties, timestamps, and embeddings are preserved.
func toInternalNode(sdk sdkgraphrag.GraphNode) graphrag.GraphNode {
	// Parse or generate node ID
	var nodeID types.ID
	if sdk.ID != "" {
		// Try to parse the SDK ID, fallback to generating a new one if invalid
		parsedID, err := types.ParseID(sdk.ID)
		if err != nil {
			nodeID = types.NewID()
		} else {
			nodeID = parsedID
		}
	} else {
		nodeID = types.NewID()
	}

	// Convert SDK Type string to internal NodeType label
	// The SDK has a single Type field, but internal uses Labels (slice of NodeType)
	labels := []graphrag.NodeType{}
	if sdk.Type != "" {
		labels = append(labels, graphrag.NodeType(sdk.Type))
	}

	// Create the internal node
	node := graphrag.GraphNode{
		ID:         nodeID,
		Labels:     labels,
		Properties: make(map[string]any),
		CreatedAt:  sdk.CreatedAt,
		UpdatedAt:  sdk.UpdatedAt,
	}

	// Copy properties, handling nil map
	if sdk.Properties != nil {
		for k, v := range sdk.Properties {
			node.Properties[k] = v
		}
	}

	// Store Content in properties if present
	if sdk.Content != "" {
		node.Properties["content"] = sdk.Content
	}

	// Store agent name if present
	if sdk.AgentName != "" {
		node.Properties["agent_name"] = sdk.AgentName
	}

	// Parse mission ID if present
	if sdk.MissionID != "" {
		missionID, err := types.ParseID(sdk.MissionID)
		if err == nil {
			node.MissionID = &missionID
		}
	}

	return node
}

// toInternalRelationship converts an SDK Relationship to an internal Relationship.
// It handles ID conversion and maps relationship properties. The Bidirectional flag
// is stored in properties since internal relationships are always unidirectional.
func toInternalRelationship(sdk sdkgraphrag.Relationship) graphrag.Relationship {
	// Parse FromID and ToID
	fromID, err := types.ParseID(sdk.FromID)
	if err != nil {
		fromID = types.NewID()
	}

	toID, err := types.ParseID(sdk.ToID)
	if err != nil {
		toID = types.NewID()
	}

	// Create internal relationship
	rel := graphrag.Relationship{
		ID:         types.NewID(),
		FromID:     fromID,
		ToID:       toID,
		Type:       graphrag.RelationType(sdk.Type),
		Properties: make(map[string]any),
		Weight:     1.0, // Default weight
		CreatedAt:  time.Now(),
	}

	// Copy properties
	if sdk.Properties != nil {
		for k, v := range sdk.Properties {
			rel.Properties[k] = v
		}
	}

	// Store bidirectional flag in properties
	if sdk.Bidirectional {
		rel.Properties["bidirectional"] = true
	}

	return rel
}

// toInternalQuery converts an SDK Query to an internal GraphRAGQuery.
// It maps all query parameters including filters, weights, and node types.
func toInternalQuery(sdk sdkgraphrag.Query) graphrag.GraphRAGQuery {
	query := graphrag.GraphRAGQuery{
		Text:         sdk.Text,
		Embedding:    sdk.Embedding,
		TopK:         sdk.TopK,
		MaxHops:      sdk.MaxHops,
		MinScore:     sdk.MinScore,
		VectorWeight: sdk.VectorWeight,
		GraphWeight:  sdk.GraphWeight,
	}

	// Convert node types
	if len(sdk.NodeTypes) > 0 {
		query.NodeTypes = make([]graphrag.NodeType, len(sdk.NodeTypes))
		for i, nt := range sdk.NodeTypes {
			query.NodeTypes[i] = graphrag.NodeType(nt)
		}
	}

	// Parse mission ID if present
	if sdk.MissionID != "" {
		missionID, err := types.ParseID(sdk.MissionID)
		if err == nil {
			query.MissionID = &missionID
		}
	}

	return query
}

// toSDKResult converts an internal GraphRAGResult to an SDK Result.
// It converts the node and path information, preserving all scoring details.
func toSDKResult(internal graphrag.GraphRAGResult) sdkgraphrag.Result {
	result := sdkgraphrag.Result{
		Node:        toSDKNode(internal.Node),
		Score:       internal.Score,
		VectorScore: internal.VectorScore,
		GraphScore:  internal.GraphScore,
		Distance:    internal.Distance,
	}

	// Convert path from []types.ID to []string
	if len(internal.Path) > 0 {
		result.Path = make([]string, len(internal.Path))
		for i, id := range internal.Path {
			result.Path[i] = id.String()
		}
	}

	return result
}

// toSDKNode converts an internal GraphNode to an SDK GraphNode.
// It extracts the primary label as Type and converts special properties
// like "content" and "agent_name" back to SDK fields.
func toSDKNode(internal graphrag.GraphNode) sdkgraphrag.GraphNode {
	node := sdkgraphrag.GraphNode{
		ID:         internal.ID.String(),
		Properties: make(map[string]any),
		CreatedAt:  internal.CreatedAt,
		UpdatedAt:  internal.UpdatedAt,
	}

	// Use the first label as the Type
	if len(internal.Labels) > 0 {
		node.Type = internal.Labels[0].String()
	}

	// Copy properties, extracting special fields
	if internal.Properties != nil {
		for k, v := range internal.Properties {
			switch k {
			case "content":
				if content, ok := v.(string); ok {
					node.Content = content
				}
			case "agent_name":
				if agentName, ok := v.(string); ok {
					node.AgentName = agentName
				}
			default:
				node.Properties[k] = v
			}
		}
	}

	// Convert mission ID
	if internal.MissionID != nil {
		node.MissionID = internal.MissionID.String()
	}

	return node
}

// toSDKAttackPattern converts an internal AttackPattern to an SDK AttackPattern.
// It extracts the similarity score from metadata if available.
func toSDKAttackPattern(internal graphrag.AttackPattern) sdkgraphrag.AttackPattern {
	pattern := sdkgraphrag.AttackPattern{
		TechniqueID: internal.TechniqueID,
		Name:        internal.Name,
		Description: internal.Description,
		Tactics:     internal.Tactics,
		Platforms:   internal.Platforms,
		Similarity:  0.0, // Default, should be set by caller if needed
	}

	// Handle nil slices
	if pattern.Tactics == nil {
		pattern.Tactics = []string{}
	}
	if pattern.Platforms == nil {
		pattern.Platforms = []string{}
	}

	return pattern
}

// toSDKFindingNode converts an internal FindingNode to an SDK FindingNode.
// It preserves all finding metadata and scoring information.
func toSDKFindingNode(internal graphrag.FindingNode) sdkgraphrag.FindingNode {
	finding := sdkgraphrag.FindingNode{
		ID:          internal.ID.String(),
		Title:       internal.Title,
		Description: internal.Description,
		Severity:    internal.Severity,
		Category:    internal.Category,
		Confidence:  internal.Confidence,
		Similarity:  0.0, // Default, should be set by caller if needed
	}

	return finding
}

// toSDKAttackChain converts an internal AttackChain to an SDK AttackChain.
// It converts all steps and preserves the chain structure.
func toSDKAttackChain(internal graphrag.AttackChain) sdkgraphrag.AttackChain {
	chain := sdkgraphrag.AttackChain{
		ID:       internal.ID.String(),
		Name:     internal.Name,
		Severity: internal.Severity,
		Steps:    make([]sdkgraphrag.AttackStep, len(internal.Steps)),
	}

	// Convert each step
	for i, step := range internal.Steps {
		chain.Steps[i] = sdkgraphrag.AttackStep{
			Order:       step.Order,
			TechniqueID: step.TechniqueID,
			NodeID:      step.NodeID.String(),
			Description: step.Description,
			Confidence:  step.Confidence,
		}
	}

	return chain
}
