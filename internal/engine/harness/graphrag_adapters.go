package harness

import (
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
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
