package harness

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/graphrag"
	"github.com/zeroroot-ai/gibson/internal/types"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
)

// TestToInternalNode tests conversion from SDK GraphNode to internal GraphNode
func TestToInternalNode(t *testing.T) {
	now := time.Now()
	missionID := types.NewID()

	tests := []struct {
		name     string
		input    sdkgraphrag.GraphNode
		validate func(t *testing.T, result graphrag.GraphNode)
	}{
		{
			name: "normal conversion with all fields",
			input: sdkgraphrag.GraphNode{
				ID:        types.NewID().String(),
				Type:      "Finding",
				Content:   "Test content",
				AgentName: "test-agent",
				Properties: map[string]any{
					"severity": "high",
					"count":    42,
				},
				MissionID: missionID.String(),
				CreatedAt: now,
				UpdatedAt: now,
			},
			validate: func(t *testing.T, result graphrag.GraphNode) {
				assert.NotEmpty(t, result.ID.String())
				assert.Equal(t, []graphrag.NodeType{graphrag.NodeType("Finding")}, result.Labels)
				assert.Equal(t, "Test content", result.Properties["content"])
				assert.Equal(t, "test-agent", result.Properties["agent_name"])
				assert.Equal(t, "high", result.Properties["severity"])
				assert.Equal(t, 42, result.Properties["count"])
				require.NotNil(t, result.MissionID)
				assert.Equal(t, missionID.String(), result.MissionID.String())
				assert.Equal(t, now, result.CreatedAt)
				assert.Equal(t, now, result.UpdatedAt)
			},
		},
		{
			name: "empty ID generates new ID",
			input: sdkgraphrag.GraphNode{
				Type: "Entity",
			},
			validate: func(t *testing.T, result graphrag.GraphNode) {
				assert.NotEmpty(t, result.ID.String())
				assert.Equal(t, []graphrag.NodeType{graphrag.NodeType("Entity")}, result.Labels)
			},
		},
		{
			name: "invalid ID generates new ID",
			input: sdkgraphrag.GraphNode{
				ID:   "not-a-valid-ulid",
				Type: "Target",
			},
			validate: func(t *testing.T, result graphrag.GraphNode) {
				assert.NotEmpty(t, result.ID.String())
				assert.NotEqual(t, "not-a-valid-ulid", result.ID.String())
				assert.Equal(t, []graphrag.NodeType{graphrag.NodeType("Target")}, result.Labels)
			},
		},
		{
			name: "empty properties map",
			input: sdkgraphrag.GraphNode{
				Type:       "Technique",
				Properties: nil,
			},
			validate: func(t *testing.T, result graphrag.GraphNode) {
				assert.NotNil(t, result.Properties)
				assert.Empty(t, result.Properties)
			},
		},
		{
			name: "empty type results in empty labels",
			input: sdkgraphrag.GraphNode{
				Type: "",
			},
			validate: func(t *testing.T, result graphrag.GraphNode) {
				assert.Empty(t, result.Labels)
			},
		},
		{
			name: "content and agent name stored in properties",
			input: sdkgraphrag.GraphNode{
				Type:      "Finding",
				Content:   "Important finding details",
				AgentName: "scanner-v2",
			},
			validate: func(t *testing.T, result graphrag.GraphNode) {
				assert.Equal(t, "Important finding details", result.Properties["content"])
				assert.Equal(t, "scanner-v2", result.Properties["agent_name"])
			},
		},
		{
			name: "invalid mission ID is skipped",
			input: sdkgraphrag.GraphNode{
				Type:      "Finding",
				MissionID: "invalid-mission-id",
			},
			validate: func(t *testing.T, result graphrag.GraphNode) {
				assert.Nil(t, result.MissionID)
			},
		},
		{
			name: "empty content and agent name not stored",
			input: sdkgraphrag.GraphNode{
				Type:      "Entity",
				Content:   "",
				AgentName: "",
			},
			validate: func(t *testing.T, result graphrag.GraphNode) {
				_, hasContent := result.Properties["content"]
				_, hasAgentName := result.Properties["agent_name"]
				assert.False(t, hasContent)
				assert.False(t, hasAgentName)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toInternalNode(tt.input)
			tt.validate(t, result)
		})
	}
}

// TestToInternalRelationship tests conversion from SDK Relationship to internal Relationship
func TestToInternalRelationship(t *testing.T) {
	fromID := types.NewID()
	toID := types.NewID()

	tests := []struct {
		name     string
		input    sdkgraphrag.Relationship
		validate func(t *testing.T, result graphrag.Relationship)
	}{
		{
			name: "normal conversion with properties",
			input: sdkgraphrag.Relationship{
				FromID: fromID.String(),
				ToID:   toID.String(),
				Type:   "EXPLOITS",
				Properties: map[string]any{
					"confidence": 0.95,
					"source":     "manual",
				},
				Bidirectional: false,
			},
			validate: func(t *testing.T, result graphrag.Relationship) {
				assert.NotEmpty(t, result.ID.String())
				assert.Equal(t, fromID.String(), result.FromID.String())
				assert.Equal(t, toID.String(), result.ToID.String())
				assert.Equal(t, graphrag.RelationType("EXPLOITS"), result.Type)
				assert.Equal(t, 0.95, result.Properties["confidence"])
				assert.Equal(t, "manual", result.Properties["source"])
				assert.Equal(t, 1.0, result.Weight)
				_, hasBidirectional := result.Properties["bidirectional"]
				assert.False(t, hasBidirectional)
			},
		},
		{
			name: "bidirectional flag stored in properties",
			input: sdkgraphrag.Relationship{
				FromID:        fromID.String(),
				ToID:          toID.String(),
				Type:          "SIMILAR_TO",
				Bidirectional: true,
			},
			validate: func(t *testing.T, result graphrag.Relationship) {
				assert.Equal(t, true, result.Properties["bidirectional"])
			},
		},
		{
			name: "empty properties map",
			input: sdkgraphrag.Relationship{
				FromID:     fromID.String(),
				ToID:       toID.String(),
				Type:       "RELATED_TO",
				Properties: nil,
			},
			validate: func(t *testing.T, result graphrag.Relationship) {
				assert.NotNil(t, result.Properties)
				// Should only have bidirectional if it was true
				_, hasBidirectional := result.Properties["bidirectional"]
				assert.False(t, hasBidirectional)
			},
		},
		{
			name: "invalid FromID generates new ID",
			input: sdkgraphrag.Relationship{
				FromID: "invalid-id",
				ToID:   toID.String(),
				Type:   "TARGETS",
			},
			validate: func(t *testing.T, result graphrag.Relationship) {
				assert.NotEmpty(t, result.FromID.String())
				assert.NotEqual(t, "invalid-id", result.FromID.String())
				assert.Equal(t, toID.String(), result.ToID.String())
			},
		},
		{
			name: "invalid ToID generates new ID",
			input: sdkgraphrag.Relationship{
				FromID: fromID.String(),
				ToID:   "invalid-id",
				Type:   "USES_TECHNIQUE",
			},
			validate: func(t *testing.T, result graphrag.Relationship) {
				assert.Equal(t, fromID.String(), result.FromID.String())
				assert.NotEmpty(t, result.ToID.String())
				assert.NotEqual(t, "invalid-id", result.ToID.String())
			},
		},
		{
			name: "default weight is 1.0",
			input: sdkgraphrag.Relationship{
				FromID: fromID.String(),
				ToID:   toID.String(),
				Type:   "PART_OF",
			},
			validate: func(t *testing.T, result graphrag.Relationship) {
				assert.Equal(t, 1.0, result.Weight)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toInternalRelationship(tt.input)
			tt.validate(t, result)
		})
	}
}

// TestToInternalQuery tests conversion from SDK Query to internal GraphRAGQuery
func TestToInternalQuery(t *testing.T) {
	missionID := types.NewID()

	tests := []struct {
		name     string
		input    sdkgraphrag.Query
		validate func(t *testing.T, result graphrag.GraphRAGQuery)
	}{
		{
			name: "complete query with all parameters",
			input: sdkgraphrag.Query{
				Text:         "find vulnerabilities",
				Embedding:    []float64{0.1, 0.2, 0.3},
				TopK:         20,
				MaxHops:      5,
				MinScore:     0.8,
				NodeTypes:    []string{"Finding", "Vulnerability"},
				MissionID:    missionID.String(),
				VectorWeight: 0.7,
				GraphWeight:  0.3,
			},
			validate: func(t *testing.T, result graphrag.GraphRAGQuery) {
				assert.Equal(t, "find vulnerabilities", result.Text)
				assert.Equal(t, []float64{0.1, 0.2, 0.3}, result.Embedding)
				assert.Equal(t, 20, result.TopK)
				assert.Equal(t, 5, result.MaxHops)
				assert.Equal(t, 0.8, result.MinScore)
				assert.Equal(t, []graphrag.NodeType{
					graphrag.NodeType("Finding"),
					graphrag.NodeType("Vulnerability"),
				}, result.NodeTypes)
				require.NotNil(t, result.MissionID)
				assert.Equal(t, missionID.String(), result.MissionID.String())
				assert.Equal(t, 0.7, result.VectorWeight)
				assert.Equal(t, 0.3, result.GraphWeight)
			},
		},
		{
			name: "query with zero values",
			input: sdkgraphrag.Query{
				Text:         "",
				TopK:         0,
				MaxHops:      0,
				MinScore:     0.0,
				VectorWeight: 0.0,
				GraphWeight:  0.0,
			},
			validate: func(t *testing.T, result graphrag.GraphRAGQuery) {
				assert.Equal(t, "", result.Text)
				assert.Equal(t, 0, result.TopK)
				assert.Equal(t, 0, result.MaxHops)
				assert.Equal(t, 0.0, result.MinScore)
				assert.Equal(t, 0.0, result.VectorWeight)
				assert.Equal(t, 0.0, result.GraphWeight)
			},
		},
		{
			name: "query with empty node types",
			input: sdkgraphrag.Query{
				Text:      "test query",
				NodeTypes: []string{},
			},
			validate: func(t *testing.T, result graphrag.GraphRAGQuery) {
				assert.Nil(t, result.NodeTypes)
			},
		},
		{
			name: "query with nil node types",
			input: sdkgraphrag.Query{
				Text:      "test query",
				NodeTypes: nil,
			},
			validate: func(t *testing.T, result graphrag.GraphRAGQuery) {
				assert.Nil(t, result.NodeTypes)
			},
		},
		{
			name: "query without mission ID",
			input: sdkgraphrag.Query{
				Text:      "test query",
				MissionID: "",
			},
			validate: func(t *testing.T, result graphrag.GraphRAGQuery) {
				assert.Nil(t, result.MissionID)
			},
		},
		{
			name: "query with invalid mission ID",
			input: sdkgraphrag.Query{
				Text:      "test query",
				MissionID: "invalid-mission-id",
			},
			validate: func(t *testing.T, result graphrag.GraphRAGQuery) {
				assert.Nil(t, result.MissionID)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toInternalQuery(tt.input)
			tt.validate(t, result)
		})
	}
}

// TestToSDKResult tests conversion from internal GraphRAGResult to SDK Result
func TestToSDKResult(t *testing.T) {
	nodeID := types.NewID()
	pathID1 := types.NewID()
	pathID2 := types.NewID()
	now := time.Now()

	tests := []struct {
		name     string
		input    graphrag.GraphRAGResult
		validate func(t *testing.T, result sdkgraphrag.Result)
	}{
		{
			name: "normal conversion with all fields",
			input: graphrag.GraphRAGResult{
				Node: graphrag.GraphNode{
					ID:     nodeID,
					Labels: []graphrag.NodeType{graphrag.NodeType("Finding")},
					Properties: map[string]any{
						"content":    "test content",
						"agent_name": "test-agent",
						"severity":   "high",
					},
					CreatedAt: now,
					UpdatedAt: now,
				},
				Score:       0.95,
				VectorScore: 0.90,
				GraphScore:  0.85,
				Distance:    2,
				Path:        []types.ID{pathID1, pathID2, nodeID},
			},
			validate: func(t *testing.T, result sdkgraphrag.Result) {
				assert.Equal(t, nodeID.String(), result.Node.ID)
				assert.Equal(t, "Finding", result.Node.Type)
				assert.Equal(t, "test content", result.Node.Content)
				assert.Equal(t, "test-agent", result.Node.AgentName)
				assert.Equal(t, "high", result.Node.Properties["severity"])
				assert.Equal(t, 0.95, result.Score)
				assert.Equal(t, 0.90, result.VectorScore)
				assert.Equal(t, 0.85, result.GraphScore)
				assert.Equal(t, 2, result.Distance)
				assert.Equal(t, []string{pathID1.String(), pathID2.String(), nodeID.String()}, result.Path)
			},
		},
		{
			name: "empty path",
			input: graphrag.GraphRAGResult{
				Node: graphrag.GraphNode{
					ID:         nodeID,
					Labels:     []graphrag.NodeType{graphrag.NodeType("Entity")},
					Properties: make(map[string]any),
					CreatedAt:  now,
					UpdatedAt:  now,
				},
				Score:       0.75,
				VectorScore: 0.80,
				GraphScore:  0.70,
				Distance:    0,
				Path:        []types.ID{},
			},
			validate: func(t *testing.T, result sdkgraphrag.Result) {
				assert.Nil(t, result.Path)
				assert.Equal(t, 0, result.Distance)
			},
		},
		{
			name: "zero scores",
			input: graphrag.GraphRAGResult{
				Node: graphrag.GraphNode{
					ID:         nodeID,
					Labels:     []graphrag.NodeType{graphrag.NodeType("Technique")},
					Properties: make(map[string]any),
					CreatedAt:  now,
					UpdatedAt:  now,
				},
				Score:       0.0,
				VectorScore: 0.0,
				GraphScore:  0.0,
				Distance:    0,
			},
			validate: func(t *testing.T, result sdkgraphrag.Result) {
				assert.Equal(t, 0.0, result.Score)
				assert.Equal(t, 0.0, result.VectorScore)
				assert.Equal(t, 0.0, result.GraphScore)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toSDKResult(tt.input)
			tt.validate(t, result)
		})
	}
}

// TestToSDKNode tests conversion from internal GraphNode to SDK GraphNode
func TestToSDKNode(t *testing.T) {
	nodeID := types.NewID()
	missionID := types.NewID()
	now := time.Now()

	tests := []struct {
		name     string
		input    graphrag.GraphNode
		validate func(t *testing.T, result sdkgraphrag.GraphNode)
	}{
		{
			name: "normal conversion with content and agent_name",
			input: graphrag.GraphNode{
				ID:     nodeID,
				Labels: []graphrag.NodeType{graphrag.NodeType("Finding")},
				Properties: map[string]any{
					"content":    "Important finding",
					"agent_name": "scanner-v1",
					"severity":   "critical",
					"count":      10,
				},
				MissionID: &missionID,
				CreatedAt: now,
				UpdatedAt: now,
			},
			validate: func(t *testing.T, result sdkgraphrag.GraphNode) {
				assert.Equal(t, nodeID.String(), result.ID)
				assert.Equal(t, "Finding", result.Type)
				assert.Equal(t, "Important finding", result.Content)
				assert.Equal(t, "scanner-v1", result.AgentName)
				assert.Equal(t, "critical", result.Properties["severity"])
				assert.Equal(t, 10, result.Properties["count"])
				// content and agent_name should not be in properties
				_, hasContent := result.Properties["content"]
				_, hasAgentName := result.Properties["agent_name"]
				assert.False(t, hasContent)
				assert.False(t, hasAgentName)
				assert.Equal(t, missionID.String(), result.MissionID)
				assert.Equal(t, now, result.CreatedAt)
				assert.Equal(t, now, result.UpdatedAt)
			},
		},
		{
			name: "no labels results in empty type",
			input: graphrag.GraphNode{
				ID:         nodeID,
				Labels:     []graphrag.NodeType{},
				Properties: make(map[string]any),
				CreatedAt:  now,
				UpdatedAt:  now,
			},
			validate: func(t *testing.T, result sdkgraphrag.GraphNode) {
				assert.Equal(t, "", result.Type)
			},
		},
		{
			name: "multiple labels uses first as type",
			input: graphrag.GraphNode{
				ID: nodeID,
				Labels: []graphrag.NodeType{
					graphrag.NodeType("Finding"),
					graphrag.NodeType("Entity"),
				},
				Properties: make(map[string]any),
				CreatedAt:  now,
				UpdatedAt:  now,
			},
			validate: func(t *testing.T, result sdkgraphrag.GraphNode) {
				assert.Equal(t, "Finding", result.Type)
			},
		},
		{
			name: "nil properties map",
			input: graphrag.GraphNode{
				ID:         nodeID,
				Labels:     []graphrag.NodeType{graphrag.NodeType("Target")},
				Properties: nil,
				CreatedAt:  now,
				UpdatedAt:  now,
			},
			validate: func(t *testing.T, result sdkgraphrag.GraphNode) {
				assert.NotNil(t, result.Properties)
				assert.Empty(t, result.Properties)
			},
		},
		{
			name: "nil mission ID",
			input: graphrag.GraphNode{
				ID:         nodeID,
				Labels:     []graphrag.NodeType{graphrag.NodeType("Mitigation")},
				Properties: make(map[string]any),
				MissionID:  nil,
				CreatedAt:  now,
				UpdatedAt:  now,
			},
			validate: func(t *testing.T, result sdkgraphrag.GraphNode) {
				assert.Empty(t, result.MissionID)
			},
		},
		{
			name: "non-string content property ignored and dropped",
			input: graphrag.GraphNode{
				ID:     nodeID,
				Labels: []graphrag.NodeType{graphrag.NodeType("Entity")},
				Properties: map[string]any{
					"content": 12345, // Not a string
				},
				CreatedAt: now,
				UpdatedAt: now,
			},
			validate: func(t *testing.T, result sdkgraphrag.GraphNode) {
				assert.Empty(t, result.Content)
				// The non-string content is dropped entirely (not extracted, not copied)
				_, hasContent := result.Properties["content"]
				assert.False(t, hasContent)
			},
		},
		{
			name: "non-string agent_name property ignored and dropped",
			input: graphrag.GraphNode{
				ID:     nodeID,
				Labels: []graphrag.NodeType{graphrag.NodeType("Entity")},
				Properties: map[string]any{
					"agent_name": true, // Not a string
				},
				CreatedAt: now,
				UpdatedAt: now,
			},
			validate: func(t *testing.T, result sdkgraphrag.GraphNode) {
				assert.Empty(t, result.AgentName)
				// The non-string agent_name is dropped entirely (not extracted, not copied)
				_, hasAgentName := result.Properties["agent_name"]
				assert.False(t, hasAgentName)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toSDKNode(tt.input)
			tt.validate(t, result)
		})
	}
}

// TestToSDKAttackPattern tests conversion from internal AttackPattern to SDK AttackPattern
func TestToSDKAttackPattern(t *testing.T) {
	tests := []struct {
		name     string
		input    graphrag.AttackPattern
		validate func(t *testing.T, result sdkgraphrag.AttackPattern)
	}{
		{
			name: "normal conversion with all fields",
			input: graphrag.AttackPattern{
				TechniqueID: "T1566.001",
				Name:        "Spearphishing Attachment",
				Description: "Adversaries may send spearphishing emails with a malicious attachment",
				Tactics:     []string{"Initial Access"},
				Platforms:   []string{"Windows", "macOS", "Linux"},
			},
			validate: func(t *testing.T, result sdkgraphrag.AttackPattern) {
				assert.Equal(t, "T1566.001", result.TechniqueID)
				assert.Equal(t, "Spearphishing Attachment", result.Name)
				assert.Equal(t, "Adversaries may send spearphishing emails with a malicious attachment", result.Description)
				assert.Equal(t, []string{"Initial Access"}, result.Tactics)
				assert.Equal(t, []string{"Windows", "macOS", "Linux"}, result.Platforms)
				assert.Equal(t, 0.0, result.Similarity) // Default value
			},
		},
		{
			name: "nil tactics slice becomes empty slice",
			input: graphrag.AttackPattern{
				TechniqueID: "T1059",
				Name:        "Command and Scripting Interpreter",
				Description: "Adversaries may abuse command and script interpreters",
				Tactics:     nil,
				Platforms:   []string{"Windows"},
			},
			validate: func(t *testing.T, result sdkgraphrag.AttackPattern) {
				assert.NotNil(t, result.Tactics)
				assert.Empty(t, result.Tactics)
				assert.Equal(t, []string{}, result.Tactics)
			},
		},
		{
			name: "nil platforms slice becomes empty slice",
			input: graphrag.AttackPattern{
				TechniqueID: "T1548",
				Name:        "Abuse Elevation Control Mechanism",
				Description: "Adversaries may circumvent mechanisms to gain elevated privileges",
				Tactics:     []string{"Privilege Escalation", "Defense Evasion"},
				Platforms:   nil,
			},
			validate: func(t *testing.T, result sdkgraphrag.AttackPattern) {
				assert.NotNil(t, result.Platforms)
				assert.Empty(t, result.Platforms)
				assert.Equal(t, []string{}, result.Platforms)
			},
		},
		{
			name: "empty slices preserved",
			input: graphrag.AttackPattern{
				TechniqueID: "T1234",
				Name:        "Test Technique",
				Description: "Test description",
				Tactics:     []string{},
				Platforms:   []string{},
			},
			validate: func(t *testing.T, result sdkgraphrag.AttackPattern) {
				assert.Equal(t, []string{}, result.Tactics)
				assert.Equal(t, []string{}, result.Platforms)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toSDKAttackPattern(tt.input)
			tt.validate(t, result)
		})
	}
}

// TestToSDKFindingNode tests conversion from internal FindingNode to SDK FindingNode
func TestToSDKFindingNode(t *testing.T) {
	findingID := types.NewID()

	tests := []struct {
		name     string
		input    graphrag.FindingNode
		validate func(t *testing.T, result sdkgraphrag.FindingNode)
	}{
		{
			name: "normal conversion with all fields",
			input: graphrag.FindingNode{
				ID:          findingID,
				Title:       "SQL Injection Vulnerability",
				Description: "Detected SQL injection in user input handler",
				Severity:    "Critical",
				Category:    "Vulnerability",
				Confidence:  0.95,
			},
			validate: func(t *testing.T, result sdkgraphrag.FindingNode) {
				assert.Equal(t, findingID.String(), result.ID)
				assert.Equal(t, "SQL Injection Vulnerability", result.Title)
				assert.Equal(t, "Detected SQL injection in user input handler", result.Description)
				assert.Equal(t, "Critical", result.Severity)
				assert.Equal(t, "Vulnerability", result.Category)
				assert.Equal(t, 0.95, result.Confidence)
				assert.Equal(t, 0.0, result.Similarity) // Default value
			},
		},
		{
			name: "empty string fields preserved",
			input: graphrag.FindingNode{
				ID:          findingID,
				Title:       "",
				Description: "",
				Severity:    "",
				Category:    "",
				Confidence:  0.0,
			},
			validate: func(t *testing.T, result sdkgraphrag.FindingNode) {
				assert.Equal(t, findingID.String(), result.ID)
				assert.Equal(t, "", result.Title)
				assert.Equal(t, "", result.Description)
				assert.Equal(t, "", result.Severity)
				assert.Equal(t, "", result.Category)
				assert.Equal(t, 0.0, result.Confidence)
				assert.Equal(t, 0.0, result.Similarity)
			},
		},
		{
			name: "high confidence value",
			input: graphrag.FindingNode{
				ID:          findingID,
				Title:       "Confirmed Exploit",
				Description: "Manual verification completed",
				Severity:    "High",
				Category:    "Exploit",
				Confidence:  1.0,
			},
			validate: func(t *testing.T, result sdkgraphrag.FindingNode) {
				assert.Equal(t, 1.0, result.Confidence)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toSDKFindingNode(tt.input)
			tt.validate(t, result)
		})
	}
}

// TestToSDKAttackChain tests conversion from internal AttackChain to SDK AttackChain
func TestToSDKAttackChain(t *testing.T) {
	chainID := types.NewID()
	nodeID1 := types.NewID()
	nodeID2 := types.NewID()
	nodeID3 := types.NewID()

	tests := []struct {
		name     string
		input    graphrag.AttackChain
		validate func(t *testing.T, result sdkgraphrag.AttackChain)
	}{
		{
			name: "normal conversion with multiple steps",
			input: graphrag.AttackChain{
				ID:       chainID,
				Name:     "Multi-stage Attack Chain",
				Severity: "Critical",
				Steps: []graphrag.AttackStep{
					{
						Order:       1,
						TechniqueID: "T1566.001",
						NodeID:      nodeID1,
						Description: "Initial phishing email",
						Confidence:  0.95,
					},
					{
						Order:       2,
						TechniqueID: "T1204.002",
						NodeID:      nodeID2,
						Description: "User execution of malicious file",
						Confidence:  0.90,
					},
					{
						Order:       3,
						TechniqueID: "T1059.001",
						NodeID:      nodeID3,
						Description: "PowerShell execution",
						Confidence:  0.85,
					},
				},
			},
			validate: func(t *testing.T, result sdkgraphrag.AttackChain) {
				assert.Equal(t, chainID.String(), result.ID)
				assert.Equal(t, "Multi-stage Attack Chain", result.Name)
				assert.Equal(t, "Critical", result.Severity)
				assert.Len(t, result.Steps, 3)

				assert.Equal(t, 1, result.Steps[0].Order)
				assert.Equal(t, "T1566.001", result.Steps[0].TechniqueID)
				assert.Equal(t, nodeID1.String(), result.Steps[0].NodeID)
				assert.Equal(t, "Initial phishing email", result.Steps[0].Description)
				assert.Equal(t, 0.95, result.Steps[0].Confidence)

				assert.Equal(t, 2, result.Steps[1].Order)
				assert.Equal(t, "T1204.002", result.Steps[1].TechniqueID)
				assert.Equal(t, nodeID2.String(), result.Steps[1].NodeID)
				assert.Equal(t, "User execution of malicious file", result.Steps[1].Description)
				assert.Equal(t, 0.90, result.Steps[1].Confidence)

				assert.Equal(t, 3, result.Steps[2].Order)
				assert.Equal(t, "T1059.001", result.Steps[2].TechniqueID)
				assert.Equal(t, nodeID3.String(), result.Steps[2].NodeID)
				assert.Equal(t, "PowerShell execution", result.Steps[2].Description)
				assert.Equal(t, 0.85, result.Steps[2].Confidence)
			},
		},
		{
			name: "empty steps slice",
			input: graphrag.AttackChain{
				ID:       chainID,
				Name:     "Single Node Chain",
				Severity: "Low",
				Steps:    []graphrag.AttackStep{},
			},
			validate: func(t *testing.T, result sdkgraphrag.AttackChain) {
				assert.NotNil(t, result.Steps)
				assert.Empty(t, result.Steps)
			},
		},
		{
			name: "single step chain",
			input: graphrag.AttackChain{
				ID:       chainID,
				Name:     "Simple Attack",
				Severity: "Medium",
				Steps: []graphrag.AttackStep{
					{
						Order:       1,
						TechniqueID: "T1078",
						NodeID:      nodeID1,
						Description: "Valid accounts used",
						Confidence:  0.75,
					},
				},
			},
			validate: func(t *testing.T, result sdkgraphrag.AttackChain) {
				assert.Len(t, result.Steps, 1)
				assert.Equal(t, 1, result.Steps[0].Order)
				assert.Equal(t, "T1078", result.Steps[0].TechniqueID)
				assert.Equal(t, nodeID1.String(), result.Steps[0].NodeID)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toSDKAttackChain(tt.input)
			tt.validate(t, result)
		})
	}
}

// TestRoundTripConversions tests that converting SDK -> Internal -> SDK preserves data
func TestRoundTripConversions(t *testing.T) {
	t.Run("node round trip preserves data", func(t *testing.T) {
		now := time.Now().Truncate(time.Millisecond) // Truncate for comparison
		missionID := types.NewID()

		original := sdkgraphrag.GraphNode{
			ID:        types.NewID().String(),
			Type:      "Finding",
			Content:   "Original content",
			AgentName: "original-agent",
			Properties: map[string]any{
				"severity": "high",
				"count":    42,
			},
			MissionID: missionID.String(),
			CreatedAt: now,
			UpdatedAt: now,
		}

		// Convert to internal and back
		internal := toInternalNode(original)
		result := toSDKNode(internal)

		// Verify data preservation (ID might be different if original was empty)
		assert.NotEmpty(t, result.ID)
		assert.Equal(t, original.Type, result.Type)
		assert.Equal(t, original.Content, result.Content)
		assert.Equal(t, original.AgentName, result.AgentName)
		assert.Equal(t, original.Properties["severity"], result.Properties["severity"])
		assert.Equal(t, original.Properties["count"], result.Properties["count"])
		assert.Equal(t, original.MissionID, result.MissionID)
		assert.Equal(t, original.CreatedAt, result.CreatedAt)
		assert.Equal(t, original.UpdatedAt, result.UpdatedAt)
	})

	t.Run("query round trip preserves data", func(t *testing.T) {
		missionID := types.NewID()

		original := sdkgraphrag.Query{
			Text:         "test query",
			Embedding:    []float64{0.1, 0.2, 0.3},
			TopK:         15,
			MaxHops:      4,
			MinScore:     0.75,
			NodeTypes:    []string{"Finding", "Entity"},
			MissionID:    missionID.String(),
			VectorWeight: 0.6,
			GraphWeight:  0.4,
		}

		// Convert to internal
		internal := toInternalQuery(original)

		// Verify all fields are preserved
		assert.Equal(t, original.Text, internal.Text)
		assert.Equal(t, original.Embedding, internal.Embedding)
		assert.Equal(t, original.TopK, internal.TopK)
		assert.Equal(t, original.MaxHops, internal.MaxHops)
		assert.Equal(t, original.MinScore, internal.MinScore)
		assert.Equal(t, original.VectorWeight, internal.VectorWeight)
		assert.Equal(t, original.GraphWeight, internal.GraphWeight)
		assert.Len(t, internal.NodeTypes, len(original.NodeTypes))
		for i, nt := range original.NodeTypes {
			assert.Equal(t, nt, internal.NodeTypes[i].String())
		}
		require.NotNil(t, internal.MissionID)
		assert.Equal(t, original.MissionID, internal.MissionID.String())
	})
}
