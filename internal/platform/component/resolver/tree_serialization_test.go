package resolver

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"gopkg.in/yaml.v3"
)

func TestDependencyNode_JSONSerialization(t *testing.T) {
	tests := []struct {
		name string
		node *DependencyNode
	}{
		{
			name: "fully populated node",
			node: &DependencyNode{
				Kind:          component.ComponentKindAgent,
				Name:          "test-agent",
				Version:       "1.0.0",
				Source:        SourceMissionExplicit,
				SourceRef:     "mission-123",
				Installed:     true,
				Running:       true,
				Healthy:       true,
				ActualVersion: "1.0.0",
			},
		},
		{
			name: "minimal node",
			node: &DependencyNode{
				Kind:      component.ComponentKindTool,
				Name:      "minimal-tool",
				Version:   "2.0.0",
				Source:    SourceManifest,
				SourceRef: "parent",
			},
		},
		{
			name: "plugin node with partial state",
			node: &DependencyNode{
				Kind:      component.ComponentKindPlugin,
				Name:      "test-plugin",
				Version:   "3.0.0",
				Source:    SourceMissionNode,
				SourceRef: "node-1",
				Installed: true,
				Running:   false,
				Healthy:   false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to JSON
			data, err := json.Marshal(tt.node)
			require.NoError(t, err)
			assert.NotEmpty(t, data)

			// Unmarshal back
			var decoded DependencyNode
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			// Verify fields match
			assert.Equal(t, tt.node.Kind, decoded.Kind)
			assert.Equal(t, tt.node.Name, decoded.Name)
			assert.Equal(t, tt.node.Version, decoded.Version)
			assert.Equal(t, tt.node.Source, decoded.Source)
			assert.Equal(t, tt.node.SourceRef, decoded.SourceRef)
			assert.Equal(t, tt.node.Installed, decoded.Installed)
			assert.Equal(t, tt.node.Running, decoded.Running)
			assert.Equal(t, tt.node.Healthy, decoded.Healthy)
			assert.Equal(t, tt.node.ActualVersion, decoded.ActualVersion)
		})
	}
}

func TestDependencyNode_YAMLSerialization(t *testing.T) {
	tests := []struct {
		name string
		node *DependencyNode
	}{
		{
			name: "agent node",
			node: &DependencyNode{
				Kind:          component.ComponentKindAgent,
				Name:          "yaml-agent",
				Version:       "1.0.0",
				Source:        SourceMissionExplicit,
				SourceRef:     "mission-456",
				Installed:     true,
				Running:       true,
				Healthy:       true,
				ActualVersion: "1.0.0",
			},
		},
		{
			name: "tool node",
			node: &DependencyNode{
				Kind:      component.ComponentKindTool,
				Name:      "yaml-tool",
				Version:   "2.0.0",
				Source:    SourceManifest,
				SourceRef: "parent-component",
				Installed: false,
				Running:   false,
				Healthy:   false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to YAML
			data, err := yaml.Marshal(tt.node)
			require.NoError(t, err)
			assert.NotEmpty(t, data)

			// Unmarshal back
			var decoded DependencyNode
			err = yaml.Unmarshal(data, &decoded)
			require.NoError(t, err)

			// Verify fields match
			assert.Equal(t, tt.node.Kind, decoded.Kind)
			assert.Equal(t, tt.node.Name, decoded.Name)
			assert.Equal(t, tt.node.Version, decoded.Version)
			assert.Equal(t, tt.node.Source, decoded.Source)
			assert.Equal(t, tt.node.SourceRef, decoded.SourceRef)
			assert.Equal(t, tt.node.Installed, decoded.Installed)
			assert.Equal(t, tt.node.Running, decoded.Running)
			assert.Equal(t, tt.node.Healthy, decoded.Healthy)
			assert.Equal(t, tt.node.ActualVersion, decoded.ActualVersion)
		})
	}
}

func TestDependencyTree_JSONSerialization(t *testing.T) {
	t.Run("tree with mixed component types", func(t *testing.T) {
		tree := NewDependencyTree("mission-123")

		// Add nodes of each type
		agent := &DependencyNode{
			Kind:      component.ComponentKindAgent,
			Name:      "agent1",
			Version:   "1.0.0",
			Source:    SourceMissionNode,
			SourceRef: "node-1",
			Installed: true,
			Running:   true,
			Healthy:   true,
		}
		tool := &DependencyNode{
			Kind:      component.ComponentKindTool,
			Name:      "tool1",
			Version:   "2.0.0",
			Source:    SourceManifest,
			SourceRef: "agent1",
			Installed: true,
			Running:   false,
			Healthy:   false,
		}
		plugin := &DependencyNode{
			Kind:      component.ComponentKindPlugin,
			Name:      "plugin1",
			Version:   "3.0.0",
			Source:    SourceMissionExplicit,
			SourceRef: "mission-123",
			Installed: false,
			Running:   false,
			Healthy:   false,
		}

		tree.AddNode(agent)
		tree.AddNode(tool)
		tree.AddNode(plugin)

		// Marshal to JSON
		data, err := json.Marshal(tree)
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		// Verify JSON structure
		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Equal(t, "mission-123", result["mission_ref"])
		assert.NotNil(t, result["resolved_at"])

		// Verify nodes map
		nodes, ok := result["nodes"].(map[string]interface{})
		require.True(t, ok)
		assert.Len(t, nodes, 3)
		assert.Contains(t, nodes, "agent:agent1")
		assert.Contains(t, nodes, "tool:tool1")
		assert.Contains(t, nodes, "plugin:plugin1")

		// Verify categorization
		agents, ok := result["agents"].([]interface{})
		require.True(t, ok)
		assert.Len(t, agents, 1)

		tools, ok := result["tools"].([]interface{})
		require.True(t, ok)
		assert.Len(t, tools, 1)

		plugins, ok := result["plugins"].([]interface{})
		require.True(t, ok)
		assert.Len(t, plugins, 1)

		// Unmarshal back to tree
		var decoded DependencyTree
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, tree.MissionRef, decoded.MissionRef)
		assert.Len(t, decoded.Nodes, 3)
		assert.Len(t, decoded.Agents, 1)
		assert.Len(t, decoded.Tools, 1)
		assert.Len(t, decoded.Plugins, 1)
	})

	t.Run("empty tree serialization", func(t *testing.T) {
		tree := NewDependencyTree("empty-mission")

		// Marshal to JSON
		data, err := json.Marshal(tree)
		require.NoError(t, err)

		// Unmarshal back
		var decoded DependencyTree
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, tree.MissionRef, decoded.MissionRef)
		assert.Empty(t, decoded.Nodes)
		assert.Empty(t, decoded.Agents)
		assert.Empty(t, decoded.Tools)
		assert.Empty(t, decoded.Plugins)
	})
}

func TestDependencyTree_YAMLSerialization(t *testing.T) {
	t.Run("tree with single plugin", func(t *testing.T) {
		tree := NewDependencyTree("test-mission")

		plugin := &DependencyNode{
			Kind:      component.ComponentKindPlugin,
			Name:      "plugin1",
			Version:   "3.0.0",
			Source:    SourceMissionExplicit,
			SourceRef: "mission-456",
			Installed: false,
			Running:   false,
			Healthy:   false,
		}

		tree.AddNode(plugin)

		// Marshal to YAML
		data, err := yaml.Marshal(tree)
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		// Verify YAML structure
		var result map[string]interface{}
		err = yaml.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Equal(t, "test-mission", result["mission_ref"])
		assert.NotNil(t, result["resolved_at"])

		// Unmarshal back to tree
		var decoded DependencyTree
		err = yaml.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, tree.MissionRef, decoded.MissionRef)
		assert.Len(t, decoded.Nodes, 1)
		assert.Len(t, decoded.Plugins, 1)
		assert.Empty(t, decoded.Agents)
		assert.Empty(t, decoded.Tools)
	})

	t.Run("round trip preserves all data", func(t *testing.T) {
		tree := NewDependencyTree("yaml-test")

		agent := &DependencyNode{
			Kind:          component.ComponentKindAgent,
			Name:          "test-agent",
			Version:       "1.0.0",
			Source:        SourceMissionNode,
			SourceRef:     "node-1",
			Installed:     true,
			Running:       true,
			Healthy:       true,
			ActualVersion: "1.0.0",
		}
		tree.AddNode(agent)

		// Marshal to YAML
		data, err := yaml.Marshal(tree)
		require.NoError(t, err)

		// Unmarshal back
		var decoded DependencyTree
		err = yaml.Unmarshal(data, &decoded)
		require.NoError(t, err)

		// Verify all data preserved
		assert.Equal(t, tree.MissionRef, decoded.MissionRef)
		require.Len(t, decoded.Agents, 1)

		decodedAgent := decoded.Agents[0]
		assert.Equal(t, agent.Kind, decodedAgent.Kind)
		assert.Equal(t, agent.Name, decodedAgent.Name)
		assert.Equal(t, agent.Version, decodedAgent.Version)
		assert.Equal(t, agent.Source, decodedAgent.Source)
		assert.Equal(t, agent.SourceRef, decodedAgent.SourceRef)
		assert.Equal(t, agent.Installed, decodedAgent.Installed)
		assert.Equal(t, agent.Running, decodedAgent.Running)
		assert.Equal(t, agent.Healthy, decodedAgent.Healthy)
		assert.Equal(t, agent.ActualVersion, decodedAgent.ActualVersion)
	})
}

func TestDependencyTree_SerializationWithRelationships(t *testing.T) {
	t.Run("dependency relationships create cycles - expected JSON limitation", func(t *testing.T) {
		tree := NewDependencyTree("test")

		// Create a simple chain
		nodeA := &DependencyNode{
			Kind:    component.ComponentKindAgent,
			Name:    "A",
			Version: "1.0",
			Source:  SourceMissionNode,
		}
		nodeB := &DependencyNode{
			Kind:    component.ComponentKindTool,
			Name:    "B",
			Version: "2.0",
			Source:  SourceManifest,
		}

		tree.AddNode(nodeA)
		tree.AddNode(nodeB)
		nodeA.AddDependency(nodeB)

		// Verify relationships exist before serialization
		require.Len(t, nodeA.DependsOn, 1)
		require.Len(t, nodeB.RequiredBy, 1)

		// Note: JSON marshaling will fail with cycles due to DependsOn/RequiredBy pointers
		// This is expected behavior - the tree structure with bidirectional pointers
		// creates cycles that JSON cannot serialize
		_, err := json.Marshal(tree)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cycle")

		// This is a known limitation. If serialization is needed, the tree would need:
		// 1. Custom MarshalJSON that omits circular references
		// 2. Reconstruction of relationships after deserialization
		// 3. Or use of reference IDs instead of direct pointers
		// For now, the tree is primarily used in-memory during resolution
	})

	t.Run("nodes without relationships can be serialized", func(t *testing.T) {
		tree := NewDependencyTree("test")

		// Add nodes without establishing dependencies
		nodeA := &DependencyNode{
			Kind:    component.ComponentKindAgent,
			Name:    "A",
			Version: "1.0",
			Source:  SourceMissionNode,
		}
		nodeB := &DependencyNode{
			Kind:    component.ComponentKindTool,
			Name:    "B",
			Version: "2.0",
			Source:  SourceManifest,
		}

		tree.AddNode(nodeA)
		tree.AddNode(nodeB)
		// Don't call AddDependency - no cycles

		// This should work fine
		data, err := json.Marshal(tree)
		require.NoError(t, err)

		var decoded DependencyTree
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		// Verify structure is preserved
		assert.Len(t, decoded.Nodes, 2)
		decodedA := decoded.GetNode(component.ComponentKindAgent, "A")
		decodedB := decoded.GetNode(component.ComponentKindTool, "B")

		require.NotNil(t, decodedA)
		require.NotNil(t, decodedB)
	})
}

func TestDependencyNode_JSONFieldMapping(t *testing.T) {
	t.Run("JSON field names match expected format", func(t *testing.T) {
		node := &DependencyNode{
			Kind:          component.ComponentKindAgent,
			Name:          "test-agent",
			Version:       "1.0.0",
			Source:        SourceMissionExplicit,
			SourceRef:     "mission-123",
			Installed:     true,
			Running:       true,
			Healthy:       true,
			ActualVersion: "1.0.0",
		}

		// Marshal to JSON
		data, err := json.Marshal(node)
		require.NoError(t, err)

		// Parse as map to check field names
		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		// Verify expected JSON field names
		assert.Contains(t, result, "kind")
		assert.Contains(t, result, "name")
		assert.Contains(t, result, "version")
		assert.Contains(t, result, "source")
		assert.Contains(t, result, "source_ref")
		assert.Contains(t, result, "installed")
		assert.Contains(t, result, "running")
		assert.Contains(t, result, "healthy")
		assert.Contains(t, result, "actual_version")

		// Verify values
		assert.Equal(t, "agent", result["kind"])
		assert.Equal(t, "test-agent", result["name"])
		assert.Equal(t, "1.0.0", result["version"])
		assert.Equal(t, "mission_explicit", result["source"])
		assert.Equal(t, "mission-123", result["source_ref"])
		assert.Equal(t, true, result["installed"])
		assert.Equal(t, true, result["running"])
		assert.Equal(t, true, result["healthy"])
		assert.Equal(t, "1.0.0", result["actual_version"])
	})
}

func TestDependencyTree_JSONFieldMapping(t *testing.T) {
	t.Run("tree JSON field names match expected format", func(t *testing.T) {
		tree := NewDependencyTree("mission-123")
		tree.AddNode(&DependencyNode{
			Kind:    component.ComponentKindAgent,
			Name:    "agent1",
			Version: "1.0.0",
			Source:  SourceMissionNode,
		})

		// Marshal to JSON
		data, err := json.Marshal(tree)
		require.NoError(t, err)

		// Parse as map to check field names
		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		// Verify expected JSON field names
		assert.Contains(t, result, "roots")
		assert.Contains(t, result, "nodes")
		assert.Contains(t, result, "agents")
		assert.Contains(t, result, "tools")
		assert.Contains(t, result, "plugins")
		assert.Contains(t, result, "resolved_at")
		assert.Contains(t, result, "mission_ref")

		// Verify mission_ref value
		assert.Equal(t, "mission-123", result["mission_ref"])
	})
}
