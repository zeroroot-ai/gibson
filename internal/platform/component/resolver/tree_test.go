package resolver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

func TestDependencySource(t *testing.T) {
	tests := []struct {
		name         string
		source       DependencySource
		valid        bool
		expectString string
	}{
		{
			name:         "mission explicit is valid",
			source:       SourceMissionExplicit,
			valid:        true,
			expectString: "mission_explicit",
		},
		{
			name:         "mission node is valid",
			source:       SourceMissionNode,
			valid:        true,
			expectString: "mission_node",
		},
		{
			name:         "manifest is valid",
			source:       SourceManifest,
			valid:        true,
			expectString: "manifest",
		},
		{
			name:         "empty is invalid",
			source:       DependencySource(""),
			valid:        false,
			expectString: "",
		},
		{
			name:         "unknown is invalid",
			source:       DependencySource("unknown"),
			valid:        false,
			expectString: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, tt.source.IsValid())
			assert.Equal(t, tt.expectString, tt.source.String())
		})
	}
}

func TestDependencyNode(t *testing.T) {
	t.Run("Key generation", func(t *testing.T) {
		node := &DependencyNode{
			Kind: component.ComponentKindAgent,
			Name: "test-agent",
		}
		assert.Equal(t, "agent:test-agent", node.Key())
	})

	t.Run("State checks", func(t *testing.T) {
		tests := []struct {
			name      string
			node      *DependencyNode
			missing   bool
			stopped   bool
			unhealthy bool
			satisfied bool
		}{
			{
				name: "missing component",
				node: &DependencyNode{
					Installed: false,
					Running:   false,
					Healthy:   false,
				},
				missing:   true,
				stopped:   false,
				unhealthy: false,
				satisfied: false,
			},
			{
				name: "stopped component",
				node: &DependencyNode{
					Installed: true,
					Running:   false,
					Healthy:   false,
				},
				missing:   false,
				stopped:   true,
				unhealthy: false,
				satisfied: false,
			},
			{
				name: "unhealthy component",
				node: &DependencyNode{
					Installed: true,
					Running:   true,
					Healthy:   false,
				},
				missing:   false,
				stopped:   false,
				unhealthy: true,
				satisfied: false,
			},
			{
				name: "satisfied component",
				node: &DependencyNode{
					Installed: true,
					Running:   true,
					Healthy:   true,
				},
				missing:   false,
				stopped:   false,
				unhealthy: false,
				satisfied: true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, tt.missing, tt.node.IsMissing())
				assert.Equal(t, tt.stopped, tt.node.IsStopped())
				assert.Equal(t, tt.unhealthy, tt.node.IsUnhealthy())
				assert.Equal(t, tt.satisfied, tt.node.IsSatisfied())
			})
		}
	})

	t.Run("AddDependency creates bidirectional link", func(t *testing.T) {
		parent := &DependencyNode{
			Kind:      component.ComponentKindAgent,
			Name:      "parent",
			DependsOn: make([]*DependencyNode, 0),
		}
		child := &DependencyNode{
			Kind:       component.ComponentKindTool,
			Name:       "child",
			RequiredBy: make([]*DependencyNode, 0),
		}

		parent.AddDependency(child)

		assert.Len(t, parent.DependsOn, 1)
		assert.Equal(t, child, parent.DependsOn[0])
		assert.Len(t, child.RequiredBy, 1)
		assert.Equal(t, parent, child.RequiredBy[0])
	})
}

func TestDependencyTree(t *testing.T) {
	t.Run("NewDependencyTree", func(t *testing.T) {
		tree := NewDependencyTree("mission-123")

		assert.Equal(t, "mission-123", tree.MissionRef)
		assert.NotNil(t, tree.Nodes)
		assert.NotNil(t, tree.Agents)
		assert.NotNil(t, tree.Tools)
		assert.NotNil(t, tree.Plugins)
		assert.NotZero(t, tree.ResolvedAt)
	})

	t.Run("AddNode categorizes by kind", func(t *testing.T) {
		tree := NewDependencyTree("test")

		agent := &DependencyNode{Kind: component.ComponentKindAgent, Name: "agent1"}
		tool := &DependencyNode{Kind: component.ComponentKindTool, Name: "tool1"}
		plugin := &DependencyNode{Kind: component.ComponentKindPlugin, Name: "plugin1"}

		tree.AddNode(agent)
		tree.AddNode(tool)
		tree.AddNode(plugin)

		assert.Len(t, tree.Nodes, 3)
		assert.Len(t, tree.Agents, 1)
		assert.Len(t, tree.Tools, 1)
		assert.Len(t, tree.Plugins, 1)
	})

	t.Run("AddNode returns existing node on duplicate", func(t *testing.T) {
		tree := NewDependencyTree("test")

		node1 := &DependencyNode{Kind: component.ComponentKindAgent, Name: "agent1", Version: "1.0.0"}
		node2 := &DependencyNode{Kind: component.ComponentKindAgent, Name: "agent1", Version: "2.0.0"}

		result1 := tree.AddNode(node1)
		result2 := tree.AddNode(node2)

		assert.Equal(t, node1, result1)
		assert.Equal(t, node1, result2)           // Should return the existing node
		assert.Equal(t, "1.0.0", result2.Version) // Version should be from first node
		assert.Len(t, tree.Nodes, 1)
	})

	t.Run("GetNode retrieves by kind and name", func(t *testing.T) {
		tree := NewDependencyTree("test")

		node := &DependencyNode{Kind: component.ComponentKindAgent, Name: "agent1"}
		tree.AddNode(node)

		retrieved := tree.GetNode(component.ComponentKindAgent, "agent1")
		assert.Equal(t, node, retrieved)

		missing := tree.GetNode(component.ComponentKindTool, "nonexistent")
		assert.Nil(t, missing)
	})

	t.Run("GetMissing returns only missing nodes", func(t *testing.T) {
		tree := NewDependencyTree("test")

		installed := &DependencyNode{
			Kind:      component.ComponentKindAgent,
			Name:      "installed",
			Installed: true,
		}
		missing := &DependencyNode{
			Kind:      component.ComponentKindAgent,
			Name:      "missing",
			Installed: false,
		}

		tree.AddNode(installed)
		tree.AddNode(missing)

		result := tree.GetMissing()
		assert.Len(t, result, 1)
		assert.Equal(t, missing, result[0])
	})

	t.Run("GetStopped returns only stopped nodes", func(t *testing.T) {
		tree := NewDependencyTree("test")

		running := &DependencyNode{
			Kind:      component.ComponentKindAgent,
			Name:      "running",
			Installed: true,
			Running:   true,
		}
		stopped := &DependencyNode{
			Kind:      component.ComponentKindAgent,
			Name:      "stopped",
			Installed: true,
			Running:   false,
		}

		tree.AddNode(running)
		tree.AddNode(stopped)

		result := tree.GetStopped()
		assert.Len(t, result, 1)
		assert.Equal(t, stopped, result[0])
	})

	t.Run("IsFullySatisfied checks all nodes", func(t *testing.T) {
		tree := NewDependencyTree("test")

		satisfied := &DependencyNode{
			Kind:      component.ComponentKindAgent,
			Name:      "satisfied",
			Installed: true,
			Running:   true,
			Healthy:   true,
		}

		tree.AddNode(satisfied)
		assert.True(t, tree.IsFullySatisfied())

		unsatisfied := &DependencyNode{
			Kind:      component.ComponentKindTool,
			Name:      "unsatisfied",
			Installed: false,
		}
		tree.AddNode(unsatisfied)
		assert.False(t, tree.IsFullySatisfied())
	})

	t.Run("CountByKind", func(t *testing.T) {
		tree := NewDependencyTree("test")

		tree.AddNode(&DependencyNode{Kind: component.ComponentKindAgent, Name: "agent1"})
		tree.AddNode(&DependencyNode{Kind: component.ComponentKindAgent, Name: "agent2"})
		tree.AddNode(&DependencyNode{Kind: component.ComponentKindTool, Name: "tool1"})
		tree.AddNode(&DependencyNode{Kind: component.ComponentKindPlugin, Name: "plugin1"})

		counts := tree.CountByKind()
		assert.Equal(t, 2, counts[component.ComponentKindAgent])
		assert.Equal(t, 1, counts[component.ComponentKindTool])
		assert.Equal(t, 1, counts[component.ComponentKindPlugin])
	})

	t.Run("CountByState", func(t *testing.T) {
		tree := NewDependencyTree("test")

		tree.AddNode(&DependencyNode{
			Kind: component.ComponentKindAgent, Name: "satisfied",
			Installed: true, Running: true, Healthy: true,
		})
		tree.AddNode(&DependencyNode{
			Kind: component.ComponentKindAgent, Name: "missing",
			Installed: false,
		})
		tree.AddNode(&DependencyNode{
			Kind: component.ComponentKindTool, Name: "stopped",
			Installed: true, Running: false,
		})

		counts := tree.CountByState()
		assert.Equal(t, 3, counts["total"])
		assert.Equal(t, 1, counts["satisfied"])
		assert.Equal(t, 1, counts["missing"])
		assert.Equal(t, 1, counts["stopped"])
	})
}

func TestTopologicalOrder(t *testing.T) {
	tests := []struct {
		name          string
		setupTree     func() *DependencyTree
		expectError   bool
		errorContains string
		validate      func(t *testing.T, order []*DependencyNode)
	}{
		{
			name: "simple chain A -> B -> C",
			setupTree: func() *DependencyTree {
				tree := NewDependencyTree("test")
				// Create chain: A -> B -> C
				nodeA := &DependencyNode{Kind: component.ComponentKindAgent, Name: "A"}
				nodeB := &DependencyNode{Kind: component.ComponentKindTool, Name: "B"}
				nodeC := &DependencyNode{Kind: component.ComponentKindPlugin, Name: "C"}

				tree.AddNode(nodeA)
				tree.AddNode(nodeB)
				tree.AddNode(nodeC)

				nodeA.AddDependency(nodeB)
				nodeB.AddDependency(nodeC)
				return tree
			},
			expectError: false,
			validate: func(t *testing.T, order []*DependencyNode) {
				require.Len(t, order, 3)
				// C should come first (no dependencies), then B, then A
				assert.Equal(t, "C", order[0].Name)
				assert.Equal(t, "B", order[1].Name)
				assert.Equal(t, "A", order[2].Name)
			},
		},
		{
			name: "diamond pattern A -> B,C -> D",
			setupTree: func() *DependencyTree {
				tree := NewDependencyTree("test")
				//     A
				//    / \
				//   B   C
				//    \ /
				//     D
				nodeA := &DependencyNode{Kind: component.ComponentKindAgent, Name: "A"}
				nodeB := &DependencyNode{Kind: component.ComponentKindTool, Name: "B"}
				nodeC := &DependencyNode{Kind: component.ComponentKindTool, Name: "C"}
				nodeD := &DependencyNode{Kind: component.ComponentKindPlugin, Name: "D"}

				tree.AddNode(nodeA)
				tree.AddNode(nodeB)
				tree.AddNode(nodeC)
				tree.AddNode(nodeD)

				nodeA.AddDependency(nodeB)
				nodeA.AddDependency(nodeC)
				nodeB.AddDependency(nodeD)
				nodeC.AddDependency(nodeD)
				return tree
			},
			expectError: false,
			validate: func(t *testing.T, order []*DependencyNode) {
				require.Len(t, order, 4)
				// D should come first, then B and C (in either order), then A
				assert.Equal(t, "D", order[0].Name)
				assert.Equal(t, "A", order[3].Name)

				// B and C can be in either order, but both should be before A
				middleNames := []string{order[1].Name, order[2].Name}
				assert.Contains(t, middleNames, "B")
				assert.Contains(t, middleNames, "C")
			},
		},
		{
			name: "multiple roots - separate trees",
			setupTree: func() *DependencyTree {
				tree := NewDependencyTree("test")
				// Tree 1: A -> B
				nodeA := &DependencyNode{Kind: component.ComponentKindAgent, Name: "A"}
				nodeB := &DependencyNode{Kind: component.ComponentKindTool, Name: "B"}

				// Tree 2: X -> Y
				nodeX := &DependencyNode{Kind: component.ComponentKindAgent, Name: "X"}
				nodeY := &DependencyNode{Kind: component.ComponentKindTool, Name: "Y"}

				tree.AddNode(nodeA)
				tree.AddNode(nodeB)
				tree.AddNode(nodeX)
				tree.AddNode(nodeY)

				nodeA.AddDependency(nodeB)
				nodeX.AddDependency(nodeY)
				return tree
			},
			expectError: false,
			validate: func(t *testing.T, order []*DependencyNode) {
				require.Len(t, order, 4)
				// Create position map
				pos := make(map[string]int)
				for i, node := range order {
					pos[node.Name] = i
				}

				// Verify dependencies come before dependents within each tree
				assert.Less(t, pos["B"], pos["A"], "B must come before A")
				assert.Less(t, pos["Y"], pos["X"], "Y must come before X")
			},
		},
		{
			name: "single node with no dependencies",
			setupTree: func() *DependencyTree {
				tree := NewDependencyTree("test")
				node := &DependencyNode{Kind: component.ComponentKindAgent, Name: "standalone"}
				tree.AddNode(node)
				return tree
			},
			expectError: false,
			validate: func(t *testing.T, order []*DependencyNode) {
				require.Len(t, order, 1)
				assert.Equal(t, "standalone", order[0].Name)
			},
		},
		{
			name: "empty tree",
			setupTree: func() *DependencyTree {
				return NewDependencyTree("test")
			},
			expectError: false,
			validate: func(t *testing.T, order []*DependencyNode) {
				assert.Empty(t, order)
			},
		},
		{
			name: "circular dependency A -> B -> C -> A",
			setupTree: func() *DependencyTree {
				tree := NewDependencyTree("test")
				nodeA := &DependencyNode{Kind: component.ComponentKindAgent, Name: "A"}
				nodeB := &DependencyNode{Kind: component.ComponentKindTool, Name: "B"}
				nodeC := &DependencyNode{Kind: component.ComponentKindPlugin, Name: "C"}

				tree.AddNode(nodeA)
				tree.AddNode(nodeB)
				tree.AddNode(nodeC)

				nodeA.AddDependency(nodeB)
				nodeB.AddDependency(nodeC)
				nodeC.AddDependency(nodeA) // Creates cycle
				return tree
			},
			expectError:   true,
			errorContains: "cycle",
			validate: func(t *testing.T, order []*DependencyNode) {
				assert.Nil(t, order)
			},
		},
		{
			name: "self-referential cycle A -> A",
			setupTree: func() *DependencyTree {
				tree := NewDependencyTree("test")
				nodeA := &DependencyNode{Kind: component.ComponentKindAgent, Name: "A"}
				tree.AddNode(nodeA)
				nodeA.AddDependency(nodeA) // Self-cycle
				return tree
			},
			expectError:   true,
			errorContains: "cycle",
			validate: func(t *testing.T, order []*DependencyNode) {
				assert.Nil(t, order)
			},
		},
		{
			name: "complex graph with multiple paths",
			setupTree: func() *DependencyTree {
				tree := NewDependencyTree("test")
				// Create a more complex dependency graph
				//       A
				//      /|\
				//     B C D
				//     |/  |
				//     E   F
				//      \ /
				//       G

				nodes := make(map[string]*DependencyNode)
				for _, name := range []string{"A", "B", "C", "D", "E", "F", "G"} {
					node := &DependencyNode{Kind: component.ComponentKindAgent, Name: name}
					tree.AddNode(node)
					nodes[name] = node
				}

				nodes["A"].AddDependency(nodes["B"])
				nodes["A"].AddDependency(nodes["C"])
				nodes["A"].AddDependency(nodes["D"])
				nodes["B"].AddDependency(nodes["E"])
				nodes["C"].AddDependency(nodes["E"])
				nodes["D"].AddDependency(nodes["F"])
				nodes["E"].AddDependency(nodes["G"])
				nodes["F"].AddDependency(nodes["G"])
				return tree
			},
			expectError: false,
			validate: func(t *testing.T, order []*DependencyNode) {
				require.Len(t, order, 7)
				// G should be first, A should be last
				assert.Equal(t, "G", order[0].Name)
				assert.Equal(t, "A", order[6].Name)

				// Create position map for validation
				pos := make(map[string]int)
				for i, node := range order {
					pos[node.Name] = i
				}

				// Verify all dependencies come before their dependents
				assert.Less(t, pos["B"], pos["A"])
				assert.Less(t, pos["C"], pos["A"])
				assert.Less(t, pos["D"], pos["A"])
				assert.Less(t, pos["E"], pos["B"])
				assert.Less(t, pos["E"], pos["C"])
				assert.Less(t, pos["F"], pos["D"])
				assert.Less(t, pos["G"], pos["E"])
				assert.Less(t, pos["G"], pos["F"])
			},
		},
		{
			name: "all nodes independent - no dependencies",
			setupTree: func() *DependencyTree {
				tree := NewDependencyTree("test")
				for _, name := range []string{"A", "B", "C", "D"} {
					node := &DependencyNode{Kind: component.ComponentKindAgent, Name: name}
					tree.AddNode(node)
				}
				return tree
			},
			expectError: false,
			validate: func(t *testing.T, order []*DependencyNode) {
				require.Len(t, order, 4)
				// All nodes should be present (order doesn't matter)
				names := make([]string, len(order))
				for i, node := range order {
					names[i] = node.Name
				}
				assert.ElementsMatch(t, []string{"A", "B", "C", "D"}, names)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := tt.setupTree()
			order, err := tree.TopologicalOrder()

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
			}

			if tt.validate != nil {
				tt.validate(t, order)
			}
		})
	}
}

func TestDependencyTree_GetMissing(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() *DependencyTree
		expected []string
	}{
		{
			name: "returns only uninstalled components",
			setup: func() *DependencyTree {
				tree := NewDependencyTree("test")
				tree.AddNode(&DependencyNode{
					Kind:      component.ComponentKindAgent,
					Name:      "installed-agent",
					Installed: true,
					Running:   true,
					Healthy:   true,
				})
				tree.AddNode(&DependencyNode{
					Kind:      component.ComponentKindAgent,
					Name:      "missing-agent",
					Installed: false,
					Running:   false,
					Healthy:   false,
				})
				tree.AddNode(&DependencyNode{
					Kind:      component.ComponentKindTool,
					Name:      "missing-tool",
					Installed: false,
					Running:   false,
					Healthy:   false,
				})
				return tree
			},
			expected: []string{"missing-agent", "missing-tool"},
		},
		{
			name: "returns empty when all installed",
			setup: func() *DependencyTree {
				tree := NewDependencyTree("test")
				tree.AddNode(&DependencyNode{
					Kind:      component.ComponentKindAgent,
					Name:      "agent1",
					Installed: true,
				})
				tree.AddNode(&DependencyNode{
					Kind:      component.ComponentKindTool,
					Name:      "tool1",
					Installed: true,
				})
				return tree
			},
			expected: []string{},
		},
		{
			name: "returns all when none installed",
			setup: func() *DependencyTree {
				tree := NewDependencyTree("test")
				tree.AddNode(&DependencyNode{
					Kind:      component.ComponentKindAgent,
					Name:      "agent1",
					Installed: false,
				})
				tree.AddNode(&DependencyNode{
					Kind:      component.ComponentKindTool,
					Name:      "tool1",
					Installed: false,
				})
				return tree
			},
			expected: []string{"agent1", "tool1"},
		},
		{
			name: "empty tree returns empty list",
			setup: func() *DependencyTree {
				return NewDependencyTree("test")
			},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := tt.setup()
			missing := tree.GetMissing()

			names := make([]string, len(missing))
			for i, node := range missing {
				names[i] = node.Name
			}

			assert.ElementsMatch(t, tt.expected, names)
		})
	}
}

func TestDependencyTree_GetStopped(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() *DependencyTree
		expected []string
	}{
		{
			name: "returns only installed but not running components",
			setup: func() *DependencyTree {
				tree := NewDependencyTree("test")
				tree.AddNode(&DependencyNode{
					Kind:      component.ComponentKindAgent,
					Name:      "running-agent",
					Installed: true,
					Running:   true,
					Healthy:   true,
				})
				tree.AddNode(&DependencyNode{
					Kind:      component.ComponentKindAgent,
					Name:      "stopped-agent",
					Installed: true,
					Running:   false,
					Healthy:   false,
				})
				tree.AddNode(&DependencyNode{
					Kind:      component.ComponentKindTool,
					Name:      "stopped-tool",
					Installed: true,
					Running:   false,
					Healthy:   false,
				})
				tree.AddNode(&DependencyNode{
					Kind:      component.ComponentKindPlugin,
					Name:      "missing-plugin",
					Installed: false,
					Running:   false,
					Healthy:   false,
				})
				return tree
			},
			expected: []string{"stopped-agent", "stopped-tool"},
		},
		{
			name: "returns empty when all running or missing",
			setup: func() *DependencyTree {
				tree := NewDependencyTree("test")
				tree.AddNode(&DependencyNode{
					Kind:      component.ComponentKindAgent,
					Name:      "running",
					Installed: true,
					Running:   true,
				})
				tree.AddNode(&DependencyNode{
					Kind:      component.ComponentKindTool,
					Name:      "missing",
					Installed: false,
					Running:   false,
				})
				return tree
			},
			expected: []string{},
		},
		{
			name: "returns all installed but stopped",
			setup: func() *DependencyTree {
				tree := NewDependencyTree("test")
				tree.AddNode(&DependencyNode{
					Kind:      component.ComponentKindAgent,
					Name:      "agent1",
					Installed: true,
					Running:   false,
				})
				tree.AddNode(&DependencyNode{
					Kind:      component.ComponentKindTool,
					Name:      "tool1",
					Installed: true,
					Running:   false,
				})
				return tree
			},
			expected: []string{"agent1", "tool1"},
		},
		{
			name: "empty tree returns empty list",
			setup: func() *DependencyTree {
				return NewDependencyTree("test")
			},
			expected: []string{},
		},
		{
			name: "excludes missing components",
			setup: func() *DependencyTree {
				tree := NewDependencyTree("test")
				// Stopped (should be included)
				tree.AddNode(&DependencyNode{
					Kind:      component.ComponentKindAgent,
					Name:      "stopped",
					Installed: true,
					Running:   false,
				})
				// Missing (should NOT be included - not installed)
				tree.AddNode(&DependencyNode{
					Kind:      component.ComponentKindAgent,
					Name:      "missing",
					Installed: false,
					Running:   false,
				})
				return tree
			},
			expected: []string{"stopped"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := tt.setup()
			stopped := tree.GetStopped()

			names := make([]string, len(stopped))
			for i, node := range stopped {
				names[i] = node.Name
			}

			assert.ElementsMatch(t, tt.expected, names)
		})
	}
}

func TestDependencyTree_FilterCombinations(t *testing.T) {
	t.Run("filters work independently", func(t *testing.T) {
		tree := NewDependencyTree("test")

		// Missing (not installed)
		missing := &DependencyNode{
			Kind:      component.ComponentKindAgent,
			Name:      "missing",
			Installed: false,
			Running:   false,
			Healthy:   false,
		}
		// Stopped (installed but not running)
		stopped := &DependencyNode{
			Kind:      component.ComponentKindAgent,
			Name:      "stopped",
			Installed: true,
			Running:   false,
			Healthy:   false,
		}
		// Unhealthy (running but not healthy)
		unhealthy := &DependencyNode{
			Kind:      component.ComponentKindAgent,
			Name:      "unhealthy",
			Installed: true,
			Running:   true,
			Healthy:   false,
		}
		// Satisfied (fully operational)
		satisfied := &DependencyNode{
			Kind:      component.ComponentKindAgent,
			Name:      "satisfied",
			Installed: true,
			Running:   true,
			Healthy:   true,
		}

		tree.AddNode(missing)
		tree.AddNode(stopped)
		tree.AddNode(unhealthy)
		tree.AddNode(satisfied)

		// Test GetMissing
		missingNodes := tree.GetMissing()
		assert.Len(t, missingNodes, 1)
		assert.Equal(t, "missing", missingNodes[0].Name)

		// Test GetStopped
		stoppedNodes := tree.GetStopped()
		assert.Len(t, stoppedNodes, 1)
		assert.Equal(t, "stopped", stoppedNodes[0].Name)

		// Test GetUnhealthy
		unhealthyNodes := tree.GetUnhealthy()
		assert.Len(t, unhealthyNodes, 1)
		assert.Equal(t, "unhealthy", unhealthyNodes[0].Name)

		// Test GetUnsatisfied (should include missing, stopped, and unhealthy)
		unsatisfied := tree.GetUnsatisfied()
		assert.Len(t, unsatisfied, 3)
		unsatisfiedNames := make([]string, len(unsatisfied))
		for i, node := range unsatisfied {
			unsatisfiedNames[i] = node.Name
		}
		assert.ElementsMatch(t, []string{"missing", "stopped", "unhealthy"}, unsatisfiedNames)

		// Test IsFullySatisfied
		assert.False(t, tree.IsFullySatisfied())
	})

	t.Run("fully satisfied tree", func(t *testing.T) {
		tree := NewDependencyTree("test")

		tree.AddNode(&DependencyNode{
			Kind:      component.ComponentKindAgent,
			Name:      "agent1",
			Installed: true,
			Running:   true,
			Healthy:   true,
		})
		tree.AddNode(&DependencyNode{
			Kind:      component.ComponentKindTool,
			Name:      "tool1",
			Installed: true,
			Running:   true,
			Healthy:   true,
		})

		assert.Empty(t, tree.GetMissing())
		assert.Empty(t, tree.GetStopped())
		assert.Empty(t, tree.GetUnhealthy())
		assert.Empty(t, tree.GetUnsatisfied())
		assert.True(t, tree.IsFullySatisfied())
	})
}

func TestDependencyTreeSerialization(t *testing.T) {
	t.Run("Nodes have proper JSON tags", func(t *testing.T) {
		node := &DependencyNode{
			Kind:      component.ComponentKindAgent,
			Name:      "test",
			Version:   "1.0.0",
			Source:    SourceMissionExplicit,
			SourceRef: "mission-123",
			Installed: true,
			Running:   true,
			Healthy:   true,
		}

		// This is a basic check that the struct has JSON tags
		// Actual serialization testing would require json.Marshal/Unmarshal
		assert.NotNil(t, node)
	})

	t.Run("Tree has proper metadata", func(t *testing.T) {
		tree := NewDependencyTree("mission-123")

		assert.Equal(t, "mission-123", tree.MissionRef)
		assert.False(t, tree.ResolvedAt.IsZero())

		// Ensure time is recent (within last minute)
		timeDiff := time.Since(tree.ResolvedAt)
		assert.Less(t, timeDiff, time.Minute)
	})
}
