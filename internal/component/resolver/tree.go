package resolver

import (
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/component"
)

// DependencySource indicates where a dependency requirement originated from.
type DependencySource string

const (
	// SourceMissionExplicit indicates the dependency was explicitly listed in the mission dependencies section
	SourceMissionExplicit DependencySource = "mission_explicit"

	// SourceMissionNode indicates the dependency was referenced by a mission node (agent/tool in a mission step)
	SourceMissionNode DependencySource = "mission_node"

	// SourceManifest indicates the dependency came from a component's manifest dependencies.components section
	SourceManifest DependencySource = "manifest"
)

// String returns the string representation of the DependencySource.
func (s DependencySource) String() string {
	return string(s)
}

// IsValid checks if the DependencySource is a valid enum value.
func (s DependencySource) IsValid() bool {
	switch s {
	case SourceMissionExplicit, SourceMissionNode, SourceManifest:
		return true
	default:
		return false
	}
}

// DependencyNode represents a single component in the dependency tree.
// It tracks both the requirement (what is needed) and the current state (what exists).
type DependencyNode struct {
	// Identity fields
	Kind    component.ComponentKind `json:"kind" yaml:"kind"`       // Type of component (agent, tool, plugin)
	Name    string                  `json:"name" yaml:"name"`       // Component name
	Version string                  `json:"version" yaml:"version"` // Required version (semantic version or constraint)

	// Graph structure
	RequiredBy []*DependencyNode `json:"required_by,omitempty" yaml:"required_by,omitempty"` // Parent nodes that depend on this
	DependsOn  []*DependencyNode `json:"depends_on,omitempty" yaml:"depends_on,omitempty"`   // Child nodes this depends on

	// Source tracking
	Source    DependencySource `json:"source" yaml:"source"`         // Where this dependency requirement came from
	SourceRef string           `json:"source_ref" yaml:"source_ref"` // Reference to the source (mission ID, node ID, component name)

	// Current state (populated by resolution)
	Installed     bool                 `json:"installed" yaml:"installed"`                     // True if component is registered in the component store
	Running       bool                 `json:"running" yaml:"running"`                         // True if component is currently running
	Healthy       bool                 `json:"healthy" yaml:"healthy"`                         // True if component passed health checks
	ActualVersion string               `json:"actual_version,omitempty" yaml:"actual_version"` // Actual installed version (may differ from required)
	Component     *component.Component `json:"component,omitempty" yaml:"component,omitempty"` // Reference to the installed component (if exists)
}

// Key returns a unique identifier for this node: "kind:name"
// Used as map keys in the DependencyTree.
func (n *DependencyNode) Key() string {
	return fmt.Sprintf("%s:%s", n.Kind, n.Name)
}

// IsMissing returns true if the component is not installed.
func (n *DependencyNode) IsMissing() bool {
	return !n.Installed
}

// IsStopped returns true if the component is installed but not running.
func (n *DependencyNode) IsStopped() bool {
	return n.Installed && !n.Running
}

// IsUnhealthy returns true if the component is running but failed health checks.
func (n *DependencyNode) IsUnhealthy() bool {
	return n.Running && !n.Healthy
}

// IsSatisfied returns true if the component is installed, running, and healthy.
func (n *DependencyNode) IsSatisfied() bool {
	return n.Installed && n.Running && n.Healthy
}

// AddDependency adds a child dependency and updates bidirectional links.
func (n *DependencyNode) AddDependency(child *DependencyNode) {
	n.DependsOn = append(n.DependsOn, child)
	child.RequiredBy = append(child.RequiredBy, n)
}

// DependencyTree represents the complete dependency graph for a mission.
// It provides a hierarchical view of all required components and their relationships.
type DependencyTree struct {
	// Graph structure
	Roots []*DependencyNode          `json:"roots" yaml:"roots"` // Root nodes (components with no parents in this tree)
	Nodes map[string]*DependencyNode `json:"nodes" yaml:"nodes"` // All nodes indexed by "kind:name"

	// Categorized views (for quick filtering)
	Agents  []*DependencyNode `json:"agents" yaml:"agents"`   // All agent nodes
	Tools   []*DependencyNode `json:"tools" yaml:"tools"`     // All tool nodes
	Plugins []*DependencyNode `json:"plugins" yaml:"plugins"` // All plugin nodes

	// Metadata
	ResolvedAt time.Time `json:"resolved_at" yaml:"resolved_at"` // When this tree was last resolved
	MissionRef string    `json:"mission_ref" yaml:"mission_ref"` // Reference to the mission (ID or name)
}

// NewDependencyTree creates a new empty dependency tree.
func NewDependencyTree(missionRef string) *DependencyTree {
	return &DependencyTree{
		Roots:      make([]*DependencyNode, 0),
		Nodes:      make(map[string]*DependencyNode),
		Agents:     make([]*DependencyNode, 0),
		Tools:      make([]*DependencyNode, 0),
		Plugins:    make([]*DependencyNode, 0),
		MissionRef: missionRef,
		ResolvedAt: time.Now(),
	}
}

// AddNode adds a node to the tree and categorizes it by kind.
// If a node with the same key already exists, it returns the existing node.
func (t *DependencyTree) AddNode(node *DependencyNode) *DependencyNode {
	key := node.Key()

	// Return existing node if already present
	if existing, exists := t.Nodes[key]; exists {
		return existing
	}

	// Add to global node map
	t.Nodes[key] = node

	// Categorize by kind
	switch node.Kind {
	case component.ComponentKindAgent:
		t.Agents = append(t.Agents, node)
	case component.ComponentKindTool:
		t.Tools = append(t.Tools, node)
	case component.ComponentKindPlugin:
		t.Plugins = append(t.Plugins, node)
	}

	return node
}

// GetNode retrieves a node by kind and name.
// Returns nil if not found.
func (t *DependencyTree) GetNode(kind component.ComponentKind, name string) *DependencyNode {
	key := fmt.Sprintf("%s:%s", kind, name)
	return t.Nodes[key]
}

// TopologicalOrder returns all nodes in dependency order (dependencies before dependents).
// Uses Kahn's algorithm for topological sorting.
// Returns an error if the graph contains cycles.
func (t *DependencyTree) TopologicalOrder() ([]*DependencyNode, error) {
	// Calculate in-degrees (number of dependencies)
	inDegree := make(map[string]int)
	for key, node := range t.Nodes {
		inDegree[key] = len(node.DependsOn)
	}

	// Initialize queue with nodes that have no dependencies
	queue := make([]*DependencyNode, 0)
	for key, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, t.Nodes[key])
		}
	}

	// Process queue
	result := make([]*DependencyNode, 0, len(t.Nodes))
	for len(queue) > 0 {
		// Dequeue
		node := queue[0]
		queue = queue[1:]
		result = append(result, node)

		// Reduce in-degree for all dependents
		for _, dependent := range node.RequiredBy {
			key := dependent.Key()
			inDegree[key]--
			if inDegree[key] == 0 {
				queue = append(queue, dependent)
			}
		}
	}

	// Check for cycles
	if len(result) != len(t.Nodes) {
		return nil, fmt.Errorf("dependency graph contains cycles: expected %d nodes, got %d", len(t.Nodes), len(result))
	}

	return result, nil
}

// GetMissing returns all nodes where the component is not installed.
func (t *DependencyTree) GetMissing() []*DependencyNode {
	missing := make([]*DependencyNode, 0)
	for _, node := range t.Nodes {
		if node.IsMissing() {
			missing = append(missing, node)
		}
	}
	return missing
}

// GetStopped returns all nodes where the component is installed but not running.
func (t *DependencyTree) GetStopped() []*DependencyNode {
	stopped := make([]*DependencyNode, 0)
	for _, node := range t.Nodes {
		if node.IsStopped() {
			stopped = append(stopped, node)
		}
	}
	return stopped
}

// GetUnhealthy returns all nodes where the component is running but failed health checks.
func (t *DependencyTree) GetUnhealthy() []*DependencyNode {
	unhealthy := make([]*DependencyNode, 0)
	for _, node := range t.Nodes {
		if node.IsUnhealthy() {
			unhealthy = append(unhealthy, node)
		}
	}
	return unhealthy
}

// GetUnsatisfied returns all nodes that are not fully satisfied (missing, stopped, or unhealthy).
func (t *DependencyTree) GetUnsatisfied() []*DependencyNode {
	unsatisfied := make([]*DependencyNode, 0)
	for _, node := range t.Nodes {
		if !node.IsSatisfied() {
			unsatisfied = append(unsatisfied, node)
		}
	}
	return unsatisfied
}

// IsFullySatisfied returns true if all nodes are installed, running, and healthy.
func (t *DependencyTree) IsFullySatisfied() bool {
	for _, node := range t.Nodes {
		if !node.IsSatisfied() {
			return false
		}
	}
	return true
}

// CountByKind returns the number of nodes for each component kind.
func (t *DependencyTree) CountByKind() map[component.ComponentKind]int {
	counts := make(map[component.ComponentKind]int)
	for _, node := range t.Nodes {
		counts[node.Kind]++
	}
	return counts
}

// CountByState returns counts of nodes in different states.
func (t *DependencyTree) CountByState() map[string]int {
	return map[string]int{
		"total":     len(t.Nodes),
		"satisfied": len(t.Nodes) - len(t.GetUnsatisfied()),
		"missing":   len(t.GetMissing()),
		"stopped":   len(t.GetStopped()),
		"unhealthy": len(t.GetUnhealthy()),
	}
}
