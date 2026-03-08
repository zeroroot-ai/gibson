package resolver

import (
	"fmt"
	"strings"
)

// DependencyGraph represents a directed graph of component dependencies.
type DependencyGraph struct {
	// Nodes maps component keys (kind:name) to their dependency lists
	Nodes map[string][]string

	// NodeInfo stores additional information about each node
	NodeInfo map[string]*DependencyNode
}

// NewDependencyGraph creates a new empty dependency graph.
func NewDependencyGraph() *DependencyGraph {
	return &DependencyGraph{
		Nodes:    make(map[string][]string),
		NodeInfo: make(map[string]*DependencyNode),
	}
}

// AddNode adds a node to the graph.
func (g *DependencyGraph) AddNode(key string, node *DependencyNode) {
	if _, exists := g.Nodes[key]; !exists {
		g.Nodes[key] = make([]string, 0)
	}
	g.NodeInfo[key] = node
}

// AddEdge adds a directed edge from 'from' node to 'to' node.
// This represents that 'from' depends on 'to'.
func (g *DependencyGraph) AddEdge(from, to string) {
	if _, exists := g.Nodes[from]; !exists {
		g.Nodes[from] = make([]string, 0)
	}
	g.Nodes[from] = append(g.Nodes[from], to)
}

// BuildFromTree constructs a dependency graph from a dependency tree.
func BuildDependencyGraph(tree *DependencyTree) *DependencyGraph {
	graph := NewDependencyGraph()

	if tree == nil || len(tree.Nodes) == 0 {
		return graph
	}

	// Add all nodes to the graph
	for key, node := range tree.Nodes {
		graph.AddNode(key, node)
	}

	// Add edges based on DependsOn relationships
	for key, node := range tree.Nodes {
		for _, dep := range node.DependsOn {
			depKey := dep.Key()
			graph.AddEdge(key, depKey)
		}
	}

	return graph
}

// CycleDetector detects circular dependencies in a dependency graph.
type CycleDetector struct {
	graph    *DependencyGraph
	visited  map[string]bool
	inStack  map[string]bool
	cyclePath []string
}

// NewCycleDetector creates a new cycle detector for the given graph.
func NewCycleDetector(graph *DependencyGraph) *CycleDetector {
	return &CycleDetector{
		graph:    graph,
		visited:  make(map[string]bool),
		inStack:  make(map[string]bool),
		cyclePath: make([]string, 0),
	}
}

// DetectCycle checks if the graph contains any cycles.
// Returns true and the cycle path if a cycle is found, false and nil otherwise.
func (d *CycleDetector) DetectCycle() (bool, []string) {
	// Try to find a cycle starting from each unvisited node
	for node := range d.graph.Nodes {
		if !d.visited[node] {
			if d.dfs(node) {
				return true, d.cyclePath
			}
		}
	}

	return false, nil
}

// dfs performs depth-first search to detect cycles.
// Returns true if a cycle is detected starting from the given node.
func (d *CycleDetector) dfs(node string) bool {
	// Mark the current node as visited and part of recursion stack
	d.visited[node] = true
	d.inStack[node] = true

	// Explore all dependencies
	if deps, exists := d.graph.Nodes[node]; exists {
		for _, dep := range deps {
			if !d.visited[dep] {
				// Recursively visit unvisited dependency
				if d.dfs(dep) {
					// Cycle found in deeper recursion, propagate it up
					d.cyclePath = append([]string{node}, d.cyclePath...)
					return true
				}
			} else if d.inStack[dep] {
				// Found a back edge - this is a cycle!
				// Build the cycle path from dep back to itself
				d.cyclePath = []string{dep, node}
				return true
			}
		}
	}

	// Remove node from recursion stack before returning
	d.inStack[node] = false
	return false
}

// DetectAllCycles finds all cycles in the graph (not just the first one).
// This is more expensive but provides complete cycle information.
func (d *CycleDetector) DetectAllCycles() [][]string {
	cycles := make([][]string, 0)

	// Reset state for each search
	for node := range d.graph.Nodes {
		d.visited = make(map[string]bool)
		d.inStack = make(map[string]bool)
		d.cyclePath = make([]string, 0)

		if d.dfs(node) && len(d.cyclePath) > 0 {
			// Found a cycle, add it if not already present
			if !containsCycle(cycles, d.cyclePath) {
				cycles = append(cycles, d.cyclePath)
			}
		}
	}

	return cycles
}

// containsCycle checks if a cycle is already in the list of cycles.
// Two cycles are considered the same if they contain the same nodes (order may differ).
func containsCycle(cycles [][]string, cycle []string) bool {
	for _, existing := range cycles {
		if cyclesEqual(existing, cycle) {
			return true
		}
	}
	return false
}

// cyclesEqual checks if two cycles contain the same nodes.
func cyclesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	// Create a set of nodes from cycle a
	setA := make(map[string]bool)
	for _, node := range a {
		setA[node] = true
	}

	// Check if all nodes from b are in a
	for _, node := range b {
		if !setA[node] {
			return false
		}
	}

	return true
}

// ValidateDependencyTree checks a dependency tree for cycles.
// Returns nil if no cycles are found, or a DependencyError describing the cycle.
func ValidateDependencyTree(tree *DependencyTree) error {
	if tree == nil || len(tree.Nodes) == 0 {
		return nil
	}

	graph := BuildDependencyGraph(tree)
	detector := NewCycleDetector(graph)

	hasCycle, cyclePath := detector.DetectCycle()
	if hasCycle {
		return NewCircularDependencyError(cyclePath)
	}

	return nil
}

// DetectCycleBeforeAdd checks for cycles before adding a new dependency.
// This allows proactive cycle detection before modifying the graph.
func DetectCycleBeforeAdd(tree *DependencyTree, from *DependencyNode, to *DependencyNode) error {
	if tree == nil || from == nil || to == nil {
		return nil
	}

	// Build graph from current tree
	graph := BuildDependencyGraph(tree)

	// Add the proposed edge
	graph.AddEdge(from.Key(), to.Key())

	// Check for cycles
	detector := NewCycleDetector(graph)
	hasCycle, cyclePath := detector.DetectCycle()
	if hasCycle {
		return NewCircularDependencyError(cyclePath)
	}

	return nil
}

// formatCyclePath formats a cycle path for error messages.
func formatCyclePath(path []string) string {
	if len(path) == 0 {
		return "circular dependency detected"
	}

	// Create a readable cycle representation: A -> B -> C -> A
	cycle := strings.Join(path, " -> ")
	if len(path) > 0 {
		cycle += " -> " + path[0] // Close the cycle
	}

	return fmt.Sprintf("circular dependency detected: %s", cycle)
}

// DependencyType represents the type of dependency.
type DependencyType string

const (
	// DependencyTypeHard represents a hard dependency (must be satisfied)
	DependencyTypeHard DependencyType = "hard"

	// DependencyTypeSoft represents a soft dependency (optional)
	DependencyTypeSoft DependencyType = "soft"
)

// TypedDependencyGraph extends DependencyGraph with dependency type information.
type TypedDependencyGraph struct {
	*DependencyGraph
	// EdgeTypes maps "from:to" to dependency type
	EdgeTypes map[string]DependencyType
}

// NewTypedDependencyGraph creates a new typed dependency graph.
func NewTypedDependencyGraph() *TypedDependencyGraph {
	return &TypedDependencyGraph{
		DependencyGraph: NewDependencyGraph(),
		EdgeTypes:       make(map[string]DependencyType),
	}
}

// AddTypedEdge adds a directed edge with a type.
func (g *TypedDependencyGraph) AddTypedEdge(from, to string, depType DependencyType) {
	g.AddEdge(from, to)
	edgeKey := from + ":" + to
	g.EdgeTypes[edgeKey] = depType
}

// GetEdgeType returns the dependency type for an edge.
func (g *TypedDependencyGraph) GetEdgeType(from, to string) DependencyType {
	edgeKey := from + ":" + to
	if depType, exists := g.EdgeTypes[edgeKey]; exists {
		return depType
	}
	return DependencyTypeHard // Default to hard dependency
}

// ValidateHardDependencies validates only hard dependencies for cycles.
// Soft dependencies are allowed to form cycles.
func ValidateHardDependencies(graph *TypedDependencyGraph) error {
	if graph == nil || len(graph.Nodes) == 0 {
		return nil
	}

	// Create a filtered graph with only hard dependencies
	hardGraph := NewDependencyGraph()
	for node := range graph.Nodes {
		hardGraph.AddNode(node, graph.NodeInfo[node])
	}

	for from, deps := range graph.Nodes {
		for _, to := range deps {
			if graph.GetEdgeType(from, to) == DependencyTypeHard {
				hardGraph.AddEdge(from, to)
			}
		}
	}

	// Check for cycles in hard dependencies only
	detector := NewCycleDetector(hardGraph)
	hasCycle, cyclePath := detector.DetectCycle()
	if hasCycle {
		return NewCircularDependencyError(cyclePath)
	}

	return nil
}
