package mission

import (
	"fmt"
	"strings"
)

// ValidNodeTypes defines the allowed workflow node types.
var ValidNodeTypes = []string{
	"agent",
	"tool",
	"plugin",
	"condition",
	"parallel",
	"join",
}

// WorkflowNode defines a workflow node configuration.
type WorkflowNode struct {
	ID        string
	Type      string
	Name      string
	DependsOn []string
	Config    map[string]any
}

// WorkflowEdge defines a workflow edge configuration.
type WorkflowEdge struct {
	From      string
	To        string
	Condition string
}

// InlineWorkflow defines an inline workflow configuration.
type InlineWorkflow struct {
	Name     string
	Nodes    []*WorkflowNode
	Edges    []*WorkflowEdge
	Metadata map[string]any
}

// ValidateInlineWorkflow validates an inline workflow configuration.
// It ensures:
// - At least one node is defined
// - All nodes have valid types
// - Node IDs are unique
// - Node dependencies reference existing nodes
// - No circular dependencies exist
func ValidateInlineWorkflow(config *InlineWorkflow) error {
	if config == nil {
		return fmt.Errorf("inline workflow config is required")
	}

	// Validate nodes
	if len(config.Nodes) == 0 {
		return fmt.Errorf("at least one node is required")
	}

	// Build node ID map for lookup
	nodeIDs := make(map[string]bool)
	for i, node := range config.Nodes {
		if err := validateWorkflowNode(node, i); err != nil {
			return err
		}
		if nodeIDs[node.ID] {
			return fmt.Errorf("duplicate node ID '%s'", node.ID)
		}
		nodeIDs[node.ID] = true
	}

	// Validate node dependencies
	for _, node := range config.Nodes {
		for _, depID := range node.DependsOn {
			if !nodeIDs[depID] {
				return fmt.Errorf("node '%s' depends on non-existent node '%s'",
					node.ID, depID)
			}
		}
	}

	// Validate edges if provided
	for i, edge := range config.Edges {
		if err := validateWorkflowEdge(edge, i, nodeIDs); err != nil {
			return err
		}
	}

	// Check for circular dependencies
	if err := detectCircularDependencies(config.Nodes); err != nil {
		return err
	}

	return nil
}

// validateWorkflowNode validates a single workflow node.
func validateWorkflowNode(node *WorkflowNode, index int) error {
	if node == nil {
		return fmt.Errorf("node at index %d is nil", index)
	}

	if node.ID == "" {
		return fmt.Errorf("node at index %d has empty ID", index)
	}

	if node.Type == "" {
		return fmt.Errorf("node '%s' has empty type", node.ID)
	}

	if !isValidWorkflowNodeType(node.Type) {
		return fmt.Errorf("node '%s' has invalid type '%s', allowed: %s",
			node.ID, node.Type, strings.Join(ValidNodeTypes, ", "))
	}

	if node.Name == "" {
		return fmt.Errorf("node '%s' has empty name", node.ID)
	}

	return nil
}

// validateWorkflowEdge validates a single workflow edge.
func validateWorkflowEdge(edge *WorkflowEdge, index int, nodeIDs map[string]bool) error {
	if edge == nil {
		return fmt.Errorf("edge at index %d is nil", index)
	}

	if edge.From == "" {
		return fmt.Errorf("edge at index %d has empty 'from' field", index)
	}

	if edge.To == "" {
		return fmt.Errorf("edge at index %d has empty 'to' field", index)
	}

	if !nodeIDs[edge.From] {
		return fmt.Errorf("edge at index %d references non-existent source node '%s'",
			index, edge.From)
	}

	if !nodeIDs[edge.To] {
		return fmt.Errorf("edge at index %d references non-existent target node '%s'",
			index, edge.To)
	}

	return nil
}

// isValidWorkflowNodeType checks if a node type is valid.
func isValidWorkflowNodeType(nodeType string) bool {
	for _, valid := range ValidNodeTypes {
		if nodeType == valid {
			return true
		}
	}
	return false
}

// detectCircularDependencies detects circular dependencies in the workflow DAG.
// Uses depth-first search to detect cycles.
func detectCircularDependencies(nodes []*WorkflowNode) error {
	// Build adjacency list
	graph := make(map[string][]string)
	for _, node := range nodes {
		graph[node.ID] = node.DependsOn
	}

	// Track visited nodes and nodes in current path
	visited := make(map[string]bool)
	inPath := make(map[string]bool)

	// DFS to detect cycles
	var dfs func(nodeID string, path []string) error
	dfs = func(nodeID string, path []string) error {
		if inPath[nodeID] {
			// Found a cycle
			cycleStart := -1
			for i, id := range path {
				if id == nodeID {
					cycleStart = i
					break
				}
			}
			cycle := append(path[cycleStart:], nodeID)
			return fmt.Errorf("circular dependency detected: %s",
				strings.Join(cycle, " -> "))
		}

		if visited[nodeID] {
			return nil
		}

		visited[nodeID] = true
		inPath[nodeID] = true
		path = append(path, nodeID)

		for _, depID := range graph[nodeID] {
			if err := dfs(depID, path); err != nil {
				return err
			}
		}

		inPath[nodeID] = false
		return nil
	}

	// Check all nodes
	for _, node := range nodes {
		if !visited[node.ID] {
			if err := dfs(node.ID, []string{}); err != nil {
				return err
			}
		}
	}

	return nil
}
