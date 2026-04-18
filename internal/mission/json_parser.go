package mission

import (
	"encoding/json"
	"fmt"
)

// ParseDefinitionFromJSON parses a mission definition from JSON bytes.
// This is used when resuming missions from stored MissionDefinitionJSON.
// Unlike ParseDefinitionFromBytes (YAML), this handles the JSON field names
// and numeric duration values produced by json.Marshal.
//
// The MissionDefinition and MissionNode structs already have correct JSON tags,
// so we can use standard json.Unmarshal directly. The only special handling
// needed is validation of required fields after unmarshaling.
//
// Parameters:
//   - data: JSON bytes to parse (typically from database MissionDefinitionJSON column)
//
// Returns:
//   - *MissionDefinition: The parsed mission definition
//   - error: Validation or parsing error, or nil on success
//
// Example usage:
//
//	def, err := ParseDefinitionFromJSON([]byte(missionRecord.MissionDefinitionJSON))
//	if err != nil {
//	    return fmt.Errorf("failed to parse mission definition: %w", err)
//	}
func ParseDefinitionFromJSON(data []byte) (*MissionDefinition, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("cannot parse empty JSON data")
	}

	var def MissionDefinition
	if err := json.Unmarshal(data, &def); err != nil {
		return nil, fmt.Errorf("failed to unmarshal mission definition: %w", err)
	}

	// Validate required fields
	if def.Name == "" {
		return nil, fmt.Errorf("mission name is required")
	}

	// Validate nodes - ensure type-specific required fields are present
	for id, node := range def.Nodes {
		if node == nil {
			return nil, fmt.Errorf("node %s is nil", id)
		}

		// Ensure node ID matches map key if not set
		if node.ID == "" {
			node.ID = id
		}

		// Validate type-specific required fields
		if err := validateNode(id, node); err != nil {
			return nil, err
		}
	}

	return &def, nil
}

// validateNode validates that a node has all required fields for its type
func validateNode(id string, node *MissionNode) error {
	switch node.Type {
	case NodeTypeAgent:
		if node.AgentName == "" {
			return fmt.Errorf("agent node %s requires 'agent_name' field", id)
		}
	case NodeTypeTool:
		if node.ToolName == "" {
			return fmt.Errorf("tool node %s requires 'tool_name' field", id)
		}
	case NodeTypePlugin:
		if node.PluginName == "" {
			return fmt.Errorf("plugin node %s requires 'plugin_name' field", id)
		}
		if node.PluginMethod == "" {
			return fmt.Errorf("plugin node %s requires 'plugin_method' field", id)
		}
	case NodeTypeCondition:
		if node.Condition == nil {
			return fmt.Errorf("condition node %s requires 'condition' field", id)
		}
		if node.Condition.Expression == "" {
			return fmt.Errorf("condition node %s requires 'condition.expression' field", id)
		}
	case NodeTypeParallel:
		if len(node.SubNodes) == 0 {
			return fmt.Errorf("parallel node %s requires 'sub_nodes' field", id)
		}
		// Validate sub-nodes recursively
		for i, subNode := range node.SubNodes {
			if subNode == nil {
				return fmt.Errorf("parallel node %s has nil sub_node at index %d", id, i)
			}
			if err := validateNode(fmt.Sprintf("%s.sub_nodes[%d]", id, i), subNode); err != nil {
				return err
			}
		}
	case NodeTypeJoin:
		// Join nodes don't have special requirements beyond basic node fields
	default:
		return fmt.Errorf("node %s has invalid type: %s", id, node.Type)
	}

	return nil
}
