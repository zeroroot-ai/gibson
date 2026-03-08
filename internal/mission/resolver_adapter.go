package mission

import (
	"strings"

	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/component/resolver"
)

// missionDefinitionAdapter adapts MissionDefinition to resolver.MissionDefinition interface.
// This avoids circular dependencies between mission and resolver packages.
type missionDefinitionAdapter struct {
	def *MissionDefinition
}

// NewResolverAdapter creates a new adapter that implements resolver.MissionDefinition.
func NewResolverAdapter(def *MissionDefinition) resolver.MissionDefinition {
	return &missionDefinitionAdapter{def: def}
}

// Nodes returns all nodes in the mission.
func (m *missionDefinitionAdapter) Nodes() []resolver.MissionNode {
	if m.def.Nodes == nil {
		return []resolver.MissionNode{}
	}

	nodes := make([]resolver.MissionNode, 0, len(m.def.Nodes))
	for _, node := range m.def.Nodes {
		nodes = append(nodes, &missionNodeAdapter{node: node})
	}
	return nodes
}

// Dependencies returns explicitly declared dependencies from the mission YAML.
func (m *missionDefinitionAdapter) Dependencies() []resolver.MissionDependency {
	if m.def.Dependencies == nil {
		return []resolver.MissionDependency{}
	}

	deps := make([]resolver.MissionDependency, 0)

	// Add agent dependencies
	for _, agent := range m.def.Dependencies.Agents {
		name, version := parseComponentRef(agent)
		deps = append(deps, &missionDependencyAdapter{
			kind:    component.ComponentKindAgent,
			name:    name,
			version: version,
		})
	}

	// Add tool dependencies
	for _, tool := range m.def.Dependencies.Tools {
		name, version := parseComponentRef(tool)
		deps = append(deps, &missionDependencyAdapter{
			kind:    component.ComponentKindTool,
			name:    name,
			version: version,
		})
	}

	// Add plugin dependencies
	for _, plugin := range m.def.Dependencies.Plugins {
		name, version := parseComponentRef(plugin)
		deps = append(deps, &missionDependencyAdapter{
			kind:    component.ComponentKindPlugin,
			name:    name,
			version: version,
		})
	}

	return deps
}

// missionNodeAdapter adapts MissionNode to resolver.MissionNode interface.
type missionNodeAdapter struct {
	node *MissionNode
}

// ID returns the unique identifier for this node within the mission.
func (m *missionNodeAdapter) ID() string {
	return m.node.ID
}

// Type returns the node type (agent, tool, plugin, condition, parallel, join).
func (m *missionNodeAdapter) Type() string {
	return string(m.node.Type)
}

// ComponentRef returns the name of the component referenced by this node.
// Returns empty string for non-component nodes (condition, parallel, join).
func (m *missionNodeAdapter) ComponentRef() string {
	switch m.node.Type {
	case NodeTypeAgent:
		return m.node.AgentName
	case NodeTypeTool:
		return m.node.ToolName
	case NodeTypePlugin:
		return m.node.PluginName
	default:
		return ""
	}
}

// missionDependencyAdapter adapts a dependency string to resolver.MissionDependency interface.
type missionDependencyAdapter struct {
	kind    component.ComponentKind
	name    string
	version string
}

// Kind returns the component kind (agent, tool, plugin).
func (m *missionDependencyAdapter) Kind() component.ComponentKind {
	return m.kind
}

// Name returns the component name.
func (m *missionDependencyAdapter) Name() string {
	return m.name
}

// Version returns the version constraint (e.g., ">=1.0.0", "^2.0.0").
// Returns empty string if no version constraint is specified.
func (m *missionDependencyAdapter) Version() string {
	return m.version
}

// parseComponentRef parses a component reference in "name" or "name@version" format.
// Returns the component name and version separately.
// If no version is specified or the version part doesn't look valid, returns empty version.
func parseComponentRef(ref string) (name, version string) {
	// Handle empty ref
	if ref == "" {
		return "", ""
	}

	// Look for @ separator (last occurrence to handle names with @)
	idx := strings.LastIndex(ref, "@")
	if idx == -1 {
		// No version specified
		return ref, ""
	}

	// Split at @
	name = ref[:idx]
	version = ref[idx+1:]

	// Validate version looks like a version
	if !isValidVersion(version) {
		// Treat entire string as name if version doesn't look valid
		return ref, ""
	}

	return name, version
}

// isValidVersion checks if a string looks like a semantic version.
// A valid version should start with a digit or 'v' followed by a digit.
func isValidVersion(v string) bool {
	if v == "" {
		return false
	}
	// Simple check: starts with digit or 'v'
	if v[0] == 'v' {
		v = v[1:]
	}
	if len(v) == 0 {
		return false
	}
	return v[0] >= '0' && v[0] <= '9'
}
