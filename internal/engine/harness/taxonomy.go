package harness

import (
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
)

// TaxonomyIntrospector provides read-only access to the taxonomy registry.
// This interface allows agents to query available node types, relationships,
// and extensions without being able to modify the registry.
//
// The introspector is the agent-facing view of the TaxonomyRegistry, exposing
// only query operations for discovering available taxonomy types at runtime.
type TaxonomyIntrospector = sdkgraphrag.TaxonomyIntrospector

// TaxonomyRegistry returns the taxonomy introspector for querying available
// node types and relationships in the knowledge graph.
//
// The introspector provides read-only access to:
//   - Core taxonomy types (Host, Port, Service, Finding, etc.)
//   - Agent-installed taxonomy extensions (custom node types and relationships)
//   - Metadata about which agent owns each extension
//
// Use cases:
//   - Discover what custom node types are available before emitting CustomNodes
//   - Query relationship types for building ExplicitRelationships
//   - Determine which extension owns a particular node type
//   - List all agent extensions that have been installed
//
// Returns nil if the taxonomy registry is not available (should not happen in
// normal operation as the registry is always initialized by the daemon).
//
// Example:
//
//	introspector := harness.TaxonomyRegistry()
//	if introspector == nil {
//	    return errors.New("taxonomy registry not available")
//	}
//
//	// Query core types
//	coreTypes := introspector.GetNodeTypes()
//	for _, nodeType := range coreTypes {
//	    harness.Logger().Info("core node type", "type", nodeType)
//	}
//
//	// Query extensions
//	extensions := introspector.ExtensionNames()
//	for _, extName := range extensions {
//	    ext := introspector.ExtensionInfo(extName)
//	    harness.Logger().Info("agent extension",
//	        "agent", extName,
//	        "node_types", len(ext.NodeTypes),
//	        "relationships", len(ext.Relationships))
//	}
//
//	// Check who owns a node type
//	source := introspector.NodeTypeSource("gitlab_secret")
//	// Returns "core" for core types, agent name for extensions, or "unknown"
func (h *DefaultAgentHarness) TaxonomyRegistry() sdkgraphrag.TaxonomyIntrospector {
	return h.taxonomyRegistry
}
