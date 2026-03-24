package harness

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkgraphrag "github.com/zero-day-ai/sdk/graphrag"
)

// TestTaxonomyRegistry_NilRegistry tests that TaxonomyRegistry() returns nil
// when no registry is configured.
func TestTaxonomyRegistry_NilRegistry(t *testing.T) {
	// Create a harness with nil taxonomy registry
	h := &DefaultAgentHarness{
		taxonomyRegistry: nil,
	}

	// Should return nil when not configured
	registry := h.TaxonomyRegistry()
	assert.Nil(t, registry, "expected nil registry when not configured")
}

// TestTaxonomyRegistry_WithRegistry tests that TaxonomyRegistry() returns
// the configured registry.
func TestTaxonomyRegistry_WithRegistry(t *testing.T) {
	// Create a taxonomy registry with core taxonomy
	coreTaxonomy := sdkgraphrag.NewSimpleTaxonomy()
	taxonomyRegistry := sdkgraphrag.NewTaxonomyRegistry(coreTaxonomy)

	// Create a harness with the registry
	h := &DefaultAgentHarness{
		taxonomyRegistry: taxonomyRegistry,
	}

	// Should return the configured registry
	registry := h.TaxonomyRegistry()
	require.NotNil(t, registry, "expected non-nil registry")

	// Verify we can query the registry
	version := registry.Version()
	assert.NotEmpty(t, version, "expected non-empty taxonomy version")

	// Verify we can get node types
	nodeTypes := registry.NodeTypes()
	assert.NotEmpty(t, nodeTypes, "expected core taxonomy to have node types")

	// Verify core types exist
	hostInfo := registry.NodeTypeInfo("Host")
	require.NotNil(t, hostInfo, "expected Host node type to exist in core taxonomy")
	assert.Equal(t, "Host", hostInfo.Name)
}

// TestTaxonomyRegistry_Extensions tests that agents can query extensions
// from the taxonomy registry.
func TestTaxonomyRegistry_Extensions(t *testing.T) {
	// Create a taxonomy registry with core taxonomy
	coreTaxonomy := sdkgraphrag.NewSimpleTaxonomy()
	taxonomyRegistry := sdkgraphrag.NewTaxonomyRegistry(coreTaxonomy)

	// Register a test extension
	testExtension := sdkgraphrag.TaxonomyExtension{
		NodeTypes: []sdkgraphrag.NodeTypeDefinition{
			{
				Name:        "test_node",
				Category:    "test",
				Description: "Test node type",
				Properties: []sdkgraphrag.PropertyInfo{
					{
						Name:        "test_property",
						Type:        "string",
						Description: "Test property",
						Required:    true,
					},
				},
			},
		},
		Relationships: []sdkgraphrag.RelationshipDefinition{
			{
				Name:      "TEST_REL",
				FromTypes: []string{"test_node"},
				ToTypes:   []string{"Host"},
			},
		},
	}

	err := taxonomyRegistry.RegisterExtension("test-agent", testExtension)
	require.NoError(t, err, "failed to register test extension")

	// Create a harness with the registry
	h := &DefaultAgentHarness{
		taxonomyRegistry: taxonomyRegistry,
	}

	// Get the registry
	registry := h.TaxonomyRegistry()
	require.NotNil(t, registry)

	// Query extensions
	extensions := registry.ExtensionNames()
	assert.Contains(t, extensions, "test-agent", "expected test-agent extension to be registered")

	// Get extension info
	extInfo := registry.ExtensionInfo("test-agent")
	require.NotNil(t, extInfo, "expected extension info for test-agent")
	assert.Len(t, extInfo.NodeTypes, 1, "expected 1 node type in extension")
	assert.Equal(t, "test_node", extInfo.NodeTypes[0].Name)

	// Query node type source
	source := registry.NodeTypeSource("test_node")
	assert.Equal(t, "test-agent", source, "expected test_node to belong to test-agent")

	// Query core type source
	hostSource := registry.NodeTypeSource("Host")
	assert.Equal(t, "core", hostSource, "expected Host to belong to core taxonomy")
}

// TestTaxonomyRegistry_MultipleExtensions tests that multiple agent extensions
// can coexist and be queried independently.
func TestTaxonomyRegistry_MultipleExtensions(t *testing.T) {
	// Create a taxonomy registry with core taxonomy
	coreTaxonomy := sdkgraphrag.NewSimpleTaxonomy()
	taxonomyRegistry := sdkgraphrag.NewTaxonomyRegistry(coreTaxonomy)

	// Register first extension
	ext1 := sdkgraphrag.TaxonomyExtension{
		NodeTypes: []sdkgraphrag.NodeTypeDefinition{
			{
				Name:        "cloud_instance",
				Category:    "asset",
				Description: "Cloud compute instance",
			},
		},
	}
	err := taxonomyRegistry.RegisterExtension("cloud-agent", ext1)
	require.NoError(t, err)

	// Register second extension
	ext2 := sdkgraphrag.TaxonomyExtension{
		NodeTypes: []sdkgraphrag.NodeTypeDefinition{
			{
				Name:        "api_key",
				Category:    "credential",
				Description: "API authentication key",
			},
		},
	}
	err = taxonomyRegistry.RegisterExtension("secrets-agent", ext2)
	require.NoError(t, err)

	// Create harness
	h := &DefaultAgentHarness{
		taxonomyRegistry: taxonomyRegistry,
	}

	registry := h.TaxonomyRegistry()
	require.NotNil(t, registry)

	// Verify both extensions are present
	extensions := registry.ExtensionNames()
	assert.Len(t, extensions, 2, "expected 2 extensions")
	assert.Contains(t, extensions, "cloud-agent")
	assert.Contains(t, extensions, "secrets-agent")

	// Verify node type sources
	assert.Equal(t, "cloud-agent", registry.NodeTypeSource("cloud_instance"))
	assert.Equal(t, "secrets-agent", registry.NodeTypeSource("api_key"))
	assert.Equal(t, "core", registry.NodeTypeSource("Host"))
	assert.Equal(t, "unknown", registry.NodeTypeSource("nonexistent"))
}

// TestTaxonomyRegistry_NodeTypeInfo tests that agents can query detailed
// node type information including properties.
func TestTaxonomyRegistry_NodeTypeInfo(t *testing.T) {
	// Create a taxonomy registry with core taxonomy
	coreTaxonomy := sdkgraphrag.NewSimpleTaxonomy()
	taxonomyRegistry := sdkgraphrag.NewTaxonomyRegistry(coreTaxonomy)

	// Register extension with detailed node type
	ext := sdkgraphrag.TaxonomyExtension{
		NodeTypes: []sdkgraphrag.NodeTypeDefinition{
			{
				Name:        "database",
				Category:    "asset",
				Description: "Database instance",
				Properties: []sdkgraphrag.PropertyInfo{
					{
						Name:        "db_type",
						Type:        "string",
						Description: "Database type (mysql, postgres, etc.)",
						Required:    true,
					},
					{
						Name:        "version",
						Type:        "string",
						Description: "Database version",
						Required:    false,
					},
				},
			},
		},
	}
	err := taxonomyRegistry.RegisterExtension("db-agent", ext)
	require.NoError(t, err)

	// Create harness
	h := &DefaultAgentHarness{
		taxonomyRegistry: taxonomyRegistry,
	}

	registry := h.TaxonomyRegistry()
	require.NotNil(t, registry)

	// Query node type info
	dbInfo := registry.NodeTypeInfo("database")
	require.NotNil(t, dbInfo, "expected database node type info")
	assert.Equal(t, "database", dbInfo.Name)
	assert.Equal(t, "asset", dbInfo.Category)
	assert.Equal(t, "Database instance", dbInfo.Description)
	assert.Len(t, dbInfo.Properties, 2)

	// Verify property details
	dbTypeProp := dbInfo.Properties[0]
	assert.Equal(t, "db_type", dbTypeProp.Name)
	assert.Equal(t, "string", dbTypeProp.Type)
	assert.True(t, dbTypeProp.Required)

	versionProp := dbInfo.Properties[1]
	assert.Equal(t, "version", versionProp.Name)
	assert.False(t, versionProp.Required)
}

// TestTaxonomyRegistry_RelationshipTypes tests that agents can query
// relationship types from extensions.
func TestTaxonomyRegistry_RelationshipTypes(t *testing.T) {
	// Create a taxonomy registry with core taxonomy
	coreTaxonomy := sdkgraphrag.NewSimpleTaxonomy()
	taxonomyRegistry := sdkgraphrag.NewTaxonomyRegistry(coreTaxonomy)

	// Register extension with custom relationships
	ext := sdkgraphrag.TaxonomyExtension{
		NodeTypes: []sdkgraphrag.NodeTypeDefinition{
			{
				Name:     "container",
				Category: "asset",
			},
		},
		Relationships: []sdkgraphrag.RelationshipDefinition{
			{
				Name:        "RUNS_CONTAINER",
				Category:    "runtime",
				Description: "Host runs container",
				FromTypes:   []string{"Host"},
				ToTypes:     []string{"container"},
			},
		},
	}
	err := taxonomyRegistry.RegisterExtension("container-agent", ext)
	require.NoError(t, err)

	// Create harness
	h := &DefaultAgentHarness{
		taxonomyRegistry: taxonomyRegistry,
	}

	registry := h.TaxonomyRegistry()
	require.NotNil(t, registry)

	// Query all relationship types (core + extensions)
	relTypes := registry.RelationshipTypes()
	assert.NotEmpty(t, relTypes)
	assert.Contains(t, relTypes, "RUNS_CONTAINER")

	// Get relationship type info
	relInfo := registry.RelationshipTypeInfo("RUNS_CONTAINER")
	require.NotNil(t, relInfo, "expected RUNS_CONTAINER relationship info")
	assert.Equal(t, "RUNS_CONTAINER", relInfo.Name)
	assert.Equal(t, "runtime", relInfo.Category)
	assert.Contains(t, relInfo.FromTypes, "Host")
	assert.Contains(t, relInfo.ToTypes, "container")
}

// TestTaxonomyRegistry_AllNodeTypes tests that NodeTypes() returns both
// core and extension node types.
func TestTaxonomyRegistry_AllNodeTypes(t *testing.T) {
	// Create a taxonomy registry with core taxonomy
	coreTaxonomy := sdkgraphrag.NewSimpleTaxonomy()
	taxonomyRegistry := sdkgraphrag.NewTaxonomyRegistry(coreTaxonomy)

	// Register extension
	ext := sdkgraphrag.TaxonomyExtension{
		NodeTypes: []sdkgraphrag.NodeTypeDefinition{
			{Name: "custom_type_1", Category: "test"},
			{Name: "custom_type_2", Category: "test"},
		},
	}
	err := taxonomyRegistry.RegisterExtension("test-agent", ext)
	require.NoError(t, err)

	// Create harness
	h := &DefaultAgentHarness{
		taxonomyRegistry: taxonomyRegistry,
	}

	registry := h.TaxonomyRegistry()
	require.NotNil(t, registry)

	// Get all node types
	nodeTypes := registry.NodeTypes()
	assert.NotEmpty(t, nodeTypes, "expected non-empty node types list")

	// Verify core types are present
	assert.Contains(t, nodeTypes, "Host", "expected core Host type")
	assert.Contains(t, nodeTypes, "Port", "expected core Port type")

	// Verify extension types are present
	assert.Contains(t, nodeTypes, "custom_type_1", "expected extension type custom_type_1")
	assert.Contains(t, nodeTypes, "custom_type_2", "expected extension type custom_type_2")
}

// TestTaxonomyRegistry_Version tests that the taxonomy version is accessible
// through the harness.
func TestTaxonomyRegistry_Version(t *testing.T) {
	// Create a taxonomy registry with core taxonomy
	coreTaxonomy := sdkgraphrag.NewSimpleTaxonomy()
	taxonomyRegistry := sdkgraphrag.NewTaxonomyRegistry(coreTaxonomy)

	// Create harness
	h := &DefaultAgentHarness{
		taxonomyRegistry: taxonomyRegistry,
	}

	registry := h.TaxonomyRegistry()
	require.NotNil(t, registry)

	// Get taxonomy version
	version := registry.Version()
	assert.NotEmpty(t, version, "expected non-empty taxonomy version")
	assert.Regexp(t, `^\d+\.\d+\.\d+$`, version, "expected semver format")
}
