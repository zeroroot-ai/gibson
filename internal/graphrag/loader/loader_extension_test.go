package loader

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
	"github.com/zero-day-ai/sdk/graphrag"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// TestLoadCustomNode_WithoutRegistry_BackwardCompatibility verifies that loading
// CustomNode without a taxonomy registry still works (backward compatibility).
// Task 6.3 requirement #1
func TestLoadCustomNode_WithoutRegistry_BackwardCompatibility(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for custom node creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "custom-1", "idx": float64(0)},
		},
	})

	// Create loader WITHOUT taxonomy registry
	loader := NewGraphLoader(client)
	ctx := context.Background()
	execCtx := ExecContext{
		AgentRunID: "test-agent-run",
	}

	discovery := &graphragpb.DiscoveryResult{
		CustomNodes: []*graphragpb.CustomNode{
			{
				NodeType: "vulnerability",
				IdProperties: map[string]string{
					"cve": "CVE-2024-1234",
				},
				Properties: map[string]string{
					"severity": "critical",
					"title":    "SQL Injection",
				},
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	// Should succeed without registry
	assert.NoError(t, err)
	assert.Equal(t, 1, result.NodesCreated)
	assert.False(t, result.HasErrors())

	// Verify the node was created with correct type
	calls := client.GetCallsByMethod("Query")
	assert.GreaterOrEqual(t, len(calls), 1)
	queryStr := calls[0].Args[0].(string)
	assert.Contains(t, queryStr, "vulnerability")
}

// TestLoadCustomNode_WithRegistry_LogsExtensionSource verifies that when a
// taxonomy registry is configured, the loader logs the extension source via span events.
// Task 6.3 requirement #2
func TestLoadCustomNode_WithRegistry_LogsExtensionSource(t *testing.T) {
	// Setup trace exporter to capture span events
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	defer tp.Shutdown(context.Background())
	otel.SetTracerProvider(tp)

	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for custom node creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "custom-1", "idx": float64(0)},
		},
	})

	// Create taxonomy registry with a test extension
	coreTaxonomy := graphrag.NewSimpleTaxonomy()
	registry := graphrag.NewTaxonomyRegistry(coreTaxonomy)

	// Register an extension with a custom node type
	ext := graphrag.TaxonomyExtension{
		NodeTypes: []graphrag.NodeTypeDefinition{
			{
				Name:        "vulnerability",
				Category:    "security",
				Description: "A security vulnerability",
				Properties: []graphrag.PropertyInfo{
					{
						Name:        "cve",
						Type:        "string",
						Required:    true,
						Description: "CVE identifier",
					},
					{
						Name:        "severity",
						Type:        "string",
						Required:    true,
						Description: "Vulnerability severity",
					},
				},
			},
		},
	}

	err = registry.RegisterExtension("security-scanner", ext)
	require.NoError(t, err)

	// Create loader WITH taxonomy registry
	loader := NewGraphLoader(client).WithTaxonomyRegistry(registry)
	ctx := context.Background()
	execCtx := ExecContext{
		AgentRunID: "test-agent-run",
	}

	discovery := &graphragpb.DiscoveryResult{
		CustomNodes: []*graphragpb.CustomNode{
			{
				NodeType: "vulnerability",
				IdProperties: map[string]string{
					"cve": "CVE-2024-1234",
				},
				Properties: map[string]string{
					"cve":      "CVE-2024-1234",
					"severity": "critical",
					"title":    "SQL Injection",
				},
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 1, result.NodesCreated)
	assert.False(t, result.HasErrors())

	// Verify span events were logged with extension source
	spans := exporter.GetSpans()
	require.GreaterOrEqual(t, len(spans), 1)

	// Find the graph store span
	var graphStoreSpan *tracetest.SpanStub
	for i := range spans {
		if spans[i].Name == "gibson.graph.store" {
			graphStoreSpan = &spans[i]
			break
		}
	}
	require.NotNil(t, graphStoreSpan)

	// Check for loading_custom_node event
	foundLoadingEvent := false
	for _, event := range graphStoreSpan.Events {
		if event.Name == "loading_custom_node" {
			foundLoadingEvent = true

			// Verify event attributes
			attrMap := make(map[string]any)
			for _, attr := range event.Attributes {
				attrMap[string(attr.Key)] = attr.Value.AsInterface()
			}

			assert.Equal(t, "vulnerability", attrMap["node_type"])
			assert.Equal(t, "security-scanner", attrMap["extension_source"])
		}
	}

	assert.True(t, foundLoadingEvent, "Expected loading_custom_node span event")
}

// TestLoadCustomNode_ValidationEnabled_MissingRequiredProperty verifies that
// when validation is enabled and a required property is missing, a warning is logged
// but the node is still loaded.
// Task 6.3 requirement #3
func TestLoadCustomNode_ValidationEnabled_MissingRequiredProperty(t *testing.T) {
	// Setup trace exporter to capture span events
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	defer tp.Shutdown(context.Background())
	otel.SetTracerProvider(tp)

	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for custom node creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "custom-1", "idx": float64(0)},
		},
	})

	// Create taxonomy registry with extension that has required properties
	coreTaxonomy := graphrag.NewSimpleTaxonomy()
	registry := graphrag.NewTaxonomyRegistry(coreTaxonomy)

	ext := graphrag.TaxonomyExtension{
		NodeTypes: []graphrag.NodeTypeDefinition{
			{
				Name:        "custom_asset",
				Category:    "asset",
				Description: "A custom asset type",
				Properties: []graphrag.PropertyInfo{
					{
						Name:        "name",
						Type:        "string",
						Required:    true,
						Description: "Asset name (required)",
					},
					{
						Name:        "description",
						Type:        "string",
						Required:    false,
						Description: "Asset description (optional)",
					},
					{
						Name:        "severity",
						Type:        "string",
						Required:    true,
						Description: "Severity level (required)",
					},
				},
			},
		},
	}

	err = registry.RegisterExtension("test-agent", ext)
	require.NoError(t, err)

	// Create loader with registry AND validation enabled
	loader := NewGraphLoader(client).
		WithTaxonomyRegistry(registry).
		WithValidateExtensions(true)

	ctx := context.Background()
	execCtx := ExecContext{
		AgentRunID: "test-agent-run",
	}

	// CustomNode MISSING the required "severity" property
	discovery := &graphragpb.DiscoveryResult{
		CustomNodes: []*graphragpb.CustomNode{
			{
				NodeType: "custom_asset",
				IdProperties: map[string]string{
					"name": "test-asset",
				},
				Properties: map[string]string{
					"name":        "test-asset",
					"description": "Test description",
					// Missing "severity" - which is required!
				},
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	// Should still succeed - validation just logs warnings
	assert.NoError(t, err)
	assert.Equal(t, 1, result.NodesCreated)
	assert.False(t, result.HasErrors())

	// Verify span events show validation failure
	spans := exporter.GetSpans()
	require.GreaterOrEqual(t, len(spans), 1)

	var graphStoreSpan *tracetest.SpanStub
	for i := range spans {
		if spans[i].Name == "gibson.graph.store" {
			graphStoreSpan = &spans[i]
			break
		}
	}
	require.NotNil(t, graphStoreSpan)

	// Check for validation_failed event
	foundValidationFailed := false
	for _, event := range graphStoreSpan.Events {
		if event.Name == "validation_failed" {
			foundValidationFailed = true

			// Verify event attributes
			attrMap := make(map[string]any)
			for _, attr := range event.Attributes {
				attrMap[string(attr.Key)] = attr.Value.AsInterface()
			}

			assert.Equal(t, "custom_asset", attrMap["node_type"])

			// The missing_properties attribute is a StringSlice which comes as []string
			// We need to find the attribute directly
			var missingPropsFound bool
			for _, attr := range event.Attributes {
				if string(attr.Key) == "missing_properties" {
					missingPropsFound = true
					// The value is a Slice, use AsStringSlice()
					missingProps := attr.Value.AsStringSlice()
					assert.Contains(t, missingProps, "severity")
				}
			}
			assert.True(t, missingPropsFound, "missing_properties attribute should exist")
		}
	}

	assert.True(t, foundValidationFailed, "Expected validation_failed span event for missing required property")
}

// TestLoadCustomNode_ValidationPasses verifies that when validation is enabled
// and all required properties are present, a validation_passed event is logged.
func TestLoadCustomNode_ValidationPasses(t *testing.T) {
	// Setup trace exporter to capture span events
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	defer tp.Shutdown(context.Background())
	otel.SetTracerProvider(tp)

	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for custom node creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "custom-1", "idx": float64(0)},
		},
	})

	// Create taxonomy registry with extension
	coreTaxonomy := graphrag.NewSimpleTaxonomy()
	registry := graphrag.NewTaxonomyRegistry(coreTaxonomy)

	ext := graphrag.TaxonomyExtension{
		NodeTypes: []graphrag.NodeTypeDefinition{
			{
				Name:        "custom_asset",
				Category:    "asset",
				Description: "A custom asset type",
				Properties: []graphrag.PropertyInfo{
					{
						Name:        "name",
						Type:        "string",
						Required:    true,
						Description: "Asset name (required)",
					},
					{
						Name:        "severity",
						Type:        "string",
						Required:    true,
						Description: "Severity level (required)",
					},
				},
			},
		},
	}

	err = registry.RegisterExtension("test-agent", ext)
	require.NoError(t, err)

	// Create loader with registry AND validation enabled
	loader := NewGraphLoader(client).
		WithTaxonomyRegistry(registry).
		WithValidateExtensions(true)

	ctx := context.Background()
	execCtx := ExecContext{
		AgentRunID: "test-agent-run",
	}

	// CustomNode WITH all required properties
	discovery := &graphragpb.DiscoveryResult{
		CustomNodes: []*graphragpb.CustomNode{
			{
				NodeType: "custom_asset",
				IdProperties: map[string]string{
					"name": "test-asset",
				},
				Properties: map[string]string{
					"name":     "test-asset",
					"severity": "high",
				},
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 1, result.NodesCreated)
	assert.False(t, result.HasErrors())

	// Verify span events show validation passed
	spans := exporter.GetSpans()
	require.GreaterOrEqual(t, len(spans), 1)

	var graphStoreSpan *tracetest.SpanStub
	for i := range spans {
		if spans[i].Name == "gibson.graph.store" {
			graphStoreSpan = &spans[i]
			break
		}
	}
	require.NotNil(t, graphStoreSpan)

	// Check for validation_passed event
	foundValidationPassed := false
	for _, event := range graphStoreSpan.Events {
		if event.Name == "validation_passed" {
			foundValidationPassed = true

			// Verify event attributes
			attrMap := make(map[string]any)
			for _, attr := range event.Attributes {
				attrMap[string(attr.Key)] = attr.Value.AsInterface()
			}

			assert.Equal(t, "custom_asset", attrMap["node_type"])
		}
	}

	assert.True(t, foundValidationPassed, "Expected validation_passed span event")
}

// TestLoadCustomNode_UnknownNodeType_LogsUnknownSource verifies that when
// a custom node type is not registered in the taxonomy, it is logged with
// "unknown" as the source.
// Task 6.3 requirement #4
func TestLoadCustomNode_UnknownNodeType_LogsUnknownSource(t *testing.T) {
	// Setup trace exporter to capture span events
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	defer tp.Shutdown(context.Background())
	otel.SetTracerProvider(tp)

	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for custom node creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "custom-1", "idx": float64(0)},
		},
	})

	// Create taxonomy registry WITHOUT registering the custom node type
	coreTaxonomy := graphrag.NewSimpleTaxonomy()
	registry := graphrag.NewTaxonomyRegistry(coreTaxonomy)

	// Create loader with registry but node type is NOT registered
	loader := NewGraphLoader(client).WithTaxonomyRegistry(registry)

	ctx := context.Background()
	execCtx := ExecContext{
		AgentRunID: "test-agent-run",
	}

	// Use a node type that is NOT registered
	discovery := &graphragpb.DiscoveryResult{
		CustomNodes: []*graphragpb.CustomNode{
			{
				NodeType: "unregistered_type",
				IdProperties: map[string]string{
					"id": "test-123",
				},
				Properties: map[string]string{
					"id":    "test-123",
					"value": "some value",
				},
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 1, result.NodesCreated)
	assert.False(t, result.HasErrors())

	// Verify span events log "unknown" as the source
	spans := exporter.GetSpans()
	require.GreaterOrEqual(t, len(spans), 1)

	var graphStoreSpan *tracetest.SpanStub
	for i := range spans {
		if spans[i].Name == "gibson.graph.store" {
			graphStoreSpan = &spans[i]
			break
		}
	}
	require.NotNil(t, graphStoreSpan)

	// Check for loading_custom_node event with "unknown" source
	foundLoadingEvent := false
	for _, event := range graphStoreSpan.Events {
		if event.Name == "loading_custom_node" {
			foundLoadingEvent = true

			// Verify event attributes
			attrMap := make(map[string]any)
			for _, attr := range event.Attributes {
				attrMap[string(attr.Key)] = attr.Value.AsInterface()
			}

			assert.Equal(t, "unregistered_type", attrMap["node_type"])
			assert.Equal(t, "unknown", attrMap["extension_source"])
		}
	}

	assert.True(t, foundLoadingEvent, "Expected loading_custom_node span event with unknown source")
}

// TestLoadCustomNode_CoreNodeType_LogsCoreSource verifies that core node types
// (like "host", "port") are logged with "core" as the source when accessed via registry.
func TestLoadCustomNode_CoreNodeType_LogsCoreSource(t *testing.T) {
	// Setup trace exporter to capture span events
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	defer tp.Shutdown(context.Background())
	otel.SetTracerProvider(tp)

	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for host creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "host-1", "idx": float64(0)},
		},
	})

	// Create taxonomy registry (core taxonomy includes "host")
	coreTaxonomy := graphrag.NewSimpleTaxonomy()
	registry := graphrag.NewTaxonomyRegistry(coreTaxonomy)

	// Create loader with registry
	loader := NewGraphLoader(client).WithTaxonomyRegistry(registry)

	ctx := context.Background()
	execCtx := ExecContext{
		AgentRunID: "test-agent-run",
	}

	// Load a core node type as a CustomNode (unusual but valid)
	discovery := &graphragpb.DiscoveryResult{
		CustomNodes: []*graphragpb.CustomNode{
			{
				NodeType: "host",
				IdProperties: map[string]string{
					"ip": "192.168.1.1",
				},
				Properties: map[string]string{
					"ip": "192.168.1.1",
				},
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 1, result.NodesCreated)
	assert.False(t, result.HasErrors())

	// Verify span events log "core" as the source
	spans := exporter.GetSpans()
	require.GreaterOrEqual(t, len(spans), 1)

	var graphStoreSpan *tracetest.SpanStub
	for i := range spans {
		if spans[i].Name == "gibson.graph.store" {
			graphStoreSpan = &spans[i]
			break
		}
	}
	require.NotNil(t, graphStoreSpan)

	// Check for loading_custom_node event with "core" source
	foundLoadingEvent := false
	for _, event := range graphStoreSpan.Events {
		if event.Name == "loading_custom_node" {
			foundLoadingEvent = true

			// Verify event attributes
			attrMap := make(map[string]any)
			for _, attr := range event.Attributes {
				attrMap[string(attr.Key)] = attr.Value.AsInterface()
			}

			assert.Equal(t, "host", attrMap["node_type"])
			assert.Equal(t, "core", attrMap["extension_source"])
		}
	}

	assert.True(t, foundLoadingEvent, "Expected loading_custom_node span event with core source")
}

// TestLoadCustomNode_ValidationDisabled_NoValidationEvents verifies that when
// validation is disabled (default), no validation events are logged.
func TestLoadCustomNode_ValidationDisabled_NoValidationEvents(t *testing.T) {
	// Setup trace exporter to capture span events
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	defer tp.Shutdown(context.Background())
	otel.SetTracerProvider(tp)

	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for custom node creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "custom-1", "idx": float64(0)},
		},
	})

	// Create taxonomy registry with extension
	coreTaxonomy := graphrag.NewSimpleTaxonomy()
	registry := graphrag.NewTaxonomyRegistry(coreTaxonomy)

	ext := graphrag.TaxonomyExtension{
		NodeTypes: []graphrag.NodeTypeDefinition{
			{
				Name:        "custom_asset",
				Category:    "asset",
				Description: "A custom asset type",
				Properties: []graphrag.PropertyInfo{
					{
						Name:        "name",
						Type:        "string",
						Required:    true,
						Description: "Asset name (required)",
					},
					{
						Name:        "severity",
						Type:        "string",
						Required:    true,
						Description: "Severity level (required)",
					},
				},
			},
		},
	}

	err = registry.RegisterExtension("test-agent", ext)
	require.NoError(t, err)

	// Create loader with registry but WITHOUT validation enabled (default is false)
	loader := NewGraphLoader(client).WithTaxonomyRegistry(registry)

	ctx := context.Background()
	execCtx := ExecContext{
		AgentRunID: "test-agent-run",
	}

	// CustomNode MISSING required property - but validation is disabled
	discovery := &graphragpb.DiscoveryResult{
		CustomNodes: []*graphragpb.CustomNode{
			{
				NodeType: "custom_asset",
				IdProperties: map[string]string{
					"name": "test-asset",
				},
				Properties: map[string]string{
					"name": "test-asset",
					// Missing "severity" - but validation is OFF
				},
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 1, result.NodesCreated)
	assert.False(t, result.HasErrors())

	// Verify NO validation events are logged
	spans := exporter.GetSpans()
	require.GreaterOrEqual(t, len(spans), 1)

	var graphStoreSpan *tracetest.SpanStub
	for i := range spans {
		if spans[i].Name == "gibson.graph.store" {
			graphStoreSpan = &spans[i]
			break
		}
	}
	require.NotNil(t, graphStoreSpan)

	// Check that NO validation events exist
	foundValidationEvent := false
	for _, event := range graphStoreSpan.Events {
		if event.Name == "validation_failed" || event.Name == "validation_passed" {
			foundValidationEvent = true
		}
	}

	assert.False(t, foundValidationEvent, "Should not log validation events when validation is disabled")

	// But loading_custom_node event should still exist
	foundLoadingEvent := false
	for _, event := range graphStoreSpan.Events {
		if event.Name == "loading_custom_node" {
			foundLoadingEvent = true

			// Verify it has extension source attribute
			attrMap := make(map[string]any)
			for _, attr := range event.Attributes {
				attrMap[string(attr.Key)] = attr.Value.AsInterface()
			}

			assert.Equal(t, "custom_asset", attrMap["node_type"])
			assert.Equal(t, "test-agent", attrMap["extension_source"])
		}
	}

	assert.True(t, foundLoadingEvent, "Expected loading_custom_node event even when validation is disabled")
}

// TestLoadCustomNode_MultipleExtensions_CorrectSourceLogging verifies that when
// multiple extensions are registered, each custom node is logged with the correct source.
func TestLoadCustomNode_MultipleExtensions_CorrectSourceLogging(t *testing.T) {
	// Setup trace exporter to capture span events
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	defer tp.Shutdown(context.Background())
	otel.SetTracerProvider(tp)

	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Mock for multiple custom node creations
	// Query 1: Create vulnerability node
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "custom-1", "idx": float64(0)},
		},
	})
	// Query 2: DISCOVERED relationship for vulnerability
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"rel_count": int64(1)},
		},
	})
	// Query 3: Create compliance_issue node
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "custom-2", "idx": float64(0)},
		},
	})
	// Query 4: DISCOVERED relationship for compliance_issue
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"rel_count": int64(1)},
		},
	})

	// Create taxonomy registry with multiple extensions
	coreTaxonomy := graphrag.NewSimpleTaxonomy()
	registry := graphrag.NewTaxonomyRegistry(coreTaxonomy)

	// Extension 1: security-scanner
	ext1 := graphrag.TaxonomyExtension{
		NodeTypes: []graphrag.NodeTypeDefinition{
			{
				Name:        "vulnerability",
				Category:    "security",
				Description: "A security vulnerability",
			},
		},
	}
	err = registry.RegisterExtension("security-scanner", ext1)
	require.NoError(t, err)

	// Extension 2: compliance-auditor
	ext2 := graphrag.TaxonomyExtension{
		NodeTypes: []graphrag.NodeTypeDefinition{
			{
				Name:        "compliance_issue",
				Category:    "compliance",
				Description: "A compliance issue",
			},
		},
	}
	err = registry.RegisterExtension("compliance-auditor", ext2)
	require.NoError(t, err)

	// Create loader with registry
	loader := NewGraphLoader(client).WithTaxonomyRegistry(registry)

	ctx := context.Background()
	execCtx := ExecContext{
		AgentRunID: "test-agent-run",
	}

	// Load custom nodes from different extensions
	discovery := &graphragpb.DiscoveryResult{
		CustomNodes: []*graphragpb.CustomNode{
			{
				NodeType: "vulnerability",
				IdProperties: map[string]string{
					"cve": "CVE-2024-1234",
				},
				Properties: map[string]string{
					"cve": "CVE-2024-1234",
				},
			},
			{
				NodeType: "compliance_issue",
				IdProperties: map[string]string{
					"id": "COMP-001",
				},
				Properties: map[string]string{
					"id": "COMP-001",
				},
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.Equal(t, 2, result.NodesCreated)
	assert.False(t, result.HasErrors())

	// Verify span events log correct sources for each node type
	spans := exporter.GetSpans()
	require.GreaterOrEqual(t, len(spans), 1)

	var graphStoreSpan *tracetest.SpanStub
	for i := range spans {
		if spans[i].Name == "gibson.graph.store" {
			graphStoreSpan = &spans[i]
			break
		}
	}
	require.NotNil(t, graphStoreSpan)

	// Track which node types and sources were logged
	nodeTypeToSource := make(map[string]string)
	for _, event := range graphStoreSpan.Events {
		if event.Name == "loading_custom_node" {
			attrMap := make(map[string]any)
			for _, attr := range event.Attributes {
				attrMap[string(attr.Key)] = attr.Value.AsInterface()
			}

			nodeType := attrMap["node_type"].(string)
			source := attrMap["extension_source"].(string)
			nodeTypeToSource[nodeType] = source
		}
	}

	// Verify each node type was logged with the correct source
	assert.Equal(t, "security-scanner", nodeTypeToSource["vulnerability"])
	assert.Equal(t, "compliance-auditor", nodeTypeToSource["compliance_issue"])
}

// Helper function to check if a span event has a specific attribute value
func spanEventHasAttribute(event sdktrace.Event, key string, expectedValue any) bool {
	for _, attr := range event.Attributes {
		if string(attr.Key) == key {
			return attr.Value.AsInterface() == expectedValue
		}
	}
	return false
}

// Helper function to get attribute value from span event
func getSpanEventAttribute(event sdktrace.Event, key string) (any, bool) {
	for _, attr := range event.Attributes {
		if string(attr.Key) == key {
			return attr.Value.AsInterface(), true
		}
	}
	return nil, false
}

// Helper function to count span events by name
func countSpanEventsByName(span *tracetest.SpanStub, eventName string) int {
	count := 0
	for _, event := range span.Events {
		if event.Name == eventName {
			count++
		}
	}
	return count
}

// Helper function to find all attributes matching a key from span events
func findSpanEventAttributes(span *tracetest.SpanStub, eventName string, attrKey string) []any {
	values := make([]any, 0)
	for _, event := range span.Events {
		if event.Name == eventName {
			for _, attr := range event.Attributes {
				if string(attr.Key) == attrKey {
					values = append(values, attr.Value.AsInterface())
				}
			}
		}
	}
	return values
}

// assertSpanHasEvent is a helper to verify a span contains a specific event with expected attributes
func assertSpanHasEvent(t *testing.T, span *tracetest.SpanStub, eventName string, expectedAttrs map[string]any) {
	t.Helper()

	found := false
	for _, event := range span.Events {
		if event.Name != eventName {
			continue
		}

		attrMap := make(map[string]any)
		for _, attr := range event.Attributes {
			attrMap[string(attr.Key)] = attr.Value.AsInterface()
		}

		// Check if all expected attributes match
		allMatch := true
		for key, expectedVal := range expectedAttrs {
			actualVal, exists := attrMap[key]
			if !exists || actualVal != expectedVal {
				allMatch = false
				break
			}
		}

		if allMatch {
			found = true
			break
		}
	}

	assert.True(t, found, "Expected span event '%s' with attributes %v", eventName, expectedAttrs)
}

// assertSpanEventAttributes is a helper to extract and verify event attributes
func assertSpanEventAttributes(t *testing.T, event sdktrace.Event, expectedAttrs map[string]any) {
	t.Helper()

	attrMap := make(map[string]any)
	for _, attr := range event.Attributes {
		attrMap[string(attr.Key)] = attr.Value.AsInterface()
	}

	for key, expectedVal := range expectedAttrs {
		actualVal, exists := attrMap[key]
		assert.True(t, exists, "Expected attribute '%s' to exist", key)
		assert.Equal(t, expectedVal, actualVal, "Attribute '%s' value mismatch", key)
	}
}

// findSpanByName is a helper to find a span by name from a slice of spans
func findSpanByName(spans []tracetest.SpanStub, name string) *tracetest.SpanStub {
	for i := range spans {
		if spans[i].Name == name {
			return &spans[i]
		}
	}
	return nil
}

// getSpanEventsByName returns all events matching the given name
func getSpanEventsByName(span *tracetest.SpanStub, eventName string) []sdktrace.Event {
	events := make([]sdktrace.Event, 0)
	for _, event := range span.Events {
		if event.Name == eventName {
			events = append(events, event)
		}
	}
	return events
}

// attributeValue extracts an attribute value from an attribute slice
func attributeValue(attrs []attribute.KeyValue, key string) (any, bool) {
	for _, attr := range attrs {
		if string(attr.Key) == key {
			return attr.Value.AsInterface(), true
		}
	}
	return nil, false
}
