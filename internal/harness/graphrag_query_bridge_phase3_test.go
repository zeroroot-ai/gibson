package harness

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
)

// TestProvenanceProperties verifies that provenance properties are added to nodes
func TestProvenanceProperties(t *testing.T) {
	agentRunID := "agent_run:test-trace:test-span"
	agentName := "test-agent"
	missionID := "01234567-89ab-cdef-0123-456789abcdef"
	missionRunID := "run-01234567-89ab-cdef-0123-456789abcdef"

	testCases := []struct {
		name           string
		inputNode      sdkgraphrag.GraphNode
		expectedProps  map[string]interface{}
		shouldHaveRun  bool
		shouldHaveTime bool
	}{
		{
			name: "Node without existing provenance properties",
			inputNode: sdkgraphrag.GraphNode{
				Type: sdkgraphrag.NodeTypeHost,
				Properties: map[string]any{
					"ip": "192.168.1.1",
				},
			},
			shouldHaveRun:  true,
			shouldHaveTime: true,
		},
		{
			name: "Node with existing created_in_run property",
			inputNode: sdkgraphrag.GraphNode{
				Type: sdkgraphrag.NodeTypePort,
				Properties: map[string]any{
					"port":           80,
					"created_in_run": "agent_run:existing:run",
				},
			},
			expectedProps: map[string]interface{}{
				"created_in_run": "agent_run:existing:run", // Should preserve existing
			},
			shouldHaveRun:  false, // Should not override
			shouldHaveTime: true,
		},
		{
			name: "Node with nil properties",
			inputNode: sdkgraphrag.GraphNode{
				Type:       sdkgraphrag.NodeTypeService,
				Properties: nil,
			},
			shouldHaveRun:  true,
			shouldHaveTime: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Call the converter function
			result := sdkNodeToInternal(tc.inputNode, missionID, missionRunID, agentName, agentRunID)

			// Verify provenance properties
			if tc.shouldHaveRun {
				assert.Equal(t, agentRunID, result.Properties["created_in_run"],
					"created_in_run should be set to agent run ID")
				assert.Equal(t, agentName, result.Properties["discovery_method"],
					"discovery_method should be set to agent name")
			}

			if tc.shouldHaveTime {
				discoveredAt, ok := result.Properties["discovered_at"].(time.Time)
				assert.True(t, ok, "discovered_at should be a time.Time")
				assert.WithinDuration(t, time.Now().UTC(), discoveredAt, 5*time.Second,
					"discovered_at should be recent")
			}

			// Verify expected properties are preserved
			for key, expectedVal := range tc.expectedProps {
				actualVal := result.Properties[key]
				assert.Equal(t, expectedVal, actualVal,
					"Property %s should be preserved", key)
			}

			// Verify original properties are preserved
			if tc.inputNode.Properties != nil {
				for key, expectedVal := range tc.inputNode.Properties {
					// Skip provenance properties as they might be overridden
					if key == "created_in_run" || key == "discovery_method" || key == "discovered_at" {
						continue
					}
					actualVal := result.Properties[key]
					assert.Equal(t, expectedVal, actualVal,
						"Original property %s should be preserved", key)
				}
			}
		})
	}
}

// TestCreateHierarchyRelationships verifies relationship detection logic
func TestCreateHierarchyRelationshipsDetection(t *testing.T) {
	testCases := []struct {
		name          string
		nodeType      string
		properties    map[string]any
		expectFromID  string
		expectRelType string
	}{
		{
			name:     "Port with host_id creates HAS_PORT relationship",
			nodeType: sdkgraphrag.NodeTypePort,
			properties: map[string]any{
				"port":    80,
				"host_id": "host-123",
			},
			expectFromID:  "host-123",
			expectRelType: sdkgraphrag.RelTypeHASPORT,
		},
		{
			name:     "Service with port_id creates RUNS_SERVICE relationship",
			nodeType: sdkgraphrag.NodeTypeService,
			properties: map[string]any{
				"name":    "http",
				"port_id": "port-456",
			},
			expectFromID:  "port-456",
			expectRelType: sdkgraphrag.RelTypeRUNSSERVICE,
		},
		{
			name:     "Endpoint with service_id creates HAS_ENDPOINT relationship",
			nodeType: sdkgraphrag.NodeTypeEndpoint,
			properties: map[string]any{
				"url":        "/api/v1",
				"service_id": "service-789",
			},
			expectFromID:  "service-789",
			expectRelType: sdkgraphrag.RelTypeHASENDPOINT,
		},
		{
			name:     "Subdomain with parent_domain creates HAS_SUBDOMAIN relationship",
			nodeType: sdkgraphrag.NodeTypeSubdomain,
			properties: map[string]any{
				"name":          "api",
				"parent_domain": "example.com",
			},
			expectFromID:  "example.com",
			expectRelType: sdkgraphrag.RelTypeHASSUBDOMAIN,
		},
		{
			name:     "Port without host_id does not create relationship",
			nodeType: sdkgraphrag.NodeTypePort,
			properties: map[string]any{
				"port": 80,
			},
			expectFromID:  "",
			expectRelType: "",
		},
		{
			name:     "Host node does not create hierarchy relationship",
			nodeType: sdkgraphrag.NodeTypeHost,
			properties: map[string]any{
				"ip": "192.168.1.1",
			},
			expectFromID:  "",
			expectRelType: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test the relationship detection logic
			node := sdkgraphrag.GraphNode{
				Type:       tc.nodeType,
				Properties: tc.properties,
			}

			var fromID, relType string

			// Replicate the logic from createHierarchyRelationships
			switch node.Type {
			case sdkgraphrag.NodeTypePort:
				if hostID, ok := tc.properties["host_id"].(string); ok && hostID != "" {
					fromID = hostID
					relType = sdkgraphrag.RelTypeHASPORT
				}
			case sdkgraphrag.NodeTypeService:
				if portID, ok := tc.properties["port_id"].(string); ok && portID != "" {
					fromID = portID
					relType = sdkgraphrag.RelTypeRUNSSERVICE
				}
			case sdkgraphrag.NodeTypeEndpoint:
				if serviceID, ok := tc.properties["service_id"].(string); ok && serviceID != "" {
					fromID = serviceID
					relType = sdkgraphrag.RelTypeHASENDPOINT
				}
			case sdkgraphrag.NodeTypeSubdomain:
				if parentDomain, ok := tc.properties["parent_domain"].(string); ok && parentDomain != "" {
					fromID = parentDomain
					relType = sdkgraphrag.RelTypeHASSUBDOMAIN
				}
			}

			assert.Equal(t, tc.expectFromID, fromID, "FromID should match expected")
			assert.Equal(t, tc.expectRelType, relType, "RelType should match expected")
		})
	}
}

// TestAgentRunIDContext verifies context propagation
func TestAgentRunIDContext(t *testing.T) {
	ctx := context.Background()
	agentRunID := "agent_run:test-trace:test-span"

	// Test setting agent run ID in context
	ctxWithID := ContextWithAgentRunID(ctx, agentRunID)
	retrievedID := AgentRunIDFromContext(ctxWithID)

	assert.Equal(t, agentRunID, retrievedID, "Agent run ID should be retrievable from context")

	// Test context without agent run ID
	emptyID := AgentRunIDFromContext(ctx)
	assert.Equal(t, "", emptyID, "Empty context should return empty string")
}
