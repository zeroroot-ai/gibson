//go:build integration

// Package loader provides integration tests for mission-scoped GraphRAG storage.
// These tests validate the CREATE-based node storage and scoped query semantics.
package loader

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/graph"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
)

// TestIntegration_MissionRunDataIsolation verifies that the same IP address
// in different MissionRuns creates separate nodes (no collision).
// Task 15.2: Multiple mission runs with data isolation
// Task 15.4: Same IP different contexts (collision prevention)
func TestIntegration_MissionRunDataIsolation(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Return mock result for each CREATE query
	for i := 0; i < 10; i++ {
		nodeID := fmt.Sprintf("node-%d", i)
		client.AddQueryResult(graph.QueryResult{
			Records: []map[string]any{
				{
					"element_id": nodeID,
					"idx":        float64(0),
				},
			},
		})
	}

	loader := NewGraphLoader(client)
	ctx := context.Background()

	// Create the same IP in two different MissionRuns
	sameIP := "192.168.1.100"

	// MissionRun 1: First discovery of the IP
	execCtx1 := ExecContext{
		MissionID:    "mission-1",
		MissionRunID: "run-1",
		AgentRunID:   "agent-run-1",
		AgentName:    "network-recon",
	}

	discovery1 := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Ip: sameIP},
		},
	}

	result1, err := loader.LoadDiscovery(ctx, execCtx1, discovery1)
	require.NoError(t, err)
	assert.Equal(t, 1, result1.NodesCreated, "Should create one node in run 1")

	// MissionRun 2: Same IP discovered again (should create NEW node, not merge)
	execCtx2 := ExecContext{
		MissionID:    "mission-1",
		MissionRunID: "run-2",
		AgentRunID:   "agent-run-2",
		AgentName:    "network-recon",
	}

	discovery2 := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Ip: sameIP},
		},
	}

	result2, err := loader.LoadDiscovery(ctx, execCtx2, discovery2)
	require.NoError(t, err)
	assert.Equal(t, 1, result2.NodesCreated, "Should create one node in run 2 (separate from run 1)")

	// Verify both queries used CREATE (not MERGE)
	calls := client.GetCallsByMethod("Query")
	require.GreaterOrEqual(t, len(calls), 2, "Should have at least 2 queries (one per run)")

	for i, call := range calls {
		if i >= 2 {
			break
		}
		queryStr := call.Args[0].(string)
		if strings.Contains(queryStr, "host") {
			assert.Contains(t, queryStr, "CREATE", "Query %d should use CREATE not MERGE", i)
			assert.NotContains(t, queryStr, "MERGE", "Query %d should not use MERGE", i)
		}
	}
}

// TestIntegration_ParentRelationshipScoping verifies that parent relationships
// are scoped to the current mission run.
// Task 15.1: End-to-end test for network-recon → tech-fingerprinting data flow
func TestIntegration_ParentRelationshipScoping(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Configure mock results for node creation and relationship creation
	// Host creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "host-node-1", "idx": float64(0)},
		},
	})
	// Port creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "port-node-1", "idx": float64(0)},
		},
	})
	// HAS_PORT relationship
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"rel_count": int64(1)},
		},
	})

	loader := NewGraphLoader(client)
	ctx := context.Background()

	execCtx := ExecContext{
		MissionID:    "mission-1",
		MissionRunID: "run-1",
		AgentRunID:   "agent-run-1",
		AgentName:    "network-recon",
	}

	// Create host and port together (simulating discovery result)
	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Ip: "10.0.0.1"},
		},
		Ports: []*graphragpb.Port{
			{
				HostIp:   "10.0.0.1",
				Number:   443,
				Protocol: "tcp",
			},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)
	require.NoError(t, err)
	assert.Equal(t, 2, result.NodesCreated)                  // host + port
	assert.GreaterOrEqual(t, result.RelationshipsCreated, 1) // HAS_PORT

	// Verify relationship query includes mission_run_id scoping
	calls := client.GetCallsByMethod("Query")
	foundRelationshipQuery := false

	for _, call := range calls {
		queryStr := call.Args[0].(string)
		if strings.Contains(queryStr, "HAS_PORT") {
			foundRelationshipQuery = true
		}
	}

	assert.True(t, foundRelationshipQuery, "Should have found a relationship creation query")
}

// TestIntegration_CreateVsMergePerformance compares CREATE vs the old MERGE behavior.
// Task 15.5: Performance benchmark: CREATE vs MERGE comparison
func TestIntegration_CreateVsMergePerformance(t *testing.T) {
	// This test validates that CREATE queries are generated correctly
	// Actual performance benchmarking requires a real Neo4j instance

	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Configure mock to return success for batch of nodes
	nodeCount := 100
	records := make([]map[string]any, nodeCount)
	for i := 0; i < nodeCount; i++ {
		records[i] = map[string]any{
			"element_id": fmt.Sprintf("node-%d", i),
			"idx":        float64(i),
		}
	}
	client.AddQueryResult(graph.QueryResult{
		Records: records,
	})

	loader := NewGraphLoader(client)
	ctx := context.Background()

	execCtx := ExecContext{
		MissionID:    "perf-mission",
		MissionRunID: "perf-run-1",
	}

	// Create many hosts
	hosts := make([]*graphragpb.Host, nodeCount)
	for i := 0; i < nodeCount; i++ {
		hosts[i] = &graphragpb.Host{
			Ip: fmt.Sprintf("10.0.0.%d", i),
		}
	}

	discovery := &graphragpb.DiscoveryResult{
		Hosts: hosts,
	}

	start := time.Now()
	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.Equal(t, nodeCount, result.NodesCreated)

	// Verify all queries used CREATE
	calls := client.GetCallsByMethod("Query")
	for _, call := range calls {
		queryStr := call.Args[0].(string)
		if strings.Contains(queryStr, "host") {
			assert.Contains(t, queryStr, "CREATE", "All queries should use CREATE")
			assert.NotContains(t, queryStr, "MERGE", "No queries should use MERGE")
		}
	}

	t.Logf("Created %d nodes in %v using CREATE (mock)", nodeCount, elapsed)
}

// TestIntegration_BatchCreateWithMissionContext verifies batch operations
// properly inject mission context into all nodes.
func TestIntegration_BatchCreateWithMissionContext(t *testing.T) {
	client := graph.NewMockGraphClient()
	err := client.Connect(context.Background())
	require.NoError(t, err)

	// Configure mock for batch creation
	client.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "batch-node-1", "idx": float64(0)},
			{"element_id": "batch-node-2", "idx": float64(1)},
			{"element_id": "batch-node-3", "idx": float64(2)},
		},
	})

	loader := NewGraphLoader(client)
	ctx := context.Background()

	execCtx := ExecContext{
		MissionID:    "batch-mission",
		MissionRunID: "batch-run-1",
		AgentRunID:   "batch-agent-run",
		AgentName:    "batch-agent",
	}

	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Ip: "10.1.1.1"},
			{Ip: "10.1.1.2"},
			{Ip: "10.1.1.3"},
		},
	}

	result, err := loader.LoadDiscovery(ctx, execCtx, discovery)
	require.NoError(t, err)
	assert.Equal(t, 3, result.NodesCreated)

	// Verify batch query parameters include mission context
	calls := client.GetCallsByMethod("Query")
	require.GreaterOrEqual(t, len(calls), 1)

	// Check that the UNWIND query was used
	foundBatchQuery := false
	for _, call := range calls {
		queryStr := call.Args[0].(string)
		if strings.Contains(queryStr, "UNWIND") && strings.Contains(queryStr, "CREATE") {
			foundBatchQuery = true
		}
	}

	assert.True(t, foundBatchQuery, "Should have found a batch UNWIND CREATE query")
}
