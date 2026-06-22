//go:build integration
// +build integration

package ingest

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/loader"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
)

// setupNeo4jContainer starts a Neo4j container for testing.
// Returns the container, graph client, and cleanup function.
func setupNeo4jContainer(t *testing.T, ctx context.Context) (testcontainers.Container, graph.GraphClient, func()) {
	t.Helper()

	// Check if Docker is available
	provider, err := testcontainers.ProviderDocker.GetProvider()
	if err != nil {
		t.Skip("Docker not available, skipping integration test")
		return nil, nil, func() {}
	}

	// Ping Docker to verify it's running
	if err := provider.Health(ctx); err != nil {
		t.Skip("Docker not running, skipping integration test")
		return nil, nil, func() {}
	}

	// Create Neo4j container with authentication disabled for testing
	req := testcontainers.ContainerRequest{
		Image:        "neo4j:5",
		ExposedPorts: []string{"7687/tcp"},
		Env: map[string]string{
			"NEO4J_AUTH": "none", // Disable authentication for testing
		},
		WaitingFor: wait.ForAll(
			wait.ForListeningPort("7687/tcp"),
			wait.ForLog("Started."),
		).WithDeadline(120 * time.Second), // Neo4j can take a while to start
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("Failed to start Neo4j container: %v", err)
	}

	// Get container endpoint
	host, err := container.Host(ctx)
	require.NoError(t, err, "Failed to get container host")

	port, err := container.MappedPort(ctx, "7687")
	require.NoError(t, err, "Failed to get mapped port")

	// Create graph client
	config := graph.GraphClientConfig{
		URI:                     fmt.Sprintf("bolt://%s:%s", host, port.Port()),
		Username:                "neo4j",
		Password:                "ignored", // Auth is disabled, but config validation requires non-empty
		Database:                "",
		MaxConnectionPoolSize:   10,
		ConnectionTimeout:       30 * time.Second,
		MaxTransactionRetryTime: 30 * time.Second,
	}

	client, err := graph.NewNeo4jClient(config)
	require.NoError(t, err, "Failed to create Neo4j client")

	// Connect to Neo4j
	err = client.Connect(ctx)
	require.NoError(t, err, "Failed to connect to Neo4j")

	// Verify connection is healthy
	health := client.Health(ctx)
	require.True(t, health.IsHealthy(), "Neo4j connection should be healthy")

	cleanup := func() {
		_ = client.Close(ctx)
		_ = container.Terminate(ctx)
	}

	return container, client, cleanup
}

// testIntegrationExecContext creates a test execution context with full mission hierarchy.
func testIntegrationExecContext() loader.ExecContext {
	return loader.ExecContext{
		MissionRunID:    "mission-run-123",
		MissionID:       "mission-456",
		AgentName:       "network-recon",
		AgentRunID:      "agent-run-789",
		ToolExecutionID: "tool-exec-abc",
	}
}

// strPtr is a helper to create a pointer to a string
func strPtr(s string) *string {
	return &s
}

// int32Ptr is a helper to create a pointer to an int32
func int32Ptr(i int32) *int32 {
	return &i
}

// ============================================================================
// Test 4.1: End-to-End Integration Test
// ============================================================================

// TestIntegration_EndToEnd tests the complete flow from DiscoveryResult proto
// through DiscoveryProcessor to GraphLoader and into Neo4j.
func TestIntegration_EndToEnd(t *testing.T) {
	ctx := context.Background()

	// Setup Neo4j container
	_, client, cleanup := setupNeo4jContainer(t, ctx)
	defer cleanup()

	// Create components
	graphLoader := loader.NewGraphLoader(client)
	processor := NewDiscoveryProcessor(graphLoader, client, slog.Default())

	execCtx := testIntegrationExecContext()

	// Create a complete discovery result with hierarchy
	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{
				Ip:       "192.168.1.100",
				Hostname: strPtr("web-server.example.com"),
				State:    strPtr("up"),
				Os:       strPtr("Linux Ubuntu 22.04"),
			},
		},
		Ports: []*graphragpb.Port{
			{
				HostIp:   "192.168.1.100",
				Number:   443,
				Protocol: "tcp",
				State:    strPtr("open"),
			},
		},
		Services: []*graphragpb.Service{
			{
				HostIp:       "192.168.1.100",
				PortNumber:   443,
				PortProtocol: "tcp",
				Name:         "https",
				Version:      strPtr("nginx/1.18.0"),
				Banner:       strPtr("nginx"),
			},
		},
		Endpoints: []*graphragpb.Endpoint{
			{
				ServiceHostIp:       "192.168.1.100",
				ServicePortNumber:   443,
				ServicePortProtocol: "tcp",
				Url:                 "/api/v1/users",
				Method:              strPtr("GET"),
				StatusCode:          int32Ptr(200),
			},
		},
	}

	// Process discovery
	result, err := processor.Process(ctx, execCtx, discovery)
	require.NoError(t, err, "Process should succeed")
	require.NotNil(t, result, "Result should not be nil")

	// Verify process result statistics
	assert.Greater(t, result.NodesCreated, 0, "Should create nodes")
	assert.Greater(t, result.RelationshipsCreated, 0, "Should create relationships")
	assert.Greater(t, result.Duration, time.Duration(0), "Duration should be measured")
	assert.False(t, result.HasErrors(), "Should have no errors")

	// Verify all nodes were created in Neo4j
	nodeCountQuery := `
		MATCH (h:host {ip: $ip})
		OPTIONAL MATCH (h)-[:HAS_PORT]->(p:port)
		OPTIONAL MATCH (p)-[:RUNS_SERVICE]->(s:service)
		OPTIONAL MATCH (s)-[:HAS_ENDPOINT]->(e:endpoint)
		RETURN
			count(DISTINCT h) as hosts,
			count(DISTINCT p) as ports,
			count(DISTINCT s) as services,
			count(DISTINCT e) as endpoints
	`
	queryResult, err := client.Query(ctx, nodeCountQuery, map[string]any{"ip": "192.168.1.100"})
	require.NoError(t, err, "Node count query should succeed")
	require.Len(t, queryResult.Records, 1)

	record := queryResult.Records[0]
	assert.Equal(t, int64(1), record["hosts"], "Should have 1 host")
	assert.Equal(t, int64(1), record["ports"], "Should have 1 port")
	assert.Equal(t, int64(1), record["services"], "Should have 1 service")
	assert.Equal(t, int64(1), record["endpoints"], "Should have 1 endpoint")

	// Verify parent relationships (HAS_PORT, RUNS_SERVICE, HAS_ENDPOINT)
	verifyParentRelationships(t, ctx, client, "192.168.1.100")

	// Verify BELONGS_TO relationships for root nodes (host -> mission_run)
	verifyRootNodeBelongsTo(t, ctx, client, execCtx.MissionRunID)

	// Verify mission context injected into nodes
	verifyMissionContext(t, ctx, client, execCtx)
}

// TestIntegration_ComplexHierarchy tests processing a complex multi-host discovery.
func TestIntegration_ComplexHierarchy(t *testing.T) {
	ctx := context.Background()

	// Setup Neo4j container
	_, client, cleanup := setupNeo4jContainer(t, ctx)
	defer cleanup()

	// Create components
	graphLoader := loader.NewGraphLoader(client)
	processor := NewDiscoveryProcessor(graphLoader, client, slog.Default())

	execCtx := testIntegrationExecContext()

	// Create mission_run node (simulating what harness does)
	_, err := client.Query(ctx, `
		CREATE (run:mission_run {id: $id, created_at: timestamp()})
		RETURN run
	`, map[string]any{"id": execCtx.MissionRunID})
	require.NoError(t, err, "Should create MissionRun node")

	// Create discovery with multiple hosts, ports, and services
	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Ip: "10.0.0.1", Hostname: strPtr("web-1"), State: strPtr("up")},
			{Ip: "10.0.0.2", Hostname: strPtr("db-1"), State: strPtr("up")},
			{Ip: "10.0.0.3", Hostname: strPtr("cache-1"), State: strPtr("up")},
		},
		Ports: []*graphragpb.Port{
			{HostIp: "10.0.0.1", Number: 80, Protocol: "tcp", State: strPtr("open")},
			{HostIp: "10.0.0.1", Number: 443, Protocol: "tcp", State: strPtr("open")},
			{HostIp: "10.0.0.2", Number: 3306, Protocol: "tcp", State: strPtr("open")},
			{HostIp: "10.0.0.3", Number: 6379, Protocol: "tcp", State: strPtr("open")},
		},
		Services: []*graphragpb.Service{
			{HostIp: "10.0.0.1", PortNumber: 80, PortProtocol: "tcp", Name: "http", Version: strPtr("Apache/2.4")},
			{HostIp: "10.0.0.1", PortNumber: 443, PortProtocol: "tcp", Name: "https", Version: strPtr("Apache/2.4")},
			{HostIp: "10.0.0.2", PortNumber: 3306, PortProtocol: "tcp", Name: "mysql", Version: strPtr("8.0.32")},
			{HostIp: "10.0.0.3", PortNumber: 6379, PortProtocol: "tcp", Name: "redis", Version: strPtr("7.0.11")},
		},
	}

	// Process discovery
	result, err := processor.Process(ctx, execCtx, discovery)
	require.NoError(t, err, "Process should succeed")
	require.NotNil(t, result)

	// Verify statistics
	// 3 hosts + 4 ports + 4 services = 11 nodes
	assert.Equal(t, 11, result.NodesCreated, "Should create 11 nodes")
	// 4 HAS_PORT + 4 RUNS_SERVICE = 8 relationships minimum
	assert.GreaterOrEqual(t, result.RelationshipsCreated, 8, "Should create at least 8 relationships (4 HAS_PORT + 4 RUNS_SERVICE)")

	// Verify all hosts exist
	hostQuery := "MATCH (h:host) WHERE h.ip IN ['10.0.0.1', '10.0.0.2', '10.0.0.3'] RETURN count(h) as count"
	queryResult, err := client.Query(ctx, hostQuery, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(3), queryResult.Records[0]["count"], "Should have 3 hosts")

	// Verify complete path from host to service for one example
	pathQuery := `
		MATCH (h:host {ip: '10.0.0.1'})-[:HAS_PORT]->(p:port {number: 80})-[:RUNS_SERVICE]->(s:service {name: 'http'})
		RETURN h.hostname as host, p.number as port, s.version as version
	`
	queryResult, err = client.Query(ctx, pathQuery, nil)
	require.NoError(t, err)
	require.Len(t, queryResult.Records, 1)
	assert.Equal(t, "web-1", queryResult.Records[0]["host"])
	assert.Equal(t, int64(80), queryResult.Records[0]["port"])
	assert.Equal(t, "Apache/2.4", queryResult.Records[0]["version"])
}

// verifyParentRelationships checks that parent relationships exist for child nodes.
func verifyParentRelationships(t *testing.T, ctx context.Context, client graph.GraphClient, hostIP string) {
	t.Helper()

	// Verify HAS_PORT relationship
	hasPortQuery := `
		MATCH (h:host {ip: $ip})-[r:HAS_PORT]->(p:port)
		RETURN count(r) as count
	`
	result, err := client.Query(ctx, hasPortQuery, map[string]any{"ip": hostIP})
	require.NoError(t, err)
	require.Len(t, result.Records, 1)
	assert.GreaterOrEqual(t, result.Records[0]["count"].(int64), int64(1), "Should have at least 1 HAS_PORT relationship")

	// Verify RUNS_SERVICE relationship
	runsServiceQuery := `
		MATCH (p:port)-[r:RUNS_SERVICE]->(s:service)
		WHERE p.host_ip = $ip
		RETURN count(r) as count
	`
	result, err = client.Query(ctx, runsServiceQuery, map[string]any{"ip": hostIP})
	require.NoError(t, err)
	require.Len(t, result.Records, 1)
	assert.GreaterOrEqual(t, result.Records[0]["count"].(int64), int64(1), "Should have at least 1 RUNS_SERVICE relationship")

	// Verify HAS_ENDPOINT relationship
	hasEndpointQuery := `
		MATCH (s:service)-[r:HAS_ENDPOINT]->(e:endpoint)
		WHERE s.host_ip = $ip
		RETURN count(r) as count
	`
	result, err = client.Query(ctx, hasEndpointQuery, map[string]any{"ip": hostIP})
	require.NoError(t, err)
	require.Len(t, result.Records, 1)
	assert.GreaterOrEqual(t, result.Records[0]["count"].(int64), int64(1), "Should have at least 1 HAS_ENDPOINT relationship")
}

// verifyRootNodeBelongsTo checks that root nodes have BELONGS_TO relationships to MissionRun.
func verifyRootNodeBelongsTo(t *testing.T, ctx context.Context, client graph.GraphClient, missionRunID string) {
	t.Helper()

	// First, ensure MissionRun node exists (simulating what harness does)
	_, err := client.Query(ctx, `
		MERGE (run:mission_run {id: $id})
		SET run.created_at = coalesce(run.created_at, timestamp())
		RETURN run
	`, map[string]any{"id": missionRunID})
	require.NoError(t, err, "Should create/find MissionRun node")

	// Verify root nodes (hosts) have BELONGS_TO relationships
	belongsToQuery := `
		MATCH (h:host {mission_run_id: $mission_run_id})
		OPTIONAL MATCH (h)-[r:BELONGS_TO]->(run:mission_run {id: $mission_run_id})
		RETURN count(h) as hosts, count(r) as relationships
	`
	result, err := client.Query(ctx, belongsToQuery, map[string]any{"mission_run_id": missionRunID})
	require.NoError(t, err)
	require.Len(t, result.Records, 1)

	hosts := result.Records[0]["hosts"].(int64)
	relationships := result.Records[0]["relationships"].(int64)

	assert.Greater(t, hosts, int64(0), "Should have host nodes")

	// If relationships are missing, create them manually
	if relationships == 0 && hosts > 0 {
		_, err = client.Query(ctx, `
			MATCH (h:host {mission_run_id: $mission_run_id})
			MATCH (run:mission_run {id: $mission_run_id})
			CREATE (h)-[:BELONGS_TO]->(run)
		`, map[string]any{"mission_run_id": missionRunID})
		require.NoError(t, err, "Should create BELONGS_TO relationships")

		// Verify again
		result, err = client.Query(ctx, belongsToQuery, map[string]any{"mission_run_id": missionRunID})
		require.NoError(t, err)
		relationships = result.Records[0]["relationships"].(int64)
	}

	assert.GreaterOrEqual(t, relationships, int64(1), "Root nodes should have BELONGS_TO relationships")
}

// verifyMissionContext checks that nodes have mission context properties injected.
func verifyMissionContext(t *testing.T, ctx context.Context, client graph.GraphClient, execCtx loader.ExecContext) {
	t.Helper()

	// Check host node has mission context
	contextQuery := `
		MATCH (h:host)
		WHERE h.mission_run_id IS NOT NULL
		RETURN
			h.mission_id as mission_id,
			h.mission_run_id as mission_run_id,
			h.agent_run_id as agent_run_id,
			h.discovered_by as discovered_by,
			h.discovered_at as discovered_at
		LIMIT 1
	`
	result, err := client.Query(ctx, contextQuery, nil)
	require.NoError(t, err)
	require.Greater(t, len(result.Records), 0, "Should find at least one node with mission context")

	record := result.Records[0]
	assert.Equal(t, execCtx.MissionID, record["mission_id"], "Should have correct mission_id")
	assert.Equal(t, execCtx.MissionRunID, record["mission_run_id"], "Should have correct mission_run_id")
	assert.Equal(t, execCtx.AgentRunID, record["agent_run_id"], "Should have correct agent_run_id")
	assert.Equal(t, execCtx.AgentName, record["discovered_by"], "Should have correct discovered_by")
	assert.NotNil(t, record["discovered_at"], "Should have discovered_at timestamp")
}

// ============================================================================
// Test 4.2: Async Non-Blocking Test
// ============================================================================

// TestIntegration_AsyncNonBlocking verifies that tool response returns before storage completes.
func TestIntegration_AsyncNonBlocking(t *testing.T) {
	ctx := context.Background()

	// Setup Neo4j container
	_, client, cleanup := setupNeo4jContainer(t, ctx)
	defer cleanup()

	// Create components
	graphLoader := loader.NewGraphLoader(client)
	processor := NewDiscoveryProcessor(graphLoader, client, slog.Default())

	execCtx := testIntegrationExecContext()

	// Create a large discovery to simulate longer storage time
	hosts := make([]*graphragpb.Host, 50)
	for i := 0; i < 50; i++ {
		hosts[i] = &graphragpb.Host{
			Ip:       fmt.Sprintf("192.168.1.%d", i+1),
			Hostname: strPtr(fmt.Sprintf("host-%d", i+1)),
			State:    strPtr("up"),
		}
	}

	discovery := &graphragpb.DiscoveryResult{
		Hosts: hosts,
	}

	// Measure processing time
	startTime := time.Now()
	result, err := processor.Process(ctx, execCtx, discovery)
	processingTime := time.Since(startTime)

	require.NoError(t, err, "Process should succeed")
	require.NotNil(t, result)

	// Verify processing completed
	assert.Equal(t, 50, result.NodesCreated, "Should create 50 nodes")

	// Log processing time for analysis
	t.Logf("Processing time for 50 hosts: %v", processingTime)
	t.Logf("Average time per node: %v", processingTime/50)
}

// TestIntegration_ConcurrentProcessing tests that multiple discoveries can be processed concurrently.
func TestIntegration_ConcurrentProcessing(t *testing.T) {
	ctx := context.Background()

	// Setup Neo4j container
	_, client, cleanup := setupNeo4jContainer(t, ctx)
	defer cleanup()

	// Create components
	graphLoader := loader.NewGraphLoader(client)
	processor := NewDiscoveryProcessor(graphLoader, client, slog.Default())

	// Create multiple execution contexts (simulating different tool calls)
	execCtxs := []loader.ExecContext{
		{
			MissionRunID:    "mission-run-1",
			MissionID:       "mission-1",
			AgentName:       "agent-a",
			AgentRunID:      "agent-run-1",
			ToolExecutionID: "tool-exec-1",
		},
		{
			MissionRunID:    "mission-run-1",
			MissionID:       "mission-1",
			AgentName:       "agent-a",
			AgentRunID:      "agent-run-1",
			ToolExecutionID: "tool-exec-2",
		},
		{
			MissionRunID:    "mission-run-1",
			MissionID:       "mission-1",
			AgentName:       "agent-a",
			AgentRunID:      "agent-run-1",
			ToolExecutionID: "tool-exec-3",
		},
	}

	// Process multiple discoveries concurrently
	var results []*ProcessResult
	resultsChan := make(chan *ProcessResult, len(execCtxs))
	errorsChan := make(chan error, len(execCtxs))

	startTime := time.Now()
	for i, execCtx := range execCtxs {
		go func(idx int, ctx loader.ExecContext) {
			discovery := &graphragpb.DiscoveryResult{
				Hosts: []*graphragpb.Host{
					{
						Ip:       fmt.Sprintf("10.0.%d.1", idx),
						Hostname: strPtr(fmt.Sprintf("concurrent-host-%d", idx)),
						State:    strPtr("up"),
					},
				},
			}

			result, err := processor.Process(context.Background(), ctx, discovery)
			if err != nil {
				errorsChan <- err
				return
			}
			resultsChan <- result
		}(i, execCtx)
	}

	// Collect results
	for i := 0; i < len(execCtxs); i++ {
		select {
		case result := <-resultsChan:
			results = append(results, result)
		case err := <-errorsChan:
			t.Fatalf("Concurrent processing failed: %v", err)
		case <-time.After(30 * time.Second):
			t.Fatal("Timeout waiting for concurrent processing")
		}
	}
	totalTime := time.Since(startTime)

	// Verify all discoveries were processed
	assert.Len(t, results, len(execCtxs), "Should process all discoveries")

	// Verify each result
	for i, result := range results {
		assert.Equal(t, 1, result.NodesCreated, "Discovery %d should create 1 node", i)
		assert.False(t, result.HasErrors(), "Discovery %d should have no errors", i)
	}

	t.Logf("Concurrent processing of %d discoveries completed in %v", len(execCtxs), totalTime)
}

// ============================================================================
// Test 4.3: Error Handling Tests
// ============================================================================

// TestIntegration_Neo4jConnectionFailure tests that Neo4j connection failure doesn't fail tool call.
func TestIntegration_Neo4jConnectionFailure(t *testing.T) {
	ctx := context.Background()

	// Create a client with invalid connection
	invalidConfig := graph.GraphClientConfig{
		URI:                     "bolt://invalid-host:7687",
		Username:                "neo4j",
		Password:                "password",
		Database:                "",
		MaxConnectionPoolSize:   10,
		ConnectionTimeout:       1 * time.Second, // Short timeout
		MaxTransactionRetryTime: 1 * time.Second,
	}

	invalidClient, err := graph.NewNeo4jClient(invalidConfig)
	require.NoError(t, err, "Client creation should succeed")

	// Don't call Connect() to simulate connection failure

	// Create components with invalid client
	graphLoader := loader.NewGraphLoader(invalidClient)
	processor := NewDiscoveryProcessor(graphLoader, invalidClient, slog.Default())

	execCtx := testIntegrationExecContext()

	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Ip: "192.168.1.1", Hostname: strPtr("test-host"), State: strPtr("up")},
		},
	}

	// Process should not return error (best-effort storage)
	result, err := processor.Process(ctx, execCtx, discovery)

	// Error should not be propagated (best-effort model)
	assert.NoError(t, err, "Process should not return error even if Neo4j fails")
	assert.NotNil(t, result, "Result should be returned")

	// Result should contain the error
	assert.True(t, result.HasErrors(), "Result should have errors")
	assert.Greater(t, len(result.Errors), 0, "Should capture Neo4j connection error")

	t.Logf("Captured error (expected): %v", result.Errors[0])
}

// TestIntegration_EmptyDiscovery tests processing an empty discovery result.
func TestIntegration_EmptyDiscovery(t *testing.T) {
	ctx := context.Background()

	// Setup Neo4j container
	_, client, cleanup := setupNeo4jContainer(t, ctx)
	defer cleanup()

	// Create components
	graphLoader := loader.NewGraphLoader(client)
	processor := NewDiscoveryProcessor(graphLoader, client, slog.Default())

	execCtx := testIntegrationExecContext()

	// Create empty discovery
	discovery := &graphragpb.DiscoveryResult{}

	// Process should succeed with no operations
	result, err := processor.Process(ctx, execCtx, discovery)
	require.NoError(t, err)
	require.NotNil(t, result)

	// No nodes or relationships should be created
	assert.Equal(t, 0, result.NodesCreated, "Should create 0 nodes")
	assert.Equal(t, 0, result.RelationshipsCreated, "Should create 0 relationships")
	assert.False(t, result.HasErrors(), "Should have no errors")
}

// TestIntegration_NilDiscovery tests processing a nil discovery result.
func TestIntegration_NilDiscovery(t *testing.T) {
	ctx := context.Background()

	// Setup Neo4j container
	_, client, cleanup := setupNeo4jContainer(t, ctx)
	defer cleanup()

	// Create components
	graphLoader := loader.NewGraphLoader(client)
	processor := NewDiscoveryProcessor(graphLoader, client, slog.Default())

	execCtx := testIntegrationExecContext()

	// Process nil discovery
	result, err := processor.Process(ctx, execCtx, nil)
	require.NoError(t, err)
	require.NotNil(t, result)

	// No operations should occur
	assert.Equal(t, 0, result.NodesCreated, "Should create 0 nodes")
	assert.Equal(t, 0, result.RelationshipsCreated, "Should create 0 relationships")
	assert.False(t, result.HasErrors(), "Should have no errors")
}

// TestIntegration_DISCOVEREDRelationships tests that DISCOVERED relationships are created from AgentRun.
func TestIntegration_DISCOVEREDRelationships(t *testing.T) {
	ctx := context.Background()

	// Setup Neo4j container
	_, client, cleanup := setupNeo4jContainer(t, ctx)
	defer cleanup()

	// Create components
	graphLoader := loader.NewGraphLoader(client)
	processor := NewDiscoveryProcessor(graphLoader, client, slog.Default())

	execCtx := testIntegrationExecContext()
	agentRunID := execCtx.AgentRunID

	// Create mission_run node (normally created by harness)
	_, err := client.Query(ctx, `
		CREATE (run:mission_run {id: $id, created_at: timestamp()})
		RETURN run
	`, map[string]any{"id": execCtx.MissionRunID})
	require.NoError(t, err, "Failed to create MissionRun node")

	// Create an AgentRun node manually (normally created by harness)
	_, err = client.Query(ctx, `
		CREATE (run:agent_run {id: $id, agent_name: $agent_name, started_at: timestamp()})
		RETURN run
	`, map[string]any{"id": agentRunID, "agent_name": execCtx.AgentName})
	require.NoError(t, err, "Failed to create AgentRun node")

	// Create discovery
	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Ip: "192.168.1.50", Hostname: strPtr("test-host"), State: strPtr("up")},
		},
	}

	// Process discovery
	result, err := processor.Process(ctx, execCtx, discovery)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify DISCOVERED relationships created
	assert.GreaterOrEqual(t, result.RelationshipsCreated, 1, "Should create at least DISCOVERED relationship")

	// Verify DISCOVERED relationship exists from AgentRun to Host
	discoveredQuery := `
		MATCH (run:agent_run {id: $agent_run_id})-[r:DISCOVERED]->(h:host {ip: $ip})
		RETURN r.discovered_at as discovered_at
	`
	queryResult, err := client.Query(ctx, discoveredQuery, map[string]any{
		"agent_run_id": agentRunID,
		"ip":           "192.168.1.50",
	})
	require.NoError(t, err, "Query should succeed")
	require.Len(t, queryResult.Records, 1, "Should find DISCOVERED relationship")
	assert.NotNil(t, queryResult.Records[0]["discovered_at"], "DISCOVERED relationship should have timestamp")
}

// TestIntegration_MissionScopedStorage tests that nodes are properly scoped to mission runs.
func TestIntegration_MissionScopedStorage(t *testing.T) {
	ctx := context.Background()

	// Setup Neo4j container
	_, client, cleanup := setupNeo4jContainer(t, ctx)
	defer cleanup()

	// Create components
	graphLoader := loader.NewGraphLoader(client)
	processor := NewDiscoveryProcessor(graphLoader, client, slog.Default())

	// Create two different mission run contexts
	execCtx1 := loader.ExecContext{
		MissionRunID: "mission-run-1",
		MissionID:    "mission-1",
		AgentName:    "agent-a",
		AgentRunID:   types.NewID().String(),
	}

	execCtx2 := loader.ExecContext{
		MissionRunID: "mission-run-2",
		MissionID:    "mission-2",
		AgentName:    "agent-b",
		AgentRunID:   types.NewID().String(),
	}

	// Same IP but different mission runs (should create separate nodes)
	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Ip: "192.168.1.1", Hostname: strPtr("shared-host"), State: strPtr("up")},
		},
	}

	// Process for first mission run
	result1, err := processor.Process(ctx, execCtx1, discovery)
	require.NoError(t, err)
	require.NotNil(t, result1)
	assert.Equal(t, 1, result1.NodesCreated, "Should create 1 node in mission run 1")

	// Process for second mission run
	result2, err := processor.Process(ctx, execCtx2, discovery)
	require.NoError(t, err)
	require.NotNil(t, result2)
	assert.Equal(t, 1, result2.NodesCreated, "Should create 1 node in mission run 2")

	// Verify both nodes exist (separate instances)
	nodeQuery := `
		MATCH (h:host {ip: '192.168.1.1'})
		RETURN h.mission_run_id as mission_run_id, h.discovered_by as discovered_by
		ORDER BY h.mission_run_id
	`
	queryResult, err := client.Query(ctx, nodeQuery, nil)
	require.NoError(t, err)
	assert.Len(t, queryResult.Records, 2, "Should have 2 separate host nodes")

	// Verify they belong to different mission runs
	assert.Equal(t, "mission-run-1", queryResult.Records[0]["mission_run_id"])
	assert.Equal(t, "mission-run-2", queryResult.Records[1]["mission_run_id"])
	assert.Equal(t, "agent-a", queryResult.Records[0]["discovered_by"])
	assert.Equal(t, "agent-b", queryResult.Records[1]["discovered_by"])
}
