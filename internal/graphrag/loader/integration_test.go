//go:build integration
// +build integration

package loader

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	"github.com/zero-day-ai/gibson/internal/types"
	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
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
	// Note: NEO4J_AUTH=none means auth is disabled, but we still need to provide
	// credentials for BasicAuth - they're just ignored by Neo4j
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

// cleanDatabase removes all nodes and relationships from the database.
func cleanDatabase(ctx context.Context, client graph.GraphClient) error {
	_, err := client.Query(ctx, "MATCH (n) DETACH DELETE n", nil)
	return err
}

// TestIntegration_BasicNodeCreation tests creating a single Host node.
func TestIntegration_BasicNodeCreation(t *testing.T) {
	ctx := context.Background()

	// Setup Neo4j container
	_, client, cleanup := setupNeo4jContainer(t, ctx)
	defer cleanup()

	// Create loader
	loader := NewGraphLoader(client)

	// Create a simple discovery result with one host
	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{
				Ip:       "192.168.1.1",
				Hostname: strPtr("gateway.local"),
				State:    strPtr("up"),
				Os:       strPtr("Linux Ubuntu 22.04"),
			},
		},
	}

	// Load into Neo4j
	execCtx := ExecContext{
		AgentRunID: "test-agent-run-123",
		MissionID:  "test-mission-456",
	}

	loadResult, err := loader.LoadDiscovery(ctx, execCtx, discovery)
	require.NoError(t, err, "LoadDiscovery should succeed")
	assert.Equal(t, 1, loadResult.NodesCreated, "Should create 1 host node")
	assert.False(t, loadResult.HasErrors(), "Should have no errors")

	// Debug: Check what nodes exist in the database
	allNodesResult, err := client.Query(ctx, "MATCH (n) RETURN labels(n) as labels, properties(n) as props", nil)
	require.NoError(t, err)
	t.Logf("All nodes in database: %d", len(allNodesResult.Records))
	for _, rec := range allNodesResult.Records {
		t.Logf("  Node: labels=%v, props=%v", rec["labels"], rec["props"])
	}

	// Verify the host node exists in Neo4j
	// Note: Neo4j node labels are case-sensitive, domain types use lowercase
	queryResult, err := client.Query(ctx, `
		MATCH (h:host {ip: $ip})
		RETURN h.ip as ip, h.hostname as hostname, h.state as state, h.os as os
	`, map[string]any{"ip": "192.168.1.1"})
	require.NoError(t, err, "Query should succeed")
	require.Len(t, queryResult.Records, 1, "Should find 1 host node")

	// Verify properties
	record := queryResult.Records[0]
	assert.Equal(t, "192.168.1.1", record["ip"])
	assert.Equal(t, "gateway.local", record["hostname"])
	assert.Equal(t, "up", record["state"])
	assert.Equal(t, "Linux Ubuntu 22.04", record["os"])
}

// TestIntegration_HostWithPortsAndServices tests creating a complete hierarchy.
func TestIntegration_HostWithPortsAndServices(t *testing.T) {
	ctx := context.Background()

	// Setup Neo4j container
	_, client, cleanup := setupNeo4jContainer(t, ctx)
	defer cleanup()

	// Create loader
	loader := NewGraphLoader(client)

	// Create a discovery result with host, ports, and services
	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{
				Ip:       "192.168.1.1",
				Hostname: strPtr("web-server"),
				State:    strPtr("up"),
			},
		},
		Ports: []*graphragpb.Port{
			{
				HostIp:   "192.168.1.1",
				Number:   22,
				Protocol: "tcp",
				State:    strPtr("open"),
			},
			{
				HostIp:   "192.168.1.1",
				Number:   80,
				Protocol: "tcp",
				State:    strPtr("open"),
			},
		},
		Services: []*graphragpb.Service{
			{
				HostIp:       "192.168.1.1",
				PortNumber:   22,
				PortProtocol: "tcp",
				Name:         "ssh",
				Version:      strPtr("OpenSSH 8.2"),
				Banner:       strPtr("SSH-2.0-OpenSSH_8.2p1"),
			},
			{
				HostIp:       "192.168.1.1",
				PortNumber:   80,
				PortProtocol: "tcp",
				Name:         "http",
				Version:      strPtr("nginx/1.18.0"),
			},
		},
	}

	// Load into Neo4j
	execCtx := ExecContext{
		AgentRunID: "test-agent-run-123",
		MissionID:  "test-mission-456",
	}

	loadResult, err := loader.LoadDiscovery(ctx, execCtx, discovery)
	require.NoError(t, err, "LoadDiscovery should succeed")
	assert.Equal(t, 5, loadResult.NodesCreated, "Should create 5 nodes (1 host + 2 ports + 2 services)")
	assert.False(t, loadResult.HasErrors(), "Should have no errors")

	// Verify all nodes exist
	queryResult, err := client.Query(ctx, `
		MATCH (h:host {ip: $ip})
		OPTIONAL MATCH (h)-[:HAS_PORT]->(p:port)
		OPTIONAL MATCH (p)-[:RUNS_SERVICE]->(s:service)
		RETURN count(DISTINCT h) as hosts, count(DISTINCT p) as ports, count(DISTINCT s) as services
	`, map[string]any{"ip": "192.168.1.1"})
	require.NoError(t, err, "Query should succeed")
	require.Len(t, queryResult.Records, 1, "Should return 1 record")

	record := queryResult.Records[0]
	assert.Equal(t, int64(1), record["hosts"])
	assert.Equal(t, int64(2), record["ports"])
	assert.Equal(t, int64(2), record["services"])

	// Verify HAS_PORT relationships from Host to Ports
	queryResult, err = client.Query(ctx, `
		MATCH (h:host {ip: $ip})-[r:HAS_PORT]->(p:port)
		RETURN count(r) as rel_count
	`, map[string]any{"ip": "192.168.1.1"})
	require.NoError(t, err)
	require.Len(t, queryResult.Records, 1)
	assert.Equal(t, int64(2), queryResult.Records[0]["rel_count"], "Should have 2 HAS_PORT relationships")

	// Verify RUNS_SERVICE relationships from Ports to Services
	queryResult, err = client.Query(ctx, `
		MATCH (p:port)-[r:RUNS_SERVICE]->(s:service)
		WHERE p.host_ip = $ip
		RETURN count(r) as rel_count
	`, map[string]any{"ip": "192.168.1.1"})
	require.NoError(t, err)
	require.Len(t, queryResult.Records, 1)
	assert.Equal(t, int64(2), queryResult.Records[0]["rel_count"], "Should have 2 RUNS_SERVICE relationships")
}

// TestIntegration_DiscoveredRelationships tests DISCOVERED relationships from AgentRun to nodes.
func TestIntegration_DiscoveredRelationships(t *testing.T) {
	ctx := context.Background()

	// Setup Neo4j container
	_, client, cleanup := setupNeo4jContainer(t, ctx)
	defer cleanup()

	// Create loader
	loader := NewGraphLoader(client)

	// First, create an AgentRun node manually (normally created by harness)
	agentRunID := types.NewID().String()
	_, err := client.Query(ctx, `
		CREATE (run:agent_run {id: $id, agent_name: "test-agent", started_at: timestamp()})
		RETURN run
	`, map[string]any{"id": agentRunID})
	require.NoError(t, err, "Failed to create AgentRun node")

	// Create a discovery result
	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{
				Ip:       "192.168.1.50",
				Hostname: strPtr("test-host"),
				State:    strPtr("up"),
			},
		},
	}

	// Load with AgentRunID in execution context
	execCtx := ExecContext{
		AgentRunID: agentRunID,
		MissionID:  "test-mission-789",
	}

	loadResult, err := loader.LoadDiscovery(ctx, execCtx, discovery)
	require.NoError(t, err, "LoadDiscovery should succeed")
	assert.Equal(t, 1, loadResult.NodesCreated, "Should create 1 node")
	assert.GreaterOrEqual(t, loadResult.RelationshipsCreated, 1, "Should create at least 1 DISCOVERED relationship")

	// Verify DISCOVERED relationship exists from AgentRun to Host
	queryResult, err := client.Query(ctx, `
		MATCH (run:agent_run {id: $agent_run_id})-[r:DISCOVERED]->(h:host {ip: $ip})
		RETURN r.discovered_at as discovered_at
	`, map[string]any{"agent_run_id": agentRunID, "ip": "192.168.1.50"})
	require.NoError(t, err, "Query should succeed")
	require.Len(t, queryResult.Records, 1, "Should find DISCOVERED relationship")
	assert.NotNil(t, queryResult.Records[0]["discovered_at"], "DISCOVERED relationship should have timestamp")
}

// TestIntegration_BatchLoading tests batch loading with multiple hosts.
func TestIntegration_BatchLoading(t *testing.T) {
	ctx := context.Background()

	// Setup Neo4j container
	_, client, cleanup := setupNeo4jContainer(t, ctx)
	defer cleanup()

	// Create loader
	loader := NewGraphLoader(client)

	// Create a discovery result with 15 hosts
	hosts := make([]*graphragpb.Host, 15)
	for i := 0; i < 15; i++ {
		hosts[i] = &graphragpb.Host{
			Ip:       fmt.Sprintf("192.168.1.%d", i+1),
			Hostname: strPtr(fmt.Sprintf("host-%d", i+1)),
			State:    strPtr("up"),
		}
	}

	discovery := &graphragpb.DiscoveryResult{
		Hosts: hosts,
	}

	execCtx := ExecContext{
		AgentRunID: "test-agent-run-batch",
		MissionID:  "test-mission-batch",
	}

	// Load using LoadDiscovery (uses batch internally)
	startTime := time.Now()
	loadResult, err := loader.LoadDiscovery(ctx, execCtx, discovery)
	duration := time.Since(startTime)
	t.Logf("LoadDiscovery completed in %v", duration)

	require.NoError(t, err, "LoadDiscovery should succeed")
	assert.Equal(t, 15, loadResult.NodesCreated, "Should create 15 nodes")
	assert.False(t, loadResult.HasErrors(), "Should have no errors")

	// Verify all hosts were created
	queryResult, err := client.Query(ctx, `
		MATCH (h:host)
		WHERE h.ip STARTS WITH '192.168.1.'
		RETURN count(h) as count
	`, nil)
	require.NoError(t, err)
	require.Len(t, queryResult.Records, 1)
	assert.Equal(t, int64(15), queryResult.Records[0]["count"], "Should have 15 host nodes")

	// Verify all hosts have correct properties
	queryResult, err = client.Query(ctx, `
		MATCH (h:host {ip: $ip})
		RETURN h.hostname as hostname, h.state as state
	`, map[string]any{"ip": "192.168.1.5"})
	require.NoError(t, err)
	require.Len(t, queryResult.Records, 1)
	assert.Equal(t, "host-5", queryResult.Records[0]["hostname"])
	assert.Equal(t, "up", queryResult.Records[0]["state"])
}

// TestIntegration_BatchLoadingWithRelationships tests batch loading with complex hierarchies.
func TestIntegration_BatchLoadingWithRelationships(t *testing.T) {
	ctx := context.Background()

	// Setup Neo4j container
	_, client, cleanup := setupNeo4jContainer(t, ctx)
	defer cleanup()

	// Create loader
	loader := NewGraphLoader(client)

	// Create a discovery result with hosts, ports, and services
	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Ip: "10.0.0.1", Hostname: strPtr("server-1"), State: strPtr("up")},
			{Ip: "10.0.0.2", Hostname: strPtr("server-2"), State: strPtr("up")},
			{Ip: "10.0.0.3", Hostname: strPtr("server-3"), State: strPtr("up")},
		},
		Ports: []*graphragpb.Port{
			{HostIp: "10.0.0.1", Number: 80, Protocol: "tcp", State: strPtr("open")},
			{HostIp: "10.0.0.1", Number: 443, Protocol: "tcp", State: strPtr("open")},
			{HostIp: "10.0.0.2", Number: 22, Protocol: "tcp", State: strPtr("open")},
			{HostIp: "10.0.0.2", Number: 3306, Protocol: "tcp", State: strPtr("open")},
			{HostIp: "10.0.0.3", Number: 5432, Protocol: "tcp", State: strPtr("open")},
		},
		Services: []*graphragpb.Service{
			{HostIp: "10.0.0.1", PortNumber: 80, PortProtocol: "tcp", Name: "http", Version: strPtr("Apache/2.4")},
			{HostIp: "10.0.0.1", PortNumber: 443, PortProtocol: "tcp", Name: "https", Version: strPtr("Apache/2.4")},
			{HostIp: "10.0.0.2", PortNumber: 22, PortProtocol: "tcp", Name: "ssh", Version: strPtr("OpenSSH 7.9")},
			{HostIp: "10.0.0.2", PortNumber: 3306, PortProtocol: "tcp", Name: "mysql", Version: strPtr("5.7.33")},
			{HostIp: "10.0.0.3", PortNumber: 5432, PortProtocol: "tcp", Name: "postgresql", Version: strPtr("13.2")},
		},
	}

	execCtx := ExecContext{
		AgentRunID: "test-agent-run-batch-rels",
		MissionID:  "test-mission-batch-rels",
	}

	// Load all nodes and relationships
	loadResult, err := loader.LoadDiscovery(ctx, execCtx, discovery)
	require.NoError(t, err, "LoadDiscovery should succeed")

	// Debug output
	t.Logf("LoadDiscovery result: created=%d, updated=%d, relationships=%d, errors=%d",
		loadResult.NodesCreated, loadResult.NodesUpdated, loadResult.RelationshipsCreated, len(loadResult.Errors))
	if loadResult.HasErrors() {
		for i, err := range loadResult.Errors {
			t.Logf("  Error %d: %v", i+1, err)
		}
	}

	// We expect 13 nodes total (3 hosts + 5 ports + 5 services)
	assert.Equal(t, 13, loadResult.NodesCreated, "Should create 13 nodes")

	// First, verify all nodes were created
	countQuery, err := client.Query(ctx, "MATCH (n) RETURN count(n) as total", nil)
	require.NoError(t, err)
	totalNodes := countQuery.Records[0]["total"]
	t.Logf("Total nodes in database: %v", totalNodes)
	assert.GreaterOrEqual(t, totalNodes, int64(13), "Should have at least 13 nodes in database")

	// Verify RUNS_SERVICE relationships exist
	serviceRelsQuery, err := client.Query(ctx, `
		MATCH (p:port)-[:RUNS_SERVICE]->(s:service)
		RETURN count(*) as count
	`, nil)
	require.NoError(t, err)
	serviceRels := serviceRelsQuery.Records[0]["count"]
	assert.Equal(t, int64(5), serviceRels, "Should have 5 RUNS_SERVICE relationships")

	// Verify HAS_PORT relationships
	portRelsQuery, err := client.Query(ctx, `
		MATCH (h:host)-[:HAS_PORT]->(p:port)
		RETURN count(*) as count
	`, nil)
	require.NoError(t, err)
	portRels := portRelsQuery.Records[0]["count"]
	assert.Equal(t, int64(5), portRels, "Should have 5 HAS_PORT relationships")

	// Verify complete paths
	queryResult, err := client.Query(ctx, `
		MATCH (h:host)-[:HAS_PORT]->(p:port)-[:RUNS_SERVICE]->(s:service)
		WHERE h.ip = $ip
		RETURN h.hostname as host, p.number as port, s.name as service
		ORDER BY p.number
	`, map[string]any{"ip": "10.0.0.1"})
	require.NoError(t, err)
	require.Len(t, queryResult.Records, 2)

	// Verify first path (port 80)
	assert.Equal(t, "server-1", queryResult.Records[0]["host"])
	assert.Equal(t, int64(80), queryResult.Records[0]["port"])
	assert.Equal(t, "http", queryResult.Records[0]["service"])

	// Verify second path (port 443)
	assert.Equal(t, "server-1", queryResult.Records[1]["host"])
	assert.Equal(t, int64(443), queryResult.Records[1]["port"])
	assert.Equal(t, "https", queryResult.Records[1]["service"])
}

// strPtr is a helper to create a pointer to a string
func strPtr(s string) *string {
	return &s
}
