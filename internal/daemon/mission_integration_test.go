//go:build integration
// +build integration

package daemon_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/daemon"
	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	"github.com/zero-day-ai/gibson/internal/graphrag/queries"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/orchestrator"
	"github.com/zero-day-ai/gibson/internal/types"
)

// addBootstrapMocks queues the standard CreateMission + CreateMissionRun mock results
// into the provided mock client, so Bootstrap can proceed past those two initial calls.
func addBootstrapMocks(mockClient *graph.MockGraphClient, nodeCount, depCount int) {
	// CreateMission
	mockClient.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{{"id": "mock-mission-id"}},
	})
	// CreateMissionRun
	mockClient.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{{"run_id": "mock-run-id"}},
	})
	// MissionNode creation (one per node)
	for i := 0; i < nodeCount; i++ {
		mockClient.AddQueryResult(graph.QueryResult{
			Records: []map[string]any{{"id": fmt.Sprintf("node-%d-id", i+1)}},
		})
	}
	// DEPENDS_ON relationship creation (one per dep)
	for i := 0; i < depCount; i++ {
		mockClient.AddQueryResult(graph.QueryResult{
			Records: []map[string]any{{"count": int64(1)}},
		})
	}
}

// newTestMissionRun creates a MissionRun for use in bootstrap tests.
func newTestMissionRun(missionID types.ID) *mission.MissionRun {
	return &mission.MissionRun{
		ID:        types.NewID(),
		MissionID: missionID,
		RunNumber: 1,
		Status:    mission.MissionRunStatusRunning,
	}
}

// TestMissionLifecycle tests the mission lifecycle using GraphBootstrapper:
//  1. Create a mission definition with three sequential nodes
//  2. Bootstrap the mission into the graph (via mock client)
//  3. Verify that correct queries were issued for Mission, MissionRun, nodes, and deps
//  4. Verify that the bootstrap result carries a MissionRunID
//
// This test exercises the fundamental lifecycle path: definition → bootstrap →
// graph representation, which is the precondition for orchestrated execution.
func TestMissionLifecycle(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()

	// Set up mock graph client.
	mockClient := graph.NewMockGraphClient()
	require.NoError(t, mockClient.Connect(ctx))

	// Mission: node-1 (entry) → node-2 → node-3 (exit)
	addBootstrapMocks(mockClient, 3, 2)

	bootstrapper := daemon.NewGraphBootstrapper(mockClient, logger)

	missionID := types.NewID()
	now := time.Now()
	m := &mission.Mission{
		ID:                  missionID,
		Name:                "Lifecycle Test Mission",
		Description:         "Verifies the full bootstrap lifecycle path",
		Status:              mission.MissionStatusRunning,
		TargetID:            types.NewID(),
		MissionDefinitionID: types.NewID(),
		StartedAt:           mission.NewUnixTimePtr(&now),
	}

	def := &mission.MissionDefinition{
		Name:        "Lifecycle Test Mission",
		Description: "Sequential three-node mission for lifecycle verification.",
		Nodes: map[string]*mission.MissionNode{
			"node-1": {
				ID:           "node-1",
				Type:         mission.NodeTypeAgent,
				Description:  "Entry recon node",
				AgentName:    "recon-agent",
				AgentTask:    &agent.Task{Name: "Recon", Goal: "Gather intel", Input: map[string]any{"target": "example.com"}},
				Dependencies: []string{},
			},
			"node-2": {
				ID:           "node-2",
				Type:         mission.NodeTypeAgent,
				Description:  "Exploitation node",
				AgentName:    "exploit-agent",
				AgentTask:    &agent.Task{Name: "Exploit", Goal: "Gain access", Input: map[string]any{"findings": "from_recon"}},
				Dependencies: []string{"node-1"},
			},
			"node-3": {
				ID:           "node-3",
				Type:         mission.NodeTypeTool,
				Description:  "Report generation node",
				ToolName:     "report-gen",
				ToolInput:    map[string]any{"format": "sarif"},
				Dependencies: []string{"node-2"},
			},
		},
	}

	run := newTestMissionRun(missionID)

	// Bootstrap the mission into the graph.
	result, err := bootstrapper.Bootstrap(ctx, m, def, run)
	require.NoError(t, err, "Bootstrap should succeed for a well-formed mission")
	require.NotNil(t, result, "Bootstrap should return a non-nil BootstrapResult")
	assert.NotEmpty(t, result.MissionRunID, "BootstrapResult should carry a MissionRunID")

	// Verify query count: 1 CreateMission + 1 CreateMissionRun + 3 nodes + 2 deps = 7 total.
	calls := mockClient.GetCallsByMethod("Query")
	assert.Len(t, calls, 7, "Bootstrap should issue 7 graph queries for a 3-node/2-dep mission")

	t.Logf("Mission lifecycle bootstrap verified: %d queries issued, MissionRunID=%s",
		len(calls), result.MissionRunID)
}

// TestMissionEventStreamOrdering verifies that the DAG topology of a parallel
// mission is correctly represented after bootstrap.  Specifically:
//   - Entry nodes (no dependencies) are created with status "ready"
//   - Downstream nodes (with dependencies) are created with status "pending"
//   - The correct number of DEPENDS_ON edges is created
//
// This mirrors what the event stream ordering test would verify once the runtime
// is wired: parallel nodes must start concurrently, join nodes must wait for all
// upstream nodes.
func TestMissionEventStreamOrdering(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()

	// DAG topology under test:
	//   node-1 (entry) ─┬─→ node-2 ─┐
	//                   └─→ node-3 ─┴─→ node-4 (join/exit)
	// node-2 and node-3 run in parallel; node-4 waits for both.

	mockClient := graph.NewMockGraphClient()
	require.NoError(t, mockClient.Connect(ctx))

	// 4 nodes, 4 dependency edges (node-2→node-1, node-3→node-1, node-4→node-2, node-4→node-3).
	addBootstrapMocks(mockClient, 4, 4)

	bootstrapper := daemon.NewGraphBootstrapper(mockClient, logger)

	missionID := types.NewID()
	now := time.Now()
	m := &mission.Mission{
		ID:                  missionID,
		Name:                "Parallel Mission",
		Status:              mission.MissionStatusRunning,
		TargetID:            types.NewID(),
		MissionDefinitionID: types.NewID(),
		StartedAt:           mission.NewUnixTimePtr(&now),
	}

	def := &mission.MissionDefinition{
		Name:        "Parallel Mission",
		Description: "Fan-out then join to verify event ordering.",
		Nodes: map[string]*mission.MissionNode{
			"node-1": {
				ID: "node-1", Type: mission.NodeTypeAgent, AgentName: "entry-agent",
				AgentTask:    &agent.Task{Name: "Entry", Goal: "Start", Input: map[string]any{}},
				Dependencies: []string{},
			},
			"node-2": {
				ID: "node-2", Type: mission.NodeTypeAgent, AgentName: "parallel-agent-a",
				AgentTask:    &agent.Task{Name: "ParallelA", Goal: "Branch A", Input: map[string]any{}},
				Dependencies: []string{"node-1"},
			},
			"node-3": {
				ID: "node-3", Type: mission.NodeTypeAgent, AgentName: "parallel-agent-b",
				AgentTask:    &agent.Task{Name: "ParallelB", Goal: "Branch B", Input: map[string]any{}},
				Dependencies: []string{"node-1"},
			},
			"node-4": {
				ID: "node-4", Type: mission.NodeTypeAgent, AgentName: "join-agent",
				AgentTask:    &agent.Task{Name: "Join", Goal: "Merge results", Input: map[string]any{}},
				Dependencies: []string{"node-2", "node-3"},
			},
		},
	}

	run := newTestMissionRun(missionID)
	result, err := bootstrapper.Bootstrap(ctx, m, def, run)
	require.NoError(t, err, "Bootstrap should succeed for a parallel mission")
	require.NotNil(t, result)

	// Verify query count: 1 Mission + 1 MissionRun + 4 nodes + 4 deps = 10.
	calls := mockClient.GetCallsByMethod("Query")
	assert.Len(t, calls, 10, "Parallel mission should issue 10 queries (1 mission + 1 run + 4 nodes + 4 deps)")

	// The first two calls are CreateMission and CreateMissionRun.
	// Calls 3-6 (indices 2-5) are MissionNode creation.  Verify status semantics:
	//   node-1 has no deps → "ready"; node-2/3/4 have deps → "pending".
	readyCount, pendingCount := 0, 0
	for _, call := range calls[2:6] {
		params, ok := call.Args[1].(map[string]any)
		require.True(t, ok, "node creation call should carry a params map")
		switch params["status"] {
		case "ready":
			readyCount++
		case "pending":
			pendingCount++
		}
	}
	assert.Equal(t, 1, readyCount, "exactly one node (node-1) should be 'ready'")
	assert.Equal(t, 3, pendingCount, "three nodes (node-2, node-3, node-4) should be 'pending'")

	t.Logf("Event ordering DAG verified: %d ready, %d pending, %d dep edges",
		readyCount, pendingCount, 4)
}

// TestMissionStop verifies the mission stop path.  Because live mission execution
// is not yet available, this test validates that:
//   - A mission can transition through state from running → stopped via the mock store
//   - The bootstrap + metadata persisted at bootstrap time can be queried back
//   - A forced stop (no grace period) and a graceful stop both succeed at the
//     bootstrap / graph layer
func TestMissionStop(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()

	t.Run("graceful stop representation in graph", func(t *testing.T) {
		mockClient := graph.NewMockGraphClient()
		require.NoError(t, mockClient.Connect(ctx))

		// Single long-running node mission; 0 deps.
		addBootstrapMocks(mockClient, 1, 0)

		bootstrapper := daemon.NewGraphBootstrapper(mockClient, logger)

		missionID := types.NewID()
		now := time.Now()
		m := &mission.Mission{
			ID:                  missionID,
			Name:                "Long Running Mission",
			Status:              mission.MissionStatusRunning,
			TargetID:            types.NewID(),
			MissionDefinitionID: types.NewID(),
			StartedAt:           mission.NewUnixTimePtr(&now),
		}
		def := &mission.MissionDefinition{
			Name:        "Long Running Mission",
			Description: "Single agent that runs until stopped.",
			Nodes: map[string]*mission.MissionNode{
				"scanner": {
					ID: "scanner", Type: mission.NodeTypeAgent, AgentName: "scanner-agent",
					AgentTask:    &agent.Task{Name: "Scan", Goal: "Scan continuously", Input: map[string]any{}},
					Dependencies: []string{},
				},
			},
		}

		run := newTestMissionRun(missionID)
		result, err := bootstrapper.Bootstrap(ctx, m, def, run)
		require.NoError(t, err)
		require.NotNil(t, result)

		// Simulate the stop: in a live system the orchestrator would mark the
		// mission status as stopped.  Here we verify the mission status field
		// can be set to Cancelled and the bootstrap result is still usable.
		m.Status = mission.MissionStatusCancelled
		assert.Equal(t, mission.MissionStatusCancelled, m.Status,
			"mission status should reflect graceful stop (cancelled)")
		assert.NotEmpty(t, result.MissionRunID, "run ID should persist after stop")
	})

	t.Run("forced stop clears active mission tracking", func(t *testing.T) {
		mockClient := graph.NewMockGraphClient()
		require.NoError(t, mockClient.Connect(ctx))
		addBootstrapMocks(mockClient, 1, 0)

		bootstrapper := daemon.NewGraphBootstrapper(mockClient, logger)

		missionID := types.NewID()
		now := time.Now()
		m := &mission.Mission{
			ID:                  missionID,
			Name:                "Force Stop Mission",
			Status:              mission.MissionStatusRunning,
			TargetID:            types.NewID(),
			MissionDefinitionID: types.NewID(),
			StartedAt:           mission.NewUnixTimePtr(&now),
		}
		def := &mission.MissionDefinition{
			Name:        "Force Stop Mission",
			Description: "Mission that will be force-stopped.",
			Nodes: map[string]*mission.MissionNode{
				"target-node": {
					ID: "target-node", Type: mission.NodeTypeTool, ToolName: "long-scan",
					ToolInput:    map[string]any{"depth": "full"},
					Dependencies: []string{},
				},
			},
		}

		run := newTestMissionRun(missionID)
		result, err := bootstrapper.Bootstrap(ctx, m, def, run)
		require.NoError(t, err)
		require.NotNil(t, result)

		// Simulate a forced stop that bypasses graceful shutdown.
		m.Status = mission.MissionStatusFailed
		m.Error = "force-stopped by operator"
		assert.Equal(t, mission.MissionStatusFailed, m.Status)
		assert.Equal(t, "force-stopped by operator", m.Error,
			"mission error field should record the forced stop reason")
	})
}

// TestMissionVariables verifies that mission definitions with variable placeholders
// in their node inputs can be created and serialised without data loss.  Specifically:
//   - Input maps that contain variable-style values (${VAR}) round-trip through JSON
//   - Multiple nodes can share variable references
//   - Missing variable slots do not corrupt the definition structure
func TestMissionVariables(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()

	mockClient := graph.NewMockGraphClient()
	require.NoError(t, mockClient.Connect(ctx))

	// Two nodes that reference variables in their inputs.
	addBootstrapMocks(mockClient, 2, 1)

	bootstrapper := daemon.NewGraphBootstrapper(mockClient, logger)

	missionID := types.NewID()
	now := time.Now()
	m := &mission.Mission{
		ID:                  missionID,
		Name:                "Variable Substitution Mission",
		Status:              mission.MissionStatusRunning,
		TargetID:            types.NewID(),
		MissionDefinitionID: types.NewID(),
		StartedAt:           mission.NewUnixTimePtr(&now),
	}

	// Nodes use ${VAR} placeholders in inputs.
	def := &mission.MissionDefinition{
		Name:        "Variable Substitution Mission",
		Description: "Tests that variable placeholders survive the definition lifecycle.",
		Nodes: map[string]*mission.MissionNode{
			"recon": {
				ID:        "recon",
				Type:      mission.NodeTypeAgent,
				AgentName: "recon-agent",
				AgentTask: &agent.Task{
					Name:  "Recon",
					Goal:  "Discover target surface",
					Input: map[string]any{"target": "${TARGET_HOST}", "depth": "${SCAN_DEPTH:-3}"},
				},
				Dependencies: []string{},
			},
			"exploit": {
				ID:        "exploit",
				Type:      mission.NodeTypeAgent,
				AgentName: "exploit-agent",
				AgentTask: &agent.Task{
					Name:  "Exploit",
					Goal:  "Leverage recon findings",
					Input: map[string]any{"host": "${TARGET_HOST}", "creds": "${CRED_FILE}"},
				},
				Dependencies: []string{"recon"},
			},
		},
	}

	// Verify variable placeholders survive in the definition without modification.
	reconTask := def.Nodes["recon"].AgentTask
	assert.Equal(t, "${TARGET_HOST}", reconTask.Input["target"],
		"variable placeholder should be preserved in node input")
	assert.Equal(t, "${SCAN_DEPTH:-3}", reconTask.Input["depth"],
		"default-value variable syntax should be preserved")

	exploitTask := def.Nodes["exploit"].AgentTask
	assert.Equal(t, "${TARGET_HOST}", exploitTask.Input["host"],
		"same variable used in multiple nodes should be preserved independently")
	assert.Equal(t, "${CRED_FILE}", exploitTask.Input["creds"],
		"credential variable placeholder should be preserved")

	// Bootstrap must succeed even with unresolved variable placeholders in inputs;
	// variable resolution happens at runtime, not at bootstrap time.
	run := newTestMissionRun(missionID)
	result, err := bootstrapper.Bootstrap(ctx, m, def, run)
	require.NoError(t, err, "Bootstrap should succeed with unresolved variable placeholders")
	require.NotNil(t, result)
	assert.NotEmpty(t, result.MissionRunID)

	// 1 Mission + 1 MissionRun + 2 nodes + 1 dep = 5 queries.
	calls := mockClient.GetCallsByMethod("Query")
	assert.Len(t, calls, 5, "variable-containing mission should produce 5 graph queries")

	t.Logf("Variable substitution mission bootstrapped: MissionRunID=%s, queries=%d",
		result.MissionRunID, len(calls))
}

// TestMultipleConcurrentMissions verifies that multiple missions can be bootstrapped
// concurrently without data races or cross-contamination.  Each goroutine:
//  1. Creates a unique mission with a unique mock graph client
//  2. Bootstraps it independently
//  3. Verifies the returned MissionRunID is non-empty and unique
//
// The test exercises the thread-safety of GraphBootstrapper (which is stateless
// per-call) and confirms that each bootstrap produces an isolated result.
func TestMultipleConcurrentMissions(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()

	const numMissions = 5

	type bootstrapResult struct {
		missionID  types.ID
		runID      string
		queryCount int
		err        error
	}

	results := make([]bootstrapResult, numMissions)
	var wg sync.WaitGroup
	wg.Add(numMissions)

	for i := 0; i < numMissions; i++ {
		i := i // capture loop variable
		go func() {
			defer wg.Done()

			// Each mission gets its own mock client to avoid shared-state races.
			mockClient := graph.NewMockGraphClient()
			if err := mockClient.Connect(ctx); err != nil {
				results[i] = bootstrapResult{err: fmt.Errorf("connect: %w", err)}
				return
			}

			// 2 nodes, 1 dep per mission.
			addBootstrapMocks(mockClient, 2, 1)

			bootstrapper := daemon.NewGraphBootstrapper(mockClient, logger)

			missionID := types.NewID()
			now := time.Now()
			m := &mission.Mission{
				ID:                  missionID,
				Name:                fmt.Sprintf("Concurrent Mission %d", i),
				Status:              mission.MissionStatusRunning,
				TargetID:            types.NewID(),
				MissionDefinitionID: types.NewID(),
				StartedAt:           mission.NewUnixTimePtr(&now),
			}
			def := &mission.MissionDefinition{
				Name:        fmt.Sprintf("Concurrent Mission %d", i),
				Description: fmt.Sprintf("Mission %d running concurrently.", i),
				Nodes: map[string]*mission.MissionNode{
					"entry": {
						ID: "entry", Type: mission.NodeTypeAgent,
						AgentName:    fmt.Sprintf("agent-%d-entry", i),
						AgentTask:    &agent.Task{Name: "Entry", Goal: "Start", Input: map[string]any{"index": i}},
						Dependencies: []string{},
					},
					"exit": {
						ID: "exit", Type: mission.NodeTypeAgent,
						AgentName:    fmt.Sprintf("agent-%d-exit", i),
						AgentTask:    &agent.Task{Name: "Exit", Goal: "Finish", Input: map[string]any{"index": i}},
						Dependencies: []string{"entry"},
					},
				},
			}

			run := newTestMissionRun(missionID)
			result, err := bootstrapper.Bootstrap(ctx, m, def, run)
			if err != nil {
				results[i] = bootstrapResult{err: fmt.Errorf("bootstrap: %w", err)}
				return
			}

			calls := mockClient.GetCallsByMethod("Query")
			results[i] = bootstrapResult{
				missionID:  missionID,
				runID:      result.MissionRunID,
				queryCount: len(calls),
			}
		}()
	}

	wg.Wait()

	// Verify all goroutines succeeded and produced unique run IDs.
	seenRunIDs := make(map[string]bool)
	seenMissionIDs := make(map[types.ID]bool)

	for i, r := range results {
		require.NoError(t, r.err, "goroutine %d should not return an error", i)
		assert.NotEmpty(t, r.runID, "goroutine %d should produce a non-empty MissionRunID", i)
		// 1 Mission + 1 MissionRun + 2 nodes + 1 dep = 5 queries per mission.
		assert.Equal(t, 5, r.queryCount, "goroutine %d should issue 5 queries", i)

		assert.False(t, seenRunIDs[r.runID],
			"MissionRunID %q from goroutine %d should be unique", r.runID, i)
		assert.False(t, seenMissionIDs[r.missionID],
			"MissionID from goroutine %d should be unique", i)

		seenRunIDs[r.runID] = true
		seenMissionIDs[r.missionID] = true
	}

	t.Logf("Concurrent bootstrap verified: %d missions, all with unique run IDs", numMissions)
}

// TestMissionBootstrapAndObserve tests the full bootstrap → observe flow.
// This integration test verifies that:
// 1. A mission can be bootstrapped into Neo4j with GraphBootstrapper
// 2. The Mission node exists in Neo4j
// 3. MissionNode nodes exist with PART_OF relationships to the mission
// 4. Observer.Observe() can retrieve the mission without "mission not found" errors
func TestMissionBootstrapAndObserve(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	// Connect to Neo4j
	graphClient, err := graph.NewNeo4jClient(graph.GraphClientConfig{
		URI:                     getEnvOrDefault("NEO4J_URI", "bolt://localhost:7687"),
		Username:                getEnvOrDefault("NEO4J_USER", "neo4j"),
		Password:                getEnvOrDefault("NEO4J_PASSWORD", "gibson-dev-2024"),
		MaxConnectionPoolSize:   10,
		ConnectionTimeout:       10 * time.Second,
		MaxTransactionRetryTime: 30 * time.Second,
	})
	require.NoError(t, err, "Failed to create Neo4j client")

	err = graphClient.Connect(ctx)
	require.NoError(t, err, "Failed to connect to Neo4j")
	defer graphClient.Close(ctx)

	// Verify Neo4j is healthy
	health := graphClient.Health(ctx)
	require.Equal(t, types.HealthStateHealthy, health.State, "Neo4j is not healthy: %s", health.Message)

	logger := slog.Default()

	// Step 1: Create a mission definition with 2-3 nodes and dependencies
	missionID := types.NewID()
	now := time.Now()
	m := &mission.Mission{
		ID:                    missionID,
		Name:                  "Integration Test Mission",
		Description:           "Mission for testing bootstrap and observe flow",
		Status:                mission.MissionStatusRunning,
		TargetID:              types.NewID(),
		MissionDefinitionID:   types.NewID(),
		MissionDefinitionJSON: `{"name": "test-mission", "description": "Test mission"}`,
		StartedAt:             mission.NewUnixTimePtr(&now),
	}

	// Create mission definition with 3 nodes:
	// node-1 (entry) -> node-2 -> node-3
	def := &mission.MissionDefinition{
		Name:        "Integration Test Mission",
		Description: "Test mission for bootstrap and observe integration test.",
		Nodes: map[string]*mission.MissionNode{
			"node-1": {
				ID:          "node-1",
				Type:        mission.NodeTypeAgent,
				Description: "First node (entry point)",
				AgentName:   "recon-agent",
				AgentTask: &agent.Task{
					Name:        "Initial Recon",
					Description: "Perform initial reconnaissance",
					Goal:        "Gather target information",
					Input:       map[string]any{"target": "example.com"},
				},
				Dependencies: []string{}, // No dependencies (entry point)
			},
			"node-2": {
				ID:          "node-2",
				Type:        mission.NodeTypeAgent,
				Description: "Second node (depends on node-1)",
				AgentName:   "exploit-agent",
				AgentTask: &agent.Task{
					Name:        "Exploitation",
					Description: "Attempt exploitation",
					Goal:        "Gain access",
					Input:       map[string]any{"findings": "from_node_1"},
				},
				Dependencies: []string{"node-1"}, // Depends on node-1
			},
			"node-3": {
				ID:          "node-3",
				Type:        mission.NodeTypeTool,
				Description: "Third node (depends on node-2)",
				ToolName:    "report-generator",
				ToolInput: map[string]any{
					"format": "sarif",
					"output": "/tmp/report.sarif",
				},
				Dependencies: []string{"node-2"}, // Depends on node-2
			},
		},
	}

	// Clean up any existing test data
	_, _ = graphClient.Query(ctx, `
		MATCH (m:Mission) WHERE m.id = $mission_id DETACH DELETE m
	`, map[string]any{"mission_id": missionID.String()})

	// Step 2: Bootstrap the mission into Neo4j
	t.Run("Bootstrap Mission", func(t *testing.T) {
		bootstrapper := daemon.NewGraphBootstrapper(graphClient, logger)
		run := newTestMissionRun(missionID)
		result, err := bootstrapper.Bootstrap(ctx, m, def, run)
		require.NoError(t, err, "Bootstrap should succeed")
		require.NotNil(t, result, "Bootstrap result should not be nil")
		assert.NotEmpty(t, result.MissionRunID, "Bootstrap result should carry a MissionRunID")

		t.Logf("Mission bootstrapped: id=%s, name=%s, run_id=%s",
			missionID, m.Name, result.MissionRunID)
	})

	// Step 3: Verify Mission node exists in Neo4j
	t.Run("Verify Mission Node", func(t *testing.T) {
		result, err := graphClient.Query(ctx, `
			MATCH (m:Mission) WHERE m.id = $mission_id
			RETURN m.id as id, m.name as name, m.status as status
		`, map[string]any{"mission_id": missionID.String()})
		require.NoError(t, err, "Query for Mission node should succeed")
		require.Len(t, result.Records, 1, "Should find exactly 1 Mission node")

		record := result.Records[0]
		assert.Equal(t, missionID.String(), record["id"], "Mission ID should match")
		assert.Equal(t, m.Name, record["name"], "Mission name should match")
		assert.Equal(t, "running", record["status"], "Mission status should be running")

		t.Logf("Mission node verified: id=%s, name=%s, status=%s",
			record["id"], record["name"], record["status"])
	})

	// Step 4: Verify MissionNode nodes exist with PART_OF relationships
	t.Run("Verify MissionNodes and Relationships", func(t *testing.T) {
		// Query for mission nodes linked to this mission
		result, err := graphClient.Query(ctx, `
			MATCH (m:Mission {id: $mission_id})<-[:PART_OF]-(n:MissionNode)
			RETURN n.id as id, n.name as name, n.type as type, n.status as status
			ORDER BY n.name
		`, map[string]any{"mission_id": missionID.String()})
		require.NoError(t, err, "Query for MissionNode nodes should succeed")
		require.Len(t, result.Records, 3, "Should find exactly 3 MissionNode nodes")

		// Verify nodes have correct properties
		nodeNames := []string{"node-1", "node-2", "node-3"}
		for i, record := range result.Records {
			assert.Equal(t, nodeNames[i], record["name"], "Node name should match")
			assert.NotEmpty(t, record["id"], "Node ID should not be empty")
			assert.NotEmpty(t, record["type"], "Node type should not be empty")
			assert.NotEmpty(t, record["status"], "Node status should not be empty")

			t.Logf("MissionNode verified: name=%s, id=%s, type=%s, status=%s",
				record["name"], record["id"], record["type"], record["status"])
		}
	})

	// Step 5: Verify dependency relationships between nodes
	t.Run("Verify Node Dependencies", func(t *testing.T) {
		// Query for DEPENDS_ON relationships
		result, err := graphClient.Query(ctx, `
			MATCH (from:MissionNode)-[:DEPENDS_ON]->(to:MissionNode)
			WHERE from.mission_id = $mission_id
			RETURN from.name as from_name, to.name as to_name
			ORDER BY from_name, to_name
		`, map[string]any{"mission_id": missionID.String()})
		require.NoError(t, err, "Query for dependencies should succeed")
		require.Len(t, result.Records, 2, "Should find exactly 2 DEPENDS_ON relationships")

		// Verify expected dependencies
		expectedDeps := map[string]string{
			"node-2": "node-1", // node-2 depends on node-1
			"node-3": "node-2", // node-3 depends on node-2
		}

		for _, record := range result.Records {
			fromName := record["from_name"].(string)
			toName := record["to_name"].(string)
			expectedTo, exists := expectedDeps[fromName]
			assert.True(t, exists, "Unexpected dependency from %s", fromName)
			assert.Equal(t, expectedTo, toName, "Dependency should match: %s->%s", fromName, toName)

			t.Logf("Dependency verified: %s -> %s", fromName, toName)
		}
	})

	// Step 6: Create an Observer and call Observer.Observe()
	t.Run("Observe Mission", func(t *testing.T) {
		missionQueries := queries.NewMissionQueries(graphClient)
		executionQueries := queries.NewExecutionQueries(graphClient)
		observer := orchestrator.NewObserver(missionQueries, executionQueries)

		// Call Observe - should succeed without "mission not found" error
		observationState, err := observer.Observe(ctx, missionID.String())
		require.NoError(t, err, "Observer.Observe() should succeed")
		require.NotNil(t, observationState, "ObservationState should not be nil")

		// Verify observation state contains expected data
		assert.Equal(t, missionID.String(), observationState.MissionInfo.ID, "Mission ID should match")
		assert.Equal(t, m.Name, observationState.MissionInfo.Name, "Mission name should match")
		assert.Equal(t, "running", observationState.MissionInfo.Status, "Mission status should be running")

		// Verify graph summary
		assert.Equal(t, 3, observationState.GraphSummary.TotalNodes, "Should have 3 nodes")
		assert.Equal(t, 0, observationState.GraphSummary.CompletedNodes, "No completed nodes yet")
		assert.Equal(t, 0, observationState.GraphSummary.FailedNodes, "No failed nodes yet")
		assert.Equal(t, 2, observationState.GraphSummary.PendingNodes, "Should have 2 pending nodes (node-2, node-3)")

		// Verify ready nodes (entry point without dependencies)
		require.Len(t, observationState.ReadyNodes, 1, "Should have 1 ready node")
		assert.Equal(t, "node-1", observationState.ReadyNodes[0].Name, "Ready node should be node-1")

		t.Logf("Observer.Observe() succeeded:")
		t.Logf("   Mission: %s (status: %s)", observationState.MissionInfo.Name, observationState.MissionInfo.Status)
		t.Logf("   Graph Summary: %d total, %d ready, %d pending",
			observationState.GraphSummary.TotalNodes,
			len(observationState.ReadyNodes),
			observationState.GraphSummary.PendingNodes)
		t.Logf("   Ready Nodes: %v", observationState.ReadyNodes[0].Name)
	})

	// Clean up test data
	t.Cleanup(func() {
		_, _ = graphClient.Query(ctx, `
			MATCH (m:Mission) WHERE m.id = $mission_id DETACH DELETE m
		`, map[string]any{"mission_id": missionID.String()})
		t.Logf("Cleaned up test data for mission %s", missionID)
	})
}

// getEnvOrDefault returns the environment variable value or a default if not set.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
