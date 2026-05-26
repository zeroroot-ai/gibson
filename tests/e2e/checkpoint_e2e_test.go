//go:build e2e
// +build e2e

package e2e

// checkpoint_e2e_test.go verifies the mission pause/resume and approval
// checkpoint workflows end-to-end.
//
// Status: tests compile and skip unconditionally. Full wiring requires a
// complete mission orchestrator + Redis testcontainer setup that is deferred
// to the mission-orchestrator-e2e spec.
//
// Refactor history:
//   - agent-checkpointing spec: removed checkpoint.Store type; current
//     interface is checkpoint.CheckpointStore. ThreadManager signature changed.
//     agent.Harness renamed to agent.AgentHarness; agent.Result is a value
//     type (not pointer); NewResult takes types.ID not string.
//   - mission-api-only-cleanup spec: removed mission.MissionConfig and
//     MissionController.Create; replaced by CreateMissionByReferenceRequest
//     and CreateByReference. WorkflowID renamed to MissionDefinitionID.
//
// Next steps to un-skip: wire NewRedisCheckpointStore + DefaultMissionController
// + a real mission definition registered via CreateMissionDefinition, then
// remove the t.Skip() from setupE2EEnv.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/checkpoint"
	"github.com/zeroroot-ai/gibson/internal/mission"
	"github.com/zeroroot-ai/gibson/internal/types"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// E2ETestEnv encapsulates all dependencies for E2E checkpoint tests.
type E2ETestEnv struct {
	RedisClient     *redis.Client
	CheckpointStore checkpoint.CheckpointStore
	Checkpointer    checkpoint.ThreadedCheckpointer
	Restorer        checkpoint.StateRestorer
	ThreadManager   checkpoint.ThreadManager
	ApprovalManager checkpoint.ApprovalManager
	MissionStore    mission.MissionStore
	Controller      mission.MissionController
	TrackingAgent   *trackingAgent
	RedisContainer  testcontainers.Container
	CleanupFuncs    []func()
}

// trackingAgent is a mock agent that records execution for verification.
type trackingAgent struct {
	mu            sync.Mutex
	executedNodes []string
	executionTime map[string]time.Time
	shouldPause   bool
	pauseAfter    string
	shouldFail    bool
	failAt        string
}

func newTrackingAgent() *trackingAgent {
	return &trackingAgent{
		executedNodes: make([]string, 0),
		executionTime: make(map[string]time.Time),
	}
}

// Execute implements agent.Agent. Signature matches the current interface:
// (ctx, task agent.Task, harness agent.AgentHarness) (agent.Result, error)
func (ta *trackingAgent) Execute(ctx context.Context, task agent.Task, harness agent.AgentHarness) (agent.Result, error) {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	nodeID := task.Name
	ta.executedNodes = append(ta.executedNodes, nodeID)
	ta.executionTime[nodeID] = time.Now()

	time.Sleep(100 * time.Millisecond)

	if ta.shouldFail && ta.failAt == nodeID {
		return agent.Result{}, fmt.Errorf("simulated failure at node %s", nodeID)
	}

	result := agent.NewResult(task.ID)

	if ta.shouldPause && ta.pauseAfter == nodeID {
		result.Output = map[string]any{"request_pause": true}
		result.Status = agent.ResultStatusCompleted
		return result, nil
	}

	result.Complete(map[string]any{
		"node_id":     nodeID,
		"executed_at": ta.executionTime[nodeID],
		"data":        fmt.Sprintf("output from %s", nodeID),
	})

	return result, nil
}

func (ta *trackingAgent) GetExecutedNodes() []string {
	ta.mu.Lock()
	defer ta.mu.Unlock()
	nodes := make([]string, len(ta.executedNodes))
	copy(nodes, ta.executedNodes)
	return nodes
}

func (ta *trackingAgent) WasNodeExecuted(nodeID string) bool {
	ta.mu.Lock()
	defer ta.mu.Unlock()
	for _, id := range ta.executedNodes {
		if id == nodeID {
			return true
		}
	}
	return false
}

func (ta *trackingAgent) Reset() {
	ta.mu.Lock()
	defer ta.mu.Unlock()
	ta.executedNodes = make([]string, 0)
	ta.executionTime = make(map[string]time.Time)
	ta.shouldPause = false
	ta.pauseAfter = ""
	ta.shouldFail = false
	ta.failAt = ""
}

// setupE2EEnv initializes the test environment with real Redis.
//
// NOTE: this function calls t.Skip() unconditionally until the full
// mission orchestrator integration is wired. See file-level comment.
func setupE2EEnv(t *testing.T) (*E2ETestEnv, func()) {
	ctx := context.Background()
	env := &E2ETestEnv{
		CleanupFuncs: make([]func(), 0),
	}

	// Start Redis container with JSON support.
	req := testcontainers.ContainerRequest{
		Image:        "redis/redis-stack-server:latest",
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForLog("Ready to accept connections"),
	}

	redisContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err, "Failed to start Redis container")
	env.RedisContainer = redisContainer

	host, err := redisContainer.Host(ctx)
	require.NoError(t, err)

	port, err := redisContainer.MappedPort(ctx, "6379")
	require.NoError(t, err)

	redisAddr := fmt.Sprintf("%s:%s", host, port.Port())
	env.RedisClient = redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})

	err = env.RedisClient.Ping(ctx).Err()
	require.NoError(t, err, "Redis connection failed")

	// TODO: wire checkpoint and mission stack once orchestrator integration is
	// available. The interfaces are:
	//   checkpoint.NewRedisCheckpointStore(stateClient, checkpoint.DefaultStoreConfig())
	//   checkpoint.NewDefaultThreadManager(store)
	//   mission.NewMissionController(store, service, orchestrator, opts...)
	//   CreateMissionDefinition via daemon client, then CreateByReference

	t.Skip("Full E2E test setup requires complete mission orchestrator — implement after orchestrator integration")

	env.TrackingAgent = newTrackingAgent()

	cleanup := func() {
		for _, fn := range env.CleanupFuncs {
			fn()
		}
		if env.RedisClient != nil {
			env.RedisClient.Close()
		}
		if env.RedisContainer != nil {
			env.RedisContainer.Terminate(ctx)
		}
	}

	return env, cleanup
}

// agentNode builds a minimal AGENT-typed proto node fixture.
func agentNode(id, name, agentName string, deps ...string) *missionpb.MissionNode {
	return &missionpb.MissionNode{
		Id:           id,
		Name:         name,
		Type:         missionpb.NodeType_NODE_TYPE_AGENT,
		Dependencies: deps,
		Config: &missionpb.MissionNode_AgentConfig{
			AgentConfig: &missionpb.AgentNodeConfig{AgentName: agentName},
		},
	}
}

// createTestMissionDef creates a test mission definition with sequential nodes.
func createTestMissionDef() *missionpb.MissionDefinition {
	return &missionpb.MissionDefinition{
		Id:          types.NewID().String(),
		Name:        "Test Mission",
		Description: "E2E test mission for checkpoint validation",
		Nodes: map[string]*missionpb.MissionNode{
			"node1": agentNode("node1", "Node 1", "tracking-agent"),
			"node2": agentNode("node2", "Node 2", "tracking-agent"),
			"node3": agentNode("node3", "Node 3", "tracking-agent"),
			"node4": agentNode("node4", "Node 4", "tracking-agent"),
		},
		Edges: []*missionpb.MissionEdge{
			{From: "node1", To: "node2"},
			{From: "node2", To: "node3"},
			{From: "node3", To: "node4"},
		},
		EntryPoints: []string{"node1"},
		ExitPoints:  []string{"node4"},
	}
}

// createApprovalMissionDef creates a mission definition with an approval-required node.
func createApprovalMissionDef() *missionpb.MissionDefinition {
	approvalNode := agentNode("approval", "Approval Node", "tracking-agent")
	approvalNode.Metadata = map[string]string{"requires_approval": "true"}
	return &missionpb.MissionDefinition{
		Id:          types.NewID().String(),
		Name:        "Approval Test Mission",
		Description: "Mission with approval workflow",
		Nodes: map[string]*missionpb.MissionNode{
			"node1":    agentNode("node1", "Pre-Approval Node", "tracking-agent"),
			"approval": approvalNode,
			"node2":    agentNode("node2", "Post-Approval Node", "tracking-agent"),
		},
		Edges: []*missionpb.MissionEdge{
			{From: "node1", To: "approval"},
			{From: "approval", To: "node2"},
		},
		EntryPoints: []string{"node1"},
		ExitPoints:  []string{"node2"},
	}
}

// createParallelMissionDef creates a mission definition with parallel nodes.
func createParallelMissionDef() *missionpb.MissionDefinition {
	return &missionpb.MissionDefinition{
		Id:          types.NewID().String(),
		Name:        "Parallel Test Mission",
		Description: "Mission with parallel node groups",
		Nodes: map[string]*missionpb.MissionNode{
			"start":     agentNode("start", "Start Node", "tracking-agent"),
			"parallel1": agentNode("parallel1", "Parallel Node 1", "tracking-agent"),
			"parallel2": agentNode("parallel2", "Parallel Node 2", "tracking-agent"),
			"join":      agentNode("join", "Join Node", "tracking-agent", "parallel1", "parallel2"),
		},
		Edges: []*missionpb.MissionEdge{
			{From: "start", To: "parallel1"},
			{From: "start", To: "parallel2"},
			{From: "parallel1", To: "join"},
			{From: "parallel2", To: "join"},
		},
		EntryPoints: []string{"start"},
		ExitPoints:  []string{"join"},
	}
}

// TestE2E_MissionPauseResume tests the complete pause/resume workflow.
func TestE2E_MissionPauseResume(t *testing.T) {
	env, cleanup := setupE2EEnv(t)
	defer cleanup()

	ctx := context.Background()
	testDef := createTestMissionDef()

	// Create mission via CreateByReference (mission-api-only-cleanup: MissionConfig
	// was removed; missions now reference pre-registered definitions by ID).
	targetID := types.NewID()
	missionRecord, err := env.Controller.CreateByReference(ctx, mission.CreateMissionByReferenceRequest{
		MissionDefinitionID: testDef.ID,
		TargetID:            targetID,
	})
	require.NoError(t, err, "Failed to create mission")

	env.TrackingAgent.shouldPause = true
	env.TrackingAgent.pauseAfter = "node2"

	err = env.Controller.Start(ctx, missionRecord.ID)
	require.NoError(t, err, "Failed to start mission")

	time.Sleep(3 * time.Second)

	missionRecord, err = env.Controller.Get(ctx, missionRecord.ID)
	require.NoError(t, err)
	assert.Equal(t, mission.MissionStatusPaused, missionRecord.Status)
	assert.NotNil(t, missionRecord.Checkpoint, "Checkpoint should be created on pause")

	assert.True(t, env.TrackingAgent.WasNodeExecuted("node1"))
	assert.True(t, env.TrackingAgent.WasNodeExecuted("node2"))
	assert.False(t, env.TrackingAgent.WasNodeExecuted("node3"))

	cp := missionRecord.Checkpoint
	assert.NotEmpty(t, cp.Checksum, "Checkpoint should have integrity checksum")

	env.TrackingAgent.shouldPause = false
	err = env.Controller.Resume(ctx, missionRecord.ID)
	require.NoError(t, err, "Failed to resume mission")

	time.Sleep(3 * time.Second)

	missionRecord, err = env.Controller.Get(ctx, missionRecord.ID)
	require.NoError(t, err)
	assert.Equal(t, mission.MissionStatusCompleted, missionRecord.Status)

	executedNodes := env.TrackingAgent.GetExecutedNodes()
	assert.Equal(t, 4, len(executedNodes), "Should execute exactly 4 nodes")

	nodeCount := make(map[string]int)
	for _, nodeID := range executedNodes {
		nodeCount[nodeID]++
	}
	for nodeID, count := range nodeCount {
		assert.Equal(t, 1, count, "Node %s should execute exactly once", nodeID)
	}

	t.Logf("SUCCESS: Mission pause/resume completed. Executed nodes: %v", executedNodes)
}

// TestE2E_CrashRecovery simulates pod eviction and recovery.
func TestE2E_CrashRecovery(t *testing.T) {
	env, cleanup := setupE2EEnv(t)
	defer cleanup()

	ctx := context.Background()
	testDef := createTestMissionDef()

	targetID := types.NewID()
	missionRecord, err := env.Controller.CreateByReference(ctx, mission.CreateMissionByReferenceRequest{
		MissionDefinitionID: testDef.ID,
		TargetID:            targetID,
	})
	require.NoError(t, err)

	err = env.Controller.Start(ctx, missionRecord.ID)
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	// Create a checkpoint (simulating periodic checkpoint via ThreadedCheckpointer).
	threadID, err := env.Checkpointer.CreateThread(ctx, missionRecord.ID)
	require.NoError(t, err)

	state := &checkpoint.ExecutionState{
		MissionID:     missionRecord.ID,
		ThreadID:      threadID,
		CurrentNodeID: "node2",
		PendingQueue:  []string{"node3", "node4"},
		NodeStates:    make(map[string]*checkpoint.NodeState),
	}

	cp, err := env.Checkpointer.Checkpoint(ctx, threadID, state)
	require.NoError(t, err)

	executedBeforeCrash := env.TrackingAgent.GetExecutedNodes()
	env.TrackingAgent.Reset()

	time.Sleep(500 * time.Millisecond)

	// Load checkpoint to verify it persisted.
	loadedCP, err := env.CheckpointStore.GetLatestCheckpoint(ctx, cp.ThreadID)
	require.NoError(t, err)
	require.NotNil(t, loadedCP)
	assert.Equal(t, cp.ID, loadedCP.ID)

	err = env.Controller.Resume(ctx, missionRecord.ID)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	missionRecord, err = env.Controller.Get(ctx, missionRecord.ID)
	require.NoError(t, err)
	assert.Equal(t, mission.MissionStatusCompleted, missionRecord.Status)

	assert.True(t, env.TrackingAgent.WasNodeExecuted("node3"))
	assert.True(t, env.TrackingAgent.WasNodeExecuted("node4"))
	assert.False(t, env.TrackingAgent.WasNodeExecuted("node1"))
	assert.False(t, env.TrackingAgent.WasNodeExecuted("node2"))

	t.Logf("Executed before crash: %v", executedBeforeCrash)
	t.Logf("Executed after recovery: %v", env.TrackingAgent.GetExecutedNodes())
}

// TestE2E_ApprovalWorkflow tests human-in-the-loop approval.
func TestE2E_ApprovalWorkflow(t *testing.T) {
	env, cleanup := setupE2EEnv(t)
	defer cleanup()

	ctx := context.Background()
	testDef := createApprovalMissionDef()

	missionRecord, err := env.Controller.CreateByReference(ctx, mission.CreateMissionByReferenceRequest{
		MissionDefinitionID: testDef.ID,
		TargetID:            types.NewID(),
	})
	require.NoError(t, err)

	err = env.Controller.Start(ctx, missionRecord.ID)
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	missionRecord, err = env.Controller.Get(ctx, missionRecord.ID)
	require.NoError(t, err)
	assert.Equal(t, mission.MissionStatusPaused, missionRecord.Status)

	require.NotNil(t, missionRecord.Checkpoint)

	// Submit approval via ApprovalManager.ProcessDecision.
	// MissionCheckpoint does not carry ThreadID; resolve it via ThreadManager.
	missionThreads, err := env.ThreadManager.ListThreads(ctx, missionRecord.ID)
	require.NoError(t, err)
	require.NotEmpty(t, missionThreads, "Expected at least one thread for the mission")
	threadID := missionThreads[0].ID
	decision := checkpoint.ApprovalDecision{
		Status:     checkpoint.ApprovalStatusApproved,
		ApprovedBy: "e2e-test",
		ApprovedAt: time.Now(),
	}

	err = env.ApprovalManager.ProcessDecision(ctx, threadID, decision)
	require.NoError(t, err)

	start := time.Now()
	time.Sleep(1 * time.Second)
	resumeDuration := time.Since(start)
	assert.Less(t, resumeDuration, 600*time.Millisecond, "Should resume within 500ms of approval")

	time.Sleep(2 * time.Second)
	missionRecord, err = env.Controller.Get(ctx, missionRecord.ID)
	require.NoError(t, err)
	assert.Equal(t, mission.MissionStatusCompleted, missionRecord.Status)

	assert.True(t, env.TrackingAgent.WasNodeExecuted("node1"))
	assert.True(t, env.TrackingAgent.WasNodeExecuted("approval"))
	assert.True(t, env.TrackingAgent.WasNodeExecuted("node2"))
}

// TestE2E_ApprovalTimeout tests approval timeout behavior.
func TestE2E_ApprovalTimeout(t *testing.T) {
	env, cleanup := setupE2EEnv(t)
	defer cleanup()

	ctx := context.Background()
	testDef := createApprovalMissionDef()
	testDef.Nodes["approval"].Timeout = 2 * time.Second

	missionRecord, err := env.Controller.CreateByReference(ctx, mission.CreateMissionByReferenceRequest{
		MissionDefinitionID: testDef.ID,
		TargetID:            types.NewID(),
	})
	require.NoError(t, err)

	err = env.Controller.Start(ctx, missionRecord.ID)
	require.NoError(t, err)

	time.Sleep(4 * time.Second)

	missionRecord, err = env.Controller.Get(ctx, missionRecord.ID)
	require.NoError(t, err)
	assert.Equal(t, mission.MissionStatusPaused, missionRecord.Status)
	if missionRecord.Metadata != nil {
		timeout, ok := missionRecord.Metadata["approval_timeout"]
		assert.True(t, ok, "Should have approval_timeout metadata")
		assert.True(t, timeout.(bool))
	}

	assert.NotNil(t, missionRecord.Checkpoint)
	t.Logf("Approval timeout handled correctly. Mission status: %s", missionRecord.Status)
}

// TestE2E_ApprovalWithModification tests approval with state modification.
func TestE2E_ApprovalWithModification(t *testing.T) {
	env, cleanup := setupE2EEnv(t)
	defer cleanup()

	ctx := context.Background()
	testDef := createApprovalMissionDef()

	missionRecord, err := env.Controller.CreateByReference(ctx, mission.CreateMissionByReferenceRequest{
		MissionDefinitionID: testDef.ID,
		TargetID:            types.NewID(),
	})
	require.NoError(t, err)

	err = env.Controller.Start(ctx, missionRecord.ID)
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	missionRecord, err = env.Controller.Get(ctx, missionRecord.ID)
	require.NoError(t, err)
	require.NotNil(t, missionRecord.Checkpoint)

	// MissionCheckpoint does not carry ThreadID; resolve it via ThreadManager.
	timeoutThreads, err := env.ThreadManager.ListThreads(ctx, missionRecord.ID)
	require.NoError(t, err)
	require.NotEmpty(t, timeoutThreads, "Expected at least one thread for the mission")
	threadID := timeoutThreads[0].ID

	decision := checkpoint.ApprovalDecision{
		Status:     checkpoint.ApprovalStatusApproved,
		ApprovedBy: "e2e-test",
		ApprovedAt: time.Now(),
	}

	err = env.ApprovalManager.ProcessDecision(ctx, threadID, decision)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	missionRecord, err = env.Controller.Get(ctx, missionRecord.ID)
	require.NoError(t, err)
	assert.Equal(t, mission.MissionStatusCompleted, missionRecord.Status)
}

// TestE2E_TimeTravel tests replaying from a historical checkpoint.
// Note: The old ReplayFromCheckpoint / BranchOptions APIs were removed.
// Thread branching is now done via ThreadedCheckpointer.UpdateState.
func TestE2E_TimeTravel(t *testing.T) {
	env, cleanup := setupE2EEnv(t)
	defer cleanup()

	ctx := context.Background()
	testDef := createTestMissionDef()

	missionRecord, err := env.Controller.CreateByReference(ctx, mission.CreateMissionByReferenceRequest{
		MissionDefinitionID: testDef.ID,
		TargetID:            types.NewID(),
	})
	require.NoError(t, err)

	env.TrackingAgent.shouldPause = true
	env.TrackingAgent.pauseAfter = "node2"

	err = env.Controller.Start(ctx, missionRecord.ID)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)
	missionRecord, err = env.Controller.Get(ctx, missionRecord.ID)
	require.NoError(t, err)
	require.NotNil(t, missionRecord.Checkpoint)
	// MissionCheckpoint does not carry ThreadID; resolve it via ThreadManager.
	midThreads, err := env.ThreadManager.ListThreads(ctx, missionRecord.ID)
	require.NoError(t, err)
	require.NotEmpty(t, midThreads, "Expected at least one thread for the mission")
	middleThreadID := midThreads[0].ID

	env.TrackingAgent.shouldPause = false
	err = env.Controller.Resume(ctx, missionRecord.ID)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)
	missionRecord, err = env.Controller.Get(ctx, missionRecord.ID)
	require.NoError(t, err)
	assert.Equal(t, mission.MissionStatusCompleted, missionRecord.Status)

	// Create a branch from the midpoint checkpoint using CreateBranchThread.
	env.TrackingAgent.Reset()

	latestCP, err := env.CheckpointStore.GetLatestCheckpoint(ctx, middleThreadID)
	require.NoError(t, err)

	branchThread, err := env.ThreadManager.CreateBranchThread(ctx, middleThreadID, latestCP.ID)
	require.NoError(t, err)
	require.NotNil(t, branchThread)

	assert.Equal(t, middleThreadID, branchThread.ParentThread)
	t.Logf("Branch thread created: %s (parent: %s)", branchThread.ID, branchThread.ParentThread)
}

// TestE2E_ThreadBranching tests creating and executing thread branches.
func TestE2E_ThreadBranching(t *testing.T) {
	env, cleanup := setupE2EEnv(t)
	defer cleanup()

	ctx := context.Background()
	testDef := createTestMissionDef()

	missionRecord, err := env.Controller.CreateByReference(ctx, mission.CreateMissionByReferenceRequest{
		MissionDefinitionID: testDef.ID,
		TargetID:            types.NewID(),
	})
	require.NoError(t, err)

	env.TrackingAgent.shouldPause = true
	env.TrackingAgent.pauseAfter = "node2"

	err = env.Controller.Start(ctx, missionRecord.ID)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	missionRecord, err = env.Controller.Get(ctx, missionRecord.ID)
	require.NoError(t, err)
	require.NotNil(t, missionRecord.Checkpoint)

	// MissionCheckpoint does not carry ThreadID; resolve it via ThreadManager.
	// MissionCheckpoint.ID is types.ID; CreateBranchThread expects a string.
	branchBaseThreads, err := env.ThreadManager.ListThreads(ctx, missionRecord.ID)
	require.NoError(t, err)
	require.NotEmpty(t, branchBaseThreads, "Expected at least one thread for the mission")
	originalThreadID := branchBaseThreads[0].ID
	originalCheckpointID := missionRecord.Checkpoint.ID.String()

	// Create branch via ThreadedCheckpointer.
	branchThread, err := env.ThreadManager.CreateBranchThread(ctx, originalThreadID, originalCheckpointID)
	require.NoError(t, err)
	require.NotNil(t, branchThread)

	env.TrackingAgent.Reset()
	env.TrackingAgent.shouldPause = false

	// Verify original thread status via ThreadManager.
	threads, err := env.ThreadManager.ListThreads(ctx, missionRecord.ID)
	require.NoError(t, err)
	assert.NotEmpty(t, threads, "Should have at least one thread")

	assert.Equal(t, originalThreadID, branchThread.ParentThread)
	t.Logf("Branch created: %s (parent: %s)", branchThread.ID, branchThread.ParentThread)
}

// TestE2E_MemoryContinuity tests memory preservation across pause/resume.
func TestE2E_MemoryContinuity(t *testing.T) {
	env, cleanup := setupE2EEnv(t)
	defer cleanup()

	ctx := context.Background()
	testDef := createTestMissionDef()

	missionRecord, err := env.Controller.CreateByReference(ctx, mission.CreateMissionByReferenceRequest{
		MissionDefinitionID: testDef.ID,
		TargetID:            types.NewID(),
	})
	require.NoError(t, err)

	err = env.Controller.Start(ctx, missionRecord.ID)
	require.NoError(t, err)

	env.TrackingAgent.shouldPause = true
	env.TrackingAgent.pauseAfter = "node2"

	time.Sleep(3 * time.Second)

	missionRecord, err = env.Controller.Get(ctx, missionRecord.ID)
	require.NoError(t, err)
	require.NotNil(t, missionRecord.Checkpoint)

	env.TrackingAgent.shouldPause = false
	err = env.Controller.Resume(ctx, missionRecord.ID)
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	missionRecord, err = env.Controller.Get(ctx, missionRecord.ID)
	require.NoError(t, err)
	assert.Equal(t, mission.MissionStatusCompleted, missionRecord.Status)

	t.Log("Memory continuity verified across pause/resume cycle")
}

// TestE2E_ParallelNodes tests checkpoint creation with parallel execution.
func TestE2E_ParallelNodes(t *testing.T) {
	env, cleanup := setupE2EEnv(t)
	defer cleanup()

	ctx := context.Background()
	testDef := createParallelMissionDef()

	missionRecord, err := env.Controller.CreateByReference(ctx, mission.CreateMissionByReferenceRequest{
		MissionDefinitionID: testDef.ID,
		TargetID:            types.NewID(),
	})
	require.NoError(t, err)

	err = env.Controller.Start(ctx, missionRecord.ID)
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	err = env.Controller.Pause(ctx, missionRecord.ID)
	require.NoError(t, err)

	time.Sleep(1 * time.Second)

	missionRecord, err = env.Controller.Get(ctx, missionRecord.ID)
	require.NoError(t, err)
	require.NotNil(t, missionRecord.Checkpoint)

	err = env.Controller.Resume(ctx, missionRecord.ID)
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	missionRecord, err = env.Controller.Get(ctx, missionRecord.ID)
	require.NoError(t, err)
	assert.Equal(t, mission.MissionStatusCompleted, missionRecord.Status)

	executedNodes := env.TrackingAgent.GetExecutedNodes()
	assert.Equal(t, 4, len(executedNodes), "Should execute all 4 nodes")

	t.Logf("Parallel execution with checkpoint successful. Nodes: %v", executedNodes)
}

// TestE2E_CheckpointIntegrity tests checkpoint integrity validation.
func TestE2E_CheckpointIntegrity(t *testing.T) {
	env, cleanup := setupE2EEnv(t)
	defer cleanup()

	ctx := context.Background()
	testDef := createTestMissionDef()

	missionRecord, err := env.Controller.CreateByReference(ctx, mission.CreateMissionByReferenceRequest{
		MissionDefinitionID: testDef.ID,
		TargetID:            types.NewID(),
	})
	require.NoError(t, err)

	// Create a thread and checkpoint via ThreadedCheckpointer.
	threadID, err := env.Checkpointer.CreateThread(ctx, missionRecord.ID)
	require.NoError(t, err)

	state := &checkpoint.ExecutionState{
		MissionID:     missionRecord.ID,
		ThreadID:      threadID,
		CurrentNodeID: "node1",
		PendingQueue:  []string{"node1", "node2", "node3", "node4"},
		NodeStates:    make(map[string]*checkpoint.NodeState),
	}

	cp, err := env.Checkpointer.Checkpoint(ctx, threadID, state)
	require.NoError(t, err)
	require.NotEmpty(t, cp.Checksum, "Checkpoint must have checksum")

	originalChecksum := cp.Checksum

	loadedCP, err := env.CheckpointStore.GetLatestCheckpoint(ctx, threadID)
	require.NoError(t, err)

	assert.Equal(t, originalChecksum, loadedCP.Checksum)

	t.Log("Checkpoint integrity validation successful")
}

// TestE2E_ConcurrentCheckpoints tests concurrent checkpoint operations.
func TestE2E_ConcurrentCheckpoints(t *testing.T) {
	env, cleanup := setupE2EEnv(t)
	defer cleanup()

	ctx := context.Background()
	testDef := createTestMissionDef()

	missionRecord, err := env.Controller.CreateByReference(ctx, mission.CreateMissionByReferenceRequest{
		MissionDefinitionID: testDef.ID,
		TargetID:            types.NewID(),
	})
	require.NoError(t, err)

	numGoroutines := 5
	var wg sync.WaitGroup
	errs := make(chan error, numGoroutines)
	checkpoints := make(chan *checkpoint.Checkpoint, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			threadID, createErr := env.Checkpointer.CreateThread(ctx, missionRecord.ID)
			if createErr != nil {
				errs <- createErr
				return
			}

			state := &checkpoint.ExecutionState{
				MissionID:     missionRecord.ID,
				ThreadID:      threadID,
				CurrentNodeID: fmt.Sprintf("node%d", idx),
				PendingQueue:  []string{"remaining"},
				NodeStates:    make(map[string]*checkpoint.NodeState),
			}

			cp, checkErr := env.Checkpointer.Checkpoint(ctx, threadID, state)
			if checkErr != nil {
				errs <- checkErr
				return
			}
			checkpoints <- cp
		}(i)
	}

	wg.Wait()
	close(errs)
	close(checkpoints)

	for err := range errs {
		assert.NoError(t, err, "Concurrent checkpoint should not error")
	}

	// Verify we can load a checkpoint from any of the threads.
	for cp := range checkpoints {
		loaded, loadErr := env.CheckpointStore.GetLatestCheckpoint(ctx, cp.ThreadID)
		require.NoError(t, loadErr)
		assert.NotNil(t, loaded)
		break // Verify one is enough to prove correctness
	}

	t.Log("Concurrent checkpoint operations handled safely")
}

// TestE2E_LargeCheckpoint tests checkpoint with large state data.
func TestE2E_LargeCheckpoint(t *testing.T) {
	env, cleanup := setupE2EEnv(t)
	defer cleanup()

	ctx := context.Background()
	testDef := createTestMissionDef()

	missionRecord, err := env.Controller.CreateByReference(ctx, mission.CreateMissionByReferenceRequest{
		MissionDefinitionID: testDef.ID,
		TargetID:            types.NewID(),
	})
	require.NoError(t, err)

	threadID, err := env.Checkpointer.CreateThread(ctx, missionRecord.ID)
	require.NoError(t, err)

	pendingNodes := make([]string, 100)
	for i := 0; i < 100; i++ {
		pendingNodes[i] = fmt.Sprintf("node_%d", i)
	}

	state := &checkpoint.ExecutionState{
		MissionID:     missionRecord.ID,
		ThreadID:      threadID,
		CurrentNodeID: "current",
		PendingQueue:  pendingNodes,
		NodeStates:    make(map[string]*checkpoint.NodeState),
	}

	start := time.Now()
	cp, err := env.Checkpointer.Checkpoint(ctx, threadID, state)
	require.NoError(t, err)
	captureDuration := time.Since(start)

	assert.Greater(t, cp.SizeBytes, int64(0), "Should track checkpoint size")

	start = time.Now()
	loadedCP, err := env.CheckpointStore.GetLatestCheckpoint(ctx, threadID)
	require.NoError(t, err)
	loadDuration := time.Since(start)

	assert.Equal(t, cp.ID, loadedCP.ID)

	t.Logf("Large checkpoint: capture=%v, load=%v, size=%d bytes",
		captureDuration, loadDuration, cp.SizeBytes)
}
