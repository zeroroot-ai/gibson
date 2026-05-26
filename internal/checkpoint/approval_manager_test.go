//go:build integration
// +build integration

// Package checkpoint integration tests — require Redis.
// Run with: go test -tags=integration ./internal/checkpoint/...
package checkpoint

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/state"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// setupTestRedis starts a miniredis instance and returns a StateClient backed
// by it plus a cleanup function.
func setupTestRedis(t *testing.T) (*state.StateClient, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err, "failed to start miniredis")
	t.Cleanup(func() { mr.Close() })

	cfg := &state.Config{URL: "redis://" + mr.Addr()}
	sc, err := state.NewStateClient(cfg)
	require.NoError(t, err, "failed to create StateClient")
	t.Cleanup(func() { sc.Close() })
	return sc, mr
}

// mockEventEmitter implements EventEmitter for testing
type mockEventEmitter struct {
	events []ApprovalEvent
}

func (m *mockEventEmitter) Emit(ctx context.Context, event ApprovalEvent) error {
	m.events = append(m.events, event)
	return nil
}

func (m *mockEventEmitter) getEventCount(eventType ApprovalEventType) int {
	count := 0
	for _, e := range m.events {
		if e.Type == eventType {
			count++
		}
	}
	return count
}

func (m *mockEventEmitter) reset() {
	m.events = nil
}

// TestDefaultApprovalConfig verifies default configuration values
func TestDefaultApprovalConfig(t *testing.T) {
	config := DefaultApprovalConfig()

	assert.Equal(t, 24*time.Hour, config.DefaultTimeout)
	assert.Equal(t, 7*24*time.Hour, config.MaxTimeout)
	assert.Equal(t, 500*time.Millisecond, config.ResumeDelay)
	assert.Equal(t, "gibson", config.KeyPrefix)
}

// TestNewApprovalManager verifies manager construction against a real (miniredis) StateClient.
func TestNewApprovalManager(t *testing.T) {
	ctx := context.Background()
	stateClient, _ := setupTestRedis(t)

	store := NewRedisCheckpointStore(stateClient, DefaultStoreConfig())
	checkpointer := NewThreadedCheckpointer(store, store, nil, DefaultCheckpointerConfig())

	config := DefaultApprovalConfig()
	manager := NewApprovalManager(store, checkpointer, stateClient, config)

	assert.NotNil(t, manager, "NewApprovalManager should return a non-nil manager")
	_ = ctx
}

// TestApprovalRequest validates request structure
func TestApprovalRequest(t *testing.T) {
	request := ApprovalRequest{
		NodeID:      "exploit-node-1",
		Title:       "Execute SQL injection test",
		Description: "Test for SQL injection vulnerability in login endpoint",
		Reasoning:   "High confidence vulnerability detected, need approval before exploit attempt",
		RiskLevel:   RiskLevelHigh,
		ProposedActions: []ProposedAction{
			{
				Type:        "exploit",
				Description: "Execute SQLi payload against /api/login",
				Parameters: map[string]any{
					"endpoint": "/api/login",
					"payload":  "' OR '1'='1",
				},
				RiskLevel:  RiskLevelHigh,
				Reversible: false,
				Impact:     "May expose database credentials",
			},
		},
		Timeout:           2 * time.Hour,
		Impact:            "Potential data exposure",
		Alternatives:      []string{"Manual verification", "Static analysis only"},
		EstimatedDuration: 30 * time.Second,
		RequiresRollback:  false,
		CurrentFindings:   []types.ID{types.NewID()},
		Metadata: map[string]any{
			"confidence": "high",
			"severity":   "critical",
		},
	}

	assert.Equal(t, "exploit-node-1", request.NodeID)
	assert.Equal(t, RiskLevelHigh, request.RiskLevel)
	assert.Len(t, request.ProposedActions, 1)
	assert.Equal(t, 2*time.Hour, request.Timeout)
}

// TestPendingApproval validates pending approval structure
func TestPendingApproval(t *testing.T) {
	missionID := types.NewID()
	threadID := "thread-123"
	checkpointID := "checkpoint-456"
	requestedAt := time.Now()
	timeoutAt := requestedAt.Add(24 * time.Hour)

	approvalState := NewApprovalState("test-node", 24*time.Hour)

	pending := &PendingApproval{
		ThreadID:     threadID,
		CheckpointID: checkpointID,
		MissionID:    missionID,
		State:        approvalState,
		CreatedAt:    requestedAt,
		TimeoutAt:    timeoutAt,
	}

	assert.Equal(t, threadID, pending.ThreadID)
	assert.Equal(t, checkpointID, pending.CheckpointID)
	assert.Equal(t, missionID, pending.MissionID)
	assert.Equal(t, ApprovalStatusPending, pending.State.Status)
	assert.False(t, pending.State.IsResolved())
}

// TestApprovalEventTypes verifies event type constants
func TestApprovalEventTypes(t *testing.T) {
	assert.Equal(t, ApprovalEventType("approval.requested"), ApprovalEventRequested)
	assert.Equal(t, ApprovalEventType("approval.approved"), ApprovalEventApproved)
	assert.Equal(t, ApprovalEventType("approval.rejected"), ApprovalEventRejected)
	assert.Equal(t, ApprovalEventType("approval.modified"), ApprovalEventModified)
	assert.Equal(t, ApprovalEventType("approval.timeout"), ApprovalEventTimeout)
	assert.Equal(t, ApprovalEventType("approval.cancelled"), ApprovalEventCancelled)
}

// TestApprovalEvent validates event structure
func TestApprovalEvent(t *testing.T) {
	event := ApprovalEvent{
		Type:      ApprovalEventRequested,
		ThreadID:  "thread-123",
		Timestamp: time.Now(),
		Data: map[string]any{
			"node_id":    "exploit-node-1",
			"risk_level": RiskLevelHigh,
		},
	}

	assert.Equal(t, ApprovalEventRequested, event.Type)
	assert.Equal(t, "thread-123", event.ThreadID)
	assert.NotNil(t, event.Data)

	data := event.Data.(map[string]any)
	assert.Equal(t, "exploit-node-1", data["node_id"])
	assert.Equal(t, RiskLevelHigh, data["risk_level"])
}

// TestMockEventEmitter verifies mock event emitter functionality
func TestMockEventEmitter(t *testing.T) {
	emitter := &mockEventEmitter{}
	ctx := context.Background()

	// Emit some events
	err := emitter.Emit(ctx, ApprovalEvent{
		Type:      ApprovalEventRequested,
		ThreadID:  "thread-1",
		Timestamp: time.Now(),
	})
	require.NoError(t, err)

	err = emitter.Emit(ctx, ApprovalEvent{
		Type:      ApprovalEventApproved,
		ThreadID:  "thread-1",
		Timestamp: time.Now(),
	})
	require.NoError(t, err)

	err = emitter.Emit(ctx, ApprovalEvent{
		Type:      ApprovalEventRequested,
		ThreadID:  "thread-2",
		Timestamp: time.Now(),
	})
	require.NoError(t, err)

	// Verify counts
	assert.Len(t, emitter.events, 3)
	assert.Equal(t, 2, emitter.getEventCount(ApprovalEventRequested))
	assert.Equal(t, 1, emitter.getEventCount(ApprovalEventApproved))
	assert.Equal(t, 0, emitter.getEventCount(ApprovalEventRejected))

	// Test reset
	emitter.reset()
	assert.Len(t, emitter.events, 0)
}

// TestApprovalManagerRedisKeys validates Redis key generation
func TestApprovalManagerRedisKeys(t *testing.T) {
	// Create manager with custom config
	config := ApprovalConfig{
		KeyPrefix: "test-gibson",
	}

	stateClient := &state.StateClient{} // Minimal mock
	manager := &DefaultApprovalManager{
		config:      config,
		stateClient: stateClient,
	}

	// Test approval key
	approvalKey := manager.approvalKey("thread-123")
	assert.Equal(t, "test-gibson:approval:thread-123", approvalKey)

	// Test index key
	indexKey := manager.approvalIndexKey()
	assert.Equal(t, "test-gibson:approval:index", indexKey)
}

// TestApprovalManagerConfigDefaults verifies config defaults are applied
func TestApprovalManagerConfigDefaults(t *testing.T) {
	stateClient := &state.StateClient{} // Minimal mock
	config := ApprovalConfig{}          // Empty config

	manager := NewApprovalManager(nil, nil, stateClient, config)

	assert.Equal(t, 24*time.Hour, manager.config.DefaultTimeout)
	assert.Equal(t, 7*24*time.Hour, manager.config.MaxTimeout)
	assert.Equal(t, 500*time.Millisecond, manager.config.ResumeDelay)
	assert.Equal(t, "gibson", manager.config.KeyPrefix)
}
