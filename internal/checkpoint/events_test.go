package checkpoint

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/types"
)

func TestLifecycleEventType_String(t *testing.T) {
	tests := []struct {
		name      string
		eventType LifecycleEventType
		want      string
	}{
		{
			name:      "checkpoint created",
			eventType: EventCheckpointCreated,
			want:      "checkpoint.created",
		},
		{
			name:      "thread branched",
			eventType: EventThreadBranched,
			want:      "thread.branched",
		},
		{
			name:      "approval approved",
			eventType: EventApprovalApproved,
			want:      "approval.approved",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.eventType.String()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCheckpointLifecycleEvent_ToStreamEntry(t *testing.T) {
	event := &CheckpointLifecycleEvent{
		Type:         EventCheckpointCreated,
		MissionID:    "mission-123",
		ThreadID:     "thread-456",
		CheckpointID: "checkpoint-789",
		NodeID:       "node-001",
		Timestamp:    time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		Data: map[string]any{
			"size_bytes": int64(1024),
			"compressed": true,
		},
		CorrelationID: "corr-123",
	}

	values := event.toStreamEntry()

	assert.Equal(t, "checkpoint.created", values["type"])
	assert.Equal(t, "mission-123", values["mission_id"])
	assert.Equal(t, "thread-456", values["thread_id"])
	assert.Equal(t, "checkpoint-789", values["checkpoint_id"])
	assert.Equal(t, "node-001", values["node_id"])
	assert.Equal(t, "corr-123", values["correlation_id"])
	assert.NotEmpty(t, values["timestamp"])
	assert.NotEmpty(t, values["data"])
}

func TestFromStreamEntry(t *testing.T) {
	t.Run("valid entry", func(t *testing.T) {
		timestamp := time.Now()
		values := map[string]interface{}{
			"type":           "checkpoint.created",
			"mission_id":     "mission-123",
			"thread_id":      "thread-456",
			"checkpoint_id":  "checkpoint-789",
			"node_id":        "node-001",
			"timestamp":      timestamp.Format(time.RFC3339Nano),
			"correlation_id": "corr-123",
			"data":           `{"size_bytes":1024}`,
		}

		event, err := fromStreamEntry("1234567890-0", values)
		require.NoError(t, err)

		assert.Equal(t, "1234567890-0", event.ID)
		assert.Equal(t, EventCheckpointCreated, event.Type)
		assert.Equal(t, "mission-123", event.MissionID)
		assert.Equal(t, "thread-456", event.ThreadID)
		assert.Equal(t, "checkpoint-789", event.CheckpointID)
		assert.Equal(t, "node-001", event.NodeID)
		assert.Equal(t, "corr-123", event.CorrelationID)
		assert.NotNil(t, event.Data)
		assert.Equal(t, float64(1024), event.Data["size_bytes"])
	})

	t.Run("missing required field", func(t *testing.T) {
		values := map[string]interface{}{
			"type":      "checkpoint.created",
			"thread_id": "thread-456",
			// Missing mission_id
		}

		_, err := fromStreamEntry("1234567890-0", values)
		assert.Error(t, err)
	})

	t.Run("invalid timestamp", func(t *testing.T) {
		values := map[string]interface{}{
			"type":       "checkpoint.created",
			"mission_id": "mission-123",
			"thread_id":  "thread-456",
			"timestamp":  "invalid-timestamp",
		}

		_, err := fromStreamEntry("1234567890-0", values)
		assert.Error(t, err)
	})
}

func TestNewCheckpointCreatedEvent(t *testing.T) {
	event := NewCheckpointCreatedEvent("mission-123", "thread-456", "checkpoint-789", 2048)

	assert.Equal(t, EventCheckpointCreated, event.Type)
	assert.Equal(t, "mission-123", event.MissionID)
	assert.Equal(t, "thread-456", event.ThreadID)
	assert.Equal(t, "checkpoint-789", event.CheckpointID)
	assert.Equal(t, int64(2048), event.Data["size_bytes"])
	assert.NotEmpty(t, event.CorrelationID)
	assert.False(t, event.Timestamp.IsZero())
}

func TestNewCheckpointRestoredEvent(t *testing.T) {
	event := NewCheckpointRestoredEvent("mission-123", "thread-456", "checkpoint-789", 5)

	assert.Equal(t, EventCheckpointRestored, event.Type)
	assert.Equal(t, "mission-123", event.MissionID)
	assert.Equal(t, "thread-456", event.ThreadID)
	assert.Equal(t, "checkpoint-789", event.CheckpointID)
	assert.Equal(t, 5, event.Data["nodes_skipped"])
	assert.NotEmpty(t, event.CorrelationID)
}

func TestNewThreadBranchedEvent(t *testing.T) {
	event := NewThreadBranchedEvent("mission-123", "parent-thread", "new-thread", "checkpoint-789")

	assert.Equal(t, EventThreadBranched, event.Type)
	assert.Equal(t, "mission-123", event.MissionID)
	assert.Equal(t, "new-thread", event.ThreadID)
	assert.Equal(t, "checkpoint-789", event.CheckpointID)
	assert.Equal(t, "parent-thread", event.Data["parent_thread_id"])
	assert.Equal(t, "new-thread", event.Data["new_thread_id"])
	assert.NotEmpty(t, event.CorrelationID)
}

func TestNewThreadCompletedEvent(t *testing.T) {
	result := &ThreadResult{
		Status:         ThreadStatusCompleted,
		FindingsCount:  10,
		NodesCompleted: 25,
		NodesFailed:    2,
		Duration:       5 * time.Minute,
		TokensUsed:     50000,
		Cost:           2.50,
		Score:          95.5,
	}

	event := NewThreadCompletedEvent("mission-123", "thread-456", result)

	assert.Equal(t, EventThreadCompleted, event.Type)
	assert.Equal(t, "mission-123", event.MissionID)
	assert.Equal(t, "thread-456", event.ThreadID)
	assert.Equal(t, "completed", event.Data["status"])
	assert.Equal(t, 10, event.Data["findings_count"])
	assert.Equal(t, 25, event.Data["nodes_completed"])
	assert.Equal(t, 2, event.Data["nodes_failed"])
	assert.Equal(t, int64(50000), event.Data["tokens_used"])
	assert.Equal(t, 2.50, event.Data["cost"])
	assert.Equal(t, 95.5, event.Data["score"])
}

func TestNewApprovalReceivedEvent(t *testing.T) {
	tests := []struct {
		name         string
		status       ApprovalStatus
		expectedType LifecycleEventType
	}{
		{
			name:         "approved",
			status:       ApprovalStatusApproved,
			expectedType: EventApprovalApproved,
		},
		{
			name:         "rejected",
			status:       ApprovalStatusRejected,
			expectedType: EventApprovalRejected,
		},
		{
			name:         "modified",
			status:       ApprovalStatusModified,
			expectedType: EventApprovalModified,
		},
		{
			name:         "timed out",
			status:       ApprovalStatusTimedOut,
			expectedType: EventApprovalTimeout,
		},
		{
			name:         "cancelled",
			status:       ApprovalStatusCancelled,
			expectedType: EventApprovalCancelled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := NewApprovalReceivedEvent("mission-123", "thread-456", "checkpoint-789", tt.status)

			assert.Equal(t, tt.expectedType, event.Type)
			assert.Equal(t, "mission-123", event.MissionID)
			assert.Equal(t, "thread-456", event.ThreadID)
			assert.Equal(t, "checkpoint-789", event.CheckpointID)
			assert.Equal(t, tt.status.String(), event.Data["status"])
		})
	}
}

func TestNewReplayStartedEvent(t *testing.T) {
	event := NewReplayStartedEvent("mission-123", "thread-456", "checkpoint-789", "target-node")

	assert.Equal(t, EventReplayStarted, event.Type)
	assert.Equal(t, "mission-123", event.MissionID)
	assert.Equal(t, "thread-456", event.ThreadID)
	assert.Equal(t, "checkpoint-789", event.CheckpointID)
	assert.Equal(t, "target-node", event.Data["target_node_id"])
}

func TestNewReplayCompletedEvent(t *testing.T) {
	event := NewReplayCompletedEvent("mission-123", "thread-456", "checkpoint-789", 15, 3000)

	assert.Equal(t, EventReplayCompleted, event.Type)
	assert.Equal(t, "mission-123", event.MissionID)
	assert.Equal(t, "thread-456", event.ThreadID)
	assert.Equal(t, "checkpoint-789", event.CheckpointID)
	assert.Equal(t, 15, event.Data["nodes_replayed"])
	assert.Equal(t, int64(3000), event.Data["duration_ms"])
}

func TestCheckpointLifecycleEvent_WithCorrelationID(t *testing.T) {
	event := NewCheckpointCreatedEvent("mission-123", "thread-456", "checkpoint-789", 1024)
	event = event.WithCorrelationID("custom-correlation-id")

	assert.Equal(t, "custom-correlation-id", event.CorrelationID)
}

func TestCheckpointLifecycleEvent_WithData(t *testing.T) {
	event := NewCheckpointCreatedEvent("mission-123", "thread-456", "checkpoint-789", 1024)
	event = event.WithData("custom_key", "custom_value")

	assert.Equal(t, "custom_value", event.Data["custom_key"])
	assert.Equal(t, int64(1024), event.Data["size_bytes"]) // Original data preserved
}

func TestRedisEventEmitter_streamKey(t *testing.T) {
	emitter := NewRedisEventEmitter(nil)

	key := emitter.streamKey("mission-123")
	assert.Equal(t, "gibson:stream:checkpoint:mission-123", key)
}

func TestRedisEventEmitter_globalStreamKey(t *testing.T) {
	emitter := NewRedisEventEmitter(nil)

	key := emitter.globalStreamKey()
	assert.Equal(t, "gibson:stream:checkpoint:all", key)
}

func TestRedisEventEmitter_Emit_ValidationErrors(t *testing.T) {
	emitter := NewRedisEventEmitter(nil)
	ctx := context.Background()

	t.Run("nil event", func(t *testing.T) {
		err := emitter.Emit(ctx, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "event cannot be nil")
	})

	t.Run("empty mission ID", func(t *testing.T) {
		event := &CheckpointLifecycleEvent{
			Type:      EventCheckpointCreated,
			MissionID: "",
			ThreadID:  "thread-123",
		}
		err := emitter.Emit(ctx, event)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "mission_id cannot be empty")
	})
}

func TestRedisEventEmitter_Close(t *testing.T) {
	emitter := NewRedisEventEmitter(nil)
	err := emitter.Close()
	assert.NoError(t, err)
}

// TestEventRoundTrip tests converting an event to stream entry and back
func TestEventRoundTrip(t *testing.T) {
	originalEvent := &CheckpointLifecycleEvent{
		Type:         EventCheckpointCreated,
		MissionID:    "mission-123",
		ThreadID:     "thread-456",
		CheckpointID: "checkpoint-789",
		NodeID:       "node-001",
		Timestamp:    time.Now().UTC().Truncate(time.Millisecond), // Truncate for comparison
		Data: map[string]any{
			"size_bytes": int64(1024),
			"test_bool":  true,
			"test_str":   "hello",
		},
		CorrelationID: "corr-123",
	}

	// Convert to stream entry
	values := originalEvent.toStreamEntry()

	// Convert back from stream entry
	restoredEvent, err := fromStreamEntry("test-id", values)
	require.NoError(t, err)

	// Verify fields match (except ID which comes from Redis)
	assert.Equal(t, "test-id", restoredEvent.ID)
	assert.Equal(t, originalEvent.Type, restoredEvent.Type)
	assert.Equal(t, originalEvent.MissionID, restoredEvent.MissionID)
	assert.Equal(t, originalEvent.ThreadID, restoredEvent.ThreadID)
	assert.Equal(t, originalEvent.CheckpointID, restoredEvent.CheckpointID)
	assert.Equal(t, originalEvent.NodeID, restoredEvent.NodeID)
	assert.Equal(t, originalEvent.CorrelationID, restoredEvent.CorrelationID)

	// Timestamp should be close (within a second due to serialization)
	assert.WithinDuration(t, originalEvent.Timestamp, restoredEvent.Timestamp, time.Second)

	// Data should match (note: numbers become float64 after JSON round-trip)
	assert.NotNil(t, restoredEvent.Data)
	assert.Equal(t, float64(1024), restoredEvent.Data["size_bytes"])
	assert.Equal(t, true, restoredEvent.Data["test_bool"])
	assert.Equal(t, "hello", restoredEvent.Data["test_str"])
}

// Example test showing how events would be used in practice
func TestEventUsageExample(t *testing.T) {
	// Create a checkpoint created event
	missionID := types.NewID()
	threadID := "thread-" + types.NewID().String()
	checkpointID := "checkpoint-" + types.NewID().String()

	event := NewCheckpointCreatedEvent(
		missionID.String(),
		threadID,
		checkpointID,
		2048,
	)

	// Add custom metadata
	event = event.WithData("node_id", "node-123")
	event = event.WithData("agent", "recon-agent")

	// Verify event structure
	assert.Equal(t, EventCheckpointCreated, event.Type)
	assert.Equal(t, missionID.String(), event.MissionID)
	assert.Equal(t, threadID, event.ThreadID)
	assert.Equal(t, checkpointID, event.CheckpointID)
	assert.NotEmpty(t, event.CorrelationID)
	assert.False(t, event.Timestamp.IsZero())
	assert.Equal(t, int64(2048), event.Data["size_bytes"])
	assert.Equal(t, "node-123", event.Data["node_id"])
	assert.Equal(t, "recon-agent", event.Data["agent"])
}
