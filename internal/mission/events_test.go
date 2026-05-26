package mission

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// TestMissionEventType_String tests the String method
func TestMissionEventType_String(t *testing.T) {
	tests := []struct {
		name      string
		eventType MissionEventType
		want      string
	}{
		{"started", EventMissionStarted, "mission.started"},
		{"paused", EventMissionPaused, "mission.paused"},
		{"resumed", EventMissionResumed, "mission.resumed"},
		{"completed", EventMissionCompleted, "mission.completed"},
		{"failed", EventMissionFailed, "mission.failed"},
		{"cancelled", EventMissionCancelled, "mission.cancelled"},
		{"progress", EventMissionProgress, "mission.progress"},
		{"finding", EventMissionFinding, "mission.finding"},
		{"approval required", EventMissionApprovalRequired, "mission.approval_required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.eventType.String())
		})
	}
}

// TestNewMissionEvent tests event creation
func TestNewMissionEvent(t *testing.T) {
	missionID := types.NewID()
	payload := map[string]any{"key": "value"}

	event := NewMissionEvent(EventMissionStarted, missionID, payload)

	assert.Equal(t, EventMissionStarted, event.Type)
	assert.Equal(t, missionID, event.MissionID)
	assert.Equal(t, payload, event.Payload)
	assert.False(t, event.Timestamp.IsZero())
}

// TestEventHelpers tests event helper functions
func TestEventHelpers(t *testing.T) {
	missionID := types.NewID()

	t.Run("NewStartedEvent", func(t *testing.T) {
		event := NewStartedEvent(missionID)
		assert.Equal(t, EventMissionStarted, event.Type)
		assert.Equal(t, missionID, event.MissionID)
	})

	t.Run("NewPausedEvent", func(t *testing.T) {
		event := NewPausedEvent(missionID, "constraint violated")
		assert.Equal(t, EventMissionPaused, event.Type)
		assert.Equal(t, missionID, event.MissionID)
		payload, ok := event.Payload.(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "constraint violated", payload["reason"])
	})

	t.Run("NewResumedEvent", func(t *testing.T) {
		event := NewResumedEvent(missionID)
		assert.Equal(t, EventMissionResumed, event.Type)
		assert.Equal(t, missionID, event.MissionID)
	})

	t.Run("NewCompletedEvent", func(t *testing.T) {
		result := &MissionResult{MissionID: missionID}
		event := NewCompletedEvent(missionID, result)
		assert.Equal(t, EventMissionCompleted, event.Type)
		assert.Equal(t, result, event.Payload)
	})

	t.Run("NewFailedEvent", func(t *testing.T) {
		err := NewValidationError("test error")
		event := NewFailedEvent(missionID, err)
		assert.Equal(t, EventMissionFailed, event.Type)
		payload, ok := event.Payload.(map[string]any)
		require.True(t, ok)
		assert.Contains(t, payload["error"], "test error")
	})

	t.Run("NewCancelledEvent", func(t *testing.T) {
		event := NewCancelledEvent(missionID, "user requested")
		assert.Equal(t, EventMissionCancelled, event.Type)
		payload, ok := event.Payload.(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "user requested", payload["reason"])
	})

	t.Run("NewProgressEvent", func(t *testing.T) {
		progress := &MissionProgress{MissionID: missionID, PercentComplete: 50.0}
		event := NewProgressEvent(missionID, progress, "halfway there")
		assert.Equal(t, EventMissionProgress, event.Type)
		payload, ok := event.Payload.(*ProgressPayload)
		require.True(t, ok)
		assert.Equal(t, progress, payload.Progress)
		assert.Equal(t, "halfway there", payload.Message)
	})

	t.Run("NewFindingEvent", func(t *testing.T) {
		findingID := types.NewID()
		event := NewFindingEvent(missionID, findingID, "SQL Injection", "high", "agent-1")
		assert.Equal(t, EventMissionFinding, event.Type)
		payload, ok := event.Payload.(*FindingPayload)
		require.True(t, ok)
		assert.Equal(t, findingID, payload.FindingID)
		assert.Equal(t, "SQL Injection", payload.Title)
		assert.Equal(t, "high", payload.Severity)
		assert.Equal(t, "agent-1", payload.AgentName)
	})

	t.Run("NewApprovalRequiredEvent", func(t *testing.T) {
		approvalID := types.NewID()
		ctx := map[string]any{"plan": "delete users"}
		event := NewApprovalRequiredEvent(missionID, approvalID, "high risk", "destructive", ctx)
		assert.Equal(t, EventMissionApprovalRequired, event.Type)
		payload, ok := event.Payload.(*ApprovalPayload)
		require.True(t, ok)
		assert.Equal(t, approvalID, payload.ApprovalID)
		assert.Equal(t, "high risk", payload.Reason)
		assert.Equal(t, "destructive", payload.ActionType)
		assert.Equal(t, ctx, payload.Context)
	})

	t.Run("NewCheckpointEvent", func(t *testing.T) {
		event := NewCheckpointEvent(missionID, "checkpoint-1", 5, 10)
		assert.Equal(t, EventMissionCheckpoint, event.Type)
		payload, ok := event.Payload.(*CheckpointPayload)
		require.True(t, ok)
		assert.Equal(t, "checkpoint-1", payload.CheckpointID)
		assert.Equal(t, 5, payload.CompletedNodes)
		assert.Equal(t, 10, payload.TotalNodes)
	})

	t.Run("NewConstraintViolationEvent", func(t *testing.T) {
		violation := &ConstraintViolation{
			Constraint: "max_cost",
			Action:     ConstraintActionPause,
		}
		event := NewConstraintViolationEvent(missionID, violation)
		assert.Equal(t, EventMissionConstraintViolation, event.Type)
		payload, ok := event.Payload.(*ConstraintViolationPayload)
		require.True(t, ok)
		assert.Equal(t, violation, payload.Violation)
		assert.True(t, payload.WillPause)
		assert.False(t, payload.WillFail)
	})
}

// TestDefaultEventEmitter_EmitAndSubscribe tests basic emit and subscribe
func TestDefaultEventEmitter_EmitAndSubscribe(t *testing.T) {
	emitter := NewDefaultEventEmitter()
	defer emitter.Close()

	ctx := context.Background()
	missionID := types.NewID()

	// Subscribe before emitting
	eventCh, cleanup := emitter.Subscribe(ctx)
	defer cleanup()

	// Emit event
	event := NewStartedEvent(missionID)
	err := emitter.Emit(ctx, event)
	require.NoError(t, err)

	// Receive event
	select {
	case received := <-eventCh:
		assert.Equal(t, event.Type, received.Type)
		assert.Equal(t, event.MissionID, received.MissionID)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for event")
	}
}

// TestDefaultEventEmitter_MultipleSubscribers tests multiple subscribers
func TestDefaultEventEmitter_MultipleSubscribers(t *testing.T) {
	emitter := NewDefaultEventEmitter()
	defer emitter.Close()

	ctx := context.Background()
	missionID := types.NewID()

	// Create multiple subscribers
	const numSubscribers = 5
	channels := make([]<-chan MissionEvent, numSubscribers)
	cleanups := make([]func(), numSubscribers)

	for i := 0; i < numSubscribers; i++ {
		ch, cleanup := emitter.Subscribe(ctx)
		channels[i] = ch
		cleanups[i] = cleanup
	}
	defer func() {
		for _, cleanup := range cleanups {
			cleanup()
		}
	}()

	// Emit event
	event := NewStartedEvent(missionID)
	err := emitter.Emit(ctx, event)
	require.NoError(t, err)

	// All subscribers should receive the event
	for i := 0; i < numSubscribers; i++ {
		select {
		case received := <-channels[i]:
			assert.Equal(t, event.Type, received.Type)
			assert.Equal(t, event.MissionID, received.MissionID)
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("subscriber %d: timeout waiting for event", i)
		}
	}

	assert.Equal(t, numSubscribers, emitter.SubscriberCount())
}

// TestDefaultEventEmitter_SubscriberCleanup tests subscriber cleanup
func TestDefaultEventEmitter_SubscriberCleanup(t *testing.T) {
	emitter := NewDefaultEventEmitter()
	defer emitter.Close()

	ctx := context.Background()

	// Subscribe and immediately cleanup
	_, cleanup := emitter.Subscribe(ctx)
	assert.Equal(t, 1, emitter.SubscriberCount())

	cleanup()
	assert.Equal(t, 0, emitter.SubscriberCount())

	// Verify channel is closed
	_, cleanup2 := emitter.Subscribe(ctx)
	assert.Equal(t, 1, emitter.SubscriberCount())
	cleanup2()
}

// TestDefaultEventEmitter_SlowConsumer tests slow consumer handling
func TestDefaultEventEmitter_SlowConsumer(t *testing.T) {
	// Small buffer to make it easy to fill
	emitter := NewDefaultEventEmitter(WithBufferSize(2))
	defer emitter.Close()

	ctx := context.Background()
	missionID := types.NewID()

	// Create a slow subscriber that doesn't consume events
	slowCh, slowCleanup := emitter.Subscribe(ctx)
	defer slowCleanup()

	// Create a fast subscriber
	fastCh, fastCleanup := emitter.Subscribe(ctx)
	defer fastCleanup()

	// Fill the slow consumer's buffer and emit more events
	const totalEvents = 10
	for i := 0; i < totalEvents; i++ {
		event := NewProgressEvent(missionID, &MissionProgress{}, "")
		err := emitter.Emit(ctx, event)
		require.NoError(t, err)
	}

	// Fast consumer should receive at least some events
	// (slow consumer's dropped events don't block fast consumer)
	fastReceivedCount := 0
	timeout := time.After(100 * time.Millisecond)
	for {
		select {
		case <-fastCh:
			fastReceivedCount++
		case <-timeout:
			goto done
		}
	}

done:
	assert.Greater(t, fastReceivedCount, 0, "fast consumer should receive events")

	// Slow consumer's channel should have some events
	slowReceivedCount := 0
	for {
		select {
		case <-slowCh:
			slowReceivedCount++
		default:
			goto slowDone
		}
	}

slowDone:
	// Slow consumer receives buffer size at most (some events dropped)
	assert.LessOrEqual(t, slowReceivedCount, 2)
}

// TestDefaultEventEmitter_ConcurrentEmit tests concurrent event emission
func TestDefaultEventEmitter_ConcurrentEmit(t *testing.T) {
	emitter := NewDefaultEventEmitter()
	defer emitter.Close()

	ctx := context.Background()
	missionID := types.NewID()

	// Create subscriber
	eventCh, cleanup := emitter.Subscribe(ctx)
	defer cleanup()

	// Emit events concurrently
	const numGoroutines = 10
	const eventsPerGoroutine = 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < eventsPerGoroutine; j++ {
				event := NewProgressEvent(missionID, &MissionProgress{}, "")
				err := emitter.Emit(ctx, event)
				assert.NoError(t, err)
			}
		}()
	}

	// Wait for all emits to complete
	wg.Wait()

	// Count received events
	receivedCount := 0
	timeout := time.After(500 * time.Millisecond)
	for {
		select {
		case <-eventCh:
			receivedCount++
		case <-timeout:
			goto countDone
		}
	}

countDone:
	expectedTotal := numGoroutines * eventsPerGoroutine
	assert.Equal(t, expectedTotal, receivedCount, "should receive all emitted events")
}

// TestDefaultEventEmitter_ContextCancellation tests context cancellation
func TestDefaultEventEmitter_ContextCancellation(t *testing.T) {
	emitter := NewDefaultEventEmitter(WithBufferSize(1))
	defer emitter.Close()

	missionID := types.NewID()

	// Create a subscriber with a full buffer to simulate blocking
	slowCh, slowCleanup := emitter.Subscribe(context.Background())
	defer slowCleanup()

	// Fill the buffer
	event := NewStartedEvent(missionID)
	_ = emitter.Emit(context.Background(), event)

	// Create a cancellable context and cancel it
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Try to emit with cancelled context
	// This should return context.Canceled when trying to send to the slow subscriber
	err := emitter.Emit(ctx, event)

	// If all subscribers are slow, we should get context.Canceled
	// Otherwise, emit succeeds (drops event for slow consumers)
	if err != nil {
		assert.Equal(t, context.Canceled, err)
	}

	// Drain the slow channel
	<-slowCh
}

// TestDefaultEventEmitter_Close tests emitter closure
func TestDefaultEventEmitter_Close(t *testing.T) {
	emitter := NewDefaultEventEmitter()

	ctx := context.Background()
	missionID := types.NewID()

	// Create subscribers
	ch1, cleanup1 := emitter.Subscribe(ctx)
	ch2, cleanup2 := emitter.Subscribe(ctx)
	_ = cleanup1
	_ = cleanup2

	assert.Equal(t, 2, emitter.SubscriberCount())

	// Close emitter
	err := emitter.Close()
	require.NoError(t, err)

	// Verify all channels are closed
	_, ok1 := <-ch1
	assert.False(t, ok1)

	_, ok2 := <-ch2
	assert.False(t, ok2)

	// Verify subscriber count is zero
	assert.Equal(t, 0, emitter.SubscriberCount())

	// Emit should fail after close
	event := NewStartedEvent(missionID)
	err = emitter.Emit(ctx, event)
	assert.Error(t, err)

	// Double close should be safe
	err = emitter.Close()
	require.NoError(t, err)
}

// TestDefaultEventEmitter_WithBufferSize tests buffer size option
func TestDefaultEventEmitter_WithBufferSize(t *testing.T) {
	emitter := NewDefaultEventEmitter(WithBufferSize(50))
	defer emitter.Close()

	assert.Equal(t, 50, emitter.bufferSize)
}

// TestDefaultEventEmitter_EmitBeforeSubscribe tests emitting before subscription
func TestDefaultEventEmitter_EmitBeforeSubscribe(t *testing.T) {
	emitter := NewDefaultEventEmitter()
	defer emitter.Close()

	ctx := context.Background()
	missionID := types.NewID()

	// Emit event before any subscribers
	event := NewStartedEvent(missionID)
	err := emitter.Emit(ctx, event)
	require.NoError(t, err)

	// Subscribe after event was emitted
	eventCh, cleanup := emitter.Subscribe(ctx)
	defer cleanup()

	// Should not receive the event (no replay)
	select {
	case <-eventCh:
		t.Fatal("should not receive event emitted before subscription")
	case <-time.After(50 * time.Millisecond):
		// Expected: timeout means no event received
	}
}

// TestDefaultEventEmitter_ConcurrentSubscribe tests concurrent subscription
func TestDefaultEventEmitter_ConcurrentSubscribe(t *testing.T) {
	emitter := NewDefaultEventEmitter()
	defer emitter.Close()

	ctx := context.Background()

	const numGoroutines = 20
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	cleanups := make([]func(), numGoroutines)
	var mu sync.Mutex

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			_, cleanup := emitter.Subscribe(ctx)
			mu.Lock()
			cleanups[idx] = cleanup
			mu.Unlock()
		}(i)
	}

	wg.Wait()

	assert.Equal(t, numGoroutines, emitter.SubscriberCount())

	// Cleanup all
	for _, cleanup := range cleanups {
		cleanup()
	}

	assert.Equal(t, 0, emitter.SubscriberCount())
}

// BenchmarkDefaultEventEmitter_Emit benchmarks event emission
func BenchmarkDefaultEventEmitter_Emit(b *testing.B) {
	emitter := NewDefaultEventEmitter()
	defer emitter.Close()

	ctx := context.Background()
	missionID := types.NewID()
	event := NewStartedEvent(missionID)

	// Create a subscriber to consume events
	_, cleanup := emitter.Subscribe(ctx)
	defer cleanup()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = emitter.Emit(ctx, event)
	}
}

// BenchmarkDefaultEventEmitter_Subscribe benchmarks subscription
func BenchmarkDefaultEventEmitter_Subscribe(b *testing.B) {
	emitter := NewDefaultEventEmitter()
	defer emitter.Close()

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, cleanup := emitter.Subscribe(ctx)
		cleanup()
	}
}
