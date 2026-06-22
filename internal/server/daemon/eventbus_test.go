package daemon

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

func TestEventBus_PublishAndSubscribe(t *testing.T) {
	logger := slog.Default()
	bus := NewEventBus(logger)
	defer bus.Close()

	ctx := context.Background()

	// Subscribe to all events
	eventChan, cleanup := bus.Subscribe(ctx, []string{}, "")
	defer cleanup()

	// Publish an event
	event := NewMissionStartedEvent("test-mission-1")
	err := bus.Publish(ctx, event)
	require.NoError(t, err)

	// Receive the event
	select {
	case received := <-eventChan:
		assert.Equal(t, "mission.started", received.EventType)
		assert.Equal(t, "test-mission-1", received.MissionEvent.MissionID)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for event")
	}
}

func TestEventBus_FilterByEventType(t *testing.T) {
	logger := slog.Default()
	bus := NewEventBus(logger)
	defer bus.Close()

	ctx := context.Background()

	// Subscribe only to mission.started events
	eventChan, cleanup := bus.Subscribe(ctx, []string{"mission.started"}, "")
	defer cleanup()

	// Publish a mission.started event
	event1 := NewMissionStartedEvent("mission-1")
	err := bus.Publish(ctx, event1)
	require.NoError(t, err)

	// Publish a mission.completed event (should be filtered out)
	event2 := NewMissionCompletedEvent("mission-1")
	err = bus.Publish(ctx, event2)
	require.NoError(t, err)

	// Should only receive the mission.started event
	select {
	case received := <-eventChan:
		assert.Equal(t, "mission.started", received.EventType)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for event")
	}

	// Should not receive the mission.completed event
	select {
	case <-eventChan:
		t.Fatal("received unexpected event")
	case <-time.After(100 * time.Millisecond):
		// Expected - no event should be received
	}
}

func TestEventBus_FilterByMissionID(t *testing.T) {
	logger := slog.Default()
	bus := NewEventBus(logger)
	defer bus.Close()

	ctx := context.Background()

	// Subscribe only to events for mission-1
	eventChan, cleanup := bus.Subscribe(ctx, []string{}, "mission-1")
	defer cleanup()

	// Publish event for mission-1
	event1 := NewMissionStartedEvent("mission-1")
	err := bus.Publish(ctx, event1)
	require.NoError(t, err)

	// Publish event for mission-2 (should be filtered out)
	event2 := NewMissionStartedEvent("mission-2")
	err = bus.Publish(ctx, event2)
	require.NoError(t, err)

	// Should only receive the mission-1 event
	select {
	case received := <-eventChan:
		assert.Equal(t, "mission-1", received.MissionEvent.MissionID)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for event")
	}

	// Should not receive the mission-2 event
	select {
	case <-eventChan:
		t.Fatal("received unexpected event")
	case <-time.After(100 * time.Millisecond):
		// Expected - no event should be received
	}
}

func TestEventBus_MultipleSubscribers(t *testing.T) {
	logger := slog.Default()
	bus := NewEventBus(logger)
	defer bus.Close()

	ctx := context.Background()

	// Create multiple subscribers
	sub1Chan, cleanup1 := bus.Subscribe(ctx, []string{}, "")
	defer cleanup1()

	sub2Chan, cleanup2 := bus.Subscribe(ctx, []string{}, "")
	defer cleanup2()

	sub3Chan, cleanup3 := bus.Subscribe(ctx, []string{}, "")
	defer cleanup3()

	// Publish an event
	event := NewMissionStartedEvent("test-mission")
	err := bus.Publish(ctx, event)
	require.NoError(t, err)

	// All subscribers should receive the event
	for i, ch := range []<-chan api.EventData{sub1Chan, sub2Chan, sub3Chan} {
		select {
		case received := <-ch:
			assert.Equal(t, "mission.started", received.EventType, "subscriber %d", i+1)
			assert.Equal(t, "test-mission", received.MissionEvent.MissionID, "subscriber %d", i+1)
		case <-time.After(1 * time.Second):
			t.Fatalf("timeout waiting for event on subscriber %d", i+1)
		}
	}
}

func TestEventBus_CleanupOnContextCancel(t *testing.T) {
	logger := slog.Default()
	bus := NewEventBus(logger)
	defer bus.Close()

	ctx, cancel := context.WithCancel(context.Background())

	// Subscribe
	eventChan, cleanup := bus.Subscribe(ctx, []string{}, "")
	defer cleanup()

	// Verify subscription was created
	assert.Equal(t, 1, bus.SubscriberCount())

	// Cancel context
	cancel()

	// Call cleanup
	cleanup()

	// Verify subscription was removed
	assert.Equal(t, 0, bus.SubscriberCount())

	// Channel should be closed
	select {
	case _, ok := <-eventChan:
		assert.False(t, ok, "channel should be closed")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("channel was not closed")
	}
}

func TestEventBus_SlowConsumer(t *testing.T) {
	logger := slog.Default()
	// Create bus with small buffer
	bus := NewEventBus(logger, WithEventBufferSize(2))
	defer bus.Close()

	ctx := context.Background()

	// Subscribe but don't consume events
	eventChan, cleanup := bus.Subscribe(ctx, []string{}, "")
	defer cleanup()

	// Publish more events than the buffer can hold
	for i := 0; i < 10; i++ {
		event := NewMissionStartedEvent("mission-1")
		err := bus.Publish(ctx, event)
		require.NoError(t, err)
	}

	// Should have received at least the buffered events
	receivedCount := 0
	timeout := time.After(100 * time.Millisecond)
	for {
		select {
		case <-eventChan:
			receivedCount++
		case <-timeout:
			// Expected - some events were dropped
			assert.LessOrEqual(t, receivedCount, 10, "should not receive more events than published")
			assert.GreaterOrEqual(t, receivedCount, 2, "should receive at least buffered events")
			return
		}
	}
}

func TestEventBus_Close(t *testing.T) {
	logger := slog.Default()
	bus := NewEventBus(logger)

	ctx := context.Background()

	// Create multiple subscribers
	sub1Chan, cleanup1 := bus.Subscribe(ctx, []string{}, "")
	defer cleanup1()

	sub2Chan, cleanup2 := bus.Subscribe(ctx, []string{}, "")
	defer cleanup2()

	assert.Equal(t, 2, bus.SubscriberCount())

	// Close the bus
	err := bus.Close()
	require.NoError(t, err)

	// All subscriber channels should be closed
	for i, ch := range []<-chan api.EventData{sub1Chan, sub2Chan} {
		select {
		case _, ok := <-ch:
			assert.False(t, ok, "subscriber %d channel should be closed", i+1)
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("subscriber %d channel was not closed", i+1)
		}
	}

	// Subscriber count should be zero
	assert.Equal(t, 0, bus.SubscriberCount())

	// Publishing after close should return error
	event := NewMissionStartedEvent("test")
	err = bus.Publish(ctx, event)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "closed")

	// Closing again should be idempotent
	err = bus.Close()
	assert.NoError(t, err)
}

func TestEventBus_CombinedFilters(t *testing.T) {
	logger := slog.Default()
	bus := NewEventBus(logger)
	defer bus.Close()

	ctx := context.Background()

	// Subscribe only to mission.started events for mission-1
	eventChan, cleanup := bus.Subscribe(ctx, []string{"mission.started"}, "mission-1")
	defer cleanup()

	// Publish mission.started for mission-1 (should receive)
	event1 := NewMissionStartedEvent("mission-1")
	err := bus.Publish(ctx, event1)
	require.NoError(t, err)

	// Publish mission.completed for mission-1 (wrong event type)
	event2 := NewMissionCompletedEvent("mission-1")
	err = bus.Publish(ctx, event2)
	require.NoError(t, err)

	// Publish mission.started for mission-2 (wrong mission)
	event3 := NewMissionStartedEvent("mission-2")
	err = bus.Publish(ctx, event3)
	require.NoError(t, err)

	// Should only receive the first event
	select {
	case received := <-eventChan:
		assert.Equal(t, "mission.started", received.EventType)
		assert.Equal(t, "mission-1", received.MissionEvent.MissionID)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for event")
	}

	// Should not receive any other events
	select {
	case <-eventChan:
		t.Fatal("received unexpected event")
	case <-time.After(100 * time.Millisecond):
		// Expected - no more events
	}
}

func TestEventBus_HelperFunctions(t *testing.T) {
	// Test helper functions create proper event structures
	t.Run("NewMissionStartedEvent", func(t *testing.T) {
		event := NewMissionStartedEvent("mission-1")
		assert.Equal(t, "mission.started", event.EventType)
		assert.Equal(t, "daemon", event.Source)
		assert.NotNil(t, event.MissionEvent)
		assert.Equal(t, "mission-1", event.MissionEvent.MissionID)
	})

	t.Run("NewMissionCompletedEvent", func(t *testing.T) {
		event := NewMissionCompletedEvent("mission-2")
		assert.Equal(t, "mission.completed", event.EventType)
		assert.Equal(t, "daemon", event.Source)
		assert.NotNil(t, event.MissionEvent)
		assert.Equal(t, "mission-2", event.MissionEvent.MissionID)
	})

	t.Run("NewMissionFailedEvent", func(t *testing.T) {
		err := assert.AnError
		event := NewMissionFailedEvent("mission-3", err)
		assert.Equal(t, "mission.failed", event.EventType)
		assert.Equal(t, "daemon", event.Source)
		assert.NotNil(t, event.MissionEvent)
		assert.Equal(t, "mission-3", event.MissionEvent.MissionID)
		assert.Contains(t, event.MissionEvent.Error, err.Error())
	})

	t.Run("NewNodeStartedEvent", func(t *testing.T) {
		event := NewNodeStartedEvent("mission-4", "node-1")
		assert.Equal(t, "node.started", event.EventType)
		assert.Equal(t, "daemon", event.Source)
		assert.NotNil(t, event.MissionEvent)
		assert.Equal(t, "mission-4", event.MissionEvent.MissionID)
		assert.Equal(t, "node-1", event.MissionEvent.NodeID)
	})

	t.Run("NewNodeCompletedEvent", func(t *testing.T) {
		event := NewNodeCompletedEvent("mission-5", "node-2")
		assert.Equal(t, "node.completed", event.EventType)
		assert.Equal(t, "daemon", event.Source)
		assert.NotNil(t, event.MissionEvent)
		assert.Equal(t, "mission-5", event.MissionEvent.MissionID)
		assert.Equal(t, "node-2", event.MissionEvent.NodeID)
	})

	t.Run("NewFindingDiscoveredEvent", func(t *testing.T) {
		finding := api.FindingData{
			ID:       "finding-1",
			Title:    "Test Finding",
			Severity: "high",
		}
		event := NewFindingDiscoveredEvent("mission-6", finding)
		assert.Equal(t, "finding.discovered", event.EventType)
		assert.Equal(t, "daemon", event.Source)
		assert.NotNil(t, event.FindingEvent)
		assert.Equal(t, "mission-6", event.FindingEvent.MissionID)
		assert.Equal(t, "finding-1", event.FindingEvent.Finding.ID)
		assert.Equal(t, "Test Finding", event.FindingEvent.Finding.Title)
	})

	t.Run("NewAgentRegisteredEvent", func(t *testing.T) {
		event := NewAgentRegisteredEvent("agent-1", "test-agent")
		assert.Equal(t, "agent.registered", event.EventType)
		assert.Equal(t, "daemon", event.Source)
		assert.NotNil(t, event.AgentEvent)
		assert.Equal(t, "agent-1", event.AgentEvent.AgentID)
		assert.Equal(t, "test-agent", event.AgentEvent.AgentName)
	})

	t.Run("NewAgentUnregisteredEvent", func(t *testing.T) {
		event := NewAgentUnregisteredEvent("agent-2", "another-agent")
		assert.Equal(t, "agent.unregistered", event.EventType)
		assert.Equal(t, "daemon", event.Source)
		assert.NotNil(t, event.AgentEvent)
		assert.Equal(t, "agent-2", event.AgentEvent.AgentID)
		assert.Equal(t, "another-agent", event.AgentEvent.AgentName)
	})
}

func TestEventBus_ConcurrentPublish(t *testing.T) {
	logger := slog.Default()
	bus := NewEventBus(logger)
	defer bus.Close()

	ctx := context.Background()

	// Subscribe
	eventChan, cleanup := bus.Subscribe(ctx, []string{}, "")
	defer cleanup()

	// Publish concurrently from multiple goroutines
	const numGoroutines = 10
	const eventsPerGoroutine = 10

	done := make(chan bool, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < eventsPerGoroutine; j++ {
				event := NewMissionStartedEvent("mission-1")
				_ = bus.Publish(ctx, event)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to finish
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Count received events
	receivedCount := 0
	timeout := time.After(500 * time.Millisecond)
	for {
		select {
		case <-eventChan:
			receivedCount++
		case <-timeout:
			// Should have received most events (some might be dropped due to buffer)
			assert.GreaterOrEqual(t, receivedCount, 1, "should receive at least some events")
			return
		}
	}
}
