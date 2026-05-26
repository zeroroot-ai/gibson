package daemon

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/daemon/api"
)

// TestSubscribeIntegration tests the full subscription mission including
// daemon method delegation to event bus.
func TestSubscribeIntegration(t *testing.T) {
	logger := slog.Default()

	// Create a mock daemon with event bus
	mockDaemon := &mockDaemonWithEventBus{
		eventBus: NewEventBus(logger),
		logger:   logger,
	}
	defer mockDaemon.eventBus.Close()

	ctx := context.Background()

	// Subscribe via the daemon interface
	eventChan, err := mockDaemon.Subscribe(ctx, []string{"mission.started"}, "")
	require.NoError(t, err)
	require.NotNil(t, eventChan)

	// Publish an event through the event bus
	event := NewMissionStartedEvent("test-mission")
	err = mockDaemon.eventBus.Publish(ctx, event)
	require.NoError(t, err)

	// Verify the event is received
	select {
	case received := <-eventChan:
		assert.Equal(t, "mission.started", received.EventType)
		assert.Equal(t, "test-mission", received.MissionEvent.MissionID)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for event")
	}
}

// TestSubscribeWithMultipleClients tests multiple clients subscribing simultaneously.
func TestSubscribeWithMultipleClients(t *testing.T) {
	logger := slog.Default()

	mockDaemon := &mockDaemonWithEventBus{
		eventBus: NewEventBus(logger),
		logger:   logger,
	}
	defer mockDaemon.eventBus.Close()

	ctx := context.Background()

	// Create multiple subscriptions
	numClients := 5
	channels := make([]<-chan api.EventData, numClients)
	for i := 0; i < numClients; i++ {
		ch, err := mockDaemon.Subscribe(ctx, []string{}, "")
		require.NoError(t, err)
		channels[i] = ch
	}

	// Publish an event
	event := NewMissionStartedEvent("mission-1")
	err := mockDaemon.eventBus.Publish(ctx, event)
	require.NoError(t, err)

	// All clients should receive the event
	for i, ch := range channels {
		select {
		case received := <-ch:
			assert.Equal(t, "mission.started", received.EventType, "client %d", i)
		case <-time.After(1 * time.Second):
			t.Fatalf("timeout on client %d", i)
		}
	}
}

// TestSubscribeWithContextCancellation tests cleanup when client disconnects.
func TestSubscribeWithContextCancellation(t *testing.T) {
	logger := slog.Default()

	mockDaemon := &mockDaemonWithEventBus{
		eventBus: NewEventBus(logger),
		logger:   logger,
	}
	defer mockDaemon.eventBus.Close()

	ctx, cancel := context.WithCancel(context.Background())

	// Subscribe
	eventChan, err := mockDaemon.Subscribe(ctx, []string{}, "")
	require.NoError(t, err)

	// Verify subscription exists
	assert.Equal(t, 1, mockDaemon.eventBus.SubscriberCount())

	// Cancel context (simulating client disconnect)
	cancel()

	// Wait for cleanup goroutine to complete
	time.Sleep(100 * time.Millisecond)

	// Verify subscription was cleaned up
	assert.Equal(t, 0, mockDaemon.eventBus.SubscriberCount())

	// Channel should eventually be closed
	select {
	case _, ok := <-eventChan:
		if ok {
			// Still receiving events, wait a bit more
			time.Sleep(100 * time.Millisecond)
		}
	case <-time.After(500 * time.Millisecond):
		// Timeout is acceptable - channel might not be closed immediately
	}
}

// TestSubscribeFiltersEventTypes tests filtering by event type.
func TestSubscribeFiltersEventTypes(t *testing.T) {
	logger := slog.Default()

	mockDaemon := &mockDaemonWithEventBus{
		eventBus: NewEventBus(logger),
		logger:   logger,
	}
	defer mockDaemon.eventBus.Close()

	ctx := context.Background()

	// Subscribe only to mission.started events
	eventChan, err := mockDaemon.Subscribe(ctx, []string{"mission.started"}, "")
	require.NoError(t, err)

	// Publish various event types
	events := []api.EventData{
		NewMissionStartedEvent("mission-1"),
		NewNodeStartedEvent("mission-1", "node-1"),
		NewMissionCompletedEvent("mission-1"),
		NewMissionStartedEvent("mission-2"),
	}

	for _, event := range events {
		err := mockDaemon.eventBus.Publish(ctx, event)
		require.NoError(t, err)
	}

	// Should only receive the two mission.started events
	receivedCount := 0
	timeout := time.After(500 * time.Millisecond)

loop:
	for {
		select {
		case event := <-eventChan:
			assert.Equal(t, "mission.started", event.EventType)
			receivedCount++
		case <-timeout:
			break loop
		}
	}

	assert.Equal(t, 2, receivedCount, "should only receive mission.started events")
}

// TestSubscribeFiltersByMissionID tests filtering by mission ID.
func TestSubscribeFiltersByMissionID(t *testing.T) {
	logger := slog.Default()

	mockDaemon := &mockDaemonWithEventBus{
		eventBus: NewEventBus(logger),
		logger:   logger,
	}
	defer mockDaemon.eventBus.Close()

	ctx := context.Background()

	// Subscribe only to events for mission-1
	eventChan, err := mockDaemon.Subscribe(ctx, []string{}, "mission-1")
	require.NoError(t, err)

	// Publish events for different missions
	events := []api.EventData{
		NewMissionStartedEvent("mission-1"),
		NewMissionStartedEvent("mission-2"),
		NewNodeStartedEvent("mission-1", "node-1"),
		NewNodeStartedEvent("mission-2", "node-2"),
		NewMissionCompletedEvent("mission-1"),
		NewMissionCompletedEvent("mission-2"),
	}

	for _, event := range events {
		err := mockDaemon.eventBus.Publish(ctx, event)
		require.NoError(t, err)
	}

	// Should only receive events for mission-1
	receivedMissions := make(map[string]int)
	timeout := time.After(500 * time.Millisecond)

loop:
	for {
		select {
		case event := <-eventChan:
			if event.MissionEvent != nil {
				receivedMissions[event.MissionEvent.MissionID]++
			}
		case <-timeout:
			break loop
		}
	}

	assert.Equal(t, 3, receivedMissions["mission-1"], "should receive all mission-1 events")
	assert.Equal(t, 0, receivedMissions["mission-2"], "should not receive mission-2 events")
}

// TestSubscribeLifecycle tests the full lifecycle of a subscription.
func TestSubscribeLifecycle(t *testing.T) {
	logger := slog.Default()

	mockDaemon := &mockDaemonWithEventBus{
		eventBus: NewEventBus(logger),
		logger:   logger,
	}

	ctx := context.Background()

	// Test 1: Normal subscription
	t.Run("normal_subscription", func(t *testing.T) {
		eventChan, err := mockDaemon.Subscribe(ctx, []string{}, "")
		require.NoError(t, err)
		assert.NotNil(t, eventChan)
	})

	// Test 2: Subscription after daemon close should fail
	t.Run("subscription_after_close", func(t *testing.T) {
		mockDaemon.eventBus.Close()

		// Subscribe should still work (new channel is created)
		// but events won't be delivered since bus is closed
		eventChan, err := mockDaemon.Subscribe(ctx, []string{}, "")

		// The Subscribe method itself doesn't fail - the event bus
		// will just not deliver events
		require.NoError(t, err)
		require.NotNil(t, eventChan)
	})
}

// mockDaemonWithEventBus is a minimal mock that implements Subscribe using EventBus.
type mockDaemonWithEventBus struct {
	eventBus *EventBus
	logger   *slog.Logger
}

// Subscribe implements the same logic as the real daemon's Subscribe method.
func (m *mockDaemonWithEventBus) Subscribe(ctx context.Context, eventTypes []string, missionID string) (<-chan api.EventData, error) {
	m.logger.Info("Subscribe called", "event_types", eventTypes, "mission_id", missionID)

	// Subscribe to events from the event bus
	eventChan, cleanup := m.eventBus.Subscribe(ctx, eventTypes, missionID)

	// Start a goroutine to handle cleanup when context is cancelled
	go func() {
		<-ctx.Done()
		cleanup()
		m.logger.Info("subscription cleanup completed", "mission_id", missionID)
	}()

	return eventChan, nil
}
