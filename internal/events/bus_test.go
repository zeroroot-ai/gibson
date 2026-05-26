package events

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// TestEventBus_BasicPublishSubscribe tests basic publish and subscribe functionality.
func TestEventBus_BasicPublishSubscribe(t *testing.T) {
	bus := NewEventBus()
	defer bus.Close()

	ctx := context.Background()

	// Subscribe to all events
	events, cleanup := bus.Subscribe(ctx, Filter{}, 10)
	defer cleanup()

	// Publish an event
	event := Event{
		Type:      EventMissionStarted,
		Timestamp: time.Now(),
		MissionID: types.NewID(),
		AgentName: "test-agent",
	}

	err := bus.Publish(ctx, event)
	if err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	// Receive the event
	select {
	case received := <-events:
		if received.Type != event.Type {
			t.Errorf("Expected event type %v, got %v", event.Type, received.Type)
		}
		if received.MissionID != event.MissionID {
			t.Errorf("Expected mission ID %v, got %v", event.MissionID, received.MissionID)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for event")
	}
}

// TestEventBus_FilterByEventType tests filtering by event type.
func TestEventBus_FilterByEventType(t *testing.T) {
	bus := NewEventBus()
	defer bus.Close()

	ctx := context.Background()

	// Subscribe only to mission started events
	events, cleanup := bus.Subscribe(ctx, Filter{
		Types: []EventType{EventMissionStarted},
	}, 10)
	defer cleanup()

	// Publish a mission started event (should be received)
	event1 := Event{
		Type:      EventMissionStarted,
		Timestamp: time.Now(),
		MissionID: types.NewID(),
	}
	bus.Publish(ctx, event1)

	// Publish a mission completed event (should NOT be received)
	event2 := Event{
		Type:      EventMissionCompleted,
		Timestamp: time.Now(),
		MissionID: types.NewID(),
	}
	bus.Publish(ctx, event2)

	// Should receive only the first event
	select {
	case received := <-events:
		if received.Type != EventMissionStarted {
			t.Errorf("Expected mission.started, got %v", received.Type)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Timeout waiting for mission.started event")
	}

	// Should NOT receive the second event
	select {
	case received := <-events:
		t.Errorf("Received unexpected event: %v", received.Type)
	case <-time.After(100 * time.Millisecond):
		// Expected timeout
	}
}

// TestEventBus_FilterByMissionID tests filtering by mission ID.
func TestEventBus_FilterByMissionID(t *testing.T) {
	bus := NewEventBus()
	defer bus.Close()

	ctx := context.Background()
	missionID := types.NewID()

	// Subscribe only to events for a specific mission
	events, cleanup := bus.Subscribe(ctx, Filter{
		MissionID: missionID,
	}, 10)
	defer cleanup()

	// Publish event for the target mission (should be received)
	event1 := Event{
		Type:      EventMissionStarted,
		Timestamp: time.Now(),
		MissionID: missionID,
	}
	bus.Publish(ctx, event1)

	// Publish event for a different mission (should NOT be received)
	event2 := Event{
		Type:      EventMissionStarted,
		Timestamp: time.Now(),
		MissionID: types.NewID(),
	}
	bus.Publish(ctx, event2)

	// Should receive only the first event
	select {
	case received := <-events:
		if received.MissionID != missionID {
			t.Errorf("Expected mission ID %v, got %v", missionID, received.MissionID)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Timeout waiting for event")
	}

	// Should NOT receive the second event
	select {
	case received := <-events:
		t.Errorf("Received unexpected event for mission: %v", received.MissionID)
	case <-time.After(100 * time.Millisecond):
		// Expected timeout
	}
}

// TestEventBus_FilterByAgentName tests filtering by agent name.
func TestEventBus_FilterByAgentName(t *testing.T) {
	bus := NewEventBus()
	defer bus.Close()

	ctx := context.Background()

	// Subscribe only to events for a specific agent
	events, cleanup := bus.Subscribe(ctx, Filter{
		AgentName: "test-agent",
	}, 10)
	defer cleanup()

	// Publish event for the target agent (should be received)
	event1 := Event{
		Type:      EventAgentStarted,
		Timestamp: time.Now(),
		AgentName: "test-agent",
	}
	bus.Publish(ctx, event1)

	// Publish event for a different agent (should NOT be received)
	event2 := Event{
		Type:      EventAgentStarted,
		Timestamp: time.Now(),
		AgentName: "other-agent",
	}
	bus.Publish(ctx, event2)

	// Should receive only the first event
	select {
	case received := <-events:
		if received.AgentName != "test-agent" {
			t.Errorf("Expected agent name 'test-agent', got %v", received.AgentName)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Timeout waiting for event")
	}

	// Should NOT receive the second event
	select {
	case received := <-events:
		t.Errorf("Received unexpected event for agent: %v", received.AgentName)
	case <-time.After(100 * time.Millisecond):
		// Expected timeout
	}
}

// TestEventBus_MultipleSubscribers tests multiple concurrent subscribers.
func TestEventBus_MultipleSubscribers(t *testing.T) {
	bus := NewEventBus()
	defer bus.Close()

	ctx := context.Background()
	numSubscribers := 10

	var wg sync.WaitGroup
	wg.Add(numSubscribers)

	// Create multiple subscribers
	for i := 0; i < numSubscribers; i++ {
		go func(id int) {
			defer wg.Done()

			events, cleanup := bus.Subscribe(ctx, Filter{}, 10)
			defer cleanup()

			// Wait for an event
			select {
			case event := <-events:
				if event.Type != EventMissionStarted {
					t.Errorf("Subscriber %d: unexpected event type: %v", id, event.Type)
				}
			case <-time.After(1 * time.Second):
				t.Errorf("Subscriber %d: timeout waiting for event", id)
			}
		}(i)
	}

	// Give subscribers time to start
	time.Sleep(50 * time.Millisecond)

	// Publish an event
	event := Event{
		Type:      EventMissionStarted,
		Timestamp: time.Now(),
		MissionID: types.NewID(),
	}
	err := bus.Publish(ctx, event)
	if err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	// Wait for all subscribers to receive the event
	wg.Wait()
}

// TestEventBus_SlowConsumer tests that slow consumers don't block publishers.
func TestEventBus_SlowConsumer(t *testing.T) {
	var droppedCount int64
	errorHandler := func(err error, context map[string]interface{}) {
		atomic.AddInt64(&droppedCount, 1)
	}

	bus := NewEventBus(
		WithDefaultBufferSize(5),
		WithErrorHandler(errorHandler),
	)
	defer bus.Close()

	ctx := context.Background()

	// Create a slow subscriber that doesn't consume events
	events, cleanup := bus.Subscribe(ctx, Filter{}, 5)
	defer cleanup()

	// Publish more events than the buffer can hold
	for i := 0; i < 10; i++ {
		event := Event{
			Type:      EventMissionStarted,
			Timestamp: time.Now(),
			MissionID: types.NewID(),
		}
		err := bus.Publish(ctx, event)
		if err != nil {
			t.Fatalf("Publish failed: %v", err)
		}
	}

	// Verify that some events were dropped
	if atomic.LoadInt64(&droppedCount) == 0 {
		t.Error("Expected some events to be dropped for slow consumer")
	}

	// Verify we can still receive events from the buffer
	received := 0
	for {
		select {
		case <-events:
			received++
		case <-time.After(100 * time.Millisecond):
			goto done
		}
	}
done:

	if received == 0 {
		t.Error("Expected to receive at least some events")
	}

	t.Logf("Received %d events, dropped %d events", received, atomic.LoadInt64(&droppedCount))
}

// TestEventBus_ConcurrentPublish tests concurrent publishing from multiple goroutines.
func TestEventBus_ConcurrentPublish(t *testing.T) {
	bus := NewEventBus(WithDefaultBufferSize(1000))
	defer bus.Close()

	ctx := context.Background()

	// Create a subscriber to receive all events
	events, cleanup := bus.Subscribe(ctx, Filter{}, 1000)
	defer cleanup()

	numPublishers := 10
	eventsPerPublisher := 100
	expectedTotal := numPublishers * eventsPerPublisher

	var wg sync.WaitGroup
	wg.Add(numPublishers)

	// Start multiple publishers
	for i := 0; i < numPublishers; i++ {
		go func(id int) {
			defer wg.Done()

			for j := 0; j < eventsPerPublisher; j++ {
				event := Event{
					Type:      EventMissionStarted,
					Timestamp: time.Now(),
					MissionID: types.NewID(),
				}
				err := bus.Publish(ctx, event)
				if err != nil {
					t.Errorf("Publisher %d: publish failed: %v", id, err)
				}
			}
		}(i)
	}

	// Wait for all publishers to finish
	wg.Wait()

	// Count received events
	received := 0
	timeout := time.After(2 * time.Second)
	for received < expectedTotal {
		select {
		case <-events:
			received++
		case <-timeout:
			t.Fatalf("Timeout: received %d/%d events", received, expectedTotal)
		}
	}

	if received != expectedTotal {
		t.Errorf("Expected %d events, received %d", expectedTotal, received)
	}
}

// TestEventBus_ContextCancellation tests subscription context cancellation.
func TestEventBus_ContextCancellation(t *testing.T) {
	bus := NewEventBus()
	defer bus.Close()

	ctx, cancel := context.WithCancel(context.Background())

	events, cleanup := bus.Subscribe(ctx, Filter{}, 10)
	defer cleanup()

	// Publish an event (should be received)
	event1 := Event{
		Type:      EventMissionStarted,
		Timestamp: time.Now(),
		MissionID: types.NewID(),
	}
	bus.Publish(context.Background(), event1)

	select {
	case <-events:
		// Expected
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Timeout waiting for event")
	}

	// Cancel the subscription context
	cancel()

	// Give the event bus time to process cancellation
	time.Sleep(50 * time.Millisecond)

	// Publish another event (should NOT be received by cancelled subscription)
	event2 := Event{
		Type:      EventMissionCompleted,
		Timestamp: time.Now(),
		MissionID: types.NewID(),
	}
	bus.Publish(context.Background(), event2)

	// Verify the event is not received (context is cancelled)
	// Note: The channel is still open until cleanup() is called
	select {
	case <-events:
		t.Error("Received event after context cancellation")
	case <-time.After(100 * time.Millisecond):
		// Expected timeout
	}
}

// TestEventBus_Close tests that closing the bus prevents further publishes.
func TestEventBus_Close(t *testing.T) {
	bus := NewEventBus()

	ctx := context.Background()

	events, cleanup := bus.Subscribe(ctx, Filter{}, 10)
	defer cleanup()

	// Publish before close (should succeed)
	event := Event{
		Type:      EventMissionStarted,
		Timestamp: time.Now(),
		MissionID: types.NewID(),
	}
	err := bus.Publish(ctx, event)
	if err != nil {
		t.Fatalf("Publish before close failed: %v", err)
	}

	// Close the bus
	err = bus.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Publish after close (should fail)
	err = bus.Publish(ctx, event)
	if err == nil {
		t.Error("Expected error when publishing to closed bus")
	}

	// Verify subscriber channel is closed
	// First drain any pending events
	for {
		select {
		case _, ok := <-events:
			if !ok {
				// Channel is closed, as expected
				return
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("Timeout waiting for channel close")
			return
		}
	}
}

// TestEventBus_SubscriberCount tests the SubscriberCount method.
func TestEventBus_SubscriberCount(t *testing.T) {
	bus := NewEventBus()
	defer bus.Close()

	ctx := context.Background()

	if bus.SubscriberCount() != 0 {
		t.Errorf("Expected 0 subscribers, got %d", bus.SubscriberCount())
	}

	// Add subscribers
	_, cleanup1 := bus.Subscribe(ctx, Filter{}, 10)
	defer cleanup1()

	if bus.SubscriberCount() != 1 {
		t.Errorf("Expected 1 subscriber, got %d", bus.SubscriberCount())
	}

	_, cleanup2 := bus.Subscribe(ctx, Filter{}, 10)
	defer cleanup2()

	if bus.SubscriberCount() != 2 {
		t.Errorf("Expected 2 subscribers, got %d", bus.SubscriberCount())
	}

	// Remove one subscriber
	cleanup1()

	if bus.SubscriberCount() != 1 {
		t.Errorf("Expected 1 subscriber after cleanup, got %d", bus.SubscriberCount())
	}
}

// TestEventBus_WithOptions tests functional options.
func TestEventBus_WithOptions(t *testing.T) {
	var errorCalled bool
	errorHandler := func(err error, context map[string]interface{}) {
		errorCalled = true
	}

	bus := NewEventBus(
		WithDefaultBufferSize(50),
		WithErrorHandler(errorHandler),
	)
	defer bus.Close()

	if bus.options.defaultBufferSize != 50 {
		t.Errorf("Expected buffer size 50, got %d", bus.options.defaultBufferSize)
	}

	// Trigger error handler by creating slow consumer
	ctx := context.Background()
	events, cleanup := bus.Subscribe(ctx, Filter{}, 2)
	defer cleanup()

	// Fill the buffer and cause drops
	for i := 0; i < 10; i++ {
		event := Event{
			Type:      EventMissionStarted,
			Timestamp: time.Now(),
			MissionID: types.NewID(),
		}
		bus.Publish(ctx, event)
	}

	if !errorCalled {
		t.Error("Expected error handler to be called")
	}

	// Drain events
	for len(events) > 0 {
		<-events
	}
}

// BenchmarkEventBus_Publish benchmarks event publishing.
func BenchmarkEventBus_Publish(b *testing.B) {
	bus := NewEventBus(WithDefaultBufferSize(1000))
	defer bus.Close()

	ctx := context.Background()
	events, cleanup := bus.Subscribe(ctx, Filter{}, 10000)
	defer cleanup()

	// Consume events in background
	go func() {
		for range events {
		}
	}()

	event := Event{
		Type:      EventMissionStarted,
		Timestamp: time.Now(),
		MissionID: types.NewID(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bus.Publish(ctx, event)
	}
}

// BenchmarkEventBus_PublishWithFiltering benchmarks filtered subscriptions.
func BenchmarkEventBus_PublishWithFiltering(b *testing.B) {
	bus := NewEventBus(WithDefaultBufferSize(1000))
	defer bus.Close()

	ctx := context.Background()
	missionID := types.NewID()

	// Subscribe with filter
	events, cleanup := bus.Subscribe(ctx, Filter{
		Types:     []EventType{EventMissionStarted},
		MissionID: missionID,
	}, 10000)
	defer cleanup()

	// Consume events in background
	go func() {
		for range events {
		}
	}()

	event := Event{
		Type:      EventMissionStarted,
		Timestamp: time.Now(),
		MissionID: missionID,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bus.Publish(ctx, event)
	}
}

// BenchmarkEventBus_MultipleSubscribers benchmarks with multiple subscribers.
func BenchmarkEventBus_MultipleSubscribers(b *testing.B) {
	bus := NewEventBus(WithDefaultBufferSize(1000))
	defer bus.Close()

	ctx := context.Background()
	numSubscribers := 10

	// Create multiple subscribers
	cleanups := make([]func(), numSubscribers)
	for i := 0; i < numSubscribers; i++ {
		events, cleanup := bus.Subscribe(ctx, Filter{}, 10000)
		cleanups[i] = cleanup

		// Consume events in background
		go func(ch <-chan Event) {
			for range ch {
			}
		}(events)
	}
	defer func() {
		for _, cleanup := range cleanups {
			cleanup()
		}
	}()

	event := Event{
		Type:      EventMissionStarted,
		Timestamp: time.Now(),
		MissionID: types.NewID(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bus.Publish(ctx, event)
	}
}
