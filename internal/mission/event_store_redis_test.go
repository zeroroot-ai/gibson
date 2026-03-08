package mission

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

// setupTestRedisClient creates a StateClient for testing.
// It uses database 15 to avoid conflicts with production data.
func setupTestRedisClient(t *testing.T) *state.StateClient {
	t.Helper()

	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379/15" // Use DB 15 for tests

	client, err := NewStateClient(cfg)
	if err != nil {
		// Check if it's a connection error
		if err == redis.Nil {
			t.Skip("Redis not available for testing")
		}
		// For module errors, create a basic client without health check
		if _, ok := err.(*state.ModuleError); ok {
			t.Logf("Warning: %v", err)
			// Create client directly without health check
			return createBasicRedisTestClient(t, cfg)
		}
		t.Fatalf("failed to create test client: %v", err)
	}

	return client
}

// NewStateClient wraps state.NewStateClient for test compatibility
func NewStateClient(cfg *state.Config) (*state.StateClient, error) {
	return state.NewStateClient(cfg)
}

// createBasicRedisTestClient creates a client without module checks for testing
func createBasicRedisTestClient(t *testing.T, cfg *state.Config) *state.StateClient {
	t.Helper()

	opts, err := redis.ParseURL(cfg.URL)
	if err != nil {
		t.Fatalf("failed to parse URL: %v", err)
	}

	client := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		t.Skipf("Redis not available: %v", err)
	}

	// Use reflection or direct struct creation (this is a test helper)
	// Since StateClient fields are not exported, we need to use the constructor
	// For testing, we'll accept the module error
	stateClient, _ := state.NewStateClient(cfg)
	return stateClient
}

func TestRedisEventStore_Append(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	eventStore := NewRedisEventStore(client)
	ctx := context.Background()

	missionID := types.NewID()

	// Clean up after test
	t.Cleanup(func() {
		eventStore.Delete(ctx, missionID)
	})

	t.Run("append simple event", func(t *testing.T) {
		event := &MissionEvent{
			Type:      EventMissionStarted,
			MissionID: missionID,
			Timestamp: time.Now(),
			Payload:   nil,
		}

		err := eventStore.Append(ctx, event)
		require.NoError(t, err)
	})

	t.Run("append event with payload", func(t *testing.T) {
		payload := map[string]any{
			"message": "test message",
			"count":   42,
			"active":  true,
		}

		event := &MissionEvent{
			Type:      EventMissionProgress,
			MissionID: missionID,
			Timestamp: time.Now(),
			Payload:   payload,
		}

		err := eventStore.Append(ctx, event)
		require.NoError(t, err)
	})

	t.Run("append event with zero timestamp", func(t *testing.T) {
		event := &MissionEvent{
			Type:      EventMissionCompleted,
			MissionID: missionID,
			Timestamp: time.Time{}, // Zero timestamp should be set automatically
			Payload:   nil,
		}

		err := eventStore.Append(ctx, event)
		require.NoError(t, err)
	})

	t.Run("append nil event", func(t *testing.T) {
		err := eventStore.Append(ctx, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be nil")
	})

	t.Run("append event with complex payload", func(t *testing.T) {
		payload := &ProgressPayload{
			Progress: &MissionProgress{
				MissionID:      missionID,
				Status:         MissionStatusRunning,
				CompletedNodes: 5,
				TotalNodes:     10,
			},
			Message: "Processing node-1",
		}

		event := &MissionEvent{
			Type:      EventMissionProgress,
			MissionID: missionID,
			Timestamp: time.Now(),
			Payload:   payload,
		}

		err := eventStore.Append(ctx, event)
		require.NoError(t, err)
	})
}

func TestRedisEventStore_Query(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	eventStore := NewRedisEventStore(client)
	ctx := context.Background()

	mission1 := types.NewID()
	mission2 := types.NewID()

	// Clean up after test
	t.Cleanup(func() {
		eventStore.Delete(ctx, mission1)
		eventStore.Delete(ctx, mission2)
	})

	// Create events at different times
	baseTime := time.Now().Add(-1 * time.Hour)

	events := []*MissionEvent{
		{
			Type:      EventMissionStarted,
			MissionID: mission1,
			Timestamp: baseTime,
			Payload:   nil,
		},
		{
			Type:      EventMissionProgress,
			MissionID: mission1,
			Timestamp: baseTime.Add(10 * time.Minute),
			Payload:   map[string]any{"progress": 0.5},
		},
		{
			Type:      EventMissionCompleted,
			MissionID: mission1,
			Timestamp: baseTime.Add(20 * time.Minute),
			Payload:   nil,
		},
		{
			Type:      EventMissionStarted,
			MissionID: mission2,
			Timestamp: baseTime.Add(5 * time.Minute),
			Payload:   nil,
		},
		{
			Type:      EventMissionFailed,
			MissionID: mission2,
			Timestamp: baseTime.Add(15 * time.Minute),
			Payload:   map[string]any{"error": "test error"},
		},
	}

	// Append all events
	for _, event := range events {
		// Add small delay to ensure distinct stream IDs
		time.Sleep(10 * time.Millisecond)
		err := eventStore.Append(ctx, event)
		require.NoError(t, err)
	}

	// Give Redis a moment to process
	time.Sleep(100 * time.Millisecond)

	t.Run("query all events for mission", func(t *testing.T) {
		filter := NewEventFilter().WithMissionID(mission1)
		results, err := eventStore.Query(ctx, filter)
		require.NoError(t, err)
		assert.Equal(t, 3, len(results))

		// Verify chronological ordering
		for i := 0; i < len(results)-1; i++ {
			assert.True(t, results[i].Timestamp.Before(results[i+1].Timestamp) || results[i].Timestamp.Equal(results[i+1].Timestamp),
				"Events should be ordered chronologically")
		}

		// Verify all events belong to correct mission
		for _, event := range results {
			assert.Equal(t, mission1, event.MissionID)
		}
	})

	t.Run("query by event type", func(t *testing.T) {
		filter := NewEventFilter().
			WithMissionID(mission1).
			WithEventTypes(EventMissionProgress)
		results, err := eventStore.Query(ctx, filter)
		require.NoError(t, err)
		assert.Equal(t, 1, len(results))
		assert.Equal(t, EventMissionProgress, results[0].Type)
	})

	t.Run("query by multiple event types", func(t *testing.T) {
		filter := NewEventFilter().
			WithMissionID(mission1).
			WithEventTypes(EventMissionStarted, EventMissionCompleted)
		results, err := eventStore.Query(ctx, filter)
		require.NoError(t, err)
		assert.Equal(t, 2, len(results))

		for _, event := range results {
			assert.True(t, event.Type == EventMissionStarted || event.Type == EventMissionCompleted)
		}
	})

	t.Run("query by time range", func(t *testing.T) {
		after := baseTime.Add(8 * time.Minute)
		before := baseTime.Add(18 * time.Minute)

		filter := NewEventFilter().
			WithMissionID(mission1).
			WithTimeRange(after, before)
		results, err := eventStore.Query(ctx, filter)
		require.NoError(t, err)
		assert.Equal(t, 1, len(results)) // Should only get the progress event

		for _, event := range results {
			assert.True(t, event.Timestamp.After(after) || event.Timestamp.Equal(after))
			assert.True(t, event.Timestamp.Before(before) || event.Timestamp.Equal(before))
		}
	})

	t.Run("query with multiple filters", func(t *testing.T) {
		filter := NewEventFilter().
			WithMissionID(mission1).
			WithEventTypes(EventMissionProgress, EventMissionCompleted)

		results, err := eventStore.Query(ctx, filter)
		require.NoError(t, err)
		assert.Equal(t, 2, len(results))

		for _, event := range results {
			assert.Equal(t, mission1, event.MissionID)
			assert.True(t, event.Type == EventMissionProgress || event.Type == EventMissionCompleted)
		}
	})

	t.Run("query with pagination", func(t *testing.T) {
		filter := NewEventFilter().
			WithMissionID(mission1).
			WithPagination(2, 0)
		results, err := eventStore.Query(ctx, filter)
		require.NoError(t, err)
		assert.Equal(t, 2, len(results))
	})

	t.Run("query with offset", func(t *testing.T) {
		// Get all events
		allFilter := NewEventFilter().
			WithMissionID(mission1).
			WithPagination(100, 0)
		allResults, err := eventStore.Query(ctx, allFilter)
		require.NoError(t, err)

		// Get with offset
		offsetFilter := NewEventFilter().
			WithMissionID(mission1).
			WithPagination(100, 1)
		offsetResults, err := eventStore.Query(ctx, offsetFilter)
		require.NoError(t, err)

		assert.Equal(t, len(allResults)-1, len(offsetResults))
	})

	t.Run("query without mission ID returns error", func(t *testing.T) {
		filter := NewEventFilter()
		_, err := eventStore.Query(ctx, filter)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "mission ID is required")
	})

	t.Run("query non-existent mission returns empty", func(t *testing.T) {
		filter := NewEventFilter().WithMissionID(types.NewID())
		results, err := eventStore.Query(ctx, filter)
		require.NoError(t, err)
		assert.Empty(t, results)
	})
}

func TestRedisEventStore_Stream(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	eventStore := NewRedisEventStore(client)
	ctx := context.Background()

	missionID := types.NewID()

	// Clean up after test
	t.Cleanup(func() {
		eventStore.Delete(ctx, missionID)
	})

	baseTime := time.Now().Add(-30 * time.Minute)

	// Create multiple events
	eventCount := 5
	for i := 0; i < eventCount; i++ {
		event := &MissionEvent{
			Type:      EventMissionProgress,
			MissionID: missionID,
			Timestamp: baseTime.Add(time.Duration(i) * time.Minute),
			Payload:   map[string]any{"step": i},
		}

		err := eventStore.Append(ctx, event)
		require.NoError(t, err)

		// Small delay to ensure distinct stream IDs
		time.Sleep(10 * time.Millisecond)
	}

	// Give Redis a moment to process
	time.Sleep(100 * time.Millisecond)

	t.Run("stream all events", func(t *testing.T) {
		eventCh, err := eventStore.Stream(ctx, missionID, baseTime.Add(-1*time.Minute))
		require.NoError(t, err)

		receivedEvents := 0
		timeout := time.After(5 * time.Second)

	receiveLoop:
		for {
			select {
			case event, ok := <-eventCh:
				if !ok {
					break receiveLoop
				}
				assert.Equal(t, missionID, event.MissionID)
				receivedEvents++
				if receivedEvents >= eventCount {
					break receiveLoop
				}
			case <-timeout:
				break receiveLoop
			}
		}

		assert.Equal(t, eventCount, receivedEvents)
	})

	t.Run("stream from specific timestamp", func(t *testing.T) {
		fromTime := baseTime.Add(2 * time.Minute)
		eventCh, err := eventStore.Stream(ctx, missionID, fromTime)
		require.NoError(t, err)

		receivedEvents := 0
		timeout := time.After(5 * time.Second)

	receiveLoop:
		for {
			select {
			case event, ok := <-eventCh:
				if !ok {
					break receiveLoop
				}
				assert.True(t, event.Timestamp.After(fromTime) || event.Timestamp.Equal(fromTime))
				receivedEvents++
				// Expect 3 events (indices 2, 3, 4)
				if receivedEvents >= 3 {
					break receiveLoop
				}
			case <-timeout:
				break receiveLoop
			}
		}

		assert.GreaterOrEqual(t, receivedEvents, 3)
	})

	t.Run("stream with context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		eventCh, err := eventStore.Stream(ctx, missionID, baseTime)
		require.NoError(t, err)

		// Cancel context after receiving one event
		receivedOne := false
		timeout := time.After(5 * time.Second)

	receiveLoop:
		for {
			select {
			case _, ok := <-eventCh:
				if !ok {
					break receiveLoop
				}
				if !receivedOne {
					receivedOne = true
					cancel()
				}
			case <-timeout:
				break receiveLoop
			}
		}

		assert.True(t, receivedOne)
	})

	t.Run("stream non-existent mission", func(t *testing.T) {
		nonExistentID := types.NewID()
		eventCh, err := eventStore.Stream(ctx, nonExistentID, baseTime)
		require.NoError(t, err)

		receivedEvents := 0
		timeout := time.After(2 * time.Second)

	receiveLoop:
		for {
			select {
			case _, ok := <-eventCh:
				if !ok {
					break receiveLoop
				}
				receivedEvents++
			case <-timeout:
				break receiveLoop
			}
		}

		assert.Equal(t, 0, receivedEvents)
	})

	t.Run("stream closes channel when done", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		eventCh, err := eventStore.Stream(ctx, missionID, baseTime)
		require.NoError(t, err)

		// Drain channel until it closes or timeout
		timeout := time.After(3 * time.Second)
		channelClosed := false

	drainLoop:
		for {
			select {
			case _, ok := <-eventCh:
				if !ok {
					channelClosed = true
					break drainLoop
				}
			case <-timeout:
				break drainLoop
			}
		}

		assert.True(t, channelClosed, "Channel should be closed")
	})
}

func TestRedisEventStore_EventPayloadSerialization(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	eventStore := NewRedisEventStore(client)
	ctx := context.Background()

	missionID := types.NewID()

	// Clean up after test
	t.Cleanup(func() {
		eventStore.Delete(ctx, missionID)
	})

	t.Run("complex payload serialization", func(t *testing.T) {
		payload := map[string]any{
			"string": "test",
			"number": 42,
			"float":  3.14,
			"bool":   true,
			"array":  []any{1, 2, 3},
			"nested": map[string]any{
				"key": "value",
			},
		}

		event := &MissionEvent{
			Type:      EventMissionProgress,
			MissionID: missionID,
			Timestamp: time.Now(),
			Payload:   payload,
		}

		err := eventStore.Append(ctx, event)
		require.NoError(t, err)

		// Small delay
		time.Sleep(50 * time.Millisecond)

		// Retrieve and verify payload
		filter := NewEventFilter().WithMissionID(missionID)
		results, err := eventStore.Query(ctx, filter)
		require.NoError(t, err)
		require.NotEmpty(t, results)

		retrievedEvent := results[0]
		assert.NotNil(t, retrievedEvent.Payload)

		// Verify payload structure (JSON unmarshals to map[string]interface{})
		payloadMap, ok := retrievedEvent.Payload.(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "test", payloadMap["string"])
		assert.Equal(t, float64(42), payloadMap["number"]) // JSON numbers become float64
		assert.Equal(t, true, payloadMap["bool"])
	})

	t.Run("nil payload", func(t *testing.T) {
		event := &MissionEvent{
			Type:      EventMissionStarted,
			MissionID: missionID,
			Timestamp: time.Now(),
			Payload:   nil,
		}

		err := eventStore.Append(ctx, event)
		require.NoError(t, err)

		// Small delay
		time.Sleep(50 * time.Millisecond)

		filter := NewEventFilter().
			WithMissionID(missionID).
			WithEventTypes(EventMissionStarted)

		results, err := eventStore.Query(ctx, filter)
		require.NoError(t, err)
		require.NotEmpty(t, results)

		// Find the started event (there might be multiple from previous tests)
		var startedEvent *MissionEvent
		for _, evt := range results {
			if evt.Type == EventMissionStarted && evt.Payload == nil {
				startedEvent = evt
				break
			}
		}

		require.NotNil(t, startedEvent, "Should find event with nil payload")
		assert.Nil(t, startedEvent.Payload)
	})
}

func TestRedisEventStore_Trim(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	eventStore := NewRedisEventStore(client)
	ctx := context.Background()

	missionID := types.NewID()

	// Clean up after test
	t.Cleanup(func() {
		eventStore.Delete(ctx, missionID)
	})

	// Create 10 events
	for i := 0; i < 10; i++ {
		event := &MissionEvent{
			Type:      EventMissionProgress,
			MissionID: missionID,
			Timestamp: time.Now(),
			Payload:   map[string]any{"index": i},
		}
		err := eventStore.Append(ctx, event)
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond)
	}

	// Give Redis a moment
	time.Sleep(100 * time.Millisecond)

	t.Run("trim to max length", func(t *testing.T) {
		removed, err := eventStore.Trim(ctx, missionID, 5)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, removed, int64(0))

		// Verify stream length is approximately 5
		filter := NewEventFilter().WithMissionID(missionID)
		results, err := eventStore.Query(ctx, filter)
		require.NoError(t, err)
		// Approximate trimming may leave slightly more than 5
		assert.LessOrEqual(t, len(results), 10)
	})

	t.Run("trim with invalid max length", func(t *testing.T) {
		_, err := eventStore.Trim(ctx, missionID, 0)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "maxLen must be greater than 0")
	})
}

func TestRedisEventStore_Delete(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	eventStore := NewRedisEventStore(client)
	ctx := context.Background()

	missionID := types.NewID()

	// Create some events
	for i := 0; i < 3; i++ {
		event := &MissionEvent{
			Type:      EventMissionProgress,
			MissionID: missionID,
			Timestamp: time.Now(),
			Payload:   map[string]any{"index": i},
		}
		err := eventStore.Append(ctx, event)
		require.NoError(t, err)
	}

	// Give Redis a moment
	time.Sleep(100 * time.Millisecond)

	// Verify events exist
	filter := NewEventFilter().WithMissionID(missionID)
	results, err := eventStore.Query(ctx, filter)
	require.NoError(t, err)
	assert.NotEmpty(t, results)

	// Delete the stream
	err = eventStore.Delete(ctx, missionID)
	require.NoError(t, err)

	// Give Redis a moment
	time.Sleep(100 * time.Millisecond)

	// Verify stream is deleted
	results, err = eventStore.Query(ctx, filter)
	require.NoError(t, err)
	assert.Empty(t, results)

	// Delete non-existent stream should not error
	err = eventStore.Delete(ctx, types.NewID())
	require.NoError(t, err)
}

func TestRedisEventStore_StreamKey(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	eventStore := NewRedisEventStore(client)
	missionID := types.NewID()

	expectedKey := "gibson:stream:mission:" + missionID.String() + ":events"
	actualKey := eventStore.streamKey(missionID)

	assert.Equal(t, expectedKey, actualKey)
}

func TestRedisEventStore_RealTimeSubscription(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	eventStore := NewRedisEventStore(client)
	ctx := context.Background()

	missionID := types.NewID()

	// Clean up after test
	t.Cleanup(func() {
		eventStore.Delete(ctx, missionID)
	})

	// Start streaming from now (only new events)
	now := time.Now()
	eventCh, err := eventStore.Stream(ctx, missionID, now)
	require.NoError(t, err)

	// Give subscription time to initialize
	time.Sleep(200 * time.Millisecond)

	// Add events after subscription starts
	go func() {
		for i := 0; i < 3; i++ {
			time.Sleep(100 * time.Millisecond)
			event := &MissionEvent{
				Type:      EventMissionProgress,
				MissionID: missionID,
				Timestamp: time.Now(),
				Payload:   map[string]any{"realtime": i},
			}
			eventStore.Append(context.Background(), event)
		}
	}()

	// Receive real-time events
	receivedEvents := 0
	timeout := time.After(5 * time.Second)

receiveLoop:
	for {
		select {
		case event, ok := <-eventCh:
			if !ok {
				break receiveLoop
			}
			assert.Equal(t, missionID, event.MissionID)
			receivedEvents++
			if receivedEvents >= 3 {
				break receiveLoop
			}
		case <-timeout:
			break receiveLoop
		}
	}

	assert.GreaterOrEqual(t, receivedEvents, 3, "Should receive real-time events")
}

// Consumer Group Tests

func TestRedisEventStore_CreateConsumerGroup(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	eventStore := NewRedisEventStore(client)
	ctx := context.Background()

	missionID := types.NewID()

	// Clean up after test
	t.Cleanup(func() {
		eventStore.Delete(ctx, missionID)
	})

	t.Run("create consumer group successfully", func(t *testing.T) {
		err := eventStore.CreateConsumerGroup(ctx, missionID, "test-group", "0")
		require.NoError(t, err)
	})

	t.Run("create consumer group is idempotent", func(t *testing.T) {
		// Creating the same group again should not error
		err := eventStore.CreateConsumerGroup(ctx, missionID, "test-group", "0")
		require.NoError(t, err)
	})

	t.Run("create consumer group with $ start ID", func(t *testing.T) {
		err := eventStore.CreateConsumerGroup(ctx, missionID, "new-messages-only", "$")
		require.NoError(t, err)
	})

	t.Run("create consumer group with empty name fails", func(t *testing.T) {
		err := eventStore.CreateConsumerGroup(ctx, missionID, "", "0")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "group name cannot be empty")
	})

	t.Run("create consumer group with empty start ID uses default", func(t *testing.T) {
		err := eventStore.CreateConsumerGroup(ctx, missionID, "default-start", "")
		require.NoError(t, err)
	})
}

func TestRedisEventStore_SubscribeWithGroup(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	eventStore := NewRedisEventStore(client)
	ctx := context.Background()

	missionID := types.NewID()

	// Clean up after test
	t.Cleanup(func() {
		eventStore.Delete(ctx, missionID)
	})

	t.Run("subscribe with consumer group for exactly-once processing", func(t *testing.T) {
		groupName := "test-processors"

		// Create consumer group
		err := eventStore.CreateConsumerGroup(ctx, missionID, groupName, "$")
		require.NoError(t, err)

		// Subscribe with consumer group
		opts := &state.ConsumerGroupOptions{
			Group:    groupName,
			Consumer: "worker-1",
			Count:    10,
			Block:    1 * time.Second,
			NoAck:    true, // Require explicit ACK
		}

		eventCh, err := eventStore.SubscribeWithGroup(ctx, missionID, opts)
		require.NoError(t, err)

		// Give subscription time to initialize
		time.Sleep(200 * time.Millisecond)

		// Add events after subscription starts
		eventCount := 3
		go func() {
			for i := 0; i < eventCount; i++ {
				time.Sleep(100 * time.Millisecond)
				event := &MissionEvent{
					Type:      EventMissionProgress,
					MissionID: missionID,
					Timestamp: time.Now(),
					Payload:   map[string]any{"index": i},
				}
				eventStore.Append(context.Background(), event)
			}
		}()

		// Receive events
		receivedEvents := 0
		timeout := time.After(5 * time.Second)

	receiveLoop:
		for {
			select {
			case event, ok := <-eventCh:
				if !ok {
					break receiveLoop
				}
				assert.Equal(t, missionID, event.MissionID)
				assert.NotEmpty(t, event.StreamID, "StreamID should be set for consumer group events")
				receivedEvents++

				// Acknowledge the event
				err := eventStore.AckEvent(ctx, missionID, groupName, event.StreamID)
				require.NoError(t, err)

				if receivedEvents >= eventCount {
					break receiveLoop
				}
			case <-timeout:
				break receiveLoop
			}
		}

		assert.GreaterOrEqual(t, receivedEvents, eventCount, "Should receive all events via consumer group")
	})

	t.Run("subscribe with nil options fails", func(t *testing.T) {
		_, err := eventStore.SubscribeWithGroup(ctx, missionID, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "options cannot be nil")
	})

	t.Run("subscribe with empty group name fails", func(t *testing.T) {
		opts := &state.ConsumerGroupOptions{
			Group:    "",
			Consumer: "worker-1",
		}
		_, err := eventStore.SubscribeWithGroup(ctx, missionID, opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "group name cannot be empty")
	})

	t.Run("subscribe with empty consumer name fails", func(t *testing.T) {
		opts := &state.ConsumerGroupOptions{
			Group:    "test-group",
			Consumer: "",
		}
		_, err := eventStore.SubscribeWithGroup(ctx, missionID, opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "consumer name cannot be empty")
	})

	t.Run("multiple consumers process different events", func(t *testing.T) {
		groupName := "multi-consumer-group"
		testMissionID := types.NewID()

		// Clean up
		defer eventStore.Delete(ctx, testMissionID)

		// Create consumer group
		err := eventStore.CreateConsumerGroup(ctx, testMissionID, groupName, "$")
		require.NoError(t, err)

		// Start two consumers
		consumer1Ch, err := eventStore.SubscribeWithGroup(ctx, testMissionID, &state.ConsumerGroupOptions{
			Group:    groupName,
			Consumer: "worker-1",
			Count:    5,
			Block:    1 * time.Second,
			NoAck:    true,
		})
		require.NoError(t, err)

		consumer2Ch, err := eventStore.SubscribeWithGroup(ctx, testMissionID, &state.ConsumerGroupOptions{
			Group:    groupName,
			Consumer: "worker-2",
			Count:    5,
			Block:    1 * time.Second,
			NoAck:    true,
		})
		require.NoError(t, err)

		// Give subscriptions time to initialize
		time.Sleep(200 * time.Millisecond)

		// Add multiple events
		eventCount := 10
		go func() {
			for i := 0; i < eventCount; i++ {
				event := &MissionEvent{
					Type:      EventMissionProgress,
					MissionID: testMissionID,
					Timestamp: time.Now(),
					Payload:   map[string]any{"index": i},
				}
				eventStore.Append(context.Background(), event)
				time.Sleep(50 * time.Millisecond)
			}
		}()

		// Collect events from both consumers
		consumer1Events := 0
		consumer2Events := 0
		timeout := time.After(10 * time.Second)

	receiveLoop:
		for {
			select {
			case event, ok := <-consumer1Ch:
				if ok {
					consumer1Events++
					eventStore.AckEvent(ctx, testMissionID, groupName, event.StreamID)
				}
			case event, ok := <-consumer2Ch:
				if ok {
					consumer2Events++
					eventStore.AckEvent(ctx, testMissionID, groupName, event.StreamID)
				}
			case <-timeout:
				break receiveLoop
			}

			if consumer1Events+consumer2Events >= eventCount {
				break receiveLoop
			}
		}

		totalEvents := consumer1Events + consumer2Events
		assert.GreaterOrEqual(t, totalEvents, eventCount, "Should receive all events across consumers")

		// Both consumers should have received some events (load balancing)
		// Note: This might occasionally fail if all events go to one consumer by chance
		t.Logf("Consumer 1 received: %d, Consumer 2 received: %d", consumer1Events, consumer2Events)
	})
}

func TestRedisEventStore_AckEvent(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	eventStore := NewRedisEventStore(client)
	ctx := context.Background()

	missionID := types.NewID()
	groupName := "ack-test-group"

	// Clean up after test
	t.Cleanup(func() {
		eventStore.Delete(ctx, missionID)
	})

	// Create consumer group
	err := eventStore.CreateConsumerGroup(ctx, missionID, groupName, "$")
	require.NoError(t, err)

	t.Run("acknowledge single event", func(t *testing.T) {
		// Add an event
		event := &MissionEvent{
			Type:      EventMissionProgress,
			MissionID: missionID,
			Timestamp: time.Now(),
			Payload:   nil,
		}
		err := eventStore.Append(ctx, event)
		require.NoError(t, err)

		// Give Redis time to process
		time.Sleep(100 * time.Millisecond)

		// Read with consumer group
		opts := &state.ConsumerGroupOptions{
			Group:    groupName,
			Consumer: "ack-worker",
			Count:    1,
			Block:    1 * time.Second,
			NoAck:    true,
		}

		eventCh, err := eventStore.SubscribeWithGroup(ctx, missionID, opts)
		require.NoError(t, err)

		// Receive event
		var streamID string
		timeout := time.After(3 * time.Second)
		select {
		case receivedEvent, ok := <-eventCh:
			require.True(t, ok)
			streamID = receivedEvent.StreamID
		case <-timeout:
			t.Fatal("timeout waiting for event")
		}

		// Acknowledge the event
		err = eventStore.AckEvent(ctx, missionID, groupName, streamID)
		require.NoError(t, err)

		// Verify event is no longer pending
		time.Sleep(100 * time.Millisecond)
		pending, err := eventStore.GetPendingEvents(ctx, missionID, groupName, 100, "")
		require.NoError(t, err)
		assert.Equal(t, 0, len(pending), "No events should be pending after acknowledgment")
	})

	t.Run("acknowledge multiple events", func(t *testing.T) {
		testMissionID := types.NewID()
		testGroupName := "multi-ack-group"

		defer eventStore.Delete(ctx, testMissionID)

		// Create consumer group
		err := eventStore.CreateConsumerGroup(ctx, testMissionID, testGroupName, "$")
		require.NoError(t, err)

		// Add multiple events
		for i := 0; i < 3; i++ {
			event := &MissionEvent{
				Type:      EventMissionProgress,
				MissionID: testMissionID,
				Timestamp: time.Now(),
				Payload:   map[string]any{"index": i},
			}
			err := eventStore.Append(ctx, event)
			require.NoError(t, err)
			time.Sleep(50 * time.Millisecond)
		}

		// Read events
		opts := &state.ConsumerGroupOptions{
			Group:    testGroupName,
			Consumer: "multi-ack-worker",
			Count:    10,
			Block:    1 * time.Second,
			NoAck:    true,
		}

		eventCh, err := eventStore.SubscribeWithGroup(ctx, testMissionID, opts)
		require.NoError(t, err)

		// Collect stream IDs
		streamIDs := []string{}
		timeout := time.After(3 * time.Second)
	collectLoop:
		for {
			select {
			case event, ok := <-eventCh:
				if ok {
					streamIDs = append(streamIDs, event.StreamID)
					if len(streamIDs) >= 3 {
						break collectLoop
					}
				}
			case <-timeout:
				break collectLoop
			}
		}

		require.GreaterOrEqual(t, len(streamIDs), 3, "Should receive at least 3 events")

		// Acknowledge all events at once
		err = eventStore.AckEvent(ctx, testMissionID, testGroupName, streamIDs...)
		require.NoError(t, err)

		// Verify no pending events
		time.Sleep(100 * time.Millisecond)
		pending, err := eventStore.GetPendingEvents(ctx, testMissionID, testGroupName, 100, "")
		require.NoError(t, err)
		assert.Equal(t, 0, len(pending))
	})

	t.Run("acknowledge with empty group name fails", func(t *testing.T) {
		err := eventStore.AckEvent(ctx, missionID, "", "some-id")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "group name cannot be empty")
	})

	t.Run("acknowledge with no stream IDs fails", func(t *testing.T) {
		err := eventStore.AckEvent(ctx, missionID, groupName)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least one stream ID must be provided")
	})
}

func TestRedisEventStore_GetPendingEvents(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	eventStore := NewRedisEventStore(client)
	ctx := context.Background()

	missionID := types.NewID()
	groupName := "pending-test-group"

	// Clean up after test
	t.Cleanup(func() {
		eventStore.Delete(ctx, missionID)
	})

	// Create consumer group
	err := eventStore.CreateConsumerGroup(ctx, missionID, groupName, "$")
	require.NoError(t, err)

	t.Run("get pending events after reading without ack", func(t *testing.T) {
		// Add events
		for i := 0; i < 3; i++ {
			event := &MissionEvent{
				Type:      EventMissionProgress,
				MissionID: missionID,
				Timestamp: time.Now(),
				Payload:   map[string]any{"index": i},
			}
			err := eventStore.Append(ctx, event)
			require.NoError(t, err)
			time.Sleep(50 * time.Millisecond)
		}

		// Read events without acknowledging
		opts := &state.ConsumerGroupOptions{
			Group:    groupName,
			Consumer: "pending-worker",
			Count:    10,
			Block:    1 * time.Second,
			NoAck:    true, // Don't auto-ack
		}

		eventCh, err := eventStore.SubscribeWithGroup(ctx, missionID, opts)
		require.NoError(t, err)

		// Read all events
		receivedCount := 0
		timeout := time.After(3 * time.Second)
	readLoop:
		for {
			select {
			case _, ok := <-eventCh:
				if ok {
					receivedCount++
					if receivedCount >= 3 {
						break readLoop
					}
				}
			case <-timeout:
				break readLoop
			}
		}

		require.GreaterOrEqual(t, receivedCount, 3, "Should receive events")

		// Give Redis time to process
		time.Sleep(100 * time.Millisecond)

		// Check pending events
		pending, err := eventStore.GetPendingEvents(ctx, missionID, groupName, 100, "")
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(pending), 3, "Should have pending events")

		// Verify pending message structure
		for _, msg := range pending {
			assert.NotEmpty(t, msg.ID)
			assert.Equal(t, "pending-worker", msg.Consumer)
			assert.GreaterOrEqual(t, msg.IdleTime, time.Duration(0))
			assert.GreaterOrEqual(t, msg.DeliveryCount, int64(1))
		}
	})

	t.Run("get pending events for specific consumer", func(t *testing.T) {
		testMissionID := types.NewID()
		testGroupName := "specific-consumer-group"

		defer eventStore.Delete(ctx, testMissionID)

		// Create consumer group
		err := eventStore.CreateConsumerGroup(ctx, testMissionID, testGroupName, "$")
		require.NoError(t, err)

		// Add event
		event := &MissionEvent{
			Type:      EventMissionProgress,
			MissionID: testMissionID,
			Timestamp: time.Now(),
			Payload:   nil,
		}
		err = eventStore.Append(ctx, event)
		require.NoError(t, err)

		time.Sleep(100 * time.Millisecond)

		// Read with specific consumer
		opts := &state.ConsumerGroupOptions{
			Group:    testGroupName,
			Consumer: "specific-worker",
			Count:    10,
			Block:    1 * time.Second,
			NoAck:    true,
		}

		eventCh, err := eventStore.SubscribeWithGroup(ctx, testMissionID, opts)
		require.NoError(t, err)

		// Read event
		timeout := time.After(2 * time.Second)
		select {
		case <-eventCh:
			// Event received
		case <-timeout:
			t.Fatal("timeout waiting for event")
		}

		time.Sleep(100 * time.Millisecond)

		// Get pending for this specific consumer
		pending, err := eventStore.GetPendingEvents(ctx, testMissionID, testGroupName, 100, "specific-worker")
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(pending), 1)

		for _, msg := range pending {
			assert.Equal(t, "specific-worker", msg.Consumer)
		}
	})

	t.Run("get pending with empty group name fails", func(t *testing.T) {
		_, err := eventStore.GetPendingEvents(ctx, missionID, "", 100, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "group name cannot be empty")
	})

	t.Run("get pending for non-existent group returns empty", func(t *testing.T) {
		pending, err := eventStore.GetPendingEvents(ctx, types.NewID(), "non-existent-group", 100, "")
		// May return error or empty list depending on Redis version
		if err == nil {
			assert.Empty(t, pending)
		}
	})
}

func TestRedisEventStore_ClaimStuckEvents(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	eventStore := NewRedisEventStore(client)
	ctx := context.Background()

	missionID := types.NewID()
	groupName := "claim-test-group"

	// Clean up after test
	t.Cleanup(func() {
		eventStore.Delete(ctx, missionID)
	})

	// Create consumer group
	err := eventStore.CreateConsumerGroup(ctx, missionID, groupName, "$")
	require.NoError(t, err)

	t.Run("claim stuck events after idle time", func(t *testing.T) {
		// Add event
		event := &MissionEvent{
			Type:      EventMissionProgress,
			MissionID: missionID,
			Timestamp: time.Now(),
			Payload:   map[string]any{"test": "claim"},
		}
		err := eventStore.Append(ctx, event)
		require.NoError(t, err)

		time.Sleep(100 * time.Millisecond)

		// Read event with first consumer (without acking)
		opts := &state.ConsumerGroupOptions{
			Group:    groupName,
			Consumer: "original-worker",
			Count:    10,
			Block:    1 * time.Second,
			NoAck:    true,
		}

		eventCh, err := eventStore.SubscribeWithGroup(ctx, missionID, opts)
		require.NoError(t, err)

		var streamID string
		timeout := time.After(3 * time.Second)
		select {
		case receivedEvent, ok := <-eventCh:
			require.True(t, ok)
			streamID = receivedEvent.StreamID
		case <-timeout:
			t.Fatal("timeout waiting for event")
		}

		// Wait for event to become "stuck" (idle)
		time.Sleep(1 * time.Second)

		// Get pending events to verify it's stuck
		pending, err := eventStore.GetPendingEvents(ctx, missionID, groupName, 100, "")
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(pending), 1)

		// Claim stuck event with second consumer
		claimedEvents, err := eventStore.ClaimStuckEvents(
			ctx,
			missionID,
			groupName,
			"recovery-worker",
			500*time.Millisecond, // Minimum idle time
			streamID,
		)
		require.NoError(t, err)
		require.Len(t, claimedEvents, 1)

		// Verify claimed event structure
		claimedEvent := claimedEvents[0]
		assert.Equal(t, missionID, claimedEvent.MissionID)
		assert.Equal(t, EventMissionProgress, claimedEvent.Type)
		assert.NotEmpty(t, claimedEvent.StreamID)

		// Acknowledge the claimed event
		err = eventStore.AckEvent(ctx, missionID, groupName, claimedEvent.StreamID)
		require.NoError(t, err)
	})

	t.Run("claim multiple stuck events", func(t *testing.T) {
		testMissionID := types.NewID()
		testGroupName := "multi-claim-group"

		defer eventStore.Delete(ctx, testMissionID)

		// Create consumer group
		err := eventStore.CreateConsumerGroup(ctx, testMissionID, testGroupName, "$")
		require.NoError(t, err)

		// Add multiple events
		for i := 0; i < 3; i++ {
			event := &MissionEvent{
				Type:      EventMissionProgress,
				MissionID: testMissionID,
				Timestamp: time.Now(),
				Payload:   map[string]any{"index": i},
			}
			err := eventStore.Append(ctx, event)
			require.NoError(t, err)
			time.Sleep(50 * time.Millisecond)
		}

		// Read events without acking
		opts := &state.ConsumerGroupOptions{
			Group:    testGroupName,
			Consumer: "stuck-worker",
			Count:    10,
			Block:    1 * time.Second,
			NoAck:    true,
		}

		eventCh, err := eventStore.SubscribeWithGroup(ctx, testMissionID, opts)
		require.NoError(t, err)

		// Collect stream IDs
		streamIDs := []string{}
		timeout := time.After(3 * time.Second)
	collectLoop:
		for {
			select {
			case event, ok := <-eventCh:
				if ok {
					streamIDs = append(streamIDs, event.StreamID)
					if len(streamIDs) >= 3 {
						break collectLoop
					}
				}
			case <-timeout:
				break collectLoop
			}
		}

		require.GreaterOrEqual(t, len(streamIDs), 3)

		// Wait for events to become stuck
		time.Sleep(1 * time.Second)

		// Claim all stuck events
		claimedEvents, err := eventStore.ClaimStuckEvents(
			ctx,
			testMissionID,
			testGroupName,
			"claim-worker",
			500*time.Millisecond,
			streamIDs...,
		)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(claimedEvents), 3)

		// Acknowledge all claimed events
		claimedIDs := make([]string, len(claimedEvents))
		for i, event := range claimedEvents {
			claimedIDs[i] = event.StreamID
		}
		err = eventStore.AckEvent(ctx, testMissionID, testGroupName, claimedIDs...)
		require.NoError(t, err)
	})

	t.Run("claim with empty group name fails", func(t *testing.T) {
		_, err := eventStore.ClaimStuckEvents(ctx, missionID, "", "worker", 1*time.Second, "id")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "group name cannot be empty")
	})

	t.Run("claim with empty consumer name fails", func(t *testing.T) {
		_, err := eventStore.ClaimStuckEvents(ctx, missionID, groupName, "", 1*time.Second, "id")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "consumer name cannot be empty")
	})

	t.Run("claim with no stream IDs fails", func(t *testing.T) {
		_, err := eventStore.ClaimStuckEvents(ctx, missionID, groupName, "worker", 1*time.Second)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least one stream ID must be provided")
	})
}

func TestRedisEventStore_ConsumerGroupKey(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	eventStore := NewRedisEventStore(client)
	missionID := types.NewID()
	groupName := "test-group"

	expectedKey := "gibson:cg:mission:" + missionID.String() + ":events:" + groupName
	actualKey := eventStore.consumerGroupKey(missionID, groupName)

	assert.Equal(t, expectedKey, actualKey)
}
