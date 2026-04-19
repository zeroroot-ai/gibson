//go:build stale
// +build stale

// NOTE: this test references `NewDBEventStore`, a SQL-backed constructor
// that was removed when the event store moved to Redis. Kept behind the
// `stale` build tag so the file is preserved for future repair.

package mission

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/types"
)

func TestDBEventStore_Append(t *testing.T) {
	db := setupTestDB(t)
	eventStore := NewDBEventStore(db)
	missionStore := NewDBMissionStore(db)
	ctx := context.Background()

	// Create test mission first (required due to foreign key constraint)
	mission := createTestMission(t)
	err := missionStore.Save(ctx, mission)
	require.NoError(t, err)
	missionID := mission.ID

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
}

func TestDBEventStore_Query(t *testing.T) {
	db := setupTestDB(t)
	eventStore := NewDBEventStore(db)
	missionStore := NewDBMissionStore(db)
	ctx := context.Background()

	// Create test missions first
	mission1Data := createTestMission(t)
	err := missionStore.Save(ctx, mission1Data)
	require.NoError(t, err)
	mission1 := mission1Data.ID

	mission2Data := createTestMission(t)
	err = missionStore.Save(ctx, mission2Data)
	require.NoError(t, err)
	mission2 := mission2Data.ID

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
		err := eventStore.Append(ctx, event)
		require.NoError(t, err)
	}

	t.Run("query all events", func(t *testing.T) {
		filter := NewEventFilter()
		results, err := eventStore.Query(ctx, filter)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(results), 5)

		// Verify chronological ordering
		for i := 0; i < len(results)-1; i++ {
			assert.True(t, results[i].Timestamp.Before(results[i+1].Timestamp) || results[i].Timestamp.Equal(results[i+1].Timestamp),
				"Events should be ordered chronologically")
		}
	})

	t.Run("query by mission ID", func(t *testing.T) {
		filter := NewEventFilter().WithMissionID(mission1)
		results, err := eventStore.Query(ctx, filter)
		require.NoError(t, err)
		assert.Equal(t, 3, len(results))

		for _, event := range results {
			assert.Equal(t, mission1, event.MissionID)
		}
	})

	t.Run("query by event type", func(t *testing.T) {
		filter := NewEventFilter().WithEventTypes(EventMissionStarted)
		results, err := eventStore.Query(ctx, filter)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(results), 2)

		for _, event := range results {
			assert.Equal(t, EventMissionStarted, event.Type)
		}
	})

	t.Run("query by multiple event types", func(t *testing.T) {
		filter := NewEventFilter().WithEventTypes(EventMissionCompleted, EventMissionFailed)
		results, err := eventStore.Query(ctx, filter)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(results), 2)

		for _, event := range results {
			assert.True(t, event.Type == EventMissionCompleted || event.Type == EventMissionFailed)
		}
	})

	t.Run("query by time range", func(t *testing.T) {
		after := baseTime.Add(8 * time.Minute)
		before := baseTime.Add(18 * time.Minute)

		filter := NewEventFilter().WithTimeRange(after, before)
		results, err := eventStore.Query(ctx, filter)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(results), 2)

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
		filter := NewEventFilter().WithPagination(2, 0)
		results, err := eventStore.Query(ctx, filter)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(results), 2)
	})

	t.Run("query with offset", func(t *testing.T) {
		// Get all events
		allFilter := NewEventFilter().WithPagination(100, 0)
		allResults, err := eventStore.Query(ctx, allFilter)
		require.NoError(t, err)

		// Get with offset
		offsetFilter := NewEventFilter().WithPagination(100, 2)
		offsetResults, err := eventStore.Query(ctx, offsetFilter)
		require.NoError(t, err)

		assert.Equal(t, len(allResults)-2, len(offsetResults))
	})

	t.Run("query with nil filter uses defaults", func(t *testing.T) {
		results, err := eventStore.Query(ctx, nil)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(results), 5)
	})

	t.Run("query non-existent mission returns empty", func(t *testing.T) {
		filter := NewEventFilter().WithMissionID(types.NewID())
		results, err := eventStore.Query(ctx, filter)
		require.NoError(t, err)
		assert.Empty(t, results)
	})
}

func TestDBEventStore_Stream(t *testing.T) {
	db := setupTestDB(t)
	eventStore := NewDBEventStore(db)
	missionStore := NewDBMissionStore(db)
	ctx := context.Background()

	// Create test mission first
	missionData := createTestMission(t)
	err := missionStore.Save(ctx, missionData)
	require.NoError(t, err)
	missionID := missionData.ID
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
	}

	t.Run("stream all events", func(t *testing.T) {
		eventCh, err := eventStore.Stream(ctx, missionID, baseTime.Add(-1*time.Minute))
		require.NoError(t, err)

		receivedEvents := 0
		for event := range eventCh {
			assert.Equal(t, missionID, event.MissionID)
			receivedEvents++
		}

		assert.Equal(t, eventCount, receivedEvents)
	})

	t.Run("stream from specific timestamp", func(t *testing.T) {
		fromTime := baseTime.Add(2 * time.Minute)
		eventCh, err := eventStore.Stream(ctx, missionID, fromTime)
		require.NoError(t, err)

		receivedEvents := 0
		for event := range eventCh {
			assert.True(t, event.Timestamp.After(fromTime) || event.Timestamp.Equal(fromTime))
			receivedEvents++
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
		for range eventCh {
			if !receivedOne {
				receivedOne = true
				cancel()
			}
		}

		assert.True(t, receivedOne)
	})

	t.Run("stream non-existent mission", func(t *testing.T) {
		nonExistentID := types.NewID()
		eventCh, err := eventStore.Stream(ctx, nonExistentID, baseTime)
		require.NoError(t, err)

		receivedEvents := 0
		for range eventCh {
			receivedEvents++
		}

		assert.Equal(t, 0, receivedEvents)
	})

	t.Run("stream closes channel when done", func(t *testing.T) {
		eventCh, err := eventStore.Stream(ctx, missionID, baseTime)
		require.NoError(t, err)

		// Drain channel
		for range eventCh {
		}

		// Channel should be closed
		_, ok := <-eventCh
		assert.False(t, ok, "Channel should be closed")
	})
}

func TestDBEventStore_EventPayloadSerialization(t *testing.T) {
	db := setupTestDB(t)
	eventStore := NewDBEventStore(db)
	missionStore := NewDBMissionStore(db)
	ctx := context.Background()

	// Create test mission first
	missionData := createTestMission(t)
	err := missionStore.Save(ctx, missionData)
	require.NoError(t, err)
	missionID := missionData.ID

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

		filter := NewEventFilter().
			WithMissionID(missionID).
			WithEventTypes(EventMissionStarted)

		results, err := eventStore.Query(ctx, filter)
		require.NoError(t, err)
		require.NotEmpty(t, results)

		assert.Nil(t, results[0].Payload)
	})
}

func TestEventFilter(t *testing.T) {
	t.Run("default values", func(t *testing.T) {
		filter := NewEventFilter()
		assert.Equal(t, 100, filter.Limit)
		assert.Equal(t, 0, filter.Offset)
		assert.Nil(t, filter.MissionID)
		assert.Nil(t, filter.EventTypes)
		assert.Nil(t, filter.After)
		assert.Nil(t, filter.Before)
	})

	t.Run("builder pattern", func(t *testing.T) {
		missionID := types.NewID()
		after := time.Now().Add(-1 * time.Hour)
		before := time.Now()

		filter := NewEventFilter().
			WithMissionID(missionID).
			WithEventTypes(EventMissionStarted, EventMissionCompleted).
			WithTimeRange(after, before).
			WithPagination(50, 10)

		assert.Equal(t, missionID, *filter.MissionID)
		assert.Equal(t, 2, len(filter.EventTypes))
		assert.Equal(t, EventMissionStarted, filter.EventTypes[0])
		assert.Equal(t, EventMissionCompleted, filter.EventTypes[1])
		assert.Equal(t, after, *filter.After)
		assert.Equal(t, before, *filter.Before)
		assert.Equal(t, 50, filter.Limit)
		assert.Equal(t, 10, filter.Offset)
	})
}
