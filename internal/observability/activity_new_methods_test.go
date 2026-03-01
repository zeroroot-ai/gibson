package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewEmitMethods tests the newly added EmitMemoryStore, EmitMemoryRecall, EmitGraphRAGStore, and EmitDelegation methods.
func TestNewEmitMethods(t *testing.T) {
	var buf bytes.Buffer
	logger, err := NewActivityLogger(ActivityLoggerConfig{
		Level:  ActivityLevelVerbose,
		Output: &buf,
	})
	require.NoError(t, err)
	defer logger.Close()

	ctx := context.Background()

	// Test EmitMemoryStore
	logger.EmitMemoryStore(ctx, "mission", "test-key", 1024)

	// Test EmitMemoryRecall
	logger.EmitMemoryRecall(ctx, "working", "some-key", true)

	// Test EmitGraphRAGStore
	logger.EmitGraphRAGStore(ctx, "Host", 5)

	// Test EmitDelegation
	logger.EmitDelegation(ctx, "parent-agent", "child-agent", "Scan the network")

	// Flush to ensure all events are written
	require.NoError(t, logger.Flush())

	// Parse events and verify
	decoder := json.NewDecoder(&buf)
	events := make([]ActivityEvent, 0)
	for decoder.More() {
		var event ActivityEvent
		require.NoError(t, decoder.Decode(&event))
		events = append(events, event)
	}

	require.Len(t, events, 4, "Expected 4 events")

	// Verify EmitMemoryStore event
	assert.Equal(t, EventMemoryStore, events[0].EventType)
	assert.Equal(t, "mission", events[0].Payload["tier"])
	assert.Equal(t, "test-key", events[0].Payload["key"])
	assert.Equal(t, float64(1024), events[0].Payload["data_size"]) // JSON unmarshals numbers as float64

	// Verify EmitMemoryRecall event
	assert.Equal(t, EventMemoryRecall, events[1].EventType)
	assert.Equal(t, "working", events[1].Payload["tier"])
	assert.Equal(t, "some-key", events[1].Payload["key"])
	assert.Equal(t, true, events[1].Payload["found"])

	// Verify EmitGraphRAGStore event
	assert.Equal(t, EventGraphRAGStore, events[2].EventType)
	assert.Equal(t, "Host", events[2].Payload["entity_type"])
	assert.Equal(t, float64(5), events[2].Payload["count"])

	// Verify EmitDelegation event
	assert.Equal(t, EventDelegation, events[3].EventType)
	assert.Equal(t, "parent-agent", events[3].Payload["parent_agent"])
	assert.Equal(t, "child-agent", events[3].Payload["child_agent"])
	assert.Equal(t, "Scan the network", events[3].Payload["task_description"])
}

// TestNoopLogger_NewMethods verifies that the noop logger doesn't panic on new methods.
func TestNoopLogger_NewMethods(t *testing.T) {
	logger := NewNoopActivityLogger()
	ctx := context.Background()

	// These should all be no-ops and not panic
	assert.NotPanics(t, func() {
		logger.EmitMemoryStore(ctx, "mission", "key", 100)
	})

	assert.NotPanics(t, func() {
		logger.EmitMemoryRecall(ctx, "working", "key", true)
	})

	assert.NotPanics(t, func() {
		logger.EmitGraphRAGStore(ctx, "Host", 5)
	})

	assert.NotPanics(t, func() {
		logger.EmitDelegation(ctx, "parent", "child", "task")
	})
}
