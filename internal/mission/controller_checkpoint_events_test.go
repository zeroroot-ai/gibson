package mission

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/events"
	"github.com/zero-day-ai/gibson/internal/types"
)

// mockEventBus captures published events for assertions.
type mockEventBus struct {
	mu       sync.Mutex
	published []events.Event
	err      error // if non-nil, Publish returns this error
}

func (m *mockEventBus) Publish(_ context.Context, evt events.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.published = append(m.published, evt)
	return nil
}

func (m *mockEventBus) Subscribe(_ context.Context, _ events.Filter, _ int) (<-chan events.Event, func()) {
	ch := make(chan events.Event)
	return ch, func() { close(ch) }
}

func (m *mockEventBus) Close() error { return nil }

// Published returns a snapshot of all events received so far.
func (m *mockEventBus) Published() []events.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]events.Event, len(m.published))
	copy(out, m.published)
	return out
}

// Compile-time assertion.
var _ events.EventBus = (*mockEventBus)(nil)

func TestEmitPausedEvent_PublishesCorrectEvent(t *testing.T) {
	bus := &mockEventBus{}
	ccm := &ControllerCheckpointMethods{
		eventBus:       bus,
		operationLocks: make(map[types.ID]*sync.Mutex),
	}

	missionID := types.NewID()
	checkpointID := "cp-abc123"

	ctx := context.Background()
	ccm.EmitPausedEvent(ctx, missionID, checkpointID)

	published := bus.Published()
	require.Len(t, published, 1)
	assert.Equal(t, events.EventMissionPaused, published[0].Type)
	assert.Equal(t, missionID, published[0].MissionID)
	payload, ok := published[0].Payload.(map[string]any)
	require.True(t, ok, "payload should be map[string]any")
	assert.Equal(t, checkpointID, payload["checkpoint_id"])
}

func TestEmitResumedEvent_PublishesCorrectEvent(t *testing.T) {
	bus := &mockEventBus{}
	ccm := &ControllerCheckpointMethods{
		eventBus:       bus,
		operationLocks: make(map[types.ID]*sync.Mutex),
	}

	missionID := types.NewID()
	checkpointID := "cp-def456"

	ctx := context.Background()
	ccm.EmitResumedEvent(ctx, missionID, checkpointID)

	published := bus.Published()
	require.Len(t, published, 1)
	assert.Equal(t, events.EventMissionResumed, published[0].Type)
	assert.Equal(t, missionID, published[0].MissionID)
	payload, ok := published[0].Payload.(map[string]any)
	require.True(t, ok, "payload should be map[string]any")
	assert.Equal(t, checkpointID, payload["checkpoint_id"])
}

func TestEmitPausedEvent_NilBus_DoesNotPanic(t *testing.T) {
	ccm := &ControllerCheckpointMethods{
		eventBus:       nil,
		operationLocks: make(map[types.ID]*sync.Mutex),
	}
	// Must not panic.
	assert.NotPanics(t, func() {
		ccm.EmitPausedEvent(context.Background(), types.NewID(), "cp-1")
	})
}

func TestEmitResumedEvent_NilBus_DoesNotPanic(t *testing.T) {
	ccm := &ControllerCheckpointMethods{
		eventBus:       nil,
		operationLocks: make(map[types.ID]*sync.Mutex),
	}
	assert.NotPanics(t, func() {
		ccm.EmitResumedEvent(context.Background(), types.NewID(), "cp-2")
	})
}

func TestEmitPausedEvent_PublishError_DoesNotPropagate(t *testing.T) {
	bus := &mockEventBus{err: errors.New("bus full")}
	ccm := &ControllerCheckpointMethods{
		eventBus:       bus,
		operationLocks: make(map[types.ID]*sync.Mutex),
	}
	// Must not panic or error-return — Publish errors are WARN-logged and swallowed.
	assert.NotPanics(t, func() {
		ccm.EmitPausedEvent(context.Background(), types.NewID(), "cp-3")
	})
}
