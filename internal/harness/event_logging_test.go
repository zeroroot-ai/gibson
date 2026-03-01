package harness

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/types"
)

// mockEventLogger captures events for testing
type mockEventLogger struct {
	events []capturedEvent
}

type capturedEvent struct {
	eventType string
	msg       string
	data      any
}

func (m *mockEventLogger) Event(ctx context.Context, eventType string, msg string, data any) {
	m.events = append(m.events, capturedEvent{
		eventType: eventType,
		msg:       msg,
		data:      data,
	})
}

func TestEventLogging_FindingSubmission(t *testing.T) {
	// Create mock event logger
	mockLogger := &mockEventLogger{
		events: make([]capturedEvent, 0),
	}

	// Create harness with event logger
	cfg := HarnessConfig{
		SlotManager:  llm.NewSlotManager(llm.NewLLMRegistry()),
		FindingStore: NewInMemoryFindingStore(),
		EventLogger:  mockLogger,
	}

	factory, err := NewHarnessFactory(cfg)
	require.NoError(t, err)

	missionCtx := MissionContext{
		ID:   types.NewID(),
		Name: "test-mission",
	}

	targetInfo := TargetInfo{
		ID:   "target-123",
		Name: "test-target",
	}

	harness, err := factory.Create("test-agent", missionCtx, targetInfo)
	require.NoError(t, err)

	// Submit finding
	ctx := context.Background()
	finding := agent.NewFinding(
		"Test Vulnerability",
		"This is a test finding",
		agent.SeverityHigh,
	).WithConfidence(0.95)

	err = harness.SubmitFinding(ctx, finding)
	require.NoError(t, err)

	// Verify event was logged
	require.Len(t, mockLogger.events, 1, "should have logged finding event")

	// Check finding event
	findingEvent := mockLogger.events[0]
	assert.Equal(t, EventFinding, findingEvent.eventType)
	assert.Contains(t, findingEvent.msg, "finding submitted")

	findingData, ok := findingEvent.data.(FindingEventData)
	require.True(t, ok, "event data should be FindingEventData")
	assert.Equal(t, "high", findingData.Severity)
	assert.Equal(t, "Test Vulnerability", findingData.Title)
	assert.Equal(t, "0.95", findingData.Confidence)
}

func TestEventLogging_NoEventLogger(t *testing.T) {
	// Create harness without event logger
	cfg := HarnessConfig{
		SlotManager:  llm.NewSlotManager(llm.NewLLMRegistry()),
		FindingStore: NewInMemoryFindingStore(),
		EventLogger:  nil, // No event logger
	}

	factory, err := NewHarnessFactory(cfg)
	require.NoError(t, err)

	missionCtx := MissionContext{
		ID:   types.NewID(),
		Name: "test-mission",
	}

	targetInfo := TargetInfo{
		ID:   "target-123",
		Name: "test-target",
	}

	harness, err := factory.Create("test-agent", missionCtx, targetInfo)
	require.NoError(t, err)

	// Submit finding
	ctx := context.Background()
	finding := agent.NewFinding(
		"Test Vulnerability",
		"This is a test finding",
		agent.SeverityHigh,
	)

	// This should not panic or error even without event logger
	err = harness.SubmitFinding(ctx, finding)
	require.NoError(t, err)
}
