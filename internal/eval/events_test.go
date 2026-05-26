package eval

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/types"
	sdkeval "github.com/zeroroot-ai/sdk/eval"
)

// mockEventEmitter is a test helper that implements MissionEventEmitter
type mockEventEmitter struct {
	mu     sync.Mutex
	events []MissionEvent
	closed bool
}

func newMockEventEmitter() *mockEventEmitter {
	return &mockEventEmitter{
		events: make([]MissionEvent, 0),
		closed: false,
	}
}

func (m *mockEventEmitter) Emit(ctx context.Context, event MissionEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return context.Canceled
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		m.events = append(m.events, event)
		return nil
	}
}

func (m *mockEventEmitter) getEvents() []MissionEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]MissionEvent(nil), m.events...)
}

func (m *mockEventEmitter) close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
}

func TestNewEvalEventHandler(t *testing.T) {
	missionID := types.NewID()
	emitter := newMockEventEmitter()

	handler := NewEvalEventHandler(missionID, emitter)

	assert.NotNil(t, handler)
	assert.Equal(t, missionID, handler.missionID)
	assert.Equal(t, emitter, handler.emitter)
}

func TestEvalEventHandler_OnFeedback(t *testing.T) {
	missionID := types.NewID()
	emitter := newMockEventEmitter()

	handler := NewEvalEventHandler(missionID, emitter)
	ctx := context.Background()

	// Create feedback
	feedback := &sdkeval.Feedback{
		Timestamp: time.Now(),
		StepIndex: 5,
		Scores: map[string]sdkeval.PartialScore{
			"tool_correctness": {
				Score:      0.85,
				Confidence: 0.9,
				Feedback:   "Good tool usage",
				Action:     sdkeval.ActionContinue,
			},
		},
		Overall: sdkeval.PartialScore{
			Score:      0.85,
			Confidence: 0.9,
			Feedback:   "Overall performing well",
			Action:     sdkeval.ActionContinue,
		},
		Alerts: []sdkeval.Alert{
			{
				Level:     sdkeval.AlertWarning,
				Scorer:    "trajectory",
				Score:     0.65,
				Threshold: 0.7,
				Message:   "Trajectory score below warning threshold",
				Action:    sdkeval.ActionAdjust,
			},
		},
	}

	// Emit feedback event
	err := handler.OnFeedback(ctx, "test-agent", feedback)
	require.NoError(t, err)

	// Verify event
	events := emitter.getEvents()
	require.Len(t, events, 1)

	event := events[0]
	assert.Equal(t, EventMissionProgress, event.Type)
	assert.Equal(t, missionID, event.MissionID)

	// Verify payload is an EvalEvent
	evalEvent, ok := event.Payload.(*EvalEvent)
	require.True(t, ok, "payload should be *EvalEvent")

	assert.Equal(t, EvalEventFeedback, evalEvent.Type)
	assert.Equal(t, "test-agent", evalEvent.AgentName)
	assert.NotNil(t, evalEvent.Feedback)
	assert.Equal(t, 5, evalEvent.Feedback.StepIndex)
	assert.Equal(t, 0.85, evalEvent.Feedback.Overall.Score)
	assert.Len(t, evalEvent.Feedback.Alerts, 1)
}

func TestEvalEventHandler_OnAlert(t *testing.T) {
	missionID := types.NewID()
	emitter := newMockEventEmitter()

	handler := NewEvalEventHandler(missionID, emitter)
	ctx := context.Background()

	// Create alert
	alert := sdkeval.Alert{
		Level:     sdkeval.AlertCritical,
		Scorer:    "finding_accuracy",
		Score:     0.25,
		Threshold: 0.3,
		Message:   "Critical: Finding accuracy below threshold",
		Action:    sdkeval.ActionAbort,
	}

	// Emit alert event
	err := handler.OnAlert(ctx, "test-agent", alert)
	require.NoError(t, err)

	// Verify event
	events := emitter.getEvents()
	require.Len(t, events, 1)

	event := events[0]
	assert.Equal(t, EventMissionProgress, event.Type)
	assert.Equal(t, missionID, event.MissionID)

	// Verify payload is an EvalEvent
	evalEvent, ok := event.Payload.(*EvalEvent)
	require.True(t, ok, "payload should be *EvalEvent")

	assert.Equal(t, EvalEventAlert, evalEvent.Type)
	assert.Equal(t, "test-agent", evalEvent.AgentName)
	assert.NotNil(t, evalEvent.Alert)
	assert.Equal(t, sdkeval.AlertCritical, evalEvent.Alert.Level)
	assert.Equal(t, "finding_accuracy", evalEvent.Alert.Scorer)
	assert.Equal(t, 0.25, evalEvent.Alert.Score)
	assert.Equal(t, 0.3, evalEvent.Alert.Threshold)
}

func TestEvalEventHandler_OnScoreUpdate(t *testing.T) {
	missionID := types.NewID()
	emitter := newMockEventEmitter()

	handler := NewEvalEventHandler(missionID, emitter)
	ctx := context.Background()

	// Create summary
	summary := NewEvalSummary(missionID)
	summary.OverallScore = 0.78
	summary.ScorerScores = map[string]float64{
		"tool_correctness": 0.85,
		"trajectory":       0.75,
		"finding_accuracy": 0.72,
	}
	summary.TotalSteps = 42
	summary.TotalAlerts = 3
	summary.WarningCount = 2
	summary.CriticalCount = 1
	summary.Duration = 5 * time.Minute
	summary.TokensUsed = 15000

	// Emit score update event
	err := handler.OnScoreUpdate(ctx, summary)
	require.NoError(t, err)

	// Verify event
	events := emitter.getEvents()
	require.Len(t, events, 1)

	event := events[0]
	assert.Equal(t, EventMissionProgress, event.Type)
	assert.Equal(t, missionID, event.MissionID)

	// Verify payload is an EvalEvent
	evalEvent, ok := event.Payload.(*EvalEvent)
	require.True(t, ok, "payload should be *EvalEvent")

	assert.Equal(t, EvalEventScoreUpdate, evalEvent.Type)
	assert.Empty(t, evalEvent.AgentName) // Not agent-specific
	assert.NotNil(t, evalEvent.Summary)
	assert.Equal(t, 0.78, evalEvent.Summary.OverallScore)
	assert.Len(t, evalEvent.Summary.ScorerScores, 3)
	assert.Equal(t, 42, evalEvent.Summary.TotalSteps)
	assert.Equal(t, 3, evalEvent.Summary.TotalAlerts)
}

func TestEvalEventHandler_OnComplete(t *testing.T) {
	missionID := types.NewID()
	emitter := newMockEventEmitter()

	handler := NewEvalEventHandler(missionID, emitter)
	ctx := context.Background()

	// Create final summary
	summary := NewEvalSummary(missionID)
	summary.OverallScore = 0.82
	summary.ScorerScores = map[string]float64{
		"tool_correctness": 0.90,
		"trajectory":       0.80,
		"finding_accuracy": 0.75,
	}
	summary.TotalSteps = 100
	summary.TotalAlerts = 5
	summary.WarningCount = 4
	summary.CriticalCount = 1
	summary.Duration = 10 * time.Minute
	summary.TokensUsed = 25000

	// Emit completion event
	err := handler.OnComplete(ctx, summary)
	require.NoError(t, err)

	// Verify event
	events := emitter.getEvents()
	require.Len(t, events, 1)

	event := events[0]
	assert.Equal(t, EventMissionProgress, event.Type)
	assert.Equal(t, missionID, event.MissionID)

	// Verify payload is an EvalEvent
	evalEvent, ok := event.Payload.(*EvalEvent)
	require.True(t, ok, "payload should be *EvalEvent")

	assert.Equal(t, EvalEventComplete, evalEvent.Type)
	assert.Empty(t, evalEvent.AgentName) // Not agent-specific
	assert.NotNil(t, evalEvent.Summary)
	assert.Equal(t, 0.82, evalEvent.Summary.OverallScore)
	assert.Equal(t, 100, evalEvent.Summary.TotalSteps)
	assert.Equal(t, 5, evalEvent.Summary.TotalAlerts)
	assert.Equal(t, 25000, evalEvent.Summary.TokensUsed)
}

func TestEvalEventHandler_MultipleEvents(t *testing.T) {
	missionID := types.NewID()
	emitter := newMockEventEmitter()

	handler := NewEvalEventHandler(missionID, emitter)
	ctx := context.Background()

	// Emit multiple events
	feedback := &sdkeval.Feedback{
		Timestamp: time.Now(),
		StepIndex: 1,
		Overall: sdkeval.PartialScore{
			Score:      0.8,
			Confidence: 0.9,
			Action:     sdkeval.ActionContinue,
		},
	}

	alert := sdkeval.Alert{
		Level:     sdkeval.AlertWarning,
		Scorer:    "test",
		Score:     0.65,
		Threshold: 0.7,
		Message:   "Warning",
		Action:    sdkeval.ActionAdjust,
	}

	summary := NewEvalSummary(missionID)
	summary.OverallScore = 0.75

	// Emit events
	require.NoError(t, handler.OnFeedback(ctx, "agent1", feedback))
	require.NoError(t, handler.OnAlert(ctx, "agent1", alert))
	require.NoError(t, handler.OnScoreUpdate(ctx, summary))

	// Verify events
	events := emitter.getEvents()
	require.Len(t, events, 3)

	// Extract eval events
	evalEvent1, ok := events[0].Payload.(*EvalEvent)
	require.True(t, ok)
	assert.Equal(t, EvalEventFeedback, evalEvent1.Type)

	evalEvent2, ok := events[1].Payload.(*EvalEvent)
	require.True(t, ok)
	assert.Equal(t, EvalEventAlert, evalEvent2.Type)

	evalEvent3, ok := events[2].Payload.(*EvalEvent)
	require.True(t, ok)
	assert.Equal(t, EvalEventScoreUpdate, evalEvent3.Type)
}

func TestEvalEventHandler_ContextCancellation(t *testing.T) {
	missionID := types.NewID()
	emitter := newMockEventEmitter()

	handler := NewEvalEventHandler(missionID, emitter)

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Attempt to emit event with cancelled context
	feedback := &sdkeval.Feedback{
		Timestamp: time.Now(),
		StepIndex: 1,
		Overall: sdkeval.PartialScore{
			Score:      0.8,
			Confidence: 0.9,
		},
	}

	err := handler.OnFeedback(ctx, "test-agent", feedback)
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestEvalEventHandler_EmitterClosed(t *testing.T) {
	missionID := types.NewID()
	emitter := newMockEventEmitter()

	handler := NewEvalEventHandler(missionID, emitter)

	// Close emitter
	emitter.close()

	// Attempt to emit event with closed emitter
	ctx := context.Background()
	feedback := &sdkeval.Feedback{
		Timestamp: time.Now(),
		StepIndex: 1,
		Overall: sdkeval.PartialScore{
			Score:      0.8,
			Confidence: 0.9,
		},
	}

	err := handler.OnFeedback(ctx, "test-agent", feedback)
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestEvalEventType_String(t *testing.T) {
	tests := []struct {
		name      string
		eventType EvalEventType
		expected  string
	}{
		{
			name:      "feedback event",
			eventType: EvalEventFeedback,
			expected:  "eval_feedback",
		},
		{
			name:      "alert event",
			eventType: EvalEventAlert,
			expected:  "eval_alert",
		},
		{
			name:      "score update event",
			eventType: EvalEventScoreUpdate,
			expected:  "eval_score_update",
		},
		{
			name:      "complete event",
			eventType: EvalEventComplete,
			expected:  "eval_complete",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.eventType.String())
		})
	}
}

func TestConvertToMissionEvent(t *testing.T) {
	missionID := types.NewID()
	emitter := newMockEventEmitter()

	handler := NewEvalEventHandler(missionID, emitter)

	evalEvent := &EvalEvent{
		Type:      EvalEventFeedback,
		AgentName: "test-agent",
		Timestamp: time.Now(),
	}

	missionEvent := handler.convertToMissionEvent(evalEvent)

	assert.Equal(t, EventMissionProgress, missionEvent.Type)
	assert.Equal(t, missionID, missionEvent.MissionID)
	assert.NotZero(t, missionEvent.Timestamp)

	payload, ok := missionEvent.Payload.(*EvalEvent)
	require.True(t, ok, "payload should be *EvalEvent")
	assert.Equal(t, evalEvent, payload)
}
