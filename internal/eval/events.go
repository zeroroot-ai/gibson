package eval

import (
	"context"
	"time"

	"github.com/zeroroot-ai/gibson/internal/types"
	sdkeval "github.com/zeroroot-ai/sdk/eval"
)

// EvalEventType identifies the type of evaluation event.
type EvalEventType string

const (
	// EvalEventFeedback indicates new evaluation feedback was generated.
	EvalEventFeedback EvalEventType = "eval_feedback"

	// EvalEventAlert indicates an evaluation alert was triggered.
	EvalEventAlert EvalEventType = "eval_alert"

	// EvalEventScoreUpdate indicates evaluation scores were updated.
	EvalEventScoreUpdate EvalEventType = "eval_score_update"

	// EvalEventComplete indicates evaluation is complete.
	EvalEventComplete EvalEventType = "eval_complete"
)

// String returns the string representation of the event type.
func (t EvalEventType) String() string {
	return string(t)
}

// EvalEvent represents an evaluation event that occurred during mission execution.
// These events are bridged to the mission event system for unified monitoring.
type EvalEvent struct {
	// Type identifies the event type.
	Type EvalEventType `json:"type"`

	// AgentName is the name of the agent that generated this event.
	AgentName string `json:"agent_name"`

	// Feedback contains evaluation feedback (for EvalEventFeedback).
	Feedback *sdkeval.Feedback `json:"feedback,omitempty"`

	// Alert contains an evaluation alert (for EvalEventAlert).
	Alert *sdkeval.Alert `json:"alert,omitempty"`

	// Summary contains evaluation summary (for EvalEventScoreUpdate and EvalEventComplete).
	Summary *EvalSummary `json:"summary,omitempty"`

	// Timestamp is when the event occurred.
	Timestamp time.Time `json:"timestamp"`
}

// MissionEventEmitter is a minimal interface for emitting mission events.
// This interface is satisfied by mission.EventEmitter and allows the eval package
// to emit events without creating a circular dependency.
type MissionEventEmitter interface {
	// Emit publishes an event to all subscribers.
	Emit(ctx context.Context, event MissionEvent) error
}

// MissionEvent represents a mission lifecycle event.
// This is a minimal definition that matches mission.MissionEvent structure.
type MissionEvent struct {
	// Type identifies the event type.
	Type string `json:"type"`

	// MissionID is the unique identifier of the mission.
	MissionID types.ID `json:"mission_id"`

	// Timestamp is when the event occurred.
	Timestamp time.Time `json:"timestamp"`

	// Payload contains type-specific event data.
	Payload any `json:"payload,omitempty"`
}

// Mission event type for eval events
const (
	// EventMissionProgress indicates mission progress update.
	// Eval events are emitted as progress events.
	EventMissionProgress = "mission.progress"
)

// EvalEventHandler bridges evaluation events to Gibson's mission event system.
// It converts SDK evaluation events into mission events and emits them to subscribers.
type EvalEventHandler struct {
	// emitter publishes mission events to subscribers
	emitter MissionEventEmitter

	// missionID is the current mission identifier
	missionID types.ID
}

// NewEvalEventHandler creates a new evaluation event handler.
// The handler will emit events for the given mission using the provided emitter.
func NewEvalEventHandler(missionID types.ID, emitter MissionEventEmitter) *EvalEventHandler {
	return &EvalEventHandler{
		emitter:   emitter,
		missionID: missionID,
	}
}

// OnFeedback converts feedback to a mission event and emits it.
// This is called when new evaluation feedback is generated during agent execution.
func (h *EvalEventHandler) OnFeedback(ctx context.Context, agentName string, feedback *sdkeval.Feedback) error {
	evalEvent := &EvalEvent{
		Type:      EvalEventFeedback,
		AgentName: agentName,
		Feedback:  feedback,
		Timestamp: time.Now(),
	}

	missionEvent := h.convertToMissionEvent(evalEvent)
	return h.emitter.Emit(ctx, missionEvent)
}

// OnAlert converts an alert to a mission event and emits it.
// This is called when an evaluation threshold is breached.
func (h *EvalEventHandler) OnAlert(ctx context.Context, agentName string, alert sdkeval.Alert) error {
	evalEvent := &EvalEvent{
		Type:      EvalEventAlert,
		AgentName: agentName,
		Alert:     &alert,
		Timestamp: time.Now(),
	}

	missionEvent := h.convertToMissionEvent(evalEvent)
	return h.emitter.Emit(ctx, missionEvent)
}

// OnScoreUpdate emits a score update event with the current evaluation summary.
// This is called when evaluation scores are updated during mission execution.
func (h *EvalEventHandler) OnScoreUpdate(ctx context.Context, summary *EvalSummary) error {
	evalEvent := &EvalEvent{
		Type:      EvalEventScoreUpdate,
		AgentName: "", // Not agent-specific
		Summary:   summary,
		Timestamp: time.Now(),
	}

	missionEvent := h.convertToMissionEvent(evalEvent)
	return h.emitter.Emit(ctx, missionEvent)
}

// OnComplete emits a completion event with the final evaluation summary.
// This is called when evaluation finalization is complete.
func (h *EvalEventHandler) OnComplete(ctx context.Context, summary *EvalSummary) error {
	evalEvent := &EvalEvent{
		Type:      EvalEventComplete,
		AgentName: "", // Not agent-specific
		Summary:   summary,
		Timestamp: time.Now(),
	}

	missionEvent := h.convertToMissionEvent(evalEvent)
	return h.emitter.Emit(ctx, missionEvent)
}

// convertToMissionEvent converts an EvalEvent to a MissionEvent.
// The EvalEvent is embedded in the mission event payload for downstream consumers.
func (h *EvalEventHandler) convertToMissionEvent(evalEvent *EvalEvent) MissionEvent {
	// Use EventMissionProgress for eval events
	// This allows TUI and other consumers to track evaluation progress
	return MissionEvent{
		Type:      EventMissionProgress,
		MissionID: h.missionID,
		Timestamp: time.Now(),
		Payload:   evalEvent,
	}
}

// EvalFeedbackPayload wraps evaluation feedback for inclusion in mission events.
// This is used when converting feedback events to mission progress events.
type EvalFeedbackPayload struct {
	// AgentName is the agent that generated the feedback.
	AgentName string `json:"agent_name"`

	// OverallScore is the current overall evaluation score (0.0 to 1.0).
	OverallScore float64 `json:"overall_score"`

	// Confidence is the confidence in the overall score (0.0 to 1.0).
	Confidence float64 `json:"confidence"`

	// StepIndex is the trajectory step when this feedback was generated.
	StepIndex int `json:"step_index"`

	// AlertCount is the number of alerts in this feedback.
	AlertCount int `json:"alert_count"`

	// Message is a human-readable summary of the feedback.
	Message string `json:"message"`
}

// EvalAlertPayload wraps evaluation alerts for inclusion in mission events.
// This is used when converting alert events to mission progress events.
type EvalAlertPayload struct {
	// AgentName is the agent that triggered the alert.
	AgentName string `json:"agent_name"`

	// Level is the alert severity level.
	Level string `json:"level"`

	// Scorer is the scorer that generated the alert.
	Scorer string `json:"scorer"`

	// Score is the score that triggered the alert.
	Score float64 `json:"score"`

	// Threshold is the threshold that was breached.
	Threshold float64 `json:"threshold"`

	// Message is the alert message.
	Message string `json:"message"`

	// Action is the recommended action.
	Action string `json:"action"`
}

// EvalSummaryPayload wraps evaluation summary for inclusion in mission events.
// This is used when converting score update and completion events.
type EvalSummaryPayload struct {
	// OverallScore is the final overall score (0.0 to 1.0).
	OverallScore float64 `json:"overall_score"`

	// ScorerScores contains individual scorer results.
	ScorerScores map[string]float64 `json:"scorer_scores"`

	// TotalSteps is the number of trajectory steps.
	TotalSteps int `json:"total_steps"`

	// TotalAlerts is the total alert count.
	TotalAlerts int `json:"total_alerts"`

	// WarningCount is the warning alert count.
	WarningCount int `json:"warning_count"`

	// CriticalCount is the critical alert count.
	CriticalCount int `json:"critical_count"`

	// Duration is the mission execution duration.
	Duration time.Duration `json:"duration"`

	// TokensUsed is the total token usage.
	TokensUsed int `json:"tokens_used"`
}
