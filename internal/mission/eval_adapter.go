package mission

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/eval"
)

// EvalEventAdapter adapts a mission.EventEmitter to satisfy eval.MissionEventEmitter.
// This allows the eval package to emit events without creating a circular dependency.
type EvalEventAdapter struct {
	emitter EventEmitter
}

// NewEvalEventAdapter creates a new adapter that wraps a mission EventEmitter.
func NewEvalEventAdapter(emitter EventEmitter) *EvalEventAdapter {
	return &EvalEventAdapter{emitter: emitter}
}

// Emit converts an eval.MissionEvent to a mission.MissionEvent and emits it.
func (a *EvalEventAdapter) Emit(ctx context.Context, event eval.MissionEvent) error {
	// Convert eval.MissionEvent to mission.MissionEvent
	missionEvent := MissionEvent{
		Type:      MissionEventType(event.Type),
		MissionID: event.MissionID,
		Timestamp: event.Timestamp,
		Payload:   event.Payload,
	}
	return a.emitter.Emit(ctx, missionEvent)
}

// Verify at compile time that EvalEventAdapter implements eval.MissionEventEmitter
var _ eval.MissionEventEmitter = (*EvalEventAdapter)(nil)
