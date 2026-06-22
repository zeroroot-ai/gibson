package mission

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// TargetStore provides access to target entities needed by the orchestrator.
// This interface allows the orchestrator to load full target details including
// connection parameters that agents need for testing.
type TargetStore interface {
	// Get retrieves a target by ID, returning the full target entity with connection details
	Get(ctx context.Context, id types.ID) (*types.Target, error)
}

// MissionOrchestrator defines the interface for executing missions.
type MissionOrchestrator interface {
	// Execute runs the mission and manages all orchestration
	Execute(ctx context.Context, mission *Mission) (*MissionResult, error)

	// ExecuteFromCheckpoint resumes a mission from a saved checkpoint.
	// Nodes listed in checkpoint.CompletedNodes are pre-marked as completed
	// before the execution loop starts, causing the scheduler to skip them.
	// When checkpoint is nil the behaviour is identical to Execute.
	ExecuteFromCheckpoint(ctx context.Context, mission *Mission, checkpoint *MissionCheckpoint) (*MissionResult, error)

	// StopMission requests the orchestrator to stop executing a mission
	StopMission(ctx context.Context, missionID types.ID) error
}

// EventBusPublisher is an interface for publishing daemon-wide events.
// This allows the orchestrator to publish to the daemon's event bus
// without creating a circular dependency.
type EventBusPublisher interface {
	Publish(ctx context.Context, event interface{}) error
}
