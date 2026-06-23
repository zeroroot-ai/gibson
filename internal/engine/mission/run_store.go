package mission

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// MissionRunStore provides persistence for MissionRun entities.
type MissionRunStore interface {
	// Save persists a new mission run to the database
	Save(ctx context.Context, run *MissionRun) error

	// Get retrieves a mission run by ID
	Get(ctx context.Context, id types.ID) (*MissionRun, error)

	// GetByMissionAndNumber retrieves a run by mission ID and run number
	GetByMissionAndNumber(ctx context.Context, missionID types.ID, runNumber int) (*MissionRun, error)

	// ListByMission retrieves all runs for a mission, ordered by run number descending
	ListByMission(ctx context.Context, missionID types.ID) ([]*MissionRun, error)

	// GetLatestByMission retrieves the most recent run for a mission
	GetLatestByMission(ctx context.Context, missionID types.ID) (*MissionRun, error)

	// GetNextRunNumber returns the next run number for a mission
	GetNextRunNumber(ctx context.Context, missionID types.ID) (int, error)

	// Update modifies an existing mission run
	Update(ctx context.Context, run *MissionRun) error

	// UpdateStatus updates only the status field
	UpdateStatus(ctx context.Context, id types.ID, status MissionRunStatus) error

	// UpdateProgress updates only the progress field
	UpdateProgress(ctx context.Context, id types.ID, progress float64) error

	// GetActive retrieves all active runs (running or paused)
	GetActive(ctx context.Context) ([]*MissionRun, error)

	// Delete removes a mission run (only terminal states)
	Delete(ctx context.Context, id types.ID) error

	// CountByMission returns the number of runs for a mission
	CountByMission(ctx context.Context, missionID types.ID) (int, error)
}
