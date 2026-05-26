package mission

import (
	"context"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// MissionRunLinker manages relationships between mission runs with the same name.
// It provides functionality to create new runs, link them to previous runs,
// and query run history for a given mission name.
//
// Deprecated: This interface is being replaced by the two-table model where
// Mission and MissionRun are separate entities. Use MissionRunStore directly.
type MissionRunLinker interface {
	// CreateRun creates a new mission run, linking it to the previous run if it exists.
	// It checks for active runs first and returns an error if one exists.
	CreateRun(ctx context.Context, name string, mission *Mission) error

	// GetRunHistory returns all runs for a mission name in descending order by run number.
	GetRunHistory(ctx context.Context, name string) ([]*MissionRunInfo, error)

	// GetLatestRun returns the most recent run for a mission name.
	GetLatestRun(ctx context.Context, name string) (*Mission, error)

	// GetActiveRun returns the currently active run for a name (if any).
	// An active run is one with status running or paused.
	GetActiveRun(ctx context.Context, name string) (*Mission, error)
}

// MissionRunInfo represents metadata about a single mission run for history queries.
// Deprecated: Use MissionRun from run.go instead for full run management.
type MissionRunInfo struct {
	// RunNumber is the sequential run number for this mission name.
	RunNumber int `json:"run_number"`

	// MissionID is the unique identifier for this run.
	MissionID types.ID `json:"mission_id"`

	// PreviousRunID is the ID of the previous run for this name (nil for first run).
	PreviousRunID *types.ID `json:"previous_run_id,omitempty"`

	// Status is the current status of this run.
	Status MissionStatus `json:"status"`

	// CreatedAt is when this run was created.
	CreatedAt time.Time `json:"created_at"`

	// CompletedAt is when this run finished (nil if not complete).
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// DefaultMissionRunLinker is the default implementation of MissionRunLinker.
type DefaultMissionRunLinker struct {
	store MissionStore
}

// NewMissionRunLinker creates a new DefaultMissionRunLinker with the given store.
func NewMissionRunLinker(store MissionStore) *DefaultMissionRunLinker {
	return &DefaultMissionRunLinker{
		store: store,
	}
}

// CreateRun creates a new mission run, linking it to the previous run if it exists.
// It performs the following steps:
// 1. Check if there's an active run for this name (error if exists)
// 2. Get the next run number atomically
// 3. Get the previous run to link to
// 4. Set run metadata on the mission
// 5. Save the mission to the store
func (l *DefaultMissionRunLinker) CreateRun(ctx context.Context, name string, mission *Mission) error {
	if mission == nil {
		return fmt.Errorf("mission cannot be nil")
	}

	if name == "" {
		return fmt.Errorf("mission name cannot be empty")
	}

	// Check for active runs first
	activeRun, err := l.GetActiveRun(ctx, name)
	if err != nil && !IsNotFoundError(err) {
		return fmt.Errorf("failed to check for active runs: %w", err)
	}

	if activeRun != nil {
		return fmt.Errorf("cannot create new run for '%s': active run exists (ID: %s, status: %s). Please stop or resume the existing run",
			name, activeRun.ID, activeRun.Status)
	}

	// Get next run number atomically
	runNumber, err := l.store.IncrementRunNumber(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to get next run number: %w", err)
	}

	// Get previous run to link to
	var previousRunID *types.ID
	previousRun, err := l.store.GetLatestByName(ctx, name)
	if err != nil && !IsNotFoundError(err) {
		return fmt.Errorf("failed to get previous run: %w", err)
	}
	if previousRun != nil {
		previousRunID = &previousRun.ID
	}

	// Set run metadata on the mission
	if mission.Metadata == nil {
		mission.Metadata = make(map[string]any)
	}
	mission.Metadata["run_number"] = runNumber
	if previousRunID != nil {
		mission.Metadata["previous_run_id"] = previousRunID.String()
	}

	// Set the mission name
	mission.Name = name

	// Save the mission
	if err := l.store.Save(ctx, mission); err != nil {
		return fmt.Errorf("failed to save mission run: %w", err)
	}

	return nil
}

// GetRunHistory returns all runs for a mission name in descending order by run number.
func (l *DefaultMissionRunLinker) GetRunHistory(ctx context.Context, name string) ([]*MissionRunInfo, error) {
	if name == "" {
		return nil, fmt.Errorf("mission name cannot be empty")
	}

	missions, err := l.store.ListByName(ctx, name, 0) // 0 means use default limit
	if err != nil {
		return nil, fmt.Errorf("failed to list missions by name: %w", err)
	}

	runs := make([]*MissionRunInfo, 0, len(missions))
	for _, m := range missions {
		run := &MissionRunInfo{
			MissionID:   m.ID,
			Status:      m.Status,
			CreatedAt:   m.CreatedAt.Time,
			CompletedAt: m.CompletedAt.Time,
		}

		// Extract run number from metadata
		if m.Metadata != nil {
			if runNum, ok := m.Metadata["run_number"].(float64); ok {
				run.RunNumber = int(runNum)
			} else if runNum, ok := m.Metadata["run_number"].(int); ok {
				run.RunNumber = runNum
			}

			// Extract previous run ID from metadata
			if prevID, ok := m.Metadata["previous_run_id"].(string); ok && prevID != "" {
				id, err := types.ParseID(prevID)
				if err == nil {
					run.PreviousRunID = &id
				}
			}
		}

		runs = append(runs, run)
	}

	return runs, nil
}

// GetLatestRun returns the most recent run for a mission name.
func (l *DefaultMissionRunLinker) GetLatestRun(ctx context.Context, name string) (*Mission, error) {
	if name == "" {
		return nil, fmt.Errorf("mission name cannot be empty")
	}

	mission, err := l.store.GetLatestByName(ctx, name)
	if err != nil {
		return nil, err
	}

	return mission, nil
}

// GetActiveRun returns the currently active run for a name (if any).
// An active run is one with status running or paused.
func (l *DefaultMissionRunLinker) GetActiveRun(ctx context.Context, name string) (*Mission, error) {
	if name == "" {
		return nil, fmt.Errorf("mission name cannot be empty")
	}

	// Check for running missions
	runningMission, err := l.store.GetByNameAndStatus(ctx, name, MissionStatusRunning)
	if err != nil && !IsNotFoundError(err) {
		return nil, fmt.Errorf("failed to check for running missions: %w", err)
	}
	if runningMission != nil {
		return runningMission, nil
	}

	// Check for paused missions
	pausedMission, err := l.store.GetByNameAndStatus(ctx, name, MissionStatusPaused)
	if err != nil && !IsNotFoundError(err) {
		return nil, fmt.Errorf("failed to check for paused missions: %w", err)
	}
	if pausedMission != nil {
		return pausedMission, nil
	}

	// No active run found
	return nil, NewNotFoundError(fmt.Sprintf("no active run for mission '%s'", name))
}

// Ensure DefaultMissionRunLinker implements MissionRunLinker at compile time.
var _ MissionRunLinker = (*DefaultMissionRunLinker)(nil)
