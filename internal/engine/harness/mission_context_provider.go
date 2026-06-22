package harness

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// MissionStore defines the subset of mission store operations needed by the context provider.
// This interface enables dependency injection without importing the mission package,
// avoiding circular dependencies (harness → mission → eval → harness).
type MissionStore interface {
	// Get retrieves a mission by ID
	Get(ctx context.Context, id types.ID) (MissionData, error)

	// ListByName retrieves all missions with the given name, ordered by run number descending
	ListByName(ctx context.Context, name string, limit int) ([]MissionData, error)
}

// MissionData represents the minimal mission data needed by the context provider.
// This is a subset of the full mission.Mission type to avoid circular dependencies.
type MissionData struct {
	ID            types.ID
	Name          string
	Status        string
	RunNumber     int
	FindingsCount int
	Checkpoint    *MissionCheckpointData
	PreviousRunID *types.ID
	CreatedAt     time.Time
	CompletedAt   *time.Time
}

// MissionCheckpointData represents checkpoint data needed to determine resume status.
type MissionCheckpointData struct {
	LastNodeID string
}

// MissionContextProvider provides enhanced mission context to agents including run history.
// This interface enables agents to access comprehensive information about the current mission,
// previous runs, and execution continuity for informed decision-making.
type MissionContextProvider interface {
	// GetContext returns the full mission execution context.
	// This includes mission metadata, run information, resume status, and historical data.
	GetContext(ctx context.Context) (*MissionExecutionContext, error)

	// GetRunHistory returns all runs for the current mission name.
	// Results are ordered by run number descending (most recent first).
	// Returns an empty slice if this is the first run.
	GetRunHistory(ctx context.Context) ([]*MissionRunSummary, error)

	// GetPreviousRun returns details of the immediate prior run.
	// Returns nil if this is the first run or if previous run data is unavailable.
	GetPreviousRun(ctx context.Context) (*MissionRunSummary, error)

	// IsResumedRun returns true if current run was resumed from checkpoint.
	// This indicates the mission was interrupted and is continuing from saved state.
	IsResumedRun() bool
}

// MissionExecutionContext provides comprehensive mission execution information.
// This type mirrors the SDK type to maintain separation between internal and public APIs.
type MissionExecutionContext struct {
	// MissionID is the unique identifier for this mission execution.
	MissionID types.ID

	// MissionName is the human-readable mission name (same across runs).
	MissionName string

	// RunNumber is the sequential run number for this mission name.
	RunNumber int

	// IsResumed indicates if this run was resumed from a checkpoint.
	IsResumed bool

	// ResumedFromNode is the mission node ID where execution resumed (empty if not resumed).
	ResumedFromNode string

	// PreviousRunID links to the prior run (nil if this is the first run).
	PreviousRunID *types.ID

	// PreviousRunStatus is the final status of the previous run (empty if no previous run).
	PreviousRunStatus string

	// TotalFindingsAllRuns is the aggregate finding count across all runs of this mission.
	TotalFindingsAllRuns int

	// MemoryContinuity describes memory state: "first_run", "resumed", or "new_run_with_history".
	MemoryContinuity string
}

// MissionRunSummary provides summary information for a single mission run.
// This type mirrors the SDK type to maintain separation between internal and public APIs.
type MissionRunSummary struct {
	// MissionID is the unique identifier for this run.
	MissionID types.ID

	// RunNumber is the sequential run number.
	RunNumber int

	// Status is the final status of this run.
	Status string

	// FindingsCount is the number of findings discovered during this run.
	FindingsCount int

	// CreatedAt is when this run was created.
	CreatedAt time.Time

	// CompletedAt is when this run finished (nil if still running or never started).
	CompletedAt *time.Time
}

// DefaultMissionContextProvider is the default implementation of MissionContextProvider.
// It queries the mission store to build comprehensive execution context for agents.
type DefaultMissionContextProvider struct {
	missionStore   MissionStore
	currentMission MissionData
	logger         *slog.Logger

	// Cached context to avoid repeated database queries within a session.
	cachedContext *MissionExecutionContext
}

// NewMissionContextProvider creates a new DefaultMissionContextProvider.
//
// Parameters:
//   - missionStore: Store for querying mission data and history
//   - currentMission: The currently executing mission
//   - logger: Structured logger for debugging and tracing
//
// Returns:
//   - *DefaultMissionContextProvider: Ready-to-use context provider
func NewMissionContextProvider(
	missionStore MissionStore,
	currentMission MissionData,
	logger *slog.Logger,
) *DefaultMissionContextProvider {
	return &DefaultMissionContextProvider{
		missionStore:   missionStore,
		currentMission: currentMission,
		logger:         logger,
	}
}

// GetContext returns the full mission execution context.
// This method builds a comprehensive view of the current mission including:
//   - Basic mission metadata (ID, name, run number)
//   - Resume status and checkpoint information
//   - Previous run linkage and status
//   - Aggregate metrics across all runs
//   - Memory continuity indicators
//
// The context is cached per session to avoid repeated database queries.
func (p *DefaultMissionContextProvider) GetContext(ctx context.Context) (*MissionExecutionContext, error) {
	// Return cached context if available
	if p.cachedContext != nil {
		return p.cachedContext, nil
	}

	// Build the context
	execCtx := &MissionExecutionContext{
		MissionID:   p.currentMission.ID,
		MissionName: p.currentMission.Name,
		RunNumber:   p.currentMission.RunNumber,
		IsResumed:   p.IsResumedRun(),
	}

	// Set resumed node if applicable
	if execCtx.IsResumed && p.currentMission.Checkpoint != nil {
		execCtx.ResumedFromNode = p.currentMission.Checkpoint.LastNodeID
	}

	// Get previous run information if available
	if p.currentMission.PreviousRunID != nil {
		execCtx.PreviousRunID = p.currentMission.PreviousRunID

		prevRun, err := p.missionStore.Get(ctx, *p.currentMission.PreviousRunID)
		if err != nil {
			// Log but don't fail - previous run data is supplementary
			p.logger.Warn("Failed to retrieve previous run",
				"previous_run_id", p.currentMission.PreviousRunID,
				"error", err)
		} else {
			execCtx.PreviousRunStatus = prevRun.Status
		}
	}

	// Calculate total findings across all runs
	runHistory, err := p.GetRunHistory(ctx)
	if err != nil {
		// Log but don't fail - history is supplementary
		p.logger.Warn("Failed to retrieve run history",
			"mission_name", p.currentMission.Name,
			"error", err)
	} else {
		totalFindings := 0
		for _, run := range runHistory {
			totalFindings += run.FindingsCount
		}
		execCtx.TotalFindingsAllRuns = totalFindings
	}

	// Determine memory continuity state
	execCtx.MemoryContinuity = p.determineMemoryContinuity(runHistory)

	// Cache the context
	p.cachedContext = execCtx

	p.logger.Debug("Built mission execution context",
		"mission_id", execCtx.MissionID,
		"mission_name", execCtx.MissionName,
		"run_number", execCtx.RunNumber,
		"is_resumed", execCtx.IsResumed,
		"memory_continuity", execCtx.MemoryContinuity)

	return execCtx, nil
}

// GetRunHistory returns all runs for the current mission name.
// Results are ordered by run number descending (most recent first).
// Returns an empty slice if this is the first run or if history retrieval fails.
func (p *DefaultMissionContextProvider) GetRunHistory(ctx context.Context) ([]*MissionRunSummary, error) {
	// Query all missions with this name (limit to reasonable number)
	missions, err := p.missionStore.ListByName(ctx, p.currentMission.Name, 100)
	if err != nil {
		return nil, fmt.Errorf("failed to list missions by name: %w", err)
	}

	// Convert to summaries
	summaries := make([]*MissionRunSummary, 0, len(missions))
	for _, m := range missions {
		summary := &MissionRunSummary{
			MissionID:     m.ID,
			RunNumber:     m.RunNumber,
			Status:        m.Status,
			FindingsCount: m.FindingsCount,
			CreatedAt:     m.CreatedAt,
			CompletedAt:   m.CompletedAt,
		}
		summaries = append(summaries, summary)
	}

	p.logger.Debug("Retrieved run history",
		"mission_name", p.currentMission.Name,
		"run_count", len(summaries))

	return summaries, nil
}

// GetPreviousRun returns details of the immediate prior run.
// Returns nil if this is the first run, if previous run ID is not set,
// or if the previous run cannot be retrieved.
func (p *DefaultMissionContextProvider) GetPreviousRun(ctx context.Context) (*MissionRunSummary, error) {
	// No previous run if not set
	if p.currentMission.PreviousRunID == nil {
		return nil, nil
	}

	// Retrieve previous run from store
	prevMission, err := p.missionStore.Get(ctx, *p.currentMission.PreviousRunID)
	if err != nil {
		// Return nil instead of error for graceful handling
		p.logger.Warn("Failed to retrieve previous run",
			"previous_run_id", p.currentMission.PreviousRunID,
			"error", err)
		return nil, nil
	}

	summary := &MissionRunSummary{
		MissionID:     prevMission.ID,
		RunNumber:     prevMission.RunNumber,
		Status:        prevMission.Status,
		FindingsCount: prevMission.FindingsCount,
		CreatedAt:     prevMission.CreatedAt,
		CompletedAt:   prevMission.CompletedAt,
	}

	p.logger.Debug("Retrieved previous run",
		"previous_run_id", prevMission.ID,
		"run_number", prevMission.RunNumber,
		"status", prevMission.Status)

	return summary, nil
}

// IsResumedRun returns true if current run was resumed from checkpoint.
// This is determined by checking if a checkpoint exists in the current mission.
func (p *DefaultMissionContextProvider) IsResumedRun() bool {
	return p.currentMission.Checkpoint != nil
}

// determineMemoryContinuity determines the memory continuity state based on run history.
// This helps agents understand the context of their execution:
//   - "first_run": No previous runs exist
//   - "resumed": Current run was resumed from a checkpoint
//   - "new_run_with_history": New run but previous runs exist
func (p *DefaultMissionContextProvider) determineMemoryContinuity(runHistory []*MissionRunSummary) string {
	if p.IsResumedRun() {
		return "resumed"
	}

	// Check if there are other runs besides the current one
	if runHistory == nil || len(runHistory) <= 1 {
		return "first_run"
	}

	return "new_run_with_history"
}

// Ensure DefaultMissionContextProvider implements MissionContextProvider at compile time.
var _ MissionContextProvider = (*DefaultMissionContextProvider)(nil)
