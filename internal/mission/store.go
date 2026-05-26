package mission

import (
	"context"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/types"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// MissionStore provides persistence for Mission entities.
type MissionStore interface {
	// Mission instance methods (Redis-backed)

	// Save persists a new mission to the database
	Save(ctx context.Context, mission *Mission) error

	// Get retrieves a mission by ID
	Get(ctx context.Context, id types.ID) (*Mission, error)

	// GetByName retrieves a mission by name
	GetByName(ctx context.Context, name string) (*Mission, error)

	// List retrieves missions with optional filtering
	List(ctx context.Context, filter *MissionFilter) ([]*Mission, error)

	// Update modifies an existing mission
	Update(ctx context.Context, mission *Mission) error

	// UpdateStatus updates only the status field of a mission
	UpdateStatus(ctx context.Context, id types.ID, status MissionStatus) error

	// UpdateProgress updates only the progress field of a mission
	UpdateProgress(ctx context.Context, id types.ID, progress float64) error

	// Delete soft-deletes a mission (only terminal states)
	Delete(ctx context.Context, id types.ID) error

	// GetByTarget retrieves all missions for a specific target
	GetByTarget(ctx context.Context, targetID types.ID) ([]*Mission, error)

	// GetActive retrieves all active missions (running or paused)
	GetActive(ctx context.Context) ([]*Mission, error)

	// SaveCheckpoint persists a mission checkpoint for resume capability
	SaveCheckpoint(ctx context.Context, missionID types.ID, checkpoint *MissionCheckpoint) error

	// Count returns the total number of missions matching the filter
	Count(ctx context.Context, filter *MissionFilter) (int, error)

	// GetByNameAndStatus retrieves a mission by name and status
	GetByNameAndStatus(ctx context.Context, name string, status MissionStatus) (*Mission, error)

	// ListByName retrieves all missions with the given name, ordered by run number descending
	ListByName(ctx context.Context, name string, limit int) ([]*Mission, error)

	// GetLatestByName retrieves the most recent mission with the given name
	GetLatestByName(ctx context.Context, name string) (*Mission, error)

	// IncrementRunNumber atomically increments and returns the next run number for a mission name
	IncrementRunNumber(ctx context.Context, name string) (int, error)

	// FindOrCreateByName looks up a mission by name, or creates it if it doesn't exist.
	// This ensures missions have stable IDs across multiple runs.
	// Returns the mission and a boolean indicating if it was created (true) or found (false).
	FindOrCreateByName(ctx context.Context, mission *Mission) (*Mission, bool, error)

	// Mission definition methods (Redis-backed)

	// CreateDefinition stores a new mission definition in Redis.
	// Returns error if a definition with the same name already exists.
	CreateDefinition(ctx context.Context, def *missionv1.MissionDefinition) error

	// GetDefinition retrieves a mission definition by name from Redis.
	// Returns nil, nil if not found.
	GetDefinition(ctx context.Context, name string) (*missionv1.MissionDefinition, error)

	// ListDefinitions returns all installed mission definitions from Redis.
	ListDefinitions(ctx context.Context) ([]*missionv1.MissionDefinition, error)

	// UpdateDefinition updates an existing mission definition in Redis.
	// Returns error if the definition does not exist.
	UpdateDefinition(ctx context.Context, def *missionv1.MissionDefinition) error

	// DeleteDefinition removes a mission definition from Redis.
	// Returns error if the definition does not exist.
	DeleteDefinition(ctx context.Context, name string) error
}

// MissionFilter provides filtering options for mission queries.
type MissionFilter struct {
	// Status filters by mission status (include only this status)
	Status *MissionStatus

	// ExcludeStatus filters out missions with these statuses
	ExcludeStatus []MissionStatus

	// TargetID filters by target
	TargetID *types.ID

	// MissionDefinitionID filters by mission
	MissionDefinitionID *types.ID

	// CreatedAfter filters missions created after this time
	CreatedAfter *time.Time

	// CreatedBefore filters missions created before this time
	CreatedBefore *time.Time

	// Limit limits the number of results
	Limit int

	// Offset skips the first N results
	Offset int

	// SearchText performs full-text search on name and description
	SearchText *string
}

// NewMissionFilter creates a new empty filter with default pagination.
func NewMissionFilter() *MissionFilter {
	return &MissionFilter{
		Limit:  100,
		Offset: 0,
	}
}

// WithStatus filters by mission status.
func (f *MissionFilter) WithStatus(status MissionStatus) *MissionFilter {
	f.Status = &status
	return f
}

// WithTarget filters by target ID.
func (f *MissionFilter) WithTarget(targetID types.ID) *MissionFilter {
	f.TargetID = &targetID
	return f
}

// WithMission filters by mission ID.
func (f *MissionFilter) WithMission(missionDefinitionID types.ID) *MissionFilter {
	f.MissionDefinitionID = &missionDefinitionID
	return f
}

// WithDateRange filters by creation date range.
func (f *MissionFilter) WithDateRange(after, before time.Time) *MissionFilter {
	f.CreatedAfter = &after
	f.CreatedBefore = &before
	return f
}

// WithPagination sets pagination parameters.
func (f *MissionFilter) WithPagination(limit, offset int) *MissionFilter {
	f.Limit = limit
	f.Offset = offset
	return f
}

// Mission Definition Storage errors
var (
	// ErrDefinitionExists is returned when attempting to create a definition that already exists
	ErrDefinitionExists = fmt.Errorf("mission definition already exists")

	// ErrDefinitionNotFound is returned when a definition cannot be found
	ErrDefinitionNotFound = fmt.Errorf("mission definition not found")
)
