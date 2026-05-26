package harness

import (
	"context"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// MissionLister is an interface for querying missions.
// This interface avoids import cycles by defining only what we need
// from the mission.MissionClient without importing the mission package.
type MissionLister interface {
	List(ctx context.Context, filter *MissionFilter) ([]*MissionRecord, error)
}

// MissionCreator is an interface for creating missions.
type MissionCreator interface {
	CreateMission(ctx context.Context, req *CreateMissionRequest) (*MissionInfo, error)
}

// MissionOperator extends MissionLister with mission lifecycle operations.
// This interface allows the harness to manage missions without importing
// the mission package directly, avoiding import cycles.
type MissionOperator interface {
	MissionLister
	MissionCreator
	Run(ctx context.Context, missionID string) error
	GetStatus(ctx context.Context, missionID string) (*MissionStatusInfo, error)
	WaitForCompletion(ctx context.Context, missionID string, timeout time.Duration) (*MissionResultInfo, error)
	Cancel(ctx context.Context, missionID types.ID) error
	GetResults(ctx context.Context, missionID types.ID) (*MissionResultInfo, error)
}

// CreateMissionRequest contains parameters for creating a new mission.
type CreateMissionRequest struct {
	MissionDefinitionJSON string
	MissionDefinitionID   types.ID
	TargetID              types.ID
	ParentMissionID       *types.ID
	ParentDepth           int
	Name                  string
	Description           string
	Constraints           *MissionConstraints
	Metadata              map[string]any
	Tags                  []string
}

// MissionConstraints limits mission execution.
type MissionConstraints struct {
	MaxDuration time.Duration
	MaxTokens   int64
	MaxCost     float64
	MaxFindings int
}

// MissionInfo provides metadata about a mission.
type MissionInfo struct {
	ID              types.ID
	Name            string
	Status          MissionStatus
	TargetID        types.ID
	ParentMissionID *types.ID
	CreatedAt       time.Time
	Tags            []string
}

// MissionStatusInfo mirrors mission.MissionStatusInfo to avoid import cycles.
type MissionStatusInfo struct {
	Status        MissionStatus
	Progress      float64
	Phase         string
	FindingCounts map[string]int
	TokenUsage    int64
	Duration      time.Duration
	Error         string
}

// MissionResultInfo mirrors mission.MissionResult fields needed by harness.
type MissionResultInfo struct {
	MissionID     string
	Status        MissionStatus
	Metrics       *MissionMetricsInfo
	FindingIDs    []string
	MissionResult map[string]any
	Error         string
	CompletedAt   time.Time
}

// MissionMetricsInfo mirrors mission.MissionMetrics fields.
type MissionMetricsInfo struct {
	Duration      time.Duration
	TotalTokens   int64
	TotalFindings int
}

// MissionFilter specifies criteria for listing missions.
// This mirrors mission.MissionFilter but is defined in the harness package
// to avoid import cycles.
type MissionFilter struct {
	Status          *MissionStatus
	TargetID        *types.ID
	ParentMissionID *types.ID
	Limit           int
	Offset          int
}

// MissionStatus represents the lifecycle state of a mission.
type MissionStatus string

const (
	// MissionStatusPending indicates the mission has been created but not yet started.
	MissionStatusPending MissionStatus = "pending"
	// MissionStatusRunning indicates the mission is currently executing.
	MissionStatusRunning MissionStatus = "running"
	// MissionStatusCompleted indicates the mission finished successfully.
	MissionStatusCompleted MissionStatus = "completed"
	// MissionStatusFailed indicates the mission finished with an error.
	MissionStatusFailed MissionStatus = "failed"
	// MissionStatusCancelled indicates the mission was cancelled before completion.
	MissionStatusCancelled MissionStatus = "cancelled"
)

// MissionRecord represents minimal mission information needed for spawn limits.
// This mirrors fields from mission.Mission but only includes what we need.
type MissionRecord struct {
	ID              types.ID
	ParentMissionID *types.ID
	Depth           int
	Status          MissionStatus
}

// SpawnLimits configures mission creation limits to prevent runaway mission spawning.
// These limits are enforced before any mission creation to ensure system stability
// and prevent resource exhaustion from recursive or exponential mission creation patterns.
type SpawnLimits struct {
	// MaxChildMissions is the maximum number of child missions a single parent
	// mission can spawn (default: 10).
	// This prevents a single mission from overwhelming the system with children.
	MaxChildMissions int

	// MaxConcurrentMissions is the maximum number of missions that can be
	// running concurrently system-wide (default: 50).
	// This protects against resource exhaustion from too many parallel missions.
	MaxConcurrentMissions int

	// MaxMissionDepth is the maximum depth of nested mission chains (default: 3).
	// Depth 0 = root mission, depth 1 = direct child, etc.
	// This prevents infinite recursion in mission spawning patterns.
	MaxMissionDepth int
}

// DefaultSpawnLimits returns sensible default values for spawn limits.
// These defaults are designed to allow reasonable mission hierarchies while
// preventing runaway spawning that could destabilize the system.
//
// Default values:
//   - MaxChildMissions: 10 children per parent
//   - MaxConcurrentMissions: 50 concurrent missions system-wide
//   - MaxMissionDepth: 3 levels deep (root + 2 levels of children)
func DefaultSpawnLimits() SpawnLimits {
	return SpawnLimits{
		MaxChildMissions:      10,
		MaxConcurrentMissions: 50,
		MaxMissionDepth:       3,
	}
}

// CheckSpawnLimits verifies that spawning a new mission would not violate any
// configured limits. It checks:
//  1. Child mission count for the current parent
//  2. Mission depth in the hierarchy
//  3. System-wide concurrent running missions
//
// This function can be called by the harness implementation when creating missions.
// It takes a MissionLister interface to query missions, the current missionID,
// and the configured SpawnLimits.
//
// Returns nil if all limits are satisfied, or a descriptive error indicating
// which limit was exceeded.
func CheckSpawnLimits(ctx context.Context, lister MissionLister, missionID types.ID, limits SpawnLimits) error {
	// Check child mission count
	// Query all missions that have this mission as their parent
	children, err := lister.List(ctx, &MissionFilter{
		ParentMissionID: &missionID,
	})
	if err != nil {
		return fmt.Errorf("failed to list child missions: %w", err)
	}

	// Verify we haven't exceeded the maximum number of children per parent
	if len(children) >= limits.MaxChildMissions {
		return types.NewError(
			ErrChildMissionLimitExceeded,
			fmt.Sprintf("mission has reached maximum child limit (%d/%d)",
				len(children), limits.MaxChildMissions),
		)
	}

	// Check mission depth
	// Get the current mission's depth and calculate what the new child's depth would be
	currentDepth := GetMissionDepth(ctx, lister, missionID)
	newChildDepth := currentDepth + 1

	// Check if spawning a child would exceed the maximum depth
	if newChildDepth >= limits.MaxMissionDepth {
		return types.NewError(
			ErrMissionDepthLimitExceeded,
			fmt.Sprintf("mission depth limit would be exceeded (new depth: %d, limit: %d)",
				newChildDepth, limits.MaxMissionDepth),
		)
	}

	// Check concurrent missions
	// Query all missions currently in running state
	runningStatus := MissionStatusRunning
	running, err := lister.List(ctx, &MissionFilter{
		Status: &runningStatus,
	})
	if err != nil {
		return fmt.Errorf("failed to list running missions: %w", err)
	}

	// Verify we haven't exceeded the system-wide concurrent limit
	if len(running) >= limits.MaxConcurrentMissions {
		return types.NewError(
			ErrConcurrentMissionLimitExceeded,
			fmt.Sprintf("concurrent mission limit reached (%d/%d)",
				len(running), limits.MaxConcurrentMissions),
		)
	}

	return nil
}

// GetMissionDepth retrieves the depth of a mission in the hierarchy.
// The depth is stored in each mission record:
//   - Root missions (no parent): depth = 0
//   - Child missions: depth = parent.depth + 1
//
// Returns 0 if the mission cannot be found (safest default for root missions).
func GetMissionDepth(ctx context.Context, lister MissionLister, missionID types.ID) int {
	// Query all missions to find the one matching this ID
	// We use a reasonable limit to avoid excessive memory usage
	allMissions, err := lister.List(ctx, &MissionFilter{
		Limit: 1000, // Reasonable limit
	})
	if err != nil {
		// If we can't query, return 0 (safest default)
		return 0
	}

	// Find our current mission in the list
	for _, m := range allMissions {
		if m.ID == missionID {
			// Return the pre-calculated depth from the mission record
			// The Depth field was added in Phase 2 (tasks 2.1-2.3)
			return m.Depth
		}
	}

	// Mission not found, return 0 (root mission default)
	return 0
}
