// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
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

// Lineage metadata keys written on a mission an agent originated from inside
// its own (ADR-0063, gibson#1657). They are plain Metadata entries for the same
// reason internal/engine/mission's origination lineage is: the durable home is
// the Timeline (ADR-0163), whose Append is callable only from the World
// engine's single tick goroutine, so a concurrent gRPC handler cannot write it
// today. The daemon fills these from the RESOLVED parent mission, never from
// the request payload, and overwrites any payload entry of the same name.
const (
	// MetadataParentMissionID is the id of the mission the originating agent
	// was running inside.
	MetadataParentMissionID = "parent_mission_id"
	// MetadataParentMissionRunID is that parent's run id, when it has one, so a
	// child is attributable to one execution of the parent rather than to the
	// definition in general.
	MetadataParentMissionRunID = "parent_mission_run_id"
	// MetadataOriginatingAgent is the name of the agent that asked, taken from
	// the context getHarness already proved live for this mission.
	MetadataOriginatingAgent = "originating_agent"
)

// CreateMissionRequest contains parameters for creating a new mission.
type CreateMissionRequest struct {
	MissionDefinitionJSON string
	MissionDefinitionID   types.ID
	TargetID              types.ID
	ParentMissionID       *types.ID
	ParentDepth           int
	Name                  string
	Description           string
	// Constraints is the constraint set that the caller asks for, in the one
	// constraint type of the platform (ADR-0004). When it is set, it replaces
	// the constraints of the mission definition before the mission is
	// created. Origination treats the two budget fields as a request and
	// writes what the ledger grants.
	Constraints *missionv1.MissionConstraints
	Metadata    map[string]any
	Tags        []string
}

// withRequestedConstraints returns the mission definition JSON with its
// constraints replaced by the constraints of the request. With no requested
// constraints, the definition returns unchanged.
func withRequestedConstraints(definitionJSON string, requested *missionv1.MissionConstraints) (string, error) {
	if requested == nil {
		return definitionJSON, nil
	}
	def, err := mission.UnmarshalDefinitionJSON([]byte(definitionJSON))
	if err != nil {
		return "", fmt.Errorf("apply the requested constraints: %w", err)
	}
	def.Constraints = requested
	body, err := mission.MarshalDefinitionJSON(def)
	if err != nil {
		return "", fmt.Errorf("apply the requested constraints: %w", err)
	}
	return string(body), nil
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
	// MissionStatusSubmitted indicates the mission has been created but not yet started.
	MissionStatusSubmitted MissionStatus = "submitted"
	// MissionStatusWorking indicates the mission is currently executing.
	MissionStatusWorking MissionStatus = "working"
	// MissionStatusCompleted indicates the mission finished successfully.
	MissionStatusCompleted MissionStatus = "completed"
	// MissionStatusFailed indicates the mission finished with an error.
	MissionStatusFailed MissionStatus = "failed"
	// MissionStatusCanceled indicates the mission was canceled before completion.
	MissionStatusCanceled MissionStatus = "canceled"
	// MissionStatusPaused indicates an operator halted the mission.
	MissionStatusPaused MissionStatus = "paused"
	// MissionStatusInputRequired indicates the mission waits for a person.
	MissionStatusInputRequired MissionStatus = "input_required"
)

// MissionRecord represents minimal mission information needed for spawn limits.
// This mirrors fields from mission.Mission but only includes what we need.
type MissionRecord struct {
	ID              types.ID
	ParentMissionID *types.ID
	Depth           int
	Status          MissionStatus
}

// SpawnLimits configures the bound on mission spawning. It holds only the
// depth bound, which stops a runaway agent from recursing without end. There
// is no count limit on child missions or on running missions.
type SpawnLimits struct {
	// MaxMissionDepth is the maximum depth of nested mission chains (default: 3).
	// Depth 0 = root mission, depth 1 = direct child, etc.
	// This prevents infinite recursion in mission spawning patterns.
	MaxMissionDepth int
}

// DefaultSpawnLimits returns the default spawn bound: 3 levels deep (root + 2
// levels of children).
func DefaultSpawnLimits() SpawnLimits {
	return SpawnLimits{
		MaxMissionDepth: 3,
	}
}

// CheckSpawnLimits verifies that spawning a new child of missionID would not
// exceed the mission depth bound. It returns nil when the child may spawn, or
// an ErrMissionDepthLimitExceeded error.
func CheckSpawnLimits(ctx context.Context, lister MissionLister, missionID types.ID, limits SpawnLimits) error {
	newChildDepth := GetMissionDepth(ctx, lister, missionID) + 1
	if newChildDepth >= limits.MaxMissionDepth {
		return types.NewError(
			ErrMissionDepthLimitExceeded,
			fmt.Sprintf("mission depth limit would be exceeded (new depth: %d, limit: %d)",
				newChildDepth, limits.MaxMissionDepth),
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
