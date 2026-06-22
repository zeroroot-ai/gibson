package harness

import (
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// SDK-Compatible Types for Agent Consumption
// These types mirror internal types but use string IDs and are suitable
// for cross-boundary communication with agents.

// MissionExecutionContextSDK provides comprehensive mission execution information to agents.
// This is the agent-facing version of MissionExecutionContext with string-based IDs.
type MissionExecutionContextSDK struct {
	// MissionID is the unique identifier for this mission execution.
	MissionID string `json:"mission_id"`

	// MissionName is the human-readable mission name (same across runs).
	MissionName string `json:"mission_name"`

	// RunNumber is the sequential run number for this mission name.
	RunNumber int `json:"run_number"`

	// IsResumed indicates if this run was resumed from a checkpoint.
	IsResumed bool `json:"is_resumed"`

	// PreviousRunID links to the prior run (empty if this is the first run).
	PreviousRunID string `json:"previous_run_id,omitempty"`

	// PreviousRunStatus is the final status of the previous run (empty if no previous run).
	PreviousRunStatus string `json:"previous_run_status,omitempty"`

	// TotalFindingsAllRuns is the aggregate finding count across all runs of this mission.
	TotalFindingsAllRuns int `json:"total_findings_all_runs"`

	// MemoryContinuity describes memory state: "first_run", "resumed", or "new_run_with_history".
	MemoryContinuity string `json:"memory_continuity"`
}

// MissionRunSummarySDK provides summary information for a single mission run.
// This is the agent-facing version of MissionRunSummary with string-based IDs.
type MissionRunSummarySDK struct {
	// MissionID is the unique identifier for this run.
	MissionID string `json:"mission_id"`

	// RunNumber is the sequential run number.
	RunNumber int `json:"run_number"`

	// Status is the final status of this run.
	Status string `json:"status"`

	// FindingsCount is the number of findings discovered during this run.
	FindingsCount int `json:"findings_count"`

	// CreatedAt is when this run was created.
	CreatedAt time.Time `json:"created_at"`

	// CompletedAt is when this run finished (nil if still running or never started).
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// Helper functions to convert between internal and SDK types

// idPtrToString converts a types.ID pointer to a string, returning empty string if nil.
func idPtrToString(id *types.ID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

// convertToSDKContext converts internal MissionExecutionContext to SDK version.
func convertToSDKContext(internal *MissionExecutionContext) MissionExecutionContextSDK {
	return MissionExecutionContextSDK{
		MissionID:            internal.MissionID.String(),
		MissionName:          internal.MissionName,
		RunNumber:            internal.RunNumber,
		IsResumed:            internal.IsResumed,
		PreviousRunID:        idPtrToString(internal.PreviousRunID),
		PreviousRunStatus:    internal.PreviousRunStatus,
		TotalFindingsAllRuns: internal.TotalFindingsAllRuns,
		MemoryContinuity:     internal.MemoryContinuity,
	}
}

// convertToSDKRunSummary converts internal MissionRunSummary to SDK version.
func convertToSDKRunSummary(internal *MissionRunSummary) MissionRunSummarySDK {
	return MissionRunSummarySDK{
		MissionID:     internal.MissionID.String(),
		RunNumber:     internal.RunNumber,
		Status:        internal.Status,
		FindingsCount: internal.FindingsCount,
		CreatedAt:     internal.CreatedAt,
		CompletedAt:   internal.CompletedAt,
	}
}
