package plan

import (
	"time"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// PlanStatus represents the current status of an execution plan.
type PlanStatus string

const (
	// PlanStatusDraft indicates the plan is being drafted and not yet ready for approval.
	PlanStatusDraft PlanStatus = "draft"

	// PlanStatusPendingApproval indicates the plan is awaiting approval.
	PlanStatusPendingApproval PlanStatus = "pending_approval"

	// PlanStatusApproved indicates the plan has been approved and is ready for execution.
	PlanStatusApproved PlanStatus = "approved"

	// PlanStatusRejected indicates the plan has been rejected and will not be executed.
	PlanStatusRejected PlanStatus = "rejected"

	// PlanStatusExecuting indicates the plan is currently being executed.
	PlanStatusExecuting PlanStatus = "executing"

	// PlanStatusCompleted indicates the plan has completed successfully.
	PlanStatusCompleted PlanStatus = "completed"

	// PlanStatusFailed indicates the plan execution has failed.
	PlanStatusFailed PlanStatus = "failed"

	// PlanStatusCancelled indicates the plan was cancelled during execution.
	PlanStatusCancelled PlanStatus = "cancelled"
)

// String returns the string representation of the plan status.
func (s PlanStatus) String() string {
	return string(s)
}

// IsTerminal returns true if the status represents a terminal state
// (completed, failed, rejected, or cancelled).
func (s PlanStatus) IsTerminal() bool {
	switch s {
	case PlanStatusCompleted, PlanStatusFailed, PlanStatusRejected, PlanStatusCancelled:
		return true
	default:
		return false
	}
}

// CanTransitionTo validates whether the current status can transition to the target status.
// It enforces the following state machine:
//
//	draft -> pending_approval
//	pending_approval -> approved, rejected
//	approved -> executing
//	executing -> completed, failed, cancelled
//
// Terminal states (completed, failed, rejected, cancelled) cannot transition to any other state.
func (s PlanStatus) CanTransitionTo(target PlanStatus) bool {
	// Terminal states cannot transition
	if s.IsTerminal() {
		return false
	}

	// Define allowed transitions
	allowedTransitions := map[PlanStatus][]PlanStatus{
		PlanStatusDraft: {
			PlanStatusPendingApproval,
		},
		PlanStatusPendingApproval: {
			PlanStatusApproved,
			PlanStatusRejected,
		},
		PlanStatusApproved: {
			PlanStatusExecuting,
		},
		PlanStatusExecuting: {
			PlanStatusCompleted,
			PlanStatusFailed,
			PlanStatusCancelled,
		},
	}

	// Check if the transition is allowed
	allowedTargets, exists := allowedTransitions[s]
	if !exists {
		return false
	}

	for _, allowedTarget := range allowedTargets {
		if allowedTarget == target {
			return true
		}
	}

	return false
}

// ExecutionPlan represents a complete execution plan for an AI agent mission.
// It contains all the steps, risk assessments, and metadata needed to execute
// a mission safely and effectively.
type ExecutionPlan struct {
	// ID is the unique identifier for this execution plan.
	ID types.ID `json:"id"`

	// MissionID is the unique identifier for the mission this plan belongs to.
	MissionID types.ID `json:"mission_id"`

	// AgentName is the name of the agent that will execute this plan.
	AgentName string `json:"agent_name"`

	// Status represents the current status of the plan.
	Status PlanStatus `json:"status"`

	// Steps contains the ordered list of execution steps for this plan.
	// This will be defined in step.go.
	Steps []ExecutionStep `json:"steps"`

	// RiskSummary contains the aggregated risk assessment for this plan.
	// This will be defined in risk.go.
	RiskSummary *PlanRiskSummary `json:"risk_summary,omitempty"`

	// Metadata contains additional custom metadata for the plan.
	// This can be used to store agent-specific or mission-specific information.
	Metadata map[string]any `json:"metadata,omitempty"`

	// CreatedAt is the timestamp when the plan was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is the timestamp when the plan was last updated.
	UpdatedAt time.Time `json:"updated_at"`

	// StartedAt is the timestamp when plan execution began.
	// This is nil until the plan starts executing.
	StartedAt *time.Time `json:"started_at,omitempty"`

	// CompletedAt is the timestamp when plan execution completed.
	// This is nil until the plan reaches a terminal state.
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}
