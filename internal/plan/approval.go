package plan

import (
	"context"
	"time"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// ApprovalService defines the interface for managing approval missions
// in the Gibson framework. It handles requesting approvals for high-risk
// steps, retrieving pending approvals, and submitting decisions.
type ApprovalService interface {
	// RequestApproval submits a new approval request and waits for a decision.
	// Returns an ApprovalDecision once approved or rejected, or an error on timeout/failure.
	RequestApproval(ctx context.Context, request ApprovalRequest) (ApprovalDecision, error)

	// GetPendingApprovals retrieves all approval requests matching the filter criteria.
	// Returns a list of pending approval requests that await decisions.
	GetPendingApprovals(ctx context.Context, filter ApprovalFilter) ([]ApprovalRequest, error)

	// SubmitDecision records an approval decision for a specific request.
	// The requestID must match an existing pending approval request.
	SubmitDecision(ctx context.Context, requestID types.ID, decision ApprovalDecision) error
}

// ApprovalRequest represents a request for human approval before executing
// a high-risk step in an execution plan. It includes all contextual information
// needed to make an informed decision.
type ApprovalRequest struct {
	// ID uniquely identifies this approval request
	ID types.ID `json:"id"`

	// PlanID identifies the execution plan containing the step
	PlanID types.ID `json:"plan_id"`

	// StepID identifies the specific step requiring approval
	StepID types.ID `json:"step_id"`

	// StepDetails contains the complete step configuration
	StepDetails ExecutionStep `json:"step_details"`

	// RiskAssessment provides the risk evaluation for this step
	RiskAssessment RiskAssessment `json:"risk_assessment"`

	// PlanContext provides broader context about the plan execution
	PlanContext PlanContext `json:"plan_context"`

	// RequestedAt is when the approval request was created
	RequestedAt time.Time `json:"requested_at"`

	// ExpiresAt is when this approval request expires if not decided
	ExpiresAt time.Time `json:"expires_at"`
}

// IsExpired checks if the approval request has exceeded its expiration time.
// Returns true if the current time is past ExpiresAt.
func (a *ApprovalRequest) IsExpired() bool {
	return time.Now().After(a.ExpiresAt)
}

// ApprovalDecision represents a human decision on an approval request.
// It captures who approved/rejected, when, and the reasoning.
type ApprovalDecision struct {
	// Approved indicates whether the step was approved (true) or rejected (false)
	Approved bool `json:"approved"`

	// ApproverID identifies who made this decision (user ID, email, etc.)
	ApproverID string `json:"approver_id"`

	// Reason provides optional explanation for the decision
	Reason string `json:"reason,omitempty"`

	// DecidedAt is when the decision was made
	DecidedAt time.Time `json:"decided_at"`
}

// IsApproved returns true if this decision approves the requested action.
// This is a convenience method equivalent to checking the Approved field.
func (d *ApprovalDecision) IsApproved() bool {
	return d.Approved
}

// ApprovalFilter specifies criteria for filtering approval requests.
// All non-nil fields must match for a request to be included in results.
type ApprovalFilter struct {
	// PlanID filters to approvals for a specific plan
	PlanID *types.ID `json:"plan_id,omitempty"`

	// StepID filters to approvals for a specific step
	StepID *types.ID `json:"step_id,omitempty"`

	// Status filters by approval status (e.g., "pending", "approved", "rejected")
	Status *string `json:"status,omitempty"`
}

// PlanContext provides contextual information about a plan execution
// to help approvers understand what they're approving within the broader
// mission and execution flow.
type PlanContext struct {
	// PlanID uniquely identifies the execution plan
	PlanID types.ID `json:"plan_id"`

	// PlanName is a human-readable name for the plan
	PlanName string `json:"plan_name,omitempty"`

	// AgentName identifies which agent generated or is executing the plan
	AgentName string `json:"agent_name"`

	// MissionID identifies the broader mission this plan belongs to
	MissionID types.ID `json:"mission_id"`

	// TotalSteps is the total number of steps in the plan
	TotalSteps int `json:"total_steps"`

	// CurrentStep is the sequence number of the step requiring approval
	CurrentStep int `json:"current_step"`
}
