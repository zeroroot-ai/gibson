package checkpoint

import (
	"encoding/json"
	"time"

	"github.com/zero-day-ai/gibson/internal/types"
)

// ApprovalState captures the state of a human-in-the-loop approval mission.
// When a mission requires human approval before proceeding (e.g., before running
// a destructive action or exploit), execution pauses and creates a checkpoint
// with ApprovalState populated.
//
// The approval mission:
//  1. Agent requests approval with details and proposed actions
//  2. Execution pauses, checkpoint created with ApprovalState
//  3. Human reviews request via UI/API
//  4. Human approves, rejects, or modifies the request
//  5. Mission resumes from checkpoint based on approval decision
//
// Approval requests can timeout, returning control to the agent to decide
// whether to proceed, skip, or fail.
type ApprovalState struct {
	// RequestID is a unique identifier for this approval request.
	RequestID string `json:"request_id" msgpack:"request_id"`

	// NodeID is the mission node that requested approval.
	NodeID string `json:"node_id" msgpack:"node_id"`

	// RequestedAt is when the approval was requested.
	RequestedAt time.Time `json:"requested_at" msgpack:"requested_at"`

	// TimeoutAt is when the approval request expires.
	// After this time, the request is considered timed out.
	TimeoutAt time.Time `json:"timeout_at" msgpack:"timeout_at"`

	// Status indicates the current state of the approval request.
	Status ApprovalStatus `json:"status" msgpack:"status"`

	// ApprovalDetails contains the human-readable approval request.
	// This includes context, reasoning, and what needs approval.
	ApprovalDetails ApprovalDetails `json:"approval_details" msgpack:"approval_details"`

	// ProposedActions lists the specific actions being requested for approval.
	// Each action should be clearly described with expected impact.
	ProposedActions []ProposedAction `json:"proposed_actions" msgpack:"proposed_actions"`

	// CurrentFindings contains relevant findings that informed this request.
	// Helps reviewers understand context for the approval decision.
	CurrentFindings []types.ID `json:"current_findings,omitempty" msgpack:"current_findings,omitempty"`

	// Decision captures the approval decision once resolved.
	// Nil until the request is approved, rejected, or modified.
	Decision *ApprovalDecision `json:"decision,omitempty" msgpack:"decision,omitempty"`

	// ResolvedAt is when the approval was resolved (approved/rejected/timed out).
	ResolvedAt *time.Time `json:"resolved_at,omitempty" msgpack:"resolved_at,omitempty"`

	// Metadata provides additional context for the approval request.
	Metadata map[string]any `json:"metadata,omitempty" msgpack:"metadata,omitempty"`
}

// ApprovalStatus represents the state of an approval request.
type ApprovalStatus string

const (
	// ApprovalStatusPending indicates the request is waiting for review.
	ApprovalStatusPending ApprovalStatus = "pending"

	// ApprovalStatusApproved indicates the request was approved.
	ApprovalStatusApproved ApprovalStatus = "approved"

	// ApprovalStatusRejected indicates the request was rejected.
	ApprovalStatusRejected ApprovalStatus = "rejected"

	// ApprovalStatusModified indicates the request was approved with modifications.
	ApprovalStatusModified ApprovalStatus = "modified"

	// ApprovalStatusTimedOut indicates the request expired before being resolved.
	ApprovalStatusTimedOut ApprovalStatus = "timed_out"

	// ApprovalStatusCancelled indicates the request was cancelled.
	ApprovalStatusCancelled ApprovalStatus = "cancelled"
)

// String returns the string representation of ApprovalStatus.
func (s ApprovalStatus) String() string {
	return string(s)
}

// IsResolved returns true if the approval has been resolved (not pending).
func (s ApprovalStatus) IsResolved() bool {
	return s != ApprovalStatusPending
}

// IsPositive returns true if the approval was approved or modified (can proceed).
func (s ApprovalStatus) IsPositive() bool {
	return s == ApprovalStatusApproved || s == ApprovalStatusModified
}

// ApprovalDetails provides context and reasoning for an approval request.
type ApprovalDetails struct {
	// Title is a brief summary of what needs approval.
	Title string `json:"title" msgpack:"title"`

	// Description provides detailed context for the approval request.
	Description string `json:"description" msgpack:"description"`

	// Reasoning explains why approval is needed and what led to this point.
	Reasoning string `json:"reasoning" msgpack:"reasoning"`

	// RiskLevel indicates the risk level of the proposed actions.
	RiskLevel RiskLevel `json:"risk_level" msgpack:"risk_level"`

	// Impact describes the expected impact of approving the request.
	Impact string `json:"impact,omitempty" msgpack:"impact,omitempty"`

	// Alternatives lists alternative approaches that were considered.
	Alternatives []string `json:"alternatives,omitempty" msgpack:"alternatives,omitempty"`

	// EstimatedDuration is how long the actions are expected to take.
	EstimatedDuration time.Duration `json:"estimated_duration,omitempty" msgpack:"estimated_duration,omitempty"`

	// RequiresRollback indicates if these actions can be rolled back.
	RequiresRollback bool `json:"requires_rollback" msgpack:"requires_rollback"`
}

// ProposedAction describes a specific action that needs approval.
type ProposedAction struct {
	// Type indicates the category of action (e.g., "exploit", "scan", "modify").
	Type string `json:"type" msgpack:"type"`

	// Description provides a clear description of the action.
	Description string `json:"description" msgpack:"description"`

	// TargetID identifies what the action will affect.
	TargetID *types.ID `json:"target_id,omitempty" msgpack:"target_id,omitempty"`

	// Parameters contains the action parameters in JSON format.
	// This allows reviewers to see exact parameters that will be used.
	Parameters map[string]any `json:"parameters,omitempty" msgpack:"parameters,omitempty"`

	// RiskLevel indicates the risk level of this specific action.
	RiskLevel RiskLevel `json:"risk_level" msgpack:"risk_level"`

	// Reversible indicates if this action can be undone.
	Reversible bool `json:"reversible" msgpack:"reversible"`

	// Impact describes the expected impact of this action.
	Impact string `json:"impact,omitempty" msgpack:"impact,omitempty"`
}

// ApprovalDecision captures the human's decision on the approval request.
type ApprovalDecision struct {
	// Status is the decision (approved, rejected, modified).
	Status ApprovalStatus `json:"status" msgpack:"status"`

	// ApprovedBy identifies who made the approval decision.
	ApprovedBy string `json:"approved_by" msgpack:"approved_by"`

	// ApprovedAt is when the decision was made.
	ApprovedAt time.Time `json:"approved_at" msgpack:"approved_at"`

	// Comments provides reasoning or instructions from the reviewer.
	Comments string `json:"comments,omitempty" msgpack:"comments,omitempty"`

	// Modifications contains modified parameters if status is Modified.
	// Maps action index to modified parameters.
	Modifications map[int]map[string]any `json:"modifications,omitempty" msgpack:"modifications,omitempty"`

	// Constraints adds additional constraints to the approved actions.
	// For example, time limits, scope restrictions, monitoring requirements.
	Constraints []string `json:"constraints,omitempty" msgpack:"constraints,omitempty"`

	// ExpiresAt is when this approval expires (if time-limited).
	ExpiresAt *time.Time `json:"expires_at,omitempty" msgpack:"expires_at,omitempty"`
}

// RiskLevel indicates the risk level of an action or request.
type RiskLevel string

const (
	// RiskLevelLow indicates minimal risk, unlikely to cause issues.
	RiskLevelLow RiskLevel = "low"

	// RiskLevelMedium indicates moderate risk, could cause minor issues.
	RiskLevelMedium RiskLevel = "medium"

	// RiskLevelHigh indicates significant risk, could cause serious issues.
	RiskLevelHigh RiskLevel = "high"

	// RiskLevelCritical indicates extreme risk, could cause severe damage.
	RiskLevelCritical RiskLevel = "critical"
)

// String returns the string representation of RiskLevel.
func (r RiskLevel) String() string {
	return string(r)
}

// NewApprovalState creates a new approval request state.
func NewApprovalState(nodeID string, timeout time.Duration) *ApprovalState {
	now := time.Now()
	return &ApprovalState{
		RequestID:       generateRequestID(),
		NodeID:          nodeID,
		RequestedAt:     now,
		TimeoutAt:       now.Add(timeout),
		Status:          ApprovalStatusPending,
		ProposedActions: []ProposedAction{},
		CurrentFindings: []types.ID{},
		Metadata:        make(map[string]any),
	}
}

// generateRequestID generates a unique request ID for approval requests.
func generateRequestID() string {
	// Use timestamp-based ID for ordering
	return time.Now().Format("20060102150405") + "-" + types.NewID().String()[:8]
}

// IsResolved returns true if the approval has been resolved.
func (a *ApprovalState) IsResolved() bool {
	return a.Status.IsResolved()
}

// IsTimedOut returns true if the approval request has exceeded its timeout.
func (a *ApprovalState) IsTimedOut() bool {
	return time.Now().After(a.TimeoutAt) && a.Status == ApprovalStatusPending
}

// IsExpired returns true if the approval decision has expired.
func (a *ApprovalState) IsExpired() bool {
	if a.Decision == nil || a.Decision.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*a.Decision.ExpiresAt)
}

// Approve marks the approval as approved with a decision.
func (a *ApprovalState) Approve(approvedBy, comments string) {
	now := time.Now()
	a.Status = ApprovalStatusApproved
	a.Decision = &ApprovalDecision{
		Status:     ApprovalStatusApproved,
		ApprovedBy: approvedBy,
		ApprovedAt: now,
		Comments:   comments,
	}
	a.ResolvedAt = &now
}

// Reject marks the approval as rejected with a decision.
func (a *ApprovalState) Reject(rejectedBy, comments string) {
	now := time.Now()
	a.Status = ApprovalStatusRejected
	a.Decision = &ApprovalDecision{
		Status:     ApprovalStatusRejected,
		ApprovedBy: rejectedBy,
		ApprovedAt: now,
		Comments:   comments,
	}
	a.ResolvedAt = &now
}

// Modify marks the approval as approved with modifications.
func (a *ApprovalState) Modify(approvedBy, comments string, modifications map[int]map[string]any) {
	now := time.Now()
	a.Status = ApprovalStatusModified
	a.Decision = &ApprovalDecision{
		Status:        ApprovalStatusModified,
		ApprovedBy:    approvedBy,
		ApprovedAt:    now,
		Comments:      comments,
		Modifications: modifications,
	}
	a.ResolvedAt = &now
}

// Timeout marks the approval as timed out.
func (a *ApprovalState) Timeout() {
	now := time.Now()
	a.Status = ApprovalStatusTimedOut
	a.ResolvedAt = &now
}

// Cancel marks the approval as cancelled.
func (a *ApprovalState) Cancel() {
	now := time.Now()
	a.Status = ApprovalStatusCancelled
	a.ResolvedAt = &now
}

// AddProposedAction adds an action to the approval request.
func (a *ApprovalState) AddProposedAction(action ProposedAction) {
	if a.ProposedActions == nil {
		a.ProposedActions = []ProposedAction{}
	}
	a.ProposedActions = append(a.ProposedActions, action)
}

// AddFinding adds a finding ID to the approval context.
func (a *ApprovalState) AddFinding(findingID types.ID) {
	if a.CurrentFindings == nil {
		a.CurrentFindings = []types.ID{}
	}
	a.CurrentFindings = append(a.CurrentFindings, findingID)
}

// Clone creates a deep copy of the approval state.
func (a *ApprovalState) Clone() *ApprovalState {
	clone := &ApprovalState{
		RequestID:       a.RequestID,
		NodeID:          a.NodeID,
		RequestedAt:     a.RequestedAt,
		TimeoutAt:       a.TimeoutAt,
		Status:          a.Status,
		ApprovalDetails: a.ApprovalDetails,
		ProposedActions: make([]ProposedAction, len(a.ProposedActions)),
		CurrentFindings: make([]types.ID, len(a.CurrentFindings)),
		Metadata:        make(map[string]any),
	}

	// Copy slices
	copy(clone.ProposedActions, a.ProposedActions)
	copy(clone.CurrentFindings, a.CurrentFindings)

	// Copy metadata
	for k, v := range a.Metadata {
		clone.Metadata[k] = v
	}

	// Copy decision if present
	if a.Decision != nil {
		clone.Decision = &ApprovalDecision{
			Status:        a.Decision.Status,
			ApprovedBy:    a.Decision.ApprovedBy,
			ApprovedAt:    a.Decision.ApprovedAt,
			Comments:      a.Decision.Comments,
			Modifications: make(map[int]map[string]any),
			Constraints:   make([]string, len(a.Decision.Constraints)),
		}
		for k, v := range a.Decision.Modifications {
			clone.Decision.Modifications[k] = v
		}
		copy(clone.Decision.Constraints, a.Decision.Constraints)
		if a.Decision.ExpiresAt != nil {
			expiresAt := *a.Decision.ExpiresAt
			clone.Decision.ExpiresAt = &expiresAt
		}
	}

	// Copy resolved time if present
	if a.ResolvedAt != nil {
		resolvedAt := *a.ResolvedAt
		clone.ResolvedAt = &resolvedAt
	}

	return clone
}

// ToJSON converts the approval state to JSON for serialization.
func (a *ApprovalState) ToJSON() ([]byte, error) {
	return json.Marshal(a)
}

// FromJSON parses approval state from JSON.
func FromJSON(data []byte) (*ApprovalState, error) {
	var state ApprovalState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}
