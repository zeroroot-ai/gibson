package plan

import (
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// StepResult represents the comprehensive outcome of executing a single step in a plan.
// This provides full execution details including findings, errors, and timing information.
type StepResult struct {
	StepID      types.ID        `json:"step_id"`
	Status      StepStatus      `json:"status"`
	Output      map[string]any  `json:"output,omitempty"`
	Error       *StepError      `json:"error,omitempty"`
	Findings    []agent.Finding `json:"findings,omitempty"`
	Duration    time.Duration   `json:"duration"`
	StartedAt   time.Time       `json:"started_at"`
	CompletedAt time.Time       `json:"completed_at"`
	Metadata    map[string]any  `json:"metadata,omitempty"`
}

// StepError represents an error that occurred during step execution
type StepError struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
	Cause   error          `json:"-"`
}

// Error implements the error interface for StepError
func (e *StepError) Error() string {
	if e == nil {
		return ""
	}
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (caused by: %v)", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// PlanResult represents the overall outcome of executing a plan
type PlanResult struct {
	PlanID        types.ID        `json:"plan_id"`
	Status        PlanStatus      `json:"status"`
	StepResults   []StepResult    `json:"step_results"`
	Findings      []agent.Finding `json:"findings,omitempty"`
	TotalDuration time.Duration   `json:"total_duration"`
	Error         *PlanError      `json:"error,omitempty"`
}

// PlanErrorCode represents the type of error that occurred during plan execution
type PlanErrorCode string

const (
	ErrPlanNotApproved      PlanErrorCode = "plan_not_approved"
	ErrPlanGenerationFailed PlanErrorCode = "plan_generation_failed"
	ErrStepExecutionFailed  PlanErrorCode = "step_execution_failed"
	ErrStepTimeout          PlanErrorCode = "step_timeout"
	ErrApprovalTimeout      PlanErrorCode = "approval_timeout"
	ErrApprovalDenied       PlanErrorCode = "approval_denied"
	ErrGuardrailBlocked     PlanErrorCode = "guardrail_blocked"
	ErrInvalidPlan          PlanErrorCode = "invalid_plan"
	ErrDependencyFailed     PlanErrorCode = "dependency_failed"
)

// PlanError represents an error that occurred during plan execution
type PlanError struct {
	Code    PlanErrorCode `json:"code"`
	Message string        `json:"message"`
	StepID  *types.ID     `json:"step_id,omitempty"`
	Cause   error         `json:"-"`
}

// Error implements the error interface for PlanError
func (e *PlanError) Error() string {
	if e == nil {
		return ""
	}

	var stepInfo string
	if e.StepID != nil {
		stepInfo = fmt.Sprintf(" (step: %s)", e.StepID.String())
	}

	if e.Cause != nil {
		return fmt.Sprintf("%s: %s%s (caused by: %v)", e.Code, e.Message, stepInfo, e.Cause)
	}
	return fmt.Sprintf("%s: %s%s", e.Code, e.Message, stepInfo)
}

// Unwrap implements the error unwrapping interface for PlanError
func (e *PlanError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// NewPlanError creates a new PlanError with the given code, message, and cause
func NewPlanError(code PlanErrorCode, message string, cause error) *PlanError {
	return &PlanError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}
