package plan

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// TestPlanStatus_IsTerminal tests the IsTerminal method for all 8 plan statuses
func TestPlanStatus_IsTerminal(t *testing.T) {
	tests := []struct {
		name     string
		status   PlanStatus
		expected bool
	}{
		{
			name:     "draft is not terminal",
			status:   PlanStatusDraft,
			expected: false,
		},
		{
			name:     "pending_approval is not terminal",
			status:   PlanStatusPendingApproval,
			expected: false,
		},
		{
			name:     "approved is not terminal",
			status:   PlanStatusApproved,
			expected: false,
		},
		{
			name:     "executing is not terminal",
			status:   PlanStatusExecuting,
			expected: false,
		},
		{
			name:     "completed is terminal",
			status:   PlanStatusCompleted,
			expected: true,
		},
		{
			name:     "failed is terminal",
			status:   PlanStatusFailed,
			expected: true,
		},
		{
			name:     "rejected is terminal",
			status:   PlanStatusRejected,
			expected: true,
		},
		{
			name:     "cancelled is terminal",
			status:   PlanStatusCancelled,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.status.IsTerminal()
			assert.Equal(t, tt.expected, got, "IsTerminal() for %s", tt.status)
		})
	}
}

// TestPlanStatus_CanTransitionTo_ValidTransitions tests valid state transitions
func TestPlanStatus_CanTransitionTo_ValidTransitions(t *testing.T) {
	tests := []struct {
		name  string
		from  PlanStatus
		to    PlanStatus
		canDo bool
	}{
		// Valid transitions from draft
		{
			name:  "draft to pending_approval",
			from:  PlanStatusDraft,
			to:    PlanStatusPendingApproval,
			canDo: true,
		},
		// Valid transitions from pending_approval
		{
			name:  "pending_approval to approved",
			from:  PlanStatusPendingApproval,
			to:    PlanStatusApproved,
			canDo: true,
		},
		{
			name:  "pending_approval to rejected",
			from:  PlanStatusPendingApproval,
			to:    PlanStatusRejected,
			canDo: true,
		},
		// Valid transitions from approved
		{
			name:  "approved to executing",
			from:  PlanStatusApproved,
			to:    PlanStatusExecuting,
			canDo: true,
		},
		// Valid transitions from executing
		{
			name:  "executing to completed",
			from:  PlanStatusExecuting,
			to:    PlanStatusCompleted,
			canDo: true,
		},
		{
			name:  "executing to failed",
			from:  PlanStatusExecuting,
			to:    PlanStatusFailed,
			canDo: true,
		},
		{
			name:  "executing to cancelled",
			from:  PlanStatusExecuting,
			to:    PlanStatusCancelled,
			canDo: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.from.CanTransitionTo(tt.to)
			assert.Equal(t, tt.canDo, got, "CanTransitionTo from %s to %s", tt.from, tt.to)
		})
	}
}

// TestPlanStatus_CanTransitionTo_InvalidTransitions tests invalid state transitions
func TestPlanStatus_CanTransitionTo_InvalidTransitions(t *testing.T) {
	tests := []struct {
		name string
		from PlanStatus
		to   PlanStatus
	}{
		// Invalid transitions from draft
		{
			name: "draft to approved",
			from: PlanStatusDraft,
			to:   PlanStatusApproved,
		},
		{
			name: "draft to executing",
			from: PlanStatusDraft,
			to:   PlanStatusExecuting,
		},
		{
			name: "draft to completed",
			from: PlanStatusDraft,
			to:   PlanStatusCompleted,
		},
		// Invalid transitions from pending_approval
		{
			name: "pending_approval to executing",
			from: PlanStatusPendingApproval,
			to:   PlanStatusExecuting,
		},
		{
			name: "pending_approval to completed",
			from: PlanStatusPendingApproval,
			to:   PlanStatusCompleted,
		},
		// Invalid transitions from approved
		{
			name: "approved to draft",
			from: PlanStatusApproved,
			to:   PlanStatusDraft,
		},
		{
			name: "approved to pending_approval",
			from: PlanStatusApproved,
			to:   PlanStatusPendingApproval,
		},
		{
			name: "approved to completed",
			from: PlanStatusApproved,
			to:   PlanStatusCompleted,
		},
		// Invalid transitions from executing
		{
			name: "executing to draft",
			from: PlanStatusExecuting,
			to:   PlanStatusDraft,
		},
		{
			name: "executing to approved",
			from: PlanStatusExecuting,
			to:   PlanStatusApproved,
		},
		// Terminal states cannot transition to anything
		{
			name: "completed to draft",
			from: PlanStatusCompleted,
			to:   PlanStatusDraft,
		},
		{
			name: "completed to executing",
			from: PlanStatusCompleted,
			to:   PlanStatusExecuting,
		},
		{
			name: "failed to draft",
			from: PlanStatusFailed,
			to:   PlanStatusDraft,
		},
		{
			name: "failed to executing",
			from: PlanStatusFailed,
			to:   PlanStatusExecuting,
		},
		{
			name: "rejected to approved",
			from: PlanStatusRejected,
			to:   PlanStatusApproved,
		},
		{
			name: "rejected to executing",
			from: PlanStatusRejected,
			to:   PlanStatusExecuting,
		},
		{
			name: "cancelled to executing",
			from: PlanStatusCancelled,
			to:   PlanStatusExecuting,
		},
		{
			name: "cancelled to completed",
			from: PlanStatusCancelled,
			to:   PlanStatusCompleted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.from.CanTransitionTo(tt.to)
			assert.False(t, got, "CanTransitionTo should be false from %s to %s", tt.from, tt.to)
		})
	}
}

// TestPlanStatus_String tests the String method for all statuses
func TestPlanStatus_String(t *testing.T) {
	tests := []struct {
		name     string
		status   PlanStatus
		expected string
	}{
		{
			name:     "draft status",
			status:   PlanStatusDraft,
			expected: "draft",
		},
		{
			name:     "pending_approval status",
			status:   PlanStatusPendingApproval,
			expected: "pending_approval",
		},
		{
			name:     "approved status",
			status:   PlanStatusApproved,
			expected: "approved",
		},
		{
			name:     "rejected status",
			status:   PlanStatusRejected,
			expected: "rejected",
		},
		{
			name:     "executing status",
			status:   PlanStatusExecuting,
			expected: "executing",
		},
		{
			name:     "completed status",
			status:   PlanStatusCompleted,
			expected: "completed",
		},
		{
			name:     "failed status",
			status:   PlanStatusFailed,
			expected: "failed",
		},
		{
			name:     "cancelled status",
			status:   PlanStatusCancelled,
			expected: "cancelled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.status.String()
			assert.Equal(t, tt.expected, got)
		})
	}
}

// TestStepError_Error tests the StepError.Error method
func TestStepError_Error(t *testing.T) {
	tests := []struct {
		name      string
		stepError *StepError
		expected  string
	}{
		{
			name: "error with code and message",
			stepError: &StepError{
				Code:    "TOOL_EXEC_FAILED",
				Message: "failed to execute tool",
			},
			expected: "TOOL_EXEC_FAILED: failed to execute tool",
		},
		{
			name: "error with cause",
			stepError: &StepError{
				Code:    "PLUGIN_ERROR",
				Message: "plugin execution failed",
				Cause:   errors.New("connection timeout"),
			},
			expected: "PLUGIN_ERROR: plugin execution failed (caused by: connection timeout)",
		},
		{
			name: "error with details and cause",
			stepError: &StepError{
				Code:    "VALIDATION_ERROR",
				Message: "invalid input",
				Details: map[string]any{
					"field": "username",
					"value": "",
				},
				Cause: errors.New("empty field"),
			},
			expected: "VALIDATION_ERROR: invalid input (caused by: empty field)",
		},
		{
			name:      "nil error",
			stepError: nil,
			expected:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.stepError.Error()
			assert.Equal(t, tt.expected, got)
		})
	}
}

// TestPlanError_Error tests the PlanError.Error method
func TestPlanError_Error(t *testing.T) {
	stepID := types.NewID()

	tests := []struct {
		name      string
		planError *PlanError
		expected  string
	}{
		{
			name: "error with code and message",
			planError: &PlanError{
				Code:    ErrPlanNotApproved,
				Message: "plan requires approval",
			},
			expected: "plan_not_approved: plan requires approval",
		},
		{
			name: "error with step ID",
			planError: &PlanError{
				Code:    ErrStepExecutionFailed,
				Message: "step execution failed",
				StepID:  &stepID,
			},
			expected: "step_execution_failed: step execution failed (step: " + stepID.String() + ")",
		},
		{
			name: "error with cause",
			planError: &PlanError{
				Code:    ErrStepTimeout,
				Message: "step timed out",
				Cause:   errors.New("context deadline exceeded"),
			},
			expected: "step_timeout: step timed out (caused by: context deadline exceeded)",
		},
		{
			name: "error with step ID and cause",
			planError: &PlanError{
				Code:    ErrDependencyFailed,
				Message: "dependency step failed",
				StepID:  &stepID,
				Cause:   errors.New("step 1 failed"),
			},
			expected: "dependency_failed: dependency step failed (step: " + stepID.String() + ") (caused by: step 1 failed)",
		},
		{
			name:      "nil error",
			planError: nil,
			expected:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.planError.Error()
			assert.Equal(t, tt.expected, got)
		})
	}
}

// TestPlanError_Unwrap tests the PlanError.Unwrap method
func TestPlanError_Unwrap(t *testing.T) {
	tests := []struct {
		name      string
		planError *PlanError
		wantNil   bool
	}{
		{
			name: "error with cause returns cause",
			planError: &PlanError{
				Code:    ErrStepExecutionFailed,
				Message: "step failed",
				Cause:   errors.New("underlying error"),
			},
			wantNil: false,
		},
		{
			name: "error without cause returns nil",
			planError: &PlanError{
				Code:    ErrPlanNotApproved,
				Message: "not approved",
			},
			wantNil: true,
		},
		{
			name:      "nil error returns nil",
			planError: nil,
			wantNil:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.planError.Unwrap()
			if tt.wantNil {
				assert.Nil(t, got)
			} else {
				assert.NotNil(t, got)
			}
		})
	}
}

// TestNewPlanError tests the NewPlanError constructor
func TestNewPlanError(t *testing.T) {
	tests := []struct {
		name        string
		code        PlanErrorCode
		message     string
		cause       error
		validateErr func(t *testing.T, err *PlanError)
	}{
		{
			name:    "create error without cause",
			code:    ErrPlanNotApproved,
			message: "approval required",
			cause:   nil,
			validateErr: func(t *testing.T, err *PlanError) {
				assert.Equal(t, ErrPlanNotApproved, err.Code)
				assert.Equal(t, "approval required", err.Message)
				assert.Nil(t, err.Cause)
				assert.Nil(t, err.StepID)
			},
		},
		{
			name:    "create error with cause",
			code:    ErrStepExecutionFailed,
			message: "execution failed",
			cause:   errors.New("network error"),
			validateErr: func(t *testing.T, err *PlanError) {
				assert.Equal(t, ErrStepExecutionFailed, err.Code)
				assert.Equal(t, "execution failed", err.Message)
				assert.NotNil(t, err.Cause)
				assert.Equal(t, "network error", err.Cause.Error())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewPlanError(tt.code, tt.message, tt.cause)
			require.NotNil(t, err)
			tt.validateErr(t, err)
		})
	}
}

// TestPlanErrorCode_Constants verifies all PlanErrorCode constants
func TestPlanErrorCode_Constants(t *testing.T) {
	tests := []struct {
		name     string
		code     PlanErrorCode
		expected string
	}{
		{
			name:     "plan not approved",
			code:     ErrPlanNotApproved,
			expected: "plan_not_approved",
		},
		{
			name:     "plan generation failed",
			code:     ErrPlanGenerationFailed,
			expected: "plan_generation_failed",
		},
		{
			name:     "step execution failed",
			code:     ErrStepExecutionFailed,
			expected: "step_execution_failed",
		},
		{
			name:     "step timeout",
			code:     ErrStepTimeout,
			expected: "step_timeout",
		},
		{
			name:     "approval timeout",
			code:     ErrApprovalTimeout,
			expected: "approval_timeout",
		},
		{
			name:     "approval denied",
			code:     ErrApprovalDenied,
			expected: "approval_denied",
		},
		{
			name:     "guardrail blocked",
			code:     ErrGuardrailBlocked,
			expected: "guardrail_blocked",
		},
		{
			name:     "invalid plan",
			code:     ErrInvalidPlan,
			expected: "invalid_plan",
		},
		{
			name:     "dependency failed",
			code:     ErrDependencyFailed,
			expected: "dependency_failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.code))
		})
	}
}

// TestExecutionPlan_JSONRoundTrip tests JSON serialization and deserialization
func TestExecutionPlan_JSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	startedAt := now.Add(1 * time.Hour)
	completedAt := now.Add(2 * time.Hour)

	tests := []struct {
		name string
		plan ExecutionPlan
	}{
		{
			name: "minimal plan",
			plan: ExecutionPlan{
				ID:        types.NewID(),
				MissionID: types.NewID(),
				AgentName: "test-agent",
				Status:    PlanStatusDraft,
				Steps:     []ExecutionStep{},
				CreatedAt: now,
				UpdatedAt: now,
			},
		},
		{
			name: "plan with all fields",
			plan: ExecutionPlan{
				ID:        types.NewID(),
				MissionID: types.NewID(),
				AgentName: "full-agent",
				Status:    PlanStatusCompleted,
				Steps:     []ExecutionStep{},
				RiskSummary: &PlanRiskSummary{
					OverallLevel:     RiskLevelMedium,
					HighRiskSteps:    1,
					CriticalSteps:    0,
					ApprovalRequired: false,
				},
				Metadata: map[string]any{
					"version": "1.0",
					"tags":    []string{"test", "integration"},
				},
				CreatedAt:   now,
				UpdatedAt:   now,
				StartedAt:   &startedAt,
				CompletedAt: &completedAt,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to JSON
			jsonData, err := json.Marshal(tt.plan)
			require.NoError(t, err)

			// Unmarshal back
			var decoded ExecutionPlan
			err = json.Unmarshal(jsonData, &decoded)
			require.NoError(t, err)

			// Verify fields
			assert.Equal(t, tt.plan.ID, decoded.ID)
			assert.Equal(t, tt.plan.MissionID, decoded.MissionID)
			assert.Equal(t, tt.plan.AgentName, decoded.AgentName)
			assert.Equal(t, tt.plan.Status, decoded.Status)
			assert.Equal(t, len(tt.plan.Steps), len(decoded.Steps))
			assert.Equal(t, tt.plan.CreatedAt.Unix(), decoded.CreatedAt.Unix())
			assert.Equal(t, tt.plan.UpdatedAt.Unix(), decoded.UpdatedAt.Unix())

			// Verify optional fields
			if tt.plan.StartedAt != nil {
				require.NotNil(t, decoded.StartedAt)
				assert.Equal(t, tt.plan.StartedAt.Unix(), decoded.StartedAt.Unix())
			} else {
				assert.Nil(t, decoded.StartedAt)
			}

			if tt.plan.CompletedAt != nil {
				require.NotNil(t, decoded.CompletedAt)
				assert.Equal(t, tt.plan.CompletedAt.Unix(), decoded.CompletedAt.Unix())
			} else {
				assert.Nil(t, decoded.CompletedAt)
			}
		})
	}
}

// TestExecutionStep_JSONRoundTrip tests JSON serialization and deserialization
func TestExecutionStep_JSONRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		step ExecutionStep
	}{
		{
			name: "tool step",
			step: ExecutionStep{
				ID:          types.NewID(),
				Sequence:    1,
				Type:        StepTypeTool,
				Name:        "scan-ports",
				Description: "Scan target ports",
				ToolName:    "nmap",
				ToolInput: map[string]any{
					"target": "192.168.1.1",
					"ports":  "1-1000",
				},
				RiskLevel:        RiskLevelMedium,
				RequiresApproval: false,
				Status:           StepStatusPending,
			},
		},
		{
			name: "plugin step",
			step: ExecutionStep{
				ID:           types.NewID(),
				Sequence:     2,
				Type:         StepTypePlugin,
				Name:         "analyze-results",
				Description:  "Analyze scan results",
				PluginName:   "analyzer",
				PluginMethod: "analyze",
				PluginParams: map[string]any{
					"threshold": 0.8,
				},
				RiskLevel:        RiskLevelLow,
				RequiresApproval: false,
				Status:           StepStatusCompleted,
			},
		},
		{
			name: "step with dependencies",
			step: ExecutionStep{
				ID:               types.NewID(),
				Sequence:         3,
				Type:             StepTypeTool,
				Name:             "exploit",
				Description:      "Exploit vulnerability",
				ToolName:         "metasploit",
				RiskLevel:        RiskLevelCritical,
				RequiresApproval: true,
				RiskRationale:    "High impact operation",
				Status:           StepStatusPending,
				DependsOn:        []types.ID{types.NewID(), types.NewID()},
				Metadata: map[string]any{
					"priority": "high",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to JSON
			jsonData, err := json.Marshal(tt.step)
			require.NoError(t, err)

			// Unmarshal back
			var decoded ExecutionStep
			err = json.Unmarshal(jsonData, &decoded)
			require.NoError(t, err)

			// Verify fields
			assert.Equal(t, tt.step.ID, decoded.ID)
			assert.Equal(t, tt.step.Sequence, decoded.Sequence)
			assert.Equal(t, tt.step.Type, decoded.Type)
			assert.Equal(t, tt.step.Name, decoded.Name)
			assert.Equal(t, tt.step.Description, decoded.Description)
			assert.Equal(t, tt.step.RiskLevel, decoded.RiskLevel)
			assert.Equal(t, tt.step.RequiresApproval, decoded.RequiresApproval)
			assert.Equal(t, tt.step.Status, decoded.Status)

			// Verify type-specific fields
			if tt.step.Type == StepTypeTool {
				assert.Equal(t, tt.step.ToolName, decoded.ToolName)
			}
			if tt.step.Type == StepTypePlugin {
				assert.Equal(t, tt.step.PluginName, decoded.PluginName)
				assert.Equal(t, tt.step.PluginMethod, decoded.PluginMethod)
			}
		})
	}
}

// TestStepResult_JSONRoundTrip tests JSON serialization and deserialization
func TestStepResult_JSONRoundTrip(t *testing.T) {
	startTime := time.Now().UTC().Truncate(time.Second)
	endTime := startTime.Add(5 * time.Second)

	tests := []struct {
		name   string
		result StepResult
	}{
		{
			name: "successful result",
			result: StepResult{
				StepID: types.NewID(),
				Status: StepStatusCompleted,
				Output: map[string]any{
					"open_ports": []int{22, 80, 443},
					"success":    true,
				},
				Duration:    5 * time.Second,
				StartedAt:   startTime,
				CompletedAt: endTime,
			},
		},
		{
			name: "failed result with error",
			result: StepResult{
				StepID: types.NewID(),
				Status: StepStatusFailed,
				Error: &StepError{
					Code:    "TOOL_FAILED",
					Message: "tool execution failed",
					Details: map[string]any{
						"exit_code": 1,
					},
				},
				Duration:    2 * time.Second,
				StartedAt:   startTime,
				CompletedAt: endTime,
			},
		},
		{
			name: "result with metadata",
			result: StepResult{
				StepID: types.NewID(),
				Status: StepStatusCompleted,
				Output: map[string]any{
					"data": "result",
				},
				Duration:    3 * time.Second,
				StartedAt:   startTime,
				CompletedAt: endTime,
				Metadata: map[string]any{
					"retries":   2,
					"cache_hit": false,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to JSON
			jsonData, err := json.Marshal(tt.result)
			require.NoError(t, err)

			// Unmarshal back
			var decoded StepResult
			err = json.Unmarshal(jsonData, &decoded)
			require.NoError(t, err)

			// Verify fields
			assert.Equal(t, tt.result.StepID, decoded.StepID)
			assert.Equal(t, tt.result.Status, decoded.Status)
			assert.Equal(t, tt.result.Duration, decoded.Duration)
			assert.Equal(t, tt.result.StartedAt.Unix(), decoded.StartedAt.Unix())
			assert.Equal(t, tt.result.CompletedAt.Unix(), decoded.CompletedAt.Unix())

			// Verify error if present
			if tt.result.Error != nil {
				require.NotNil(t, decoded.Error)
				assert.Equal(t, tt.result.Error.Code, decoded.Error.Code)
				assert.Equal(t, tt.result.Error.Message, decoded.Error.Message)
			}
		})
	}
}

// TestPlanStatus_JSONMarshaling tests JSON marshaling of PlanStatus
func TestPlanStatus_JSONMarshaling(t *testing.T) {
	tests := []struct {
		name     string
		status   PlanStatus
		expected string
	}{
		{
			name:     "draft status",
			status:   PlanStatusDraft,
			expected: `"draft"`,
		},
		{
			name:     "pending_approval status",
			status:   PlanStatusPendingApproval,
			expected: `"pending_approval"`,
		},
		{
			name:     "completed status",
			status:   PlanStatusCompleted,
			expected: `"completed"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonData, err := json.Marshal(tt.status)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(jsonData))

			var decoded PlanStatus
			err = json.Unmarshal(jsonData, &decoded)
			require.NoError(t, err)
			assert.Equal(t, tt.status, decoded)
		})
	}
}

// TestErrorChaining tests error wrapping and unwrapping
func TestErrorChaining(t *testing.T) {
	t.Run("PlanError wraps underlying error", func(t *testing.T) {
		originalErr := errors.New("database connection lost")
		planErr := NewPlanError(ErrStepExecutionFailed, "step failed", originalErr)

		// Test unwrapping
		unwrapped := errors.Unwrap(planErr)
		assert.Equal(t, originalErr, unwrapped)

		// Test Is() for error chain
		assert.True(t, errors.Is(planErr, originalErr))
	})

	t.Run("StepError with cause", func(t *testing.T) {
		originalErr := errors.New("network timeout")
		stepErr := &StepError{
			Code:    "NETWORK_ERROR",
			Message: "network operation failed",
			Cause:   originalErr,
		}

		// Verify error message includes cause
		assert.Contains(t, stepErr.Error(), "network timeout")
		assert.Contains(t, stepErr.Error(), "NETWORK_ERROR")
	})
}
