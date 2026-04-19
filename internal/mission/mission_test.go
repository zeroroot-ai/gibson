package mission

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/types"
)

// TestMissionStatus_String tests the String method
func TestMissionStatus_String(t *testing.T) {
	tests := []struct {
		name   string
		status MissionStatus
		want   string
	}{
		{"pending", MissionStatusPending, "pending"},
		{"running", MissionStatusRunning, "running"},
		{"paused", MissionStatusPaused, "paused"},
		{"completed", MissionStatusCompleted, "completed"},
		{"failed", MissionStatusFailed, "failed"},
		{"cancelled", MissionStatusCancelled, "cancelled"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.status.String())
		})
	}
}

// TestMissionStatus_IsTerminal tests terminal status detection
func TestMissionStatus_IsTerminal(t *testing.T) {
	tests := []struct {
		name     string
		status   MissionStatus
		terminal bool
	}{
		{"pending not terminal", MissionStatusPending, false},
		{"running not terminal", MissionStatusRunning, false},
		{"paused not terminal", MissionStatusPaused, false},
		{"completed is terminal", MissionStatusCompleted, true},
		{"failed is terminal", MissionStatusFailed, true},
		{"cancelled is terminal", MissionStatusCancelled, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.terminal, tt.status.IsTerminal())
		})
	}
}

// TestMissionStatus_CanTransitionTo tests state transition validation
func TestMissionStatus_CanTransitionTo(t *testing.T) {
	tests := []struct {
		name    string
		current MissionStatus
		target  MissionStatus
		allowed bool
	}{
		// Pending transitions
		{"pending to running", MissionStatusPending, MissionStatusRunning, true},
		{"pending to cancelled", MissionStatusPending, MissionStatusCancelled, true},
		{"pending to completed", MissionStatusPending, MissionStatusCompleted, false},
		{"pending to paused", MissionStatusPending, MissionStatusPaused, false},
		{"pending to failed", MissionStatusPending, MissionStatusFailed, false},

		// Running transitions
		{"running to paused", MissionStatusRunning, MissionStatusPaused, true},
		{"running to completed", MissionStatusRunning, MissionStatusCompleted, true},
		{"running to failed", MissionStatusRunning, MissionStatusFailed, true},
		{"running to cancelled", MissionStatusRunning, MissionStatusCancelled, true},
		{"running to pending", MissionStatusRunning, MissionStatusPending, false},

		// Paused transitions
		{"paused to running", MissionStatusPaused, MissionStatusRunning, true},
		{"paused to failed", MissionStatusPaused, MissionStatusFailed, true},
		{"paused to cancelled", MissionStatusPaused, MissionStatusCancelled, true},
		{"paused to completed", MissionStatusPaused, MissionStatusCompleted, false},
		{"paused to pending", MissionStatusPaused, MissionStatusPending, false},

		// Terminal states cannot transition
		{"completed to any", MissionStatusCompleted, MissionStatusRunning, false},
		{"failed to any", MissionStatusFailed, MissionStatusRunning, false},
		{"cancelled to any", MissionStatusCancelled, MissionStatusRunning, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.allowed, tt.current.CanTransitionTo(tt.target))
		})
	}
}

// TestMission_Validate tests mission validation
func TestMission_Validate(t *testing.T) {
	validMission := &Mission{
		ID:                  types.NewID(),
		Name:                "Test Mission",
		TargetID:            types.NewID(),
		MissionDefinitionID: types.NewID(),
		Status:              MissionStatusPending,
	}

	tests := []struct {
		name    string
		mission *Mission
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid mission",
			mission: validMission,
			wantErr: false,
		},
		{
			name: "missing ID",
			mission: &Mission{
				Name:                "Test",
				TargetID:            types.NewID(),
				MissionDefinitionID: types.NewID(),
				Status:              MissionStatusPending,
			},
			wantErr: true,
			errMsg:  "mission ID is required",
		},
		{
			name: "missing name",
			mission: &Mission{
				ID:                  types.NewID(),
				TargetID:            types.NewID(),
				MissionDefinitionID: types.NewID(),
				Status:              MissionStatusPending,
			},
			wantErr: true,
			errMsg:  "mission name is required",
		},
		{
			name: "missing target ID",
			mission: &Mission{
				ID:                  types.NewID(),
				Name:                "Test",
				MissionDefinitionID: types.NewID(),
				Status:              MissionStatusPending,
			},
			wantErr: true,
			errMsg:  "target ID is required",
		},
		{
			name: "missing mission ID",
			mission: &Mission{
				ID:       types.NewID(),
				Name:     "Test",
				TargetID: types.NewID(),
				Status:   MissionStatusPending,
			},
			wantErr: true,
			errMsg:  "mission ID is required",
		},
		{
			name: "missing status",
			mission: &Mission{
				ID:                  types.NewID(),
				Name:                "Test",
				TargetID:            types.NewID(),
				MissionDefinitionID: types.NewID(),
			},
			wantErr: true,
			errMsg:  "mission status is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.mission.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestMission_CalculateProgress tests progress calculation
func TestMission_CalculateProgress(t *testing.T) {
	tests := []struct {
		name     string
		metrics  *MissionMetrics
		expected float64
	}{
		{
			name:     "no metrics",
			metrics:  nil,
			expected: 0.0,
		},
		{
			name: "zero total nodes",
			metrics: &MissionMetrics{
				TotalNodes:     0,
				CompletedNodes: 0,
			},
			expected: 0.0,
		},
		{
			name: "50% complete",
			metrics: &MissionMetrics{
				TotalNodes:     10,
				CompletedNodes: 5,
			},
			expected: 50.0,
		},
		{
			name: "100% complete",
			metrics: &MissionMetrics{
				TotalNodes:     10,
				CompletedNodes: 10,
			},
			expected: 100.0,
		},
		{
			name: "25% complete",
			metrics: &MissionMetrics{
				TotalNodes:     8,
				CompletedNodes: 2,
			},
			expected: 25.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mission := &Mission{
				Metrics: tt.metrics,
			}
			assert.Equal(t, tt.expected, mission.CalculateProgress())
		})
	}
}

// TestMission_GetProgress tests progress snapshot generation
func TestMission_GetProgress(t *testing.T) {
	missionID := types.NewID()
	mission := &Mission{
		ID:     missionID,
		Status: MissionStatusRunning,
		Metrics: &MissionMetrics{
			TotalNodes:     10,
			CompletedNodes: 3,
			TotalFindings:  5,
		},
		Checkpoint: &MissionCheckpoint{
			PendingNodes: []string{"node4", "node5"},
		},
	}

	progress := mission.GetProgress()

	assert.Equal(t, missionID, progress.MissionID)
	assert.Equal(t, MissionStatusRunning, progress.Status)
	assert.Equal(t, 30.0, progress.PercentComplete)
	assert.Equal(t, 3, progress.CompletedNodes)
	assert.Equal(t, 10, progress.TotalNodes)
	assert.Equal(t, 5, progress.FindingsCount)
	assert.Equal(t, []string{"node4", "node5"}, progress.PendingNodes)
	assert.Empty(t, progress.RunningNodes)
}

// TestMission_GetDuration tests duration calculation
func TestMission_GetDuration(t *testing.T) {
	now := time.Now()
	past := now.Add(-1 * time.Hour)

	tests := []struct {
		name        string
		startedAt   *time.Time
		completedAt *time.Time
		minDuration time.Duration
	}{
		{
			name:        "not started",
			startedAt:   nil,
			completedAt: nil,
			minDuration: 0,
		},
		{
			name:        "running",
			startedAt:   &past,
			completedAt: nil,
			minDuration: 59 * time.Minute, // At least 59 minutes
		},
		{
			name:        "completed",
			startedAt:   &past,
			completedAt: &now,
			minDuration: 59 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mission := &Mission{
				StartedAt:   NewUnixTimePtr(tt.startedAt),
				CompletedAt: NewUnixTimePtr(tt.completedAt),
			}
			duration := mission.GetDuration()
			if tt.minDuration > 0 {
				assert.GreaterOrEqual(t, duration, tt.minDuration)
			} else {
				assert.Equal(t, time.Duration(0), duration)
			}
		})
	}
}

// TestConstraintAction_String tests the String method
func TestConstraintAction_String(t *testing.T) {
	tests := []struct {
		name   string
		action ConstraintAction
		want   string
	}{
		{"pause", ConstraintActionPause, "pause"},
		{"fail", ConstraintActionFail, "fail"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.action.String())
		})
	}
}

// TestConstraintViolation_Error tests error string generation
func TestConstraintViolation_Error(t *testing.T) {
	violation := &ConstraintViolation{
		Constraint: "max_cost",
		Message:    "Cost exceeded",
		Action:     ConstraintActionPause,
	}

	expected := "constraint violation: max_cost - Cost exceeded (action: pause)"
	assert.Equal(t, expected, violation.Error())
}

// TestMissionConstraints_Validate tests constraint validation
func TestMissionConstraints_Validate(t *testing.T) {
	tests := []struct {
		name        string
		constraints *MissionConstraints
		wantErr     bool
		errMsg      string
	}{
		{
			name: "valid constraints",
			constraints: &MissionConstraints{
				MaxDuration:       1 * time.Hour,
				MaxFindings:       100,
				SeverityThreshold: agent.SeverityHigh,
				SeverityAction:    ConstraintActionPause,
				MaxTokens:         10000,
				MaxCost:           50.0,
			},
			wantErr: false,
		},
		{
			name: "negative duration",
			constraints: &MissionConstraints{
				MaxDuration: -1 * time.Hour,
			},
			wantErr: true,
			errMsg:  "max_duration cannot be negative",
		},
		{
			name: "negative findings",
			constraints: &MissionConstraints{
				MaxFindings: -1,
			},
			wantErr: true,
			errMsg:  "max_findings cannot be negative",
		},
		{
			name: "negative tokens",
			constraints: &MissionConstraints{
				MaxTokens: -1,
			},
			wantErr: true,
			errMsg:  "max_tokens cannot be negative",
		},
		{
			name: "negative cost",
			constraints: &MissionConstraints{
				MaxCost: -1.0,
			},
			wantErr: true,
			errMsg:  "max_cost cannot be negative",
		},
		{
			name: "invalid severity threshold",
			constraints: &MissionConstraints{
				SeverityThreshold: agent.FindingSeverity("invalid"),
			},
			wantErr: true,
			errMsg:  "invalid severity_threshold",
		},
		{
			name: "invalid severity action",
			constraints: &MissionConstraints{
				SeverityThreshold: agent.SeverityHigh,
				SeverityAction:    ConstraintAction("invalid"),
			},
			wantErr: true,
			errMsg:  "invalid severity_action",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.constraints.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestDefaultConstraintChecker_Check tests constraint checking
func TestDefaultConstraintChecker_Check(t *testing.T) {
	checker := NewDefaultConstraintChecker()
	ctx := context.Background()

	tests := []struct {
		name            string
		constraints     *MissionConstraints
		metrics         *MissionMetrics
		expectViolation bool
		expectedCode    string
		expectedAction  ConstraintAction
	}{
		{
			name:            "nil constraints",
			constraints:     nil,
			metrics:         &MissionMetrics{},
			expectViolation: false,
		},
		{
			name:            "nil metrics",
			constraints:     &MissionConstraints{},
			metrics:         nil,
			expectViolation: false,
		},
		{
			name: "cost exceeded",
			constraints: &MissionConstraints{
				MaxCost: 10.0,
			},
			metrics: &MissionMetrics{
				TotalCost: 15.0,
			},
			expectViolation: true,
			expectedCode:    "max_cost",
			expectedAction:  ConstraintActionPause,
		},
		{
			name: "tokens exceeded",
			constraints: &MissionConstraints{
				MaxTokens: 1000,
			},
			metrics: &MissionMetrics{
				TotalTokens: 1500,
			},
			expectViolation: true,
			expectedCode:    "max_tokens",
			expectedAction:  ConstraintActionPause,
		},
		{
			name: "duration exceeded",
			constraints: &MissionConstraints{
				MaxDuration: 1 * time.Hour,
			},
			metrics: &MissionMetrics{
				Duration: 2 * time.Hour,
			},
			expectViolation: true,
			expectedCode:    "max_duration",
			expectedAction:  ConstraintActionFail,
		},
		{
			name: "findings limit reached",
			constraints: &MissionConstraints{
				MaxFindings: 10,
			},
			metrics: &MissionMetrics{
				TotalFindings: 10,
			},
			expectViolation: true,
			expectedCode:    "max_findings",
			expectedAction:  ConstraintActionPause,
		},
		{
			name: "severity threshold exceeded - critical",
			constraints: &MissionConstraints{
				SeverityThreshold: agent.SeverityCritical,
				SeverityAction:    ConstraintActionFail,
			},
			metrics: &MissionMetrics{
				FindingsBySeverity: map[string]int{
					"critical": 1,
				},
			},
			expectViolation: true,
			expectedCode:    "severity_threshold",
			expectedAction:  ConstraintActionFail,
		},
		{
			name: "severity threshold exceeded - high includes critical",
			constraints: &MissionConstraints{
				SeverityThreshold: agent.SeverityHigh,
				SeverityAction:    ConstraintActionPause,
			},
			metrics: &MissionMetrics{
				FindingsBySeverity: map[string]int{
					"critical": 1,
				},
			},
			expectViolation: true,
			expectedCode:    "severity_threshold",
			expectedAction:  ConstraintActionPause,
		},
		{
			name: "severity threshold not exceeded",
			constraints: &MissionConstraints{
				SeverityThreshold: agent.SeverityCritical,
			},
			metrics: &MissionMetrics{
				FindingsBySeverity: map[string]int{
					"high": 1,
				},
			},
			expectViolation: false,
		},
		{
			name: "all constraints within limits",
			constraints: &MissionConstraints{
				MaxDuration:       2 * time.Hour,
				MaxFindings:       100,
				MaxTokens:         10000,
				MaxCost:           50.0,
				SeverityThreshold: agent.SeverityCritical,
			},
			metrics: &MissionMetrics{
				Duration:      1 * time.Hour,
				TotalFindings: 50,
				TotalTokens:   5000,
				TotalCost:     25.0,
				FindingsBySeverity: map[string]int{
					"high": 5,
				},
			},
			expectViolation: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violation, err := checker.Check(ctx, tt.constraints, tt.metrics)
			require.NoError(t, err)

			if tt.expectViolation {
				require.NotNil(t, violation)
				assert.Equal(t, tt.expectedCode, violation.Constraint)
				assert.Equal(t, tt.expectedAction, violation.Action)
			} else {
				assert.Nil(t, violation)
			}
		})
	}
}

// TestDefaultConstraints tests default constraints
func TestDefaultConstraints(t *testing.T) {
	defaults := DefaultConstraints()

	assert.Equal(t, 24*time.Hour, defaults.MaxDuration)
	assert.Equal(t, 1000, defaults.MaxFindings)
	assert.Equal(t, agent.SeverityCritical, defaults.SeverityThreshold)
	assert.Equal(t, ConstraintActionPause, defaults.SeverityAction)
	assert.Equal(t, false, defaults.RequireEvidence)
	assert.Equal(t, int64(10000000), defaults.MaxTokens)
	assert.Equal(t, 100.0, defaults.MaxCost)
}

// TestMissionError_Error tests error string formatting
func TestMissionError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *MissionError
		expected string
	}{
		{
			name: "error without cause",
			err: &MissionError{
				Code:    ErrMissionNotFound,
				Message: "mission not found",
			},
			expected: "[mission_not_found] mission not found",
		},
		{
			name: "error with cause",
			err: &MissionError{
				Code:    ErrMissionMissionFailed,
				Message: "mission execution failed",
				Cause:   errors.New("database connection lost"),
			},
			expected: "[mission_failed] mission execution failed: database connection lost",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

// TestMissionError_Unwrap tests error unwrapping
func TestMissionError_Unwrap(t *testing.T) {
	causeErr := errors.New("underlying error")
	missionErr := WrapMissionError(ErrMissionInternal, "internal error", causeErr)

	unwrapped := missionErr.Unwrap()
	assert.Equal(t, causeErr, unwrapped)
}

// TestMissionError_Is tests error comparison
func TestMissionError_Is(t *testing.T) {
	err1 := NewMissionError(ErrMissionNotFound, "not found")
	err2 := NewMissionError(ErrMissionNotFound, "different message")
	err3 := NewMissionError(ErrMissionValidation, "validation failed")

	assert.True(t, errors.Is(err1, err2))
	assert.False(t, errors.Is(err1, err3))
}

// TestMissionError_WithContext tests context addition
func TestMissionError_WithContext(t *testing.T) {
	err := NewMissionError(ErrMissionNotFound, "not found")
	err.WithContext("mission_id", "123")
	err.WithContext("user_id", "456")

	assert.Equal(t, "123", err.Context["mission_id"])
	assert.Equal(t, "456", err.Context["user_id"])
}

// TestMissionErrorHelpers tests error helper functions
func TestMissionErrorHelpers(t *testing.T) {
	t.Run("NewNotFoundError", func(t *testing.T) {
		err := NewNotFoundError("mission-123")
		assert.Equal(t, ErrMissionNotFound, err.Code)
		assert.Contains(t, err.Message, "mission-123")
		assert.Equal(t, "mission-123", err.Context["mission_id"])
	})

	t.Run("NewInvalidStateError", func(t *testing.T) {
		err := NewInvalidStateError(MissionStatusCompleted, MissionStatusRunning)
		assert.Equal(t, ErrMissionInvalidState, err.Code)
		assert.Equal(t, MissionStatusCompleted, err.Context["current_state"])
		assert.Equal(t, MissionStatusRunning, err.Context["target_state"])
	})

	t.Run("NewValidationError", func(t *testing.T) {
		err := NewValidationError("invalid field")
		assert.Equal(t, ErrMissionValidation, err.Code)
		assert.Contains(t, err.Message, "invalid field")
	})

	t.Run("NewTargetNotFoundError", func(t *testing.T) {
		err := NewTargetNotFoundError("target-123")
		assert.Equal(t, ErrMissionTargetNotFound, err.Code)
		assert.Equal(t, "target-123", err.Context["target_id"])
	})

	t.Run("NewMissionNotFoundError", func(t *testing.T) {
		err := NewMissionNotFoundError("mission-123")
		assert.Equal(t, ErrMissionMissionNotFound, err.Code)
		assert.Equal(t, "mission-123", err.Context["mission_definition_id"])
	})

	t.Run("NewMissionFailedError", func(t *testing.T) {
		causeErr := errors.New("node failed")
		err := NewMissionFailedError("mission-123", causeErr)
		assert.Equal(t, ErrMissionMissionFailed, err.Code)
		assert.Equal(t, causeErr, err.Cause)
	})

	t.Run("NewConstraintViolationError", func(t *testing.T) {
		violation := &ConstraintViolation{
			Constraint: "max_cost",
			Message:    "cost exceeded",
			Action:     ConstraintActionPause,
		}
		err := NewConstraintViolationError(violation)
		assert.Equal(t, ErrMissionConstraint, err.Code)
		assert.Equal(t, "max_cost", err.Context["constraint"])
	})

	t.Run("NewTimeoutError", func(t *testing.T) {
		err := NewTimeoutError("1h")
		assert.Equal(t, ErrMissionTimeout, err.Code)
	})

	t.Run("NewCancelledError", func(t *testing.T) {
		err := NewCancelledError("user requested")
		assert.Equal(t, ErrMissionCancelled, err.Code)
	})
}

// TestMissionErrorTypeChecks tests error type checking functions
func TestMissionErrorTypeChecks(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		checkFn  func(error) bool
		expected bool
	}{
		{"IsNotFoundError true", NewNotFoundError("123"), IsNotFoundError, true},
		{"IsNotFoundError false", NewValidationError("test"), IsNotFoundError, false},
		{"IsInvalidStateError true", NewInvalidStateError(MissionStatusCompleted, MissionStatusRunning), IsInvalidStateError, true},
		{"IsInvalidStateError false", NewValidationError("test"), IsInvalidStateError, false},
		{"IsValidationError true", NewValidationError("test"), IsValidationError, true},
		{"IsValidationError false", NewNotFoundError("123"), IsValidationError, false},
		{"IsConstraintViolationError true", NewConstraintViolationError(&ConstraintViolation{}), IsConstraintViolationError, true},
		{"IsConstraintViolationError false", NewValidationError("test"), IsConstraintViolationError, false},
		{"IsTimeoutError true", NewTimeoutError("1h"), IsTimeoutError, true},
		{"IsTimeoutError false", NewValidationError("test"), IsTimeoutError, false},
		{"IsCancelledError true", NewCancelledError("user"), IsCancelledError, true},
		{"IsCancelledError false", NewValidationError("test"), IsCancelledError, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.checkFn(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
