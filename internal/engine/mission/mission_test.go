// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mission

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
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
			// The message says "mission definition ID", not "mission ID". The two
			// used to read the same, so a Save refused for a missing
			// MissionDefinitionID sent the reader looking at Mission.ID.
			name: "missing mission definition ID",
			mission: &Mission{
				ID:       types.NewID(),
				Name:     "Test",
				TargetID: types.NewID(),
				Status:   MissionStatusPending,
			},
			wantErr: true,
			errMsg:  "mission definition ID is required",
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

// TestValidateConstraints tests the ValidateConstraints free function which replaced
// the method formerly on the deleted daemon-local MissionConstraints struct.
// SeverityAction is no longer a proto field — it lives in DefaultConstraintChecker
// as a daemon runtime-policy knob (see constraints.go for rationale).
func TestValidateConstraints(t *testing.T) {
	tests := []struct {
		name        string
		constraints *missionv1.MissionConstraints
		wantErr     bool
		errMsg      string
	}{
		{
			name: "valid constraints",
			constraints: &missionv1.MissionConstraints{
				MaxDuration:       durationpb.New(1 * time.Hour),
				MaxFindings:       100,
				SeverityThreshold: string(agent.SeverityHigh),
				MaxTokens:         10000,
				MaxCost:           50.0,
			},
			wantErr: false,
		},
		{
			name:        "nil constraints",
			constraints: nil,
			wantErr:     false,
		},
		{
			name: "negative duration",
			constraints: &missionv1.MissionConstraints{
				MaxDuration: durationpb.New(-1 * time.Hour),
			},
			wantErr: true,
			errMsg:  "max_duration cannot be negative",
		},
		{
			name: "negative findings",
			constraints: &missionv1.MissionConstraints{
				MaxFindings: -1,
			},
			wantErr: true,
			errMsg:  "max_findings cannot be negative",
		},
		{
			name: "negative tokens",
			constraints: &missionv1.MissionConstraints{
				MaxTokens: -1,
			},
			wantErr: true,
			errMsg:  "max_tokens cannot be negative",
		},
		{
			name: "negative cost",
			constraints: &missionv1.MissionConstraints{
				MaxCost: -1.0,
			},
			wantErr: true,
			errMsg:  "max_cost cannot be negative",
		},
		{
			name: "invalid severity threshold",
			constraints: &missionv1.MissionConstraints{
				SeverityThreshold: "invalid",
			},
			wantErr: true,
			errMsg:  "invalid severity_threshold",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConstraints(tt.constraints)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
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
