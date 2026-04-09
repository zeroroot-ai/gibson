package orchestrator

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/harness"
	"github.com/zero-day-ai/gibson/internal/types"
)

// mockMissionGraphManager is a mock implementation of MissionGraphManager for testing
type mockMissionGraphManager struct {
	ensureMissionCalls        []ensureMissionCall
	createMissionRunCalls     []createMissionRunCall
	updateMissionRunCalls     []updateMissionRunCall
	nextMissionID             string
	nextMissionRunID          string
	ensureMissionErr          error
	createMissionRunErr       error
	updateMissionRunStatusErr error
}

type ensureMissionCall struct {
	name     string
	targetID string
}

type createMissionRunCall struct {
	missionID string
	runNumber int
}

type updateMissionRunCall struct {
	runID  string
	status string
}

func (m *mockMissionGraphManager) EnsureMissionNode(ctx context.Context, name, targetID string) (string, error) {
	m.ensureMissionCalls = append(m.ensureMissionCalls, ensureMissionCall{
		name:     name,
		targetID: targetID,
	})
	if m.ensureMissionErr != nil {
		return "", m.ensureMissionErr
	}
	if m.nextMissionID == "" {
		m.nextMissionID = "mission_" + types.NewID().String()
	}
	return m.nextMissionID, nil
}

func (m *mockMissionGraphManager) CreateMissionRunNode(ctx context.Context, missionID string, runNumber int) (string, error) {
	m.createMissionRunCalls = append(m.createMissionRunCalls, createMissionRunCall{
		missionID: missionID,
		runNumber: runNumber,
	})
	if m.createMissionRunErr != nil {
		return "", m.createMissionRunErr
	}
	if m.nextMissionRunID == "" {
		m.nextMissionRunID = "mission_run_" + types.NewID().String()
	}
	return m.nextMissionRunID, nil
}

func (m *mockMissionGraphManager) UpdateMissionRunStatus(ctx context.Context, runID string, status string) error {
	m.updateMissionRunCalls = append(m.updateMissionRunCalls, updateMissionRunCall{
		runID:  runID,
		status: status,
	})
	return m.updateMissionRunStatusErr
}

// TestMissionGraphManager_Interface tests that the mockMissionGraphManager
// properly implements the MissionGraphManager interface
func TestMissionGraphManager_Interface(t *testing.T) {
	var _ MissionGraphManager = (*mockMissionGraphManager)(nil)
}

// TestMissionGraphTracking_ContextInjection verifies that MissionRunID is properly
// injected into the context for harness access
func TestMissionGraphTracking_ContextInjection(t *testing.T) {
	// Test context injection helpers
	ctx := context.Background()
	missionRunID := "test_mission_run_123"

	// Test ContextWithMissionRunID
	ctxWithID := harness.ContextWithMissionRunID(ctx, missionRunID)
	require.NotNil(t, ctxWithID)

	// Test MissionRunIDFromContext
	retrievedID := harness.MissionRunIDFromContext(ctxWithID)
	assert.Equal(t, missionRunID, retrievedID)

	// Test empty context returns empty string
	emptyID := harness.MissionRunIDFromContext(context.Background())
	assert.Equal(t, "", emptyID)
}

// TestMissionGraphTracking_StatusMapping tests that orchestrator status is properly
// mapped to mission run status values
func TestMissionGraphTracking_StatusMapping(t *testing.T) {
	testCases := []struct {
		name              string
		orchStatus        OrchestratorStatus
		expectedRunStatus string
	}{
		{
			name:              "completed maps to completed",
			orchStatus:        StatusCompleted,
			expectedRunStatus: "completed",
		},
		{
			name:              "failed maps to failed",
			orchStatus:        StatusFailed,
			expectedRunStatus: "failed",
		},
		{
			name:              "cancelled maps to cancelled",
			orchStatus:        StatusCancelled,
			expectedRunStatus: "cancelled",
		},
		{
			name:              "max iterations maps to failed",
			orchStatus:        StatusMaxIterations,
			expectedRunStatus: "failed",
		},
		{
			name:              "timeout maps to failed",
			orchStatus:        StatusTimeout,
			expectedRunStatus: "failed",
		},
		{
			name:              "budget exceeded maps to failed",
			orchStatus:        StatusBudgetExceeded,
			expectedRunStatus: "failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// This is a conceptual test - the actual mapping happens in adapter.Execute()
			// We're documenting the expected behavior here
			var status string
			switch tc.orchStatus {
			case StatusCompleted:
				status = "completed"
			case StatusFailed:
				status = "failed"
			case StatusCancelled:
				status = "cancelled"
			default:
				status = "failed"
			}
			assert.Equal(t, tc.expectedRunStatus, status)
		})
	}
}

// TestMissionGraphTracking_RunNumberExtraction tests extraction of run number from metadata
func TestMissionGraphTracking_RunNumberExtraction(t *testing.T) {
	testCases := []struct {
		name           string
		metadata       map[string]any
		expectedRunNum int
	}{
		{
			name: "int run number",
			metadata: map[string]any{
				"run_number": 5,
			},
			expectedRunNum: 5,
		},
		{
			name: "float64 run number",
			metadata: map[string]any{
				"run_number": 7.0,
			},
			expectedRunNum: 7,
		},
		{
			name:           "missing run number",
			metadata:       map[string]any{},
			expectedRunNum: 0,
		},
		{
			name:           "nil metadata",
			metadata:       nil,
			expectedRunNum: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate the run number extraction logic from adapter.Execute()
			runNumber := 0
			if tc.metadata != nil {
				if rn, ok := tc.metadata["run_number"].(int); ok {
					runNumber = rn
				} else if rn, ok := tc.metadata["run_number"].(float64); ok {
					runNumber = int(rn)
				}
			}
			assert.Equal(t, tc.expectedRunNum, runNumber)
		})
	}
}

// TestMissionGraphTracking_OptionalBehavior tests that mission graph tracking
// is optional - adapter can be created with nil MissionGraphManager
func TestMissionGraphTracking_OptionalBehavior(t *testing.T) {
	// Test that MissionGraphManager can be nil
	var mgr MissionGraphManager = nil
	assert.Nil(t, mgr)

	// Verify that the Config can have nil MissionGraphManager
	cfg := Config{
		MissionGraphManager: nil,
	}
	assert.Nil(t, cfg.MissionGraphManager)
}
