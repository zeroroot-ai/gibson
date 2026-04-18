package mission

import (
	"context"
	"time"

	"github.com/zero-day-ai/gibson/internal/types"
)

// Mock mission types for testing (mission package was removed)
// These are shared across all test files in the mission package.

type mockMissionNodeType string
type mockMissionStatus string
type mockNodeStatus string

const (
	mockNodeTypeAgent        mockMissionNodeType = "agent"
	mockNodeTypeTool         mockMissionNodeType = "tool"
	mockMissionStatusRunning mockMissionStatus   = "running"
	mockNodeStatusCompleted  mockNodeStatus      = "completed"
	mockNodeStatusPending    mockNodeStatus      = "pending"
)

type mockMissionNode struct {
	ID        string
	Name      string
	Type      mockMissionNodeType
	AgentName string
}

type mockMissionEdge struct {
	From string
	To   string
}

type mockMission struct {
	ID          types.ID
	Name        string
	Description string
	Nodes       map[string]*mockMissionNode
	Edges       []mockMissionEdge
	EntryPoints []string
	ExitPoints  []string
	Metadata    map[string]any
	CreatedAt   time.Time
}

type mockNodeResult struct {
	NodeID      string
	Status      mockNodeStatus
	Output      map[string]any
	CompletedAt time.Time
}

type mockNodeState struct {
	Status mockNodeStatus
	Result *mockNodeResult
}

type mockMissionState struct {
	MissionDefinitionID types.ID
	Status              mockMissionStatus
	StartedAt           time.Time
	NodeStates          map[string]*mockNodeState
}

func newMockMissionState(wf *mockMission) *mockMissionState {
	states := make(map[string]*mockNodeState)
	for id := range wf.Nodes {
		states[id] = &mockNodeState{
			Status: mockNodeStatusPending,
		}
	}
	return &mockMissionState{
		MissionDefinitionID: wf.ID,
		Status:              mockMissionStatusRunning,
		StartedAt:           time.Now(),
		NodeStates:          states,
	}
}

func (s *mockMissionState) MarkNodeStarted(nodeID string) {
	// No-op for tests
}

func (s *mockMissionState) MarkNodeCompleted(nodeID string, result *mockNodeResult) {
	if state, ok := s.NodeStates[nodeID]; ok {
		state.Status = mockNodeStatusCompleted
		state.Result = result
	}
}

// mockMissionOrchestrator is a simple mock orchestrator for testing
type mockMissionOrchestrator struct {
	executeResult *MissionResult
	executeError  error
}

func (m *mockMissionOrchestrator) Execute(ctx context.Context, mission *Mission) (*MissionResult, error) {
	if m.executeError != nil {
		return nil, m.executeError
	}
	if m.executeResult != nil {
		return m.executeResult, nil
	}
	return &MissionResult{
		MissionID: mission.ID,
		Status:    MissionStatusCompleted,
	}, nil
}

// ExecuteFromCheckpoint implements MissionOrchestrator for testing.
// It delegates to Execute for simplicity; tests that need to distinguish
// checkpoint vs. non-checkpoint execution should use a custom mock.
func (m *mockMissionOrchestrator) ExecuteFromCheckpoint(ctx context.Context, mission *Mission, checkpoint *MissionCheckpoint) (*MissionResult, error) {
	return m.Execute(ctx, mission)
}

func (m *mockMissionOrchestrator) StopMission(ctx context.Context, missionID types.ID) error {
	return nil
}
