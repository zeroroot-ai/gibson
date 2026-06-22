//go:build skip_old_tests
// +build skip_old_tests

// NOTE: This file contains tests for the old mission-based API which has been removed.
// These tests need to be rewritten for the new mission definition API.
// Use -tags=skip_old_tests to run these (they will fail).

package mission

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// Helper function to create a test mission with specific status
func createTestMissionWithStatus(status MissionStatus) *Mission {
	now := time.Now()
	targetID := types.NewID()
	missionDefinitionID := types.NewID()

	mission := &Mission{
		ID:                  types.NewID(),
		Name:                "test-mission",
		Description:         "Test mission",
		Status:              status,
		TargetID:            targetID,
		MissionDefinitionID: missionDefinitionID,
		CreatedAt:           now,
		UpdatedAt:           now,
		Progress:            0.0,
	}

	if status == MissionStatusRunning {
		startedAt := now
		mission.StartedAt = &startedAt
		mission.Progress = 0.5
		mission.Metrics = &MissionMetrics{
			TotalNodes:     10,
			CompletedNodes: 5,
			TotalTokens:    1000,
		}
	}

	if status.IsTerminal() {
		startedAt := now.Add(-1 * time.Hour)
		completedAt := now
		mission.StartedAt = &startedAt
		mission.CompletedAt = &completedAt
		mission.Progress = 1.0
		mission.Metrics = &MissionMetrics{
			TotalNodes:     10,
			CompletedNodes: 10,
			TotalFindings:  5,
			TotalTokens:    5000,
			Duration:       time.Hour,
			FindingsBySeverity: map[string]int{
				"high": 2,
				"low":  3,
			},
		}
	}

	return mission
}

// Mock implementations for testing

type mockMissionStore struct {
	saveCalled        bool
	missions          map[types.ID]*Mission
	getResult         *Mission
	getResults        []*Mission
	getResultIndex    int
	getError          error
	listResult        []*Mission
	listError         error
	updateStatusError error
	mu                sync.RWMutex
}

func (m *mockMissionStore) Save(ctx context.Context, mission *Mission) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saveCalled = true
	if m.missions == nil {
		m.missions = make(map[types.ID]*Mission)
	}
	m.missions[mission.ID] = mission
	return nil
}

func (m *mockMissionStore) Get(ctx context.Context, id types.ID) (*Mission, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.getError != nil {
		return nil, m.getError
	}

	// Support multiple get results for WaitForCompletion tests
	if len(m.getResults) > 0 {
		idx := m.getResultIndex
		m.getResultIndex++
		if idx < len(m.getResults) {
			result := m.getResults[idx]
			result.ID = id
			return result, nil
		}
		// Return last result if we've exhausted the list
		result := m.getResults[len(m.getResults)-1]
		result.ID = id
		return result, nil
	}

	if m.getResult != nil {
		m.getResult.ID = id
		return m.getResult, nil
	}
	return nil, fmt.Errorf("mission not found: %s", id)
}

func (m *mockMissionStore) GetByName(ctx context.Context, name string) (*Mission, error) {
	return nil, nil
}

func (m *mockMissionStore) List(ctx context.Context, filter *MissionFilter) ([]*Mission, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.listError != nil {
		return nil, m.listError
	}
	return m.listResult, nil
}

func (m *mockMissionStore) Update(ctx context.Context, mission *Mission) error {
	return nil
}

func (m *mockMissionStore) UpdateStatus(ctx context.Context, id types.ID, status MissionStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.updateStatusError != nil {
		return m.updateStatusError
	}
	return nil
}

func (m *mockMissionStore) UpdateProgress(ctx context.Context, id types.ID, progress float64) error {
	return nil
}

func (m *mockMissionStore) Delete(ctx context.Context, id types.ID) error {
	return nil
}

func (m *mockMissionStore) GetByTarget(ctx context.Context, targetID types.ID) ([]*Mission, error) {
	return nil, nil
}

func (m *mockMissionStore) GetActive(ctx context.Context) ([]*Mission, error) {
	return nil, nil
}

func (m *mockMissionStore) SaveCheckpoint(ctx context.Context, missionID types.ID, checkpoint *MissionCheckpoint) error {
	return nil
}

func (m *mockMissionStore) Count(ctx context.Context, filter *MissionFilter) (int, error) {
	return 0, nil
}

func (m *mockMissionStore) GetByNameAndStatus(ctx context.Context, name string, status MissionStatus) (*Mission, error) {
	return nil, nil
}

func (m *mockMissionStore) ListByName(ctx context.Context, name string, limit int) ([]*Mission, error) {
	return nil, nil
}

func (m *mockMissionStore) GetLatestByName(ctx context.Context, name string) (*Mission, error) {
	return nil, nil
}

func (m *mockMissionStore) IncrementRunNumber(ctx context.Context, name string) (int, error) {
	return 0, nil
}

// Mission definition methods (stubs for testing)
func (m *mockMissionStore) CreateDefinition(ctx context.Context, def *missionv1.MissionDefinition) error {
	return nil
}

func (m *mockMissionStore) GetDefinition(ctx context.Context, name string) (*missionv1.MissionDefinition, error) {
	return nil, nil
}

func (m *mockMissionStore) ListDefinitions(ctx context.Context) ([]*missionv1.MissionDefinition, error) {
	return nil, nil
}

func (m *mockMissionStore) UpdateDefinition(ctx context.Context, def *missionv1.MissionDefinition) error {
	return nil
}

func (m *mockMissionStore) DeleteDefinition(ctx context.Context, name string) error {
	return nil
}

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

// TestNewMissionClient verifies that NewMissionClient creates a client with proper defaults.
func TestNewMissionClient(t *testing.T) {
	// Create mock dependencies
	store := &mockMissionStore{}
	orchestrator := &mockMissionOrchestrator{}

	// Create client
	client := NewMissionClient(store, orchestrator)

	// Verify defaults
	if client.store != store {
		t.Error("store not set correctly")
	}
	if client.orchestrator != orchestrator {
		t.Error("orchestrator not set correctly")
	}
	if client.maxChildMissions != 10 {
		t.Errorf("expected maxChildMissions=10, got %d", client.maxChildMissions)
	}
	if client.maxConcurrentMissions != 50 {
		t.Errorf("expected maxConcurrentMissions=50, got %d", client.maxConcurrentMissions)
	}
	if client.maxMissionDepth != 3 {
		t.Errorf("expected maxMissionDepth=3, got %d", client.maxMissionDepth)
	}
}

// TestNewMissionClientWithOptions verifies that functional options work correctly.
func TestNewMissionClientWithOptions(t *testing.T) {
	store := &mockMissionStore{}
	orchestrator := &mockMissionOrchestrator{}

	// Create client with custom spawn limits
	client := NewMissionClient(
		store,
		orchestrator,
		WithSpawnLimits(5, 25, 2),
	)

	if client.maxChildMissions != 5 {
		t.Errorf("expected maxChildMissions=5, got %d", client.maxChildMissions)
	}
	if client.maxConcurrentMissions != 25 {
		t.Errorf("expected maxConcurrentMissions=25, got %d", client.maxConcurrentMissions)
	}
	if client.maxMissionDepth != 2 {
		t.Errorf("expected maxMissionDepth=2, got %d", client.maxMissionDepth)
	}
}

// TestMissionClientCreate_Success verifies successful mission creation.
func TestMissionClientCreate_Success(t *testing.T) {
	ctx := context.Background()
	store := &mockMissionStore{}
	orchestrator := &mockMissionOrchestrator{}

	client := NewMissionClient(store, orchestrator)

	// Create mission
	wf := &mockMission{
		Name: "test-mission",
		Nodes: map[string]*mockMissionNode{
			"node1": {
				ID:   "node1",
				Type: mockNodeTypeAgent,
			},
		},
	}

	// Create request
	targetID := types.NewID()
	req := &CreateMissionRequest{
		Mission:     wf,
		TargetID:    targetID,
		Name:        "test-mission",
		Description: "Test mission description",
	}

	// Create mission
	mission, err := client.Create(ctx, req)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Verify mission properties
	if mission.Name != "test-mission" {
		t.Errorf("expected name='test-mission', got %s", mission.Name)
	}
	if mission.Description != "Test mission description" {
		t.Errorf("expected description='Test mission description', got %s", mission.Description)
	}
	if mission.TargetID != targetID {
		t.Errorf("target ID mismatch")
	}
	if mission.Status != MissionStatusPending {
		t.Errorf("expected status=pending, got %s", mission.Status)
	}
	if mission.Depth != 0 {
		t.Errorf("expected depth=0 for root mission, got %d", mission.Depth)
	}
	if mission.ParentMissionID != nil {
		t.Error("expected no parent for root mission")
	}

	// Verify store was called
	if !store.saveCalled {
		t.Error("expected store.Save to be called")
	}
}

// TestMissionClientCreate_WithParent verifies mission creation with lineage tracking.
func TestMissionClientCreate_WithParent(t *testing.T) {
	ctx := context.Background()
	store := &mockMissionStore{}
	orchestrator := &mockMissionOrchestrator{}

	client := NewMissionClient(store, orchestrator)

	// Create mission
	wf := &mockMission{
		Name: "child-mission",
		Nodes: map[string]*mockMissionNode{
			"node1": {ID: "node1", Type: mockNodeTypeAgent},
		},
	}

	// Create request with parent
	parentID := types.NewID()
	req := &CreateMissionRequest{
		Mission:         wf,
		TargetID:        types.NewID(),
		ParentMissionID: &parentID,
		ParentDepth:     0, // Parent is root
	}

	// Create mission
	mission, err := client.Create(ctx, req)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Verify lineage tracking
	if mission.ParentMissionID == nil {
		t.Fatal("expected parent mission ID to be set")
	}
	if *mission.ParentMissionID != parentID {
		t.Error("parent mission ID mismatch")
	}
	if mission.Depth != 1 {
		t.Errorf("expected depth=1, got %d", mission.Depth)
	}
}

// TestMissionClientCreate_AutoGenerateName verifies name auto-generation.
func TestMissionClientCreate_AutoGenerateName(t *testing.T) {
	ctx := context.Background()
	store := &mockMissionStore{}
	orchestrator := &mockMissionOrchestrator{}

	client := NewMissionClient(store, orchestrator)

	// Create mission with name
	wf := &mockMission{
		Name: "auto-mission",
		Nodes: map[string]*mockMissionNode{
			"node1": {ID: "node1", Type: mockNodeTypeAgent},
		},
	}

	// Create request without name
	req := &CreateMissionRequest{
		Mission:  wf,
		TargetID: types.NewID(),
	}

	// Create mission
	mission, err := client.Create(ctx, req)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Verify name was auto-generated from mission
	if mission.Name != "auto-mission" {
		t.Errorf("expected name='auto-mission', got %s", mission.Name)
	}
}

// TestMissionClientCreate_ValidationErrors verifies validation error handling.
func TestMissionClientCreate_ValidationErrors(t *testing.T) {
	ctx := context.Background()
	store := &mockMissionStore{}
	orchestrator := &mockMissionOrchestrator{}

	client := NewMissionClient(store, orchestrator)

	tests := []struct {
		name    string
		req     *CreateMissionRequest
		wantErr string
	}{
		{
			name:    "nil request",
			req:     nil,
			wantErr: "request cannot be nil",
		},
		{
			name: "nil mission",
			req: &CreateMissionRequest{
				TargetID: types.NewID(),
			},
			wantErr: "mission cannot be nil",
		},
		{
			name: "zero target ID",
			req: &CreateMissionRequest{
				Mission: &mockMission{
					Nodes: map[string]*mockMissionNode{
						"node1": {ID: "node1", Type: mockNodeTypeAgent},
					},
				},
			},
			wantErr: "target ID is required",
		},
		{
			name: "empty mission nodes",
			req: &CreateMissionRequest{
				Mission: &mockMission{
					Nodes: map[string]*mockMissionNode{},
				},
				TargetID: types.NewID(),
			},
			wantErr: "mission must contain at least one node",
		},
		{
			name: "depth limit exceeded",
			req: &CreateMissionRequest{
				Mission: &mockMission{
					Nodes: map[string]*mockMissionNode{
						"node1": {ID: "node1", Type: mockNodeTypeAgent},
					},
				},
				TargetID:        types.NewID(),
				ParentMissionID: func() *types.ID { id := types.NewID(); return &id }(),
				ParentDepth:     2, // Would create depth 3, which equals limit
			},
			wantErr: "mission depth limit exceeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.Create(ctx, tt.req)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			// Check error message contains expected text
			if err.Error() == "" {
				t.Error("error message is empty")
			}
		})
	}
}

// TestMissionClientCreate_ConstraintValidation verifies constraint validation.
func TestMissionClientCreate_ConstraintValidation(t *testing.T) {
	ctx := context.Background()
	store := &mockMissionStore{}
	orchestrator := &mockMissionOrchestrator{}

	client := NewMissionClient(store, orchestrator)

	// Create request with invalid constraints
	req := &CreateMissionRequest{
		Mission: &mockMission{
			Nodes: map[string]*mockMissionNode{
				"node1": {ID: "node1", Type: mockNodeTypeAgent},
			},
		},
		TargetID: types.NewID(),
		Constraints: &MissionConstraints{
			MaxDuration: -1 * time.Hour, // Invalid: negative duration
		},
	}

	// Should fail validation
	_, err := client.Create(ctx, req)
	if err == nil {
		t.Fatal("expected validation error for negative max_duration")
	}
}

// TestMissionClient_Run tests the Run method with table-driven tests.
func TestMissionClient_Run(t *testing.T) {
	tests := []struct {
		name        string
		missionID   string
		setupMocks  func(*mockMissionStore, *mockMissionOrchestrator)
		wantErr     bool
		errContains string
	}{
		{
			name:      "successful run of pending mission",
			missionID: types.NewID().String(),
			setupMocks: func(store *mockMissionStore, orch *mockMissionOrchestrator) {
				mission := createTestMissionWithStatus(MissionStatusPending)
				store.getResult = mission
				store.getError = nil
				orch.executeResult = &MissionResult{
					MissionID: mission.ID,
					Status:    MissionStatusCompleted,
				}
			},
			wantErr: false,
		},
		{
			name:      "invalid mission ID",
			missionID: "invalid-id",
			setupMocks: func(store *mockMissionStore, orch *mockMissionOrchestrator) {
				// No setup needed
			},
			wantErr:     true,
			errContains: "invalid mission ID",
		},
		{
			name:      "mission not found",
			missionID: types.NewID().String(),
			setupMocks: func(store *mockMissionStore, orch *mockMissionOrchestrator) {
				store.getError = errors.New("not found")
			},
			wantErr:     true,
			errContains: "failed to load mission",
		},
		{
			name:      "invalid state transition",
			missionID: types.NewID().String(),
			setupMocks: func(store *mockMissionStore, orch *mockMissionOrchestrator) {
				mission := createTestMissionWithStatus(MissionStatusCompleted)
				store.getResult = mission
			},
			wantErr:     true,
			errContains: "invalid state transition",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockMissionStore{}
			orch := &mockMissionOrchestrator{}
			tt.setupMocks(store, orch)

			client := NewMissionClient(store, orch)

			err := client.Run(context.Background(), tt.missionID)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				// Give goroutine a moment to start
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

// TestMissionClient_GetStatus tests the GetStatus method with table-driven tests.
func TestMissionClient_GetStatus(t *testing.T) {
	tests := []struct {
		name        string
		missionID   string
		setupMocks  func(*mockMissionStore)
		wantErr     bool
		errContains string
		validate    func(*testing.T, *MissionStatusInfo)
	}{
		{
			name:      "get status of running mission",
			missionID: types.NewID().String(),
			setupMocks: func(store *mockMissionStore) {
				mission := createTestMissionWithStatus(MissionStatusRunning)
				mission.Checkpoint = &MissionCheckpoint{
					PendingNodes: []string{"node-2", "node-3"},
				}
				store.getResult = mission
			},
			wantErr: false,
			validate: func(t *testing.T, info *MissionStatusInfo) {
				assert.Equal(t, MissionStatusRunning, info.Status)
				assert.Equal(t, 0.5, info.Progress)
				assert.Equal(t, "node-2", info.Phase)
				assert.Equal(t, int64(1000), info.TokenUsage)
			},
		},
		{
			name:      "get status of completed mission",
			missionID: types.NewID().String(),
			setupMocks: func(store *mockMissionStore) {
				mission := createTestMissionWithStatus(MissionStatusCompleted)
				store.getResult = mission
			},
			wantErr: false,
			validate: func(t *testing.T, info *MissionStatusInfo) {
				assert.Equal(t, MissionStatusCompleted, info.Status)
				assert.Equal(t, 1.0, info.Progress)
				assert.Greater(t, info.Duration, time.Duration(0))
			},
		},
		{
			name:      "invalid mission ID",
			missionID: "invalid-id",
			setupMocks: func(store *mockMissionStore) {
				// No setup needed
			},
			wantErr:     true,
			errContains: "invalid mission ID",
		},
		{
			name:      "mission not found",
			missionID: types.NewID().String(),
			setupMocks: func(store *mockMissionStore) {
				store.getError = errors.New("not found")
			},
			wantErr:     true,
			errContains: "failed to load mission",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockMissionStore{}
			orch := &mockMissionOrchestrator{}
			tt.setupMocks(store)

			client := NewMissionClient(store, orch)

			status, err := client.GetStatus(context.Background(), tt.missionID)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, status)
			} else {
				require.NoError(t, err)
				require.NotNil(t, status)
				if tt.validate != nil {
					tt.validate(t, status)
				}
			}
		})
	}
}

// TestMissionClient_WaitForCompletion tests the WaitForCompletion method with table-driven tests.
func TestMissionClient_WaitForCompletion(t *testing.T) {
	tests := []struct {
		name        string
		missionID   string
		timeout     time.Duration
		setupMocks  func(*mockMissionStore)
		wantErr     bool
		errContains string
		validate    func(*testing.T, *MissionResult)
	}{
		{
			name:      "mission completes successfully",
			missionID: types.NewID().String(),
			timeout:   5 * time.Second,
			setupMocks: func(store *mockMissionStore) {
				// Simulate mission transitioning from running to completed
				runningMission := createTestMissionWithStatus(MissionStatusRunning)
				completedMission := createTestMissionWithStatus(MissionStatusCompleted)
				store.getResults = []*Mission{runningMission, completedMission}
				store.getResultIndex = 0
			},
			wantErr: false,
			validate: func(t *testing.T, result *MissionResult) {
				assert.Equal(t, MissionStatusCompleted, result.Status)
				assert.NotNil(t, result.Metrics)
			},
		},
		{
			name:      "mission fails during execution",
			missionID: types.NewID().String(),
			timeout:   5 * time.Second,
			setupMocks: func(store *mockMissionStore) {
				failedMission := createTestMissionWithStatus(MissionStatusFailed)
				failedMission.Error = "execution failed"
				store.getResult = failedMission
			},
			wantErr: false,
			validate: func(t *testing.T, result *MissionResult) {
				assert.Equal(t, MissionStatusFailed, result.Status)
				assert.Equal(t, "execution failed", result.Error)
			},
		},
		{
			name:      "timeout waiting for completion",
			missionID: types.NewID().String(),
			timeout:   100 * time.Millisecond,
			setupMocks: func(store *mockMissionStore) {
				runningMission := createTestMissionWithStatus(MissionStatusRunning)
				store.getResult = runningMission
			},
			wantErr:     true,
			errContains: "context deadline exceeded",
		},
		{
			name:      "invalid mission ID",
			missionID: "invalid-id",
			timeout:   5 * time.Second,
			setupMocks: func(store *mockMissionStore) {
				// No setup needed
			},
			wantErr:     true,
			errContains: "invalid mission ID",
		},
		{
			name:      "error checking status",
			missionID: types.NewID().String(),
			timeout:   5 * time.Second,
			setupMocks: func(store *mockMissionStore) {
				store.getError = errors.New("database error")
			},
			wantErr:     true,
			errContains: "failed to check mission status",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockMissionStore{}
			orch := &mockMissionOrchestrator{}
			tt.setupMocks(store)

			client := NewMissionClient(store, orch)

			result, err := client.WaitForCompletion(context.Background(), tt.missionID, tt.timeout)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				if tt.validate != nil {
					tt.validate(t, result)
				}
			}
		})
	}
}

// TestMissionClient_List tests the List method with table-driven tests.
func TestMissionClient_List(t *testing.T) {
	tests := []struct {
		name        string
		filter      *MissionFilter
		setupMocks  func(*mockMissionStore)
		wantErr     bool
		errContains string
		validate    func(*testing.T, []*Mission)
	}{
		{
			name:   "list all missions with default filter",
			filter: nil,
			setupMocks: func(store *mockMissionStore) {
				missions := []*Mission{
					createTestMissionWithStatus(MissionStatusCompleted),
					createTestMissionWithStatus(MissionStatusRunning),
				}
				store.listResult = missions
			},
			wantErr: false,
			validate: func(t *testing.T, missions []*Mission) {
				assert.Len(t, missions, 2)
			},
		},
		{
			name: "list missions with status filter",
			filter: &MissionFilter{
				Status: func() *MissionStatus { s := MissionStatusRunning; return &s }(),
				Limit:  10,
				Offset: 0,
			},
			setupMocks: func(store *mockMissionStore) {
				missions := []*Mission{
					createTestMissionWithStatus(MissionStatusRunning),
				}
				store.listResult = missions
			},
			wantErr: false,
			validate: func(t *testing.T, missions []*Mission) {
				assert.Len(t, missions, 1)
				assert.Equal(t, MissionStatusRunning, missions[0].Status)
			},
		},
		{
			name: "empty result set",
			filter: &MissionFilter{
				Limit: 100,
			},
			setupMocks: func(store *mockMissionStore) {
				store.listResult = []*Mission{}
			},
			wantErr: false,
			validate: func(t *testing.T, missions []*Mission) {
				assert.Empty(t, missions)
			},
		},
		{
			name: "invalid filter - negative limit",
			filter: &MissionFilter{
				Limit: -1,
			},
			setupMocks: func(store *mockMissionStore) {
				// No setup needed
			},
			wantErr:     true,
			errContains: "limit cannot be negative",
		},
		{
			name: "invalid filter - negative offset",
			filter: &MissionFilter{
				Offset: -1,
			},
			setupMocks: func(store *mockMissionStore) {
				// No setup needed
			},
			wantErr:     true,
			errContains: "offset cannot be negative",
		},
		{
			name: "store error",
			filter: &MissionFilter{
				Limit: 10,
			},
			setupMocks: func(store *mockMissionStore) {
				store.listError = errors.New("database error")
			},
			wantErr:     true,
			errContains: "failed to list missions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockMissionStore{}
			orch := &mockMissionOrchestrator{}
			tt.setupMocks(store)

			client := NewMissionClient(store, orch)

			missions, err := client.List(context.Background(), tt.filter)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, missions)
			} else {
				require.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, missions)
				}
			}
		})
	}
}

// TestMissionClient_Cancel tests the Cancel method with table-driven tests.
func TestMissionClient_Cancel(t *testing.T) {
	tests := []struct {
		name        string
		missionID   types.ID
		setupMocks  func(*mockMissionStore)
		wantErr     bool
		errContains string
	}{
		{
			name:      "cancel running mission",
			missionID: types.NewID(),
			setupMocks: func(store *mockMissionStore) {
				mission := createTestMissionWithStatus(MissionStatusRunning)
				store.getResult = mission
			},
			wantErr: false,
		},
		{
			name:      "cancel pending mission",
			missionID: types.NewID(),
			setupMocks: func(store *mockMissionStore) {
				mission := createTestMissionWithStatus(MissionStatusPending)
				store.getResult = mission
			},
			wantErr: false,
		},
		{
			name:      "cancel already completed mission (idempotent)",
			missionID: types.NewID(),
			setupMocks: func(store *mockMissionStore) {
				mission := createTestMissionWithStatus(MissionStatusCompleted)
				store.getResult = mission
			},
			wantErr: false,
		},
		{
			name:      "cancel already cancelled mission (idempotent)",
			missionID: types.NewID(),
			setupMocks: func(store *mockMissionStore) {
				mission := createTestMissionWithStatus(MissionStatusCancelled)
				store.getResult = mission
			},
			wantErr: false,
		},
		{
			name:      "zero mission ID",
			missionID: types.ID(""),
			setupMocks: func(store *mockMissionStore) {
				// No setup needed
			},
			wantErr:     true,
			errContains: "mission ID is required",
		},
		{
			name:      "mission not found",
			missionID: types.NewID(),
			setupMocks: func(store *mockMissionStore) {
				store.getError = errors.New("not found")
			},
			wantErr:     true,
			errContains: "failed to get mission",
		},
		{
			name:      "update status error",
			missionID: types.NewID(),
			setupMocks: func(store *mockMissionStore) {
				mission := createTestMissionWithStatus(MissionStatusRunning)
				store.getResult = mission
				store.updateStatusError = errors.New("database error")
			},
			wantErr:     true,
			errContains: "failed to cancel mission",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockMissionStore{}
			orch := &mockMissionOrchestrator{}
			tt.setupMocks(store)

			client := NewMissionClient(store, orch)

			err := client.Cancel(context.Background(), tt.missionID)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestMissionClient_GetResults tests the GetResults method with table-driven tests.
func TestMissionClient_GetResults(t *testing.T) {
	tests := []struct {
		name        string
		missionID   types.ID
		setupMocks  func(*mockMissionStore)
		wantErr     bool
		errContains string
		validate    func(*testing.T, *MissionResult)
	}{
		{
			name:      "get results of completed mission",
			missionID: types.NewID(),
			setupMocks: func(store *mockMissionStore) {
				mission := createTestMissionWithStatus(MissionStatusCompleted)
				mission.MissionDefinitionJSON = `{"output": "test result"}`
				store.getResult = mission
			},
			wantErr: false,
			validate: func(t *testing.T, result *MissionResult) {
				assert.Equal(t, MissionStatusCompleted, result.Status)
				assert.NotNil(t, result.Metrics)
				assert.NotEmpty(t, result.MissionResult)
				assert.Equal(t, "test result", result.MissionResult["output"])
			},
		},
		{
			name:      "get results of failed mission",
			missionID: types.NewID(),
			setupMocks: func(store *mockMissionStore) {
				mission := createTestMissionWithStatus(MissionStatusFailed)
				mission.Error = "execution error"
				store.getResult = mission
			},
			wantErr: false,
			validate: func(t *testing.T, result *MissionResult) {
				assert.Equal(t, MissionStatusFailed, result.Status)
				assert.Equal(t, "execution error", result.Error)
			},
		},
		{
			name:      "get results with invalid mission JSON",
			missionID: types.NewID(),
			setupMocks: func(store *mockMissionStore) {
				mission := createTestMissionWithStatus(MissionStatusCompleted)
				mission.MissionDefinitionJSON = `{invalid json}`
				store.getResult = mission
			},
			wantErr: false,
			validate: func(t *testing.T, result *MissionResult) {
				// Should succeed but mission result will be nil
				assert.Equal(t, MissionStatusCompleted, result.Status)
			},
		},
		{
			name:      "zero mission ID",
			missionID: types.ID(""),
			setupMocks: func(store *mockMissionStore) {
				// No setup needed
			},
			wantErr:     true,
			errContains: "mission ID is required",
		},
		{
			name:      "mission not found",
			missionID: types.NewID(),
			setupMocks: func(store *mockMissionStore) {
				store.getError = errors.New("not found")
			},
			wantErr:     true,
			errContains: "failed to get mission",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockMissionStore{}
			orch := &mockMissionOrchestrator{}
			tt.setupMocks(store)

			client := NewMissionClient(store, orch)

			result, err := client.GetResults(context.Background(), tt.missionID)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				if tt.validate != nil {
					tt.validate(t, result)
				}
			}
		})
	}
}

// TestMissionClient_ConcurrentOperations tests thread safety.
func TestMissionClient_ConcurrentOperations(t *testing.T) {
	t.Run("concurrent list operations", func(t *testing.T) {
		store := &mockMissionStore{}
		orch := &mockMissionOrchestrator{}

		missions := []*Mission{
			createTestMissionWithStatus(MissionStatusCompleted),
		}
		store.listResult = missions

		client := NewMissionClient(store, orch)

		// Run 10 concurrent List operations
		const numOps = 10
		errors := make(chan error, numOps)

		for i := 0; i < numOps; i++ {
			go func() {
				_, err := client.List(context.Background(), nil)
				errors <- err
			}()
		}

		// Check all operations succeeded
		for i := 0; i < numOps; i++ {
			err := <-errors
			assert.NoError(t, err)
		}
	})

	t.Run("concurrent status checks", func(t *testing.T) {
		store := &mockMissionStore{}
		orch := &mockMissionOrchestrator{}

		mission := createTestMissionWithStatus(MissionStatusRunning)
		store.getResult = mission

		client := NewMissionClient(store, orch)

		// Run 10 concurrent GetStatus operations
		const numOps = 10
		errors := make(chan error, numOps)

		for i := 0; i < numOps; i++ {
			go func() {
				_, err := client.GetStatus(context.Background(), mission.ID.String())
				errors <- err
			}()
		}

		// Check all operations succeeded
		for i := 0; i < numOps; i++ {
			err := <-errors
			assert.NoError(t, err)
		}
	})
}

// TestMissionClient_SerializeMission tests mission serialization.
func TestMissionClient_SerializeMission(t *testing.T) {
	t.Run("successful serialization", func(t *testing.T) {
		store := &mockMissionStore{}
		orch := &mockMissionOrchestrator{}
		client := NewMissionClient(store, orch)

		wf := &mockMission{
			Name: "test-mission",
			Nodes: map[string]*mockMissionNode{
				"node1": {ID: "node1", Type: mockNodeTypeAgent},
			},
		}

		result, err := client.serializeMission(wf)

		assert.NoError(t, err)
		assert.NotEmpty(t, result)

		// Verify it's valid JSON
		var parsed mockMission
		err = json.Unmarshal([]byte(result), &parsed)
		assert.NoError(t, err)
		assert.Equal(t, wf.Name, parsed.Name)
	})
}
