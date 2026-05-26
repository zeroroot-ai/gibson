package harness

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/types"
	sdkmission "github.com/zeroroot-ai/sdk/mission"
	"go.opentelemetry.io/otel/trace/noop"
)

// mockMissionOperator is a full mock implementation of MissionOperator for testing.
type mockMissionOperator struct {
	// Storage for missions
	missions map[string]*MissionInfo
	statuses map[string]*MissionStatusInfo
	results  map[string]*MissionResultInfo
	records  []*MissionRecord

	// Behavior flags
	createErr          error
	runErr             error
	getStatusErr       error
	waitErr            error
	listErr            error
	cancelErr          error
	getResultsErr      error
	waitDelay          time.Duration
	runningMissionIDs  []string
	cancelledMissionID string
}

func newMockMissionOperator() *mockMissionOperator {
	return &mockMissionOperator{
		missions: make(map[string]*MissionInfo),
		statuses: make(map[string]*MissionStatusInfo),
		results:  make(map[string]*MissionResultInfo),
		records:  []*MissionRecord{},
	}
}

func (m *mockMissionOperator) CreateMission(ctx context.Context, req *CreateMissionRequest) (*MissionInfo, error) {
	if m.createErr != nil {
		return nil, m.createErr
	}

	missionID := types.NewID()
	info := &MissionInfo{
		ID:              missionID,
		Name:            req.Name,
		Status:          "pending",
		TargetID:        req.TargetID,
		ParentMissionID: req.ParentMissionID,
		CreatedAt:       time.Now(),
		Tags:            req.Tags,
	}
	m.missions[missionID.String()] = info

	// Add to records for listing
	record := &MissionRecord{
		ID:              missionID,
		ParentMissionID: req.ParentMissionID,
		Depth:           req.ParentDepth + 1,
		Status:          "pending",
	}
	m.records = append(m.records, record)

	return info, nil
}

func (m *mockMissionOperator) Run(ctx context.Context, missionID string) error {
	if m.runErr != nil {
		return m.runErr
	}

	// Update mission status to running
	if info, ok := m.missions[missionID]; ok {
		info.Status = MissionStatusRunning
	}

	// Update records
	for _, r := range m.records {
		if r.ID.String() == missionID {
			r.Status = MissionStatusRunning
			break
		}
	}

	m.runningMissionIDs = append(m.runningMissionIDs, missionID)

	return nil
}

func (m *mockMissionOperator) GetStatus(ctx context.Context, missionID string) (*MissionStatusInfo, error) {
	if m.getStatusErr != nil {
		return nil, m.getStatusErr
	}

	if status, ok := m.statuses[missionID]; ok {
		return status, nil
	}

	// Return default status if not set
	return &MissionStatusInfo{
		Status:   MissionStatusRunning,
		Progress: 0.5,
		Phase:    "executing",
		FindingCounts: map[string]int{
			"high": 2,
			"low":  1,
		},
		TokenUsage: 1000,
		Duration:   time.Second * 10,
		Error:      "",
	}, nil
}

func (m *mockMissionOperator) WaitForCompletion(ctx context.Context, missionID string, timeout time.Duration) (*MissionResultInfo, error) {
	if m.waitErr != nil {
		return nil, m.waitErr
	}

	// Simulate wait delay
	if m.waitDelay > 0 {
		select {
		case <-time.After(m.waitDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Return result if set
	if result, ok := m.results[missionID]; ok {
		return result, nil
	}

	// Return default result
	return &MissionResultInfo{
		MissionID: missionID,
		Status:    "completed",
		Metrics: &MissionMetricsInfo{
			Duration:      time.Minute,
			TotalTokens:   5000,
			TotalFindings: 3,
		},
		FindingIDs: []string{"finding-1", "finding-2", "finding-3"},
		MissionResult: map[string]any{
			"success": true,
			"message": "mission completed",
		},
		CompletedAt: time.Now(),
	}, nil
}

func (m *mockMissionOperator) List(ctx context.Context, filter *MissionFilter) ([]*MissionRecord, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}

	if filter == nil {
		return m.records, nil
	}

	// Filter records
	var result []*MissionRecord
	for _, record := range m.records {
		match := true

		// Filter by ParentMissionID
		if filter.ParentMissionID != nil {
			if record.ParentMissionID == nil || *record.ParentMissionID != *filter.ParentMissionID {
				match = false
			}
		}

		// Filter by Status
		if filter.Status != nil && record.Status != *filter.Status {
			match = false
		}

		if match {
			result = append(result, record)
		}
	}

	// Apply limit and offset
	if filter.Limit > 0 {
		start := filter.Offset
		if start > len(result) {
			return []*MissionRecord{}, nil
		}
		end := start + filter.Limit
		if end > len(result) {
			end = len(result)
		}
		result = result[start:end]
	}

	return result, nil
}

func (m *mockMissionOperator) Cancel(ctx context.Context, missionID types.ID) error {
	if m.cancelErr != nil {
		return m.cancelErr
	}

	m.cancelledMissionID = missionID.String()

	// Update mission status to cancelled
	if info, ok := m.missions[missionID.String()]; ok {
		info.Status = "cancelled"
	}

	// Update records
	for _, r := range m.records {
		if r.ID == missionID {
			r.Status = "cancelled"
			break
		}
	}

	return nil
}

func (m *mockMissionOperator) GetResults(ctx context.Context, missionID types.ID) (*MissionResultInfo, error) {
	if m.getResultsErr != nil {
		return nil, m.getResultsErr
	}

	// Return result if set
	if result, ok := m.results[missionID.String()]; ok {
		return result, nil
	}

	// Return default result
	return &MissionResultInfo{
		MissionID: missionID.String(),
		Status:    "completed",
		Metrics: &MissionMetricsInfo{
			Duration:      time.Minute,
			TotalTokens:   5000,
			TotalFindings: 3,
		},
		FindingIDs: []string{"finding-1", "finding-2"},
		MissionResult: map[string]any{
			"status":  "success",
			"output":  "test results",
			"details": "completed successfully",
		},
		CompletedAt: time.Now(),
	}, nil
}

// createTestMissionHarness creates a harness instance for testing with mock mission client.
func createTestMissionHarness(missionClient MissionOperator, spawnLimits SpawnLimits) *DefaultAgentHarness {
	return &DefaultAgentHarness{
		missionClient: missionClient,
		spawnLimits:   spawnLimits,
		missionCtx: MissionContext{
			ID:           types.NewID(),
			Name:         "test-mission",
			CurrentAgent: "test-agent",
		},
		tracer: noop.NewTracerProvider().Tracer("test"),
		logger: slog.Default(),
	}
}

// TestCreateMission tests the CreateMission method with valid mission.
func TestCreateMission(t *testing.T) {
	ctx := context.Background()
	mockClient := newMockMissionOperator()

	// Create parent mission record for spawn limit checks
	parentID := types.NewID()
	mockClient.records = append(mockClient.records, &MissionRecord{
		ID:              parentID,
		ParentMissionID: nil,
		Depth:           0,
		Status:          MissionStatusRunning,
	})

	harness := createTestMissionHarness(mockClient, DefaultSpawnLimits())
	harness.missionCtx.ID = parentID

	// Create a simple mission struct
	mission := map[string]any{
		"name":  "test-mission",
		"steps": []string{"step1", "step2"},
	}

	targetID := types.NewID()
	opts := &sdkmission.CreateMissionOpts{
		Name: "Test Mission",
		Tags: []string{"test", "integration"},
		Metadata: map[string]any{
			"priority": "high",
		},
		Constraints: &sdkmission.MissionConstraints{
			MaxDuration: time.Hour,
			MaxTokens:   100000,
			MaxCost:     10.0,
			MaxFindings: 100,
		},
	}

	// Execute
	missionInfo, err := harness.CreateMission(ctx, mission, targetID.String(), opts)

	// Verify
	if err != nil {
		t.Fatalf("CreateMission failed: %v", err)
	}

	if missionInfo == nil {
		t.Fatal("Expected mission info, got nil")
	}

	if missionInfo.Name != "Test Mission" {
		t.Errorf("Expected name 'Test Mission', got %q", missionInfo.Name)
	}

	if len(missionInfo.Tags) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(missionInfo.Tags))
	}

	if missionInfo.ParentMissionID != parentID.String() {
		t.Errorf("Expected parent mission ID %s, got %s", parentID.String(), missionInfo.ParentMissionID)
	}
}

// TestCreateMission_NoMissionClient tests that CreateMission fails when mission client is nil.
func TestCreateMission_NoMissionClient(t *testing.T) {
	ctx := context.Background()
	harness := createTestMissionHarness(nil, DefaultSpawnLimits())

	mission := map[string]any{"name": "test"}
	targetID := types.NewID()

	_, err := harness.CreateMission(ctx, mission, targetID.String(), nil)

	if err == nil {
		t.Fatal("Expected error when mission client is nil, got nil")
	}

	if !stringContains(err.Error(), "mission management not enabled") {
		t.Errorf("Expected 'mission management not enabled' error, got %v", err)
	}
}

// TestCreateMission_InvalidMission tests CreateMission with invalid mission that cannot be serialized.
func TestCreateMission_InvalidMission(t *testing.T) {
	ctx := context.Background()
	mockClient := newMockMissionOperator()
	harness := createTestMissionHarness(mockClient, DefaultSpawnLimits())

	// Create a mission with un-serializable content (channel)
	mission := map[string]any{
		"name":    "test",
		"channel": make(chan int), // channels cannot be JSON marshaled
	}

	targetID := types.NewID()

	_, err := harness.CreateMission(ctx, mission, targetID.String(), nil)

	if err == nil {
		t.Fatal("Expected error for invalid mission, got nil")
	}

	if !stringContains(err.Error(), "failed to serialize mission") {
		t.Errorf("Expected 'failed to serialize mission' error, got %v", err)
	}
}

// TestCreateMission_InvalidTargetID tests CreateMission with invalid target ID.
func TestCreateMission_InvalidTargetID(t *testing.T) {
	ctx := context.Background()
	mockClient := newMockMissionOperator()
	harness := createTestMissionHarness(mockClient, DefaultSpawnLimits())

	mission := map[string]any{"name": "test"}

	_, err := harness.CreateMission(ctx, mission, "invalid-id", nil)

	if err == nil {
		t.Fatal("Expected error for invalid target ID, got nil")
	}

	if !stringContains(err.Error(), "invalid target ID") {
		t.Errorf("Expected 'invalid target ID' error, got %v", err)
	}
}

// TestCreateMission_SpawnLimitExceeded tests that CreateMission enforces spawn limits.
func TestCreateMission_SpawnLimitExceeded(t *testing.T) {
	ctx := context.Background()
	mockClient := newMockMissionOperator()

	parentID := types.NewID()

	// Create parent and max number of children
	mockClient.records = append(mockClient.records, &MissionRecord{
		ID:              parentID,
		ParentMissionID: nil,
		Depth:           0,
		Status:          MissionStatusRunning,
	})

	// Add 10 children (at limit)
	for i := 0; i < 10; i++ {
		mockClient.records = append(mockClient.records, &MissionRecord{
			ID:              types.NewID(),
			ParentMissionID: &parentID,
			Depth:           1,
			Status:          "pending",
		})
	}

	limits := SpawnLimits{
		MaxChildMissions:      10,
		MaxConcurrentMissions: 100,
		MaxMissionDepth:       5,
	}

	harness := createTestMissionHarness(mockClient, limits)
	harness.missionCtx.ID = parentID

	mission := map[string]any{"name": "test"}
	targetID := types.NewID()

	_, err := harness.CreateMission(ctx, mission, targetID.String(), nil)

	if err == nil {
		t.Fatal("Expected spawn limit error, got nil")
	}

	if !stringContains(err.Error(), "maximum child limit") {
		t.Errorf("Expected 'maximum child limit' error, got %v", err)
	}
}

// TestRunMission tests the RunMission method.
func TestRunMission(t *testing.T) {
	ctx := context.Background()
	mockClient := newMockMissionOperator()

	missionID := types.NewID()
	mockClient.missions[missionID.String()] = &MissionInfo{
		ID:     missionID,
		Name:   "Test Mission",
		Status: "pending",
	}

	harness := createTestMissionHarness(mockClient, DefaultSpawnLimits())

	opts := &sdkmission.RunMissionOpts{
		Wait:    false,
		Timeout: 0,
	}

	err := harness.RunMission(ctx, missionID.String(), opts)

	if err != nil {
		t.Fatalf("RunMission failed: %v", err)
	}

	// Verify mission was marked as running
	if len(mockClient.runningMissionIDs) != 1 {
		t.Errorf("Expected 1 running mission, got %d", len(mockClient.runningMissionIDs))
	}

	if mockClient.runningMissionIDs[0] != missionID.String() {
		t.Errorf("Expected mission %s to be running, got %s", missionID.String(), mockClient.runningMissionIDs[0])
	}
}

// TestRunMission_WithWait tests RunMission with Wait option.
func TestRunMission_WithWait(t *testing.T) {
	ctx := context.Background()
	mockClient := newMockMissionOperator()

	missionID := types.NewID()
	mockClient.missions[missionID.String()] = &MissionInfo{
		ID:     missionID,
		Name:   "Test Mission",
		Status: "pending",
	}

	// Set a short wait delay
	mockClient.waitDelay = 10 * time.Millisecond

	harness := createTestMissionHarness(mockClient, DefaultSpawnLimits())

	opts := &sdkmission.RunMissionOpts{
		Wait:    true,
		Timeout: time.Second,
	}

	start := time.Now()
	err := harness.RunMission(ctx, missionID.String(), opts)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("RunMission with wait failed: %v", err)
	}

	// Verify it actually waited
	if elapsed < mockClient.waitDelay {
		t.Errorf("Expected wait of at least %v, got %v", mockClient.waitDelay, elapsed)
	}
}

// TestRunMission_NoMissionClient tests RunMission fails when mission client is nil.
func TestRunMission_NoMissionClient(t *testing.T) {
	ctx := context.Background()
	harness := createTestMissionHarness(nil, DefaultSpawnLimits())

	err := harness.RunMission(ctx, "mission-id", nil)

	if err == nil {
		t.Fatal("Expected error when mission client is nil, got nil")
	}

	if !stringContains(err.Error(), "mission management not enabled") {
		t.Errorf("Expected 'mission management not enabled' error, got %v", err)
	}
}

// TestGetMissionStatus tests the GetMissionStatus method.
func TestGetMissionStatus(t *testing.T) {
	ctx := context.Background()
	mockClient := newMockMissionOperator()

	missionID := types.NewID()
	expectedStatus := &MissionStatusInfo{
		Status:   MissionStatusRunning,
		Progress: 0.75,
		Phase:    "scanning",
		FindingCounts: map[string]int{
			"critical": 1,
			"high":     3,
			"medium":   5,
		},
		TokenUsage: 2500,
		Duration:   time.Minute * 5,
		Error:      "",
	}
	mockClient.statuses[missionID.String()] = expectedStatus

	harness := createTestMissionHarness(mockClient, DefaultSpawnLimits())

	status, err := harness.GetMissionStatus(ctx, missionID.String())

	if err != nil {
		t.Fatalf("GetMissionStatus failed: %v", err)
	}

	if status == nil {
		t.Fatal("Expected status, got nil")
	}

	if status.Status != sdkmission.MissionStatus(expectedStatus.Status) {
		t.Errorf("Expected status %q, got %q", expectedStatus.Status, status.Status)
	}

	if status.Progress != expectedStatus.Progress {
		t.Errorf("Expected progress %f, got %f", expectedStatus.Progress, status.Progress)
	}

	if status.FindingCounts["high"] != 3 {
		t.Errorf("Expected 3 high findings, got %d", status.FindingCounts["high"])
	}
}

// TestWaitForMission tests the WaitForMission method.
func TestWaitForMission(t *testing.T) {
	ctx := context.Background()
	mockClient := newMockMissionOperator()

	missionID := types.NewID()
	expectedResult := &MissionResultInfo{
		MissionID: missionID.String(),
		Status:    "completed",
		Metrics: &MissionMetricsInfo{
			Duration:      time.Minute * 2,
			TotalTokens:   10000,
			TotalFindings: 5,
		},
		FindingIDs: []string{"finding-1", "finding-2", "finding-3"},
		MissionResult: map[string]any{
			"success": true,
			"data":    "test data",
		},
		CompletedAt: time.Now(),
	}
	mockClient.results[missionID.String()] = expectedResult

	harness := createTestMissionHarness(mockClient, DefaultSpawnLimits())

	result, err := harness.WaitForMission(ctx, missionID.String(), time.Minute)

	if err != nil {
		t.Fatalf("WaitForMission failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	if result.MissionID != missionID.String() {
		t.Errorf("Expected mission ID %s, got %s", missionID.String(), result.MissionID)
	}

	if result.Status != sdkmission.MissionStatus(expectedResult.Status) {
		t.Errorf("Expected status %q, got %q", expectedResult.Status, result.Status)
	}

	if result.Metrics.TokensUsed != expectedResult.Metrics.TotalTokens {
		t.Errorf("Expected %d tokens, got %d", expectedResult.Metrics.TotalTokens, result.Metrics.TokensUsed)
	}
}

// TestWaitForMission_Timeout tests WaitForMission with context timeout.
func TestWaitForMission_Timeout(t *testing.T) {
	mockClient := newMockMissionOperator()

	// Set a long wait delay that will exceed our timeout
	mockClient.waitDelay = time.Second * 2

	harness := createTestMissionHarness(mockClient, DefaultSpawnLimits())

	missionID := types.NewID()

	// Create context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := harness.WaitForMission(ctx, missionID.String(), time.Second)

	if err == nil {
		t.Fatal("Expected timeout error, got nil")
	}

	if !errors.Is(err, context.DeadlineExceeded) && !stringContains(err.Error(), "context") {
		t.Errorf("Expected context deadline error, got %v", err)
	}
}

// TestListMissions tests the ListMissions method with filters.
func TestListMissions(t *testing.T) {
	ctx := context.Background()
	mockClient := newMockMissionOperator()

	parentID := types.NewID()

	// Create multiple missions
	mockClient.records = []*MissionRecord{
		{
			ID:              types.NewID(),
			ParentMissionID: &parentID,
			Depth:           1,
			Status:          MissionStatusRunning,
		},
		{
			ID:              types.NewID(),
			ParentMissionID: &parentID,
			Depth:           1,
			Status:          "completed",
		},
		{
			ID:              types.NewID(),
			ParentMissionID: nil,
			Depth:           0,
			Status:          MissionStatusRunning,
		},
	}

	harness := createTestMissionHarness(mockClient, DefaultSpawnLimits())

	tests := []struct {
		name          string
		filter        *sdkmission.MissionFilter
		expectedCount int
	}{
		{
			name:          "list all missions",
			filter:        nil,
			expectedCount: 3,
		},
		{
			name: "filter by parent mission ID",
			filter: &sdkmission.MissionFilter{
				ParentMissionID: stringPtr(parentID.String()),
			},
			expectedCount: 2,
		},
		{
			name: "filter by status",
			filter: &sdkmission.MissionFilter{
				Status: sdkMissionStatusPtr(string(MissionStatusRunning)),
			},
			expectedCount: 2,
		},
		{
			name: "filter with limit",
			filter: &sdkmission.MissionFilter{
				Limit: 2,
			},
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			missions, err := harness.ListMissions(ctx, tt.filter)

			if err != nil {
				t.Fatalf("ListMissions failed: %v", err)
			}

			if len(missions) != tt.expectedCount {
				t.Errorf("Expected %d missions, got %d", tt.expectedCount, len(missions))
			}
		})
	}
}

// TestListMissions_InvalidFilter tests ListMissions with invalid filter.
func TestListMissions_InvalidFilter(t *testing.T) {
	ctx := context.Background()
	mockClient := newMockMissionOperator()
	harness := createTestMissionHarness(mockClient, DefaultSpawnLimits())

	filter := &sdkmission.MissionFilter{
		ParentMissionID: stringPtr("invalid-id"),
	}

	_, err := harness.ListMissions(ctx, filter)

	if err == nil {
		t.Fatal("Expected error for invalid filter, got nil")
	}

	if !stringContains(err.Error(), "invalid") {
		t.Errorf("Expected 'invalid' error, got %v", err)
	}
}

// TestCancelMission tests the CancelMission method.
func TestCancelMission(t *testing.T) {
	ctx := context.Background()
	mockClient := newMockMissionOperator()

	missionID := types.NewID()
	mockClient.missions[missionID.String()] = &MissionInfo{
		ID:     missionID,
		Name:   "Test Mission",
		Status: MissionStatusRunning,
	}

	harness := createTestMissionHarness(mockClient, DefaultSpawnLimits())

	err := harness.CancelMission(ctx, missionID.String())

	if err != nil {
		t.Fatalf("CancelMission failed: %v", err)
	}

	if mockClient.cancelledMissionID != missionID.String() {
		t.Errorf("Expected mission %s to be cancelled, got %s", missionID.String(), mockClient.cancelledMissionID)
	}
}

// TestCancelMission_InvalidID tests CancelMission with invalid mission ID.
func TestCancelMission_InvalidID(t *testing.T) {
	ctx := context.Background()
	mockClient := newMockMissionOperator()
	harness := createTestMissionHarness(mockClient, DefaultSpawnLimits())

	err := harness.CancelMission(ctx, "invalid-id")

	if err == nil {
		t.Fatal("Expected error for invalid mission ID, got nil")
	}

	if !stringContains(err.Error(), "invalid mission ID") {
		t.Errorf("Expected 'invalid mission ID' error, got %v", err)
	}
}

// TestCancelMission_Idempotent tests that CancelMission is idempotent.
func TestCancelMission_Idempotent(t *testing.T) {
	ctx := context.Background()
	mockClient := newMockMissionOperator()

	missionID := types.NewID()
	mockClient.missions[missionID.String()] = &MissionInfo{
		ID:     missionID,
		Name:   "Test Mission",
		Status: MissionStatusRunning,
	}

	harness := createTestMissionHarness(mockClient, DefaultSpawnLimits())

	// Cancel first time
	err := harness.CancelMission(ctx, missionID.String())
	if err != nil {
		t.Fatalf("First cancel failed: %v", err)
	}

	// Cancel second time (should not error)
	err = harness.CancelMission(ctx, missionID.String())
	if err != nil {
		t.Fatalf("Second cancel failed: %v", err)
	}
}

// TestGetMissionResults tests the GetMissionResults method.
func TestGetMissionResults(t *testing.T) {
	ctx := context.Background()
	mockClient := newMockMissionOperator()

	missionID := types.NewID()
	expectedResult := &MissionResultInfo{
		MissionID: missionID.String(),
		Status:    "completed",
		Metrics: &MissionMetricsInfo{
			Duration:      time.Minute * 3,
			TotalTokens:   15000,
			TotalFindings: 7,
		},
		FindingIDs: []string{"finding-1", "finding-2", "finding-3", "finding-4"},
		MissionResult: map[string]any{
			"status":          "success",
			"vulnerabilities": 4,
			"scan_time":       180,
		},
		CompletedAt: time.Now(),
	}
	mockClient.results[missionID.String()] = expectedResult

	harness := createTestMissionHarness(mockClient, DefaultSpawnLimits())

	result, err := harness.GetMissionResults(ctx, missionID.String())

	if err != nil {
		t.Fatalf("GetMissionResults failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	if result.MissionID != missionID.String() {
		t.Errorf("Expected mission ID %s, got %s", missionID.String(), result.MissionID)
	}

	if result.Metrics.FindingsCount != expectedResult.Metrics.TotalFindings {
		t.Errorf("Expected %d findings, got %d", expectedResult.Metrics.TotalFindings, result.Metrics.FindingsCount)
	}

	// Verify output contains expected data
	if result.Output != nil {
		if vulns, ok := result.Output["vulnerabilities"].(int); !ok || vulns != 4 {
			t.Errorf("Expected 4 vulnerabilities in output, got %v", result.Output["vulnerabilities"])
		}
	} else {
		t.Error("Expected output to be non-nil")
	}
}

// TestGetMissionResults_InvalidID tests GetMissionResults with invalid mission ID.
func TestGetMissionResults_InvalidID(t *testing.T) {
	ctx := context.Background()
	mockClient := newMockMissionOperator()
	harness := createTestMissionHarness(mockClient, DefaultSpawnLimits())

	_, err := harness.GetMissionResults(ctx, "invalid-id")

	if err == nil {
		t.Fatal("Expected error for invalid mission ID, got nil")
	}

	if !stringContains(err.Error(), "invalid mission ID") {
		t.Errorf("Expected 'invalid mission ID' error, got %v", err)
	}
}

// TestMissionLineageTracking tests that parent mission IDs are tracked correctly.
func TestMissionLineageTracking(t *testing.T) {
	ctx := context.Background()
	mockClient := newMockMissionOperator()

	parentID := types.NewID()
	mockClient.records = append(mockClient.records, &MissionRecord{
		ID:              parentID,
		ParentMissionID: nil,
		Depth:           0,
		Status:          MissionStatusRunning,
	})

	harness := createTestMissionHarness(mockClient, DefaultSpawnLimits())
	harness.missionCtx.ID = parentID

	mission := map[string]any{"name": "child-mission"}
	targetID := types.NewID()
	opts := &sdkmission.CreateMissionOpts{
		Name: "Child Mission",
	}

	// Create child mission
	childInfo, err := harness.CreateMission(ctx, mission, targetID.String(), opts)
	if err != nil {
		t.Fatalf("Failed to create child mission: %v", err)
	}

	// Verify parent mission ID is set correctly
	if childInfo.ParentMissionID != parentID.String() {
		t.Errorf("Expected parent mission ID %s, got %s", parentID.String(), childInfo.ParentMissionID)
	}

	// Verify lineage in records
	var childRecord *MissionRecord
	for _, r := range mockClient.records {
		if r.ID.String() == childInfo.ID {
			childRecord = r
			break
		}
	}

	if childRecord == nil {
		t.Fatal("Child mission not found in records")
	}

	if childRecord.ParentMissionID == nil {
		t.Fatal("Child record has nil parent mission ID")
	}

	if *childRecord.ParentMissionID != parentID {
		t.Errorf("Expected child record parent ID %s, got %s", parentID.String(), childRecord.ParentMissionID.String())
	}

	if childRecord.Depth != 1 {
		t.Errorf("Expected child depth 1, got %d", childRecord.Depth)
	}
}

// TestEndToEndMissionFlow tests the complete mission lifecycle.
func TestEndToEndMissionFlow(t *testing.T) {
	ctx := context.Background()
	mockClient := newMockMissionOperator()

	// Setup parent mission
	parentID := types.NewID()
	mockClient.records = append(mockClient.records, &MissionRecord{
		ID:              parentID,
		ParentMissionID: nil,
		Depth:           0,
		Status:          MissionStatusRunning,
	})

	harness := createTestMissionHarness(mockClient, DefaultSpawnLimits())
	harness.missionCtx.ID = parentID

	// Step 1: Create mission
	mission := map[string]any{
		"name":   "integration-test",
		"steps":  []string{"scan", "analyze", "report"},
		"config": map[string]any{"timeout": 300},
	}
	targetID := types.NewID()
	opts := &sdkmission.CreateMissionOpts{
		Name: "Integration Test Mission",
		Tags: []string{"test", "integration"},
		Constraints: &sdkmission.MissionConstraints{
			MaxDuration: time.Hour,
			MaxTokens:   50000,
		},
	}

	missionInfo, err := harness.CreateMission(ctx, mission, targetID.String(), opts)
	if err != nil {
		t.Fatalf("Step 1 (Create) failed: %v", err)
	}

	if missionInfo.ID == "" {
		t.Fatal("Created mission has empty ID")
	}

	// Step 2: Run mission
	runOpts := &sdkmission.RunMissionOpts{
		Wait:    false,
		Timeout: 0,
	}

	err = harness.RunMission(ctx, missionInfo.ID, runOpts)
	if err != nil {
		t.Fatalf("Step 2 (Run) failed: %v", err)
	}

	// Step 3: Get status
	status, err := harness.GetMissionStatus(ctx, missionInfo.ID)
	if err != nil {
		t.Fatalf("Step 3 (GetStatus) failed: %v", err)
	}

	if status.Status != sdkmission.MissionStatus(MissionStatusRunning) {
		t.Errorf("Expected status 'running', got %q", status.Status)
	}

	// Step 4: Wait for completion
	mockClient.waitDelay = 5 * time.Millisecond // Short delay for test

	result, err := harness.WaitForMission(ctx, missionInfo.ID, time.Second)
	if err != nil {
		t.Fatalf("Step 4 (Wait) failed: %v", err)
	}

	if result == nil {
		t.Fatal("Wait returned nil result")
	}

	// Step 5: Get results
	finalResult, err := harness.GetMissionResults(ctx, missionInfo.ID)
	if err != nil {
		t.Fatalf("Step 5 (GetResults) failed: %v", err)
	}

	if finalResult == nil {
		t.Fatal("GetResults returned nil")
	}

	if finalResult.MissionID != missionInfo.ID {
		t.Errorf("Result mission ID mismatch: expected %s, got %s", missionInfo.ID, finalResult.MissionID)
	}

	// Verify metrics are populated
	if finalResult.Metrics.Duration == 0 {
		t.Error("Expected non-zero duration in metrics")
	}

	if finalResult.Metrics.TokensUsed == 0 {
		t.Error("Expected non-zero token usage in metrics")
	}
}

// TestSpawnLimitIntegration tests spawn limit enforcement during mission creation.
func TestSpawnLimitIntegration(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name             string
		existingDepth    int
		existingChildren int
		runningCount     int
		limits           SpawnLimits
		expectError      bool
		errorContains    string
	}{
		{
			name:             "within all limits",
			existingDepth:    0,
			existingChildren: 2,
			runningCount:     10,
			limits: SpawnLimits{
				MaxChildMissions:      10,
				MaxConcurrentMissions: 50,
				MaxMissionDepth:       3,
			},
			expectError: false,
		},
		{
			name:             "child limit exceeded",
			existingDepth:    0,
			existingChildren: 10,
			runningCount:     10,
			limits: SpawnLimits{
				MaxChildMissions:      10,
				MaxConcurrentMissions: 50,
				MaxMissionDepth:       3,
			},
			expectError:   true,
			errorContains: "maximum child limit",
		},
		{
			name:             "depth limit exceeded",
			existingDepth:    2,
			existingChildren: 2,
			runningCount:     10,
			limits: SpawnLimits{
				MaxChildMissions:      10,
				MaxConcurrentMissions: 50,
				MaxMissionDepth:       3,
			},
			expectError:   true,
			errorContains: "depth limit",
		},
		{
			name:             "concurrent limit exceeded",
			existingDepth:    0,
			existingChildren: 2,
			runningCount:     50,
			limits: SpawnLimits{
				MaxChildMissions:      10,
				MaxConcurrentMissions: 50,
				MaxMissionDepth:       3,
			},
			expectError:   true,
			errorContains: "concurrent mission limit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newMockMissionOperator()

			parentID := types.NewID()

			// Create parent mission
			mockClient.records = append(mockClient.records, &MissionRecord{
				ID:              parentID,
				ParentMissionID: nil,
				Depth:           tt.existingDepth,
				Status:          MissionStatusRunning,
			})

			// Add existing children
			for i := 0; i < tt.existingChildren; i++ {
				mockClient.records = append(mockClient.records, &MissionRecord{
					ID:              types.NewID(),
					ParentMissionID: &parentID,
					Depth:           tt.existingDepth + 1,
					Status:          "pending",
				})
			}

			// Add running missions
			for i := 0; i < tt.runningCount; i++ {
				mockClient.records = append(mockClient.records, &MissionRecord{
					ID:              types.NewID(),
					ParentMissionID: nil,
					Depth:           0,
					Status:          MissionStatusRunning,
				})
			}

			harness := createTestMissionHarness(mockClient, tt.limits)
			harness.missionCtx.ID = parentID

			mission := map[string]any{"name": "test"}
			targetID := types.NewID()

			_, err := harness.CreateMission(ctx, mission, targetID.String(), nil)

			if tt.expectError {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				if tt.errorContains != "" && !stringContains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain %q, got %v", tt.errorContains, err)
				}
			} else {
				if err != nil {
					t.Fatalf("Expected no error, got %v", err)
				}
			}
		})
	}
}

// Helper functions

func stringPtr(s string) *string {
	return &s
}

func sdkMissionStatusPtr(s string) *sdkmission.MissionStatus {
	status := sdkmission.MissionStatus(s)
	return &status
}
