package harness

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// mockMissionLister is a mock implementation of MissionLister for testing.
type mockMissionLister struct {
	missions []*MissionRecord
	listErr  error
}

func (m *mockMissionLister) List(ctx context.Context, filter *MissionFilter) ([]*MissionRecord, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}

	if filter == nil {
		return m.missions, nil
	}

	// Filter missions based on criteria
	var result []*MissionRecord
	for _, mission := range m.missions {
		match := true

		// Filter by ParentMissionID
		if filter.ParentMissionID != nil {
			if mission.ParentMissionID == nil || *mission.ParentMissionID != *filter.ParentMissionID {
				match = false
			}
		}

		// Filter by Status
		if filter.Status != nil && mission.Status != *filter.Status {
			match = false
		}

		// Filter by TargetID (not used in limits.go, but included for completeness)
		if filter.TargetID != nil {
			// Not implemented in MissionRecord, so skip
			match = true
		}

		if match {
			result = append(result, mission)
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

// Helper function to create mission IDs
func newID(s string) types.ID {
	return types.ID(s)
}

// Helper function to create pointer to ID
func idPtr(s string) *types.ID {
	id := newID(s)
	return &id
}

func TestDefaultSpawnLimits(t *testing.T) {
	limits := DefaultSpawnLimits()

	if limits.MaxChildMissions != 10 {
		t.Errorf("Expected MaxChildMissions=10, got %d", limits.MaxChildMissions)
	}
	if limits.MaxConcurrentMissions != 50 {
		t.Errorf("Expected MaxConcurrentMissions=50, got %d", limits.MaxConcurrentMissions)
	}
	if limits.MaxMissionDepth != 3 {
		t.Errorf("Expected MaxMissionDepth=3, got %d", limits.MaxMissionDepth)
	}
}

func TestCheckSpawnLimits_ChildLimit(t *testing.T) {
	ctx := context.Background()
	parentID := newID("parent-1")

	tests := []struct {
		name          string
		childCount    int
		maxChildren   int
		expectError   bool
		errorContains string
	}{
		{
			name:        "under limit",
			childCount:  5,
			maxChildren: 10,
			expectError: false,
		},
		{
			name:        "exactly at limit minus one",
			childCount:  9,
			maxChildren: 10,
			expectError: false,
		},
		{
			name:          "exactly at limit",
			childCount:    10,
			maxChildren:   10,
			expectError:   true,
			errorContains: "maximum child limit",
		},
		{
			name:          "over limit",
			childCount:    15,
			maxChildren:   10,
			expectError:   true,
			errorContains: "maximum child limit",
		},
		{
			name:          "zero limit blocks even with no existing children",
			childCount:    0,
			maxChildren:   0,
			expectError:   true,
			errorContains: "maximum child limit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock missions with specified number of children
			missions := []*MissionRecord{
				{
					ID:              parentID,
					ParentMissionID: nil,
					Depth:           0,
					Status:          MissionStatusRunning,
				},
			}

			// Add child missions
			for i := 0; i < tt.childCount; i++ {
				missions = append(missions, &MissionRecord{
					ID:              newID("child-" + string(rune(i))),
					ParentMissionID: &parentID,
					Depth:           1,
					Status:          MissionStatusRunning,
				})
			}

			lister := &mockMissionLister{missions: missions}
			limits := SpawnLimits{
				MaxChildMissions:      tt.maxChildren,
				MaxConcurrentMissions: 100, // High enough to not interfere
				MaxMissionDepth:       10,  // High enough to not interfere
			}

			err := CheckSpawnLimits(ctx, lister, parentID, limits)

			if tt.expectError {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				// Verify it's the correct error type
				var gibsonErr *types.GibsonError
				if !errors.As(err, &gibsonErr) {
					t.Fatalf("Expected types.GibsonError, got %T", err)
				}
				if gibsonErr.Code != ErrChildMissionLimitExceeded {
					t.Errorf("Expected error code %s, got %s", ErrChildMissionLimitExceeded, gibsonErr.Code)
				}
				if tt.errorContains != "" && !stringContains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain %q, got %q", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("Expected no error, got %v", err)
				}
			}
		})
	}
}

func TestCheckSpawnLimits_DepthLimit(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		currentDepth  int
		maxDepth      int
		expectError   bool
		errorContains string
	}{
		{
			name:         "root mission (depth 0) under limit",
			currentDepth: 0,
			maxDepth:     3,
			expectError:  false,
		},
		{
			name:         "depth 1 under limit",
			currentDepth: 1,
			maxDepth:     3,
			expectError:  false,
		},
		{
			name:          "exactly at limit minus one (child would reach limit)",
			currentDepth:  2,
			maxDepth:      3,
			expectError:   true,
			errorContains: "depth limit would be exceeded",
		},
		{
			name:          "at limit (child would exceed)",
			currentDepth:  3,
			maxDepth:      3,
			expectError:   true,
			errorContains: "depth limit would be exceeded",
		},
		{
			name:          "over limit",
			currentDepth:  5,
			maxDepth:      3,
			expectError:   true,
			errorContains: "depth limit would be exceeded",
		},
		{
			name:          "zero depth limit (no missions allowed)",
			currentDepth:  0,
			maxDepth:      0,
			expectError:   true,
			errorContains: "depth limit would be exceeded",
		},
		{
			name:          "depth 1 limit prevents root from spawning (child would be depth 1, which is >= limit)",
			currentDepth:  0,
			maxDepth:      1,
			expectError:   true,
			errorContains: "depth limit would be exceeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			missionID := newID("mission-1")

			// Create mission with specified depth
			missions := []*MissionRecord{
				{
					ID:              missionID,
					ParentMissionID: nil,
					Depth:           tt.currentDepth,
					Status:          MissionStatusRunning,
				},
			}

			lister := &mockMissionLister{missions: missions}
			limits := SpawnLimits{
				MaxChildMissions:      100, // High enough to not interfere
				MaxConcurrentMissions: 100, // High enough to not interfere
				MaxMissionDepth:       tt.maxDepth,
			}

			err := CheckSpawnLimits(ctx, lister, missionID, limits)

			if tt.expectError {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				// Verify it's the correct error type
				var gibsonErr *types.GibsonError
				if !errors.As(err, &gibsonErr) {
					t.Fatalf("Expected types.GibsonError, got %T", err)
				}
				if gibsonErr.Code != ErrMissionDepthLimitExceeded {
					t.Errorf("Expected error code %s, got %s", ErrMissionDepthLimitExceeded, gibsonErr.Code)
				}
				if tt.errorContains != "" && !stringContains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain %q, got %q", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("Expected no error, got %v", err)
				}
			}
		})
	}
}

func TestCheckSpawnLimits_ConcurrentLimit(t *testing.T) {
	ctx := context.Background()
	parentID := newID("parent-1")

	tests := []struct {
		name          string
		runningCount  int
		maxConcurrent int
		expectError   bool
		errorContains string
	}{
		{
			name:          "under limit",
			runningCount:  25,
			maxConcurrent: 50,
			expectError:   false,
		},
		{
			name:          "exactly at limit minus one (parent + 48 others = 49)",
			runningCount:  48,
			maxConcurrent: 50,
			expectError:   false,
		},
		{
			name:          "exactly at limit (parent + 49 others = 50)",
			runningCount:  49,
			maxConcurrent: 50,
			expectError:   true,
			errorContains: "concurrent mission limit",
		},
		{
			name:          "over limit",
			runningCount:  75,
			maxConcurrent: 50,
			expectError:   true,
			errorContains: "concurrent mission limit",
		},
		{
			name:          "zero limit blocks even parent mission",
			runningCount:  0,
			maxConcurrent: 0,
			expectError:   true,
			errorContains: "concurrent mission limit",
		},
		{
			name:          "single concurrent at limit (parent is running, counts as 1)",
			runningCount:  0,
			maxConcurrent: 2, // Allow parent + 1 more
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create parent mission
			missions := []*MissionRecord{
				{
					ID:              parentID,
					ParentMissionID: nil,
					Depth:           0,
					Status:          MissionStatusRunning,
				},
			}

			// Add running missions
			for i := 0; i < tt.runningCount; i++ {
				missions = append(missions, &MissionRecord{
					ID:              newID("running-" + string(rune(i))),
					ParentMissionID: nil,
					Depth:           0,
					Status:          MissionStatusRunning,
				})
			}

			lister := &mockMissionLister{missions: missions}
			limits := SpawnLimits{
				MaxChildMissions:      100, // High enough to not interfere
				MaxConcurrentMissions: tt.maxConcurrent,
				MaxMissionDepth:       10, // High enough to not interfere
			}

			err := CheckSpawnLimits(ctx, lister, parentID, limits)

			if tt.expectError {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				// Verify it's the correct error type
				var gibsonErr *types.GibsonError
				if !errors.As(err, &gibsonErr) {
					t.Fatalf("Expected types.GibsonError, got %T", err)
				}
				if gibsonErr.Code != ErrConcurrentMissionLimitExceeded {
					t.Errorf("Expected error code %s, got %s", ErrConcurrentMissionLimitExceeded, gibsonErr.Code)
				}
				if tt.errorContains != "" && !stringContains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain %q, got %q", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("Expected no error, got %v", err)
				}
			}
		})
	}
}

func TestCheckSpawnLimits_CombinedLimits(t *testing.T) {
	ctx := context.Background()
	parentID := newID("parent-1")

	tests := []struct {
		name          string
		childCount    int
		parentDepth   int
		runningCount  int
		limits        SpawnLimits
		expectError   bool
		expectedCode  types.ErrorCode
		errorContains string
	}{
		{
			name:         "all limits satisfied",
			childCount:   5,
			parentDepth:  1,
			runningCount: 25,
			limits: SpawnLimits{
				MaxChildMissions:      10,
				MaxConcurrentMissions: 50,
				MaxMissionDepth:       3,
			},
			expectError: false,
		},
		{
			name:         "child limit hit first (checked first)",
			childCount:   10,
			parentDepth:  2,
			runningCount: 50,
			limits: SpawnLimits{
				MaxChildMissions:      10,
				MaxConcurrentMissions: 50,
				MaxMissionDepth:       3,
			},
			expectError:   true,
			expectedCode:  ErrChildMissionLimitExceeded,
			errorContains: "maximum child limit",
		},
		{
			name:         "depth limit hit (checked second)",
			childCount:   5,
			parentDepth:  2,
			runningCount: 50,
			limits: SpawnLimits{
				MaxChildMissions:      10,
				MaxConcurrentMissions: 50,
				MaxMissionDepth:       3,
			},
			expectError:   true,
			expectedCode:  ErrMissionDepthLimitExceeded,
			errorContains: "depth limit would be exceeded",
		},
		{
			name:         "concurrent limit hit (checked third)",
			childCount:   5,
			parentDepth:  1,
			runningCount: 50,
			limits: SpawnLimits{
				MaxChildMissions:      10,
				MaxConcurrentMissions: 50,
				MaxMissionDepth:       3,
			},
			expectError:   true,
			expectedCode:  ErrConcurrentMissionLimitExceeded,
			errorContains: "concurrent mission limit",
		},
		{
			name:         "all limits near threshold (parent + children + others < limits)",
			childCount:   9,
			parentDepth:  1,
			runningCount: 40, // parent + 9 children + 40 others = 50 total, but we add later
			limits: SpawnLimits{
				MaxChildMissions:      10,
				MaxConcurrentMissions: 60, // High enough to not interfere
				MaxMissionDepth:       3,
			},
			expectError: false,
		},
		{
			name:         "all limits exactly at threshold",
			childCount:   10,
			parentDepth:  2,
			runningCount: 50,
			limits: SpawnLimits{
				MaxChildMissions:      10,
				MaxConcurrentMissions: 50,
				MaxMissionDepth:       3,
			},
			expectError:   true,
			expectedCode:  ErrChildMissionLimitExceeded, // First check fails
			errorContains: "maximum child limit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create parent mission
			missions := []*MissionRecord{
				{
					ID:              parentID,
					ParentMissionID: nil,
					Depth:           tt.parentDepth,
					Status:          MissionStatusRunning,
				},
			}

			// Add child missions of the parent
			for i := 0; i < tt.childCount; i++ {
				missions = append(missions, &MissionRecord{
					ID:              newID("child-" + string(rune(i))),
					ParentMissionID: &parentID,
					Depth:           tt.parentDepth + 1,
					Status:          MissionStatusRunning,
				})
			}

			// Add other running missions
			for i := 0; i < tt.runningCount; i++ {
				missions = append(missions, &MissionRecord{
					ID:              newID("running-" + string(rune(i))),
					ParentMissionID: nil,
					Depth:           0,
					Status:          MissionStatusRunning,
				})
			}

			lister := &mockMissionLister{missions: missions}

			err := CheckSpawnLimits(ctx, lister, parentID, tt.limits)

			if tt.expectError {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				// Verify it's the correct error type
				var gibsonErr *types.GibsonError
				if !errors.As(err, &gibsonErr) {
					t.Fatalf("Expected types.GibsonError, got %T", err)
				}
				if gibsonErr.Code != tt.expectedCode {
					t.Errorf("Expected error code %s, got %s", tt.expectedCode, gibsonErr.Code)
				}
				if tt.errorContains != "" && !stringContains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain %q, got %q", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("Expected no error, got %v", err)
				}
			}
		})
	}
}

func TestCheckSpawnLimits_ListErrors(t *testing.T) {
	ctx := context.Background()
	parentID := newID("parent-1")

	tests := []struct {
		name          string
		listErr       error
		expectError   bool
		errorContains string
	}{
		{
			name:          "error listing child missions",
			listErr:       errors.New("database connection failed"),
			expectError:   true,
			errorContains: "failed to list child missions",
		},
		{
			name:        "successful list returns no error",
			listErr:     nil,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lister := &mockMissionLister{
				missions: []*MissionRecord{
					{
						ID:              parentID,
						ParentMissionID: nil,
						Depth:           0,
						Status:          MissionStatusRunning,
					},
				},
				listErr: tt.listErr,
			}

			limits := DefaultSpawnLimits()

			err := CheckSpawnLimits(ctx, lister, parentID, limits)

			if tt.expectError {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				if tt.errorContains != "" && !stringContains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain %q, got %q", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("Expected no error, got %v", err)
				}
			}
		})
	}
}

func TestGetMissionDepth(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		missions      []*MissionRecord
		queryID       types.ID
		expectedDepth int
	}{
		{
			name: "root mission has depth 0",
			missions: []*MissionRecord{
				{ID: newID("root-1"), ParentMissionID: nil, Depth: 0},
			},
			queryID:       newID("root-1"),
			expectedDepth: 0,
		},
		{
			name: "child mission has depth 1",
			missions: []*MissionRecord{
				{ID: newID("root-1"), ParentMissionID: nil, Depth: 0},
				{ID: newID("child-1"), ParentMissionID: idPtr("root-1"), Depth: 1},
			},
			queryID:       newID("child-1"),
			expectedDepth: 1,
		},
		{
			name: "grandchild mission has depth 2",
			missions: []*MissionRecord{
				{ID: newID("root-1"), ParentMissionID: nil, Depth: 0},
				{ID: newID("child-1"), ParentMissionID: idPtr("root-1"), Depth: 1},
				{ID: newID("grandchild-1"), ParentMissionID: idPtr("child-1"), Depth: 2},
			},
			queryID:       newID("grandchild-1"),
			expectedDepth: 2,
		},
		{
			name: "mission not found returns 0",
			missions: []*MissionRecord{
				{ID: newID("root-1"), ParentMissionID: nil, Depth: 0},
			},
			queryID:       newID("nonexistent"),
			expectedDepth: 0,
		},
		{
			name:          "empty list returns 0",
			missions:      []*MissionRecord{},
			queryID:       newID("any"),
			expectedDepth: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lister := &mockMissionLister{missions: tt.missions}
			depth := GetMissionDepth(ctx, lister, tt.queryID)

			if depth != tt.expectedDepth {
				t.Errorf("Expected depth %d, got %d", tt.expectedDepth, depth)
			}
		})
	}
}

func TestGetMissionDepth_ListError(t *testing.T) {
	ctx := context.Background()

	lister := &mockMissionLister{
		missions: nil,
		listErr:  errors.New("database error"),
	}

	depth := GetMissionDepth(ctx, lister, newID("any"))

	// Should return 0 on error (safe default)
	if depth != 0 {
		t.Errorf("Expected depth 0 on error, got %d", depth)
	}
}

// stringContains checks if a string contains a substring.
// This is a helper function to avoid using strings package in tests.
func stringContains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
