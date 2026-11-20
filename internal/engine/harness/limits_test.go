// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"fmt"
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

	if limits.MaxMissionDepth != 3 {
		t.Errorf("Expected MaxMissionDepth=3, got %d", limits.MaxMissionDepth)
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
					Status:          MissionStatusWorking,
				},
			}

			lister := &mockMissionLister{missions: missions}
			limits := SpawnLimits{MaxMissionDepth: tt.maxDepth}

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

// TestCheckSpawnLimits_NoCountLimit proves that no count refuses a child
// mission: a parent with many children, among many running missions, may
// still spawn while it is under the depth bound.
func TestCheckSpawnLimits_NoCountLimit(t *testing.T) {
	ctx := context.Background()
	parentID := newID("parent-1")

	missions := []*MissionRecord{
		{ID: parentID, Depth: 0, Status: MissionStatusWorking},
	}
	for i := range 500 {
		missions = append(missions, &MissionRecord{
			ID:              newID(fmt.Sprintf("child-%d", i)),
			ParentMissionID: &parentID,
			Depth:           1,
			Status:          MissionStatusWorking,
		})
	}

	err := CheckSpawnLimits(ctx, &mockMissionLister{missions: missions}, parentID, DefaultSpawnLimits())
	if err != nil {
		t.Fatalf("Expected no error for a parent with 500 running children, got %v", err)
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
