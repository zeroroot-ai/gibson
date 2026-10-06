// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"io"
	"log/slog"
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// ────────────────────────────────────────────────────────────────────────────
// Mock Mission Store
// ────────────────────────────────────────────────────────────────────────────

// mockMissionStore is a test implementation of MissionStore.
type mockMissionStore struct {
	missions       map[types.ID]MissionData
	missionsByName map[string][]MissionData
}

// newMockMissionStore creates a new mock store for testing.
func newMockMissionStore() *mockMissionStore {
	return &mockMissionStore{
		missions:       make(map[types.ID]MissionData),
		missionsByName: make(map[string][]MissionData),
	}
}

// addMission adds a mission to the mock store.
func (m *mockMissionStore) addMission(mission MissionData) {
	m.missions[mission.ID] = mission
	m.missionsByName[mission.Name] = append(m.missionsByName[mission.Name], mission)
}

// Get retrieves a mission by ID.
func (m *mockMissionStore) Get(ctx context.Context, id types.ID) (MissionData, error) {
	mission, ok := m.missions[id]
	if !ok {
		return MissionData{}, &notFoundError{id: id.String()}
	}
	return mission, nil
}

// ListByName retrieves all missions with the given name, ordered by run number descending.
func (m *mockMissionStore) ListByName(ctx context.Context, name string, limit int) ([]MissionData, error) {
	missions := m.missionsByName[name]
	if missions == nil {
		return []MissionData{}, nil
	}

	// Sort by run number descending (most recent first)
	sorted := make([]MissionData, len(missions))
	copy(sorted, missions)

	// Simple bubble sort for test data
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].RunNumber > sorted[i].RunNumber {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	// Apply limit
	if limit > 0 && len(sorted) > limit {
		sorted = sorted[:limit]
	}

	return sorted, nil
}

// notFoundError simulates a not found error.
type notFoundError struct {
	id string
}

func (e *notFoundError) Error() string {
	return "mission not found: " + e.id
}

// ────────────────────────────────────────────────────────────────────────────
// Test Helper Functions
// ────────────────────────────────────────────────────────────────────────────

// createTestMission creates a test mission with sensible defaults.
func createTestMission(name string, runNumber int) MissionData {
	return MissionData{
		ID:            types.NewID(),
		Name:          name,
		Status:        "completed",
		RunNumber:     runNumber,
		FindingsCount: 0,
		CreatedAt:     time.Now().Add(-time.Duration(runNumber) * time.Hour),
	}
}

// createTestMissionWithFindings creates a test mission with findings.
func createTestMissionWithFindings(name string, runNumber int, findingsCount int) MissionData {
	mission := createTestMission(name, runNumber)
	mission.FindingsCount = findingsCount
	return mission
}

// createTestMissionWithCheckpoint creates a test mission with a checkpoint.
func createTestMissionWithCheckpoint(name string, runNumber int, lastNodeID string) MissionData {
	mission := createTestMission(name, runNumber)
	mission.Checkpoint = &MissionCheckpointData{
		LastNodeID: lastNodeID,
	}
	return mission
}

// createTestMissionWithPreviousRun creates a test mission linked to a previous run.
func createTestMissionWithPreviousRun(name string, runNumber int, previousRunID types.ID) MissionData {
	mission := createTestMission(name, runNumber)
	mission.PreviousRunID = &previousRunID
	return mission
}

// ────────────────────────────────────────────────────────────────────────────
// GetContext Tests
// ────────────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────────────
// GetRunHistory Tests
// ────────────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────────────
// GetPreviousRun Tests
// ────────────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────────────
// IsResumedRun Tests
// ────────────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────────────
// Memory Continuity Tests
// ────────────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────────────
// Integration Tests
// ────────────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────────────
// Test Utilities
// ────────────────────────────────────────────────────────────────────────────

// noopLogger returns a no-op logger for tests.
func noopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
		Level: slog.LevelError, // Only log errors to reduce noise
	}))
}
