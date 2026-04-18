package orchestrator

import (
	"strings"
	"testing"
	"time"
)

// TestGraphContextFormatting specifically tests the graph context formatting
// in FormatForPrompt() to ensure all sections are properly rendered.
func TestGraphContextFormatting(t *testing.T) {
	t.Run("formats empty observation state correctly", func(t *testing.T) {
		state := &ObservationState{
			MissionInfo: MissionInfo{
				ID:        "test",
				Name:      "Test",
				Objective: "Test",
				Status:    "running",
			},
			GraphSummary:    GraphSummary{},
			ReadyNodes:      []NodeSummary{},
			RunningNodes:    []NodeSummary{},
			CompletedNodes:  []CompletedNodeSummary{},
			FailedNodes:     []NodeSummary{},
			RecentDecisions: []DecisionSummary{},
			ResourceConstraints: ResourceConstraints{
				MaxConcurrent: 10,
			},
			ObservedAt: time.Now(),
		}

		output := state.FormatForPrompt()

		if !strings.Contains(output, "=== MISSION CONTEXT ===") {
			t.Error("missing mission context header")
		}
		if !strings.Contains(output, "=== MISSION PROGRESS ===") {
			t.Error("missing mission progress header")
		}
	})

	t.Run("formats observation state with complete mission info", func(t *testing.T) {
		state := &ObservationState{
			MissionInfo: MissionInfo{
				ID:        "test",
				Name:      "Test Mission",
				Objective: "Find vulnerabilities",
				Status:    "running",
			},
			GraphSummary: GraphSummary{
				TotalNodes:     5,
				CompletedNodes: 2,
				FailedNodes:    1,
				PendingNodes:   2,
			},
			ReadyNodes:      []NodeSummary{},
			RunningNodes:    []NodeSummary{},
			CompletedNodes:  []CompletedNodeSummary{},
			FailedNodes:     []NodeSummary{},
			RecentDecisions: []DecisionSummary{},
			ResourceConstraints: ResourceConstraints{
				MaxConcurrent: 10,
			},
			ObservedAt: time.Now(),
		}

		output := state.FormatForPrompt()

		requiredSections := []string{
			"=== MISSION CONTEXT ===",
			"Mission: Test Mission",
			"Objective: Find vulnerabilities",
			"Status: running",
			"=== MISSION PROGRESS ===",
			"Total Nodes: 5",
			"Completed: 2",
			"Failed: 1",
			"Pending: 2",
		}

		for _, section := range requiredSections {
			if !strings.Contains(output, section) {
				t.Errorf("missing required section: %q", section)
			}
		}
	})

	t.Run("formats ready nodes correctly", func(t *testing.T) {
		state := &ObservationState{
			MissionInfo: MissionInfo{
				ID:        "test",
				Name:      "Test",
				Objective: "Test",
				Status:    "running",
			},
			GraphSummary: GraphSummary{},
			ReadyNodes: []NodeSummary{
				{
					ID:          "node-1",
					Name:        "Recon Node",
					Description: "Perform reconnaissance",
					AgentName:   "recon-agent",
				},
			},
			RunningNodes:    []NodeSummary{},
			CompletedNodes:  []CompletedNodeSummary{},
			FailedNodes:     []NodeSummary{},
			RecentDecisions: []DecisionSummary{},
			ResourceConstraints: ResourceConstraints{
				MaxConcurrent: 10,
			},
			ObservedAt: time.Now(),
		}

		output := state.FormatForPrompt()

		if !strings.Contains(output, "=== READY NODES") {
			t.Error("missing ready nodes header")
		}
		if !strings.Contains(output, "Recon Node") {
			t.Error("missing node name in output")
		}
		if !strings.Contains(output, "recon-agent") {
			t.Error("missing agent name in output")
		}
	})

	t.Run("does not show ready nodes section when empty", func(t *testing.T) {
		state := &ObservationState{
			MissionInfo: MissionInfo{
				ID:        "test",
				Name:      "Test",
				Objective: "Test",
				Status:    "running",
			},
			GraphSummary:    GraphSummary{},
			ReadyNodes:      []NodeSummary{},
			RunningNodes:    []NodeSummary{},
			CompletedNodes:  []CompletedNodeSummary{},
			FailedNodes:     []NodeSummary{},
			RecentDecisions: []DecisionSummary{},
			ResourceConstraints: ResourceConstraints{
				MaxConcurrent: 10,
			},
			ObservedAt: time.Now(),
		}

		output := state.FormatForPrompt()

		if strings.Contains(output, "=== READY NODES") {
			t.Error("should not show ready nodes section when empty")
		}
	})

	t.Run("formats failed execution context", func(t *testing.T) {
		state := &ObservationState{
			MissionInfo: MissionInfo{
				ID:        "test",
				Name:      "Test",
				Objective: "Test",
				Status:    "running",
			},
			GraphSummary:    GraphSummary{},
			ReadyNodes:      []NodeSummary{},
			RunningNodes:    []NodeSummary{},
			CompletedNodes:  []CompletedNodeSummary{},
			FailedNodes:     []NodeSummary{},
			RecentDecisions: []DecisionSummary{},
			ResourceConstraints: ResourceConstraints{
				MaxConcurrent: 10,
			},
			FailedExecution: &ExecutionFailure{
				NodeID:     "node-1",
				NodeName:   "Scan Node",
				AgentName:  "scan-agent",
				Error:      "connection refused",
				Attempt:    1,
				MaxRetries: 3,
				CanRetry:   true,
			},
			ObservedAt: time.Now(),
		}

		output := state.FormatForPrompt()

		if !strings.Contains(output, "=== RECENT FAILURE ===") {
			t.Error("missing recent failure header")
		}
		if !strings.Contains(output, "Scan Node") {
			t.Error("missing node name in failure context")
		}
		if !strings.Contains(output, "connection refused") {
			t.Error("missing error message in failure context")
		}
	})
}

// TestIsGraphContextEmpty tests the GraphContext helper for emptiness checks.
func TestIsGraphContextEmpty(t *testing.T) {
	tests := []struct {
		name     string
		gc       *GraphContext
		expected bool
	}{
		{
			name:     "nil context is empty",
			gc:       nil,
			expected: true,
		},
		{
			name:     "empty context is empty",
			gc:       &GraphContext{},
			expected: true,
		},
		{
			name: "context with target history is not empty",
			gc: &GraphContext{
				TargetHistory: &TargetHistory{
					TargetID:          "example.com",
					PreviousScanCount: 1,
				},
			},
			expected: false,
		},
		{
			name: "context with prior findings is not empty",
			gc: &GraphContext{
				PriorFindings: []HistoricalFinding{
					{ID: "f1", Title: "Finding 1"},
				},
			},
			expected: false,
		},
		{
			name: "context with known entities is not empty",
			gc: &GraphContext{
				KnownEntities: []EntitySummary{
					{ID: "e1", Type: "endpoint"},
				},
			},
			expected: false,
		},
		{
			name: "context with successful patterns is not empty",
			gc: &GraphContext{
				SuccessfulPatterns: []AttackPattern{
					{TechniqueID: "T1595.001"},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := graphContextIsEmpty(tt.gc)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// graphContextIsEmpty is a helper used only by tests to check if a GraphContext
// has no meaningful content.
func graphContextIsEmpty(gc *GraphContext) bool {
	if gc == nil {
		return true
	}
	return gc.TargetHistory == nil &&
		len(gc.PriorFindings) == 0 &&
		len(gc.KnownEntities) == 0 &&
		len(gc.SuccessfulPatterns) == 0
}
