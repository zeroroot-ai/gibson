package orchestrator

import (
	"strings"
	"testing"
	"time"
)

// TestGraphContextFormatting specifically tests the graph context formatting
// in FormatForPrompt() to ensure all sections are properly rendered.
func TestGraphContextFormatting(t *testing.T) {
	t.Run("formats empty graph context correctly", func(t *testing.T) {
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
			GraphContext: nil,
			ObservedAt:   time.Now(),
		}

		output := state.FormatForPrompt()

		if !strings.Contains(output, "## Graph Intelligence (Prior Knowledge)") {
			t.Error("missing graph intelligence header")
		}
		if !strings.Contains(output, "No prior knowledge available for this target") {
			t.Error("missing 'no prior knowledge' message")
		}
	})

	t.Run("formats complete graph context with all sections", func(t *testing.T) {
		lastScan := time.Now().Add(-24 * time.Hour)
		discoveredAt := time.Now().Add(-48 * time.Hour)

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
			GraphContext: &GraphContext{
				TargetHistory: &TargetHistory{
					TargetID:          "example.com",
					PreviousScanCount: 5,
					LastScanDate:      &lastScan,
					TotalFindings:     42,
					CriticalCount:     3,
					HighCount:         8,
					MediumCount:       15,
					LowCount:          16,
				},
				PriorFindings: []HistoricalFinding{
					{
						ID:           "f1",
						Title:        "SQL Injection",
						Severity:     "critical",
						Category:     "injection",
						TargetEntity: "https://api.example.com/users",
						DiscoveredAt: discoveredAt,
					},
				},
				KnownEntities: []EntitySummary{
					{
						ID:           "e1",
						Type:         "endpoint",
						Identifier:   "https://api.example.com/users",
						Properties:   map[string]any{"method": "GET"},
						DiscoveredAt: discoveredAt,
					},
					{
						ID:           "e2",
						Type:         "host",
						Identifier:   "192.168.1.100:443",
						Properties:   map[string]any{"service": "https"},
						DiscoveredAt: discoveredAt,
					},
				},
				SuccessfulPatterns: []AttackPattern{
					{
						TechniqueID:   "T1595.001",
						TechniqueName: "Active Scanning",
						Description:   "Scanning for vulnerabilities",
						SuccessRate:   0.85,
						SampleCount:   20,
						TargetTypes:   []string{"web_application"},
					},
				},
				TargetRiskScore: 67.5,
				Truncated:       false,
			},
			ObservedAt: time.Now(),
		}

		output := state.FormatForPrompt()

		// Check all major sections exist
		requiredSections := []string{
			"## Graph Intelligence (Prior Knowledge)",
			"### Target History",
			"Previous scans: 5",
			"Total findings: 42",
			"Critical: 3",
			"High: 8",
			"Medium: 15",
			"Low: 16",
			"### Known Entities",
			"Total known entities: 2",
			"endpoint: 1",
			"host: 1",
			"[endpoint] https://api.example.com/users",
			"[host] 192.168.1.100:443",
			"### Prior Findings",
			"Total findings available: 1",
			"[CRITICAL] SQL Injection",
			"Category: injection",
			"### Successful Attack Patterns",
			"Active Scanning (T1595.001)",
			"Success rate: 85.0% (20 samples)",
			"### Target Risk Score: 67.5/100",
			"Risk level: High",
		}

		for _, section := range requiredSections {
			if !strings.Contains(output, section) {
				t.Errorf("missing required section: %q", section)
			}
		}
	})

	t.Run("formats target history without optional fields", func(t *testing.T) {
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
			GraphContext: &GraphContext{
				TargetHistory: &TargetHistory{
					TargetID:          "example.com",
					PreviousScanCount: 1,
					LastScanDate:      nil, // No last scan date
					TotalFindings:     0,   // No findings
				},
			},
			ObservedAt: time.Now(),
		}

		output := state.FormatForPrompt()

		if !strings.Contains(output, "Previous scans: 1") {
			t.Error("missing scan count")
		}
		if !strings.Contains(output, "Total findings: 0") {
			t.Error("missing total findings")
		}
		// Should not show severity breakdown if no findings
		if strings.Contains(output, "Finding severity breakdown:") {
			t.Error("should not show severity breakdown when no findings")
		}
	})

	t.Run("truncates entity sample to 5 items", func(t *testing.T) {
		entities := make([]EntitySummary, 10)
		for i := 0; i < 10; i++ {
			entities[i] = EntitySummary{
				ID:           string(rune('a' + i)),
				Type:         "endpoint",
				Identifier:   "endpoint-" + string(rune('a'+i)),
				DiscoveredAt: time.Now(),
			}
		}

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
			GraphContext: &GraphContext{
				KnownEntities: entities,
			},
			ObservedAt: time.Now(),
		}

		output := state.FormatForPrompt()

		// Should show total count
		if !strings.Contains(output, "Total known entities: 10") {
			t.Error("missing total entity count")
		}

		// Should show first 5 samples
		for i := 0; i < 5; i++ {
			expected := "endpoint-" + string(rune('a'+i))
			if !strings.Contains(output, expected) {
				t.Errorf("missing sample entity: %s", expected)
			}
		}

		// Should NOT show 6th entity and beyond in sample
		for i := 5; i < 10; i++ {
			unexpected := "endpoint-" + string(rune('a'+i))
			if strings.Contains(output, unexpected) {
				t.Errorf("should not show entity beyond first 5: %s", unexpected)
			}
		}
	})

	t.Run("truncates findings to top 5", func(t *testing.T) {
		findings := make([]HistoricalFinding, 10)
		for i := 0; i < 10; i++ {
			findings[i] = HistoricalFinding{
				ID:           string(rune('a' + i)),
				Title:        "Finding " + string(rune('A'+i)),
				Severity:     "high",
				Category:     "test",
				DiscoveredAt: time.Now(),
			}
		}

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
			GraphContext: &GraphContext{
				PriorFindings: findings,
			},
			ObservedAt: time.Now(),
		}

		output := state.FormatForPrompt()

		// Should show total count
		if !strings.Contains(output, "Total findings available: 10") {
			t.Error("missing total findings count")
		}

		// Should show first 5
		for i := 0; i < 5; i++ {
			expected := "Finding " + string(rune('A'+i))
			if !strings.Contains(output, expected) {
				t.Errorf("missing finding: %s", expected)
			}
		}

		// Should NOT show 6th finding and beyond
		for i := 5; i < 10; i++ {
			unexpected := "Finding " + string(rune('A'+i))
			if strings.Contains(output, unexpected) {
				t.Errorf("should not show finding beyond first 5: %s", unexpected)
			}
		}
	})
}

// TestIsGraphContextEmpty tests the helper function
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
			result := isGraphContextEmpty(tt.gc)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}
