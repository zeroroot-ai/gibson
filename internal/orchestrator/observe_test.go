package orchestrator

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson/internal/graphrag/queries"
	"github.com/zero-day-ai/gibson/internal/graphrag/schema"
	"github.com/zero-day-ai/gibson/internal/types"
)

// TestObserver_NewObserver tests Observer construction
func TestObserver_NewObserver(t *testing.T) {
	t.Run("creates observer with valid dependencies", func(t *testing.T) {
		mq := &queries.MissionQueries{}
		eq := &queries.ExecutionQueries{}

		observer := NewObserver(mq, eq)

		if observer == nil {
			t.Fatal("expected non-nil observer")
		}
		if observer.missionQueries != mq {
			t.Error("mission queries not set correctly")
		}
		if observer.executionQueries != eq {
			t.Error("execution queries not set correctly")
		}
	})

	t.Run("accepts nil dependencies without panic", func(t *testing.T) {
		// Should not panic, but will error on Observe()
		observer := NewObserver(nil, nil)
		if observer == nil {
			t.Fatal("expected non-nil observer")
		}
	})
}

// stubGraphQueries is a minimal in-memory GraphQueries used by wiring tests.
type stubGraphQueries struct {
	hist     *TargetHistory
	findings []HistoricalFinding
	entities []EntitySummary
	patterns []AttackPattern
}

func (s *stubGraphQueries) GetTargetHistory(ctx context.Context, targetID string) (*TargetHistory, error) {
	return s.hist, nil
}
func (s *stubGraphQueries) GetPriorFindings(ctx context.Context, domain string, limit int) ([]HistoricalFinding, error) {
	return s.findings, nil
}
func (s *stubGraphQueries) GetKnownEntities(ctx context.Context, targetID string) ([]EntitySummary, error) {
	return s.entities, nil
}
func (s *stubGraphQueries) GetSuccessfulPatterns(ctx context.Context, targetType string) ([]AttackPattern, error) {
	return s.patterns, nil
}

// TestObserver_WithGraphQueries verifies the WithGraphQueries functional option
// wires a GraphQueries dependency into the Observer and that the no-op fallback
// (no option passed) leaves the field nil. Per spec productionize-graph-intelligence,
// these were the missing wiring confirmations from orchestrator-graph-intelligence
// Task 7.
func TestObserver_WithGraphQueries(t *testing.T) {
	t.Run("WithGraphQueries populates the field", func(t *testing.T) {
		stub := &stubGraphQueries{}
		observer := NewObserver(&queries.MissionQueries{}, &queries.ExecutionQueries{},
			WithGraphQueries(stub),
		)
		if observer.graphQueries == nil {
			t.Fatal("expected graphQueries to be populated by WithGraphQueries")
		}
		if observer.graphQueries != stub {
			t.Error("expected graphQueries to be the same instance passed in")
		}
	})

	t.Run("no option leaves graphQueries nil so observeGraphContext is a no-op", func(t *testing.T) {
		observer := NewObserver(&queries.MissionQueries{}, &queries.ExecutionQueries{})
		if observer.graphQueries != nil {
			t.Fatal("expected graphQueries to be nil when WithGraphQueries is not passed")
		}
		// observeGraphContext must be safe to call with nil graphQueries; this is
		// the production-side fallback when the GraphRAG client doesn't expose
		// a live Neo4j driver.
		state := &ObservationState{MissionInfo: MissionInfo{ID: "m1", TargetRef: "example.com"}}
		observer.observeGraphContext(context.Background(), state)
		if state.GraphContext != nil {
			t.Error("expected GraphContext to remain nil when graphQueries is nil")
		}
	})

	t.Run("observeGraphContext skips when target ref is empty", func(t *testing.T) {
		stub := &stubGraphQueries{
			hist: &TargetHistory{TargetID: "should-not-appear", PreviousScanCount: 5},
		}
		observer := NewObserver(&queries.MissionQueries{}, &queries.ExecutionQueries{},
			WithGraphQueries(stub),
		)
		state := &ObservationState{MissionInfo: MissionInfo{ID: "m1" /* TargetRef intentionally empty */}}
		observer.observeGraphContext(context.Background(), state)
		if state.GraphContext != nil {
			t.Error("expected GraphContext to remain nil when TargetRef is empty (e.g., orchestration mission)")
		}
	})

	t.Run("observeGraphContext populates GraphContext when wired and target ref present", func(t *testing.T) {
		stub := &stubGraphQueries{
			hist:     &TargetHistory{TargetID: "example.com", PreviousScanCount: 3, TotalFindings: 7},
			findings: []HistoricalFinding{{ID: "f1", Title: "SQLi", Severity: "high", Category: "injection"}},
			entities: []EntitySummary{{ID: "e1", Type: "host", Identifier: "example.com"}},
			patterns: []AttackPattern{{TechniqueID: "T1190", TechniqueName: "Exploit Public-Facing App", SuccessRate: 0.4, SampleCount: 5}},
		}
		observer := NewObserver(&queries.MissionQueries{}, &queries.ExecutionQueries{},
			WithGraphQueries(stub),
		)
		state := &ObservationState{MissionInfo: MissionInfo{ID: "m1", TargetRef: "example.com"}}
		observer.observeGraphContext(context.Background(), state)
		if state.GraphContext == nil {
			t.Fatal("expected GraphContext to be populated")
		}
		if state.GraphContext.TargetHistory == nil || state.GraphContext.TargetHistory.PreviousScanCount != 3 {
			t.Errorf("expected TargetHistory with PreviousScanCount=3, got %+v", state.GraphContext.TargetHistory)
		}
		if len(state.GraphContext.PriorFindings) != 1 {
			t.Errorf("expected 1 prior finding, got %d", len(state.GraphContext.PriorFindings))
		}
		if len(state.GraphContext.KnownEntities) != 1 {
			t.Errorf("expected 1 known entity, got %d", len(state.GraphContext.KnownEntities))
		}
		if len(state.GraphContext.SuccessfulPatterns) != 1 {
			t.Errorf("expected 1 attack pattern, got %d", len(state.GraphContext.SuccessfulPatterns))
		}
	})
}

// TestObservationState_FormatForPrompt tests prompt formatting
func TestObservationState_FormatForPrompt(t *testing.T) {
	t.Run("formats complete observation state", func(t *testing.T) {
		state := &ObservationState{
			MissionInfo: MissionInfo{
				ID:          "mission-123",
				Name:        "Test Mission",
				Objective:   "Test all targets",
				Status:      "running",
				StartedAt:   time.Now().Add(-10 * time.Minute),
				TimeElapsed: "10.0m",
			},
			GraphSummary: GraphSummary{
				TotalNodes:      10,
				CompletedNodes:  5,
				FailedNodes:     1,
				PendingNodes:    4,
				TotalDecisions:  3,
				TotalExecutions: 6,
			},
			ReadyNodes: []NodeSummary{
				{
					ID:          "node-1",
					Name:        "nmap_scan",
					Type:        "agent",
					Description: "Scan target network",
					AgentName:   "nmap",
					Status:      "ready",
				},
			},
			RunningNodes: []NodeSummary{
				{
					ID:        "node-2",
					Name:      "exploit_vuln",
					Type:      "agent",
					AgentName: "metasploit",
					Status:    "running",
					Attempt:   1,
				},
			},
			FailedNodes: []NodeSummary{
				{
					ID:        "node-3",
					Name:      "brute_force",
					Type:      "agent",
					AgentName: "hydra",
					Status:    "failed",
					Attempt:   2,
				},
			},
			RecentDecisions: []DecisionSummary{
				{
					Iteration:  1,
					Action:     "execute_agent",
					Target:     "node-2",
					Reasoning:  "Ready to exploit discovered vulnerability",
					Confidence: 0.85,
					Timestamp:  time.Now().Add(-5 * time.Minute).Format(time.RFC3339),
				},
			},
			ResourceConstraints: ResourceConstraints{
				MaxConcurrent:    10,
				CurrentRunning:   1,
				TotalIterations:  1,
				RemainingRetries: 1,
			},
			ObservedAt: time.Now(),
		}

		prompt := state.FormatForPrompt()

		// Verify all sections are present
		expectedSections := []string{
			"=== MISSION CONTEXT ===",
			"=== WORKFLOW PROGRESS ===",
			"=== RESOURCE CONSTRAINTS ===",
			"=== READY NODES (Can Execute Now) ===",
			"=== RUNNING NODES ===",
			"=== FAILED NODES ===",
			"=== RECENT DECISIONS ===",
		}

		for _, section := range expectedSections {
			if !strings.Contains(prompt, section) {
				t.Errorf("prompt missing section: %s", section)
			}
		}

		// Verify mission info is present
		if !strings.Contains(prompt, "Test Mission") {
			t.Error("mission name not in prompt")
		}
		if !strings.Contains(prompt, "Test all targets") {
			t.Error("objective not in prompt")
		}

		// Verify node information is present
		if !strings.Contains(prompt, "nmap_scan") {
			t.Error("ready node not in prompt")
		}
		if !strings.Contains(prompt, "exploit_vuln") {
			t.Error("running node not in prompt")
		}
		if !strings.Contains(prompt, "brute_force") {
			t.Error("failed node not in prompt")
		}

		// Verify decision context is present
		if !strings.Contains(prompt, "execute_agent") {
			t.Error("decision action not in prompt")
		}
	})

	t.Run("formats state with failed execution context", func(t *testing.T) {
		state := &ObservationState{
			MissionInfo: MissionInfo{
				ID:          "mission-123",
				Name:        "Test Mission",
				Objective:   "Test objective",
				Status:      "running",
				StartedAt:   time.Now(),
				TimeElapsed: "1m",
			},
			GraphSummary: GraphSummary{
				TotalNodes: 5,
			},
			ReadyNodes:     []NodeSummary{},
			RunningNodes:   []NodeSummary{},
			CompletedNodes: []CompletedNodeSummary{},
			FailedNodes:    []NodeSummary{},
			FailedExecution: &ExecutionFailure{
				NodeID:     "node-failed",
				NodeName:   "ssh_brute",
				AgentName:  "hydra",
				Attempt:    2,
				Error:      "Connection timeout after 30s",
				FailedAt:   time.Now(),
				CanRetry:   true,
				MaxRetries: 3,
			},
			RecentDecisions: []DecisionSummary{},
			ResourceConstraints: ResourceConstraints{
				MaxConcurrent:  10,
				CurrentRunning: 0,
			},
			ObservedAt: time.Now(),
		}

		prompt := state.FormatForPrompt()

		// Verify failure section is present
		if !strings.Contains(prompt, "=== RECENT FAILURE ===") {
			t.Error("failure section not in prompt")
		}
		if !strings.Contains(prompt, "ssh_brute") {
			t.Error("failed node name not in prompt")
		}
		if !strings.Contains(prompt, "Connection timeout") {
			t.Error("error message not in prompt")
		}
		if !strings.Contains(prompt, "Attempt: 2/3") {
			t.Error("attempt info not in prompt")
		}
		if !strings.Contains(prompt, "Can Retry: true") {
			t.Error("retry info not in prompt")
		}
	})

	t.Run("formats state with enhanced error classification", func(t *testing.T) {
		state := &ObservationState{
			MissionInfo: MissionInfo{
				ID:          "mission-123",
				Name:        "Test Mission",
				Objective:   "Test objective",
				Status:      "running",
				StartedAt:   time.Now(),
				TimeElapsed: "1m",
			},
			GraphSummary: GraphSummary{
				TotalNodes: 5,
			},
			ReadyNodes:     []NodeSummary{},
			RunningNodes:   []NodeSummary{},
			CompletedNodes: []CompletedNodeSummary{},
			FailedNodes:    []NodeSummary{},
			FailedExecution: &ExecutionFailure{
				NodeID:     "node-failed",
				NodeName:   "nmap_scan",
				AgentName:  "nmap",
				Attempt:    1,
				Error:      "nmap binary not found in PATH",
				FailedAt:   time.Now(),
				CanRetry:   true,
				MaxRetries: 3,
				// NEW: Enhanced error fields
				ErrorClass: "infrastructure",
				ErrorCode:  "BINARY_NOT_FOUND",
				RecoveryHints: []RecoveryHintSummary{
					{
						Strategy:    "use_alternative_tool",
						Alternative: "masscan",
						Reason:      "masscan can perform similar port scanning",
						Priority:    1,
					},
					{
						Strategy:    "use_alternative_tool",
						Alternative: "netcat",
						Reason:      "nc can probe individual ports",
						Priority:    2,
					},
				},
				PartialResults: map[string]any{
					"scanned_hosts": 5,
					"completed":     false,
				},
				FailureContext: map[string]any{
					"attempted_binary": "/usr/bin/nmap",
					"search_paths":     []string{"/usr/bin", "/usr/local/bin"},
				},
			},
			RecentDecisions: []DecisionSummary{},
			ResourceConstraints: ResourceConstraints{
				MaxConcurrent:  10,
				CurrentRunning: 0,
			},
			ObservedAt: time.Now(),
		}

		prompt := state.FormatForPrompt()

		// Verify enhanced error classification
		if !strings.Contains(prompt, "Error Code: BINARY_NOT_FOUND") {
			t.Error("error code not in prompt")
		}
		if !strings.Contains(prompt, "Error Class: infrastructure") {
			t.Error("error class not in prompt")
		}

		// Verify recovery hints are rendered
		if !strings.Contains(prompt, "Recovery Options:") {
			t.Error("recovery options section not in prompt")
		}
		if !strings.Contains(prompt, "[use_alternative_tool] masscan") {
			t.Error("first recovery hint not in prompt")
		}
		if !strings.Contains(prompt, "masscan can perform similar port scanning") {
			t.Error("recovery hint reason not in prompt")
		}

		// Verify partial results
		if !strings.Contains(prompt, "Partial Results Recovered:") {
			t.Error("partial results section not in prompt")
		}
		if !strings.Contains(prompt, "scanned_hosts: 5") {
			t.Error("partial results not in prompt")
		}

		// Verify failure context
		if !strings.Contains(prompt, "Failure Context:") {
			t.Error("failure context section not in prompt")
		}
		if !strings.Contains(prompt, "attempted_binary") {
			t.Error("failure context not in prompt")
		}
	})

	t.Run("handles empty state gracefully", func(t *testing.T) {
		state := &ObservationState{
			MissionInfo: MissionInfo{
				ID:        "mission-empty",
				Name:      "Empty Mission",
				Objective: "No nodes yet",
				Status:    "pending",
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

		prompt := state.FormatForPrompt()

		// Should still have basic sections
		if !strings.Contains(prompt, "=== MISSION CONTEXT ===") {
			t.Error("missing mission context section")
		}
		if !strings.Contains(prompt, "Empty Mission") {
			t.Error("mission name not in prompt")
		}

		// Should not have node sections when empty
		if strings.Contains(prompt, "=== READY NODES") {
			t.Error("should not show ready nodes section when empty")
		}
	})
}

// TestHelperFunctions tests utility helper functions
func TestHelperFunctions(t *testing.T) {
	t.Run("nodeToSummary converts workflow node", func(t *testing.T) {
		id := types.NewID()
		missionID := types.NewID()
		node := &schema.WorkflowNode{
			ID:          id,
			MissionID:   missionID,
			Type:        schema.WorkflowNodeTypeAgent,
			Name:        "test_node",
			Description: "Test node description",
			AgentName:   "test_agent",
			Status:      schema.WorkflowNodeStatusReady,
			IsDynamic:   true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		summary := nodeToSummary(node)

		if summary.ID != id.String() {
			t.Errorf("expected ID %s, got %s", id.String(), summary.ID)
		}
		if summary.Name != "test_node" {
			t.Errorf("expected name test_node, got %s", summary.Name)
		}
		if summary.Type != "agent" {
			t.Errorf("expected type agent, got %s", summary.Type)
		}
		if summary.AgentName != "test_agent" {
			t.Errorf("expected agent_name test_agent, got %s", summary.AgentName)
		}
		if !summary.IsDynamic {
			t.Error("expected is_dynamic to be true")
		}
	})

	t.Run("formatDuration formats time durations", func(t *testing.T) {
		tests := []struct {
			duration time.Duration
			expected string
		}{
			{30 * time.Second, "30s"},
			{90 * time.Second, "1.5m"},
			{5 * time.Minute, "5.0m"},
			{90 * time.Minute, "1.5h"},
			{3 * time.Hour, "3.0h"},
		}

		for _, tt := range tests {
			result := formatDuration(tt.duration)
			if result != tt.expected {
				t.Errorf("formatDuration(%v) = %s, expected %s", tt.duration, result, tt.expected)
			}
		}
	})

	t.Run("truncateString handles various lengths", func(t *testing.T) {
		tests := []struct {
			input    string
			maxLen   int
			expected string
		}{
			{"short", 100, "short"},
			{"exactly ten", 11, "exactly ten"},
			{"this is a very long string that should be truncated", 20, "this is a very lo..."},
			{"test", 3, "..."},
			{"test", 4, "test"}, // Not truncated since exactly at max length
			{"tests", 4, "t..."},
		}

		for _, tt := range tests {
			result := truncateString(tt.input, tt.maxLen)
			if result != tt.expected {
				t.Errorf("truncateString(%q, %d) = %q, expected %q", tt.input, tt.maxLen, result, tt.expected)
			}
		}
	})
}

// TestResourceConstraints tests resource constraint calculation
func TestResourceConstraints(t *testing.T) {
	t.Run("calculates constraints correctly", func(t *testing.T) {
		state := &ObservationState{
			MissionInfo: MissionInfo{
				StartedAt: time.Now().Add(-15 * time.Minute),
			},
			RunningNodes: []NodeSummary{
				{ID: "node-1", Status: "running"},
				{ID: "node-2", Status: "running"},
			},
			FailedNodes: []NodeSummary{
				{ID: "node-3", Status: "failed", Attempt: 1},
				{ID: "node-4", Status: "failed", Attempt: 2},
				{ID: "node-5", Status: "failed", Attempt: 3}, // Max attempts
			},
			RecentDecisions: []DecisionSummary{
				{Iteration: 1},
				{Iteration: 2},
				{Iteration: 3},
			},
		}

		observer := &Observer{}
		observer.calculateResourceConstraints(state)

		constraints := state.ResourceConstraints

		if constraints.CurrentRunning != 2 {
			t.Errorf("expected 2 running nodes, got %d", constraints.CurrentRunning)
		}
		if constraints.TotalIterations != 3 {
			t.Errorf("expected 3 iterations, got %d", constraints.TotalIterations)
		}
		if constraints.RemainingRetries != 2 {
			t.Errorf("expected 2 nodes available for retry, got %d", constraints.RemainingRetries)
		}
		if constraints.MaxConcurrent != 10 {
			t.Errorf("expected default max concurrent 10, got %d", constraints.MaxConcurrent)
		}
	})
}

// TestDecisionSummary tests decision summary creation
func TestDecisionSummary(t *testing.T) {
	t.Run("truncates long reasoning", func(t *testing.T) {
		longReasoning := strings.Repeat("This is a very long reasoning string. ", 20)

		summary := DecisionSummary{
			Iteration:  1,
			Action:     "execute_agent",
			Reasoning:  truncateString(longReasoning, 200),
			Confidence: 0.95,
		}

		if len(summary.Reasoning) > 200 {
			t.Errorf("reasoning should be truncated to 200 chars, got %d", len(summary.Reasoning))
		}
		if !strings.HasSuffix(summary.Reasoning, "...") {
			t.Error("truncated reasoning should end with ellipsis")
		}
	})
}

// TestExecutionFailure tests failed execution context
func TestExecutionFailure(t *testing.T) {
	t.Run("identifies retryable failure", func(t *testing.T) {
		failure := &ExecutionFailure{
			NodeID:     "node-123",
			NodeName:   "test_node",
			Attempt:    2,
			Error:      "Timeout",
			FailedAt:   time.Now(),
			CanRetry:   true,
			MaxRetries: 3,
		}

		if !failure.CanRetry {
			t.Error("failure should be retryable")
		}
		if failure.Attempt >= failure.MaxRetries {
			t.Error("attempt should be less than max retries for retryable failure")
		}
	})

	t.Run("identifies non-retryable failure", func(t *testing.T) {
		failure := &ExecutionFailure{
			NodeID:     "node-456",
			NodeName:   "test_node",
			Attempt:    3,
			Error:      "Max retries exceeded",
			FailedAt:   time.Now(),
			CanRetry:   false,
			MaxRetries: 3,
		}

		if failure.CanRetry {
			t.Error("failure should not be retryable")
		}
		if failure.Attempt != failure.MaxRetries {
			t.Error("attempt should equal max retries for non-retryable failure")
		}
	})
}

// Example demonstrates basic observer usage
func ExampleObserver_Observe() {
	// Note: This is a documentation example only
	// Real usage requires actual graph database connection

	ctx := context.Background()

	// Initialize queries (would need real graph client)
	// missionQueries := queries.NewMissionQueries(graphClient)
	// executionQueries := queries.NewExecutionQueries(graphClient)

	// Create observer
	// observer := NewObserver(missionQueries, executionQueries)

	// Observe mission state
	// state, err := observer.Observe(ctx, "mission-id")
	// if err != nil {
	//     log.Fatal(err)
	// }

	// Format for LLM prompt
	// prompt := state.FormatForPrompt()
	// fmt.Println(prompt)

	_ = ctx // Suppress unused variable warning
}

// Example demonstrates observing with failure context
func ExampleObserver_ObserveWithFailure() {
	// Note: This is a documentation example only

	ctx := context.Background()

	// When a node fails, observe with failure context
	// state, err := observer.ObserveWithFailure(ctx, "mission-id", "failed-node-id")
	// if err != nil {
	//     log.Fatal(err)
	// }

	// The state will include FailedExecution with details
	// if state.FailedExecution != nil {
	//     fmt.Printf("Node %s failed: %s\n",
	//         state.FailedExecution.NodeName,
	//         state.FailedExecution.Error)
	//     fmt.Printf("Can retry: %v\n", state.FailedExecution.CanRetry)
	// }

	_ = ctx
}
