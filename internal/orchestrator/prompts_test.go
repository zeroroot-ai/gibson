package orchestrator

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSystemPrompt(t *testing.T) {
	t.Run("SystemPrompt contains key sections", func(t *testing.T) {
		requiredSections := []string{
			"Mission Orchestrator",
			"Your Role",
			"Decision Guidelines",
			"Output Format",
			"Decision Actions Available",
			"Confidence Scoring",
			"Chain-of-Thought Reasoning",
		}

		for _, section := range requiredSections {
			if !strings.Contains(SystemPrompt, section) {
				t.Errorf("SystemPrompt missing required section: %s", section)
			}
		}
	})

	t.Run("SystemPrompt includes all actions", func(t *testing.T) {
		actions := []string{
			"execute_agent",
			"skip_agent",
			"modify_params",
			"retry",
			"spawn_agent",
			"complete",
		}

		for _, action := range actions {
			if !strings.Contains(SystemPrompt, action) {
				t.Errorf("SystemPrompt missing action: %s", action)
			}
		}
	})

	t.Run("SystemPrompt includes decision guidelines", func(t *testing.T) {
		guidelines := []string{
			"DAG dependencies",
			"parallelization",
			"high-value targets",
			"conservative with dynamic node spawning",
		}

		for _, guideline := range guidelines {
			if !strings.Contains(SystemPrompt, guideline) {
				t.Errorf("SystemPrompt missing guideline: %s", guideline)
			}
		}
	})

	t.Run("SystemPrompt is reasonable length", func(t *testing.T) {
		// Should be substantial but not excessive (< 4k tokens ~= 16k chars)
		if len(SystemPrompt) < 1000 {
			t.Error("SystemPrompt seems too short")
		}
		if len(SystemPrompt) > 16000 {
			t.Error("SystemPrompt is too long (may exceed token limits)")
		}
	})
}

func TestBuildObservationPrompt(t *testing.T) {
	t.Run("handles nil state gracefully", func(t *testing.T) {
		prompt := BuildObservationPrompt(nil)
		if prompt == "" {
			t.Error("Expected non-empty prompt for nil state")
		}
		if !strings.Contains(prompt, "No observation state") {
			t.Error("Expected error message in prompt for nil state")
		}
	})

	t.Run("includes mission overview", func(t *testing.T) {
		state := &ObservationState{
			MissionInfo: MissionInfo{
				ID:          "mission-123",
				Name:        "Test Mission",
				Objective:   "Test all security vulnerabilities",
				Status:      "running",
				TimeElapsed: "15.0m",
			},
			GraphSummary: GraphSummary{
				TotalNodes:     10,
				CompletedNodes: 3,
				FailedNodes:    1,
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

		prompt := BuildObservationPrompt(state)

		// Check for mission details
		if !strings.Contains(prompt, "mission-123") {
			t.Error("Prompt missing mission ID")
		}
		if !strings.Contains(prompt, "Test all security vulnerabilities") {
			t.Error("Prompt missing mission objective")
		}
		if !strings.Contains(prompt, "3/10") {
			t.Error("Prompt missing progress information")
		}
		if !strings.Contains(prompt, "15") {
			t.Error("Prompt missing elapsed time")
		}
	})

	t.Run("includes ready nodes", func(t *testing.T) {
		state := &ObservationState{
			MissionInfo: MissionInfo{
				ID:          "mission-123",
				Name:        "Test Mission",
				Objective:   "Test security",
				TimeElapsed: "5.0m",
			},
			GraphSummary: GraphSummary{
				TotalNodes:     5,
				CompletedNodes: 0,
			},
			ReadyNodes: []NodeSummary{
				{
					ID:          "node-1",
					Name:        "Port Scanner",
					Type:        "agent",
					AgentName:   "port-scanner",
					Description: "Scan open ports",
					Status:      "ready",
				},
				{
					ID:          "node-2",
					Name:        "HTTP Probe",
					Type:        "tool",
					ToolName:    "http-client",
					Description: "HTTP probe",
					Status:      "ready",
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

		prompt := BuildObservationPrompt(state)

		// Check for ready nodes section
		if !strings.Contains(prompt, "Ready Nodes") {
			t.Error("Prompt missing Ready Nodes section")
		}
		if !strings.Contains(prompt, "node-1") {
			t.Error("Prompt missing node-1")
		}
		if !strings.Contains(prompt, "port-scanner") {
			t.Error("Prompt missing agent name")
		}
		if !strings.Contains(prompt, "Scan open ports") {
			t.Error("Prompt missing description")
		}
	})

	t.Run("includes running nodes", func(t *testing.T) {
		state := &ObservationState{
			MissionInfo: MissionInfo{
				ID:          "mission-123",
				Name:        "Test Mission",
				Objective:   "Test security",
				TimeElapsed: "5.0m",
			},
			GraphSummary: GraphSummary{
				TotalNodes: 5,
			},
			ReadyNodes: []NodeSummary{},
			RunningNodes: []NodeSummary{
				{
					ID:        "node-3",
					Name:      "Jailbreak Test",
					Type:      "agent",
					AgentName: "jailbreaker",
					Status:    "running",
					Attempt:   1,
				},
			},
			CompletedNodes:  []CompletedNodeSummary{},
			FailedNodes:     []NodeSummary{},
			RecentDecisions: []DecisionSummary{},
			ResourceConstraints: ResourceConstraints{
				MaxConcurrent: 10,
			},
			ObservedAt: time.Now(),
		}

		prompt := BuildObservationPrompt(state)

		if !strings.Contains(prompt, "Currently Running") {
			t.Error("Prompt missing running nodes section")
		}
		if !strings.Contains(prompt, "node-3") {
			t.Error("Prompt missing running node")
		}
		if !strings.Contains(prompt, "jailbreaker") {
			t.Error("Prompt missing running agent name")
		}
	})

	t.Run("includes failed nodes", func(t *testing.T) {
		state := &ObservationState{
			MissionInfo: MissionInfo{
				ID:          "mission-123",
				Name:        "Test Mission",
				Objective:   "Test security",
				TimeElapsed: "10.0m",
			},
			GraphSummary: GraphSummary{
				TotalNodes:  5,
				FailedNodes: 1,
			},
			ReadyNodes:     []NodeSummary{},
			RunningNodes:   []NodeSummary{},
			CompletedNodes: []CompletedNodeSummary{},
			FailedNodes: []NodeSummary{
				{
					ID:        "node-fail",
					Name:      "Broken Agent",
					Type:      "agent",
					AgentName: "broken-agent",
					Status:    "failed",
					Attempt:   1,
				},
			},
			FailedExecution: &ExecutionFailure{
				NodeID:     "node-fail",
				NodeName:   "Broken Agent",
				AgentName:  "broken-agent",
				Attempt:    1,
				Error:      "Connection timeout",
				FailedAt:   time.Now().Add(-10 * time.Minute),
				CanRetry:   true,
				MaxRetries: 3,
			},
			RecentDecisions: []DecisionSummary{},
			ResourceConstraints: ResourceConstraints{
				MaxConcurrent:    10,
				RemainingRetries: 1,
			},
			ObservedAt: time.Now(),
		}

		prompt := BuildObservationPrompt(state)

		if !strings.Contains(prompt, "Failed Nodes") {
			t.Error("Prompt missing failed nodes section")
		}
		if !strings.Contains(prompt, "node-fail") {
			t.Error("Prompt missing failed node ID")
		}
		if !strings.Contains(prompt, "Connection timeout") {
			t.Error("Prompt missing error message")
		}
		if !strings.Contains(prompt, "1/3") {
			t.Error("Prompt missing retry information")
		}
	})

	t.Run("includes recent decisions", func(t *testing.T) {
		state := &ObservationState{
			MissionInfo: MissionInfo{
				ID:          "mission-123",
				Name:        "Test Mission",
				Objective:   "Test security",
				TimeElapsed: "10.0m",
			},
			GraphSummary: GraphSummary{
				TotalNodes: 5,
			},
			ReadyNodes:     []NodeSummary{},
			RunningNodes:   []NodeSummary{},
			CompletedNodes: []CompletedNodeSummary{},
			FailedNodes:    []NodeSummary{},
			RecentDecisions: []DecisionSummary{
				{
					Iteration:  1,
					Action:     "execute_agent",
					Target:     "node-1",
					Reasoning:  "Starting with reconnaissance",
					Confidence: 0.9,
					Timestamp:  time.Now().Add(-5 * time.Minute).Format(time.RFC3339),
				},
				{
					Iteration:  2,
					Action:     "execute_agent",
					Target:     "node-2",
					Reasoning:  "Following up with scanning",
					Confidence: 0.85,
					Timestamp:  time.Now().Add(-2 * time.Minute).Format(time.RFC3339),
				},
			},
			ResourceConstraints: ResourceConstraints{
				MaxConcurrent:   10,
				TotalIterations: 2,
			},
			ObservedAt: time.Now(),
		}

		prompt := BuildObservationPrompt(state)

		if !strings.Contains(prompt, "Recent Decisions") {
			t.Error("Prompt missing recent decisions section")
		}
		if !strings.Contains(prompt, "Iteration 1") {
			t.Error("Prompt missing first decision")
		}
		if !strings.Contains(prompt, "execute_agent") {
			t.Error("Prompt missing action")
		}
		if !strings.Contains(prompt, "confidence: 0.90") {
			t.Error("Prompt missing confidence")
		}
	})

	t.Run("includes resource constraints", func(t *testing.T) {
		state := &ObservationState{
			MissionInfo: MissionInfo{
				ID:          "mission-123",
				Name:        "Test Mission",
				Objective:   "Test security",
				TimeElapsed: "10.0m",
			},
			GraphSummary: GraphSummary{
				TotalNodes: 5,
			},
			ReadyNodes:      []NodeSummary{},
			RunningNodes:    []NodeSummary{},
			CompletedNodes:  []CompletedNodeSummary{},
			FailedNodes:     []NodeSummary{},
			RecentDecisions: []DecisionSummary{},
			ResourceConstraints: ResourceConstraints{
				MaxConcurrent:   10,
				CurrentRunning:  3,
				TotalIterations: 5,
				ExecutionBudget: &BudgetInfo{
					MaxExecutions:       100,
					RemainingExecutions: 75,
				},
			},
			ObservedAt: time.Now(),
		}

		prompt := BuildObservationPrompt(state)

		if !strings.Contains(prompt, "Resource Constraints") {
			t.Error("Prompt missing resource constraints section")
		}
		if !strings.Contains(prompt, "Max concurrent: 10") {
			t.Error("Prompt missing max concurrent")
		}
		if !strings.Contains(prompt, "Currently running: 3") {
			t.Error("Prompt missing currently running")
		}
		if !strings.Contains(prompt, "75/100") {
			t.Error("Prompt missing execution budget")
		}
	})

	t.Run("includes decision guidance", func(t *testing.T) {
		state := &ObservationState{
			MissionInfo: MissionInfo{
				ID:          "mission-123",
				Name:        "Test Mission",
				Objective:   "Test security",
				TimeElapsed: "5.0m",
			},
			GraphSummary: GraphSummary{
				TotalNodes: 5,
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

		prompt := BuildObservationPrompt(state)

		if !strings.Contains(prompt, "What Should We Do Next") {
			t.Error("Prompt missing decision guidance section")
		}
		if !strings.Contains(prompt, "Based on the current state") {
			t.Error("Prompt missing decision prompt")
		}
	})

	t.Run("prompt is reasonable length", func(t *testing.T) {
		// Create a realistic state
		state := &ObservationState{
			MissionInfo: MissionInfo{
				ID:          "mission-123",
				Name:        "Comprehensive Security Audit",
				Objective:   "Comprehensive security audit",
				Status:      "running",
				TimeElapsed: "30.0m",
			},
			GraphSummary: GraphSummary{
				TotalNodes:     20,
				CompletedNodes: 5,
				FailedNodes:    1,
				PendingNodes:   10,
			},
			ReadyNodes: []NodeSummary{
				{ID: "node-1", Type: "agent", AgentName: "scanner", Name: "Scanner"},
				{ID: "node-2", Type: "agent", AgentName: "injector", Name: "Injector"},
			},
			RunningNodes:   []NodeSummary{},
			CompletedNodes: []CompletedNodeSummary{},
			FailedNodes:    []NodeSummary{},
			RecentDecisions: []DecisionSummary{
				{Iteration: 1, Action: "execute_agent", Confidence: 0.9},
			},
			ResourceConstraints: ResourceConstraints{
				MaxConcurrent:   10,
				CurrentRunning:  0,
				TotalIterations: 1,
			},
			ObservedAt: time.Now(),
		}

		prompt := BuildObservationPrompt(state)

		// Should be substantial but not excessive (target < 2k tokens ~= 8k chars)
		if len(prompt) < 500 {
			t.Error("Observation prompt seems too short")
		}
		if len(prompt) > 12000 {
			t.Errorf("Observation prompt is too long (%d chars, ~%d tokens). Target is <8k chars.",
				len(prompt), EstimatePromptTokens(prompt))
		}
	})
}

func TestBuildDecisionSchema(t *testing.T) {
	t.Run("returns valid JSON", func(t *testing.T) {
		schema := BuildDecisionSchema()

		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(schema), &parsed); err != nil {
			t.Fatalf("Schema is not valid JSON: %v", err)
		}
	})

	t.Run("includes all required fields", func(t *testing.T) {
		schema := BuildDecisionSchema()

		var parsed map[string]interface{}
		json.Unmarshal([]byte(schema), &parsed)

		properties, ok := parsed["properties"].(map[string]interface{})
		if !ok {
			t.Fatal("Schema missing properties")
		}

		requiredFields := []string{
			"reasoning",
			"action",
			"target_node_id",
			"modifications",
			"spawn_config",
			"confidence",
			"stop_reason",
		}

		for _, field := range requiredFields {
			if _, exists := properties[field]; !exists {
				t.Errorf("Schema missing field: %s", field)
			}
		}
	})

	t.Run("action field has all valid enums", func(t *testing.T) {
		schema := BuildDecisionSchema()

		var parsed map[string]interface{}
		json.Unmarshal([]byte(schema), &parsed)

		properties := parsed["properties"].(map[string]interface{})
		action := properties["action"].(map[string]interface{})
		enums := action["enum"].([]interface{})

		expectedActions := []string{
			"execute_agent",
			"skip_agent",
			"modify_params",
			"retry",
			"spawn_agent",
			"complete",
			"request_approval",
			"abort",
			"escalate",
			"rollback",
			"reflect",
			"recall",
		}

		if len(enums) != len(expectedActions) {
			t.Errorf("Expected %d actions, got %d", len(expectedActions), len(enums))
		}

		for _, expected := range expectedActions {
			found := false
			for _, enum := range enums {
				if enum.(string) == expected {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Schema missing action enum: %s", expected)
			}
		}
	})

	t.Run("has conditional validation rules", func(t *testing.T) {
		schema := BuildDecisionSchema()

		var parsed map[string]interface{}
		json.Unmarshal([]byte(schema), &parsed)

		allOf, exists := parsed["allOf"]
		if !exists {
			t.Error("Schema missing conditional validation (allOf)")
		}

		// Should have at least 4 conditional rules
		rules, ok := allOf.([]interface{})
		if !ok || len(rules) < 4 {
			t.Error("Schema should have at least 4 conditional validation rules")
		}
	})

	t.Run("confidence has min/max constraints", func(t *testing.T) {
		schema := BuildDecisionSchema()

		var parsed map[string]interface{}
		json.Unmarshal([]byte(schema), &parsed)

		properties := parsed["properties"].(map[string]interface{})
		confidence := properties["confidence"].(map[string]interface{})

		if confidence["minimum"].(float64) != 0.0 {
			t.Error("Confidence minimum should be 0.0")
		}
		if confidence["maximum"].(float64) != 1.0 {
			t.Error("Confidence maximum should be 1.0")
		}
	})
}

func TestFormatDecisionExample(t *testing.T) {
	t.Run("returns valid JSON", func(t *testing.T) {
		example := FormatDecisionExample()

		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(example), &parsed); err != nil {
			t.Fatalf("Example is not valid JSON: %v", err)
		}
	})

	t.Run("includes required fields", func(t *testing.T) {
		example := FormatDecisionExample()

		var parsed map[string]interface{}
		json.Unmarshal([]byte(example), &parsed)

		requiredFields := []string{"reasoning", "action", "target_node_id", "confidence"}
		for _, field := range requiredFields {
			if _, exists := parsed[field]; !exists {
				t.Errorf("Example missing field: %s", field)
			}
		}
	})

	t.Run("has execute_agent action", func(t *testing.T) {
		example := FormatDecisionExample()

		var parsed map[string]interface{}
		json.Unmarshal([]byte(example), &parsed)

		if parsed["action"].(string) != "execute_agent" {
			t.Error("Example should demonstrate execute_agent action")
		}
	})
}

func TestFormatCompleteExample(t *testing.T) {
	t.Run("returns valid JSON", func(t *testing.T) {
		example := FormatCompleteExample()

		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(example), &parsed); err != nil {
			t.Fatalf("Example is not valid JSON: %v", err)
		}
	})

	t.Run("has complete action", func(t *testing.T) {
		example := FormatCompleteExample()

		var parsed map[string]interface{}
		json.Unmarshal([]byte(example), &parsed)

		if parsed["action"].(string) != "complete" {
			t.Error("Example should demonstrate complete action")
		}
	})

	t.Run("includes stop_reason", func(t *testing.T) {
		example := FormatCompleteExample()

		var parsed map[string]interface{}
		json.Unmarshal([]byte(example), &parsed)

		stopReason, exists := parsed["stop_reason"]
		if !exists {
			t.Error("Complete example must include stop_reason")
		}
		if stopReason.(string) == "" {
			t.Error("stop_reason should not be empty")
		}
	})
}

func TestFormatSpawnExample(t *testing.T) {
	t.Run("returns valid JSON", func(t *testing.T) {
		example := FormatSpawnExample()

		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(example), &parsed); err != nil {
			t.Fatalf("Example is not valid JSON: %v", err)
		}
	})

	t.Run("has spawn_agent action", func(t *testing.T) {
		example := FormatSpawnExample()

		var parsed map[string]interface{}
		json.Unmarshal([]byte(example), &parsed)

		if parsed["action"].(string) != "spawn_agent" {
			t.Error("Example should demonstrate spawn_agent action")
		}
	})

	t.Run("includes spawn_config", func(t *testing.T) {
		example := FormatSpawnExample()

		var parsed map[string]interface{}
		json.Unmarshal([]byte(example), &parsed)

		spawnConfig, exists := parsed["spawn_config"]
		if !exists {
			t.Error("Spawn example must include spawn_config")
		}

		config := spawnConfig.(map[string]interface{})
		requiredFields := []string{"agent_name", "description", "task_config", "depends_on"}
		for _, field := range requiredFields {
			if _, exists := config[field]; !exists {
				t.Errorf("spawn_config missing field: %s", field)
			}
		}
	})
}

func TestBuildFullPrompt(t *testing.T) {
	state := &ObservationState{
		MissionInfo: MissionInfo{
			ID:          "mission-123",
			Name:        "Test Mission",
			Objective:   "Test security",
			TimeElapsed: "5.0m",
		},
		GraphSummary: GraphSummary{
			TotalNodes: 5,
		},
		ReadyNodes: []NodeSummary{
			{ID: "node-1", Type: "agent", Name: "Test Node"},
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

	t.Run("includes system prompt", func(t *testing.T) {
		fullPrompt := BuildFullPrompt(state, false)

		if !strings.Contains(fullPrompt, "Mission Orchestrator") {
			t.Error("Full prompt missing system prompt")
		}
	})

	t.Run("includes observation prompt", func(t *testing.T) {
		fullPrompt := BuildFullPrompt(state, false)

		if !strings.Contains(fullPrompt, "mission-123") {
			t.Error("Full prompt missing observation state")
		}
	})

	t.Run("includes examples when requested", func(t *testing.T) {
		fullPromptWithExamples := BuildFullPrompt(state, true)

		if !strings.Contains(fullPromptWithExamples, "Example Decisions") {
			t.Error("Full prompt should include examples when requested")
		}
		if !strings.Contains(fullPromptWithExamples, "Execute Agent") {
			t.Error("Full prompt missing execute example")
		}
		if !strings.Contains(fullPromptWithExamples, "Complete Mission") {
			t.Error("Full prompt missing complete example")
		}
	})

	t.Run("excludes examples when not requested", func(t *testing.T) {
		fullPromptNoExamples := BuildFullPrompt(state, false)

		if strings.Contains(fullPromptNoExamples, "Example Decisions") {
			t.Error("Full prompt should not include examples when not requested")
		}
	})

	t.Run("has proper structure with separators", func(t *testing.T) {
		fullPrompt := BuildFullPrompt(state, false)

		// Should have section separators
		separatorCount := strings.Count(fullPrompt, "---")
		if separatorCount < 2 {
			t.Error("Full prompt should have section separators")
		}
	})

	t.Run("ends with decision request", func(t *testing.T) {
		fullPrompt := BuildFullPrompt(state, false)

		if !strings.Contains(fullPrompt, "provide your decision") {
			t.Error("Full prompt should end with decision request")
		}
	})
}

func TestEstimatePromptTokens(t *testing.T) {
	tests := []struct {
		name          string
		prompt        string
		expectedRange [2]int // min, max
	}{
		{
			name:          "empty string",
			prompt:        "",
			expectedRange: [2]int{0, 0},
		},
		{
			name:          "short prompt",
			prompt:        "Hello world",
			expectedRange: [2]int{2, 3},
		},
		{
			name:          "~400 character prompt",
			prompt:        strings.Repeat("test ", 80), // 400 chars
			expectedRange: [2]int{95, 105},             // ~100 tokens
		},
		{
			name:          "~4000 character prompt",
			prompt:        strings.Repeat("test ", 800), // 4000 chars
			expectedRange: [2]int{950, 1050},            // ~1000 tokens
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := EstimatePromptTokens(tt.prompt)

			if tokens < tt.expectedRange[0] || tokens > tt.expectedRange[1] {
				t.Errorf("EstimatePromptTokens(%d chars) = %d tokens, expected %d-%d",
					len(tt.prompt), tokens, tt.expectedRange[0], tt.expectedRange[1])
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{
			name:     "short string unchanged",
			input:    "hello",
			maxLen:   10,
			expected: "hello",
		},
		{
			name:     "exact length unchanged",
			input:    "hello",
			maxLen:   5,
			expected: "hello",
		},
		{
			name:     "truncate long string",
			input:    "hello world this is a long string",
			maxLen:   15,
			expected: "hello world ...",
		},
		{
			name:     "maxLen less than ellipsis",
			input:    "hello",
			maxLen:   2,
			expected: "...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncate(tt.input, tt.maxLen)
			if result != tt.expected {
				t.Errorf("truncate(%q, %d) = %q, expected %q",
					tt.input, tt.maxLen, result, tt.expected)
			}
		})
	}
}

func BenchmarkBuildObservationPrompt(b *testing.B) {
	// Create a realistic observation state
	state := &ObservationState{
		MissionInfo: MissionInfo{
			ID:          "mission-benchmark",
			Name:        "Benchmark Mission",
			Objective:   "Comprehensive security audit of production LLM system",
			Status:      "running",
			TimeElapsed: "45.0m",
		},
		GraphSummary: GraphSummary{
			TotalNodes:     50,
			CompletedNodes: 20,
			FailedNodes:    2,
			PendingNodes:   20,
		},
		ReadyNodes: []NodeSummary{
			{ID: "node-1", Type: "agent", AgentName: "scanner", Name: "Scanner"},
			{ID: "node-2", Type: "agent", AgentName: "injector", Name: "Injector"},
			{ID: "node-3", Type: "tool", ToolName: "http-client", Name: "HTTP Client"},
		},
		RunningNodes: []NodeSummary{
			{ID: "node-4", Type: "agent", AgentName: "jailbreaker", Name: "Jailbreaker"},
		},
		CompletedNodes: []CompletedNodeSummary{},
		FailedNodes: []NodeSummary{
			{ID: "node-fail-1", Name: "Failed Node 1", Attempt: 2},
		},
		RecentDecisions: []DecisionSummary{
			{Iteration: 1, Action: "execute_agent", Confidence: 0.9},
			{Iteration: 2, Action: "execute_agent", Confidence: 0.85},
		},
		ResourceConstraints: ResourceConstraints{
			MaxConcurrent:   10,
			CurrentRunning:  1,
			TotalIterations: 2,
		},
		ObservedAt: time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BuildObservationPrompt(state)
	}
}

func BenchmarkBuildFullPrompt(b *testing.B) {
	state := &ObservationState{
		MissionInfo: MissionInfo{
			ID:          "mission-benchmark",
			Name:        "Benchmark Mission",
			Objective:   "Security audit",
			TimeElapsed: "10.0m",
		},
		GraphSummary: GraphSummary{
			TotalNodes:     20,
			CompletedNodes: 5,
		},
		ReadyNodes: []NodeSummary{
			{ID: "node-1", Type: "agent", Name: "Test Node"},
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

	b.Run("without examples", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			BuildFullPrompt(state, false)
		}
	})

	b.Run("with examples", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			BuildFullPrompt(state, true)
		}
	})
}
