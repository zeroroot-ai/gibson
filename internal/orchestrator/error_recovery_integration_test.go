package orchestrator

import (
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/sdk/toolerr"
)

// TestErrorRecoveryIntegration_FullFlow tests the complete error recovery flow:
// tool error -> enrichment -> observation -> prompt formatting
func TestErrorRecoveryIntegration_FullFlow(t *testing.T) {
	t.Run("infrastructure error with alternative tool suggestions", func(t *testing.T) {
		// Step 1: Create a tool error (simulating what SDK would return)
		toolErr := toolerr.New("nmap", "scan", toolerr.ErrCodeBinaryNotFound, "nmap binary not found in PATH")

		// Step 2: Enrich the error (simulating what agent harness would do)
		enrichedErr := toolerr.EnrichError(toolErr)

		// Verify enrichment worked
		if enrichedErr.Class != toolerr.ErrorClassInfrastructure {
			t.Errorf("expected error class %q, got %q", toolerr.ErrorClassInfrastructure, enrichedErr.Class)
		}
		if len(enrichedErr.Hints) == 0 {
			t.Fatal("expected recovery hints to be attached")
		}

		// Step 3: Convert to orchestrator ExecutionFailure
		failure := &ExecutionFailure{
			NodeID:     "node-scan-target",
			NodeName:   "nmap_scan",
			AgentName:  "nmap",
			Attempt:    1,
			Error:      enrichedErr.Message,
			FailedAt:   time.Now(),
			CanRetry:   true,
			MaxRetries: 3,
			ErrorClass: string(enrichedErr.Class),
			ErrorCode:  enrichedErr.Code,
		}

		// Convert hints to summary format
		for _, hint := range enrichedErr.Hints {
			failure.RecoveryHints = append(failure.RecoveryHints, RecoveryHintSummary{
				Strategy:    string(hint.Strategy),
				Alternative: hint.Alternative,
				Params:      hint.Params,
				Reason:      hint.Reason,
				Priority:    hint.Priority,
			})
		}

		// Step 4: Create ObservationState with failure
		state := &ObservationState{
			MissionInfo: MissionInfo{
				ID:          "mission-123",
				Name:        "Network Scan Mission",
				Objective:   "Discover and enumerate network services",
				Status:      "running",
				StartedAt:   time.Now().Add(-5 * time.Minute),
				TimeElapsed: "5.0m",
			},
			GraphSummary: GraphSummary{
				TotalNodes:      5,
				CompletedNodes:  2,
				FailedNodes:     1,
				PendingNodes:    2,
				TotalDecisions:  1,
				TotalExecutions: 3,
			},
			ReadyNodes: []NodeSummary{
				{
					ID:          "node-alt-scan",
					Name:        "masscan_scan",
					Type:        "agent",
					Description: "Alternative port scanner",
					AgentName:   "masscan",
					Status:      "ready",
				},
			},
			FailedExecution: failure,
			ResourceConstraints: ResourceConstraints{
				MaxConcurrent:  10,
				CurrentRunning: 0,
			},
			ObservedAt: time.Now(),
		}

		// Step 5: Format for prompt
		prompt := state.FormatForPrompt()

		// Verify prompt contains all semantic error recovery information
		expectedStrings := []string{
			"=== RECENT FAILURE ===",
			"nmap_scan",
			"Error Code: BINARY_NOT_FOUND",
			"Error Class: infrastructure",
			"Attempt: 1/3",
			"Recovery Options:",
			"[use_alternative_tool] masscan",
			"masscan provides similar port scanning",
		}

		for _, expected := range expectedStrings {
			if !strings.Contains(prompt, expected) {
				t.Errorf("prompt missing expected string: %q\nFull prompt:\n%s", expected, prompt)
			}
		}

		// Verify the prompt provides actionable guidance
		if !strings.Contains(prompt, "Recovery Options:") {
			t.Error("prompt should include recovery options section")
		}

		// Verify alternative tool is suggested
		if !strings.Contains(prompt, "masscan") {
			t.Error("prompt should suggest masscan as alternative")
		}
	})

	t.Run("transient error with retry and parameter modification", func(t *testing.T) {
		// Create timeout error
		toolErr := toolerr.New("nmap", "scan", toolerr.ErrCodeTimeout, "scan timeout after 30s")
		enrichedErr := toolerr.EnrichError(toolErr)

		// Verify enrichment
		if enrichedErr.Class != toolerr.ErrorClassTransient {
			t.Errorf("expected error class %q, got %q", toolerr.ErrorClassTransient, enrichedErr.Class)
		}
		if len(enrichedErr.Hints) == 0 {
			t.Fatal("expected recovery hints for timeout")
		}

		// Convert to failure
		failure := &ExecutionFailure{
			NodeID:     "node-scan-slow",
			NodeName:   "nmap_detailed_scan",
			AgentName:  "nmap",
			Attempt:    1,
			Error:      enrichedErr.Message,
			FailedAt:   time.Now(),
			CanRetry:   true,
			MaxRetries: 3,
			ErrorClass: string(enrichedErr.Class),
			ErrorCode:  enrichedErr.Code,
		}

		for _, hint := range enrichedErr.Hints {
			failure.RecoveryHints = append(failure.RecoveryHints, RecoveryHintSummary{
				Strategy:    string(hint.Strategy),
				Alternative: hint.Alternative,
				Params:      hint.Params,
				Reason:      hint.Reason,
				Priority:    hint.Priority,
			})
		}

		state := &ObservationState{
			MissionInfo: MissionInfo{
				ID:        "mission-456",
				Name:      "Timeout Recovery Test",
				Objective: "Handle transient failures",
				Status:    "running",
			},
			FailedExecution: failure,
			ObservedAt:      time.Now(),
		}

		prompt := state.FormatForPrompt()

		// Verify timeout-specific recovery hints
		expectedStrings := []string{
			"Error Code: TIMEOUT",
			"Error Class: transient",
			"Recovery Options:",
			"modify_params",
			"timing",
		}

		for _, expected := range expectedStrings {
			if !strings.Contains(prompt, expected) {
				t.Errorf("prompt missing expected string for timeout: %q", expected)
			}
		}
	})

	t.Run("semantic error with partial results salvaged", func(t *testing.T) {
		// Create parse error with partial results
		toolErr := toolerr.New("nmap", "scan", toolerr.ErrCodeParseError, "failed to parse XML output")
		enrichedErr := toolerr.EnrichError(toolErr)

		if enrichedErr.Class != toolerr.ErrorClassSemantic {
			t.Errorf("expected error class %q, got %q", toolerr.ErrorClassSemantic, enrichedErr.Class)
		}

		failure := &ExecutionFailure{
			NodeID:     "node-parse-fail",
			NodeName:   "nmap_xml_parse",
			AgentName:  "nmap",
			Attempt:    1,
			Error:      enrichedErr.Message,
			FailedAt:   time.Now(),
			CanRetry:   false,
			MaxRetries: 3,
			ErrorClass: string(enrichedErr.Class),
			ErrorCode:  enrichedErr.Code,
			PartialResults: map[string]any{
				"hosts_scanned":    25,
				"hosts_completed":  20,
				"hosts_failed":     5,
				"open_ports_found": 42,
			},
			FailureContext: map[string]any{
				"xml_line_number": 1456,
				"parsing_error":   "unexpected EOF",
			},
		}

		state := &ObservationState{
			MissionInfo: MissionInfo{
				ID:        "mission-789",
				Name:      "Parse Error Recovery",
				Objective: "Test partial results",
				Status:    "running",
			},
			FailedExecution: failure,
			ObservedAt:      time.Now(),
		}

		prompt := state.FormatForPrompt()

		// Verify partial results and context are shown
		expectedStrings := []string{
			"Error Code: PARSE_ERROR",
			"Error Class: semantic",
			"Partial Results Recovered:",
			"hosts_scanned: 25",
			"open_ports_found: 42",
			"Failure Context:",
			"xml_line_number",
		}

		for _, expected := range expectedStrings {
			if !strings.Contains(prompt, expected) {
				t.Errorf("prompt missing expected string for partial results: %q", expected)
			}
		}
	})

	t.Run("multiple recovery hints with priority ordering", func(t *testing.T) {
		// Create permission denied error (should have high-confidence hint)
		toolErr := toolerr.New("nmap", "scan", toolerr.ErrCodePermissionDenied, "permission denied: requires root")
		enrichedErr := toolerr.EnrichError(toolErr)

		if enrichedErr.Class != toolerr.ErrorClassInfrastructure {
			t.Errorf("expected error class %q, got %q", toolerr.ErrorClassInfrastructure, enrichedErr.Class)
		}

		failure := &ExecutionFailure{
			NodeID:     "node-permission-fail",
			NodeName:   "nmap_syn_scan",
			AgentName:  "nmap",
			Attempt:    1,
			Error:      enrichedErr.Message,
			FailedAt:   time.Now(),
			CanRetry:   true,
			MaxRetries: 3,
			ErrorClass: string(enrichedErr.Class),
			ErrorCode:  enrichedErr.Code,
		}

		for _, hint := range enrichedErr.Hints {
			failure.RecoveryHints = append(failure.RecoveryHints, RecoveryHintSummary{
				Strategy:    string(hint.Strategy),
				Alternative: hint.Alternative,
				Params:      hint.Params,
				Reason:      hint.Reason,
				Priority:    hint.Priority,
			})
		}

		state := &ObservationState{
			MissionInfo: MissionInfo{
				ID:        "mission-perms",
				Name:      "Permission Error Test",
				Objective: "Handle privilege issues",
				Status:    "running",
			},
			FailedExecution: failure,
			ObservedAt:      time.Now(),
		}

		prompt := state.FormatForPrompt()

		// Verify permission-specific recovery
		expectedStrings := []string{
			"Error Code: PERMISSION_DENIED",
			"Error Class: infrastructure",
			"Recovery Options:",
			"modify_params",
			"scan_type",
			"connect",
		}

		for _, expected := range expectedStrings {
			if !strings.Contains(prompt, expected) {
				t.Errorf("prompt missing expected string for permission denied: %q", expected)
			}
		}
	})
}

// TestErrorRecoveryIntegration_AllErrorClasses verifies all error classes are handled
func TestErrorRecoveryIntegration_AllErrorClasses(t *testing.T) {
	errorCases := []struct {
		name          string
		code          string
		expectedClass toolerr.ErrorClass
	}{
		{
			name:          "binary not found",
			code:          toolerr.ErrCodeBinaryNotFound,
			expectedClass: toolerr.ErrorClassInfrastructure,
		},
		{
			name:          "permission denied",
			code:          toolerr.ErrCodePermissionDenied,
			expectedClass: toolerr.ErrorClassInfrastructure,
		},
		{
			name:          "dependency missing",
			code:          toolerr.ErrCodeDependencyMissing,
			expectedClass: toolerr.ErrorClassInfrastructure,
		},
		{
			name:          "invalid input",
			code:          toolerr.ErrCodeInvalidInput,
			expectedClass: toolerr.ErrorClassSemantic,
		},
		{
			name:          "parse error",
			code:          toolerr.ErrCodeParseError,
			expectedClass: toolerr.ErrorClassSemantic,
		},
		{
			name:          "timeout",
			code:          toolerr.ErrCodeTimeout,
			expectedClass: toolerr.ErrorClassTransient,
		},
		{
			name:          "network error",
			code:          toolerr.ErrCodeNetworkError,
			expectedClass: toolerr.ErrorClassTransient,
		},
	}

	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create and enrich error
			err := toolerr.New("test-tool", "test-op", tc.code, "test message")
			enriched := toolerr.EnrichError(err)

			// Verify classification
			if enriched.Class != tc.expectedClass {
				t.Errorf("code %s: expected class %q, got %q", tc.code, tc.expectedClass, enriched.Class)
			}

			// Convert to failure and format
			failure := &ExecutionFailure{
				NodeID:     "node-test",
				NodeName:   "test_node",
				AgentName:  "test-tool",
				Attempt:    1,
				Error:      enriched.Message,
				ErrorClass: string(enriched.Class),
				ErrorCode:  enriched.Code,
			}

			state := &ObservationState{
				MissionInfo: MissionInfo{
					ID:        "test-mission",
					Name:      "Test Mission",
					Objective: "Test error class",
					Status:    "running",
				},
				FailedExecution: failure,
				ObservedAt:      time.Now(),
			}

			prompt := state.FormatForPrompt()

			// Verify error classification appears in prompt
			if !strings.Contains(prompt, "Error Code: "+tc.code) {
				t.Errorf("prompt missing error code: %s", tc.code)
			}
			if !strings.Contains(prompt, "Error Class: "+string(tc.expectedClass)) {
				t.Errorf("prompt missing error class: %s", tc.expectedClass)
			}
		})
	}
}

// TestErrorRecoveryIntegration_ConcurrentEnrichment tests concurrent error enrichment
func TestErrorRecoveryIntegration_ConcurrentEnrichment(t *testing.T) {
	// This test verifies that the error enrichment flow is thread-safe
	// and can handle concurrent errors from multiple agent executions

	done := make(chan bool)
	errorCount := 50

	for i := 0; i < errorCount; i++ {
		go func(id int) {
			defer func() { done <- true }()

			// Alternate between different error types
			var code string
			var tool string
			switch id % 4 {
			case 0:
				code = toolerr.ErrCodeBinaryNotFound
				tool = "nmap"
			case 1:
				code = toolerr.ErrCodeTimeout
				tool = "masscan"
			case 2:
				code = toolerr.ErrCodePermissionDenied
				tool = "nuclei"
			case 3:
				code = toolerr.ErrCodeNetworkError
				tool = "httpx"
			}

			// Create and enrich error
			err := toolerr.New(tool, "scan", code, "concurrent test")
			enriched := toolerr.EnrichError(err)

			// Verify enrichment succeeded
			if enriched.Class == "" {
				t.Errorf("goroutine %d: class not set", id)
			}

			// Create failure and format prompt
			failure := &ExecutionFailure{
				NodeID:     "node-concurrent",
				NodeName:   "concurrent_test",
				AgentName:  tool,
				ErrorClass: string(enriched.Class),
				ErrorCode:  enriched.Code,
			}

			state := &ObservationState{
				MissionInfo: MissionInfo{
					ID:     "concurrent-test",
					Status: "running",
				},
				FailedExecution: failure,
				ObservedAt:      time.Now(),
			}

			// Format prompt (should not panic or race)
			prompt := state.FormatForPrompt()
			if prompt == "" {
				t.Errorf("goroutine %d: empty prompt", id)
			}
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < errorCount; i++ {
		<-done
	}
}

// TestErrorRecoveryIntegration_PromptTokenBudget verifies prompts don't exceed token budgets
func TestErrorRecoveryIntegration_PromptTokenBudget(t *testing.T) {
	// Create a complex scenario with many failures and hints
	failure := &ExecutionFailure{
		NodeID:     "node-complex",
		NodeName:   "complex_operation_with_very_long_name_that_might_cause_token_overflow",
		AgentName:  "nmap",
		Attempt:    3,
		Error:      "This is a very long error message that contains a lot of diagnostic information about what went wrong during the scan operation including details about network timeouts, connection refused errors, DNS resolution failures, and various other issues that might be relevant for debugging but could also contribute to token bloat in the prompt",
		FailedAt:   time.Now(),
		CanRetry:   true,
		MaxRetries: 5,
		ErrorClass: "transient",
		ErrorCode:  "TIMEOUT",
		RecoveryHints: []RecoveryHintSummary{
			{
				Strategy: "retry_with_backoff",
				Reason:   "First recovery hint with detailed explanation",
				Priority: 1,
			},
			{
				Strategy: "modify_params",
				Params:   map[string]any{"timing": 2, "retries": 5, "timeout": "120s"},
				Reason:   "Second recovery hint with parameter modifications",
				Priority: 2,
			},
			{
				Strategy:    "use_alternative_tool",
				Alternative: "masscan",
				Reason:      "Third recovery hint suggesting alternative tool",
				Priority:    3,
			},
		},
		PartialResults: map[string]any{
			"hosts_scanned": 100,
			"ports_found":   500,
			"services":      []string{"http", "https", "ssh", "ftp", "smtp"},
		},
	}

	state := &ObservationState{
		MissionInfo: MissionInfo{
			ID:          "complex-mission",
			Name:        "Complex Mission with Many Details",
			Objective:   "Test token budget management in prompts",
			Status:      "running",
			TimeElapsed: "15.5m",
		},
		FailedExecution: failure,
		ObservedAt:      time.Now(),
	}

	prompt := state.FormatForPrompt()

	// Verify error message is truncated (design specifies 300 char limit)
	if strings.Contains(prompt, "connection refused errors, DNS resolution failures") {
		// The full error should be truncated
		lines := splitLines(prompt)
		for _, line := range lines {
			if strings.Contains(line, "Error:") && len(line) > 350 {
				t.Errorf("error message not properly truncated: length %d", len(line))
			}
		}
	}

	// Verify prompt still contains essential information
	essentialInfo := []string{
		"complex_operation",
		"Error Code: TIMEOUT",
		"Recovery Options:",
		"Partial Results",
	}

	for _, info := range essentialInfo {
		if !strings.Contains(prompt, info) {
			t.Errorf("prompt missing essential info after truncation: %q", info)
		}
	}
}

// Helper functions for integration tests

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
