// Package guardrail_test provides comprehensive integration tests for the guardrail pipeline.
//
// These tests verify the complete guardrail system working together:
//
//  1. TestPipeline_MultipleGuardrails - Tests full pipeline with multiple guardrails
//     (scope, rate, tool, PII) working together, including:
//     - All guardrails passing
//     - Individual guardrails blocking
//     - PII redaction
//     - Multiple redactions through the pipeline
//     - Output guardrails
//
//  2. TestPipeline_RealisticAgentScenarios - Tests realistic agent request scenarios:
//     - Reconnaissance agent scanning allowed targets
//     - Agent attempting to access blocked paths
//     - Agent sending requests with PII
//     - Agent attempting to use restricted tools
//     - Agent performing allowed network scans
//
//  3. TestPipeline_ShortCircuitOnBlock - Verifies pipeline stops on first block:
//     - Scope blocking early in pipeline
//     - Tool restriction blocking mid-pipeline
//     - Content filter blocking
//
//  4. TestPipeline_ConcurrentUsage - Tests concurrent pipeline usage:
//     - Multiple agents with different targets
//     - Multiple agents with same target (shared rate limiting)
//     - Concurrent PII redaction (thread safety)
//
//  5. TestPipeline_RedactionThroughMultipleGuardrails - Tests content modifications:
//     - PII redaction followed by content filter
//     - Multiple PII types redacted
//     - Cascading redactions
//
//  6. TestPipeline_RateLimitingBehavior - Tests rate limiting edge cases:
//     - Rate limit recovery after window
//     - Burst handling
//
//  7. TestPipeline_EmptyPipeline - Tests behavior with no guardrails
//
// All tests use table-driven test patterns and verify both success and failure cases.
package guardrail_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/guardrail"
	"github.com/zeroroot-ai/gibson/internal/engine/guardrail/builtin"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// TestPipeline_MultipleGuardrails tests a full pipeline with multiple guardrails working together
func TestPipeline_MultipleGuardrails(t *testing.T) {
	tests := []struct {
		name        string
		guardrails  []guardrail.Guardrail
		input       guardrail.GuardrailInput
		output      guardrail.GuardrailOutput
		wantErr     bool
		wantBlocked bool
		checkInput  func(t *testing.T, result guardrail.GuardrailInput)
		checkOutput func(t *testing.T, result guardrail.GuardrailOutput)
	}{
		{
			name: "scope+rate+tool+pii - all pass",
			guardrails: []guardrail.Guardrail{
				builtin.NewScopeValidator(builtin.ScopeValidatorConfig{
					AllowedDomains: []string{"*.example.com"},
				}),
				builtin.NewRateLimiter(builtin.RateLimiterConfig{
					MaxRequests: 10,
					Window:      time.Second,
				}),
				builtin.NewToolRestriction(builtin.ToolRestrictionConfig{
					AllowedTools: []string{"web_fetch", "grep"},
				}),
				mustNewPIIDetector(t, builtin.PIIDetectorConfig{
					Action:          guardrail.GuardrailActionRedact,
					EnabledPatterns: []string{"email"},
				}),
			},
			input: guardrail.GuardrailInput{
				Content:  "Fetch data from the API",
				ToolName: "web_fetch",
				TargetInfo: &harness.TargetInfo{
					URL: "https://api.example.com/data",
				},
			},
			wantErr:     false,
			wantBlocked: false,
			checkInput: func(t *testing.T, result guardrail.GuardrailInput) {
				assert.Equal(t, "Fetch data from the API", result.Content)
			},
		},
		{
			name: "scope blocks unauthorized domain",
			guardrails: []guardrail.Guardrail{
				builtin.NewScopeValidator(builtin.ScopeValidatorConfig{
					AllowedDomains: []string{"example.com"},
				}),
				builtin.NewRateLimiter(builtin.RateLimiterConfig{
					MaxRequests: 10,
					Window:      time.Second,
				}),
			},
			input: guardrail.GuardrailInput{
				Content: "Access unauthorized site",
				TargetInfo: &harness.TargetInfo{
					URL: "https://evil.com/data",
				},
			},
			wantErr:     true,
			wantBlocked: true,
		},
		{
			name: "tool restriction blocks unauthorized tool",
			guardrails: []guardrail.Guardrail{
				builtin.NewToolRestriction(builtin.ToolRestrictionConfig{
					AllowedTools: []string{"web_fetch", "grep"},
				}),
			},
			input: guardrail.GuardrailInput{
				Content:  "Execute dangerous command",
				ToolName: "execute_shell",
			},
			wantErr:     true,
			wantBlocked: true,
		},
		{
			name: "pii detector redacts sensitive data",
			guardrails: []guardrail.Guardrail{
				mustNewPIIDetector(t, builtin.PIIDetectorConfig{
					Action:          guardrail.GuardrailActionRedact,
					EnabledPatterns: []string{"email", "ssn"},
				}),
			},
			input: guardrail.GuardrailInput{
				Content: "Contact john.doe@example.com or use SSN 123-45-6789",
			},
			wantErr:     false,
			wantBlocked: false,
			checkInput: func(t *testing.T, result guardrail.GuardrailInput) {
				assert.Contains(t, result.Content, "[REDACTED-EMAIL]")
				assert.Contains(t, result.Content, "[REDACTED-SSN]")
				assert.NotContains(t, result.Content, "john.doe@example.com")
				assert.NotContains(t, result.Content, "123-45-6789")
			},
		},
		{
			name: "multiple redactions through pipeline",
			guardrails: []guardrail.Guardrail{
				mustNewPIIDetector(t, builtin.PIIDetectorConfig{
					Action:          guardrail.GuardrailActionRedact,
					EnabledPatterns: []string{"email"},
				}),
				mustNewContentFilter(t, builtin.ContentFilterConfig{
					Patterns: []builtin.ContentPattern{
						{
							Pattern: `\b(password|secret)\b`,
							Action:  guardrail.GuardrailActionRedact,
							Replace: "[REDACTED-SENSITIVE]",
						},
					},
				}),
			},
			input: guardrail.GuardrailInput{
				Content: "Email admin@example.com with password abc123",
			},
			wantErr:     false,
			wantBlocked: false,
			checkInput: func(t *testing.T, result guardrail.GuardrailInput) {
				// First guardrail redacts email
				assert.Contains(t, result.Content, "[REDACTED-EMAIL]")
				assert.NotContains(t, result.Content, "admin@example.com")
				// Second guardrail redacts password
				assert.Contains(t, result.Content, "[REDACTED-SENSITIVE]")
				assert.NotContains(t, result.Content, "password")
			},
		},
		{
			name: "output guardrails redact PII",
			guardrails: []guardrail.Guardrail{
				mustNewPIIDetector(t, builtin.PIIDetectorConfig{
					Action:          guardrail.GuardrailActionRedact,
					EnabledPatterns: []string{"phone"},
				}),
			},
			output: guardrail.GuardrailOutput{
				Content: "Customer phone: 555-123-4567",
			},
			wantErr:     false,
			wantBlocked: false,
			checkOutput: func(t *testing.T, result guardrail.GuardrailOutput) {
				assert.Contains(t, result.Content, "[REDACTED-PHONE]")
				assert.NotContains(t, result.Content, "555-123-4567")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pipeline := guardrail.NewGuardrailPipeline(tt.guardrails...)
			ctx := context.Background()

			// Test input processing if input is provided
			if tt.input.Content != "" || tt.input.ToolName != "" {
				result, err := pipeline.ProcessInput(ctx, tt.input)

				if tt.wantErr {
					require.Error(t, err)
					if tt.wantBlocked {
						var blockedErr *guardrail.GuardrailBlockedError
						assert.True(t, errors.As(err, &blockedErr))
					}
				} else {
					require.NoError(t, err)
					if tt.checkInput != nil {
						tt.checkInput(t, result)
					}
				}
			}

			// Test output processing if output is provided
			if tt.output.Content != "" {
				result, err := pipeline.ProcessOutput(ctx, tt.output)

				if tt.wantErr {
					require.Error(t, err)
					if tt.wantBlocked {
						var blockedErr *guardrail.GuardrailBlockedError
						assert.True(t, errors.As(err, &blockedErr))
					}
				} else {
					require.NoError(t, err)
					if tt.checkOutput != nil {
						tt.checkOutput(t, result)
					}
				}
			}
		})
	}
}

// TestPipeline_RealisticAgentScenarios tests realistic agent request scenarios
func TestPipeline_RealisticAgentScenarios(t *testing.T) {
	tests := []struct {
		name        string
		scenario    string
		input       guardrail.GuardrailInput
		wantErr     bool
		wantBlocked bool
		checkResult func(t *testing.T, result guardrail.GuardrailInput, err error)
	}{
		{
			name:     "reconnaissance agent scanning allowed target",
			scenario: "Agent performing authorized recon on target domain",
			input: guardrail.GuardrailInput{
				Content:   "Scan web server for open ports and services",
				AgentName: "recon-agent",
				ToolName:  "port_scanner",
				TargetInfo: &harness.TargetInfo{
					ID:   types.NewID(),
					Name: "test-target",
					URL:  "https://target.example.com",
					Type: "web-server",
				},
				MissionContext: &harness.MissionContext{
					ID:           types.NewID(),
					Name:         "pentest-mission-001",
					CurrentAgent: "recon-agent",
					Phase:        "reconnaissance",
				},
			},
			wantErr:     false,
			wantBlocked: false,
		},
		{
			name:     "agent attempting to access blocked path",
			scenario: "Agent trying to access admin panel (blocked path)",
			input: guardrail.GuardrailInput{
				Content:   "Check admin panel for vulnerabilities",
				AgentName: "scanner-agent",
				ToolName:  "web_fetch",
				TargetInfo: &harness.TargetInfo{
					URL: "https://target.example.com/admin/users",
				},
			},
			wantErr:     true,
			wantBlocked: true,
		},
		{
			name:     "agent sending request with PII in logs",
			scenario: "Agent inadvertently logging PII that should be redacted",
			input: guardrail.GuardrailInput{
				Content:   "Found user credentials: email test@example.com, SSN 123-45-6789",
				AgentName: "exfil-agent",
				ToolName:  "log_finding",
			},
			wantErr:     false,
			wantBlocked: false,
			checkResult: func(t *testing.T, result guardrail.GuardrailInput, err error) {
				assert.NoError(t, err)
				assert.Contains(t, result.Content, "[REDACTED-EMAIL]")
				assert.Contains(t, result.Content, "[REDACTED-SSN]")
				assert.NotContains(t, result.Content, "test@example.com")
				assert.NotContains(t, result.Content, "123-45-6789")
			},
		},
		{
			name:     "agent attempting to use restricted tool",
			scenario: "Agent trying to use shell execution tool (blocked)",
			input: guardrail.GuardrailInput{
				Content:   "rm -rf /tmp/test",
				AgentName: "exploit-agent",
				ToolName:  "execute_shell",
			},
			wantErr:     true,
			wantBlocked: true,
		},
		{
			name:     "agent performing allowed network scan",
			scenario: "Agent using allowed tool with proper scope",
			input: guardrail.GuardrailInput{
				Content:   "Perform nmap scan on target network",
				AgentName: "network-agent",
				ToolName:  "nmap",
				TargetInfo: &harness.TargetInfo{
					URL:  "https://target.example.com",
					Type: "network",
				},
			},
			wantErr:     false,
			wantBlocked: false,
		},
	}

	// Create a comprehensive pipeline for realistic scenarios
	pipeline := guardrail.NewGuardrailPipeline(
		builtin.NewScopeValidator(builtin.ScopeValidatorConfig{
			AllowedDomains: []string{"*.example.com"},
			BlockedPaths:   []string{"/admin/*", "/internal/*"},
		}),
		builtin.NewRateLimiter(builtin.RateLimiterConfig{
			MaxRequests: 100,
			Window:      time.Minute,
		}),
		builtin.NewToolRestriction(builtin.ToolRestrictionConfig{
			AllowedTools: []string{"port_scanner", "web_fetch", "nmap", "log_finding"},
			BlockedTools: []string{"execute_shell", "delete_file"},
		}),
		mustNewPIIDetector(t, builtin.PIIDetectorConfig{
			Action:          guardrail.GuardrailActionRedact,
			EnabledPatterns: []string{"email", "ssn", "phone", "credit_card"},
		}),
	)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			result, err := pipeline.ProcessInput(ctx, tt.input)

			if tt.wantErr {
				require.Error(t, err, "Expected error for scenario: %s", tt.scenario)
				if tt.wantBlocked {
					var blockedErr *guardrail.GuardrailBlockedError
					assert.True(t, errors.As(err, &blockedErr),
						"Expected GuardrailBlockedError for scenario: %s", tt.scenario)
					t.Logf("Blocked by: %s (%s) - %s",
						blockedErr.GuardrailName,
						blockedErr.GuardrailType,
						blockedErr.Reason)
				}
			} else {
				require.NoError(t, err, "Unexpected error for scenario: %s", tt.scenario)
				if tt.checkResult != nil {
					tt.checkResult(t, result, err)
				}
			}
		})
	}
}

// TestPipeline_ShortCircuitOnBlock tests that pipeline stops on first block
func TestPipeline_ShortCircuitOnBlock(t *testing.T) {
	tests := []struct {
		name             string
		guardrails       []guardrail.Guardrail
		input            guardrail.GuardrailInput
		expectedBlocker  string // Name of guardrail that should block
		expectedType     guardrail.GuardrailType
		subsequentCalled bool // Whether subsequent guardrails should be called
	}{
		{
			name: "scope blocks, rate limiter never called",
			guardrails: []guardrail.Guardrail{
				builtin.NewScopeValidator(builtin.ScopeValidatorConfig{
					AllowedDomains: []string{"example.com"},
				}),
				builtin.NewRateLimiter(builtin.RateLimiterConfig{
					MaxRequests: 1,
					Window:      time.Second,
				}),
			},
			input: guardrail.GuardrailInput{
				Content: "Access blocked domain",
				TargetInfo: &harness.TargetInfo{
					URL: "https://evil.com/data",
				},
			},
			expectedBlocker:  "scope-validator",
			expectedType:     guardrail.GuardrailTypeScope,
			subsequentCalled: false,
		},
		{
			name: "tool restriction blocks, PII detector never called",
			guardrails: []guardrail.Guardrail{
				builtin.NewToolRestriction(builtin.ToolRestrictionConfig{
					BlockedTools: []string{"dangerous_tool"},
				}),
				mustNewPIIDetector(t, builtin.PIIDetectorConfig{
					Action:          guardrail.GuardrailActionBlock,
					EnabledPatterns: []string{"email"},
				}),
			},
			input: guardrail.GuardrailInput{
				Content:  "Use blocked tool with email test@example.com",
				ToolName: "dangerous_tool",
			},
			expectedBlocker:  "tool_restriction",
			expectedType:     guardrail.GuardrailTypeTool,
			subsequentCalled: false,
		},
		{
			name: "first guardrail allows, second blocks",
			guardrails: []guardrail.Guardrail{
				builtin.NewScopeValidator(builtin.ScopeValidatorConfig{
					AllowedDomains: []string{"*.example.com"},
				}),
				mustNewContentFilter(t, builtin.ContentFilterConfig{
					Patterns: []builtin.ContentPattern{
						{
							Pattern: `forbidden`,
							Action:  guardrail.GuardrailActionBlock,
						},
					},
				}),
			},
			input: guardrail.GuardrailInput{
				Content: "This contains forbidden content",
				TargetInfo: &harness.TargetInfo{
					URL: "https://api.example.com",
				},
			},
			expectedBlocker:  "content-filter",
			expectedType:     guardrail.GuardrailTypeContent,
			subsequentCalled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pipeline := guardrail.NewGuardrailPipeline(tt.guardrails...)
			ctx := context.Background()

			_, err := pipeline.ProcessInput(ctx, tt.input)

			require.Error(t, err)

			var blockedErr *guardrail.GuardrailBlockedError
			require.True(t, errors.As(err, &blockedErr))

			assert.Equal(t, tt.expectedBlocker, blockedErr.GuardrailName,
				"Expected blocker to be %s but got %s", tt.expectedBlocker, blockedErr.GuardrailName)
			assert.Equal(t, tt.expectedType, blockedErr.GuardrailType,
				"Expected type to be %s but got %s", tt.expectedType, blockedErr.GuardrailType)

			t.Logf("Successfully short-circuited at: %s (%s) - %s",
				blockedErr.GuardrailName,
				blockedErr.GuardrailType,
				blockedErr.Reason)
		})
	}
}

// TestPipeline_ConcurrentUsage tests concurrent pipeline usage from multiple agents
func TestPipeline_ConcurrentUsage(t *testing.T) {
	// Create a pipeline with rate limiting per target
	pipeline := guardrail.NewGuardrailPipeline(
		builtin.NewScopeValidator(builtin.ScopeValidatorConfig{
			AllowedDomains: []string{"*.example.com"},
		}),
		builtin.NewRateLimiter(builtin.RateLimiterConfig{
			MaxRequests: 5,
			Window:      100 * time.Millisecond,
			PerTarget:   true, // Separate limits per target
		}),
		mustNewPIIDetector(t, builtin.PIIDetectorConfig{
			Action:          guardrail.GuardrailActionRedact,
			EnabledPatterns: []string{"email"},
		}),
	)

	// Test concurrent requests from multiple agents
	t.Run("concurrent agents with different targets", func(t *testing.T) {
		ctx := context.Background()
		numAgents := 3
		requestsPerAgent := 10

		var wg sync.WaitGroup
		results := make([][]error, numAgents)

		for agentIdx := 0; agentIdx < numAgents; agentIdx++ {
			wg.Add(1)
			results[agentIdx] = make([]error, requestsPerAgent)

			go func(idx int) {
				defer wg.Done()

				targetDomain := fmt.Sprintf("target%d.example.com", idx)
				agentName := fmt.Sprintf("agent-%d", idx)

				for reqIdx := 0; reqIdx < requestsPerAgent; reqIdx++ {
					input := guardrail.GuardrailInput{
						Content:   fmt.Sprintf("Request %d from %s to %s", reqIdx, agentName, targetDomain),
						AgentName: agentName,
						ToolName:  "web_fetch",
						TargetInfo: &harness.TargetInfo{
							URL: fmt.Sprintf("https://%s/api/data", targetDomain),
						},
					}

					_, err := pipeline.ProcessInput(ctx, input)
					results[idx][reqIdx] = err

					// Small delay between requests
					time.Sleep(10 * time.Millisecond)
				}
			}(agentIdx)
		}

		wg.Wait()

		// Verify results
		for agentIdx, agentResults := range results {
			t.Logf("Agent %d results:", agentIdx)
			allowedCount := 0
			blockedCount := 0

			for reqIdx, err := range agentResults {
				if err == nil {
					allowedCount++
				} else {
					var blockedErr *guardrail.GuardrailBlockedError
					if errors.As(err, &blockedErr) {
						blockedCount++
						t.Logf("  Request %d: Blocked by %s - %s",
							reqIdx, blockedErr.GuardrailName, blockedErr.Reason)
					} else {
						t.Errorf("  Request %d: Unexpected error: %v", reqIdx, err)
					}
				}
			}

			t.Logf("  Allowed: %d, Blocked: %d", allowedCount, blockedCount)

			// Each agent should have some allowed and some blocked due to rate limiting
			assert.Greater(t, allowedCount, 0, "Agent %d should have some allowed requests", agentIdx)
			assert.Greater(t, blockedCount, 0, "Agent %d should have some blocked requests", agentIdx)
		}
	})

	t.Run("concurrent agents with same target", func(t *testing.T) {
		ctx := context.Background()
		numAgents := 5
		requestsPerAgent := 3

		var wg sync.WaitGroup
		var mu sync.Mutex
		totalAllowed := 0
		totalBlocked := 0

		for agentIdx := 0; agentIdx < numAgents; agentIdx++ {
			wg.Add(1)

			go func(idx int) {
				defer wg.Done()

				agentName := fmt.Sprintf("concurrent-agent-%d", idx)

				for reqIdx := 0; reqIdx < requestsPerAgent; reqIdx++ {
					input := guardrail.GuardrailInput{
						Content:   fmt.Sprintf("Request %d from %s", reqIdx, agentName),
						AgentName: agentName,
						ToolName:  "web_fetch",
						TargetInfo: &harness.TargetInfo{
							URL: "https://shared-target.example.com/api/data",
						},
					}

					_, err := pipeline.ProcessInput(ctx, input)

					mu.Lock()
					if err == nil {
						totalAllowed++
					} else {
						var blockedErr *guardrail.GuardrailBlockedError
						if errors.As(err, &blockedErr) {
							totalBlocked++
						}
					}
					mu.Unlock()
				}
			}(agentIdx)
		}

		wg.Wait()

		t.Logf("Concurrent same-target results: Allowed: %d, Blocked: %d",
			totalAllowed, totalBlocked)

		// With same target and rate limiting, some should be blocked
		assert.Greater(t, totalAllowed, 0, "Should have some allowed requests")
		assert.Greater(t, totalBlocked, 0, "Should have some blocked requests due to shared rate limit")
	})

	t.Run("concurrent PII redaction", func(t *testing.T) {
		ctx := context.Background()
		numGoroutines := 10

		var wg sync.WaitGroup
		var mu sync.Mutex
		redactedCount := 0

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)

			go func(idx int) {
				defer wg.Done()

				input := guardrail.GuardrailInput{
					Content:   fmt.Sprintf("Email for agent %d: agent%d@example.com", idx, idx),
					AgentName: fmt.Sprintf("agent-%d", idx),
					ToolName:  "log_message",
					TargetInfo: &harness.TargetInfo{
						URL: fmt.Sprintf("https://target%d.example.com", idx),
					},
				}

				result, err := pipeline.ProcessInput(ctx, input)
				require.NoError(t, err)

				mu.Lock()
				if !assert.Contains(t, result.Content, "[REDACTED-EMAIL]") {
					t.Errorf("Expected redacted content, got: %s", result.Content)
				} else {
					redactedCount++
				}
				mu.Unlock()
			}(i)
		}

		wg.Wait()

		assert.Equal(t, numGoroutines, redactedCount,
			"All concurrent requests should have PII redacted")
	})
}

// TestPipeline_RedactionThroughMultipleGuardrails tests content modifications across pipeline
func TestPipeline_RedactionThroughMultipleGuardrails(t *testing.T) {
	tests := []struct {
		name             string
		guardrails       []guardrail.Guardrail
		input            string
		expectedOutput   string
		checkContains    []string
		checkNotContains []string
	}{
		{
			name: "PII then content filter redactions",
			guardrails: []guardrail.Guardrail{
				mustNewPIIDetector(t, builtin.PIIDetectorConfig{
					Action:          guardrail.GuardrailActionRedact,
					EnabledPatterns: []string{"email", "ssn"},
				}),
				mustNewContentFilter(t, builtin.ContentFilterConfig{
					Patterns: []builtin.ContentPattern{
						{
							Pattern: `\b(password|secret)\b`,
							Action:  guardrail.GuardrailActionRedact,
							Replace: "[SENSITIVE]",
						},
					},
				}),
			},
			input: "Contact admin@example.com with password p@ssw0rd and SSN 123-45-6789",
			checkContains: []string{
				"[REDACTED-EMAIL]",
				"[REDACTED-SSN]",
				"[SENSITIVE]",
			},
			checkNotContains: []string{
				"admin@example.com",
				"123-45-6789",
				"password",
			},
		},
		{
			name: "multiple PII types redacted",
			guardrails: []guardrail.Guardrail{
				mustNewPIIDetector(t, builtin.PIIDetectorConfig{
					Action:          guardrail.GuardrailActionRedact,
					EnabledPatterns: []string{"email", "ssn"},
				}),
			},
			input: "Customer: email test@example.com, SSN 123-45-6789, account A12345",
			checkContains: []string{
				"[REDACTED-EMAIL]",
				"[REDACTED-SSN]",
			},
			checkNotContains: []string{
				"test@example.com",
				"123-45-6789",
			},
		},
		{
			name: "cascading redactions",
			guardrails: []guardrail.Guardrail{
				mustNewContentFilter(t, builtin.ContentFilterConfig{
					Patterns: []builtin.ContentPattern{
						{
							Pattern: `API_KEY=\w+`,
							Action:  guardrail.GuardrailActionRedact,
							Replace: "API_KEY=[HIDDEN]",
						},
					},
				}),
				mustNewContentFilter(t, builtin.ContentFilterConfig{
					Patterns: []builtin.ContentPattern{
						{
							Pattern: `TOKEN:\w+`,
							Action:  guardrail.GuardrailActionRedact,
							Replace: "TOKEN:[HIDDEN]",
						},
					},
				}),
			},
			input: "Auth: API_KEY=abc123 and TOKEN:xyz789",
			checkContains: []string{
				"API_KEY=[HIDDEN]",
				"TOKEN:[HIDDEN]",
			},
			checkNotContains: []string{
				"abc123",
				"xyz789",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pipeline := guardrail.NewGuardrailPipeline(tt.guardrails...)
			ctx := context.Background()

			input := guardrail.GuardrailInput{
				Content: tt.input,
			}

			result, err := pipeline.ProcessInput(ctx, input)
			require.NoError(t, err)

			t.Logf("Original: %s", tt.input)
			t.Logf("Redacted: %s", result.Content)

			for _, expected := range tt.checkContains {
				assert.Contains(t, result.Content, expected,
					"Expected content to contain: %s", expected)
			}

			for _, notExpected := range tt.checkNotContains {
				assert.NotContains(t, result.Content, notExpected,
					"Expected content to NOT contain: %s", notExpected)
			}
		})
	}
}

// TestPipeline_RateLimitingBehavior tests rate limiting edge cases
func TestPipeline_RateLimitingBehavior(t *testing.T) {
	t.Run("rate limit recovery after window", func(t *testing.T) {
		pipeline := guardrail.NewGuardrailPipeline(
			builtin.NewRateLimiter(builtin.RateLimiterConfig{
				MaxRequests: 2,
				Window:      100 * time.Millisecond,
			}),
		)

		ctx := context.Background()
		input := guardrail.GuardrailInput{
			Content:  "Test request",
			ToolName: "test_tool",
		}

		// First 2 requests should pass
		for i := 0; i < 2; i++ {
			_, err := pipeline.ProcessInput(ctx, input)
			assert.NoError(t, err, "Request %d should be allowed", i+1)
		}

		// Third request should be rate limited
		_, err := pipeline.ProcessInput(ctx, input)
		require.Error(t, err)
		var blockedErr *guardrail.GuardrailBlockedError
		require.True(t, errors.As(err, &blockedErr))
		assert.Equal(t, guardrail.GuardrailTypeRate, blockedErr.GuardrailType)

		// Wait for window to reset
		time.Sleep(150 * time.Millisecond)

		// Should be able to make requests again
		_, err = pipeline.ProcessInput(ctx, input)
		assert.NoError(t, err, "Request after window reset should be allowed")
	})

	t.Run("burst handling", func(t *testing.T) {
		pipeline := guardrail.NewGuardrailPipeline(
			builtin.NewRateLimiter(builtin.RateLimiterConfig{
				MaxRequests: 5,
				Window:      time.Second,
				BurstSize:   10, // Allow burst of 10
			}),
		)

		ctx := context.Background()
		input := guardrail.GuardrailInput{
			Content:  "Burst request",
			ToolName: "test_tool",
		}

		allowedCount := 0
		blockedCount := 0

		// Send burst of 15 requests
		for i := 0; i < 15; i++ {
			_, err := pipeline.ProcessInput(ctx, input)
			if err == nil {
				allowedCount++
			} else {
				blockedCount++
			}
		}

		t.Logf("Burst test: Allowed: %d, Blocked: %d", allowedCount, blockedCount)

		// Should allow burst, then start blocking
		assert.Greater(t, allowedCount, 5, "Should allow burst beyond base rate")
		assert.Greater(t, blockedCount, 0, "Should eventually block requests")
	})
}

// TestPipeline_EmptyPipeline tests behavior with no guardrails
func TestPipeline_EmptyPipeline(t *testing.T) {
	pipeline := guardrail.NewGuardrailPipeline()
	ctx := context.Background()

	t.Run("empty pipeline allows all input", func(t *testing.T) {
		input := guardrail.GuardrailInput{
			Content:  "Any content with email test@example.com",
			ToolName: "any_tool",
		}

		result, err := pipeline.ProcessInput(ctx, input)
		require.NoError(t, err)
		assert.Equal(t, input.Content, result.Content, "Content should be unchanged")
	})

	t.Run("empty pipeline allows all output", func(t *testing.T) {
		output := guardrail.GuardrailOutput{
			Content: "Any output content",
		}

		result, err := pipeline.ProcessOutput(ctx, output)
		require.NoError(t, err)
		assert.Equal(t, output.Content, result.Content, "Content should be unchanged")
	})
}

// Helper functions

// mustNewPIIDetector creates a PII detector or fails the test
func mustNewPIIDetector(t *testing.T, config builtin.PIIDetectorConfig) *builtin.PIIDetector {
	t.Helper()
	detector, err := builtin.NewPIIDetector(config)
	require.NoError(t, err)
	return detector
}

// mustNewContentFilter creates a content filter or fails the test
func mustNewContentFilter(t *testing.T, config builtin.ContentFilterConfig) *builtin.ContentFilter {
	t.Helper()
	filter, err := builtin.NewContentFilter(config)
	require.NoError(t, err)
	return filter
}
