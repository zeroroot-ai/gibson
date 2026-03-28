package observability

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/graphrag/schema"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/orchestrator"
	"github.com/zero-day-ai/gibson/internal/types"
)

// TestNewDecisionLogWriterAdapter tests the adapter constructor.
func TestNewDecisionLogWriterAdapter(t *testing.T) {
	tests := []struct {
		name         string
		setupTracer  func() *MissionTracer
		setupMission func() *schema.Mission
		expectError  bool
		errorMsg     string
	}{
		{
			name: "valid inputs",
			setupTracer: func() *MissionTracer {
				server := newMockLangfuseServer()
				t.Cleanup(server.Close)
				tracer, err := NewMissionTracer(LangfuseConfig{
					Host:      server.URL,
					PublicKey: "test-public-key",
					SecretKey: "test-secret-key",
				})
				require.NoError(t, err)
				t.Cleanup(func() { tracer.Close() })
				return tracer
			},
			setupMission: func() *schema.Mission {
				return schema.NewMission(
					types.NewID(),
					"Test Mission",
					"Test mission description",
					"Test objective",
					"target-123",
					"yaml: test",
				)
			},
			expectError: false,
		},
		{
			name: "nil tracer",
			setupTracer: func() *MissionTracer {
				return nil
			},
			setupMission: func() *schema.Mission {
				return schema.NewMission(
					types.NewID(),
					"Test Mission",
					"Test mission description",
					"Test objective",
					"target-123",
					"yaml: test",
				)
			},
			expectError: true,
			errorMsg:    "tracer cannot be nil",
		},
		{
			name: "nil mission",
			setupTracer: func() *MissionTracer {
				server := newMockLangfuseServer()
				t.Cleanup(server.Close)
				tracer, err := NewMissionTracer(LangfuseConfig{
					Host:      server.URL,
					PublicKey: "test-public-key",
					SecretKey: "test-secret-key",
				})
				require.NoError(t, err)
				t.Cleanup(func() { tracer.Close() })
				return tracer
			},
			setupMission: func() *schema.Mission {
				return nil
			},
			expectError: true,
			errorMsg:    "mission cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracer := tt.setupTracer()
			mission := tt.setupMission()

			ctx := context.Background()
			adapter, err := NewDecisionLogWriterAdapter(ctx, tracer, mission)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, adapter)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, adapter)
				assert.NotNil(t, adapter.tracer)
				assert.NotNil(t, adapter.trace)
				assert.NotNil(t, adapter.agentLogs)
				assert.NotNil(t, adapter.statistics)
				assert.Equal(t, mission.ID.String(), adapter.missionID)
				assert.Equal(t, mission.Name, adapter.missionName)
			}
		})
	}
}

// TestDecisionLogAdapterLogDecision tests decision logging through the adapter.
func TestDecisionLogAdapterLogDecision(t *testing.T) {
	tests := []struct {
		name          string
		setupDecision func(missionID string) *orchestrator.Decision
		setupResult   func() *orchestrator.ThinkResult
		iteration     int
		missionID     string
		expectLogged  bool
		checkEvents   func(t *testing.T, events []map[string]any)
	}{
		{
			name: "valid decision with execute_agent",
			setupDecision: func(missionID string) *orchestrator.Decision {
				return &orchestrator.Decision{
					Reasoning:    "Execute the reconnaissance agent",
					Action:       orchestrator.ActionExecuteAgent,
					TargetNodeID: "node-1",
					Confidence:   0.95,
				}
			},
			setupResult: func() *orchestrator.ThinkResult {
				return &orchestrator.ThinkResult{
					PromptTokens:     100,
					CompletionTokens: 50,
					TotalTokens:      150,
					Latency:          250 * time.Millisecond,
					Model:            "gpt-4",
					RawResponse:      `{"action":"execute_agent","node":"node-1"}`,
				}
			},
			iteration:    1,
			expectLogged: true,
			checkEvents: func(t *testing.T, events []map[string]any) {
				// Should have generation-create event (trace-create was cleared by server.reset())
				require.GreaterOrEqual(t, len(events), 1)

				// Find generation-create event
				var genEvent map[string]any
				for _, event := range events {
					if event["type"] == "generation-create" {
						genEvent = event
						break
					}
				}
				require.NotNil(t, genEvent, "should have generation-create event")

				body, ok := genEvent["body"].(map[string]any)
				require.True(t, ok)
				assert.Contains(t, body["name"], "orchestrator-decision")
				assert.Equal(t, float64(100), body["promptTokens"])
				assert.Equal(t, float64(50), body["completionTokens"])
				assert.Equal(t, "gpt-4", body["model"])

				metadata, ok := body["metadata"].(map[string]any)
				require.True(t, ok)
				assert.Equal(t, float64(1), metadata["iteration"])
				assert.Equal(t, "execute_agent", metadata["action"])
			},
		},
		{
			name: "nil decision",
			setupDecision: func(missionID string) *orchestrator.Decision {
				return nil
			},
			setupResult: func() *orchestrator.ThinkResult {
				return &orchestrator.ThinkResult{
					TotalTokens: 150,
				}
			},
			iteration:    1,
			expectLogged: false,
			checkEvents: func(t *testing.T, events []map[string]any) {
				// Should only have trace-create, no generation
				for _, event := range events {
					assert.NotEqual(t, "generation-create", event["type"],
						"should not log generation for nil decision")
				}
			},
		},
		{
			name: "nil result",
			setupDecision: func(missionID string) *orchestrator.Decision {
				return &orchestrator.Decision{
					Reasoning:    "Test decision",
					Action:       orchestrator.ActionExecuteAgent,
					TargetNodeID: "node-1",
					Confidence:   0.95,
				}
			},
			setupResult: func() *orchestrator.ThinkResult {
				return nil
			},
			iteration:    1,
			expectLogged: false,
			checkEvents: func(t *testing.T, events []map[string]any) {
				// Should only have trace-create, no generation
				for _, event := range events {
					assert.NotEqual(t, "generation-create", event["type"],
						"should not log generation for nil result")
				}
			},
		},
		{
			name: "mission ID mismatch",
			setupDecision: func(missionID string) *orchestrator.Decision {
				return &orchestrator.Decision{
					Reasoning:    "Test decision",
					Action:       orchestrator.ActionExecuteAgent,
					TargetNodeID: "node-1",
					Confidence:   0.95,
				}
			},
			setupResult: func() *orchestrator.ThinkResult {
				return &orchestrator.ThinkResult{
					TotalTokens: 150,
				}
			},
			iteration:    1,
			missionID:    "wrong-mission-id",
			expectLogged: false,
			checkEvents: func(t *testing.T, events []map[string]any) {
				// Should only have trace-create, no generation
				for _, event := range events {
					assert.NotEqual(t, "generation-create", event["type"],
						"should not log generation for mismatched mission ID")
				}
			},
		},
		{
			name: "decision with modifications",
			setupDecision: func(missionID string) *orchestrator.Decision {
				return &orchestrator.Decision{
					Reasoning:    "Modify and execute",
					Action:       orchestrator.ActionModifyParams,
					TargetNodeID: "node-1",
					Confidence:   0.85,
					Modifications: map[string]interface{}{
						"timeout": 600,
						"retries": 3,
					},
				}
			},
			setupResult: func() *orchestrator.ThinkResult {
				return &orchestrator.ThinkResult{
					PromptTokens:     200,
					CompletionTokens: 100,
					TotalTokens:      300,
					Latency:          500 * time.Millisecond,
					Model:            "gpt-4",
					RawResponse:      `{"action":"modify_params"}`,
				}
			},
			iteration:    2,
			expectLogged: true,
			checkEvents: func(t *testing.T, events []map[string]any) {
				// Find generation-create event
				var genEvent map[string]any
				for _, event := range events {
					if event["type"] == "generation-create" {
						genEvent = event
						break
					}
				}
				require.NotNil(t, genEvent)

				body, ok := genEvent["body"].(map[string]any)
				require.True(t, ok)

				metadata, ok := body["metadata"].(map[string]any)
				require.True(t, ok)
				assert.Equal(t, "modify_params", metadata["action"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newMockLangfuseServer()
			defer server.Close()

			tracer, err := NewMissionTracer(LangfuseConfig{
				Host:      server.URL,
				PublicKey: "test-public-key",
				SecretKey: "test-secret-key",
			})
			require.NoError(t, err)
			defer tracer.Close()

			missionID := types.NewID()
			mission := schema.NewMission(
				missionID,
				"Test Mission",
				"Test mission description",
				"Test objective",
				"target-123",
				"yaml: test",
			)

			ctx := context.Background()
			adapter, err := NewDecisionLogWriterAdapter(ctx, tracer, mission)
			require.NoError(t, err)

			// Clear events from trace creation
			server.reset()

			// Set up test data
			testMissionID := tt.missionID
			if testMissionID == "" {
				testMissionID = missionID.String()
			}
			decision := tt.setupDecision(testMissionID)
			result := tt.setupResult()

			// Log decision (fire-and-forget, always returns nil)
			err = adapter.LogDecision(ctx, decision, result, tt.iteration, testMissionID)
			assert.NoError(t, err, "LogDecision should never return error (fire-and-forget)")

			// Wait for async logging
			time.Sleep(50 * time.Millisecond)

			// Check events
			events := server.getEvents()
			tt.checkEvents(t, events)

			// Verify statistics update
			if tt.expectLogged && decision != nil && result != nil {
				adapter.mu.RLock()
				assert.Greater(t, adapter.statistics.totalDecisions, 0)
				assert.Greater(t, adapter.statistics.totalTokens, 0)
				adapter.mu.RUnlock()
			}
		})
	}
}

// TestLogAction tests action result logging and routing.
func TestLogAction(t *testing.T) {
	tests := []struct {
		name         string
		setupAction  func(missionID types.ID) *orchestrator.ActionResult
		iteration    int
		missionID    string
		expectLogged bool
		checkEvents  func(t *testing.T, events []map[string]any)
	}{
		{
			name: "execute_agent action",
			setupAction: func(missionID types.ID) *orchestrator.ActionResult {
				exec := schema.NewAgentExecution("workflow-node-1", missionID)
				exec.WithConfig(map[string]any{"timeout": 300})
				exec.WithResult(map[string]any{"status": "success"})
				now := time.Now()
				exec.CompletedAt = &now
				exec.Status = schema.ExecutionStatusCompleted

				return &orchestrator.ActionResult{
					Action:         orchestrator.ActionExecuteAgent,
					AgentExecution: exec,
					Metadata: map[string]interface{}{
						"agent_name": "recon-agent",
					},
				}
			},
			iteration:    1,
			expectLogged: true,
			checkEvents: func(t *testing.T, events []map[string]any) {
				// Should have span-create for agent execution
				var spanEvent map[string]any
				for _, event := range events {
					if event["type"] == "span-create" {
						body, ok := event["body"].(map[string]any)
						if ok && body["name"] != nil {
							name := body["name"].(string)
							if len(name) > 15 && name[:15] == "agent-execution" {
								spanEvent = event
								break
							}
						}
					}
				}
				require.NotNil(t, spanEvent, "should have agent-execution span")

				body, ok := spanEvent["body"].(map[string]any)
				require.True(t, ok)
				assert.Contains(t, body["name"], "agent-execution")
				assert.Contains(t, body["name"], "recon-agent")

				metadata, ok := body["metadata"].(map[string]any)
				require.True(t, ok)
				assert.Equal(t, "recon-agent", metadata["agent_name"])
			},
		},
		{
			name: "spawn_agent action",
			setupAction: func(missionID types.ID) *orchestrator.ActionResult {
				newNode := &schema.WorkflowNode{
					ID:        types.NewID(),
					AgentName: "exploit-agent",
				}

				return &orchestrator.ActionResult{
					Action:  orchestrator.ActionSpawnAgent,
					NewNode: newNode,
				}
			},
			iteration:    1,
			expectLogged: false, // Spawn doesn't create separate spans
			checkEvents: func(t *testing.T, events []map[string]any) {
				// Spawn actions are logged in metadata, not as separate spans
				// Just verify no unexpected events
			},
		},
		{
			name: "complete action",
			setupAction: func(missionID types.ID) *orchestrator.ActionResult {
				return &orchestrator.ActionResult{
					Action:     orchestrator.ActionComplete,
					IsTerminal: true,
				}
			},
			iteration:    5,
			expectLogged: false, // Complete is logged in Close()
			checkEvents: func(t *testing.T, events []map[string]any) {
				// Complete actions are handled by Close(), not LogAction
			},
		},
		{
			name: "skip action",
			setupAction: func(missionID types.ID) *orchestrator.ActionResult {
				return &orchestrator.ActionResult{
					Action:       orchestrator.ActionSkipAgent,
					TargetNodeID: "node-1",
				}
			},
			iteration:    1,
			expectLogged: false, // Skip doesn't create spans
			checkEvents: func(t *testing.T, events []map[string]any) {
				// Skip actions don't create separate spans
			},
		},
		{
			name: "nil action",
			setupAction: func(missionID types.ID) *orchestrator.ActionResult {
				return nil
			},
			iteration:    1,
			expectLogged: false,
			checkEvents: func(t *testing.T, events []map[string]any) {
				// No events expected for nil action
			},
		},
		{
			name: "mission ID mismatch",
			setupAction: func(missionID types.ID) *orchestrator.ActionResult {
				exec := schema.NewAgentExecution("workflow-node-1", missionID)
				return &orchestrator.ActionResult{
					Action:         orchestrator.ActionExecuteAgent,
					AgentExecution: exec,
				}
			},
			iteration:    1,
			missionID:    "wrong-mission-id",
			expectLogged: false,
			checkEvents: func(t *testing.T, events []map[string]any) {
				// Should not log for mismatched mission ID
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newMockLangfuseServer()
			defer server.Close()

			tracer, err := NewMissionTracer(LangfuseConfig{
				Host:      server.URL,
				PublicKey: "test-public-key",
				SecretKey: "test-secret-key",
			})
			require.NoError(t, err)
			defer tracer.Close()

			missionID := types.NewID()
			mission := schema.NewMission(
				missionID,
				"Test Mission",
				"Test mission description",
				"Test objective",
				"target-123",
				"yaml: test",
			)

			ctx := context.Background()
			adapter, err := NewDecisionLogWriterAdapter(ctx, tracer, mission)
			require.NoError(t, err)

			// Clear events from trace creation
			server.reset()

			// Set up test data
			testMissionID := tt.missionID
			if testMissionID == "" {
				testMissionID = missionID.String()
			}
			action := tt.setupAction(missionID)

			// Log action (fire-and-forget, always returns nil)
			err = adapter.LogAction(ctx, action, tt.iteration, testMissionID)
			assert.NoError(t, err, "LogAction should never return error (fire-and-forget)")

			// Wait for async logging
			time.Sleep(50 * time.Millisecond)

			// Check events
			events := server.getEvents()
			tt.checkEvents(t, events)

			// Verify statistics update
			if tt.expectLogged && action != nil && action.Action == orchestrator.ActionExecuteAgent {
				adapter.mu.RLock()
				assert.Greater(t, adapter.statistics.totalExecutions, 0)
				adapter.mu.RUnlock()
			}
		})
	}
}

// TestClose tests adapter close and summary generation.
func TestClose(t *testing.T) {
	tests := []struct {
		name         string
		setupAdapter func(adapter *DecisionLogWriterAdapter)
		summary      *MissionTraceSummary
		checkSummary func(t *testing.T, events []map[string]any)
	}{
		{
			name: "close with provided summary",
			setupAdapter: func(adapter *DecisionLogWriterAdapter) {
				adapter.mu.Lock()
				adapter.statistics.totalDecisions = 10
				adapter.statistics.totalExecutions = 8
				adapter.statistics.totalTokens = 5000
				adapter.mu.Unlock()
			},
			summary: &MissionTraceSummary{
				Status:          string(schema.MissionStatusCompleted),
				TotalDecisions:  0, // Should be overwritten
				TotalExecutions: 0, // Should be overwritten
				TotalTokens:     0, // Should be overwritten
				TotalCost:       0.50,
				Duration:        0, // Should be calculated
				Outcome:         "Mission completed successfully",
				GraphStats: map[string]int{
					"nodes":    100,
					"findings": 5,
				},
			},
			checkSummary: func(t *testing.T, events []map[string]any) {
				// Find mission-complete span
				var completeEvent map[string]any
				for _, event := range events {
					if event["type"] == "span-create" {
						body, ok := event["body"].(map[string]any)
						if ok && body["name"] == "mission-complete" {
							completeEvent = event
							break
						}
					}
				}
				require.NotNil(t, completeEvent, "should have mission-complete span")

				body, ok := completeEvent["body"].(map[string]any)
				require.True(t, ok)

				metadata, ok := body["metadata"].(map[string]any)
				require.True(t, ok)
				assert.Equal(t, float64(10), metadata["total_decisions"])
				assert.Equal(t, float64(8), metadata["total_executions"])
				assert.Equal(t, float64(5000), metadata["total_tokens"])
				assert.Equal(t, 0.50, metadata["total_cost_usd"])
			},
		},
		{
			name: "close with nil summary",
			setupAdapter: func(adapter *DecisionLogWriterAdapter) {
				adapter.mu.Lock()
				adapter.statistics.totalDecisions = 5
				adapter.statistics.totalExecutions = 4
				adapter.statistics.totalTokens = 2500
				adapter.mu.Unlock()
			},
			summary: nil,
			checkSummary: func(t *testing.T, events []map[string]any) {
				// Should use default summary
				var completeEvent map[string]any
				for _, event := range events {
					if event["type"] == "span-create" {
						body, ok := event["body"].(map[string]any)
						if ok && body["name"] == "mission-complete" {
							completeEvent = event
							break
						}
					}
				}
				require.NotNil(t, completeEvent)

				body, ok := completeEvent["body"].(map[string]any)
				require.True(t, ok)

				metadata, ok := body["metadata"].(map[string]any)
				require.True(t, ok)
				assert.Equal(t, float64(5), metadata["total_decisions"])
				assert.Equal(t, float64(4), metadata["total_executions"])
				assert.Equal(t, float64(2500), metadata["total_tokens"])
			},
		},
		{
			name: "close with empty statistics",
			setupAdapter: func(adapter *DecisionLogWriterAdapter) {
				// No statistics
			},
			summary: nil,
			checkSummary: func(t *testing.T, events []map[string]any) {
				// Should still create complete event with zero stats
				var completeEvent map[string]any
				for _, event := range events {
					if event["type"] == "span-create" {
						body, ok := event["body"].(map[string]any)
						if ok && body["name"] == "mission-complete" {
							completeEvent = event
							break
						}
					}
				}
				require.NotNil(t, completeEvent)

				body, ok := completeEvent["body"].(map[string]any)
				require.True(t, ok)

				metadata, ok := body["metadata"].(map[string]any)
				require.True(t, ok)
				assert.Equal(t, float64(0), metadata["total_decisions"])
				assert.Equal(t, float64(0), metadata["total_executions"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newMockLangfuseServer()
			defer server.Close()

			tracer, err := NewMissionTracer(LangfuseConfig{
				Host:      server.URL,
				PublicKey: "test-public-key",
				SecretKey: "test-secret-key",
			})
			require.NoError(t, err)
			defer tracer.Close()

			missionID := types.NewID()
			mission := schema.NewMission(
				missionID,
				"Test Mission",
				"Test mission description",
				"Test objective",
				"target-123",
				"yaml: test",
			)

			ctx := context.Background()
			adapter, err := NewDecisionLogWriterAdapter(ctx, tracer, mission)
			require.NoError(t, err)

			// Set up adapter state
			tt.setupAdapter(adapter)

			// Clear events from trace creation
			server.reset()

			// Close adapter (fire-and-forget, always returns nil)
			err = adapter.Close(ctx, tt.summary)
			assert.NoError(t, err, "Close should never return error (fire-and-forget)")

			// Wait for async logging
			time.Sleep(50 * time.Millisecond)

			// Check summary
			events := server.getEvents()
			tt.checkSummary(t, events)
		})
	}
}

// TestDecisionLogAdapterConcurrentAccess tests thread-safety of the adapter.
func TestDecisionLogAdapterConcurrentAccess(t *testing.T) {
	server := newMockLangfuseServer()
	defer server.Close()

	tracer, err := NewMissionTracer(LangfuseConfig{
		Host:      server.URL,
		PublicKey: "test-public-key",
		SecretKey: "test-secret-key",
	})
	require.NoError(t, err)
	defer tracer.Close()

	missionID := types.NewID()
	mission := schema.NewMission(
		missionID,
		"Concurrent Test",
		"Test concurrent access",
		"Test objective",
		"target-123",
		"yaml: test",
	)

	ctx := context.Background()
	adapter, err := NewDecisionLogWriterAdapter(ctx, tracer, mission)
	require.NoError(t, err)

	numGoroutines := 20
	var wg sync.WaitGroup

	// Concurrently log decisions
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(iteration int) {
			defer wg.Done()

			decision := &orchestrator.Decision{
				Reasoning:    fmt.Sprintf("Decision %d", iteration),
				Action:       orchestrator.ActionExecuteAgent,
				TargetNodeID: fmt.Sprintf("node-%d", iteration),
				Confidence:   0.9,
			}

			result := &orchestrator.ThinkResult{
				PromptTokens:     100,
				CompletionTokens: 50,
				TotalTokens:      150,
				Latency:          100 * time.Millisecond,
				Model:            "gpt-4",
				RawResponse:      fmt.Sprintf(`{"action":"execute_agent","iteration":%d}`, iteration),
			}

			err := adapter.LogDecision(ctx, decision, result, iteration, missionID.String())
			assert.NoError(t, err)
		}(i)
	}

	// Concurrently log actions
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(iteration int) {
			defer wg.Done()

			exec := schema.NewAgentExecution(fmt.Sprintf("node-%d", iteration), missionID)
			exec.WithConfig(map[string]any{"timeout": 300})
			now := time.Now()
			exec.CompletedAt = &now
			exec.Status = schema.ExecutionStatusCompleted

			action := &orchestrator.ActionResult{
				Action:         orchestrator.ActionExecuteAgent,
				AgentExecution: exec,
				Metadata: map[string]interface{}{
					"agent_name": fmt.Sprintf("agent-%d", iteration),
				},
			}

			err := adapter.LogAction(ctx, action, iteration, missionID.String())
			assert.NoError(t, err)
		}(i)
	}

	wg.Wait()

	// Verify statistics are consistent
	adapter.mu.RLock()
	assert.Equal(t, numGoroutines, adapter.statistics.totalDecisions)
	assert.Equal(t, numGoroutines, adapter.statistics.totalExecutions)
	assert.Equal(t, numGoroutines*150, adapter.statistics.totalTokens)
	adapter.mu.RUnlock()

	// Close should not panic
	err = adapter.Close(ctx, nil)
	assert.NoError(t, err)
}

// TestAdapterAgentLogTracking tests that agent logs are properly stored for tool execution linking.
func TestAdapterAgentLogTracking(t *testing.T) {
	server := newMockLangfuseServer()
	defer server.Close()

	tracer, err := NewMissionTracer(LangfuseConfig{
		Host:      server.URL,
		PublicKey: "test-public-key",
		SecretKey: "test-secret-key",
	})
	require.NoError(t, err)
	defer tracer.Close()

	missionID := types.NewID()
	mission := schema.NewMission(
		missionID,
		"Test Mission",
		"Test mission description",
		"Test objective",
		"target-123",
		"yaml: test",
	)

	ctx := context.Background()
	adapter, err := NewDecisionLogWriterAdapter(ctx, tracer, mission)
	require.NoError(t, err)

	// Create multiple agent executions
	execID1 := types.NewID()
	exec1 := schema.NewAgentExecution("node-1", missionID)
	exec1.ID = execID1

	execID2 := types.NewID()
	exec2 := schema.NewAgentExecution("node-2", missionID)
	exec2.ID = execID2

	action1 := &orchestrator.ActionResult{
		Action:         orchestrator.ActionExecuteAgent,
		AgentExecution: exec1,
		Metadata: map[string]interface{}{
			"agent_name": "recon-agent",
		},
	}

	action2 := &orchestrator.ActionResult{
		Action:         orchestrator.ActionExecuteAgent,
		AgentExecution: exec2,
		Metadata: map[string]interface{}{
			"agent_name": "exploit-agent",
		},
	}

	// Log actions
	err = adapter.LogAction(ctx, action1, 1, missionID.String())
	require.NoError(t, err)

	err = adapter.LogAction(ctx, action2, 2, missionID.String())
	require.NoError(t, err)

	// Verify agent logs are stored
	adapter.mu.RLock()
	assert.Len(t, adapter.agentLogs, 2)
	assert.Contains(t, adapter.agentLogs, execID1.String())
	assert.Contains(t, adapter.agentLogs, execID2.String())

	log1 := adapter.agentLogs[execID1.String()]
	assert.Equal(t, "recon-agent", log1.AgentName)
	assert.Equal(t, execID1, log1.Execution.ID)

	log2 := adapter.agentLogs[execID2.String()]
	assert.Equal(t, "exploit-agent", log2.AgentName)
	assert.Equal(t, execID2, log2.Execution.ID)
	adapter.mu.RUnlock()
}

// TestFireAndForgetErrorHandling tests that errors don't propagate to caller.
func TestFireAndForgetErrorHandling(t *testing.T) {
	// Create a server that will close immediately to cause errors
	server := newMockLangfuseServer()
	serverURL := server.URL
	server.Close() // Close immediately

	tracer, err := NewMissionTracer(LangfuseConfig{
		Host:      serverURL,
		PublicKey: "test-public-key",
		SecretKey: "test-secret-key",
	})
	require.NoError(t, err)
	defer tracer.Close()

	missionID := types.NewID()
	mission := schema.NewMission(
		missionID,
		"Test Mission",
		"Test mission description",
		"Test objective",
		"target-123",
		"yaml: test",
	)

	ctx := context.Background()
	// This should fail to start trace, but that's expected
	adapter, err := NewDecisionLogWriterAdapter(ctx, tracer, mission)
	// Note: Constructor returns error, but subsequent operations don't
	if adapter == nil {
		// If adapter creation failed, skip rest of test
		t.Skip("Adapter creation failed (expected), skipping fire-and-forget test")
		return
	}

	// All these operations should return nil even though Langfuse is unavailable
	decision := &orchestrator.Decision{
		Reasoning:    "Test decision",
		Action:       orchestrator.ActionExecuteAgent,
		TargetNodeID: "node-1",
		Confidence:   0.95,
	}

	result := &orchestrator.ThinkResult{
		TotalTokens: 150,
		Model:       "gpt-4",
		RawResponse: `{"action":"execute_agent"}`,
	}

	err = adapter.LogDecision(ctx, decision, result, 1, missionID.String())
	assert.NoError(t, err, "LogDecision should not return error (fire-and-forget)")

	exec := schema.NewAgentExecution("node-1", missionID)
	action := &orchestrator.ActionResult{
		Action:         orchestrator.ActionExecuteAgent,
		AgentExecution: exec,
		Metadata: map[string]interface{}{
			"agent_name": "test-agent",
		},
	}

	err = adapter.LogAction(ctx, action, 1, missionID.String())
	assert.NoError(t, err, "LogAction should not return error (fire-and-forget)")

	err = adapter.Close(ctx, nil)
	assert.NoError(t, err, "Close should not return error (fire-and-forget)")
}

// TestAdapter_BuildFullPrompt tests the buildFullPrompt helper function.
func TestAdapter_BuildFullPrompt(t *testing.T) {
	adapter := &DecisionLogWriterAdapter{
		missionID: "test-mission",
	}

	tests := []struct {
		name           string
		result         *orchestrator.ThinkResult
		expectedOutput []string // Strings that should be in output
		shouldBeEmpty  bool
	}{
		{
			name: "full prompt with system and user",
			result: &orchestrator.ThinkResult{
				SystemPrompt: "You are an orchestrator for security testing",
				UserPrompt:   "Analyze the current mission state and decide next action",
			},
			expectedOutput: []string{
				"[SYSTEM]:",
				"You are an orchestrator for security testing",
				"[USER]:",
				"Analyze the current mission state and decide next action",
				"---",
			},
		},
		{
			name: "only system prompt",
			result: &orchestrator.ThinkResult{
				SystemPrompt: "System instructions here",
				UserPrompt:   "",
			},
			expectedOutput: []string{
				"[SYSTEM]:",
				"System instructions here",
				"---",
			},
		},
		{
			name: "only user prompt",
			result: &orchestrator.ThinkResult{
				SystemPrompt: "",
				UserPrompt:   "User query here",
			},
			expectedOutput: []string{
				"[USER]:",
				"User query here",
			},
		},
		{
			name:          "nil result",
			result:        nil,
			shouldBeEmpty: true,
		},
		{
			name: "empty result",
			result: &orchestrator.ThinkResult{
				SystemPrompt: "",
				UserPrompt:   "",
			},
			shouldBeEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := adapter.buildFullPrompt(tt.result)

			if tt.shouldBeEmpty {
				assert.Empty(t, output, "Output should be empty for nil/empty result")
			} else {
				for _, expected := range tt.expectedOutput {
					assert.Contains(t, output, expected, "Output should contain expected string")
				}
			}
		})
	}
}

// TestAdapter_ConvertMessages tests the convertMessages helper function.
func TestAdapter_ConvertMessages(t *testing.T) {
	adapter := &DecisionLogWriterAdapter{
		missionID: "test-mission",
	}

	tests := []struct {
		name     string
		messages []llm.Message
		expected []MessageLog
	}{
		{
			name: "complete message with all fields",
			messages: []llm.Message{
				{
					Role:       llm.RoleSystem,
					Content:    "System message content",
					Name:       "system",
					ToolCallID: "call-123",
				},
			},
			expected: []MessageLog{
				{
					Role:       "system",
					Content:    "System message content",
					Name:       "system",
					ToolCallID: "call-123",
				},
			},
		},
		{
			name: "multiple messages with different roles",
			messages: []llm.Message{
				{
					Role:    llm.RoleSystem,
					Content: "System prompt",
				},
				{
					Role:    llm.RoleUser,
					Content: "User query",
				},
				{
					Role:    llm.RoleAssistant,
					Content: "Assistant response",
				},
			},
			expected: []MessageLog{
				{
					Role:    "system",
					Content: "System prompt",
				},
				{
					Role:    "user",
					Content: "User query",
				},
				{
					Role:    "assistant",
					Content: "Assistant response",
				},
			},
		},
		{
			name:     "nil messages",
			messages: nil,
			expected: nil,
		},
		{
			name:     "empty messages",
			messages: []llm.Message{},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := adapter.convertMessages(tt.messages)

			if tt.expected == nil {
				assert.Nil(t, result, "Result should be nil for nil/empty input")
			} else {
				require.Len(t, result, len(tt.expected), "Result length should match expected")
				for i, expectedLog := range tt.expected {
					assert.Equal(t, expectedLog.Role, result[i].Role, "Role should match")
					assert.Equal(t, expectedLog.Content, result[i].Content, "Content should match")
					assert.Equal(t, expectedLog.Name, result[i].Name, "Name should match")
					assert.Equal(t, expectedLog.ToolCallID, result[i].ToolCallID, "ToolCallID should match")
				}
			}
		})
	}
}

// TestAdapter_BuildRequestMetadata tests the buildRequestMetadata helper function.
func TestAdapter_BuildRequestMetadata(t *testing.T) {
	adapter := &DecisionLogWriterAdapter{
		missionID: "test-mission",
	}

	tests := []struct {
		name     string
		result   *orchestrator.ThinkResult
		expected *RequestMetadata
	}{
		{
			name: "complete request config",
			result: &orchestrator.ThinkResult{
				Model: "gpt-4",
				RequestConfig: orchestrator.RequestConfig{
					Temperature: 0.7,
					MaxTokens:   2000,
					TopP:        0.9,
					SlotName:    "primary",
				},
			},
			expected: &RequestMetadata{
				Model:       "gpt-4",
				Temperature: 0.7,
				MaxTokens:   2000,
				TopP:        0.9,
				SlotName:    "primary",
				Provider:    "", // Provider not available in ThinkResult
			},
		},
		{
			name: "zero values in config",
			result: &orchestrator.ThinkResult{
				Model: "claude-3",
				RequestConfig: orchestrator.RequestConfig{
					Temperature: 0.0,
					MaxTokens:   0,
					TopP:        0.0,
					SlotName:    "",
				},
			},
			expected: &RequestMetadata{
				Model:       "claude-3",
				Temperature: 0.0,
				MaxTokens:   0,
				TopP:        0.0,
				SlotName:    "",
				Provider:    "",
			},
		},
		{
			name:     "nil result",
			result:   nil,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := adapter.buildRequestMetadata(tt.result)

			if tt.expected == nil {
				assert.Nil(t, result, "Result should be nil for nil input")
			} else {
				require.NotNil(t, result, "Result should not be nil")
				assert.Equal(t, tt.expected.Model, result.Model, "Model should match")
				assert.Equal(t, tt.expected.Temperature, result.Temperature, "Temperature should match")
				assert.Equal(t, tt.expected.MaxTokens, result.MaxTokens, "MaxTokens should match")
				assert.Equal(t, tt.expected.TopP, result.TopP, "TopP should match")
				assert.Equal(t, tt.expected.SlotName, result.SlotName, "SlotName should match")
				assert.Equal(t, tt.expected.Provider, result.Provider, "Provider should be empty")
			}
		})
	}
}
