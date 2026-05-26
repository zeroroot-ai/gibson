package schema

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/types"
)

func TestExecutionStatus_Validate(t *testing.T) {
	tests := []struct {
		name    string
		status  ExecutionStatus
		wantErr bool
	}{
		{
			name:    "valid running status",
			status:  ExecutionStatusRunning,
			wantErr: false,
		},
		{
			name:    "valid completed status",
			status:  ExecutionStatusCompleted,
			wantErr: false,
		},
		{
			name:    "valid failed status",
			status:  ExecutionStatusFailed,
			wantErr: false,
		},
		{
			name:    "invalid status",
			status:  ExecutionStatus("invalid"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.status.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewAgentExecution(t *testing.T) {
	missionNodeID := "agent_1"
	missionID := types.NewID()

	exec := NewAgentExecution(missionNodeID, missionID)

	assert.NotEmpty(t, exec.ID)
	assert.Equal(t, missionNodeID, exec.MissionNodeID)
	assert.Equal(t, missionID, exec.MissionID)
	assert.Equal(t, ExecutionStatusRunning, exec.Status)
	assert.Equal(t, 1, exec.Attempt)
	assert.NotNil(t, exec.ConfigUsed)
	assert.NotNil(t, exec.Result)
	assert.False(t, exec.StartedAt.IsZero())
	assert.False(t, exec.CreatedAt.IsZero())
	assert.False(t, exec.UpdatedAt.IsZero())
	assert.Nil(t, exec.CompletedAt)
}

func TestAgentExecution_MethodChaining(t *testing.T) {
	missionID := types.NewID()
	config := map[string]any{"timeout": 30}
	result := map[string]any{"status": "success"}

	exec := NewAgentExecution("agent_1", missionID).
		WithConfig(config).
		WithResult(result).
		WithAttempt(2).
		WithLangfuseSpanID("span_123")

	assert.Equal(t, config, exec.ConfigUsed)
	assert.Equal(t, result, exec.Result)
	assert.Equal(t, 2, exec.Attempt)
	assert.Equal(t, "span_123", exec.LangfuseSpanID)
}

func TestAgentExecution_MarkCompleted(t *testing.T) {
	exec := NewAgentExecution("agent_1", types.NewID())

	// Sleep briefly to ensure CompletedAt differs from StartedAt
	time.Sleep(1 * time.Millisecond)

	exec.MarkCompleted()

	assert.Equal(t, ExecutionStatusCompleted, exec.Status)
	assert.NotNil(t, exec.CompletedAt)
	assert.True(t, exec.CompletedAt.After(exec.StartedAt))
	assert.True(t, exec.IsComplete())
}

func TestAgentExecution_MarkFailed(t *testing.T) {
	exec := NewAgentExecution("agent_1", types.NewID())
	errMsg := "connection timeout"

	// Sleep briefly to ensure CompletedAt differs from StartedAt
	time.Sleep(1 * time.Millisecond)

	exec.MarkFailed(errMsg)

	assert.Equal(t, ExecutionStatusFailed, exec.Status)
	assert.Equal(t, errMsg, exec.Error)
	assert.NotNil(t, exec.CompletedAt)
	assert.True(t, exec.CompletedAt.After(exec.StartedAt))
	assert.True(t, exec.IsComplete())
}

func TestAgentExecution_MarkFailedWithDetails(t *testing.T) {
	exec := NewAgentExecution("agent_1", types.NewID())
	errMsg := "nmap binary not found"
	errorClass := "infrastructure"
	errorCode := "BINARY_NOT_FOUND"

	// Create mock recovery hints as []map[string]any
	hints := []map[string]any{
		{
			"strategy":    "use_alternative_tool",
			"alternative": "masscan",
			"reason":      "masscan can perform similar port scanning",
			"confidence":  0.8,
			"priority":    1,
		},
		{
			"strategy":    "use_alternative_tool",
			"alternative": "netcat",
			"reason":      "nc can probe individual ports",
			"confidence":  0.5,
			"priority":    2,
		},
	}

	// Sleep briefly to ensure CompletedAt differs from StartedAt
	time.Sleep(1 * time.Millisecond)

	exec.MarkFailedWithDetails(errMsg, errorClass, errorCode, hints)

	assert.Equal(t, ExecutionStatusFailed, exec.Status)
	assert.Equal(t, errMsg, exec.Error)
	assert.Equal(t, errorClass, exec.ErrorClass)
	assert.Equal(t, errorCode, exec.ErrorCode)
	assert.NotNil(t, exec.RecoveryHints)
	assert.Len(t, exec.RecoveryHints, 2)
	assert.Equal(t, "use_alternative_tool", exec.RecoveryHints[0]["strategy"])
	assert.Equal(t, "masscan", exec.RecoveryHints[0]["alternative"])
	assert.NotNil(t, exec.CompletedAt)
	assert.True(t, exec.CompletedAt.After(exec.StartedAt))
	assert.True(t, exec.IsComplete())
}

func TestAgentExecution_MarkFailedWithDetails_NilHints(t *testing.T) {
	exec := NewAgentExecution("agent_1", types.NewID())
	errMsg := "unknown error"
	errorClass := "transient"
	errorCode := "EXECUTION_FAILED"

	// Sleep briefly to ensure CompletedAt differs from StartedAt
	time.Sleep(1 * time.Millisecond)

	exec.MarkFailedWithDetails(errMsg, errorClass, errorCode, nil)

	assert.Equal(t, ExecutionStatusFailed, exec.Status)
	assert.Equal(t, errMsg, exec.Error)
	assert.Equal(t, errorClass, exec.ErrorClass)
	assert.Equal(t, errorCode, exec.ErrorCode)
	assert.Nil(t, exec.RecoveryHints)
	assert.NotNil(t, exec.CompletedAt)
	assert.True(t, exec.IsComplete())
}

func TestAgentExecution_Duration(t *testing.T) {
	exec := NewAgentExecution("agent_1", types.NewID())

	// Duration should be 0 when not completed
	assert.Equal(t, time.Duration(0), exec.Duration())

	// Sleep and complete
	time.Sleep(10 * time.Millisecond)
	exec.MarkCompleted()

	// Duration should be > 0 after completion
	assert.Greater(t, exec.Duration(), time.Duration(0))
	assert.GreaterOrEqual(t, exec.Duration(), 10*time.Millisecond)
}

func TestAgentExecution_Validate(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() *AgentExecution
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid execution",
			setup: func() *AgentExecution {
				return NewAgentExecution("agent_1", types.NewID())
			},
			wantErr: false,
		},
		{
			name: "empty mission node ID",
			setup: func() *AgentExecution {
				exec := NewAgentExecution("agent_1", types.NewID())
				exec.MissionNodeID = ""
				return exec
			},
			wantErr: true,
			errMsg:  "mission_node_id is required",
		},
		{
			name: "invalid status",
			setup: func() *AgentExecution {
				exec := NewAgentExecution("agent_1", types.NewID())
				exec.Status = ExecutionStatus("invalid")
				return exec
			},
			wantErr: true,
		},
		{
			name: "invalid attempt",
			setup: func() *AgentExecution {
				exec := NewAgentExecution("agent_1", types.NewID())
				exec.Attempt = 0
				return exec
			},
			wantErr: true,
			errMsg:  "attempt must be >= 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := tt.setup()
			err := exec.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAgentExecution_JSON(t *testing.T) {
	original := NewAgentExecution("agent_1", types.NewID()).
		WithConfig(map[string]any{"timeout": 30}).
		WithResult(map[string]any{"status": "success"}).
		WithLangfuseSpanID("span_123")

	// Marshal to JSON
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var decoded AgentExecution
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Compare key fields
	assert.Equal(t, original.ID, decoded.ID)
	assert.Equal(t, original.MissionNodeID, decoded.MissionNodeID)
	assert.Equal(t, original.MissionID, decoded.MissionID)
	assert.Equal(t, original.Status, decoded.Status)
	assert.Equal(t, original.LangfuseSpanID, decoded.LangfuseSpanID)
}

func TestNewDecision(t *testing.T) {
	missionID := types.NewID()
	iteration := 5
	action := DecisionActionExecuteAgent

	decision := NewDecision(missionID, iteration, action)

	assert.NotEmpty(t, decision.ID)
	assert.Equal(t, missionID, decision.MissionID)
	assert.Equal(t, iteration, decision.Iteration)
	assert.Equal(t, action, decision.Action)
	assert.Equal(t, 1.0, decision.Confidence)
	assert.NotNil(t, decision.Modifications)
	assert.False(t, decision.Timestamp.IsZero())
	assert.False(t, decision.CreatedAt.IsZero())
	assert.False(t, decision.UpdatedAt.IsZero())
}

func TestDecision_MethodChaining(t *testing.T) {
	missionID := types.NewID()
	mods := map[string]any{"max_depth": 3}

	decision := NewDecision(missionID, 1, DecisionActionExecuteAgent).
		WithTargetNode("agent_2").
		WithReasoning("Need to scan the target deeply").
		WithConfidence(0.85).
		WithModifications(mods).
		WithGraphStateSummary("5 nodes, 3 edges").
		WithTokenUsage(500, 150).
		WithLatency(1234).
		WithLangfuseSpanID("span_456")

	assert.Equal(t, "agent_2", decision.TargetNodeID)
	assert.Equal(t, "Need to scan the target deeply", decision.Reasoning)
	assert.Equal(t, 0.85, decision.Confidence)
	assert.Equal(t, mods, decision.Modifications)
	assert.Equal(t, "5 nodes, 3 edges", decision.GraphStateSummary)
	assert.Equal(t, 500, decision.PromptTokens)
	assert.Equal(t, 150, decision.CompletionTokens)
	assert.Equal(t, 1234, decision.LatencyMs)
	assert.Equal(t, "span_456", decision.LangfuseSpanID)
}

func TestDecision_TotalTokens(t *testing.T) {
	decision := NewDecision(types.NewID(), 1, DecisionActionExecuteAgent).
		WithTokenUsage(500, 150)

	assert.Equal(t, 650, decision.TotalTokens())
}

func TestDecision_Validate(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() *Decision
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid decision",
			setup: func() *Decision {
				return NewDecision(types.NewID(), 1, DecisionActionExecuteAgent)
			},
			wantErr: false,
		},
		{
			name: "invalid iteration",
			setup: func() *Decision {
				d := NewDecision(types.NewID(), -1, DecisionActionExecuteAgent)
				return d
			},
			wantErr: true,
			errMsg:  "iteration must be >= 0",
		},
		{
			name: "empty action",
			setup: func() *Decision {
				d := NewDecision(types.NewID(), 1, DecisionActionExecuteAgent)
				d.Action = ""
				return d
			},
			wantErr: true,
			errMsg:  "action is required",
		},
		{
			name: "invalid confidence too low",
			setup: func() *Decision {
				return NewDecision(types.NewID(), 1, DecisionActionExecuteAgent).
					WithConfidence(-0.1)
			},
			wantErr: true,
			errMsg:  "confidence must be between 0.0 and 1.0",
		},
		{
			name: "invalid confidence too high",
			setup: func() *Decision {
				return NewDecision(types.NewID(), 1, DecisionActionExecuteAgent).
					WithConfidence(1.5)
			},
			wantErr: true,
			errMsg:  "confidence must be between 0.0 and 1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := tt.setup()
			err := decision.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDecision_JSON(t *testing.T) {
	original := NewDecision(types.NewID(), 3, DecisionActionModifyParams).
		WithTargetNode("agent_1").
		WithReasoning("Need to adjust parameters").
		WithConfidence(0.9).
		WithTokenUsage(400, 100).
		WithLangfuseSpanID("span_789")

	// Marshal to JSON
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var decoded Decision
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Compare key fields
	assert.Equal(t, original.ID, decoded.ID)
	assert.Equal(t, original.MissionID, decoded.MissionID)
	assert.Equal(t, original.Iteration, decoded.Iteration)
	assert.Equal(t, original.Action, decoded.Action)
	assert.Equal(t, original.Confidence, decoded.Confidence)
	assert.Equal(t, original.LangfuseSpanID, decoded.LangfuseSpanID)
}

func TestNewToolExecution(t *testing.T) {
	agentExecID := types.NewID()
	toolName := "nmap_scan"

	toolExec := NewToolExecution(agentExecID, toolName)

	assert.NotEmpty(t, toolExec.ID)
	assert.Equal(t, agentExecID, toolExec.AgentExecutionID)
	assert.Equal(t, toolName, toolExec.ToolName)
	assert.Equal(t, ExecutionStatusRunning, toolExec.Status)
	assert.NotNil(t, toolExec.Input)
	assert.NotNil(t, toolExec.Output)
	assert.False(t, toolExec.StartedAt.IsZero())
	assert.False(t, toolExec.CreatedAt.IsZero())
	assert.False(t, toolExec.UpdatedAt.IsZero())
	assert.Nil(t, toolExec.CompletedAt)
}

func TestToolExecution_MethodChaining(t *testing.T) {
	agentExecID := types.NewID()
	input := map[string]any{"target": "192.168.1.1"}
	output := map[string]any{"ports": []int{22, 80, 443}}

	toolExec := NewToolExecution(agentExecID, "nmap_scan").
		WithInput(input).
		WithOutput(output).
		WithLangfuseSpanID("span_abc")

	assert.Equal(t, input, toolExec.Input)
	assert.Equal(t, output, toolExec.Output)
	assert.Equal(t, "span_abc", toolExec.LangfuseSpanID)
}

func TestToolExecution_MarkCompleted(t *testing.T) {
	toolExec := NewToolExecution(types.NewID(), "nmap_scan")

	// Sleep briefly to ensure CompletedAt differs from StartedAt
	time.Sleep(1 * time.Millisecond)

	toolExec.MarkCompleted()

	assert.Equal(t, ExecutionStatusCompleted, toolExec.Status)
	assert.NotNil(t, toolExec.CompletedAt)
	assert.True(t, toolExec.CompletedAt.After(toolExec.StartedAt))
	assert.True(t, toolExec.IsComplete())
}

func TestToolExecution_MarkFailed(t *testing.T) {
	toolExec := NewToolExecution(types.NewID(), "nmap_scan")
	errMsg := "host unreachable"

	// Sleep briefly to ensure CompletedAt differs from StartedAt
	time.Sleep(1 * time.Millisecond)

	toolExec.MarkFailed(errMsg)

	assert.Equal(t, ExecutionStatusFailed, toolExec.Status)
	assert.Equal(t, errMsg, toolExec.Error)
	assert.NotNil(t, toolExec.CompletedAt)
	assert.True(t, toolExec.CompletedAt.After(toolExec.StartedAt))
	assert.True(t, toolExec.IsComplete())
}

func TestToolExecution_Duration(t *testing.T) {
	toolExec := NewToolExecution(types.NewID(), "nmap_scan")

	// Duration should be 0 when not completed
	assert.Equal(t, time.Duration(0), toolExec.Duration())

	// Sleep and complete
	time.Sleep(10 * time.Millisecond)
	toolExec.MarkCompleted()

	// Duration should be > 0 after completion
	assert.Greater(t, toolExec.Duration(), time.Duration(0))
	assert.GreaterOrEqual(t, toolExec.Duration(), 10*time.Millisecond)
}

func TestToolExecution_Validate(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() *ToolExecution
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid execution",
			setup: func() *ToolExecution {
				return NewToolExecution(types.NewID(), "nmap_scan")
			},
			wantErr: false,
		},
		{
			name: "empty tool name",
			setup: func() *ToolExecution {
				toolExec := NewToolExecution(types.NewID(), "nmap_scan")
				toolExec.ToolName = ""
				return toolExec
			},
			wantErr: true,
			errMsg:  "tool_name is required",
		},
		{
			name: "invalid status",
			setup: func() *ToolExecution {
				toolExec := NewToolExecution(types.NewID(), "nmap_scan")
				toolExec.Status = ExecutionStatus("invalid")
				return toolExec
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			toolExec := tt.setup()
			err := toolExec.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestToolExecution_JSON(t *testing.T) {
	original := NewToolExecution(types.NewID(), "nmap_scan").
		WithInput(map[string]any{"target": "192.168.1.1"}).
		WithOutput(map[string]any{"ports": []int{22, 80}}).
		WithLangfuseSpanID("span_xyz")

	// Marshal to JSON
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var decoded ToolExecution
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Compare key fields
	assert.Equal(t, original.ID, decoded.ID)
	assert.Equal(t, original.AgentExecutionID, decoded.AgentExecutionID)
	assert.Equal(t, original.ToolName, decoded.ToolName)
	assert.Equal(t, original.Status, decoded.Status)
	assert.Equal(t, original.LangfuseSpanID, decoded.LangfuseSpanID)
}

// Benchmark tests
func BenchmarkNewAgentExecution(b *testing.B) {
	missionID := types.NewID()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewAgentExecution("agent_1", missionID)
	}
}

func BenchmarkNewDecision(b *testing.B) {
	missionID := types.NewID()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewDecision(missionID, 1, DecisionActionExecuteAgent)
	}
}

func BenchmarkNewToolExecution(b *testing.B) {
	agentExecID := types.NewID()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewToolExecution(agentExecID, "nmap_scan")
	}
}
