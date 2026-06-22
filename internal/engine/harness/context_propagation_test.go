package harness

import (
	"context"
	"testing"
)

func TestAgentRunIDContextPropagation(t *testing.T) {
	tests := []struct {
		name        string
		agentRunID  string
		expectEmpty bool
	}{
		{
			name:       "valid agent run ID",
			agentRunID: "agent_run:01234567-89ab-cdef-0123-456789abcdef:0123456789abcdef",
		},
		{
			name:       "empty agent run ID",
			agentRunID: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Set agent run ID in context
			ctx = ContextWithAgentRunID(ctx, tt.agentRunID)

			// Retrieve agent run ID from context
			retrieved := AgentRunIDFromContext(ctx)

			if retrieved != tt.agentRunID {
				t.Errorf("expected agent run ID %q, got %q", tt.agentRunID, retrieved)
			}
		})
	}
}

func TestAgentRunIDFromContextEmpty(t *testing.T) {
	ctx := context.Background()

	// Retrieve from context without setting
	retrieved := AgentRunIDFromContext(ctx)

	if retrieved != "" {
		t.Errorf("expected empty string, got %q", retrieved)
	}
}

func TestToolExecutionIDContextPropagation(t *testing.T) {
	tests := []struct {
		name            string
		toolExecutionID string
		expectEmpty     bool
	}{
		{
			name:            "valid tool execution ID",
			toolExecutionID: "tool_execution:01234567-89ab-cdef-0123-456789abcdef:0123456789abcdef:1234567890",
		},
		{
			name:            "empty tool execution ID",
			toolExecutionID: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Set tool execution ID in context
			ctx = ContextWithToolExecutionID(ctx, tt.toolExecutionID)

			// Retrieve tool execution ID from context
			retrieved := ToolExecutionIDFromContext(ctx)

			if retrieved != tt.toolExecutionID {
				t.Errorf("expected tool execution ID %q, got %q", tt.toolExecutionID, retrieved)
			}
		})
	}
}

func TestToolExecutionIDFromContextEmpty(t *testing.T) {
	ctx := context.Background()

	// Retrieve from context without setting
	retrieved := ToolExecutionIDFromContext(ctx)

	if retrieved != "" {
		t.Errorf("expected empty string, got %q", retrieved)
	}
}

func TestBothIDsInContext(t *testing.T) {
	ctx := context.Background()

	agentRunID := "agent_run:01234567-89ab-cdef-0123-456789abcdef:0123456789abcdef"
	toolExecutionID := "tool_execution:01234567-89ab-cdef-0123-456789abcdef:0123456789abcdef:1234567890"

	// Set both IDs in context
	ctx = ContextWithAgentRunID(ctx, agentRunID)
	ctx = ContextWithToolExecutionID(ctx, toolExecutionID)

	// Retrieve both IDs
	retrievedAgentRunID := AgentRunIDFromContext(ctx)
	retrievedToolExecutionID := ToolExecutionIDFromContext(ctx)

	if retrievedAgentRunID != agentRunID {
		t.Errorf("expected agent run ID %q, got %q", agentRunID, retrievedAgentRunID)
	}

	if retrievedToolExecutionID != toolExecutionID {
		t.Errorf("expected tool execution ID %q, got %q", toolExecutionID, retrievedToolExecutionID)
	}
}

func TestContextPropagationThroughChain(t *testing.T) {
	// Simulate a chain of context propagation
	ctx := context.Background()

	agentRunID := "agent_run:01234567-89ab-cdef-0123-456789abcdef:0123456789abcdef"

	// Parent context with agent run ID
	parentCtx := ContextWithAgentRunID(ctx, agentRunID)

	// Child context (simulating a tool execution)
	toolExecutionID := "tool_execution:01234567-89ab-cdef-0123-456789abcdef:0123456789abcdef:1234567890"
	childCtx := ContextWithToolExecutionID(parentCtx, toolExecutionID)

	// Both IDs should be available in child context
	retrievedAgentRunID := AgentRunIDFromContext(childCtx)
	retrievedToolExecutionID := ToolExecutionIDFromContext(childCtx)

	if retrievedAgentRunID != agentRunID {
		t.Errorf("expected agent run ID %q in child context, got %q", agentRunID, retrievedAgentRunID)
	}

	if retrievedToolExecutionID != toolExecutionID {
		t.Errorf("expected tool execution ID %q in child context, got %q", toolExecutionID, retrievedToolExecutionID)
	}
}
