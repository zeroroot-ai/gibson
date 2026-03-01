package observability

import (
	"context"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/llm"
)

// NoopActivityLogger is a no-op implementation of ActivityLogger.
// It satisfies the interface but performs no operations, making it suitable
// for use when activity logging is disabled. All methods are zero-allocation.
type NoopActivityLogger struct{}

// NewNoopActivityLogger creates a new no-op activity logger.
func NewNoopActivityLogger() *NoopActivityLogger {
	return &NoopActivityLogger{}
}

// Emit does nothing.
func (n *NoopActivityLogger) Emit(ctx context.Context, event ActivityEvent) {}

// EmitAgentStart does nothing.
func (n *NoopActivityLogger) EmitAgentStart(ctx context.Context, agentName string, taskDescription string) {
}

// EmitAgentEnd does nothing.
func (n *NoopActivityLogger) EmitAgentEnd(ctx context.Context, agentName string, status string, durationMs int64) {
}

// EmitLLMPrompt does nothing.
func (n *NoopActivityLogger) EmitLLMPrompt(ctx context.Context, slot string, messages []llm.Message) {
}

// EmitLLMResponse does nothing.
func (n *NoopActivityLogger) EmitLLMResponse(ctx context.Context, slot string, response *llm.CompletionResponse) {
}

// EmitToolCall does nothing.
func (n *NoopActivityLogger) EmitToolCall(ctx context.Context, toolName string, params interface{}) {
}

// EmitToolResult does nothing.
func (n *NoopActivityLogger) EmitToolResult(ctx context.Context, toolName string, result interface{}, durationMs int64, err error) {
}

// EmitFinding does nothing.
func (n *NoopActivityLogger) EmitFinding(ctx context.Context, finding *agent.Finding) {}

// EmitDecision does nothing.
func (n *NoopActivityLogger) EmitDecision(ctx context.Context, action string, target string, reasoning string, confidence float64) {
}

// EmitError does nothing.
func (n *NoopActivityLogger) EmitError(ctx context.Context, operation string, err error) {}

// Level returns ActivityLevelQuiet.
func (n *NoopActivityLogger) Level() ActivityLevel {
	return ActivityLevelQuiet
}

// SetLevel does nothing.
func (n *NoopActivityLogger) SetLevel(level ActivityLevel) {}

// Flush does nothing.
func (n *NoopActivityLogger) Flush() error {
	return nil
}

// Close does nothing.
func (n *NoopActivityLogger) Close() error {
	return nil
}
