package observability_test

import (
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/observability"
)

// Example demonstrates how to use the tool-related observability functions
// for tracking GenAI tool calls in OpenTelemetry traces.
func Example_toolCallObservability() {
	// Create sample tool calls from an LLM response
	toolCalls := []llm.ToolCall{
		{
			ID:        "call_abc123",
			Name:      "get_weather",
			Type:      "function",
			Arguments: `{"location": "San Francisco", "unit": "fahrenheit"}`,
		},
		{
			ID:        "call_def456",
			Name:      "get_time",
			Type:      "function",
			Arguments: `{"timezone": "America/Los_Angeles"}`,
		},
	}

	// Get attributes for all tool calls (suitable for span attributes)
	// This will include the count and summary information
	attrs := observability.ToolCallAttributes(toolCalls)
	fmt.Printf("Tool call summary attributes: %d attributes\n", len(attrs))

	// Get attributes for tool choice setting
	toolChoiceAttrs := observability.ToolChoiceAttributes("auto")
	fmt.Printf("Tool choice attributes: %d attributes\n", len(toolChoiceAttrs))

	// For detailed tool call logging, use SingleToolCallAttributes
	// This is typically used when logging tool calls as span events
	for _, tc := range toolCalls {
		singleAttrs := observability.SingleToolCallAttributes(tc.ID, tc.Name, tc.Arguments)
		fmt.Printf("Single tool call '%s' attributes: %d attributes\n", tc.Name, len(singleAttrs))
	}

	// When tool execution completes, log the result
	result := `{"temperature": 72, "condition": "sunny", "humidity": 65}`
	resultAttrs := observability.ToolResultAttributes(
		"call_abc123",
		"get_weather",
		result,
		false, // not truncated
	)
	fmt.Printf("Tool result attributes: %d attributes\n", len(resultAttrs))

	// Output:
	// Tool call summary attributes: 5 attributes
	// Tool choice attributes: 1 attributes
	// Single tool call 'get_weather' attributes: 3 attributes
	// Single tool call 'get_time' attributes: 3 attributes
	// Tool result attributes: 3 attributes
}

// Example demonstrates how to handle large tool arguments that need truncation.
func Example_toolCallTruncation() {
	// Large arguments should be truncated
	largeArgs := string(make([]byte, 2000)) // 2KB of data
	attrs := observability.SingleToolCallAttributes("call_123", "process_data", largeArgs)

	fmt.Printf("Attributes count: %d\n", len(attrs))
	// The arguments will be automatically truncated to 1KB with a truncation indicator

	// Large results should also be truncated
	largeResult := string(make([]byte, 3000)) // 3KB of data
	resultAttrs := observability.ToolResultAttributes("call_456", "fetch_data", largeResult, false)

	fmt.Printf("Result attributes count: %d\n", len(resultAttrs))
	// The result will be automatically truncated to 2KB with a truncation indicator

	// Output:
	// Attributes count: 3
	// Result attributes count: 4
}

// Example demonstrates the event name constants for logging content.
func Example_eventNames() {
	// Use event name constants when adding events to spans
	fmt.Println("Prompt event:", observability.EventGenAIContentPrompt)
	fmt.Println("Completion event:", observability.EventGenAIContentCompletion)
	fmt.Println("Tool input event:", observability.EventGenAIToolCallInput)
	fmt.Println("Tool output event:", observability.EventGenAIToolCallOutput)

	// Output:
	// Prompt event: gen_ai.content.prompt
	// Completion event: gen_ai.content.completion
	// Tool input event: gen_ai.tool_call.input
	// Tool output event: gen_ai.tool_call.output
}
