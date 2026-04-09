package middleware

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	agentpb "github.com/zero-day-ai/sdk/api/gen/gibson/agent/v1"
	commonpb "github.com/zero-day-ai/sdk/api/gen/gibson/common/v1"
	_ "github.com/zero-day-ai/sdk/api/gen/gibson/types/v1" // imported for type registry side effects
)

// mockStreamSender is a mock implementation of StreamSender for testing
type mockStreamSender struct {
	toolCalls   []*agentpb.ToolCallEvent
	toolResults []*agentpb.ToolResultEvent
	outputs     []*agentpb.OutputChunk
	findings    []*agentpb.FindingEvent
}

func newMockStreamSender() *mockStreamSender {
	return &mockStreamSender{
		toolCalls:   make([]*agentpb.ToolCallEvent, 0),
		toolResults: make([]*agentpb.ToolResultEvent, 0),
		outputs:     make([]*agentpb.OutputChunk, 0),
		findings:    make([]*agentpb.FindingEvent, 0),
	}
}

func (m *mockStreamSender) SendToolCall(call *agentpb.ToolCallEvent) error {
	m.toolCalls = append(m.toolCalls, call)
	return nil
}

func (m *mockStreamSender) SendToolResult(result *agentpb.ToolResultEvent) error {
	m.toolResults = append(m.toolResults, result)
	return nil
}

func (m *mockStreamSender) SendOutput(output *agentpb.OutputChunk) error {
	m.outputs = append(m.outputs, output)
	return nil
}

func (m *mockStreamSender) SendFinding(finding *agentpb.FindingEvent) error {
	m.findings = append(m.findings, finding)
	return nil
}

// TestToolCallCorrelation tests that callID is shared between tool call and result events
func TestToolCallCorrelation(t *testing.T) {
	tests := []struct {
		name        string
		toolName    string
		input       map[string]any
		output      map[string]any
		expectError bool
	}{
		{
			name:     "basic tool call correlation",
			toolName: "search",
			input: map[string]any{
				"query": "test query",
			},
			output: map[string]any{
				"results": []string{"result1", "result2"},
			},
			expectError: false,
		},
		{
			name:     "tool call with complex input",
			toolName: "analyze",
			input: map[string]any{
				"target": map[string]any{
					"host": "example.com",
					"port": 443,
				},
				"options": []string{"deep-scan", "verbose"},
			},
			output: map[string]any{
				"findings": 5,
				"status":   "complete",
			},
			expectError: false,
		},
		{
			name:     "tool call with empty input",
			toolName: "status",
			input:    map[string]any{},
			output: map[string]any{
				"healthy": true,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStream := newMockStreamSender()

			// Create context with operation type
			ctx := context.Background()
			ctx = context.WithValue(ctx, CtxOperationType, OpCallToolProto)

			// Create tool request
			req := map[string]any{
				"name":  tt.toolName,
				"input": tt.input,
			}

			// Create mock operation that returns the expected output
			mockOp := func(ctx context.Context, req any) (any, error) {
				return tt.output, nil
			}

			// Apply streaming middleware
			middleware := StreamingMiddleware(mockStream, nil, nil)
			wrappedOp := middleware(mockOp)

			// Execute the operation
			result, err := wrappedOp(ctx, req)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.output, result)

			// Verify tool call event was sent
			require.Len(t, mockStream.toolCalls, 1, "Expected one tool call event")
			toolCall := mockStream.toolCalls[0]

			assert.Equal(t, tt.toolName, toolCall.ToolName)
			assert.NotEmpty(t, toolCall.CallId, "CallID should not be empty")

			// Verify tool result event was sent
			require.Len(t, mockStream.toolResults, 1, "Expected one tool result event")
			toolResult := mockStream.toolResults[0]

			assert.NotEmpty(t, toolResult.CallId, "CallID should not be empty")
			assert.True(t, toolResult.Success, "Tool call should succeed")

			// CRITICAL: Verify callID matches between call and result
			assert.Equal(t, toolCall.CallId, toolResult.CallId,
				"CallID must match between tool call and result for correlation")
		})
	}
}

// TestToolCallIDUniqueness tests that each tool call gets a unique callID
func TestToolCallIDUniqueness(t *testing.T) {
	mockStream := newMockStreamSender()

	// Create context with operation type
	ctx := context.Background()
	ctx = context.WithValue(ctx, CtxOperationType, OpCallToolProto)

	// Create mock operation
	mockOp := func(ctx context.Context, req any) (any, error) {
		return map[string]any{"result": "ok"}, nil
	}

	// Apply streaming middleware
	middleware := StreamingMiddleware(mockStream, nil, nil)
	wrappedOp := middleware(mockOp)

	// Execute multiple tool calls
	numCalls := 5
	for i := 0; i < numCalls; i++ {
		req := map[string]any{
			"name":  "tool",
			"input": map[string]any{"index": i},
		}

		_, err := wrappedOp(ctx, req)
		require.NoError(t, err)
	}

	// Verify we have the expected number of events
	require.Len(t, mockStream.toolCalls, numCalls)
	require.Len(t, mockStream.toolResults, numCalls)

	// Collect all callIDs
	callIDs := make(map[string]bool)
	for i := 0; i < numCalls; i++ {
		callID := mockStream.toolCalls[i].CallId
		assert.NotEmpty(t, callID, "CallID should not be empty")

		// Verify uniqueness
		assert.False(t, callIDs[callID], "CallID %s is not unique", callID)
		callIDs[callID] = true

		// Verify correlation
		assert.Equal(t, callID, mockStream.toolResults[i].CallId,
			"CallID should match between call and result")
	}
}

// TestToolCallInputSerialization tests that tool inputs are correctly serialized
func TestToolCallInputSerialization(t *testing.T) {
	tests := []struct {
		name          string
		input         map[string]any
		validateInput func(*testing.T, map[string]*commonpb.TypedValue)
	}{
		{
			name: "string input",
			input: map[string]any{
				"query": "test query",
			},
			validateInput: func(t *testing.T, input map[string]*commonpb.TypedValue) {
				require.Contains(t, input, "query")
				stringVal, ok := input["query"].Kind.(*commonpb.TypedValue_StringValue)
				require.True(t, ok, "Expected string value")
				assert.Equal(t, "test query", stringVal.StringValue)
			},
		},
		{
			name: "numeric input",
			input: map[string]any{
				"count": 42,
			},
			validateInput: func(t *testing.T, input map[string]*commonpb.TypedValue) {
				require.Contains(t, input, "count")
				// JSON unmarshal converts numbers to float64 by default
				switch v := input["count"].Kind.(type) {
				case *commonpb.TypedValue_IntValue:
					assert.Equal(t, int64(42), v.IntValue)
				case *commonpb.TypedValue_DoubleValue:
					assert.InDelta(t, 42.0, v.DoubleValue, 0.001)
				default:
					t.Fatalf("Expected numeric value, got %T", v)
				}
			},
		},
		{
			name: "boolean input",
			input: map[string]any{
				"enabled": true,
			},
			validateInput: func(t *testing.T, input map[string]*commonpb.TypedValue) {
				require.Contains(t, input, "enabled")
				boolVal, ok := input["enabled"].Kind.(*commonpb.TypedValue_BoolValue)
				require.True(t, ok, "Expected bool value")
				assert.True(t, boolVal.BoolValue)
			},
		},
		{
			name: "nested map input",
			input: map[string]any{
				"config": map[string]any{
					"host": "example.com",
					"port": 443,
				},
			},
			validateInput: func(t *testing.T, input map[string]*commonpb.TypedValue) {
				require.Contains(t, input, "config")
				mapVal, ok := input["config"].Kind.(*commonpb.TypedValue_MapValue)
				require.True(t, ok, "Expected map value")
				require.Contains(t, mapVal.MapValue.Entries, "host")
				require.Contains(t, mapVal.MapValue.Entries, "port")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStream := newMockStreamSender()

			ctx := context.Background()
			ctx = context.WithValue(ctx, CtxOperationType, OpCallToolProto)

			req := map[string]any{
				"name":  "test-tool",
				"input": tt.input,
			}

			mockOp := func(ctx context.Context, req any) (any, error) {
				return map[string]any{}, nil
			}

			middleware := StreamingMiddleware(mockStream, nil, nil)
			wrappedOp := middleware(mockOp)

			_, err := wrappedOp(ctx, req)
			require.NoError(t, err)

			require.Len(t, mockStream.toolCalls, 1)
			toolCall := mockStream.toolCalls[0]

			if tt.validateInput != nil {
				tt.validateInput(t, toolCall.Input)
			}
		})
	}
}

// TestToolResultOutputSerialization tests that tool outputs are correctly serialized
func TestToolResultOutputSerialization(t *testing.T) {
	tests := []struct {
		name           string
		output         any
		validateOutput func(*testing.T, *commonpb.TypedValue)
	}{
		{
			name: "map output",
			output: map[string]any{
				"status": "success",
				"count":  5,
			},
			validateOutput: func(t *testing.T, output *commonpb.TypedValue) {
				mapVal, ok := output.Kind.(*commonpb.TypedValue_MapValue)
				require.True(t, ok, "Expected map value")
				require.Contains(t, mapVal.MapValue.Entries, "status")
				require.Contains(t, mapVal.MapValue.Entries, "count")
			},
		},
		{
			name:   "string output",
			output: "result string",
			validateOutput: func(t *testing.T, output *commonpb.TypedValue) {
				// String outputs get wrapped in a map
				mapVal, ok := output.Kind.(*commonpb.TypedValue_MapValue)
				require.True(t, ok, "Expected wrapped map value")
				require.Contains(t, mapVal.MapValue.Entries, "result")
			},
		},
		{
			name: "array output",
			output: map[string]any{
				"items": []any{"item1", "item2", "item3"},
			},
			validateOutput: func(t *testing.T, output *commonpb.TypedValue) {
				mapVal, ok := output.Kind.(*commonpb.TypedValue_MapValue)
				require.True(t, ok, "Expected map value")
				require.Contains(t, mapVal.MapValue.Entries, "items")

				arrayVal, ok := mapVal.MapValue.Entries["items"].Kind.(*commonpb.TypedValue_ArrayValue)
				require.True(t, ok, "Expected array value")
				assert.Len(t, arrayVal.ArrayValue.Items, 3)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStream := newMockStreamSender()

			ctx := context.Background()
			ctx = context.WithValue(ctx, CtxOperationType, OpCallToolProto)

			req := map[string]any{
				"name":  "test-tool",
				"input": map[string]any{},
			}

			mockOp := func(ctx context.Context, req any) (any, error) {
				return tt.output, nil
			}

			middleware := StreamingMiddleware(mockStream, nil, nil)
			wrappedOp := middleware(mockOp)

			_, err := wrappedOp(ctx, req)
			require.NoError(t, err)

			require.Len(t, mockStream.toolResults, 1)
			toolResult := mockStream.toolResults[0]

			if tt.validateOutput != nil {
				tt.validateOutput(t, toolResult.Output)
			}
		})
	}
}

// TestToolCallFailureHandling tests that tool call failures are properly tracked
func TestToolCallFailureHandling(t *testing.T) {
	mockStream := newMockStreamSender()

	ctx := context.Background()
	ctx = context.WithValue(ctx, CtxOperationType, OpCallToolProto)

	req := map[string]any{
		"name":  "failing-tool",
		"input": map[string]any{"test": "data"},
	}

	// Create operation that returns an error
	expectedErr := assert.AnError
	mockOp := func(ctx context.Context, req any) (any, error) {
		return nil, expectedErr
	}

	middleware := StreamingMiddleware(mockStream, nil, nil)
	wrappedOp := middleware(mockOp)

	result, err := wrappedOp(ctx, req)

	// Error should be propagated
	require.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, result)

	// Verify tool call event was sent
	require.Len(t, mockStream.toolCalls, 1)
	toolCall := mockStream.toolCalls[0]
	assert.NotEmpty(t, toolCall.CallId)

	// Verify tool result event was sent with success=false
	require.Len(t, mockStream.toolResults, 1)
	toolResult := mockStream.toolResults[0]
	assert.Equal(t, toolCall.CallId, toolResult.CallId, "CallID should match even on failure")
	assert.False(t, toolResult.Success, "Success should be false for failed tool calls")
}

// TestStreamingMiddlewareNoOp tests that middleware is no-op when stream is nil
func TestStreamingMiddlewareNoOp(t *testing.T) {
	// Create middleware with nil stream
	middleware := StreamingMiddleware(nil, nil, nil)

	ctx := context.Background()
	ctx = context.WithValue(ctx, CtxOperationType, OpCallToolProto)

	req := map[string]any{
		"name":  "test-tool",
		"input": map[string]any{},
	}

	expectedResult := map[string]any{"result": "ok"}
	mockOp := func(ctx context.Context, req any) (any, error) {
		return expectedResult, nil
	}

	wrappedOp := middleware(mockOp)
	result, err := wrappedOp(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, expectedResult, result)
}

// TestStreamingMiddlewareNoOpType tests that middleware is no-op without operation type
func TestStreamingMiddlewareNoOpType(t *testing.T) {
	mockStream := newMockStreamSender()
	middleware := StreamingMiddleware(mockStream, nil, nil)

	// Context without operation type
	ctx := context.Background()

	req := map[string]any{
		"name":  "test-tool",
		"input": map[string]any{},
	}

	expectedResult := map[string]any{"result": "ok"}
	mockOp := func(ctx context.Context, req any) (any, error) {
		return expectedResult, nil
	}

	wrappedOp := middleware(mockOp)
	result, err := wrappedOp(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, expectedResult, result)

	// No events should be sent
	assert.Empty(t, mockStream.toolCalls)
	assert.Empty(t, mockStream.toolResults)
}

// TestBuildToolCallEvent tests the tool call event builder function
func TestBuildToolCallEvent(t *testing.T) {
	input := map[string]any{
		"query": "test",
		"limit": int64(10),
	}

	inputJSON, err := json.Marshal(input)
	require.NoError(t, err)

	event := buildToolCallEvent("search", string(inputJSON), "call-123", "trace-456", "span-789")

	assert.NotNil(t, event)
	assert.Equal(t, "search", event.ToolName)
	assert.Equal(t, "call-123", event.CallId)
	assert.Contains(t, event.Input, "query")
	assert.Contains(t, event.Input, "limit")
}

// TestBuildToolResultEvent tests the tool result event builder function
func TestBuildToolResultEvent(t *testing.T) {
	output := map[string]any{
		"status": "success",
		"items":  []any{"a", "b", "c"},
	}

	outputJSON, err := json.Marshal(output)
	require.NoError(t, err)

	event := buildToolResultEvent("call-123", string(outputJSON), true, "trace-456", "span-789")

	assert.NotNil(t, event)
	assert.Equal(t, "call-123", event.CallId)
	assert.True(t, event.Success)
	assert.NotNil(t, event.Output)
}

// TestAnyToTypedValue tests the type conversion function
func TestAnyToTypedValue(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		validate func(*testing.T, *commonpb.TypedValue)
	}{
		{
			name:  "nil value",
			input: nil,
			validate: func(t *testing.T, tv *commonpb.TypedValue) {
				_, ok := tv.Kind.(*commonpb.TypedValue_NullValue)
				assert.True(t, ok, "Expected null value")
			},
		},
		{
			name:  "string value",
			input: "test string",
			validate: func(t *testing.T, tv *commonpb.TypedValue) {
				sv, ok := tv.Kind.(*commonpb.TypedValue_StringValue)
				assert.True(t, ok, "Expected string value")
				assert.Equal(t, "test string", sv.StringValue)
			},
		},
		{
			name:  "int value",
			input: 42,
			validate: func(t *testing.T, tv *commonpb.TypedValue) {
				iv, ok := tv.Kind.(*commonpb.TypedValue_IntValue)
				assert.True(t, ok, "Expected int value")
				assert.Equal(t, int64(42), iv.IntValue)
			},
		},
		{
			name:  "bool value",
			input: true,
			validate: func(t *testing.T, tv *commonpb.TypedValue) {
				bv, ok := tv.Kind.(*commonpb.TypedValue_BoolValue)
				assert.True(t, ok, "Expected bool value")
				assert.True(t, bv.BoolValue)
			},
		},
		{
			name:  "float value",
			input: 3.14,
			validate: func(t *testing.T, tv *commonpb.TypedValue) {
				fv, ok := tv.Kind.(*commonpb.TypedValue_DoubleValue)
				assert.True(t, ok, "Expected double value")
				assert.InDelta(t, 3.14, fv.DoubleValue, 0.001)
			},
		},
		{
			name:  "array value",
			input: []any{1, "two", true},
			validate: func(t *testing.T, tv *commonpb.TypedValue) {
				av, ok := tv.Kind.(*commonpb.TypedValue_ArrayValue)
				assert.True(t, ok, "Expected array value")
				assert.Len(t, av.ArrayValue.Items, 3)
			},
		},
		{
			name: "map value",
			input: map[string]any{
				"key1": "value1",
				"key2": 123,
			},
			validate: func(t *testing.T, tv *commonpb.TypedValue) {
				mv, ok := tv.Kind.(*commonpb.TypedValue_MapValue)
				assert.True(t, ok, "Expected map value")
				assert.Contains(t, mv.MapValue.Entries, "key1")
				assert.Contains(t, mv.MapValue.Entries, "key2")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := anyToTypedValue(tt.input)
			require.NotNil(t, result)

			if tt.validate != nil {
				tt.validate(t, result)
			}
		})
	}
}
