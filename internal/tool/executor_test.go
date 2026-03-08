package tool

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/types"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// mockTool implements the Tool interface for testing
type mockTool struct {
	name              string
	description       string
	version           string
	tags              []string
	inputMessageType  string
	outputMessageType string
	executeFn         func(ctx context.Context, input proto.Message) (proto.Message, error)
	healthFn          func(ctx context.Context) types.HealthStatus
}

func (m *mockTool) Name() string              { return m.name }
func (m *mockTool) Description() string       { return m.description }
func (m *mockTool) Version() string           { return m.version }
func (m *mockTool) Tags() []string            { return m.tags }
func (m *mockTool) InputMessageType() string  { return m.inputMessageType }
func (m *mockTool) OutputMessageType() string { return m.outputMessageType }

func (m *mockTool) ExecuteProto(ctx context.Context, input proto.Message) (proto.Message, error) {
	if m.executeFn != nil {
		return m.executeFn(ctx, input)
	}
	// Default behavior
	return structpb.NewStruct(map[string]interface{}{
		"result": "success",
	})
}

func (m *mockTool) Health(ctx context.Context) types.HealthStatus {
	if m.healthFn != nil {
		return m.healthFn(ctx)
	}
	return types.Healthy("OK")
}

func TestToolExecutor_Execute_Success(t *testing.T) {
	registry := NewToolRegistry()

	tool := &mockTool{
		name:              "test-tool",
		description:       "A test tool",
		version:           "1.0.0",
		tags:              []string{"test"},
		inputMessageType:  "google.protobuf.Struct",
		outputMessageType: "google.protobuf.Struct",
	}

	err := registry.RegisterInternal(tool)
	require.NoError(t, err)

	executor := NewToolExecutor(registry)

	input, err := structpb.NewStruct(map[string]interface{}{
		"key": "value",
	})
	require.NoError(t, err)

	result, err := executor.Execute(context.Background(), "test-tool", input)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestToolExecutor_Execute_ToolNotFound(t *testing.T) {
	registry := NewToolRegistry()
	executor := NewToolExecutor(registry)

	input, err := structpb.NewStruct(map[string]interface{}{})
	require.NoError(t, err)

	_, err = executor.Execute(context.Background(), "nonexistent-tool", input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestToolExecutor_Execute_ValidationError(t *testing.T) {
	registry := NewToolRegistry()

	tool := &mockTool{
		name:              "test-tool",
		description:       "A test tool",
		version:           "1.0.0",
		inputMessageType:  "google.protobuf.Struct",
		outputMessageType: "google.protobuf.Struct",
	}

	err := registry.RegisterInternal(tool)
	require.NoError(t, err)

	executor := NewToolExecutor(registry)

	// Test with nil input
	_, err = executor.Execute(context.Background(), "test-tool", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "input validation failed")
}

func TestToolExecutor_ExecuteWithRetry_Success(t *testing.T) {
	registry := NewToolRegistry()

	attempts := 0
	tool := &mockTool{
		name:              "test-tool",
		description:       "A test tool",
		version:           "1.0.0",
		inputMessageType:  "google.protobuf.Struct",
		outputMessageType: "google.protobuf.Struct",
		executeFn: func(ctx context.Context, input proto.Message) (proto.Message, error) {
			attempts++
			if attempts < 3 {
				// Fail first 2 attempts with retryable error
				return nil, &types.GibsonError{
					Code:      ErrToolExecutionFailed,
					Message:   "temporary failure",
					Retryable: true,
				}
			}
			return structpb.NewStruct(map[string]interface{}{
				"result": "success",
			})
		},
	}

	err := registry.RegisterInternal(tool)
	require.NoError(t, err)

	executor := NewToolExecutor(registry).WithRetryConfig(RetryConfig{
		MaxRetries:     3,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     100 * time.Millisecond,
		BackoffFactor:  2.0,
		RetryableErrors: []types.ErrorCode{
			ErrToolExecutionFailed,
		},
	})

	input, err := structpb.NewStruct(map[string]interface{}{})
	require.NoError(t, err)

	result, err := executor.Execute(context.Background(), "test-tool", input)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 3, attempts) // Should have retried twice
}

func TestToolExecutor_ExecuteWithRetry_NonRetryableError(t *testing.T) {
	registry := NewToolRegistry()

	attempts := 0
	tool := &mockTool{
		name:              "test-tool",
		description:       "A test tool",
		version:           "1.0.0",
		inputMessageType:  "google.protobuf.Struct",
		outputMessageType: "google.protobuf.Struct",
		executeFn: func(ctx context.Context, input proto.Message) (proto.Message, error) {
			attempts++
			// Non-retryable error
			return nil, &types.GibsonError{
				Code:      ErrToolInvalidInput,
				Message:   "invalid input",
				Retryable: false,
			}
		},
	}

	err := registry.RegisterInternal(tool)
	require.NoError(t, err)

	executor := NewToolExecutor(registry)

	input, err := structpb.NewStruct(map[string]interface{}{})
	require.NoError(t, err)

	_, err = executor.Execute(context.Background(), "test-tool", input)
	require.Error(t, err)
	assert.Equal(t, 1, attempts) // Should not have retried
}

func TestToolExecutor_WithCache(t *testing.T) {
	registry := NewToolRegistry()

	executions := 0
	tool := &mockTool{
		name:              "test-tool",
		description:       "A test tool",
		version:           "1.0.0",
		inputMessageType:  "google.protobuf.Struct",
		outputMessageType: "google.protobuf.Struct",
		executeFn: func(ctx context.Context, input proto.Message) (proto.Message, error) {
			executions++
			return structpb.NewStruct(map[string]interface{}{
				"result":     "success",
				"executions": executions,
			})
		},
	}

	err := registry.RegisterInternal(tool)
	require.NoError(t, err)

	cache := NewMemoryToolCache(10)
	executor := NewToolExecutor(registry).WithCache(cache)

	input, err := structpb.NewStruct(map[string]interface{}{
		"key": "value",
	})
	require.NoError(t, err)

	// First execution - should call the tool
	result1, err := executor.Execute(context.Background(), "test-tool", input)
	require.NoError(t, err)
	require.NotNil(t, result1)
	assert.Equal(t, 1, executions)

	// Second execution with same input - should use cache
	result2, err := executor.Execute(context.Background(), "test-tool", input)
	require.NoError(t, err)
	require.NotNil(t, result2)
	assert.Equal(t, 1, executions) // Should not have executed again
}

func TestMemoryToolCache_LRUEviction(t *testing.T) {
	cache := NewMemoryToolCache(2) // Max 2 entries

	result1 := &CachedResult{
		Result: &structpb.Struct{},
	}
	result2 := &CachedResult{
		Result: &structpb.Struct{},
	}
	result3 := &CachedResult{
		Result: &structpb.Struct{},
	}

	cache.Set("key1", result1, 5*time.Minute)
	cache.Set("key2", result2, 5*time.Minute)

	// Both should be in cache
	_, found := cache.Get("key1")
	assert.True(t, found)
	_, found = cache.Get("key2")
	assert.True(t, found)

	// Add third entry - should evict key1 (LRU)
	cache.Set("key3", result3, 5*time.Minute)

	// key1 should be evicted
	_, found = cache.Get("key1")
	assert.False(t, found)

	// key2 and key3 should still be there
	_, found = cache.Get("key2")
	assert.True(t, found)
	_, found = cache.Get("key3")
	assert.True(t, found)
}

func TestMemoryToolCache_Expiration(t *testing.T) {
	cache := NewMemoryToolCache(10)

	result := &CachedResult{
		Result: &structpb.Struct{},
	}

	// Set with very short TTL
	cache.Set("key1", result, 10*time.Millisecond)

	// Should be available immediately
	_, found := cache.Get("key1")
	assert.True(t, found)

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	// Should be expired now
	_, found = cache.Get("key1")
	assert.False(t, found)
}

func TestToolExecutor_StreamExecute_NonStreamingTool(t *testing.T) {
	registry := NewToolRegistry()

	tool := &mockTool{
		name:              "test-tool",
		description:       "A test tool",
		version:           "1.0.0",
		inputMessageType:  "google.protobuf.Struct",
		outputMessageType: "google.protobuf.Struct",
	}

	err := registry.RegisterInternal(tool)
	require.NoError(t, err)

	executor := NewToolExecutor(registry)

	input, err := structpb.NewStruct(map[string]interface{}{
		"key": "value",
	})
	require.NoError(t, err)

	result := executor.StreamExecute(context.Background(), "test-tool", input)

	// Should receive single chunk with final result
	chunks := 0
	for chunk := range result.Chunks {
		chunks++
		assert.True(t, chunk.IsFinal)
		assert.NoError(t, chunk.Error)
		assert.NotNil(t, chunk.Data)
	}

	assert.Equal(t, 1, chunks)
}

func TestToolExecutor_StreamExecute_ContextCancellation(t *testing.T) {
	registry := NewToolRegistry()

	tool := &mockTool{
		name:              "test-tool",
		description:       "A test tool",
		version:           "1.0.0",
		inputMessageType:  "google.protobuf.Struct",
		outputMessageType: "google.protobuf.Struct",
		executeFn: func(ctx context.Context, input proto.Message) (proto.Message, error) {
			// Simulate long-running operation
			time.Sleep(100 * time.Millisecond)
			return structpb.NewStruct(map[string]interface{}{
				"result": "success",
			})
		},
	}

	err := registry.RegisterInternal(tool)
	require.NoError(t, err)

	executor := NewToolExecutor(registry)

	input, err := structpb.NewStruct(map[string]interface{}{})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	result := executor.StreamExecute(ctx, "test-tool", input)

	// Cancel immediately
	cancel()

	// Should stop streaming
	for chunk := range result.Chunks {
		// May receive error chunk or no chunks at all
		if chunk.Error != nil {
			assert.Contains(t, chunk.Error.Error(), "cancel")
		}
	}
}

func TestValidateToolInput(t *testing.T) {
	schema := `{
		"type": "object",
		"properties": {
			"name": {"type": "string"},
			"age": {"type": "number"}
		},
		"required": ["name"]
	}`

	t.Run("valid input", func(t *testing.T) {
		input := map[string]interface{}{
			"name": "John",
			"age":  float64(30),
		}

		errors := ValidateToolInput(schema, input)
		assert.Empty(t, errors)
	})

	t.Run("missing required field", func(t *testing.T) {
		input := map[string]interface{}{
			"age": float64(30),
		}

		errors := ValidateToolInput(schema, input)
		assert.NotEmpty(t, errors)
		assert.Contains(t, errors[0].Error(), "name")
		assert.Contains(t, errors[0].Error(), "required")
	})

	t.Run("wrong type", func(t *testing.T) {
		input := map[string]interface{}{
			"name": "John",
			"age":  "thirty", // Should be number
		}

		errors := ValidateToolInput(schema, input)
		assert.NotEmpty(t, errors)
		assert.Contains(t, errors[0].Error(), "age")
		assert.Contains(t, errors[0].Error(), "type")
	})
}

func TestRetryConfig_CalculateBackoff(t *testing.T) {
	config := RetryConfig{
		InitialBackoff: 100 * time.Millisecond,
		MaxBackoff:     1 * time.Second,
		BackoffFactor:  2.0,
	}

	// First attempt should be around initial backoff (with jitter)
	backoff1 := config.calculateBackoff(0)
	assert.InDelta(t, 100*time.Millisecond, backoff1, float64(50*time.Millisecond))

	// Second attempt should be around 2x
	backoff2 := config.calculateBackoff(1)
	assert.InDelta(t, 200*time.Millisecond, backoff2, float64(100*time.Millisecond))

	// Should not exceed max backoff
	backoff10 := config.calculateBackoff(10)
	assert.LessOrEqual(t, backoff10, config.MaxBackoff+time.Duration(float64(config.MaxBackoff)*0.25))
}

func TestStreamingWrapper(t *testing.T) {
	tool := &mockTool{
		name:              "test-tool",
		description:       "A test tool",
		version:           "1.0.0",
		inputMessageType:  "google.protobuf.Struct",
		outputMessageType: "google.protobuf.Struct",
	}

	wrapper := NewStreamingWrapper(tool)

	// Should not support streaming (it's a wrapper)
	assert.False(t, wrapper.SupportsStreaming())

	input, err := structpb.NewStruct(map[string]interface{}{})
	require.NoError(t, err)

	result := wrapper.StreamExecute(context.Background(), input)

	// Should receive single chunk
	chunks := 0
	for chunk := range result.Chunks {
		chunks++
		assert.True(t, chunk.IsFinal)
		assert.NoError(t, chunk.Error)
	}

	assert.Equal(t, 1, chunks)
}

func TestRetryConfig_IsRetryable(t *testing.T) {
	config := RetryConfig{
		RetryableErrors: []types.ErrorCode{
			ErrToolExecutionFailed,
		},
	}

	t.Run("retryable gibson error with flag", func(t *testing.T) {
		err := &types.GibsonError{
			Code:      ErrToolInvalidInput,
			Retryable: true,
		}
		assert.True(t, config.isRetryable(err))
	})

	t.Run("retryable gibson error with code", func(t *testing.T) {
		err := &types.GibsonError{
			Code:      ErrToolExecutionFailed,
			Retryable: false,
		}
		assert.True(t, config.isRetryable(err))
	})

	t.Run("non-retryable gibson error", func(t *testing.T) {
		err := &types.GibsonError{
			Code:      ErrToolInvalidInput,
			Retryable: false,
		}
		assert.False(t, config.isRetryable(err))
	})

	t.Run("non-gibson error", func(t *testing.T) {
		err := errors.New("some error")
		assert.False(t, config.isRetryable(err))
	})

	t.Run("nil error", func(t *testing.T) {
		assert.False(t, config.isRetryable(nil))
	})
}
