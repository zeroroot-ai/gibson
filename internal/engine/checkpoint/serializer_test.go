package checkpoint

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// createTestExecutionState creates a test execution state with various data types.
func createTestExecutionState() *ExecutionState {
	now := time.Now()
	state := NewExecutionState(types.NewID(), "thread-456")

	state.CurrentNodeID = "node-1"

	// Add node states
	state.NodeStates["node-1"] = &NodeState{
		NodeID:      "node-1",
		Status:      NodeStatusRunning,
		StartedAt:   &now,
		RetryCount:  0,
		RetryParams: map[string]any{"timeout": 30},
		Duration:    5 * time.Second,
	}

	state.NodeStates["node-2"] = &NodeState{
		NodeID:     "node-2",
		Status:     NodeStatusPending,
		RetryCount: 0,
	}

	// Add completed results
	state.CompletedResults["node-0"] = &NodeOutput{
		NodeID:      "node-0",
		Status:      "completed",
		Output:      map[string]any{"result": "success", "count": 42},
		Duration:    10 * time.Second,
		CompletedAt: now,
	}

	// Set pending queue
	state.PendingQueue = []string{"node-2", "node-3"}

	// Set working memory with various types
	state.WorkingMemory["string_key"] = "string_value"
	state.WorkingMemory["int_key"] = 123
	state.WorkingMemory["float_key"] = 45.67
	state.WorkingMemory["bool_key"] = true
	state.WorkingMemory["array_key"] = []any{1, 2, 3}
	state.WorkingMemory["map_key"] = map[string]any{"nested": "value"}

	// Set mission memory
	state.MissionMemory["target"] = "192.168.1.100"
	state.MissionMemory["discovered_ports"] = []any{80, 443, 8080}

	// Add conversation history
	state.ConversationHistory = []llm.Message{
		{Role: llm.RoleUser, Content: "Start the mission"},
		{Role: llm.RoleAssistant, Content: "Starting reconnaissance"},
	}

	// Set DAG state
	state.DAGState = &DAGTraversalState{
		PendingNodes:   []string{"node-2", "node-3"},
		CurrentBranch:  "main",
		ParallelState:  map[string][]string{"group-1": {"node-0"}},
		VisitedNodes:   []string{"node-0", "node-1"},
		ExecutionOrder: []string{"node-0", "node-1"},
	}

	// Add findings
	state.Findings = []types.ID{types.NewID(), types.NewID()}

	// Set metadata
	state.Metadata["user"] = "test-user"
	state.Metadata["environment"] = "test"

	return state
}

func TestSerializer_MsgpackRoundTrip(t *testing.T) {
	t.Parallel()

	serializer := NewStateSerializer()
	state := createTestExecutionState()
	ctx := context.Background()

	opts := SerializeOptions{
		Format:   FormatMessagePack,
		Encrypt:  false,
		Compress: false,
	}

	// Serialize
	data, err := serializer.Serialize(ctx, state, opts)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Deserialize
	deserializeOpts := DeserializeOptions{
		Format:     FormatMessagePack,
		Encrypted:  false,
		Compressed: false,
	}

	restored, err := serializer.Deserialize(ctx, data, deserializeOpts)
	require.NoError(t, err)
	require.NotNil(t, restored)

	// Verify all fields
	assert.Equal(t, state.MissionID, restored.MissionID)
	assert.Equal(t, state.ThreadID, restored.ThreadID)
	assert.Equal(t, state.CurrentNodeID, restored.CurrentNodeID)
	assert.Equal(t, len(state.NodeStates), len(restored.NodeStates))
	assert.Equal(t, len(state.CompletedResults), len(restored.CompletedResults))
	assert.Equal(t, state.PendingQueue, restored.PendingQueue)
	assert.Equal(t, len(state.WorkingMemory), len(restored.WorkingMemory))
	assert.Equal(t, len(state.MissionMemory), len(restored.MissionMemory))
	assert.Equal(t, len(state.ConversationHistory), len(restored.ConversationHistory))
	assert.Equal(t, state.Findings, restored.Findings)
}

func TestSerializer_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	serializer := NewStateSerializer()
	state := createTestExecutionState()
	ctx := context.Background()

	opts := SerializeOptions{
		Format:   FormatJSON,
		Encrypt:  false,
		Compress: false,
	}

	// Serialize
	data, err := serializer.Serialize(ctx, state, opts)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Verify the payload (after stripping the 1-byte format header) is valid JSON.
	// The serializer always prepends a header byte even for plain formats;
	// data[0] is headerRaw (0x00) here, data[1:] is the actual JSON.
	var jsonCheck map[string]any
	err = json.Unmarshal(data[1:], &jsonCheck)
	require.NoError(t, err)

	// Deserialize
	deserializeOpts := DeserializeOptions{
		Format:     FormatJSON,
		Encrypted:  false,
		Compressed: false,
	}

	restored, err := serializer.Deserialize(ctx, data, deserializeOpts)
	require.NoError(t, err)
	require.NotNil(t, restored)

	// Verify critical fields
	assert.Equal(t, state.MissionID, restored.MissionID)
	assert.Equal(t, state.ThreadID, restored.ThreadID)
	assert.Equal(t, state.CurrentNodeID, restored.CurrentNodeID)
}

func TestSerializer_ChecksumGeneration(t *testing.T) {
	t.Parallel()

	testData := []byte("test checkpoint data")

	checksum := GenerateChecksum(testData)

	// Verify checksum is non-empty
	assert.NotEmpty(t, checksum)

	// Verify checksum is hex string (64 chars for SHA256)
	assert.Len(t, checksum, 64)

	// Verify checksum is deterministic
	checksum2 := GenerateChecksum(testData)
	assert.Equal(t, checksum, checksum2)
}

func TestSerializer_ChecksumValidation(t *testing.T) {
	t.Parallel()

	serializer := NewStateSerializer()
	testData := []byte("test checkpoint data")
	checksum := GenerateChecksum(testData)

	// Valid checksum should pass
	err := serializer.ValidateChecksum(testData, checksum)
	assert.NoError(t, err)
}

func TestSerializer_InvalidChecksum(t *testing.T) {
	t.Parallel()

	serializer := NewStateSerializer()
	testData := []byte("test checkpoint data")
	invalidChecksum := "0000000000000000000000000000000000000000000000000000000000000000"

	// Invalid checksum should fail
	err := serializer.ValidateChecksum(testData, invalidChecksum)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checksum mismatch")
}

func TestSerializer_LargeState(t *testing.T) {
	t.Parallel()

	serializer := NewStateSerializer()
	ctx := context.Background()

	// Create a state with large data
	state := createTestExecutionState()

	// Add large working memory
	for i := 0; i < 1000; i++ {
		key := "large_key_" + string(rune(i))
		value := strings.Repeat("data", 100)
		state.WorkingMemory[key] = value
	}

	// Add many conversation messages
	for i := 0; i < 500; i++ {
		state.ConversationHistory = append(state.ConversationHistory, llm.Message{
			Role:    llm.RoleUser,
			Content: "Message " + string(rune(i)),
		})
	}

	opts := SerializeOptions{
		Format:   FormatMessagePack,
		Encrypt:  false,
		Compress: false,
	}

	// Serialize large state
	data, err := serializer.Serialize(ctx, state, opts)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Deserialize
	deserializeOpts := DeserializeOptions{
		Format:     FormatMessagePack,
		Encrypted:  false,
		Compressed: false,
	}

	restored, err := serializer.Deserialize(ctx, data, deserializeOpts)
	require.NoError(t, err)
	require.NotNil(t, restored)

	// Verify sizes match
	assert.Equal(t, len(state.WorkingMemory), len(restored.WorkingMemory))
	assert.Equal(t, len(state.ConversationHistory), len(restored.ConversationHistory))
}

func TestSerializer_EmptyState(t *testing.T) {
	t.Parallel()

	serializer := NewStateSerializer()
	ctx := context.Background()

	// Create minimal state
	state := NewExecutionState(types.NewID(), "thread-empty")

	opts := SerializeOptions{
		Format:   FormatMessagePack,
		Encrypt:  false,
		Compress: false,
	}

	// Serialize
	data, err := serializer.Serialize(ctx, state, opts)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Deserialize
	deserializeOpts := DeserializeOptions{
		Format:     FormatMessagePack,
		Encrypted:  false,
		Compressed: false,
	}

	restored, err := serializer.Deserialize(ctx, data, deserializeOpts)
	require.NoError(t, err)
	require.NotNil(t, restored)

	assert.Equal(t, state.MissionID, restored.MissionID)
	assert.Equal(t, state.ThreadID, restored.ThreadID)
}

func TestSerializer_NestedStructures(t *testing.T) {
	t.Parallel()

	serializer := NewStateSerializer()
	ctx := context.Background()

	state := NewExecutionState(types.NewID(), "thread-nested")

	// Create deeply nested structures
	state.WorkingMemory["nested"] = map[string]any{
		"level1": map[string]any{
			"level2": map[string]any{
				"level3": map[string]any{
					"deep_value": "found",
					"deep_array": []any{1, 2, 3, map[string]any{"inner": "value"}},
				},
			},
		},
		"arrays": []any{
			[]any{1, 2, 3},
			[]any{"a", "b", "c"},
			[]any{
				map[string]any{"nested_in_array": true},
			},
		},
	}

	opts := SerializeOptions{
		Format:   FormatMessagePack,
		Encrypt:  false,
		Compress: false,
	}

	// Serialize
	data, err := serializer.Serialize(ctx, state, opts)
	require.NoError(t, err)

	// Deserialize
	deserializeOpts := DeserializeOptions{
		Format:     FormatMessagePack,
		Encrypted:  false,
		Compressed: false,
	}

	restored, err := serializer.Deserialize(ctx, data, deserializeOpts)
	require.NoError(t, err)

	// Verify nested structure is preserved
	assert.NotNil(t, restored.WorkingMemory["nested"])
}

func TestSerializer_NilFields(t *testing.T) {
	t.Parallel()

	serializer := NewStateSerializer()
	ctx := context.Background()

	state := NewExecutionState(types.NewID(), "thread-nil")

	// Set some fields to nil explicitly
	state.WorkingMemory = nil
	state.MissionMemory = nil
	state.ConversationHistory = nil
	state.DAGState = nil
	state.InProgress = nil

	opts := SerializeOptions{
		Format:   FormatMessagePack,
		Encrypt:  false,
		Compress: false,
	}

	// Serialize
	data, err := serializer.Serialize(ctx, state, opts)
	require.NoError(t, err)

	// Deserialize
	deserializeOpts := DeserializeOptions{
		Format:     FormatMessagePack,
		Encrypted:  false,
		Compressed: false,
	}

	restored, err := serializer.Deserialize(ctx, data, deserializeOpts)
	require.NoError(t, err)

	// Nil fields should be restored as nil or empty
	assert.Equal(t, state.MissionID, restored.MissionID)
}

func TestSerializer_NilState(t *testing.T) {
	t.Parallel()

	serializer := NewStateSerializer()
	ctx := context.Background()

	opts := SerializeOptions{
		Format:   FormatMessagePack,
		Encrypt:  false,
		Compress: false,
	}

	// Serialize nil state should fail
	_, err := serializer.Serialize(ctx, nil, opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "state cannot be nil")
}

func TestSerializer_EmptyData(t *testing.T) {
	t.Parallel()

	serializer := NewStateSerializer()
	ctx := context.Background()

	deserializeOpts := DeserializeOptions{
		Format:     FormatMessagePack,
		Encrypted:  false,
		Compressed: false,
	}

	// Deserialize empty data should fail
	_, err := serializer.Deserialize(ctx, []byte{}, deserializeOpts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "data cannot be empty")
}

func TestSerializer_InvalidFormat(t *testing.T) {
	t.Parallel()

	serializer := NewStateSerializer()
	ctx := context.Background()
	state := createTestExecutionState()

	opts := SerializeOptions{
		Format:   SerializationFormat("invalid"),
		Encrypt:  false,
		Compress: false,
	}

	// Serialize with invalid format should fail
	_, err := serializer.Serialize(ctx, state, opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported serialization format")
}

func TestSerializer_CancelledContext(t *testing.T) {
	t.Parallel()

	serializer := NewStateSerializer()
	state := createTestExecutionState()

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	opts := SerializeOptions{
		Format:   FormatMessagePack,
		Encrypt:  false,
		Compress: false,
	}

	// Serialize with cancelled context should fail
	_, err := serializer.Serialize(ctx, state, opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context cancelled")
}

func TestSerializer_DefaultFormat(t *testing.T) {
	t.Parallel()

	serializer := NewStateSerializer()
	ctx := context.Background()
	state := createTestExecutionState()

	// Use empty format (should default to MessagePack)
	opts := SerializeOptions{
		Format:   "",
		Encrypt:  false,
		Compress: false,
	}

	data, err := serializer.Serialize(ctx, state, opts)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Should be able to deserialize with MessagePack
	deserializeOpts := DeserializeOptions{
		Format:     FormatMessagePack,
		Encrypted:  false,
		Compressed: false,
	}

	restored, err := serializer.Deserialize(ctx, data, deserializeOpts)
	require.NoError(t, err)
	assert.Equal(t, state.MissionID, restored.MissionID)
}

func TestSerializer_ValidateChecksumErrors(t *testing.T) {
	t.Parallel()

	serializer := NewStateSerializer()

	t.Run("empty data", func(t *testing.T) {
		err := serializer.ValidateChecksum([]byte{}, "checksum")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "data cannot be empty")
	})

	t.Run("empty checksum", func(t *testing.T) {
		err := serializer.ValidateChecksum([]byte("data"), "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "checksum cannot be empty")
	})
}

func TestSerializer_MissingMissionID(t *testing.T) {
	t.Parallel()

	serializer := NewStateSerializer()
	ctx := context.Background()

	// Create state without mission ID
	state := &ExecutionState{
		MissionID: "",
		ThreadID:  "thread-123",
	}

	opts := SerializeOptions{
		Format:   FormatMessagePack,
		Encrypt:  false,
		Compress: false,
	}

	// Serialize (should work)
	data, err := serializer.Serialize(ctx, state, opts)
	require.NoError(t, err)

	// Deserialize should fail validation
	deserializeOpts := DeserializeOptions{
		Format:     FormatMessagePack,
		Encrypted:  false,
		Compressed: false,
	}

	_, err = serializer.Deserialize(ctx, data, deserializeOpts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty mission_id")
}

func TestSerializer_Formats(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		format SerializationFormat
	}{
		{
			name:   "msgpack format",
			format: FormatMessagePack,
		},
		{
			name:   "json format",
			format: FormatJSON,
		},
	}

	serializer := NewStateSerializer()
	ctx := context.Background()
	state := createTestExecutionState()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := SerializeOptions{
				Format:   tt.format,
				Encrypt:  false,
				Compress: false,
			}

			// Serialize
			data, err := serializer.Serialize(ctx, state, opts)
			require.NoError(t, err)
			require.NotEmpty(t, data)

			// Deserialize
			deserializeOpts := DeserializeOptions{
				Format:     tt.format,
				Encrypted:  false,
				Compressed: false,
			}

			restored, err := serializer.Deserialize(ctx, data, deserializeOpts)
			require.NoError(t, err)
			assert.Equal(t, state.MissionID, restored.MissionID)
		})
	}
}

// Benchmark tests
func BenchmarkSerializer_Msgpack(b *testing.B) {
	serializer := NewStateSerializer()
	ctx := context.Background()
	state := createTestExecutionState()

	opts := SerializeOptions{
		Format:   FormatMessagePack,
		Encrypt:  false,
		Compress: false,
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		data, err := serializer.Serialize(ctx, state, opts)
		if err != nil {
			b.Fatal(err)
		}
		b.SetBytes(int64(len(data)))
	}
}

func BenchmarkSerializer_JSON(b *testing.B) {
	serializer := NewStateSerializer()
	ctx := context.Background()
	state := createTestExecutionState()

	opts := SerializeOptions{
		Format:   FormatJSON,
		Encrypt:  false,
		Compress: false,
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		data, err := serializer.Serialize(ctx, state, opts)
		if err != nil {
			b.Fatal(err)
		}
		b.SetBytes(int64(len(data)))
	}
}

func BenchmarkSerializer_MsgpackDeserialize(b *testing.B) {
	serializer := NewStateSerializer()
	ctx := context.Background()
	state := createTestExecutionState()

	opts := SerializeOptions{
		Format:   FormatMessagePack,
		Encrypt:  false,
		Compress: false,
	}

	data, err := serializer.Serialize(ctx, state, opts)
	if err != nil {
		b.Fatal(err)
	}

	deserializeOpts := DeserializeOptions{
		Format:     FormatMessagePack,
		Encrypted:  false,
		Compressed: false,
	}

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		_, err := serializer.Deserialize(ctx, data, deserializeOpts)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSerializer_JSONDeserialize(b *testing.B) {
	serializer := NewStateSerializer()
	ctx := context.Background()
	state := createTestExecutionState()

	opts := SerializeOptions{
		Format:   FormatJSON,
		Encrypt:  false,
		Compress: false,
	}

	data, err := serializer.Serialize(ctx, state, opts)
	if err != nil {
		b.Fatal(err)
	}

	deserializeOpts := DeserializeOptions{
		Format:     FormatJSON,
		Encrypted:  false,
		Compressed: false,
	}

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		_, err := serializer.Deserialize(ctx, data, deserializeOpts)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateChecksum(b *testing.B) {
	data := make([]byte, 1024*1024) // 1MB
	_, _ = rand.Read(data)

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		_ = GenerateChecksum(data)
	}
}

func BenchmarkValidateChecksum(b *testing.B) {
	serializer := NewStateSerializer()
	data := make([]byte, 1024*1024) // 1MB
	_, _ = rand.Read(data)
	checksum := GenerateChecksum(data)

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		_ = serializer.ValidateChecksum(data, checksum)
	}
}
