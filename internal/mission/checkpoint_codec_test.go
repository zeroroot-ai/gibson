package mission

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSerializeMissionState(t *testing.T) {
	t.Run("valid state", func(t *testing.T) {
		state := map[string]any{
			"mission_definition_id": "test-id",
			"status":                "running",
			"node_states": map[string]any{
				"node1": "completed",
				"node2": "pending",
			},
		}

		data, err := SerializeMissionState(state)
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		// Verify it's valid JSON with envelope
		var envelope checkpointEnvelope
		err = json.Unmarshal(data, &envelope)
		require.NoError(t, err)
		assert.Equal(t, CheckpointCodecVersion, envelope.Version)
		assert.Equal(t, state, envelope.Data)
	})

	t.Run("nil state", func(t *testing.T) {
		_, err := SerializeMissionState(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "mission state cannot be nil")
	})

	t.Run("empty state", func(t *testing.T) {
		state := map[string]any{}
		data, err := SerializeMissionState(state)
		require.NoError(t, err)
		assert.NotEmpty(t, data)
	})
}

func TestDeserializeMissionState(t *testing.T) {
	t.Run("valid data", func(t *testing.T) {
		original := map[string]any{
			"mission_definition_id": "test-id",
			"status":                "running",
			"node_states": map[string]any{
				"node1": "completed",
			},
		}

		// Serialize first
		data, err := SerializeMissionState(original)
		require.NoError(t, err)

		// Deserialize
		restored, err := DeserializeMissionState(data)
		require.NoError(t, err)
		assert.Equal(t, original["mission_definition_id"], restored["mission_definition_id"])
		assert.Equal(t, original["status"], restored["status"])
	})

	t.Run("invalid JSON", func(t *testing.T) {
		_, err := DeserializeMissionState([]byte("invalid json"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unmarshal")
	})

	t.Run("empty data", func(t *testing.T) {
		_, err := DeserializeMissionState([]byte{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be empty")
	})

	t.Run("newer version", func(t *testing.T) {
		data := []byte(`{"version": 999, "data": {}}`)
		_, err := DeserializeMissionState(data)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "newer than supported")
	})
}

func TestSerializeDeserializeMissionState_RoundTrip(t *testing.T) {
	original := map[string]any{
		"mission_definition_id": "test-mission-id",
		"status":                "running",
		"node_states": map[string]any{
			"node1": map[string]any{
				"status":      "completed",
				"retry_count": float64(0),
			},
			"node2": map[string]any{
				"status":      "running",
				"retry_count": float64(1),
			},
		},
		"execution_order": []any{"node1", "node2", "node3"},
		"started_at":      "2024-01-01T00:00:00Z",
	}

	// Serialize
	data, err := SerializeMissionState(original)
	require.NoError(t, err)

	// Deserialize
	restored, err := DeserializeMissionState(data)
	require.NoError(t, err)

	// Verify all fields
	assert.Equal(t, original["mission_definition_id"], restored["mission_definition_id"])
	assert.Equal(t, original["status"], restored["status"])
	assert.Equal(t, original["started_at"], restored["started_at"])

	// Verify node states
	nodeStates, ok := restored["node_states"].(map[string]any)
	require.True(t, ok)
	assert.Len(t, nodeStates, 2)

	// Verify execution order
	execOrder, ok := restored["execution_order"].([]any)
	require.True(t, ok)
	assert.Len(t, execOrder, 3)
}

func TestComputeChecksum(t *testing.T) {
	t.Run("produces consistent checksums", func(t *testing.T) {
		data := []byte("test data for checksum")
		checksum1 := ComputeChecksum(data)
		checksum2 := ComputeChecksum(data)

		assert.Equal(t, checksum1, checksum2)
		assert.Len(t, checksum1, 64) // SHA256 produces 64 hex characters
	})

	t.Run("different data produces different checksums", func(t *testing.T) {
		data1 := []byte("test data 1")
		data2 := []byte("test data 2")

		checksum1 := ComputeChecksum(data1)
		checksum2 := ComputeChecksum(data2)

		assert.NotEqual(t, checksum1, checksum2)
	})

	t.Run("known hash values", func(t *testing.T) {
		// SHA256 of "hello world" is known
		data := []byte("hello world")
		expected := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

		checksum := ComputeChecksum(data)
		assert.Equal(t, expected, checksum)
	})
}

func TestValidateChecksum(t *testing.T) {
	t.Run("valid checksum passes", func(t *testing.T) {
		data := []byte("test data for validation")
		checksum := ComputeChecksum(data)

		err := ValidateChecksum(data, checksum)
		assert.NoError(t, err)
	})

	t.Run("invalid checksum fails", func(t *testing.T) {
		data := []byte("test data for validation")
		fakeChecksum := "0000000000000000000000000000000000000000000000000000000000000000"

		err := ValidateChecksum(data, fakeChecksum)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "checksum mismatch")
	})

	t.Run("corrupted data detected", func(t *testing.T) {
		data := []byte("test data for validation")
		checksum := ComputeChecksum(data)

		// Modify data
		corruptedData := []byte("test data for validatioN") // Changed last character

		err := ValidateChecksum(corruptedData, checksum)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "checksum mismatch")
	})

	t.Run("empty checksum fails", func(t *testing.T) {
		data := []byte("test data")

		err := ValidateChecksum(data, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected checksum cannot be empty")
	})

	t.Run("empty data fails", func(t *testing.T) {
		err := ValidateChecksum([]byte{}, "somechecksum")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "checkpoint data cannot be empty")
	})
}

func TestComputeChecksum_Consistency(t *testing.T) {
	// Create state map
	stateMap := map[string]any{
		"mission_definition_id": "test-id",
		"status":                "running",
		"node_states": map[string]any{
			"node1": map[string]any{
				"status":       "completed",
				"retry_count":  0,
				"completed_at": "2024-01-01T00:00:00Z",
			},
		},
		"started_at": "2024-01-01T00:00:00Z",
	}

	// Serialize multiple times and verify checksums match
	checksums := make([]string, 3)
	for i := 0; i < 3; i++ {
		data, err := SerializeMissionState(stateMap)
		require.NoError(t, err)
		checksums[i] = ComputeChecksum(data)
	}

	// All checksums should be identical
	assert.Equal(t, checksums[0], checksums[1])
	assert.Equal(t, checksums[0], checksums[2])
}

func TestValidateChecksum_DetectsBitFlip(t *testing.T) {
	// Original data
	data := []byte("This is important checkpoint data that must not be corrupted")
	checksum := ComputeChecksum(data)

	// Verify original is valid
	err := ValidateChecksum(data, checksum)
	require.NoError(t, err)

	// Simulate a single bit flip (change one byte)
	corruptedData := make([]byte, len(data))
	copy(corruptedData, data)
	corruptedData[len(corruptedData)/2] ^= 0x01 // Flip lowest bit

	// Validation should detect corruption
	err = ValidateChecksum(corruptedData, checksum)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "checksum mismatch")
}
