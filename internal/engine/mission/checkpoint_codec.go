package mission

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// CheckpointCodecVersion defines the version of the checkpoint serialization format.
// This is used to ensure compatibility when deserializing checkpoints created
// by different versions of the software.
const CheckpointCodecVersion = 1

// checkpointEnvelope wraps the serialized checkpoint data with version information
// for future compatibility and integrity checking.
type checkpointEnvelope struct {
	// Version is the codec version used to serialize this checkpoint
	Version int `json:"version"`

	// Data contains the serialized mission state
	Data map[string]any `json:"data"`
}

// SerializeMissionState serializes a mission state map to JSON bytes with version information.
// The state is wrapped in an envelope that includes the codec version for future compatibility.
// Returns the serialized bytes or an error if serialization fails.
func SerializeMissionState(state map[string]any) ([]byte, error) {
	if state == nil {
		return nil, fmt.Errorf("mission state cannot be nil")
	}

	// Wrap state in versioned envelope
	envelope := checkpointEnvelope{
		Version: CheckpointCodecVersion,
		Data:    state,
	}

	// Serialize to JSON with consistent formatting
	data, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal mission state: %w", err)
	}

	return data, nil
}

// DeserializeMissionState deserializes JSON bytes back into a mission state map.
// It validates the version and extracts the state data from the envelope.
// Returns the mission state map or an error if deserialization fails or version is incompatible.
func DeserializeMissionState(data []byte) (map[string]any, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("checkpoint data cannot be empty")
	}

	var envelope checkpointEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("failed to unmarshal checkpoint envelope: %w", err)
	}

	// Version compatibility check
	if envelope.Version > CheckpointCodecVersion {
		return nil, fmt.Errorf("checkpoint version %d is newer than supported version %d - please upgrade Gibson",
			envelope.Version, CheckpointCodecVersion)
	}

	// Future: handle version-specific migrations here when codec version changes
	// For now, version 1 is the only supported version
	if envelope.Version < 1 {
		return nil, fmt.Errorf("checkpoint version %d is not supported (minimum version 1)", envelope.Version)
	}

	if envelope.Data == nil {
		return nil, fmt.Errorf("checkpoint data field is nil")
	}

	return envelope.Data, nil
}

// ComputeChecksum computes a SHA256 checksum of the checkpoint data for integrity verification.
// The checksum is returned as a hexadecimal string.
func ComputeChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// ValidateChecksum validates that the computed checksum of the data matches the expected checksum.
// Returns nil if the checksums match, or an error describing the validation failure.
func ValidateChecksum(data []byte, expected string) error {
	if len(expected) == 0 {
		return fmt.Errorf("expected checksum cannot be empty")
	}

	if len(data) == 0 {
		return fmt.Errorf("checkpoint data cannot be empty")
	}

	computed := ComputeChecksum(data)
	if computed != expected {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expected, computed)
	}

	return nil
}
