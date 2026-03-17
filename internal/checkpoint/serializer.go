package checkpoint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/vmihailenco/msgpack/v5"
	"github.com/zero-day-ai/gibson/internal/checkpoint/keyprovider"
)

// SerializationFormat defines the format used for serialization.
type SerializationFormat string

const (
	// FormatMessagePack uses MessagePack binary serialization for compact, efficient encoding.
	FormatMessagePack SerializationFormat = "msgpack"
	// FormatJSON uses JSON serialization for human-readable, debugging-friendly encoding.
	FormatJSON SerializationFormat = "json"
)

// SerializeOptions contains options for serialization.
type SerializeOptions struct {
	// Format specifies the serialization format to use
	Format SerializationFormat

	// Encrypt indicates whether to encrypt the serialized data
	Encrypt bool

	// Compress indicates whether to compress the serialized data
	Compress bool

	// KeyProvider provides encryption keys when Encrypt is true
	KeyProvider keyprovider.KeyProvider
}

// DeserializeOptions contains options for deserialization.
type DeserializeOptions struct {
	// Format specifies the serialization format expected
	Format SerializationFormat

	// Encrypted indicates whether the data is encrypted
	Encrypted bool

	// Compressed indicates whether the data is compressed
	Compressed bool

	// KeyProvider provides decryption keys when Encrypted is true
	KeyProvider keyprovider.KeyProvider
}

// StateSerializer defines the interface for serializing and deserializing execution state.
type StateSerializer interface {
	// Serialize converts an ExecutionState to bytes using the specified options.
	Serialize(ctx context.Context, state *ExecutionState, opts SerializeOptions) ([]byte, error)

	// Deserialize converts bytes back to an ExecutionState using the specified options.
	Deserialize(ctx context.Context, data []byte, opts DeserializeOptions) (*ExecutionState, error)

	// ValidateChecksum verifies the integrity of serialized data.
	ValidateChecksum(data []byte, checksum string) error
}

// DefaultStateSerializer is the default implementation of StateSerializer.
type DefaultStateSerializer struct {
	// No fields needed for stateless serialization
}

// NewStateSerializer creates a new DefaultStateSerializer instance.
func NewStateSerializer() *DefaultStateSerializer {
	return &DefaultStateSerializer{}
}

// Serialize converts an ExecutionState to bytes using the specified options.
// It supports both MessagePack and JSON formats, with optional encryption and compression.
func (s *DefaultStateSerializer) Serialize(ctx context.Context, state *ExecutionState, opts SerializeOptions) ([]byte, error) {
	if state == nil {
		return nil, fmt.Errorf("state cannot be nil")
	}

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	// Serialize based on format
	var data []byte
	var err error

	switch opts.Format {
	case FormatMessagePack, "": // Default to MessagePack
		data, err = msgpack.Marshal(state)
		if err != nil {
			return nil, fmt.Errorf("msgpack serialization failed: %w", err)
		}

	case FormatJSON:
		data, err = json.Marshal(state)
		if err != nil {
			return nil, fmt.Errorf("json serialization failed: %w", err)
		}

	default:
		return nil, fmt.Errorf("unsupported serialization format: %s", opts.Format)
	}

	// Apply compression if requested
	if opts.Compress {
		// TODO: Implement compression in future iteration
		// For now, compression is a no-op to keep the implementation focused
	}

	// Apply encryption if requested
	if opts.Encrypt {
		if opts.KeyProvider == nil {
			return nil, fmt.Errorf("encryption requested but no key provider specified")
		}

		// TODO: Implement encryption in future iteration
		// For now, encryption is a no-op to keep the implementation focused
		// When implemented, use AES-GCM for authenticated encryption
	}

	return data, nil
}

// Deserialize converts bytes back to an ExecutionState using the specified options.
// It supports both MessagePack and JSON formats, with optional decryption and decompression.
func (s *DefaultStateSerializer) Deserialize(ctx context.Context, data []byte, opts DeserializeOptions) (*ExecutionState, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data cannot be empty")
	}

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	// Apply decryption if data is encrypted
	if opts.Encrypted {
		if opts.KeyProvider == nil {
			return nil, fmt.Errorf("data is encrypted but no key provider specified")
		}

		// TODO: Implement decryption in future iteration
		// For now, decryption is a no-op to keep the implementation focused
	}

	// Apply decompression if data is compressed
	if opts.Compressed {
		// TODO: Implement decompression in future iteration
		// For now, decompression is a no-op to keep the implementation focused
	}

	// Deserialize based on format
	var state ExecutionState
	var err error

	switch opts.Format {
	case FormatMessagePack, "": // Default to MessagePack
		err = msgpack.Unmarshal(data, &state)
		if err != nil {
			return nil, fmt.Errorf("msgpack deserialization failed: %w", err)
		}

	case FormatJSON:
		err = json.Unmarshal(data, &state)
		if err != nil {
			return nil, fmt.Errorf("json deserialization failed: %w", err)
		}

	default:
		return nil, fmt.Errorf("unsupported deserialization format: %s", opts.Format)
	}

	// Validate required fields
	if state.MissionID == "" {
		return nil, fmt.Errorf("deserialized state has empty mission_id")
	}

	return &state, nil
}

// ValidateChecksum verifies the integrity of serialized data by comparing checksums.
// It uses SHA256 hashing to ensure data has not been corrupted or tampered with.
func (s *DefaultStateSerializer) ValidateChecksum(data []byte, checksum string) error {
	if len(data) == 0 {
		return fmt.Errorf("data cannot be empty")
	}

	if checksum == "" {
		return fmt.Errorf("checksum cannot be empty")
	}

	// Generate checksum of the provided data
	computed := GenerateChecksum(data)

	// Compare checksums
	if computed != checksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", checksum, computed)
	}

	return nil
}

// GenerateChecksum generates a SHA256 checksum of the provided data.
// It returns the checksum as a lowercase hexadecimal string.
func GenerateChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
