package checkpoint

import "errors"

// Common errors for checkpoint operations.
var (
	// ErrChecksumMissing is returned when a checkpoint is missing a checksum.
	ErrChecksumMissing = errors.New("checkpoint checksum is missing")

	// ErrChecksumMismatch is returned when a checkpoint's checksum doesn't match the computed value.
	ErrChecksumMismatch = errors.New("checkpoint checksum mismatch")

	// ErrCheckpointNotFound is returned when a requested checkpoint doesn't exist.
	ErrCheckpointNotFound = errors.New("checkpoint not found")

	// ErrInvalidCheckpoint is returned when a checkpoint structure is invalid.
	ErrInvalidCheckpoint = errors.New("invalid checkpoint")

	// ErrSerializationFailed is returned when serialization fails.
	ErrSerializationFailed = errors.New("serialization failed")

	// ErrDeserializationFailed is returned when deserialization fails.
	ErrDeserializationFailed = errors.New("deserialization failed")

	// ErrDecryptionFailed is returned when decryption fails.
	ErrDecryptionFailed = errors.New("decryption failed")

	// ErrEncryptionFailed is returned when encryption fails.
	ErrEncryptionFailed = errors.New("encryption failed")

	// ErrCompressionFailed is returned when compression fails.
	ErrCompressionFailed = errors.New("compression failed")

	// ErrDecompressionFailed is returned when decompression fails.
	ErrDecompressionFailed = errors.New("decompression failed")

	// ErrThreadNotFound is returned when a thread doesn't exist.
	ErrThreadNotFound = errors.New("thread not found")

	// ErrBlobNotFound is returned when a requested blob doesn't exist.
	ErrBlobNotFound = errors.New("blob not found")

	// ErrInvalidMissionID is returned when a mission ID is invalid or empty.
	ErrInvalidMissionID = errors.New("invalid mission ID")

	// ErrInvalidThreadID is returned when a thread ID is invalid or empty.
	ErrInvalidThreadID = errors.New("invalid thread ID")

	// ErrInvalidCheckpointID is returned when a checkpoint ID is invalid or empty.
	ErrInvalidCheckpointID = errors.New("invalid checkpoint ID")
)
