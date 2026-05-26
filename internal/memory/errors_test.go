package memory

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// TestNewWorkingMemoryFullError tests working memory full error creation
func TestNewWorkingMemoryFullError(t *testing.T) {
	message := "memory is full"
	err := NewWorkingMemoryFullError(message)

	require.NotNil(t, err)
	assert.Equal(t, ErrCodeWorkingMemoryFull, err.Code)
	assert.Equal(t, message, err.Message)
	assert.Contains(t, err.Error(), string(ErrCodeWorkingMemoryFull))
	assert.Contains(t, err.Error(), message)
}

// TestNewTokenLimitExceededError tests token limit exceeded error creation
func TestNewTokenLimitExceededError(t *testing.T) {
	message := "token limit exceeded"
	err := NewTokenLimitExceededError(message)

	require.NotNil(t, err)
	assert.Equal(t, ErrCodeTokenLimitExceeded, err.Code)
	assert.Equal(t, message, err.Message)
}

// TestNewMissionMemoryNotFoundError tests mission memory not found error
func TestNewMissionMemoryNotFoundError(t *testing.T) {
	key := "test-key"
	err := NewMissionMemoryNotFoundError(key)

	require.NotNil(t, err)
	assert.Equal(t, ErrCodeMissionMemoryNotFound, err.Code)
	assert.Contains(t, err.Message, key)
	assert.Contains(t, err.Error(), key)
}

// TestNewMissionMemoryStoreError tests mission memory store error with cause
func TestNewMissionMemoryStoreError(t *testing.T) {
	message := "failed to store"
	cause := errors.New("database locked")
	err := NewMissionMemoryStoreError(message, cause)

	require.NotNil(t, err)
	assert.Equal(t, ErrCodeMissionMemoryStore, err.Code)
	assert.Equal(t, message, err.Message)
	assert.Equal(t, cause, err.Cause)
	assert.Contains(t, err.Error(), message)
	assert.Contains(t, err.Error(), cause.Error())
}

// TestNewFTSQueryError tests FTS query error with cause
func TestNewFTSQueryError(t *testing.T) {
	message := "invalid FTS query"
	cause := errors.New("syntax error")
	err := NewFTSQueryError(message, cause)

	require.NotNil(t, err)
	assert.Equal(t, ErrCodeFTSQueryFailed, err.Code)
	assert.Equal(t, message, err.Message)
	assert.Equal(t, cause, err.Cause)
}

// TestNewVectorStoreUnavailableError tests vector store unavailable error
func TestNewVectorStoreUnavailableError(t *testing.T) {
	message := "vector store is down"
	err := NewVectorStoreUnavailableError(message)

	require.NotNil(t, err)
	assert.Equal(t, ErrCodeVectorStoreUnavailable, err.Code)
	assert.Equal(t, message, err.Message)
}

// TestNewVectorNotFoundError tests vector not found error
func TestNewVectorNotFoundError(t *testing.T) {
	id := "vec-123"
	err := NewVectorNotFoundError(id)

	require.NotNil(t, err)
	assert.Equal(t, ErrCodeVectorNotFound, err.Code)
	assert.Contains(t, err.Message, id)
}

// TestNewVectorStoreError tests vector store error with cause
func TestNewVectorStoreError(t *testing.T) {
	message := "failed to store vector"
	cause := errors.New("connection timeout")
	err := NewVectorStoreError(message, cause)

	require.NotNil(t, err)
	assert.Equal(t, ErrCodeVectorStoreFailed, err.Code)
	assert.Equal(t, message, err.Message)
	assert.Equal(t, cause, err.Cause)
}

// TestNewVectorSearchError tests vector search error with cause
func TestNewVectorSearchError(t *testing.T) {
	message := "search failed"
	cause := errors.New("invalid query")
	err := NewVectorSearchError(message, cause)

	require.NotNil(t, err)
	assert.Equal(t, ErrCodeVectorSearchFailed, err.Code)
	assert.Equal(t, message, err.Message)
	assert.Equal(t, cause, err.Cause)
}

// TestNewEmbedderUnavailableError tests embedder unavailable error
func TestNewEmbedderUnavailableError(t *testing.T) {
	message := "embedder is offline"
	err := NewEmbedderUnavailableError(message)

	require.NotNil(t, err)
	assert.Equal(t, ErrCodeEmbedderUnavailable, err.Code)
	assert.Equal(t, message, err.Message)
}

// TestNewEmbeddingError tests embedding generation error with cause
func TestNewEmbeddingError(t *testing.T) {
	message := "failed to generate embedding"
	cause := errors.New("API rate limit")
	err := NewEmbeddingError(message, cause)

	require.NotNil(t, err)
	assert.Equal(t, ErrCodeEmbeddingFailed, err.Code)
	assert.Equal(t, message, err.Message)
	assert.Equal(t, cause, err.Cause)
}

// TestNewEmbeddingBatchError tests batch embedding error with cause
func TestNewEmbeddingBatchError(t *testing.T) {
	message := "batch embedding failed"
	cause := errors.New("network error")
	err := NewEmbeddingBatchError(message, cause)

	require.NotNil(t, err)
	assert.Equal(t, ErrCodeEmbeddingBatchFailed, err.Code)
	assert.Equal(t, message, err.Message)
	assert.Equal(t, cause, err.Cause)
}

// TestNewMemoryNotFoundError tests generic memory not found error
func TestNewMemoryNotFoundError(t *testing.T) {
	key := "missing-key"
	err := NewMemoryNotFoundError(key)

	require.NotNil(t, err)
	assert.Equal(t, ErrCodeMemoryNotFound, err.Code)
	assert.Contains(t, err.Message, key)
}

// TestNewInvalidConfigError tests invalid config error
func TestNewInvalidConfigError(t *testing.T) {
	message := "invalid configuration"
	err := NewInvalidConfigError(message)

	require.NotNil(t, err)
	assert.Equal(t, ErrCodeInvalidConfig, err.Code)
	assert.Equal(t, message, err.Message)
}

// TestNewInvalidMemoryItemError tests invalid memory item error
func TestNewInvalidMemoryItemError(t *testing.T) {
	message := "item validation failed"
	err := NewInvalidMemoryItemError(message)

	require.NotNil(t, err)
	assert.Equal(t, ErrCodeInvalidMemoryItem, err.Code)
	assert.Equal(t, message, err.Message)
}

// TestNewInvalidVectorRecordError tests invalid vector record error
func TestNewInvalidVectorRecordError(t *testing.T) {
	message := "record validation failed"
	err := NewInvalidVectorRecordError(message)

	require.NotNil(t, err)
	assert.Equal(t, ErrCodeInvalidVectorRecord, err.Code)
	assert.Equal(t, message, err.Message)
}

// TestNewInvalidVectorQueryError tests invalid vector query error
func TestNewInvalidVectorQueryError(t *testing.T) {
	message := "query validation failed"
	err := NewInvalidVectorQueryError(message)

	require.NotNil(t, err)
	assert.Equal(t, ErrCodeInvalidVectorQuery, err.Code)
	assert.Equal(t, message, err.Message)
}

// TestErrorCodes tests that all error codes are defined and unique
func TestErrorCodes(t *testing.T) {
	codes := []types.ErrorCode{
		ErrCodeWorkingMemoryFull,
		ErrCodeTokenLimitExceeded,
		ErrCodeMissionMemoryNotFound,
		ErrCodeMissionMemoryStore,
		ErrCodeFTSQueryFailed,
		ErrCodeVectorStoreUnavailable,
		ErrCodeVectorNotFound,
		ErrCodeVectorStoreFailed,
		ErrCodeVectorSearchFailed,
		ErrCodeEmbedderUnavailable,
		ErrCodeEmbeddingFailed,
		ErrCodeEmbeddingBatchFailed,
		ErrCodeMemoryNotFound,
		ErrCodeInvalidConfig,
		ErrCodeInvalidMemoryItem,
		ErrCodeInvalidVectorRecord,
		ErrCodeInvalidVectorQuery,
	}

	// Check all codes are non-empty
	for _, code := range codes {
		assert.NotEmpty(t, code, "error code should not be empty")
	}

	// Check all codes are unique
	codeSet := make(map[types.ErrorCode]bool)
	for _, code := range codes {
		assert.False(t, codeSet[code], "error code %s is duplicated", code)
		codeSet[code] = true
	}
}

// TestErrorWrapping tests that errors properly wrap causes
func TestErrorWrapping(t *testing.T) {
	cause := errors.New("underlying cause")

	tests := []struct {
		name string
		err  *types.GibsonError
	}{
		{
			name: "mission memory store error",
			err:  NewMissionMemoryStoreError("test", cause),
		},
		{
			name: "FTS query error",
			err:  NewFTSQueryError("test", cause),
		},
		{
			name: "vector store error",
			err:  NewVectorStoreError("test", cause),
		},
		{
			name: "vector search error",
			err:  NewVectorSearchError("test", cause),
		},
		{
			name: "embedding error",
			err:  NewEmbeddingError("test", cause),
		},
		{
			name: "embedding batch error",
			err:  NewEmbeddingBatchError("test", cause),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test Unwrap
			unwrapped := tt.err.Unwrap()
			assert.Equal(t, cause, unwrapped)

			// Test errors.Is
			assert.True(t, errors.Is(tt.err, cause))

			// Test error message includes cause
			assert.Contains(t, tt.err.Error(), cause.Error())
		})
	}
}

// TestErrorCodeMatching tests that error codes can be matched
func TestErrorCodeMatching(t *testing.T) {
	err1 := NewMissionMemoryNotFoundError("key1")
	err2 := NewMissionMemoryNotFoundError("key2")

	// Same error code should match via Is()
	assert.True(t, err1.Is(err2))
	assert.True(t, err2.Is(err1))

	// Different error codes should not match
	err3 := NewVectorNotFoundError("id")
	assert.False(t, err1.Is(err3))
	assert.False(t, err3.Is(err1))
}

// TestErrorMessages tests that error messages are descriptive
func TestErrorMessages(t *testing.T) {
	tests := []struct {
		name          string
		err           *types.GibsonError
		shouldContain string
	}{
		{
			name:          "working memory full",
			err:           NewWorkingMemoryFullError("test message"),
			shouldContain: "test message",
		},
		{
			name:          "mission memory not found",
			err:           NewMissionMemoryNotFoundError("my-key"),
			shouldContain: "my-key",
		},
		{
			name:          "vector not found",
			err:           NewVectorNotFoundError("vec-123"),
			shouldContain: "vec-123",
		},
		{
			name:          "invalid config",
			err:           NewInvalidConfigError("bad config"),
			shouldContain: "bad config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errorString := tt.err.Error()
			assert.Contains(t, errorString, tt.shouldContain)
			assert.Contains(t, errorString, string(tt.err.Code))
		})
	}
}

// TestGibsonErrorInterface tests that errors implement error interface
func TestGibsonErrorInterface(t *testing.T) {
	var err error
	err = NewMissionMemoryNotFoundError("test")

	require.NotNil(t, err)
	assert.NotEmpty(t, err.Error())

	// Test type assertion
	gibsonErr, ok := err.(*types.GibsonError)
	require.True(t, ok)
	assert.Equal(t, ErrCodeMissionMemoryNotFound, gibsonErr.Code)
}
