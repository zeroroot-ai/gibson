package tool

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/zero-day-ai/gibson/internal/types"
	"google.golang.org/protobuf/proto"
)

// ResultChunk represents a single chunk of streaming execution result
type ResultChunk struct {
	// Data contains the chunk data as proto message
	Data proto.Message
	// ChunkIndex is the sequence number of this chunk
	ChunkIndex int
	// IsFinal indicates if this is the last chunk
	IsFinal bool
	// Error contains any error that occurred during execution
	Error error
}

// StreamingResult contains a channel for receiving result chunks
type StreamingResult struct {
	// Chunks is a channel that receives result chunks
	Chunks <-chan ResultChunk
	// Cancel can be called to cancel the streaming execution
	Cancel context.CancelFunc
}

// StreamingTool extends Tool interface with streaming capability
type StreamingTool interface {
	Tool
	// SupportsStreaming returns true if the tool supports streaming execution
	SupportsStreaming() bool
	// StreamExecute runs the tool with proto message input and streams results as chunks.
	// The returned channel will be closed when execution completes or encounters an error.
	StreamExecute(ctx context.Context, input proto.Message) StreamingResult
}

// ValidationError represents a validation error with field path and message
type ValidationError struct {
	// FieldPath is the JSON path to the invalid field
	FieldPath string
	// Message describes the validation error
	Message string
}

// Error implements the error interface
func (v ValidationError) Error() string {
	if v.FieldPath == "" {
		return v.Message
	}
	return fmt.Sprintf("%s: %s", v.FieldPath, v.Message)
}

// RetryConfig configures retry behavior for tool execution
type RetryConfig struct {
	// MaxRetries is the maximum number of retry attempts (0 means no retries)
	MaxRetries int
	// InitialBackoff is the initial backoff duration
	InitialBackoff time.Duration
	// MaxBackoff is the maximum backoff duration
	MaxBackoff time.Duration
	// BackoffFactor is the multiplier for exponential backoff
	BackoffFactor float64
	// RetryableErrors is a list of error codes that should trigger a retry
	RetryableErrors []types.ErrorCode
}

// DefaultRetryConfig returns a sensible default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:     3,
		InitialBackoff: 100 * time.Millisecond,
		MaxBackoff:     10 * time.Second,
		BackoffFactor:  2.0,
		RetryableErrors: []types.ErrorCode{
			ErrToolExecutionFailed,
		},
	}
}

// isRetryable checks if an error should trigger a retry
func (c *RetryConfig) isRetryable(err error) bool {
	if err == nil {
		return false
	}

	// Check if it's a GibsonError with retryable flag
	if gibsonErr, ok := err.(*types.GibsonError); ok {
		if gibsonErr.Retryable {
			return true
		}
		// Check if the error code is in the retryable list
		for _, code := range c.RetryableErrors {
			if gibsonErr.Code == code {
				return true
			}
		}
	}

	return false
}

// calculateBackoff calculates the backoff duration for the given attempt with jitter
func (c *RetryConfig) calculateBackoff(attempt int) time.Duration {
	backoff := float64(c.InitialBackoff) * pow(c.BackoffFactor, float64(attempt))
	if backoff > float64(c.MaxBackoff) {
		backoff = float64(c.MaxBackoff)
	}

	// Add jitter: randomize +/- 25%
	jitter := backoff * 0.25 * (rand.Float64()*2 - 1)
	return time.Duration(backoff + jitter)
}

// pow is a simple integer exponentiation for backoff calculation
func pow(base float64, exp float64) float64 {
	result := 1.0
	for i := 0; i < int(exp); i++ {
		result *= base
	}
	return result
}

// ToolCache is an interface for caching tool execution results
type ToolCache interface {
	// Get retrieves a cached result by key
	Get(key string) (*CachedResult, bool)
	// Set stores a result in the cache with TTL
	Set(key string, result *CachedResult, ttl time.Duration)
	// Delete removes a result from the cache
	Delete(key string)
	// Clear removes all entries from the cache
	Clear()
}

// CachedResult wraps a tool execution result with metadata
type CachedResult struct {
	// Result is the cached proto message output
	Result proto.Message
	// CachedAt is when the result was cached
	CachedAt time.Time
	// ExpiresAt is when the cached result expires
	ExpiresAt time.Time
	// HitCount tracks how many times this cached result was used
	HitCount int64
}

// IsExpired checks if the cached result has expired
func (c *CachedResult) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

// MemoryToolCache implements ToolCache with in-memory LRU eviction
type MemoryToolCache struct {
	mu      sync.RWMutex
	cache   map[string]*CachedResult
	maxSize int
	lruList []string // Simple LRU tracking
}

// NewMemoryToolCache creates a new in-memory tool cache
func NewMemoryToolCache(maxSize int) *MemoryToolCache {
	return &MemoryToolCache{
		cache:   make(map[string]*CachedResult),
		maxSize: maxSize,
		lruList: make([]string, 0, maxSize),
	}
}

// Get retrieves a cached result by key
func (m *MemoryToolCache) Get(key string) (*CachedResult, bool) {
	m.mu.RLock()
	result, exists := m.cache[key]
	m.mu.RUnlock()

	if !exists {
		return nil, false
	}

	// Check expiration
	if result.IsExpired() {
		m.Delete(key)
		return nil, false
	}

	// Update hit count and LRU position
	m.mu.Lock()
	result.HitCount++
	m.updateLRU(key)
	m.mu.Unlock()

	return result, true
}

// Set stores a result in the cache with TTL
func (m *MemoryToolCache) Set(key string, result *CachedResult, ttl time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Set expiration time
	result.CachedAt = time.Now()
	result.ExpiresAt = result.CachedAt.Add(ttl)

	// Evict if at capacity
	if len(m.cache) >= m.maxSize {
		m.evictLRU()
	}

	m.cache[key] = result
	m.updateLRU(key)
}

// Delete removes a result from the cache
func (m *MemoryToolCache) Delete(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.cache, key)
	m.removeLRU(key)
}

// Clear removes all entries from the cache
func (m *MemoryToolCache) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cache = make(map[string]*CachedResult)
	m.lruList = make([]string, 0, m.maxSize)
}

// updateLRU moves the key to the front of the LRU list (most recently used)
func (m *MemoryToolCache) updateLRU(key string) {
	// Remove from current position
	for i, k := range m.lruList {
		if k == key {
			m.lruList = append(m.lruList[:i], m.lruList[i+1:]...)
			break
		}
	}
	// Add to front
	m.lruList = append([]string{key}, m.lruList...)
}

// removeLRU removes a key from the LRU list
func (m *MemoryToolCache) removeLRU(key string) {
	for i, k := range m.lruList {
		if k == key {
			m.lruList = append(m.lruList[:i], m.lruList[i+1:]...)
			return
		}
	}
}

// evictLRU removes the least recently used entry
func (m *MemoryToolCache) evictLRU() {
	if len(m.lruList) == 0 {
		return
	}

	// Remove the last entry (least recently used)
	lruKey := m.lruList[len(m.lruList)-1]
	delete(m.cache, lruKey)
	m.lruList = m.lruList[:len(m.lruList)-1]
}

// ToolExecutor provides enhanced tool execution with retry, caching, and validation
type ToolExecutor struct {
	registry    ToolRegistry
	cache       ToolCache
	retryConfig RetryConfig
	enableCache bool
}

// NewToolExecutor creates a new ToolExecutor with the given configuration
func NewToolExecutor(registry ToolRegistry) *ToolExecutor {
	return &ToolExecutor{
		registry:    registry,
		cache:       NewMemoryToolCache(1000), // Default 1000 entries
		retryConfig: DefaultRetryConfig(),
		enableCache: false, // Disabled by default
	}
}

// WithCache enables caching with the provided cache implementation
func (e *ToolExecutor) WithCache(cache ToolCache) *ToolExecutor {
	e.cache = cache
	e.enableCache = true
	return e
}

// WithRetryConfig sets a custom retry configuration
func (e *ToolExecutor) WithRetryConfig(config RetryConfig) *ToolExecutor {
	e.retryConfig = config
	return e
}

// ValidateInput validates the input proto message against the tool's schema
func (e *ToolExecutor) ValidateInput(tool Tool, input proto.Message) []ValidationError {
	var errors []ValidationError

	// Basic nil check
	if input == nil {
		errors = append(errors, ValidationError{
			FieldPath: "",
			Message:   "input cannot be nil",
		})
		return errors
	}

	// Additional validation can be added here based on proto reflection
	// For now, we rely on proto unmarshaling validation

	return errors
}

// generateCacheKey creates a deterministic cache key from tool name and input
func (e *ToolExecutor) generateCacheKey(toolName string, input proto.Message) (string, error) {
	// Marshal input to JSON for consistent hashing
	inputJSON, err := proto.Marshal(input)
	if err != nil {
		return "", err
	}

	// Create hash
	hash := sha256.Sum256(inputJSON)
	return fmt.Sprintf("%s:%x", toolName, hash), nil
}

// Execute runs a tool with retry logic, caching, and validation
func (e *ToolExecutor) Execute(ctx context.Context, toolName string, input proto.Message) (proto.Message, error) {
	// Get tool from registry
	tool, err := e.registry.Get(toolName)
	if err != nil {
		return nil, err
	}

	// Validate input
	validationErrors := e.ValidateInput(tool, input)
	if len(validationErrors) > 0 {
		return nil, types.WrapError(ErrToolInvalidInput,
			fmt.Sprintf("input validation failed: %v", validationErrors[0]),
			validationErrors[0])
	}

	// Check cache if enabled
	if e.enableCache {
		cacheKey, err := e.generateCacheKey(toolName, input)
		if err == nil {
			if cached, found := e.cache.Get(cacheKey); found {
				return cached.Result, nil
			}
		}
	}

	// Execute with retry
	result, err := e.executeWithRetry(ctx, func() (proto.Message, error) {
		return tool.ExecuteProto(ctx, input)
	})

	// Cache result if successful and caching is enabled
	if err == nil && e.enableCache {
		cacheKey, keyErr := e.generateCacheKey(toolName, input)
		if keyErr == nil {
			e.cache.Set(cacheKey, &CachedResult{
				Result:    result,
				CachedAt:  time.Now(),
				ExpiresAt: time.Now().Add(5 * time.Minute), // Default 5 min TTL
			}, 5*time.Minute)
		}
	}

	return result, err
}

// executeWithRetry executes a function with exponential backoff retry logic
func (e *ToolExecutor) executeWithRetry(ctx context.Context, fn func() (proto.Message, error)) (proto.Message, error) {
	var lastErr error

	for attempt := 0; attempt <= e.retryConfig.MaxRetries; attempt++ {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return nil, types.WrapError(ErrToolExecutionFailed, "execution cancelled", ctx.Err())
		default:
		}

		// Execute the function
		result, err := fn()
		if err == nil {
			return result, nil
		}

		lastErr = err

		// Don't retry if this is the last attempt or error is not retryable
		if attempt == e.retryConfig.MaxRetries || !e.retryConfig.isRetryable(err) {
			break
		}

		// Calculate backoff and wait
		backoff := e.retryConfig.calculateBackoff(attempt)

		// Log retry attempt (in production, use proper logging)
		fmt.Printf("Tool execution failed (attempt %d/%d), retrying in %v: %v\n",
			attempt+1, e.retryConfig.MaxRetries+1, backoff, err)

		select {
		case <-time.After(backoff):
			// Continue to next retry
		case <-ctx.Done():
			return nil, types.WrapError(ErrToolExecutionFailed, "execution cancelled during retry", ctx.Err())
		}
	}

	return nil, lastErr
}

// StreamExecute executes a tool with streaming support if available
func (e *ToolExecutor) StreamExecute(ctx context.Context, toolName string, input proto.Message) StreamingResult {
	// Create a cancellable context
	streamCtx, cancel := context.WithCancel(ctx)

	chunks := make(chan ResultChunk, 10) // Buffer for backpressure

	go func() {
		defer close(chunks)
		defer cancel()

		// Get tool from registry
		tool, err := e.registry.Get(toolName)
		if err != nil {
			chunks <- ResultChunk{
				Error:      err,
				IsFinal:    true,
				ChunkIndex: 0,
			}
			return
		}

		// Validate input
		validationErrors := e.ValidateInput(tool, input)
		if len(validationErrors) > 0 {
			chunks <- ResultChunk{
				Error: types.WrapError(ErrToolInvalidInput,
					fmt.Sprintf("input validation failed: %v", validationErrors[0]),
					validationErrors[0]),
				IsFinal:    true,
				ChunkIndex: 0,
			}
			return
		}

		// Check if tool supports streaming
		if streamingTool, ok := tool.(StreamingTool); ok && streamingTool.SupportsStreaming() {
			// Use native streaming
			result := streamingTool.StreamExecute(streamCtx, input)

			// Forward chunks
			chunkIndex := 0
			for chunk := range result.Chunks {
				select {
				case chunks <- ResultChunk{
					Data:       chunk.Data,
					ChunkIndex: chunkIndex,
					IsFinal:    chunk.IsFinal,
					Error:      chunk.Error,
				}:
					chunkIndex++
				case <-streamCtx.Done():
					return
				}
			}
		} else {
			// Fallback: execute synchronously and return single chunk
			result, err := e.Execute(streamCtx, toolName, input)
			chunks <- ResultChunk{
				Data:       result,
				ChunkIndex: 0,
				IsFinal:    true,
				Error:      err,
			}
		}
	}()

	return StreamingResult{
		Chunks: chunks,
		Cancel: cancel,
	}
}

// SupportsStreaming checks if a tool supports streaming execution
func (e *ToolExecutor) SupportsStreaming(toolName string) bool {
	tool, err := e.registry.Get(toolName)
	if err != nil {
		return false
	}

	if streamingTool, ok := tool.(StreamingTool); ok {
		return streamingTool.SupportsStreaming()
	}

	return false
}

// StreamingWrapper wraps a non-streaming tool to provide streaming interface
type StreamingWrapper struct {
	Tool
}

// NewStreamingWrapper creates a wrapper that adds streaming support to any tool
func NewStreamingWrapper(tool Tool) *StreamingWrapper {
	return &StreamingWrapper{Tool: tool}
}

// SupportsStreaming always returns false for wrapped non-streaming tools
func (w *StreamingWrapper) SupportsStreaming() bool {
	// Check if underlying tool already supports streaming
	if streamingTool, ok := w.Tool.(StreamingTool); ok {
		return streamingTool.SupportsStreaming()
	}
	return false
}

// StreamExecute executes the tool and returns the result as a single chunk
func (w *StreamingWrapper) StreamExecute(ctx context.Context, input proto.Message) StreamingResult {
	chunks := make(chan ResultChunk, 1)
	streamCtx, cancel := context.WithCancel(ctx)

	go func() {
		defer close(chunks)

		// Execute the tool
		result, err := w.Tool.ExecuteProto(streamCtx, input)

		// Send single chunk
		chunks <- ResultChunk{
			Data:       result,
			ChunkIndex: 0,
			IsFinal:    true,
			Error:      err,
		}
	}()

	return StreamingResult{
		Chunks: chunks,
		Cancel: cancel,
	}
}

// ValidateToolInput is a standalone function for input validation
func ValidateToolInput(inputSchema string, input map[string]interface{}) []ValidationError {
	var errors []ValidationError

	// Parse schema
	var schema map[string]interface{}
	if err := json.Unmarshal([]byte(inputSchema), &schema); err != nil {
		errors = append(errors, ValidationError{
			FieldPath: "",
			Message:   fmt.Sprintf("invalid schema: %v", err),
		})
		return errors
	}

	// Validate required fields
	if required, ok := schema["required"].([]interface{}); ok {
		for _, req := range required {
			fieldName := req.(string)
			if _, exists := input[fieldName]; !exists {
				errors = append(errors, ValidationError{
					FieldPath: fieldName,
					Message:   "required field is missing",
				})
			}
		}
	}

	// Validate types
	if properties, ok := schema["properties"].(map[string]interface{}); ok {
		for fieldName, fieldValue := range input {
			if propSchema, exists := properties[fieldName]; exists {
				propMap := propSchema.(map[string]interface{})
				if expectedType, ok := propMap["type"].(string); ok {
					actualType := getJSONType(fieldValue)
					if actualType != expectedType {
						errors = append(errors, ValidationError{
							FieldPath: fieldName,
							Message:   fmt.Sprintf("expected type %s, got %s", expectedType, actualType),
						})
					}
				}
			}
		}
	}

	return errors
}

// getJSONType returns the JSON type name for a value
func getJSONType(value interface{}) string {
	switch value.(type) {
	case string:
		return "string"
	case float64, int, int64:
		return "number"
	case bool:
		return "boolean"
	case []interface{}:
		return "array"
	case map[string]interface{}:
		return "object"
	case nil:
		return "null"
	default:
		return "unknown"
	}
}
