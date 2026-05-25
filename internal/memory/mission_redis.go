package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

// MemoryEntry represents a stored memory entry in Redis JSON format.
// This structure is persisted as JSON and indexed for full-text search.
// CreatedAt and UpdatedAt are stored as Unix milliseconds (int64) so that
// RediSearch NUMERIC fields can index and sort them correctly.
type MemoryEntry struct {
	Key       string         `json:"key"`
	Value     string         `json:"value"`
	MissionID string         `json:"mission_id"`
	TenantID  string         `json:"tenant_id,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt int64          `json:"created_at"` // Unix milliseconds
	UpdatedAt int64          `json:"updated_at"` // Unix milliseconds
}

// RedisMissionMemory implements MissionMemory using Redis with RediSearch for full-text search.
// It leverages RedisJSON for document storage and RediSearch for efficient querying.
//
// Architecture:
//   - Each memory entry is stored as a JSON document with key pattern:
//     gibson:memory:{tenant_id}:{mission_id}:{key}  (when tenantID is set)
//     gibson:memory:{mission_id}:{key}               (when tenantID is empty, backward compat)
//   - A Redis set tracks all keys for efficient listing:
//     gibson:memory:idx:{tenant_id}:{mission_id}  (when tenantID is set)
//     gibson:memory:idx:{mission_id}               (when tenantID is empty, backward compat)
//   - RediSearch index (gibson:idx:memory) enables full-text search with mission_id
//     and tenant_id filtering for defense-in-depth tenant isolation
//
// TTL Management:
//   - All keys (doc + index set) receive a configurable TTL on creation
//   - TTL is refreshed on every read/write access to keep active missions alive
//   - After mission completion, SetCompletedTTL reduces TTL for faster cleanup
//   - Set ttl to 0 to disable TTL entirely (backward-compatible behavior)
//
// Thread Safety:
//   - All operations are atomic at the Redis level
//   - No local caching to ensure consistency in distributed environments
type RedisMissionMemory struct {
	client    *state.StateClient
	missionID types.ID
	tenantID  string // empty string preserves backward-compatible key format

	// TTL for mission memory keys. Zero means no expiry.
	ttl time.Duration

	// Memory continuity fields
	continuityMode    MemoryContinuityMode
	previousMissionID types.ID // ID of the prior run's mission (for inherit/shared modes)
	missionName       string   // Mission name (for shared mode key scoping)
}

// RedisMissionMemoryOption configures optional behavior on RedisMissionMemory.
type RedisMissionMemoryOption func(*RedisMissionMemory)

// WithTTL sets the TTL for mission memory keys. Zero disables TTL.
func WithTTL(ttl time.Duration) RedisMissionMemoryOption {
	return func(m *RedisMissionMemory) {
		m.ttl = ttl
	}
}

// WithContinuity configures memory continuity mode and the previous mission ID
// for cross-run memory access.
func WithContinuity(mode MemoryContinuityMode, previousMissionID types.ID, missionName string) RedisMissionMemoryOption {
	return func(m *RedisMissionMemory) {
		m.continuityMode = mode
		m.previousMissionID = previousMissionID
		m.missionName = missionName
	}
}

// NewRedisMissionMemory creates a new RedisMissionMemory instance.
// It uses the provided StateClient for all Redis operations and scopes all
// operations to the specified mission ID and tenant ID.
//
// Parameters:
//   - client: StateClient instance with RediSearch and RedisJSON support
//   - missionID: Mission identifier to scope all memory operations
//   - tenantID: Tenant identifier for defense-in-depth isolation.
//     When non-empty, tenant is included in key prefixes and search filters.
//     When empty, the old key format without tenant prefix is used for backward compatibility.
//   - opts: Optional configuration (TTL, continuity mode)
//
// Example:
//
//	memory := memory.NewRedisMissionMemory(client, missionID, tenantID,
//	    memory.WithTTL(24 * time.Hour),
//	    memory.WithContinuity(memory.MemoryInherit, prevID, "recon-scan"),
//	)
func NewRedisMissionMemory(client *state.StateClient, missionID types.ID, tenantID string, opts ...RedisMissionMemoryOption) *RedisMissionMemory {
	m := &RedisMissionMemory{
		client:         client,
		missionID:      missionID,
		tenantID:       tenantID,
		continuityMode: MemoryIsolated,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// SetCompletedTTL reduces the TTL on all mission memory keys after a mission completes.
// This enables faster cleanup of finished missions while keeping active ones alive longer.
// If completedTTL is 0, no change is made.
func (m *RedisMissionMemory) SetCompletedTTL(ctx context.Context, completedTTL time.Duration) error {
	if completedTTL <= 0 {
		return nil
	}

	keys, err := m.Keys(ctx)
	if err != nil {
		return NewMissionMemoryStoreError("failed to retrieve keys for TTL update", err)
	}

	if len(keys) == 0 {
		return nil
	}

	pipe := m.client.Client().Pipeline()

	// Reduce TTL on all document keys
	for _, key := range keys {
		docKey := m.buildDocKey(key)
		pipe.Expire(ctx, docKey, completedTTL)
	}

	// Reduce TTL on the index set key
	indexKey := m.buildIndexKey()
	pipe.Expire(ctx, indexKey, completedTTL)

	if _, err := pipe.Exec(ctx); err != nil {
		return NewMissionMemoryStoreError("failed to set completed TTL on mission memory keys", err)
	}

	return nil
}

// Store persists a key-value pair with optional metadata to Redis.
// The operation is atomic and uses a pipeline to ensure consistency.
//
// Implementation:
//   - Marshals value to JSON string for storage
//   - Creates MemoryEntry with timestamps
//   - Stores document using JSON.SET
//   - Adds key to index set using SADD
//
// Returns an error if the key is empty or if Redis operations fail.
func (m *RedisMissionMemory) Store(ctx context.Context, key string, value any, metadata map[string]any) error {
	if key == "" {
		return NewMissionMemoryStoreError("key cannot be empty", nil)
	}

	// Marshal value to JSON string for searchability
	valueJSON, err := json.Marshal(value)
	if err != nil {
		return NewMissionMemoryStoreError("failed to marshal value", err)
	}

	// Create memory entry document
	nowMs := time.Now().UnixMilli()
	entry := MemoryEntry{
		Key:       key,
		Value:     string(valueJSON),
		MissionID: string(m.missionID),
		TenantID:  m.tenantID,
		Metadata:  metadata,
		CreatedAt: nowMs,
		UpdatedAt: nowMs,
	}

	// Build Redis keys
	docKey := m.buildDocKey(key)
	indexKey := m.buildIndexKey()

	// Use pipeline for atomic operation
	pipe := m.client.Client().Pipeline()

	// Store the JSON document
	entryJSON, err := json.Marshal(entry)
	if err != nil {
		return NewMissionMemoryStoreError("failed to marshal entry", err)
	}

	pipe.Do(ctx, "JSON.SET", docKey, "$", string(entryJSON))

	// Add key to index set for efficient listing
	pipe.SAdd(ctx, indexKey, key)

	// Apply TTL to both keys if configured
	if m.ttl > 0 {
		pipe.Expire(ctx, docKey, m.ttl)
		pipe.Expire(ctx, indexKey, m.ttl)
	}

	// Execute pipeline
	if _, err := pipe.Exec(ctx); err != nil {
		return NewMissionMemoryStoreError("failed to store item in Redis", err)
	}

	return nil
}

// Retrieve gets a memory item by key from Redis.
// It fetches the JSON document and unmarshals both the entry metadata and the value.
//
// Returns ErrNotFound if the key does not exist.
// Returns an error if Redis operations or JSON unmarshaling fails.
func (m *RedisMissionMemory) Retrieve(ctx context.Context, key string) (*MemoryItem, error) {
	docKey := m.buildDocKey(key)

	// Retrieve the JSON document
	var entry MemoryEntry
	err := m.client.JSONGet(ctx, docKey, "$", &entry)
	if err != nil {
		if state.IsNotFound(err) {
			return nil, NewMissionMemoryNotFoundError(key)
		}
		return nil, NewMissionMemoryStoreError("failed to retrieve item", err)
	}

	// Refresh TTL on read access to keep active missions alive
	if m.ttl > 0 {
		indexKey := m.buildIndexKey()
		pipe := m.client.Client().Pipeline()
		pipe.Expire(ctx, docKey, m.ttl)
		pipe.Expire(ctx, indexKey, m.ttl)
		// Best-effort TTL refresh — don't fail the read if expire fails
		_, _ = pipe.Exec(ctx)
	}

	// Unmarshal the value from JSON string
	var value any
	if entry.Value != "" {
		if err := json.Unmarshal([]byte(entry.Value), &value); err != nil {
			return nil, NewMissionMemoryStoreError("failed to unmarshal value", err)
		}
	}

	return &MemoryItem{
		Key:       entry.Key,
		Value:     value,
		Metadata:  entry.Metadata,
		CreatedAt: time.UnixMilli(entry.CreatedAt),
		UpdatedAt: time.UnixMilli(entry.UpdatedAt),
	}, nil
}

// Delete removes a memory entry from Redis.
// It removes both the JSON document and the key from the index set.
//
// Returns an error if the key doesn't exist or if Redis operations fail.
func (m *RedisMissionMemory) Delete(ctx context.Context, key string) error {
	docKey := m.buildDocKey(key)
	indexKey := m.buildIndexKey()

	// Check if key exists before deletion
	exists, err := m.client.Client().Exists(ctx, docKey).Result()
	if err != nil {
		return NewMissionMemoryStoreError("failed to check key existence", err)
	}

	if exists == 0 {
		return NewMissionMemoryNotFoundError(key)
	}

	// Use pipeline for atomic deletion
	pipe := m.client.Client().Pipeline()

	// Delete the JSON document
	pipe.Do(ctx, "JSON.DEL", docKey, "$")

	// Remove key from index set
	pipe.SRem(ctx, indexKey, key)

	// Execute pipeline
	if _, err := pipe.Exec(ctx); err != nil {
		return NewMissionMemoryStoreError("failed to delete item from Redis", err)
	}

	return nil
}

// Search performs full-text search across stored memory entries using RediSearch.
// It filters results by mission_id to ensure multi-tenant isolation.
//
// Implementation:
//   - Escapes mission_id as TAG field filter
//   - Escapes search query for full-text search
//   - Combines filters: "@mission_id:{escaped_id} {escaped_query}"
//   - Parses results and unmarshals values
//
// Parameters:
//   - query: Full-text search query string
//   - limit: Maximum number of results to return (defaults to 10 if <= 0)
//
// Returns search results ordered by relevance score (BM25).
func (m *RedisMissionMemory) Search(ctx context.Context, query string, limit int) ([]MemoryResult, error) {
	if query == "" {
		return nil, NewFTSQueryError("query cannot be empty", nil)
	}

	if limit <= 0 {
		limit = 10
	}

	// Escape mission_id for TAG field filter
	escapedMissionID := state.EscapeTag(string(m.missionID))

	// Escape query for full-text search
	escapedQuery := state.EscapeQuery(query)

	// Build RediSearch query with mission_id filter and optional tenant_id filter.
	// When tenantID is set, add @tenant_id filter for defense-in-depth isolation
	// so that a mission_id collision across tenants cannot expose cross-tenant data.
	var searchQuery string
	if m.tenantID != "" {
		escapedTenantID := state.EscapeTag(m.tenantID)
		searchQuery = fmt.Sprintf("@tenant_id:{%s} @mission_id:{%s} %s", escapedTenantID, escapedMissionID, escapedQuery)
	} else {
		searchQuery = fmt.Sprintf("@mission_id:{%s} %s", escapedMissionID, escapedQuery)
	}

	// Execute search with scores
	opts := &state.SearchOptions{
		Limit:      limit,
		Offset:     0,
		WithScores: true,
	}

	result, err := m.client.Search(ctx, "gibson:idx:memory", searchQuery, opts)
	if err != nil {
		return nil, NewFTSQueryError("failed to execute search query", err)
	}

	// Parse results into MemoryResult slice
	results := make([]MemoryResult, 0, len(result.Documents))

	for _, doc := range result.Documents {
		var entry MemoryEntry
		if err := json.Unmarshal(doc.JSON, &entry); err != nil {
			return nil, NewFTSQueryError("failed to unmarshal search result", err)
		}

		// Unmarshal the value from JSON string
		var value any
		if entry.Value != "" {
			if err := json.Unmarshal([]byte(entry.Value), &value); err != nil {
				return nil, NewFTSQueryError("failed to unmarshal value", err)
			}
		}

		item := MemoryItem{
			Key:       entry.Key,
			Value:     value,
			Metadata:  entry.Metadata,
			CreatedAt: time.UnixMilli(entry.CreatedAt),
			UpdatedAt: time.UnixMilli(entry.UpdatedAt),
		}

		results = append(results, MemoryResult{
			Item:  item,
			Score: doc.Score,
		})
	}

	return results, nil
}

// History returns recent memory entries ordered by creation time.
// It uses RediSearch to query all entries for this mission sorted by timestamp.
//
// Parameters:
//   - limit: Maximum number of results to return (defaults to 100 if <= 0)
//
// Returns entries sorted by created_at in descending order (most recent first).
func (m *RedisMissionMemory) History(ctx context.Context, limit int) ([]MemoryItem, error) {
	if limit <= 0 {
		limit = 100
	}

	// Escape mission_id for TAG field filter
	escapedMissionID := state.EscapeTag(string(m.missionID))

	// Build query to match all entries for this mission.
	// When tenantID is set, add @tenant_id filter for defense-in-depth isolation.
	var searchQuery string
	if m.tenantID != "" {
		escapedTenantID := state.EscapeTag(m.tenantID)
		searchQuery = fmt.Sprintf("@tenant_id:{%s} @mission_id:{%s}", escapedTenantID, escapedMissionID)
	} else {
		searchQuery = fmt.Sprintf("@mission_id:{%s}", escapedMissionID)
	}

	// Execute search sorted by created_at descending
	opts := &state.SearchOptions{
		Limit:   limit,
		Offset:  0,
		SortBy:  "created_at",
		SortAsc: false,
	}

	result, err := m.client.Search(ctx, "gibson:idx:memory", searchQuery, opts)
	if err != nil {
		return nil, NewMissionMemoryStoreError("failed to query history", err)
	}

	// Parse results into MemoryItem slice
	items := make([]MemoryItem, 0, len(result.Documents))

	for _, doc := range result.Documents {
		var entry MemoryEntry
		if err := json.Unmarshal(doc.JSON, &entry); err != nil {
			return nil, NewMissionMemoryStoreError("failed to unmarshal history result", err)
		}

		// Unmarshal the value from JSON string
		var value any
		if entry.Value != "" {
			if err := json.Unmarshal([]byte(entry.Value), &value); err != nil {
				return nil, NewMissionMemoryStoreError("failed to unmarshal value", err)
			}
		}

		items = append(items, MemoryItem{
			Key:       entry.Key,
			Value:     value,
			Metadata:  entry.Metadata,
			CreatedAt: time.UnixMilli(entry.CreatedAt),
			UpdatedAt: time.UnixMilli(entry.UpdatedAt),
		})
	}

	return items, nil
}

// Keys returns all memory keys for this mission.
// It retrieves the set members from the index set for O(n) performance.
//
// Returns keys in arbitrary order (set members are unordered).
func (m *RedisMissionMemory) Keys(ctx context.Context) ([]string, error) {
	indexKey := m.buildIndexKey()

	// Get all members from the index set
	keys, err := m.client.Client().SMembers(ctx, indexKey).Result()
	if err != nil {
		if err == redis.Nil {
			return []string{}, nil
		}
		return nil, NewMissionMemoryStoreError("failed to retrieve keys", err)
	}

	return keys, nil
}

// MissionID returns the mission identifier this memory is scoped to.
func (m *RedisMissionMemory) MissionID() types.ID {
	return m.missionID
}

// ContinuityMode returns the current memory continuity mode.
// Currently always returns MemoryIsolated for Redis implementation.
func (m *RedisMissionMemory) ContinuityMode() MemoryContinuityMode {
	return m.continuityMode
}

// GetPreviousRunValue retrieves a value from the prior run's memory.
// Requires continuity mode 'inherit' or 'shared' and a valid previousMissionID.
// Returns ErrContinuityNotSupported if mode is 'isolated'.
// Returns ErrNoPreviousRun if no previous mission ID is configured.
func (m *RedisMissionMemory) GetPreviousRunValue(ctx context.Context, key string) (any, error) {
	if m.continuityMode == MemoryIsolated {
		return nil, ErrContinuityNotSupported
	}

	if m.previousMissionID.IsZero() {
		return nil, ErrNoPreviousRun
	}

	// Build the key for the previous mission's memory entry
	prevDocKey := m.buildDocKeyForMission(m.previousMissionID, key)

	var entry MemoryEntry
	err := m.client.JSONGet(ctx, prevDocKey, "$", &entry)
	if err != nil {
		if state.IsNotFound(err) {
			return nil, NewMissionMemoryNotFoundError(key)
		}
		return nil, NewMissionMemoryStoreError("failed to retrieve previous run value", err)
	}

	// Unmarshal the value
	var value any
	if entry.Value != "" {
		if err := json.Unmarshal([]byte(entry.Value), &value); err != nil {
			return nil, NewMissionMemoryStoreError("failed to unmarshal previous run value", err)
		}
	}

	return value, nil
}

// GetValueHistory returns values for a key across recent runs by walking the
// RediSearch index for entries with the same key and mission name.
// Returns entries in chronological order (oldest first).
func (m *RedisMissionMemory) GetValueHistory(ctx context.Context, key string) ([]HistoricalValue, error) {
	if m.continuityMode == MemoryIsolated {
		return []HistoricalValue{}, nil
	}

	// Use RediSearch to find all entries with this key across missions.
	// The search uses the key field (exact match) and tenant scoping.
	escapedKey := state.EscapeQuery(key)

	var searchQuery string
	if m.tenantID != "" {
		escapedTenantID := state.EscapeTag(m.tenantID)
		searchQuery = fmt.Sprintf("@tenant_id:{%s} @key:{%s}", escapedTenantID, escapedKey)
	} else {
		searchQuery = fmt.Sprintf("@key:{%s}", escapedKey)
	}

	opts := &state.SearchOptions{
		Limit:   100, // Cap history depth
		Offset:  0,
		SortBy:  "created_at",
		SortAsc: true, // Chronological order
	}

	result, err := m.client.Search(ctx, "gibson:idx:memory", searchQuery, opts)
	if err != nil {
		return nil, NewMissionMemoryStoreError("failed to query value history", err)
	}

	history := make([]HistoricalValue, 0, len(result.Documents))
	for _, doc := range result.Documents {
		var entry MemoryEntry
		if err := json.Unmarshal(doc.JSON, &entry); err != nil {
			continue
		}

		var value any
		if entry.Value != "" {
			if err := json.Unmarshal([]byte(entry.Value), &value); err != nil {
				continue
			}
		}

		history = append(history, HistoricalValue{
			Value:     value,
			MissionID: entry.MissionID,
			StoredAt:  time.UnixMilli(entry.CreatedAt),
		})
	}

	return history, nil
}

// GetAll returns a snapshot of every key-value pair in this mission's memory.
//
// Algorithm:
//  1. Call Keys(ctx) to get the SMEMBERS set (O(N) with N = stored keys for this mission).
//  2. Sort the key list for deterministic ordering.
//  3. Pipeline one JSON.GET per document key.
//  4. Unmarshal each MemoryEntry.Value (a JSON string) into any.
//  5. On redis.Nil for a key (concurrent delete race), skip that key.
//  6. On any other Redis error, return nil map + error (never partial map alongside error).
//
// The checkpoint consumer (CaptureExecutionState) uses this as a recovery-aid
// snapshot. Redis remains the authoritative source of truth on resume.
func (m *RedisMissionMemory) GetAll(ctx context.Context) (map[string]any, error) {
	keys, err := m.Keys(ctx)
	if err != nil {
		return nil, NewMissionMemoryStoreError("GetAll: failed to retrieve key set", err)
	}

	if len(keys) == 0 {
		return make(map[string]any), nil
	}

	// Deterministic order for reproducible snapshots.
	sort.Strings(keys)

	// Pipeline one JSON.GET command per document key.
	pipe := m.client.Client().Pipeline()
	cmds := make([]*redis.Cmd, len(keys))
	for i, key := range keys {
		docKey := m.buildDocKey(key)
		cmds[i] = pipe.Do(ctx, "JSON.GET", docKey, "$")
	}

	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		// A pipeline-level error (connection refused, timeout, etc.) — fail fast.
		return nil, NewMissionMemoryStoreError("GetAll: pipeline execution failed", err)
	}

	result := make(map[string]any, len(keys))
	for i, key := range keys {
		raw, err := cmds[i].Text()
		if err != nil {
			if err == redis.Nil {
				// Key was deleted between SMEMBERS and JSON.GET — skip it.
				continue
			}
			// Any other Redis command error — fail fast, return no partial map.
			return nil, NewMissionMemoryStoreError(
				fmt.Sprintf("GetAll: JSON.GET failed for key %q", key), err)
		}

		// RedisJSON with "$" path returns an array; unwrap single-element arrays.
		trimmed := []byte(raw)
		if len(trimmed) > 0 && trimmed[0] == '[' {
			var arr []json.RawMessage
			if err := json.Unmarshal(trimmed, &arr); err == nil && len(arr) == 1 {
				trimmed = arr[0]
			}
		}

		var entry MemoryEntry
		if err := json.Unmarshal(trimmed, &entry); err != nil {
			return nil, NewMissionMemoryStoreError(
				fmt.Sprintf("GetAll: unmarshal MemoryEntry for key %q", key), err)
		}

		// Unmarshal the value from the JSON string stored in entry.Value.
		var value any
		if entry.Value != "" {
			if err := json.Unmarshal([]byte(entry.Value), &value); err != nil {
				return nil, NewMissionMemoryStoreError(
					fmt.Sprintf("GetAll: unmarshal value for key %q", key), err)
			}
		}

		result[key] = value
	}

	return result, nil
}

// buildDocKeyForMission constructs a doc key for a specific mission (used for cross-run reads).
func (m *RedisMissionMemory) buildDocKeyForMission(missionID types.ID, key string) string {
	if m.tenantID != "" {
		return fmt.Sprintf("gibson:memory:%s:%s:%s", m.tenantID, missionID, key)
	}
	return fmt.Sprintf("gibson:memory:%s:%s", missionID, key)
}

// buildDocKey constructs the Redis key for a memory document.
//
// When tenantID is non-empty (multi-tenant mode):
//
//	Format: gibson:memory:{tenant_id}:{mission_id}:{key}
//
// When tenantID is empty (backward-compatible single-tenant mode):
//
//	Format: gibson:memory:{mission_id}:{key}
//
// The RediSearch index prefix "gibson:memory:" covers both formats.
func (m *RedisMissionMemory) buildDocKey(key string) string {
	if m.tenantID != "" {
		return fmt.Sprintf("gibson:memory:%s:%s:%s", m.tenantID, m.missionID, key)
	}
	return fmt.Sprintf("gibson:memory:%s:%s", m.missionID, key)
}

// buildIndexKey constructs the Redis key for the mission's key index set.
//
// When tenantID is non-empty (multi-tenant mode):
//
//	Format: gibson:memory:idx:{tenant_id}:{mission_id}
//
// When tenantID is empty (backward-compatible single-tenant mode):
//
//	Format: gibson:memory:idx:{mission_id}
func (m *RedisMissionMemory) buildIndexKey() string {
	if m.tenantID != "" {
		return fmt.Sprintf("gibson:memory:idx:%s:%s", m.tenantID, m.missionID)
	}
	return fmt.Sprintf("gibson:memory:idx:%s", m.missionID)
}

// Clear removes all memory entries for this mission.
// It deletes all documents and the index set in a pipeline for atomicity.
//
// WARNING: This is a destructive operation and cannot be undone.
func (m *RedisMissionMemory) Clear(ctx context.Context) error {
	indexKey := m.buildIndexKey()

	// Get all keys for this mission
	keys, err := m.Keys(ctx)
	if err != nil {
		return NewMissionMemoryStoreError("failed to retrieve keys for clearing", err)
	}

	if len(keys) == 0 {
		// Nothing to delete
		return nil
	}

	// Build list of document keys to delete
	docKeys := make([]string, len(keys))
	for i, key := range keys {
		docKeys[i] = m.buildDocKey(key)
	}

	// Use pipeline for atomic deletion
	pipe := m.client.Client().Pipeline()

	// Delete all JSON documents
	for _, docKey := range docKeys {
		pipe.Do(ctx, "JSON.DEL", docKey, "$")
	}

	// Delete the index set
	pipe.Del(ctx, indexKey)

	// Execute pipeline
	if _, err := pipe.Exec(ctx); err != nil {
		return NewMissionMemoryStoreError("failed to clear memory", err)
	}

	return nil
}
