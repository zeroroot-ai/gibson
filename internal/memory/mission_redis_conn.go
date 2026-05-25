// Package memory — mission_redis_conn.go
//
// ConnBoundMissionMemory implements MissionMemory using a tenant-bound *redis.Client.
// Keys carry no tenant prefix; isolation is structural (audit C16 closure —
// the per-tenant client is the isolation boundary, eliminating any in-process
// EventBus cross-tenant fallback).
package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/zero-day-ai/gibson/internal/types"
)

// ConnBoundMissionMemory implements MissionMemory using a tenant-bound Redis client.
// All keys are scoped to a single mission; the per-tenant logical DB provides
// tenant isolation structurally (audit C16 closure).
type ConnBoundMissionMemory struct {
	rdb       *goredis.Client
	missionID types.ID
	ttl       time.Duration

	continuityMode    MemoryContinuityMode
	previousMissionID types.ID
}

// ConnBoundMissionMemoryOption configures optional behavior.
type ConnBoundMissionMemoryOption func(*ConnBoundMissionMemory)

// WithConnTTL sets the TTL for memory keys. Zero disables TTL.
func WithConnTTL(ttl time.Duration) ConnBoundMissionMemoryOption {
	return func(m *ConnBoundMissionMemory) { m.ttl = ttl }
}

// WithConnContinuity sets continuity mode and previous mission ID.
func WithConnContinuity(mode MemoryContinuityMode, prev types.ID) ConnBoundMissionMemoryOption {
	return func(m *ConnBoundMissionMemory) {
		m.continuityMode = mode
		m.previousMissionID = prev
	}
}

// NewConnBoundMissionMemory creates a MissionMemory backed by the given tenant-bound Redis client.
func NewConnBoundMissionMemory(rdb *goredis.Client, missionID types.ID, opts ...ConnBoundMissionMemoryOption) *ConnBoundMissionMemory {
	m := &ConnBoundMissionMemory{
		rdb:            rdb,
		missionID:      missionID,
		continuityMode: MemoryIsolated,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// MissionID returns the mission this memory is scoped to.
func (m *ConnBoundMissionMemory) MissionID() types.ID { return m.missionID }

// ContinuityMode returns the current memory continuity mode.
func (m *ConnBoundMissionMemory) ContinuityMode() MemoryContinuityMode { return m.continuityMode }

// Key helpers — no tenant prefix (C16 closure).

func (m *ConnBoundMissionMemory) docKey(key string) string {
	return fmt.Sprintf("gibson:memory:%s:%s", m.missionID, key)
}

func (m *ConnBoundMissionMemory) indexKey() string {
	return fmt.Sprintf("gibson:memory:idx:%s", m.missionID)
}

func (m *ConnBoundMissionMemory) missionDocKey(missionID types.ID, key string) string {
	return fmt.Sprintf("gibson:memory:%s:%s", missionID, key)
}

func (m *ConnBoundMissionMemory) missionIndexKey(missionID types.ID) string {
	return fmt.Sprintf("gibson:memory:idx:%s", missionID)
}

// Store persists a key-value pair with optional metadata.
func (m *ConnBoundMissionMemory) Store(ctx context.Context, key string, value any, metadata map[string]any) error {
	if key == "" {
		return NewMissionMemoryStoreError("key cannot be empty", nil)
	}
	valueJSON, err := json.Marshal(value)
	if err != nil {
		return NewMissionMemoryStoreError("failed to marshal value", err)
	}
	nowMs := time.Now().UnixMilli()
	entry := MemoryEntry{
		Key:       key,
		Value:     string(valueJSON),
		MissionID: string(m.missionID),
		Metadata:  metadata,
		CreatedAt: nowMs,
		UpdatedAt: nowMs,
	}
	entryJSON, err := json.Marshal(entry)
	if err != nil {
		return NewMissionMemoryStoreError("failed to marshal entry", err)
	}
	pipe := m.rdb.Pipeline()
	pipe.Do(ctx, "JSON.SET", m.docKey(key), "$", string(entryJSON))
	pipe.SAdd(ctx, m.indexKey(), key)
	if m.ttl > 0 {
		pipe.Expire(ctx, m.docKey(key), m.ttl)
		pipe.Expire(ctx, m.indexKey(), m.ttl)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return NewMissionMemoryStoreError("failed to store item", err)
	}
	return nil
}

// Retrieve gets a memory item by key.
func (m *ConnBoundMissionMemory) Retrieve(ctx context.Context, key string) (*MemoryItem, error) {
	entry, err := m.getEntry(ctx, m.docKey(key))
	if err != nil {
		return nil, err
	}
	if m.ttl > 0 {
		pipe := m.rdb.Pipeline()
		pipe.Expire(ctx, m.docKey(key), m.ttl)
		pipe.Expire(ctx, m.indexKey(), m.ttl)
		_, _ = pipe.Exec(ctx)
	}
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

// Delete removes a memory entry.
func (m *ConnBoundMissionMemory) Delete(ctx context.Context, key string) error {
	pipe := m.rdb.Pipeline()
	pipe.Do(ctx, "JSON.DEL", m.docKey(key), "$")
	pipe.SRem(ctx, m.indexKey(), key)
	if _, err := pipe.Exec(ctx); err != nil {
		return NewMissionMemoryStoreError("failed to delete item", err)
	}
	return nil
}

// Search performs a simple full-text search (key/value contains query).
func (m *ConnBoundMissionMemory) Search(ctx context.Context, query string, limit int) ([]MemoryResult, error) {
	keys, err := m.Keys(ctx)
	if err != nil {
		return nil, err
	}
	var results []MemoryResult
	for _, key := range keys {
		entry, err := m.getEntry(ctx, m.docKey(key))
		if err != nil {
			continue
		}
		if containsIgnoreCase(key, query) || containsIgnoreCase(entry.Value, query) {
			var val any
			_ = json.Unmarshal([]byte(entry.Value), &val)
			results = append(results, MemoryResult{
				Item: MemoryItem{
					Key:       entry.Key,
					Value:     val,
					Metadata:  entry.Metadata,
					CreatedAt: time.UnixMilli(entry.CreatedAt),
					UpdatedAt: time.UnixMilli(entry.UpdatedAt),
				},
				Score: 1.0,
			})
			if limit > 0 && len(results) >= limit {
				break
			}
		}
	}
	return results, nil
}

// History returns recent entries ordered by time (newest first).
func (m *ConnBoundMissionMemory) History(ctx context.Context, limit int) ([]MemoryItem, error) {
	keys, err := m.Keys(ctx)
	if err != nil {
		return nil, err
	}
	items := make([]MemoryItem, 0, len(keys))
	for _, key := range keys {
		entry, err := m.getEntry(ctx, m.docKey(key))
		if err != nil {
			continue
		}
		var val any
		_ = json.Unmarshal([]byte(entry.Value), &val)
		items = append(items, MemoryItem{
			Key:       entry.Key,
			Value:     val,
			Metadata:  entry.Metadata,
			CreatedAt: time.UnixMilli(entry.CreatedAt),
			UpdatedAt: time.UnixMilli(entry.UpdatedAt),
		})
	}
	// Sort by CreatedAt descending (simple insertion sort for small sets).
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j].CreatedAt.After(items[j-1].CreatedAt); j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

// Keys returns all keys for this mission.
func (m *ConnBoundMissionMemory) Keys(ctx context.Context) ([]string, error) {
	keys, err := m.rdb.SMembers(ctx, m.indexKey()).Result()
	if err != nil {
		return nil, NewMissionMemoryStoreError("failed to retrieve keys", err)
	}
	return keys, nil
}

// GetAll returns a snapshot of every key-value pair in this mission's memory.
// Uses the same SMEMBERS + pipelined JSON.GET approach as RedisMissionMemory.GetAll.
func (m *ConnBoundMissionMemory) GetAll(ctx context.Context) (map[string]any, error) {
	keys, err := m.Keys(ctx)
	if err != nil {
		return nil, NewMissionMemoryStoreError("GetAll: failed to retrieve key set", err)
	}
	if len(keys) == 0 {
		return make(map[string]any), nil
	}
	sort.Strings(keys)

	pipe := m.rdb.Pipeline()
	cmds := make([]*goredis.Cmd, len(keys))
	for i, key := range keys {
		cmds[i] = pipe.Do(ctx, "JSON.GET", m.docKey(key), "$")
	}
	if _, err := pipe.Exec(ctx); err != nil && err != goredis.Nil {
		return nil, NewMissionMemoryStoreError("GetAll: pipeline execution failed", err)
	}

	result := make(map[string]any, len(keys))
	for i, key := range keys {
		raw, err := cmds[i].Text()
		if err != nil {
			if err == goredis.Nil {
				continue
			}
			return nil, NewMissionMemoryStoreError(
				fmt.Sprintf("GetAll: JSON.GET failed for key %q", key), err)
		}
		entry, err := parseMemoryEntry(raw)
		if err != nil {
			return nil, NewMissionMemoryStoreError(
				fmt.Sprintf("GetAll: unmarshal MemoryEntry for key %q", key), err)
		}
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

// parseMemoryEntry parses a raw JSON string (possibly wrapped in a JSONPath array)
// into a MemoryEntry. Used by GetAll.
func parseMemoryEntry(raw string) (*MemoryEntry, error) {
	trimmed := []byte(raw)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var arr []json.RawMessage
		if err := json.Unmarshal(trimmed, &arr); err == nil && len(arr) == 1 {
			trimmed = arr[0]
		}
	}
	var entry MemoryEntry
	if err := json.Unmarshal(trimmed, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

// GetPreviousRunValue retrieves a value from the prior run's memory.
func (m *ConnBoundMissionMemory) GetPreviousRunValue(ctx context.Context, key string) (any, error) {
	if m.continuityMode == MemoryIsolated {
		return nil, ErrContinuityNotSupported
	}
	if m.previousMissionID.IsZero() {
		return nil, ErrNoPreviousRun
	}
	entry, err := m.getEntry(ctx, m.missionDocKey(m.previousMissionID, key))
	if err != nil {
		return nil, ErrNoPreviousRun
	}
	var val any
	if entry.Value != "" {
		_ = json.Unmarshal([]byte(entry.Value), &val)
	}
	return val, nil
}

// GetValueHistory returns values for a key across all runs (simplified — current run only).
func (m *ConnBoundMissionMemory) GetValueHistory(ctx context.Context, key string) ([]HistoricalValue, error) {
	entry, err := m.getEntry(ctx, m.docKey(key))
	if err != nil {
		return []HistoricalValue{}, nil
	}
	var val any
	_ = json.Unmarshal([]byte(entry.Value), &val)
	return []HistoricalValue{{
		Value:     val,
		MissionID: string(m.missionID),
		StoredAt:  time.UnixMilli(entry.CreatedAt),
	}}, nil
}

// SetCompletedTTL reduces TTL on all mission memory keys after mission completion.
func (m *ConnBoundMissionMemory) SetCompletedTTL(ctx context.Context, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	keys, err := m.Keys(ctx)
	if err != nil {
		return NewMissionMemoryStoreError("failed to retrieve keys", err)
	}
	pipe := m.rdb.Pipeline()
	for _, key := range keys {
		pipe.Expire(ctx, m.docKey(key), ttl)
	}
	pipe.Expire(ctx, m.indexKey(), ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return NewMissionMemoryStoreError("failed to set completed TTL", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (m *ConnBoundMissionMemory) getEntry(ctx context.Context, key string) (*MemoryEntry, error) {
	result, err := m.rdb.Do(ctx, "JSON.GET", key, "$").Result()
	if err == goredis.Nil || result == nil {
		return nil, NewMissionMemoryNotFoundError(key)
	}
	if err != nil {
		return nil, NewMissionMemoryStoreError("failed to get entry", err)
	}
	raw, ok := result.(string)
	if !ok {
		return nil, NewMissionMemoryStoreError("unexpected result type", nil)
	}
	var docs []json.RawMessage
	if err := json.Unmarshal([]byte(raw), &docs); err == nil && len(docs) > 0 {
		var entry MemoryEntry
		if err := json.Unmarshal(docs[0], &entry); err != nil {
			return nil, NewMissionMemoryStoreError("failed to unmarshal entry", err)
		}
		return &entry, nil
	}
	var entry MemoryEntry
	if err := json.Unmarshal([]byte(raw), &entry); err != nil {
		return nil, NewMissionMemoryStoreError("failed to unmarshal entry", err)
	}
	return &entry, nil
}

func containsIgnoreCase(s, substr string) bool {
	if substr == "" {
		return true
	}
	sl := make([]byte, len(s))
	copy(sl, s)
	for i, c := range sl {
		if c >= 'A' && c <= 'Z' {
			sl[i] = c + 32
		}
	}
	subl := make([]byte, len(substr))
	copy(subl, substr)
	for i, c := range subl {
		if c >= 'A' && c <= 'Z' {
			subl[i] = c + 32
		}
	}
	return fmt.Sprintf("%s", sl) != "" && len(subl) <= len(sl) &&
		containsBytes(sl, subl)
}

func containsBytes(s, sub []byte) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			if s[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// Ensure ConnBoundMissionMemory implements MissionMemory at compile time.
var _ MissionMemory = (*ConnBoundMissionMemory)(nil)
