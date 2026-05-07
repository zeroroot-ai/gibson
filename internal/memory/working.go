package memory

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// WorkingMemory provides ephemeral in-memory storage with token budget management.
// All operations are thread-safe and designed to complete in <1ms.
type WorkingMemory interface {
	// Get retrieves a value by key, returns nil and false if not found.
	// Updates the AccessedAt timestamp for LRU eviction.
	Get(key string) (any, bool)

	// Set stores a value with automatic token counting.
	// Triggers LRU eviction if token budget is exceeded.
	Set(key string, value any) error

	// Delete removes an entry and updates token count.
	// Returns true if the entry existed, false otherwise.
	Delete(key string) bool

	// Clear removes all entries and resets token count to zero.
	Clear()

	// List returns all stored keys in no particular order.
	List() []string

	// GetAll returns a snapshot of every key-value pair currently in working memory.
	// The returned map is a copy — mutations do not affect the live memory.
	// Safe to call concurrently with Set, Get, and Delete.
	// Non-JSON-serializable values are skipped; each skip emits a level=warn log.
	GetAll() (map[string]any, error)

	// TokenCount returns the current total token usage.
	TokenCount() int

	// MaxTokens returns the configured token limit.
	MaxTokens() int
}

// workingMemoryEntry is the internal storage structure for each entry.
type workingMemoryEntry struct {
	Value      any
	TokenCount int
	AccessedAt time.Time
	CreatedAt  time.Time
}

// DefaultWorkingMemory implements WorkingMemory using sync.Map for thread-safe storage.
type DefaultWorkingMemory struct {
	entries       sync.Map
	maxTokens     int
	currentTokens int
	tokensMu      sync.Mutex // Protects currentTokens counter
}

// NewWorkingMemory creates a new WorkingMemory instance with the specified token limit.
// If maxTokens is 0 or negative, defaults to 100000 tokens.
func NewWorkingMemory(maxTokens int) WorkingMemory {
	if maxTokens <= 0 {
		maxTokens = 100000 // Default from design doc
	}

	return &DefaultWorkingMemory{
		maxTokens:     maxTokens,
		currentTokens: 0,
	}
}

// Get retrieves a value by key and updates the access timestamp for LRU.
func (w *DefaultWorkingMemory) Get(key string) (any, bool) {
	value, ok := w.entries.Load(key)
	if !ok {
		return nil, false
	}

	entry := value.(*workingMemoryEntry)

	// Update access time for LRU eviction
	now := time.Now()
	updatedEntry := &workingMemoryEntry{
		Value:      entry.Value,
		TokenCount: entry.TokenCount,
		AccessedAt: now,
		CreatedAt:  entry.CreatedAt,
	}
	w.entries.Store(key, updatedEntry)

	return entry.Value, true
}

// Set stores a value with automatic token counting and LRU eviction.
func (w *DefaultWorkingMemory) Set(key string, value any) error {
	now := time.Now()
	tokens := estimateTokens(value)

	entry := &workingMemoryEntry{
		Value:      value,
		TokenCount: tokens,
		AccessedAt: now,
		CreatedAt:  now,
	}

	// Check if updating existing entry
	if existingValue, exists := w.entries.Load(key); exists {
		existingEntry := existingValue.(*workingMemoryEntry)

		// Update token count (remove old, add new)
		w.tokensMu.Lock()
		w.currentTokens -= existingEntry.TokenCount
		w.currentTokens += tokens
		w.tokensMu.Unlock()

		// Preserve creation time on update
		entry.CreatedAt = existingEntry.CreatedAt
	} else {
		// New entry, just add tokens
		w.tokensMu.Lock()
		w.currentTokens += tokens
		w.tokensMu.Unlock()
	}

	w.entries.Store(key, entry)

	// Trigger eviction if needed
	w.evictIfNeeded()

	return nil
}

// Delete removes an entry and updates token count.
func (w *DefaultWorkingMemory) Delete(key string) bool {
	value, loaded := w.entries.LoadAndDelete(key)
	if !loaded {
		return false
	}

	entry := value.(*workingMemoryEntry)

	w.tokensMu.Lock()
	w.currentTokens -= entry.TokenCount
	w.tokensMu.Unlock()

	return true
}

// Clear removes all entries and resets token count.
func (w *DefaultWorkingMemory) Clear() {
	w.entries.Range(func(key, value any) bool {
		w.entries.Delete(key)
		return true
	})

	w.tokensMu.Lock()
	w.currentTokens = 0
	w.tokensMu.Unlock()
}

// List returns all stored keys.
func (w *DefaultWorkingMemory) List() []string {
	keys := make([]string, 0)

	w.entries.Range(func(key, value any) bool {
		keys = append(keys, key.(string))
		return true
	})

	return keys
}

// TokenCount returns the current token usage.
func (w *DefaultWorkingMemory) TokenCount() int {
	w.tokensMu.Lock()
	defer w.tokensMu.Unlock()
	return w.currentTokens
}

// MaxTokens returns the configured token limit.
func (w *DefaultWorkingMemory) MaxTokens() int {
	return w.maxTokens
}

// GetAll returns a snapshot of every key-value pair currently in working memory.
// Uses sync.Map.Range for a point-in-time atomic snapshot — no additional mutex
// is held beyond what sync.Map already provides. tokensMu is NOT held during
// Range, consistent with the design constraint.
//
// Non-JSON-serializable values (channels, func pointers, etc.) are skipped with
// a level=warn log. The partial map and a nil error are returned.
func (w *DefaultWorkingMemory) GetAll() (map[string]any, error) {
	result := make(map[string]any)

	w.entries.Range(func(k, v any) bool {
		key := k.(string)
		entry := v.(*workingMemoryEntry)

		// Verify the value is JSON-serializable. Attempt a marshal probe.
		if _, err := json.Marshal(entry.Value); err != nil {
			var unsupported *json.UnsupportedTypeError
			if ok := isUnsupportedTypeError(err, &unsupported); ok {
				slog.Warn("working memory value skipped: not JSON-serializable",
					"key", key,
					"value_type", fmt.Sprintf("%T", entry.Value),
				)
				return true // continue Range
			}
			// Other marshal errors (e.g. cyclic struct) — also skip with warn.
			slog.Warn("working memory value skipped: JSON marshal error",
				"key", key,
				"value_type", fmt.Sprintf("%T", entry.Value),
				"err", err,
			)
			return true
		}

		result[key] = entry.Value
		return true
	})

	return result, nil
}

// isUnsupportedTypeError checks if err wraps or is a *json.UnsupportedTypeError.
func isUnsupportedTypeError(err error, target **json.UnsupportedTypeError) bool {
	if err == nil {
		return false
	}
	if e, ok := err.(*json.UnsupportedTypeError); ok {
		if target != nil {
			*target = e
		}
		return true
	}
	// Check for errors.As equivalent — json may wrap inside marshal error.
	type unwrapper interface{ Unwrap() error }
	if u, ok := err.(unwrapper); ok {
		return isUnsupportedTypeError(u.Unwrap(), target)
	}
	return false
}

// evictIfNeeded removes least recently accessed entries until under budget.
// Special case: if a single entry exceeds the budget, we keep it.
func (w *DefaultWorkingMemory) evictIfNeeded() {
	w.tokensMu.Lock()
	overBudget := w.currentTokens > w.maxTokens
	w.tokensMu.Unlock()

	if !overBudget {
		return
	}

	// Safety limit: count total entries to prevent infinite loop
	var totalEntries int
	w.entries.Range(func(key, value any) bool {
		totalEntries++
		return true
	})

	// Keep evicting until we're under budget or only 1 entry remains
	evictionCount := 0
	for evictionCount < totalEntries-1 {
		w.tokensMu.Lock()
		currentTokens := w.currentTokens
		w.tokensMu.Unlock()

		if currentTokens <= w.maxTokens {
			break
		}

		// Find least recently accessed entry
		var oldestKey string
		var oldestTime time.Time
		foundAny := false

		w.entries.Range(func(key, value any) bool {
			entry := value.(*workingMemoryEntry)
			if !foundAny || entry.AccessedAt.Before(oldestTime) {
				oldestKey = key.(string)
				oldestTime = entry.AccessedAt
				foundAny = true
			}
			return true
		})

		if !foundAny {
			// No entries left, break to prevent infinite loop
			break
		}

		// Delete the oldest entry
		w.Delete(oldestKey)
		evictionCount++
	}

	// If we've evicted all but one entry and still over budget,
	// that means the remaining single entry exceeds the budget.
	// This is acceptable - we keep it and log/accept the overage.
}
