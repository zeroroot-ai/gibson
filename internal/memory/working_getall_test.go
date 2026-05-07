package memory

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetAll_BasicSnapshot verifies that GetAll returns all entries present at call time.
func TestGetAll_BasicSnapshot(t *testing.T) {
	wm := NewWorkingMemory(100000).(*DefaultWorkingMemory)

	require.NoError(t, wm.Set("alpha", "value-a"))
	require.NoError(t, wm.Set("beta", 42))
	require.NoError(t, wm.Set("gamma", map[string]any{"nested": true}))

	got, err := wm.GetAll()
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, 3, len(got))
	assert.Equal(t, "value-a", got["alpha"])
	assert.Equal(t, 42, got["beta"])

	nestedVal, ok := got["gamma"].(map[string]any)
	require.True(t, ok, "gamma should be a map")
	assert.Equal(t, true, nestedVal["nested"])
}

// TestGetAll_SkipsNonSerializable verifies that non-JSON-serializable values
// (channels, func pointers) are absent from the result and no error is returned.
func TestGetAll_SkipsNonSerializable(t *testing.T) {
	wm := &DefaultWorkingMemory{}

	// Store a JSON-serializable entry.
	require.NoError(t, wm.Set("good_key", "good_value"))

	// Bypass json.Marshal check in Set by directly storing a channel entry
	// via the sync.Map, simulating a non-serializable value in working memory.
	ch := make(chan struct{})
	wm.entries.Store("bad_key", &workingMemoryEntry{Value: ch, TokenCount: 1})

	got, err := wm.GetAll()
	require.NoError(t, err, "GetAll must not return an error for skipped entries")
	require.NotNil(t, got)

	// The good key should be present.
	assert.Equal(t, "good_value", got["good_key"])

	// The bad key must be absent.
	_, hasBad := got["bad_key"]
	assert.False(t, hasBad, "non-serializable key must be absent from GetAll result")
}

// TestGetAll_ConcurrentSetDuringRange verifies no race detector hit and no panic
// when GetAll runs concurrently with Set and Delete operations.
func TestGetAll_ConcurrentSetDuringRange(t *testing.T) {
	wm := NewWorkingMemory(1000000).(*DefaultWorkingMemory)

	// Pre-populate
	for i := 0; i < 20; i++ {
		require.NoError(t, wm.Set(fmt.Sprintf("key-%d", i), fmt.Sprintf("value-%d", i)))
	}

	var wg sync.WaitGroup
	numGoroutines := 50

	// Spawn concurrent writers and deleters.
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := fmt.Sprintf("concurrent-%d", id)
			_ = wm.Set(key, id)
			if id%3 == 0 {
				wm.Delete(key)
			}
		}(i)
	}

	// GetAll runs concurrently with the above.
	wg.Add(1)
	go func() {
		defer wg.Done()
		got, err := wm.GetAll()
		// No error expected; partial snapshot is acceptable.
		assert.NoError(t, err)
		assert.NotNil(t, got)
	}()

	wg.Wait()
}

// TestGetAll_EmptyMemory verifies that GetAll on a fresh instance returns an
// empty non-nil map and a nil error.
func TestGetAll_EmptyMemory(t *testing.T) {
	wm := NewWorkingMemory(100000).(*DefaultWorkingMemory)

	got, err := wm.GetAll()
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, 0, len(got))
}

// TestGetAll_PartialTruncation verifies that truncateMemorySnapshot trims the
// snapshot to the configured threshold, keeping lexicographically first keys and
// discarding the rest.
//
// This test exercises the helper that CaptureExecutionState uses (task 9).
// The helper is defined in checkpoint_integration.go in the orchestrator package,
// but we test the behavior via a local mirror here to validate the algorithm
// before wiring.
func TestGetAll_PartialTruncation(t *testing.T) {
	// Build a snapshot whose entries, when serialized, exceed a small threshold.
	// Each entry value is a 100-byte string; 5 entries = ~500 bytes serialized.
	snapshot := make(map[string]any)
	keys := []string{"aaa", "bbb", "ccc", "ddd", "eee"}
	for _, k := range keys {
		snapshot[k] = string(make([]byte, 100))
	}

	serialized, err := json.Marshal(snapshot)
	require.NoError(t, err)
	require.Greater(t, len(serialized), 0)

	// Apply the local truncation algorithm: sort keys, keep from front until threshold.
	// Threshold that allows ~2 entries.
	threshold := int64(len(serialized) / 3)

	truncated := localTruncateMemorySnapshot(snapshot, threshold)

	// The result must have fewer keys than the original.
	assert.Less(t, len(truncated), len(snapshot))

	// The retained keys must be the lexicographically first ones.
	sortedKeys := make([]string, 0, len(snapshot))
	for k := range snapshot {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	for k := range truncated {
		// Each retained key must appear before the first discarded key.
		idx := sort.SearchStrings(sortedKeys, k)
		firstDroppedIdx := len(truncated) // First idx not in truncated
		assert.Less(t, idx, firstDroppedIdx, "retained keys must be from the lexicographic front")
	}

	// The serialized truncated map must fit within the threshold.
	truncatedBytes, err := json.Marshal(truncated)
	require.NoError(t, err)
	assert.LessOrEqual(t, int64(len(truncatedBytes)), threshold,
		"truncated snapshot must fit within threshold")
}

// localTruncateMemorySnapshot mirrors the algorithm in truncateMemorySnapshot
// (orchestrator package, task 9). Used here so the unit test does not have a
// cross-package dependency before task 9 is implemented.
func localTruncateMemorySnapshot(snapshot map[string]any, threshold int64) map[string]any {
	if threshold <= 0 {
		return make(map[string]any)
	}

	keys := make([]string, 0, len(snapshot))
	for k := range snapshot {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	result := make(map[string]any)
	for _, k := range keys {
		result[k] = snapshot[k]
		b, err := json.Marshal(result)
		if err != nil {
			// Should not happen; remove the just-added key and stop.
			delete(result, k)
			break
		}
		if int64(len(b)) > threshold {
			delete(result, k)
			break
		}
	}
	return result
}
