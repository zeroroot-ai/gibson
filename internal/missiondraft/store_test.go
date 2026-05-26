package missiondraft

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestStore creates a RedisMissionDraftStore backed by an in-process miniredis.
func newTestStore(t *testing.T) *RedisMissionDraftStore {
	t.Helper()
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return New(client, logger)
}

func TestSave_CreatesWithUUID(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	draftID, err := store.Save(ctx, "tenant-a", "My Draft", "name: hello", "")
	require.NoError(t, err)
	assert.NotEmpty(t, draftID)
	// UUID format: 8-4-4-4-12
	assert.Len(t, strings.Split(draftID, "-"), 5)
}

func TestList_ReturnsDraft(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.Save(ctx, "tenant-b", "Draft One", "name: one", "")
	require.NoError(t, err)

	drafts, err := store.List(ctx, "tenant-b")
	require.NoError(t, err)
	require.Len(t, drafts, 1)
	assert.Equal(t, "Draft One", drafts[0].Name)
	assert.Empty(t, drafts[0].CueSource, "CUE source should be omitted from list responses")
}

func TestSave_WithExistingID_Updates(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	id, err := store.Save(ctx, "tenant-c", "Original", "name: original", "")
	require.NoError(t, err)

	_, err = store.Save(ctx, "tenant-c", "Updated", "name: updated", id)
	require.NoError(t, err)

	drafts, err := store.List(ctx, "tenant-c")
	require.NoError(t, err)
	require.Len(t, drafts, 1, "update should not create a second draft")
	assert.Equal(t, "Updated", drafts[0].Name)
}

func TestDelete_RemovesFromList(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	id, err := store.Save(ctx, "tenant-d", "To Delete", "name: delete-me", "")
	require.NoError(t, err)

	require.NoError(t, store.Delete(ctx, "tenant-d", id))

	drafts, err := store.List(ctx, "tenant-d")
	require.NoError(t, err)
	assert.Empty(t, drafts)
}

func TestSave_CUEExceedsLimit_ReturnsError(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	bigCUE := strings.Repeat("x", 512*1024+1)
	_, err := store.Save(ctx, "tenant-e", "Big Draft", bigCUE, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "512 KB")
}

func TestList_EmptyTenant_ReturnsEmptySlice(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	drafts, err := store.List(ctx, "tenant-f")
	require.NoError(t, err)
	assert.Empty(t, drafts)
}

func TestGet_IncludesCUESource(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	const cue = "name: get-test\nversion: 1"
	id, err := store.Save(ctx, "tenant-g", "Get Test", cue, "")
	require.NoError(t, err)

	draft, err := store.Get(ctx, "tenant-g", id)
	require.NoError(t, err)
	assert.Equal(t, cue, draft.CueSource)
	assert.Equal(t, "Get Test", draft.Name)
}

func TestGet_LegacyYAMLField_Fallback(t *testing.T) {
	// Simulates a draft written before the cue_source rename: the Redis hash
	// has a "yaml" field but no "cue_source" field. Get must fall back to it.
	store := newTestStore(t)
	ctx := context.Background()

	const legacyCUE = "name: legacy\nversion: 0"
	draftID := "legacy-draft-id"
	key := draftKey("tenant-h", draftID)

	// Write directly with the old "yaml" field, bypassing Save.
	err := store.client.HMSet(ctx, key, map[string]any{
		"id":         draftID,
		"name":       "Legacy Draft",
		"yaml":       legacyCUE,
		"created_at": "2025-01-01T00:00:00Z",
		"updated_at": "2025-01-01T00:00:00Z",
	}).Err()
	require.NoError(t, err)
	err = store.client.ZAdd(ctx, indexKey("tenant-h"), goredis.Z{Score: 1, Member: draftID}).Err()
	require.NoError(t, err)

	draft, err := store.Get(ctx, "tenant-h", draftID)
	require.NoError(t, err)
	assert.Equal(t, legacyCUE, draft.CueSource)
}
