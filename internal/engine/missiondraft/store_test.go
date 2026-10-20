// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package missiondraft

import (
	"context"
	"errors"
	"fmt"
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

	draftID, err := store.Save(ctx, "tenant-a", "My Draft", "name: hello", "", "")
	require.NoError(t, err)
	assert.NotEmpty(t, draftID)
	// UUID format: 8-4-4-4-12
	assert.Len(t, strings.Split(draftID, "-"), 5)
}

func TestList_ReturnsDraft(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.Save(ctx, "tenant-b", "Draft One", "name: one", "", "")
	require.NoError(t, err)

	drafts, err := listAll(ctx, store, "tenant-b")
	require.NoError(t, err)
	require.Len(t, drafts, 1)
	assert.Equal(t, "Draft One", drafts[0].Name)
	assert.Empty(t, drafts[0].CueSource, "CUE source should be omitted from list responses")
}

func TestSave_WithExistingID_Updates(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	id, err := store.Save(ctx, "tenant-c", "Original", "name: original", "", "")
	require.NoError(t, err)

	_, err = store.Save(ctx, "tenant-c", "Updated", "name: updated", id, "")
	require.NoError(t, err)

	drafts, err := listAll(ctx, store, "tenant-c")
	require.NoError(t, err)
	require.Len(t, drafts, 1, "update should not create a second draft")
	assert.Equal(t, "Updated", drafts[0].Name)
}

func TestDelete_RemovesFromList(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	id, err := store.Save(ctx, "tenant-d", "To Delete", "name: delete-me", "", "")
	require.NoError(t, err)

	require.NoError(t, store.Delete(ctx, "tenant-d", id))

	drafts, err := listAll(ctx, store, "tenant-d")
	require.NoError(t, err)
	assert.Empty(t, drafts)
}

func TestSave_CUEExceedsLimit_ReturnsError(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	bigCUE := strings.Repeat("x", 512*1024+1)
	_, err := store.Save(ctx, "tenant-e", "Big Draft", bigCUE, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "512 KB")
}

func TestList_EmptyTenant_ReturnsEmptySlice(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	drafts, err := listAll(ctx, store, "tenant-f")
	require.NoError(t, err)
	assert.Empty(t, drafts)
}

func TestGet_IncludesCUESource(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	const cue = "name: get-test\nversion: 1"
	id, err := store.Save(ctx, "tenant-g", "Get Test", cue, "", "")
	require.NoError(t, err)

	draft, err := store.Get(ctx, "tenant-g", id)
	require.NoError(t, err)
	assert.Equal(t, cue, draft.CueSource)
	assert.Equal(t, "Get Test", draft.Name)
}

// listAll walks every page of a tenant and returns the drafts in order.
func listAll(ctx context.Context, store *RedisMissionDraftStore, tenant string) ([]*MissionDraft, error) {
	var all []*MissionDraft
	after := ""
	for range 1000 {
		page, next, err := store.ListPage(ctx, tenant, after, 100)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		if next == "" {
			return all, nil
		}
		after = next
	}
	return nil, errors.New("the walk did not end")
}

// A walk with saves between the pages gives each first draft once.
func TestListPage_WalkWithSavesBetweenPages(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	first := map[string]bool{}
	for i := range 5 {
		id, err := store.Save(ctx, "tenant-walk", fmt.Sprintf("d%d", i), "x", "", "")
		require.NoError(t, err)
		first[id] = true
	}

	seen := map[string]int{}
	after := ""
	for pages := 0; ; pages++ {
		require.Less(t, pages, 10, "the walk must end")
		page, next, err := store.ListPage(ctx, "tenant-walk", after, 2)
		require.NoError(t, err)
		for _, d := range page {
			seen[d.ID]++
		}
		_, err = store.Save(ctx, "tenant-walk", "late", "x", "", "")
		require.NoError(t, err)
		if next == "" {
			break
		}
		after = next
	}
	for id := range first {
		assert.Equal(t, 1, seen[id], "draft %s", id)
	}
	for id, n := range seen {
		assert.Equal(t, 1, n, "draft %s", id)
	}
}

func TestListPage_SkipsAStaleIndexEntryAndFillsThePage(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	var ids []string
	for i := range 3 {
		id, err := store.Save(ctx, "tenant-stale", fmt.Sprintf("d%d", i), "x", "", "")
		require.NoError(t, err)
		ids = append(ids, id)
	}
	// Remove the hash of one draft and keep its index entry.
	require.NoError(t, store.client.Del(ctx, draftKey("tenant-stale", ids[1])).Err())

	all, err := listAll(ctx, store, "tenant-stale")
	require.NoError(t, err)
	assert.Len(t, all, 2)
}

func TestListPage_Refusals(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	_, _, err := store.ListPage(ctx, "", "", 10)
	require.Error(t, err)
	_, _, err = store.ListPage(ctx, "acme", "", 0)
	require.Error(t, err)
	for _, pos := range []string{"nobar", "|id", "5|"} {
		_, _, err = store.ListPage(ctx, "acme", pos, 10)
		assert.ErrorIs(t, err, ErrBadPosition, pos)
	}
}

// A draft that is saved again during a walk keeps its place: it comes back
// once, and the walk does not miss it.
func TestListPage_ASaveAgainDuringTheWalkKeepsThePlace(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ids := make([]string, 0, 5)
	for i := range 5 {
		id, err := store.Save(ctx, "tenant-resave", fmt.Sprintf("d%d", i), "x", "", "")
		require.NoError(t, err)
		ids = append(ids, id)
	}
	first, next, err := store.ListPage(ctx, "tenant-resave", "", 2)
	require.NoError(t, err)
	require.NotEmpty(t, next)
	seen := map[string]int{}
	for _, d := range first {
		seen[d.ID]++
	}
	// Save again every draft that the walk has not reached.
	for _, id := range ids {
		if seen[id] == 0 {
			_, err := store.Save(ctx, "tenant-resave", "renamed", "x", id, "")
			require.NoError(t, err)
		}
	}
	for next != "" {
		var page []*MissionDraft
		page, next, err = store.ListPage(ctx, "tenant-resave", next, 2)
		require.NoError(t, err)
		for _, d := range page {
			seen[d.ID]++
		}
	}
	for _, id := range ids {
		assert.Equal(t, 1, seen[id], "draft %s", id)
	}
}
