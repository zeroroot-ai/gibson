package missiondraft

// durability_link_test.go — gibson#505.
//
// Authored records must be durable (no TTL) so a mission can be reopened at any
// time, and must carry the mission_definition_id link so the run flow can
// update the right definition in place.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSave_IsDurable_NoTTL(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	id, err := store.Save(ctx, "tenant-dur", "Durable", "name: durable", "", "")
	require.NoError(t, err)

	ttl, err := store.client.TTL(ctx, draftKey("tenant-dur", id)).Result()
	require.NoError(t, err)
	assert.True(t, ttl < 0, "authored records must have no TTL (got %v)", ttl)
}

func TestSave_ClearsLegacyTTL(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	id, err := store.Save(ctx, "tenant-ttl", "Has TTL", "name: x", "", "")
	require.NoError(t, err)
	key := draftKey("tenant-ttl", id)

	// Simulate a record written by the pre-#505 code path that carried a 30-day
	// TTL.
	require.NoError(t, store.client.Expire(ctx, key, 30*24*time.Hour).Err())
	pre, _ := store.client.TTL(ctx, key).Result()
	require.True(t, pre > 0, "precondition: TTL is set")

	// Reopening (an in-place Save) must clear it.
	_, err = store.Save(ctx, "tenant-ttl", "Has TTL", "name: x2", id, "")
	require.NoError(t, err)

	post, err := store.client.TTL(ctx, key).Result()
	require.NoError(t, err)
	assert.True(t, post < 0, "Save must clear any pre-existing TTL (got %v)", post)
}

func TestMissionDefinitionLink_RoundTrips(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	id, err := store.Save(ctx, "tenant-link", "Linked", "name: linked", "", "def-123")
	require.NoError(t, err)

	got, err := store.Get(ctx, "tenant-link", id)
	require.NoError(t, err)
	assert.Equal(t, "def-123", got.MissionDefinitionID)

	list, err := store.List(ctx, "tenant-link")
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "def-123", list[0].MissionDefinitionID)
}

func TestMissionDefinitionLink_EmptyWhenNeverRun(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	id, err := store.Save(ctx, "tenant-norun", "Unrun", "name: unrun", "", "")
	require.NoError(t, err)

	got, err := store.Get(ctx, "tenant-norun", id)
	require.NoError(t, err)
	assert.Equal(t, "", got.MissionDefinitionID)
}

func TestMissionDefinitionLink_UpdatePreservesViaResave(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// First run links the definition; a later in-place save re-supplies it.
	id, err := store.Save(ctx, "tenant-up", "Iterate", "v1", "", "def-9")
	require.NoError(t, err)
	_, err = store.Save(ctx, "tenant-up", "Iterate", "v2", id, "def-9")
	require.NoError(t, err)

	got, err := store.Get(ctx, "tenant-up", id)
	require.NoError(t, err)
	assert.Equal(t, "def-9", got.MissionDefinitionID)
	assert.Equal(t, "v2", got.CueSource)
}
