// Package mission — definition_cue_source_test.go
//
// Round-trip tests for the raw CUE source persisted alongside a mission
// definition (gibson#504). The source lives in a sibling Redis key so
// GetMissionDefinition can return the author's exact CUE rather than a
// reconstruction.
package mission

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

func TestDefinitionCueSource_RoundTrip(t *testing.T) {
	store, mr := newTestConnBoundStore(t)
	defer mr.Close()
	ctx := context.Background()

	const name = "round-trip"
	const cue = "mission: { name: \"round-trip\"\n description: \"x\" }"
	require.NoError(t, store.CreateDefinition(ctx, &missionv1.MissionDefinition{Name: name}))
	require.NoError(t, store.SetDefinitionSource(ctx, name, cue))

	got, err := store.GetDefinitionSource(ctx, name)
	require.NoError(t, err)
	assert.Equal(t, cue, got, "stored CUE source must round-trip byte-identically")
}

func TestDefinitionCueSource_UpdateInPlace(t *testing.T) {
	store, mr := newTestConnBoundStore(t)
	defer mr.Close()
	ctx := context.Background()

	const name = "iterate"
	require.NoError(t, store.CreateDefinition(ctx, &missionv1.MissionDefinition{Name: name}))
	require.NoError(t, store.SetDefinitionSource(ctx, name, "v1"))
	require.NoError(t, store.SetDefinitionSource(ctx, name, "v2"))

	got, err := store.GetDefinitionSource(ctx, name)
	require.NoError(t, err)
	assert.Equal(t, "v2", got, "SetDefinitionSource must overwrite in place")
}

func TestDefinitionCueSource_MissingReturnsEmpty(t *testing.T) {
	store, mr := newTestConnBoundStore(t)
	defer mr.Close()
	ctx := context.Background()

	got, err := store.GetDefinitionSource(ctx, "never-set")
	require.NoError(t, err, "a missing source is not an error")
	assert.Equal(t, "", got)
}

func TestDefinitionCueSource_EmptyIsNoOp(t *testing.T) {
	store, mr := newTestConnBoundStore(t)
	defer mr.Close()
	ctx := context.Background()

	const name = "no-clobber"
	require.NoError(t, store.SetDefinitionSource(ctx, name, "keep-me"))
	// An empty source (e.g. a CLI registration without source) must not wipe
	// an existing record.
	require.NoError(t, store.SetDefinitionSource(ctx, name, ""))

	got, err := store.GetDefinitionSource(ctx, name)
	require.NoError(t, err)
	assert.Equal(t, "keep-me", got)
}

func TestDefinitionCueSource_RejectsOversized(t *testing.T) {
	store, mr := newTestConnBoundStore(t)
	defer mr.Close()
	ctx := context.Background()

	oversized := strings.Repeat("a", maxDefinitionCueBytes+1)
	err := store.SetDefinitionSource(ctx, "too-big", oversized)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "512 KB")
}

func TestDefinitionCueSource_DeletedWithDefinition(t *testing.T) {
	store, mr := newTestConnBoundStore(t)
	defer mr.Close()
	ctx := context.Background()

	const name = "ephemeral"
	require.NoError(t, store.CreateDefinition(ctx, &missionv1.MissionDefinition{Name: name}))
	require.NoError(t, store.SetDefinitionSource(ctx, name, "bye"))
	require.NoError(t, store.DeleteDefinition(ctx, name))

	got, err := store.GetDefinitionSource(ctx, name)
	require.NoError(t, err)
	assert.Equal(t, "", got, "deleting a definition must remove its CUE source")
}
