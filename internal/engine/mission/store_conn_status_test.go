// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mission

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// gibson#1112: the status secondary index is gone. The status predicate is
// applied per candidate by missionMatchesFilter, and GetActive /
// GetByNameAndStatus are compositions over List and the (surviving) name
// index. These tests pin the predicate semantics — the part that actually
// replaced the index — and the composition/skip paths.
//
// Redis JSON commands are not available under miniredis, so store-level
// tests here exercise the paths that do not require a JSON document to
// exist: SCAN candidate collection, name-index lookup, unparseable-ID and
// missing-document skips, and the not-found tails. Full JSON round-trips run
// in the cluster-bound suites.

func TestMissionMatchesFilter_StatusPredicate(t *testing.T) {
	running := MissionStatusRunning
	paused := MissionStatusPaused

	m := &Mission{Status: MissionStatusRunning}

	assert.True(t, missionMatchesFilter(m, &MissionFilter{Status: &running}),
		"a running mission must match a running filter")
	assert.False(t, missionMatchesFilter(m, &MissionFilter{Status: &paused}),
		"a running mission must not match a paused filter — this predicate is "+
			"what replaced the status index; if it stops filtering, status-"+
			"filtered List silently returns everything")
	assert.True(t, missionMatchesFilter(m, &MissionFilter{}),
		"no status filter matches any status")
}

func TestListStatusFilter_TakesScanPath(t *testing.T) {
	store, mr := newTestConnBoundStore(t)
	ctx := context.Background()

	// Keys matching the scan pattern whose documents cannot be loaded (no
	// JSON doc under miniredis) are skipped, not fatal.
	require.NoError(t, mr.Set("gibson:mission:0123456789abcdef", "not-a-json-doc"))

	running := MissionStatusRunning
	missions, err := store.List(ctx, &MissionFilter{Status: &running})
	require.NoError(t, err,
		"a status-filtered List must take the SCAN path without a status index")
	assert.Empty(t, missions)
}

func TestGetActive_ComposesStatusFilteredLists(t *testing.T) {
	store, _ := newTestConnBoundStore(t)

	missions, err := store.GetActive(context.Background())
	require.NoError(t, err)
	assert.Empty(t, missions,
		"an empty store has no active missions, and no error — GetActive is "+
			"a composition of two status-filtered Lists, not an index read")
}

func TestGetByNameAndStatus_NotFoundOnEmptyNameIndex(t *testing.T) {
	store, _ := newTestConnBoundStore(t)

	_, err := store.GetByNameAndStatus(context.Background(), "no-such-mission", MissionStatusRunning)
	require.Error(t, err)
	assert.True(t, IsNotFoundError(err), "empty name index -> NotFound, got: %v", err)
}

func TestGetByNameAndStatus_SkipsUnloadableCandidates(t *testing.T) {
	store, mr := newTestConnBoundStore(t)
	ctx := context.Background()

	// The name index survives (record identity, not folded state). Seed it
	// with an unparseable member and a well-formed ID that has no document:
	// both are skipped, and the tail is NotFound rather than an error.
	_, err := mr.SAdd(cbMissionByNameKey("recon"), "not-a-valid-id")
	require.NoError(t, err)
	_, err = mr.SAdd(cbMissionByNameKey("recon"), types.NewID().String())
	require.NoError(t, err)

	_, gerr := store.GetByNameAndStatus(ctx, "recon", MissionStatusRunning)
	require.Error(t, gerr)
	assert.True(t, IsNotFoundError(gerr),
		"unloadable candidates are skipped and the tail is NotFound, got: %v", gerr)
}
