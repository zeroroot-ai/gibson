// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// historyEngine returns an engine with a durable store and a snapshot after
// each two events, with seven events applied: two missions and five hosts.
func historyEngine(t *testing.T) (*Engine, *memTimelineStore) {
	t.Helper()
	store := &memTimelineStore{}
	e := NewEngine("t").WithStore(store).WithSnapshotCadence(2)
	e.Submit(MissionStarted{ID: "A", Goal: "g"})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.1", MissionID: "A"})
	e.Submit(MissionStarted{ID: "B", Goal: "g"})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.2", MissionID: "B"})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.3", MissionID: "A"})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.4", MissionID: "A"})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", MissionID: "B"})
	require.Equal(t, 7, e.Tick())
	require.Equal(t, 1, store.remaining(), "three snapshots trimmed six events from the stream")
	return e, store
}

// The history of a store-backed engine is each event, in order, after the
// stream trim removed most of them (ADR-0163, gibson#786).
func TestEngine_HistoryIsTheFullOrderedHistoryAfterATrim(t *testing.T) {
	e, _ := historyEngine(t)
	ctx := context.Background()

	history, err := e.History(ctx)
	require.NoError(t, err)
	require.Len(t, history, 7)
	assert.Equal(t, "mission.started", history[0].Kind())
	last, ok := history[6].(HostObserved)
	require.True(t, ok)
	assert.Equal(t, "10.0.0.5", last.Address)

	missionA, err := e.MissionHistory(ctx, "A")
	require.NoError(t, err)
	assert.Len(t, missionA, 4, "mission A: its start and three hosts")

	// A new engine on the same store hydrates the snapshot and the tail. Its
	// in-memory Timeline holds only the tail, and its history is still full.
	fresh := NewEngine("t").WithStore(e.store)
	require.NoError(t, fresh.Hydrate(ctx))
	require.Less(t, len(fresh.Events()), 7, "the in-memory Timeline of a hydrated engine is the tail")
	freshHistory, err := fresh.History(ctx)
	require.NoError(t, err)
	assert.Equal(t, history, freshHistory)
}

// A replay frame folds the full history, so a frame before the last snapshot
// is still there after the trim.
func TestEngine_HistoryFrameAtFoldsTheFullHistory(t *testing.T) {
	e, _ := historyEngine(t)
	ctx := context.Background()

	frame, seq, total, err := e.HistoryFrameAt(ctx, "", 2)
	require.NoError(t, err)
	assert.Equal(t, 2, seq)
	assert.Equal(t, 7, total)
	assert.Len(t, frame.Snapshot(), 1, "the frame after two events holds one host")

	end, seq, total, err := e.HistoryFrameAt(ctx, "", 99)
	require.NoError(t, err)
	assert.Equal(t, 7, seq, "n is clamped to the total")
	assert.Equal(t, 7, total)
	assert.Equal(t, e.Hosts(), end.Snapshot(), "the last frame is the live World")

	start, seq, _, err := e.HistoryFrameAt(ctx, "", -3)
	require.NoError(t, err)
	assert.Equal(t, 0, seq)
	assert.Empty(t, start.Snapshot())

	missionB, seq, total, err := e.HistoryFrameAt(ctx, "B", 2)
	require.NoError(t, err)
	assert.Equal(t, 2, seq)
	assert.Equal(t, 3, total, "mission B: its start and two hosts")
	assert.Len(t, missionB.Snapshot(), 1)
}

// An engine with no store never trims, so its in-memory Timeline is the full
// history and the frame methods read it.
func TestEngine_HistoryOfAnEngineWithNoStoreIsItsTimeline(t *testing.T) {
	e := NewEngine("t")
	e.Submit(MissionStarted{ID: "A", Goal: "g"})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.1", MissionID: "A"})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.2"})
	e.Tick()
	ctx := context.Background()

	history, err := e.History(ctx)
	require.NoError(t, err)
	assert.Equal(t, e.Events(), history)

	missionA, err := e.MissionHistory(ctx, "A")
	require.NoError(t, err)
	assert.Equal(t, e.MissionEvents("A"), missionA)

	frame, seq, total, err := e.HistoryFrameAt(ctx, "", 2)
	require.NoError(t, err)
	assert.Equal(t, 2, seq)
	assert.Equal(t, 3, total)
	assert.Equal(t, e.FrameAt(2).Snapshot(), frame.Snapshot())

	scoped, seq, total, err := e.HistoryFrameAt(ctx, "A", 9)
	require.NoError(t, err)
	assert.Equal(t, 2, seq)
	assert.Equal(t, 2, total)
	assert.Equal(t, e.MissionFrameAt("A", 2).Snapshot(), scoped.Snapshot())
}

// historyFailStore fails each history read.
type historyFailStore struct{ memTimelineStore }

var errHistoryDown = errors.New("the history is down")

func (*historyFailStore) LoadHistory(context.Context, string) ([]Event, error) {
	return nil, errHistoryDown
}

// A history read that fails is an error for the reader, never a short history.
func TestEngine_HistoryReturnsTheStoreError(t *testing.T) {
	e := NewEngine("t").WithStore(&historyFailStore{})
	ctx := context.Background()

	_, err := e.History(ctx)
	require.ErrorIs(t, err, errHistoryDown)
	_, err = e.MissionHistory(ctx, "A")
	require.ErrorIs(t, err, errHistoryDown)
	_, _, _, err = e.HistoryFrameAt(ctx, "", 1)
	require.ErrorIs(t, err, errHistoryDown)
}
