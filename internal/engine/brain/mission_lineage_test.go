// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func lineageEvents() []Event {
	return []Event{
		MissionProjected{ID: "parent", Goal: "find a path"},
		MissionOriginated{
			MissionID: "child-1", ParentMissionID: "parent", ParentWorkID: "parent/scan",
			OriginatingComponent: "agent_principal:recon", CapabilityGrantID: "grant-1",
		},
		MissionOriginated{
			MissionID: "child-2", ParentMissionID: "child-1", ParentWorkID: "child-1-dec-1",
			OriginatingComponent: "agent_principal:exploit", CapabilityGrantID: "grant-2",
		},
	}
}

// The reducer folds the lineage event, and the World answers which mission
// started which.
func TestMissionOriginated_FoldsTheLineage(t *testing.T) {
	e := NewEngine("t")
	for _, ev := range lineageEvents() {
		e.Submit(ev)
	}
	e.Tick()

	got, ok := e.MissionLineage("child-1")
	require.True(t, ok)
	assert.Equal(t, MissionLineage{
		MissionID: "child-1", ParentMissionID: "parent", ParentWorkID: "parent/scan",
		OriginatingComponent: "agent_principal:recon", CapabilityGrantID: "grant-1",
	}, got)

	_, ok = e.MissionLineage("parent")
	assert.False(t, ok, "a mission that no component originated has no lineage")

	all := e.World.MissionLineageSnapshot()
	require.Len(t, all, 2)
	assert.Equal(t, "child-1", all[0].MissionID)
	assert.Equal(t, "child-2", all[1].MissionID)
}

// The acceptance test of gibson#734: a replay of the Timeline rebuilds the
// lineage, with no second store.
func TestMissionOriginated_AReplayRebuildsTheLineage(t *testing.T) {
	e := NewEngine("t")
	for _, ev := range lineageEvents() {
		e.Submit(ev)
	}
	e.Tick()

	replayed := Replay("t", e.Timeline)
	assert.Equal(t, e.World.MissionLineageSnapshot(), replayed.MissionLineageSnapshot())

	// The chain is readable from the replayed World alone.
	l2, ok := replayed.MissionLineage("child-2")
	require.True(t, ok)
	l1, ok := replayed.MissionLineage(l2.ParentMissionID)
	require.True(t, ok)
	assert.Equal(t, "parent", l1.ParentMissionID)
}

// Lineage is a fact about the creation of a mission: the first event wins.
func TestMissionOriginated_TheFirstEventWins(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, MissionOriginated{MissionID: "m", ParentMissionID: "p1", CapabilityGrantID: "g1"})
	Reduce(w, MissionOriginated{MissionID: "m", ParentMissionID: "p2", CapabilityGrantID: "g2"})
	Reduce(w, MissionOriginated{ParentMissionID: "p3"}) // no mission id: ignored

	got, ok := w.MissionLineage("m")
	require.True(t, ok)
	assert.Equal(t, "p1", got.ParentMissionID)
	assert.Equal(t, "g1", got.CapabilityGrantID)
	assert.Len(t, w.MissionLineageSnapshot(), 1)
}

func TestMissionOriginated_RoundTripsTheCodec(t *testing.T) {
	in := lineageEvents()[1]
	b, err := EncodeEvent(in)
	require.NoError(t, err)
	out, err := DecodeEvent(b)
	require.NoError(t, err)
	assert.Equal(t, in, out)
}

// The World snapshot holds the lineage, so the lineage is still there after
// the trim removed the mission.originated events from the stream.
func TestMissionOriginated_SurvivesASnapshot(t *testing.T) {
	w := NewWorld("t")
	for _, ev := range lineageEvents() {
		Reduce(w, ev)
	}

	restored, err := RestoreWorld(SnapshotWorld(w, "7-0"), "t")
	require.NoError(t, err)
	assert.Equal(t, w.MissionLineageSnapshot(), restored.MissionLineageSnapshot())
	require.Len(t, restored.MissionLineageSnapshot(), 2)
}
