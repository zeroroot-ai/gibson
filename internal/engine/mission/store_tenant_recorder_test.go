// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mission_test

import (
	"context"
	"errors"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/engine/mission/missiontest"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// fakeRecorder keeps the tuples of the missions as a set. It also notes the
// order of its calls against the store.
type fakeRecorder struct {
	tuples map[string]bool
	calls  []string
	err    error
	docs   *missiontest.Docs
	// existedAtRecord notes, for each Record, whether the mission document
	// already existed. The tuple must come first.
	existedAtRecord []bool
}

func (f *fakeRecorder) Record(_ context.Context, tenant string, id types.ID) error {
	f.calls = append(f.calls, "record:"+tenant+"/"+id.String())
	if f.err != nil {
		return f.err
	}
	f.existedAtRecord = append(f.existedAtRecord, f.docs.Has("gibson:mission:"+id.String()))
	f.tuples[tenant+"|"+id.String()] = true
	return nil
}

func (f *fakeRecorder) Forget(_ context.Context, tenant string, id types.ID) error {
	f.calls = append(f.calls, "forget:"+tenant+"/"+id.String())
	delete(f.tuples, tenant+"|"+id.String())
	return nil
}

func newRecordingStore(t *testing.T) (*mission.ConnBoundMissionStore, *fakeRecorder, *missiontest.Docs) {
	t.Helper()
	rdb, docs := newJSONFakeClient(t)
	rec := &fakeRecorder{tuples: map[string]bool{}, docs: docs}
	return mission.NewConnBoundMissionStore(rdb).WithTenantRecorder(rec, "acme"), rec, docs
}

func newMission(name string) *mission.Mission {
	return &mission.Mission{
		ID: types.NewID(), TenantID: "acme", Name: name, Status: mission.MissionStatusSubmitted,
		TargetID: types.NewID(), MissionDefinitionID: types.NewID(),
	}
}

func TestSave_RecordsTheTenantBeforeTheMissionExists(t *testing.T) {
	store, rec, docs := newRecordingStore(t)
	m := newMission("save-1")
	require.NoError(t, store.Save(context.Background(), m))

	assert.True(t, rec.tuples["acme|"+m.ID.String()], "the tuple exists after the mission does")
	assert.True(t, docs.Has("gibson:mission:"+m.ID.String()))
	assert.Equal(t, []bool{false}, rec.existedAtRecord, "the tuple is written before the record")
}

func TestSave_AFailedRecordCreatesNoMission(t *testing.T) {
	store, rec, docs := newRecordingStore(t)
	rec.err = errors.New("fga down")
	m := newMission("save-2")
	err := store.Save(context.Background(), m)
	require.Error(t, err)
	assert.Zero(t, docs.Count(), "a mission must not exist without its tuple")
}

func TestFindOrCreateByName_RecordsANewMissionAndRepairsAnExistingOne(t *testing.T) {
	store, rec, _ := newRecordingStore(t)
	ctx := context.Background()
	first, created, err := store.FindOrCreateByName(ctx, newMission("by-name"))
	require.NoError(t, err)
	require.True(t, created)
	assert.True(t, rec.tuples["acme|"+first.ID.String()])
	assert.Equal(t, []bool{false}, rec.existedAtRecord)

	// A mission that exists gets its tuple again. The write is idempotent, and a
	// mission made before the store wrote tuples is repaired by its next run.
	again, created, err := store.FindOrCreateByName(ctx, newMission("by-name"))
	require.NoError(t, err)
	assert.False(t, created)
	assert.Equal(t, first.ID, again.ID)
	assert.Equal(t, []bool{false, true}, rec.existedAtRecord, "the repeat records the mission that exists")
}

func TestFindOrCreateByName_ARunByNameRepairsAMissionWithNoTuple(t *testing.T) {
	rdb, docs := newJSONFakeClient(t)
	ctx := context.Background()
	old := missiontest.NewRecorder()
	m := newMission("made-before")
	require.NoError(t, mission.NewConnBoundMissionStore(rdb).WithTenantRecorder(old, "acme").Save(ctx, m))
	require.True(t, docs.Has("gibson:mission:"+m.ID.String()))

	// A new recorder is a store with no tuple for the mission.
	fresh := missiontest.NewRecorder()
	store := mission.NewConnBoundMissionStore(rdb).WithTenantRecorder(fresh, "acme")
	found, created, err := store.FindOrCreateByName(ctx, newMission("made-before"))
	require.NoError(t, err)
	require.False(t, created)
	assert.True(t, fresh.Has("acme", found.ID), "a run by name writes the tuple of a mission that has none")

	// A run by ID goes through Save.
	fresh2 := missiontest.NewRecorder()
	byID := mission.NewConnBoundMissionStore(rdb).WithTenantRecorder(fresh2, "acme")
	require.NoError(t, byID.Save(ctx, found))
	assert.True(t, fresh2.Has("acme", found.ID))
}

func TestFindOrCreateByName_AFailedRecordCreatesNoMission(t *testing.T) {
	store, rec, docs := newRecordingStore(t)
	rec.err = errors.New("fga down")
	_, _, err := store.FindOrCreateByName(context.Background(), newMission("by-name-2"))
	require.Error(t, err)
	assert.Zero(t, docs.Count())
}

func TestDelete_RemovesTheTenantTuple(t *testing.T) {
	store, rec, docs := newRecordingStore(t)
	ctx := context.Background()
	m := newMission("delete-1")
	m.Status = mission.MissionStatusCompleted
	require.NoError(t, store.Save(ctx, m))
	require.True(t, rec.tuples["acme|"+m.ID.String()])

	require.NoError(t, store.Delete(ctx, m.ID))
	assert.False(t, rec.tuples["acme|"+m.ID.String()], "the tuple goes with the mission")
	assert.False(t, docs.Has("gibson:mission:"+m.ID.String()))
}

// A store that creates a mission with no recorder fails, so a call site that
// forgets the recorder meets the error in its first test.
func TestStoreWithNoRecorderRefusesToCreateOrDelete(t *testing.T) {
	rdb, docs := newJSONFakeClient(t)
	store := mission.NewConnBoundMissionStore(rdb)
	ctx := context.Background()

	require.ErrorIs(t, store.Save(ctx, newMission("plain")), mission.ErrNoTenantRecorder)
	_, _, err := store.FindOrCreateByName(ctx, newMission("plain-2"))
	require.ErrorIs(t, err, mission.ErrNoTenantRecorder)
	require.ErrorIs(t, store.Delete(ctx, types.NewID()), mission.ErrNoTenantRecorder)
	assert.Zero(t, docs.Count(), "no mission exists")
}

// The record write fails after the tuple write. The tuple of a mission that does
// not exist goes, as a best effort.
func TestSave_AFailedRecordWriteForgetsTheNewTuple(t *testing.T) {
	store, rec, docs := newRecordingStore(t)
	docs.FailSet = true
	m := newMission("save-fail")
	require.Error(t, store.Save(context.Background(), m))
	assert.False(t, rec.tuples["acme|"+m.ID.String()], "the tuple of a mission that was not created goes")
	assert.Contains(t, rec.calls, "forget:acme/"+m.ID.String())
}

// A Save of a mission that exists and fails must not remove the tuple: the
// mission is still there.
func TestSave_AFailedUpdateKeepsTheTupleOfAMissionThatExists(t *testing.T) {
	store, rec, docs := newRecordingStore(t)
	ctx := context.Background()
	m := newMission("save-update")
	require.NoError(t, store.Save(ctx, m))
	docs.FailSet = true
	require.Error(t, store.Save(ctx, m))
	assert.True(t, rec.tuples["acme|"+m.ID.String()], "the mission exists, so its tuple stays")
	assert.NotContains(t, rec.calls, "forget:acme/"+m.ID.String())
}

func TestFindOrCreateByName_AFailedRecordWriteForgetsTheNewTuple(t *testing.T) {
	store, rec, docs := newRecordingStore(t)
	docs.FailSet = true
	_, _, err := store.FindOrCreateByName(context.Background(), newMission("create-fail"))
	require.Error(t, err)
	assert.Empty(t, rec.tuples)
	require.Len(t, rec.calls, 2)
	assert.Contains(t, rec.calls[1], "forget:")
}

// The error of a failed tuple write is marked, so the API maps it to Unavailable.
func TestAFailedTupleWriteIsMarked(t *testing.T) {
	store, rec, _ := newRecordingStore(t)
	rec.err = errors.New("tuple not found in the store")
	err := store.Save(context.Background(), newMission("marked"))
	require.ErrorIs(t, err, mission.ErrTenantRecordFailed)
}

// newJSONFakeClient returns a client on a miniredis server with the JSON
// commands of the mission store answered by missiontest.
func newJSONFakeClient(t *testing.T) (*redis.Client, *missiontest.Docs) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb, missiontest.Attach(rdb)
}
