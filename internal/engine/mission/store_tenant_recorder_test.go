// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mission_test

import (
	"context"
	"errors"
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
	rdb, docs := missiontest.NewClient(t)
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

func TestFindOrCreateByName_RecordsOnlyANewMission(t *testing.T) {
	store, rec, _ := newRecordingStore(t)
	ctx := context.Background()
	first, created, err := store.FindOrCreateByName(ctx, newMission("by-name"))
	require.NoError(t, err)
	require.True(t, created)
	assert.True(t, rec.tuples["acme|"+first.ID.String()])
	assert.Equal(t, []bool{false}, rec.existedAtRecord)

	again, created, err := store.FindOrCreateByName(ctx, newMission("by-name"))
	require.NoError(t, err)
	assert.False(t, created)
	assert.Equal(t, first.ID, again.ID)
	assert.Len(t, rec.existedAtRecord, 1, "a mission that already exists records nothing")
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

func TestStoreWithNoRecorderSavesAsBefore(t *testing.T) {
	rdb, docs := missiontest.NewClient(t)
	require.NoError(t, mission.NewConnBoundMissionStore(rdb).Save(context.Background(), newMission("plain")))
	assert.Equal(t, 1, docs.Count())
}
