// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"github.com/alicebob/miniredis/v2"
	"log/slog"
	"testing"

	"github.com/redis/go-redis/v9"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/engine/mission/missiontest"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/sdk/auth"
)

// A mission that exists without the tuple (tenant, belongs_to, mission) is the
// defect: a grant of an Agent Skill or an outside agent to the mission reads
// NotFound, and the first Agent Skills exit test run met it. Each path that
// creates a mission builds its store through one function. These tests create a
// mission through the store of each path and look for the tuple.

func tenantTestCtx(t *testing.T) context.Context {
	t.Helper()
	return auth.ContextWithTenantString(context.Background(), "acme")
}

func newTenantMission(name string) *mission.Mission {
	return &mission.Mission{
		ID: types.NewID(), TenantID: "acme", Name: name, Status: mission.MissionStatusSubmitted,
		TargetID: types.NewID(), MissionDefinitionID: types.NewID(),
	}
}

func requireTuple(t *testing.T, fga *fakeAuthorizer, m *mission.Mission) {
	t.Helper()
	want := authz.Tuple{User: "tenant:acme", Relation: "belongs_to", Object: "mission:" + m.ID.String()}
	for _, got := range fga.written {
		if got == want {
			return
		}
	}
	t.Fatalf("the mission %s exists and the tuple %+v was not written; written: %+v", m.ID, want, fga.written)
}

func testDaemon(rdb *redis.Client, fga *fakeAuthorizer) *daemonImpl {
	return &daemonImpl{
		authorizer: fga,
		pool:       &mockPool{conn: &datapool.Conn{Redis: rdb}},
	}
}

// RunMission and the inbound A2A start: a mission found or created by name.
func TestMissionTenantTuple_RunByName(t *testing.T) {
	rdb, _ := newJSONFakeClient(t)
	fga := &fakeAuthorizer{}
	m := &missionManager{pool: &mockPool{conn: &datapool.Conn{Redis: rdb}}, logger: slog.New(slog.DiscardHandler),
		recorderFn: testDaemon(rdb, fga).missionTenantRecorder}

	store, release, err := m.missionStoreFor(tenantTestCtx(t), auth.MustNewTenantID("acme"))
	if err != nil {
		t.Fatalf("missionStoreFor: %v", err)
	}
	defer release()
	rec, created, err := store.FindOrCreateByName(tenantTestCtx(t), newTenantMission("run-by-name"))
	if err != nil || !created {
		t.Fatalf("FindOrCreateByName = (%v, %v)", created, err)
	}
	requireTuple(t, fga, rec)
}

// RunExisting, rewind and a child that an agent starts: a record saved through
// the store of the manager.
func TestMissionTenantTuple_SavedThroughTheManagerStore(t *testing.T) {
	rdb, _ := newJSONFakeClient(t)
	fga := &fakeAuthorizer{}
	m := &missionManager{pool: &mockPool{conn: &datapool.Conn{Redis: rdb}}, logger: slog.New(slog.DiscardHandler),
		recorderFn: testDaemon(rdb, fga).missionTenantRecorder}

	store, release, err := m.missionStoreFor(tenantTestCtx(t), auth.MustNewTenantID("acme"))
	if err != nil {
		t.Fatalf("missionStoreFor: %v", err)
	}
	defer release()
	child := newTenantMission("rewound-child")
	if err := store.Save(tenantTestCtx(t), child); err != nil {
		t.Fatalf("Save: %v", err)
	}
	requireTuple(t, fga, child)
}

// The create call of the dashboard (CreateMission) builds its store with the
// daemon function.
func TestMissionTenantTuple_CreateMission(t *testing.T) {
	rdb, _ := newJSONFakeClient(t)
	fga := &fakeAuthorizer{}
	d := testDaemon(rdb, fga)
	m := newTenantMission("dashboard-create")
	if err := d.newMissionStore(rdb, "acme").Save(tenantTestCtx(t), m); err != nil {
		t.Fatalf("Save: %v", err)
	}
	requireTuple(t, fga, m)
}

// The harness creates a mission for an agent (and the component service does
// the same through the adapter).
func TestMissionTenantTuple_HarnessCreate(t *testing.T) {
	rdb, _ := newJSONFakeClient(t)
	fga := &fakeAuthorizer{}
	a := &missionHarnessAdapter{daemon: testDaemon(rdb, fga)}

	store, release, err := a.storeForCtx(tenantTestCtx(t))
	if err != nil {
		t.Fatalf("storeForCtx: %v", err)
	}
	defer release()
	m := newTenantMission("harness-create")
	if err := store.Save(tenantTestCtx(t), m); err != nil {
		t.Fatalf("Save: %v", err)
	}
	requireTuple(t, fga, m)
}

// A child mission that an agent originates is saved through the store of the
// component mission manager.
func TestMissionTenantTuple_Originate(t *testing.T) {
	rdb, _ := newJSONFakeClient(t)
	fga := &fakeAuthorizer{}
	cm := newComponentMissionManager(testDaemon(rdb, fga))

	store, _, release, err := cm.tenantConn(tenantTestCtx(t), "")
	if err != nil {
		t.Fatalf("tenantConn: %v", err)
	}
	defer release()
	m := newTenantMission("originated-child")
	if err := store.Save(tenantTestCtx(t), m); err != nil {
		t.Fatalf("Save: %v", err)
	}
	requireTuple(t, fga, m)
}

// The failure rule: a failed tuple write creates no mission, on each path.
func TestMissionTenantTuple_AFailedWriteCreatesNoMission(t *testing.T) {
	rdb, docs := newJSONFakeClient(t)
	fga := &fakeAuthorizer{writeErr: errors.New("fga down")}
	d := testDaemon(rdb, fga)

	if err := d.newMissionStore(rdb, "acme").Save(tenantTestCtx(t), newTenantMission("no-tuple-1")); err == nil {
		t.Fatal("Save must fail when the tuple cannot be written")
	}
	m := &missionManager{pool: d.pool, logger: slog.New(slog.DiscardHandler), recorderFn: d.missionTenantRecorder}
	store, release, err := m.missionStoreFor(tenantTestCtx(t), auth.MustNewTenantID("acme"))
	if err != nil {
		t.Fatalf("missionStoreFor: %v", err)
	}
	defer release()
	if _, _, err := store.FindOrCreateByName(tenantTestCtx(t), newTenantMission("no-tuple-2")); err == nil {
		t.Fatal("FindOrCreateByName must fail when the tuple cannot be written")
	}
	if docs.Count() != 0 {
		t.Fatalf("%d mission documents exist with no tuple", docs.Count())
	}
}

// A deleted mission loses its tuple, and an absent tuple is not an error.
func TestMissionTenantTuple_ForgetOnDelete(t *testing.T) {
	fga := &fakeAuthorizer{}
	r := missionTenantTuples{az: fga}
	id := types.NewID()
	if err := r.Forget(context.Background(), "acme", id); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	if len(fga.removed) != 1 || fga.removed[0] != authz.MissionBelongsToTuple("acme", id.String()) {
		t.Fatalf("removed = %+v", fga.removed)
	}
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

// The adapter refuses a call with no tenant before it opens the store, so no record
// is made without a tenant to stamp on it (gibson#1469).
func TestHarnessCreate_RefusesACallWithNoTenant(t *testing.T) {
	rdb, _ := newJSONFakeClient(t)
	a := newMissionHarnessAdapter(testDaemon(rdb, &fakeAuthorizer{}))
	_, err := a.CreateMission(context.Background(), &harness.MissionClientCreateRequest{MissionDefinitionJSON: `{"name":"x"}`, TargetID: types.NewID()})
	if err == nil {
		t.Fatal("a call with no tenant created a mission")
	}
}
