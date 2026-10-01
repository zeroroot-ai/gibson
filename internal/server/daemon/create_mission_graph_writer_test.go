// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"

	"github.com/zeroroot-ai/gibson/internal/platform/principal"

	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	"github.com/zeroroot-ai/sdk/auth"
)

// redisJSONClientForMissionTest returns a real go-redis client against the
// local Redis, skipping the test if it is unreachable or lacks the RedisJSON
// module. mission.ConnBoundMissionStore.Save persists via JSON.SET, which
// miniredis does not implement, so this — like the plain (non-miniredis)
// tests elsewhere in this repo (e.g. internal/engine/state) — talks to a real
// redis-stack instance: the "coverage gates" and "integration suite" CI jobs
// both run a redis/redis-stack-server service on localhost:6379 for exactly
// this reason.
func redisJSONClientForMissionTest(t *testing.T) *goredis.Client {
	t.Helper()
	rdb := goredis.NewClient(&goredis.Options{Addr: "localhost:6379"})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	probeKey := "gibson:test:json-probe:" + types.NewID().String()
	if err := rdb.Do(ctx, "JSON.SET", probeKey, "$", `"probe"`).Err(); err != nil {
		_ = rdb.Close()
		t.Skipf("RedisJSON not available at localhost:6379 (%v) — skipping, this runs against redis-stack in CI", err)
	}
	rdb.Del(ctx, probeKey)
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

// fakeTargetStoreForMission satisfies the full targetStore interface but only
// Get is exercised by CreateMission's resolution path; the rest panic on an
// unexpected call.
type fakeTargetStoreForMission struct {
	target *types.Target
}

func (f *fakeTargetStoreForMission) Get(_ context.Context, id types.ID) (*types.Target, error) {
	if f.target != nil && f.target.ID == id {
		return f.target, nil
	}
	return nil, nil
}
func (f *fakeTargetStoreForMission) GetByName(context.Context, string) (*types.Target, error) {
	panic("GetByName not expected from CreateMission")
}
func (f *fakeTargetStoreForMission) Create(context.Context, *types.Target) error {
	panic("Create not expected from CreateMission")
}
func (f *fakeTargetStoreForMission) List(context.Context, *types.TargetFilter) ([]*types.Target, error) {
	panic("List not expected from CreateMission")
}
func (f *fakeTargetStoreForMission) Update(context.Context, *types.Target) error {
	panic("Update not expected from CreateMission")
}
func (f *fakeTargetStoreForMission) Delete(context.Context, types.ID) error {
	panic("Delete not expected from CreateMission")
}

// TestCreateMission_MaterializesViaGraphWriter is the gibson#1254/ADR-0012
// regression test for the RPC-layer change: CreateMission must no longer open
// its own Neo4j write transaction, but it must still ask the sole writer (the
// graph projector, via GraphWriter.UpsertMission) to materialize the Mission
// node — using fakeGraphWriter (graph_projector_test.go) rather than a live
// Neo4j connection, since the point under test is "did the RPC handler call
// the writer", not the writer's own Cypher (covered separately in
// graph_projector_neo4j_test.go).
func TestCreateMission_MaterializesViaGraphWriter(t *testing.T) {
	rdb := redisJSONClientForMissionTest(t)

	tenant := auth.MustNewTenantID("acme")
	ctx := auth.WithTenant(context.Background(), tenant)

	target := &types.Target{ID: types.NewID(), TenantID: tenant.String(), Name: "t1"}
	targets := &fakeTargetStoreForMission{target: target}
	pool := &mockPool{conn: &datapool.Conn{Redis: rdb}}
	writer := newFakeGraphWriter()

	reg := brain.NewRegistry(ctx, brain.BeliefSystem)
	d := &daemonImpl{
		logger:        testObsLogger(),
		targetStore:   targets,
		pool:          pool,
		graphWriter:   writer,
		brainRegistry: reg,
	}

	missionDefinitionID := types.NewID().String()
	res, err := d.CreateMission(ctx, api.CreateMissionData{
		Name:                "recon-1",
		TargetID:            target.ID.String(),
		MissionDefinitionID: missionDefinitionID,
		CreatedBy:           principal.Principal{Kind: principal.User, ID: "123456789012345678"},
	})
	if err != nil {
		t.Fatalf("CreateMission: %v", err)
	}
	// The creator the handler stamped rides the real result (hosted#205):
	// identity run 36786911496 saw a CreateMission response with no
	// created_by because only the fake backend echoed it.
	if want := (principal.Principal{Kind: principal.User, ID: "123456789012345678"}); res.CreatedBy != want {
		t.Fatalf("result.CreatedBy = %+v, want %+v", res.CreatedBy, want)
	}
	if res.MissionID == "" {
		t.Fatal("CreateMission returned no mission id")
	}

	require.Eventually(t, func() bool {
		writer.mu.Lock()
		defer writer.mu.Unlock()
		return len(writer.missions[tenant.String()]) == 1
	}, 2*time.Second, 10*time.Millisecond, "CreateMission's background goroutine never reached GraphWriter.UpsertMission")

	writer.mu.Lock()
	got := writer.missions[tenant.String()][0]
	writer.mu.Unlock()
	if got.ID != res.MissionID {
		t.Errorf("UpsertMission got ID %q, want %q", got.ID, res.MissionID)
	}
	// The World knows the mission from creation: pending, attributed, so
	// ListMissions serves it before it runs (hosted#205, run 36795001822).
	eng := reg.For(tenant.String())
	eng.Tick()
	var inWorld *brain.MissionSnapshot
	for _, ms := range eng.Missions() {
		if ms.ID == res.MissionID {
			m := ms
			inWorld = &m
		}
	}
	if inWorld == nil {
		t.Fatalf("the World does not know mission %s; ListMissions would not list it", res.MissionID)
	}
	if inWorld.Status != brain.MissionPending || inWorld.CreatedBy != (principal.Principal{Kind: principal.User, ID: "123456789012345678"}) || inWorld.Name != "recon-1" {
		t.Fatalf("World mission = %+v, want pending, named recon-1, created by the caller", *inWorld)
	}
	if got.CreatedBy != "user:123456789012345678" {
		t.Errorf("UpsertMission got CreatedBy %q, want the principal ref, not the mission name", got.CreatedBy)
	}
	if got.Name != "recon-1" {
		t.Errorf("UpsertMission got Name %q, want recon-1", got.Name)
	}
}

// TestCreateMission_NilGraphWriter_Skipped proves the nil-graphWriter guard:
// when the daemon has not wired a GraphWriter (e.g. Neo4j disabled), the
// background goroutine must return early rather than nil-panic.
func TestCreateMission_NilGraphWriter_Skipped(t *testing.T) {
	rdb := redisJSONClientForMissionTest(t)

	tenant := auth.MustNewTenantID("acme")
	ctx := auth.WithTenant(context.Background(), tenant)

	target := &types.Target{ID: types.NewID(), TenantID: tenant.String(), Name: "t1"}
	targets := &fakeTargetStoreForMission{target: target}
	pool := &mockPool{conn: &datapool.Conn{Redis: rdb}}

	d := &daemonImpl{
		logger:      testObsLogger(),
		targetStore: targets,
		pool:        pool,
		graphWriter: nil,
	}

	missionDefinitionID := types.NewID().String()
	if _, err := d.CreateMission(ctx, api.CreateMissionData{
		Name:                "recon-2",
		TargetID:            target.ID.String(),
		MissionDefinitionID: missionDefinitionID,
	}); err != nil {
		t.Fatalf("CreateMission with no graph writer configured: %v", err)
	}
	// Give the background goroutine a moment to run; there is nothing to
	// assert beyond "no panic" since graphWriter is nil.
	time.Sleep(20 * time.Millisecond)
}
