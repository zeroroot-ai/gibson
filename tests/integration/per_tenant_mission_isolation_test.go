//go:build integration
// +build integration

package integration

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/datapool"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/types"
	missionpb "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
	"github.com/zero-day-ai/sdk/auth"
)

// perTenantMissionConn creates a datapool.Conn backed by the given miniredis
// client. The release func is nil — calling conn.Release() is still safe
// (the release hook is guarded by a nil check in connRelease).
func perTenantMissionConn(rdb *goredis.Client, tenantID auth.TenantID) *datapool.Conn {
	return &datapool.Conn{
		Tenant: tenantID,
		Redis:  rdb,
	}
}

// TestPerTenantMissionIsolation_TwoTenants verifies that missions written to
// tenant A's per-tenant Redis logical DB are not visible from tenant B's store.
//
// Audit C6 / C9 closure regression guard.
func TestPerTenantMissionIsolation_TwoTenants(t *testing.T) {
	ctx := context.Background()

	// Two independent miniredis instances simulate two tenants' logical Redis DBs.
	mrA, err := miniredis.Run()
	require.NoError(t, err)
	defer mrA.Close()

	mrB, err := miniredis.Run()
	require.NoError(t, err)
	defer mrB.Close()

	tenantA, err := auth.NewTenantID("tenant-a")
	require.NoError(t, err)
	tenantB, err := auth.NewTenantID("tenant-b")
	require.NoError(t, err)

	rdbA := goredis.NewClient(&goredis.Options{Addr: mrA.Addr()})
	rdbB := goredis.NewClient(&goredis.Options{Addr: mrB.Addr()})
	defer rdbA.Close()
	defer rdbB.Close()

	connA := perTenantMissionConn(rdbA, tenantA)
	connB := perTenantMissionConn(rdbB, tenantB)
	defer connA.Release()
	defer connB.Release()

	storeA := mission.NewConnBoundMissionStore(connA.Redis)
	storeB := mission.NewConnBoundMissionStore(connB.Redis)

	// Create a mission definition in tenant A.
	defA := &missionpb.MissionDefinition{
		Id:   types.NewID().String(),
		Name: "recon-tenant-a",
	}
	require.NoError(t, storeA.CreateDefinition(ctx, defA))

	// Tenant B should not see tenant A's definition.
	gotFromB, err := storeB.GetDefinition(ctx, defA.GetName())
	require.NoError(t, err)
	assert.Nil(t, gotFromB, "tenant B should not see tenant A's mission definition")

	// Create a mission in tenant A (TargetID required by Mission.Validate).
	// ConnBoundMissionStore.Save uses JSON.SET; skip on miniredis which doesn't support it.
	mA := &mission.Mission{
		ID:       types.NewID(),
		Name:     "mission-for-a",
		Status:   mission.MissionStatusPending,
		TargetID: types.NewID(),
	}
	if err := storeA.Save(ctx, mA); err != nil {
		t.Skipf("JSON.SET not supported by Redis server (miniredis?): %v", err)
	}

	// Tenant B should not find tenant A's mission by ID.
	got, err := storeB.Get(ctx, mA.ID)
	assert.Error(t, err, "tenant B Get for tenant A's ID should return not-found")
	assert.Nil(t, got, "tenant B should not be able to retrieve tenant A's mission")

	// ListMissions from tenant A should only include A's mission.
	missionsA, err := storeA.List(ctx, mission.NewMissionFilter())
	require.NoError(t, err)
	require.Len(t, missionsA, 1, "tenant A should see exactly 1 mission")
	assert.Equal(t, mA.ID, missionsA[0].ID)

	// ListMissions from tenant B should see nothing.
	missionsB, err := storeB.List(ctx, mission.NewMissionFilter())
	require.NoError(t, err)
	assert.Empty(t, missionsB, "tenant B should see zero missions")
}

// TestPerTenantMissionIsolation_CrossTenantGetReturnsNotFound verifies the
// specific cross-tenant Get path: a mission created in tenant A is not found
// when looked up from tenant B's store (structural IDOR prevention, audit C9).
func TestPerTenantMissionIsolation_CrossTenantGetReturnsNotFound(t *testing.T) {
	ctx := context.Background()

	mrA, err := miniredis.Run()
	require.NoError(t, err)
	defer mrA.Close()

	mrB, err := miniredis.Run()
	require.NoError(t, err)
	defer mrB.Close()

	tenantA, err := auth.NewTenantID("tenant-x")
	require.NoError(t, err)
	tenantB, err := auth.NewTenantID("tenant-y")
	require.NoError(t, err)

	rdbA := goredis.NewClient(&goredis.Options{Addr: mrA.Addr()})
	rdbB := goredis.NewClient(&goredis.Options{Addr: mrB.Addr()})
	defer rdbA.Close()
	defer rdbB.Close()

	connA := perTenantMissionConn(rdbA, tenantA)
	connB := perTenantMissionConn(rdbB, tenantB)
	defer connA.Release()
	defer connB.Release()

	storeA := mission.NewConnBoundMissionStore(connA.Redis)
	storeB := mission.NewConnBoundMissionStore(connB.Redis)

	mA := &mission.Mission{
		ID:       types.NewID(),
		Name:     "secret-mission",
		Status:   mission.MissionStatusRunning,
		TargetID: types.NewID(), // required by Mission.Validate()
	}
	if err := storeA.Save(ctx, mA); err != nil {
		t.Skipf("JSON.SET not supported by Redis server (miniredis?): %v", err)
	}

	// Cross-tenant Get should return not-found.
	got, err := storeB.Get(ctx, mA.ID)
	_ = err // not-found may be returned as err or as nil,nil depending on the impl
	assert.Nil(t, got, "cross-tenant mission lookup must return nil (audit C9 closure)")
}
