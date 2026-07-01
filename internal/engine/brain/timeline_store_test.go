//go:build !embedder_tests

package brain_test

import (
	"context"
	"testing"

	miniredis "github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// newTestRedis starts an in-memory Redis server and returns a connected client.
// The caller is responsible for calling mr.Close() and rdb.Close() when done.
func newTestRedis(t *testing.T) (*miniredis.Miniredis, *goredis.Client) {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() {
		rdb.Close()
		mr.Close()
	})
	return mr, rdb
}

// TestCodecRoundTrip verifies that EncodeEvent / DecodeEvent are inverse for
// representative concrete event types. The decoded event must equal the
// original value.
func TestCodecRoundTrip(t *testing.T) {
	cases := []brain.Event{
		brain.HostObserved{
			ScopeID:    "scope-1",
			Address:    "10.0.0.1",
			SSHHostKey: "AAAAB3NzaC1yc2E=",
			CloudID:    "i-abc123",
			OpenPorts:  []int{22, 443},
			MissionID:  "m1",
		},
		brain.WorkDispatched{
			ID:        "work-1",
			MissionID: "m1",
			ItemKind:  "tool",
			Target:    "port-scan",
			Input:     `{"target":"10.0.0.1"}`,
		},
		brain.MissionStarted{
			ID:          "m1",
			Goal:        "find exposed services",
			BeliefModel: "base-v1",
		},
		brain.WorkCompleted{
			ID:     "work-1",
			Result: `{"open":[22,443]}`,
		},
		brain.MissionDone{
			ID:      "m1",
			Reason:  "all nodes done",
			Outcome: brain.MissionCompleted,
		},
	}

	for _, ev := range cases {
		ev := ev
		t.Run(ev.Kind(), func(t *testing.T) {
			encoded, err := brain.EncodeEvent(ev)
			require.NoError(t, err, "EncodeEvent should not fail")
			require.NotEmpty(t, encoded, "encoded bytes should not be empty")

			decoded, err := brain.DecodeEvent(encoded)
			require.NoError(t, err, "DecodeEvent should not fail")
			require.Equal(t, ev, decoded, "decoded event should equal the original")
		})
	}
}

// TestRedisTimelineStore_AppendLoad verifies that appended events are returned
// by LoadForReplay in the correct order.
func TestRedisTimelineStore_AppendLoad(t *testing.T) {
	_, rdb := newTestRedis(t)
	store := brain.NewRedisTimelineStore(rdb)
	ctx := context.Background()
	tenant := "tenant-a"

	evs := []brain.Event{
		brain.HostObserved{ScopeID: "s", Address: "10.0.0.1"},
		brain.WorkDispatched{ID: "w1", MissionID: "m1", ItemKind: "tool", Target: "scan"},
		brain.MissionDone{ID: "m1", Reason: "done", Outcome: brain.MissionCompleted},
	}

	for _, ev := range evs {
		_, err := store.Append(ctx, tenant, ev)
		require.NoError(t, err)
	}

	loaded, err := store.LoadForReplay(ctx, tenant, "")
	require.NoError(t, err)
	require.Len(t, loaded, len(evs), "should get back all 3 events")

	for i, ev := range evs {
		assert.Equal(t, ev, loaded[i], "event at position %d should match", i)
	}
}

// TestRedisTimelineStore_PerTenantIsolation verifies that two separate
// RedisTimelineStore instances with different backing clients do not share
// events, even when the stream key scheme matches the same tenant name.
func TestRedisTimelineStore_PerTenantIsolation(t *testing.T) {
	_, rdbA := newTestRedis(t)
	_, rdbB := newTestRedis(t)

	storeA := brain.NewRedisTimelineStore(rdbA)
	storeB := brain.NewRedisTimelineStore(rdbB)
	ctx := context.Background()
	tenant := "shared-tenant-name"

	evA := brain.HostObserved{ScopeID: "scope-a", Address: "10.0.0.1"}
	evB := brain.HostObserved{ScopeID: "scope-b", Address: "192.168.0.1"}

	_, err := storeA.Append(ctx, tenant, evA)
	require.NoError(t, err)
	_, err = storeB.Append(ctx, tenant, evB)
	require.NoError(t, err)

	loadedA, err := storeA.LoadForReplay(ctx, tenant, "")
	require.NoError(t, err)
	require.Len(t, loadedA, 1, "storeA should have exactly 1 event")
	assert.Equal(t, evA, loadedA[0], "storeA should only have tenant-a's event")

	loadedB, err := storeB.LoadForReplay(ctx, tenant, "")
	require.NoError(t, err)
	require.Len(t, loadedB, 1, "storeB should have exactly 1 event")
	assert.Equal(t, evB, loadedB[0], "storeB should only have tenant-b's event")
}

// TestEngine_WithStore_PersistsEvents verifies that events processed by the
// Engine are written to the store and can be replayed.
func TestEngine_WithStore_PersistsEvents(t *testing.T) {
	_, rdb := newTestRedis(t)
	store := brain.NewRedisTimelineStore(rdb)

	eng := brain.NewEngine("t1")
	eng.WithStore(store)

	ev1 := brain.HostObserved{ScopeID: "s", Address: "10.0.0.1"}
	ev2 := brain.HostObserved{ScopeID: "s", Address: "10.0.0.2"}

	eng.Submit(ev1)
	eng.Submit(ev2)
	eng.Tick()

	loaded, err := store.LoadForReplay(context.Background(), "t1", "")
	require.NoError(t, err)
	require.Len(t, loaded, 2, "both submitted events should be persisted")
	assert.Equal(t, ev1, loaded[0], "first event should match")
	assert.Equal(t, ev2, loaded[1], "second event should match")
}

// TestEngine_WithStore_NilSafe verifies that an Engine without a store does
// not panic on Submit + Tick.
func TestEngine_WithStore_NilSafe(t *testing.T) {
	eng := brain.NewEngine("t1")
	// No store wired — should operate in-memory only.

	eng.Submit(brain.HostObserved{ScopeID: "s", Address: "10.0.0.1"})
	require.NotPanics(t, func() {
		eng.Tick()
	}, "Tick should not panic without a store")
}
