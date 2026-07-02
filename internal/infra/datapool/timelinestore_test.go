//go:build !embedder_tests

package datapool

import (
	"context"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// waitForCondition polls cond until true or 2 s (used by hydration tests to
// wait for the async tick loop to apply replay-submitted events).
func waitForCondition(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within deadline")
}

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

// staticAcquire returns an acquire closure that always hands out the same
// pre-created client with a no-op release. This mirrors the "single live
// client" scenario used by tests that do not need to exercise pool eviction.
func staticAcquire(rdb *goredis.Client) func(ctx context.Context) (*goredis.Client, func(), error) {
	return func(_ context.Context) (*goredis.Client, func(), error) {
		return rdb, func() {}, nil
	}
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
	store := NewRedisTimelineStore(staticAcquire(rdb))
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

	storeA := NewRedisTimelineStore(staticAcquire(rdbA))
	storeB := NewRedisTimelineStore(staticAcquire(rdbB))
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
	store := NewRedisTimelineStore(staticAcquire(rdb))

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

// TestHydrate_EquivalenceAfterRestart is the primary correctness test for
// ADR-0011 slice #1114: a fresh Engine hydrated from the persisted Timeline must
// reproduce the same World state as the original engine (fold-determinism).
//
// Scenario:
//  1. Engine "pre" appends a fixed event sequence directly to the store (no
//     Systems, so no cascaded events — the set of persisted events is exactly
//     what we submitted). This isolates fold-determinism from system behavior.
//  2. A fresh Registry is built with the same store. Registry.For(tenant)
//     creates a new Engine, calls Hydrate internally, and starts the tick loop.
//  3. The rehydrated World snapshots must equal the original fold over the same
//     events.
//
// ADR-0009 guarantee: the subscriber installed via OnEngine must NOT fire during
// Hydrate (replay is a pure fold; no side effects).
func TestHydrate_EquivalenceAfterRestart(t *testing.T) {
	const tenant = "tenant-hydrate"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, rdb := newTestRedis(t)
	store := NewRedisTimelineStore(staticAcquire(rdb))

	// --- Phase 1: persist a deterministic event sequence ---
	// We persist events directly to the store (rather than through an Engine)
	// so the set of stored events is exactly the submitted set — no cascades.
	events := []brain.Event{
		brain.MissionStarted{ID: "m1", Goal: "scan hosts", BeliefModel: "test"},
		brain.HostObserved{ScopeID: "scope", Address: "10.0.0.1", OpenPorts: []int{22, 443}, MissionID: "m1"},
		brain.HostObserved{ScopeID: "scope", Address: "10.0.0.2", OpenPorts: []int{80}, MissionID: "m1"},
		brain.WorkDispatched{ID: "work-a", MissionID: "m1", ItemKind: "tool", Target: "port-scan", Input: `{"target":"10.0.0.1"}`},
		brain.WorkCompleted{ID: "work-a", Result: `{"open":[22,443]}`},
	}
	for _, ev := range events {
		_, err := store.Append(context.Background(), tenant, ev)
		require.NoError(t, err)
	}

	// Compute the "expected" World by folding the same events into a fresh engine.
	expected := brain.NewEngine(tenant)
	for _, ev := range events {
		expected.Submit(ev)
	}
	expected.Tick()
	expMissions := expected.Missions()
	expHosts := expected.Hosts()
	expWork := expected.Work()

	require.Len(t, expMissions, 1, "expected: one mission")
	require.Len(t, expHosts, 2, "expected: two hosts")
	require.Len(t, expWork, 1, "expected: one work item")

	// --- Phase 2: simulate restart via a fresh Registry ---
	// Count subscribers fired during Hydrate (must be 0 — ADR-0009).
	replayDispatchCount := 0
	r := brain.NewRegistry(ctx)
	r.WithStoreFactory(func(_ context.Context, _ string) brain.TimelineStore {
		return store
	})
	// Subscribe BEFORE For() so the hook is installed before hydration.
	r.OnEngine(func(e *brain.Engine) {
		e.Subscribe(func(ev brain.Event) {
			if _, ok := ev.(brain.WorkDispatched); ok {
				replayDispatchCount++
			}
		})
	})

	post := r.For(tenant) // hydrates synchronously before returning

	// Snapshots must reproduce the expected fold.
	postMissions := post.Missions()
	postHosts := post.Hosts()
	postWork := post.Work()

	require.Len(t, postMissions, len(expMissions), "post: mission count must match expected")
	assert.Equal(t, expMissions[0].ID, postMissions[0].ID, "post: mission ID")
	assert.Equal(t, expMissions[0].Status, postMissions[0].Status, "post: mission status")

	require.Len(t, postHosts, len(expHosts), "post: host count must match expected")
	for i := range expHosts {
		assert.Equal(t, expHosts[i].Address, postHosts[i].Address, "post: host[%d] address", i)
		assert.Equal(t, expHosts[i].OpenPorts, postHosts[i].OpenPorts, "post: host[%d] open ports", i)
	}

	require.Len(t, postWork, len(expWork), "post: work count must match expected")
	for i := range expWork {
		assert.Equal(t, expWork[i].ID, postWork[i].ID, "post: work[%d] ID", i)
		assert.Equal(t, expWork[i].State, postWork[i].State, "post: work[%d] state", i)
	}

	// ADR-0009: no subscribers may fire during Hydrate (replay is a pure fold).
	// The subscriber was installed by OnEngine before Hydrate ran, so if it had
	// fired during the fold, replayDispatchCount would be > 0 here.
	assert.Equal(t, 0, replayDispatchCount,
		"no WorkDispatched subscribers may fire during Hydrate (ADR-0009: replay has no effects)")
}

// TestHydrate_InFlightWorkFailedOnRestart verifies that work still `running`
// in the persisted Timeline is transitioned to WorkFailed on hydration
// (ADR-0011 decision 5: a crash IS a failure).
func TestHydrate_InFlightWorkFailedOnRestart(t *testing.T) {
	const tenant = "tenant-inflight"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, rdb := newTestRedis(t)
	store := NewRedisTimelineStore(staticAcquire(rdb))

	// Append raw events so we can craft an exact "running but never completed"
	// scenario without running systems.
	events := []brain.Event{
		brain.MissionStarted{ID: "m1", Goal: "find open ports", BeliefModel: "test"},
		brain.WorkDispatched{ID: "work-orphan", MissionID: "m1", ItemKind: "tool", Target: "scan", Input: `{}`},
		// No WorkCompleted — simulates daemon crash mid-flight.
	}
	for _, ev := range events {
		_, err := store.Append(context.Background(), tenant, ev)
		require.NoError(t, err)
	}

	// Hydrate: Registry.For creates a fresh engine, calls Hydrate which replays
	// the timeline and submits ResumeFailInFlight events to the intake queue.
	r := brain.NewRegistry(ctx)
	r.WithStoreFactory(func(_ context.Context, _ string) brain.TimelineStore {
		return store
	})
	eng := r.For(tenant) // hydrates; intake queue now has a WorkCompleted{Err:"interrupted:..."}

	// After one tick the RetrySystem / MissionCompletion see the failed work.
	// We must tick once to drain the intake (ResumeFailInFlight was submitted to
	// the intake, not applied directly during Hydrate).
	waitForCondition(t, func() bool {
		work := eng.Work()
		for _, wi := range work {
			if wi.ID == "work-orphan" && wi.State != brain.WorkRunning {
				return true
			}
		}
		return false
	})

	// Confirm the orphaned work is no longer running.
	for _, wi := range eng.Work() {
		if wi.ID == "work-orphan" {
			require.NotEqual(t, brain.WorkRunning, wi.State,
				"orphaned in-flight work must not remain Running after hydration + tick")
		}
	}
}

// TestRegistry_WithStoreFactory_NoopWhenFactoryNil verifies that a Registry
// without a StoreFactory creates engines that operate in-memory only (no panic,
// backward-compatible with pre-#1113 behavior).
func TestRegistry_WithStoreFactory_NoopWhenFactoryNil(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r := brain.NewRegistry(ctx)
	// No WithStoreFactory call — should be safe.
	eng := r.For("tenant-noop")
	eng.Submit(brain.HostObserved{ScopeID: "s", Address: "10.0.0.1"})
	require.NotPanics(t, func() { eng.Tick() }, "in-memory engine must not panic without a store factory")
	require.Len(t, eng.Hosts(), 1, "event should still be processed in-memory")
}

// TestSnapshot_RoundTrip verifies that WriteSnapshot / LoadSnapshot are inverse:
// the loaded snapshot has the same AtSeq and Data as the written one.
func TestSnapshot_RoundTrip(t *testing.T) {
	_, rdb := newTestRedis(t)
	store := NewRedisTimelineStore(staticAcquire(rdb))
	ctx := context.Background()
	tenant := "tenant-snap-rt"

	// Append one event to get a real seq id.
	seq, err := store.Append(ctx, tenant, brain.HostObserved{ScopeID: "s", Address: "10.0.0.1"})
	require.NoError(t, err)

	snap := brain.WorldSnapshot{AtSeq: seq, Data: []byte(`{"test":true}`)}
	handle, err := store.WriteSnapshot(ctx, tenant, snap)
	require.NoError(t, err)
	assert.Equal(t, seq, handle, "WriteSnapshot should return snap.AtSeq as the handle")

	loaded, err := store.LoadSnapshot(ctx, tenant)
	require.NoError(t, err)
	require.NotNil(t, loaded, "LoadSnapshot should return the stored snapshot")
	assert.Equal(t, snap.AtSeq, loaded.AtSeq, "AtSeq must survive the round-trip")
	assert.Equal(t, snap.Data, loaded.Data, "Data must survive the round-trip")
}

// TestTrimTo_BoundsStream verifies that TrimTo removes stream entries preceding
// the given handle, leaving only entries at or after the handle.
func TestTrimTo_BoundsStream(t *testing.T) {
	mr, rdb := newTestRedis(t)
	_ = mr
	store := NewRedisTimelineStore(staticAcquire(rdb))
	ctx := context.Background()
	tenant := "tenant-trim"

	ev := brain.HostObserved{ScopeID: "s", Address: ""}
	var seqs []string
	for i := 0; i < 5; i++ {
		ev.Address = "10.0.0." + string(rune('1'+i))
		seq, err := store.Append(ctx, tenant, ev)
		require.NoError(t, err)
		seqs = append(seqs, seq)
	}

	// Trim up to (and including) the third entry.
	require.NoError(t, store.TrimTo(ctx, tenant, seqs[2]))

	// Only events after seqs[2] (i.e. seqs[3] and seqs[4]) should remain.
	remaining, err := store.LoadForReplay(ctx, tenant, "")
	require.NoError(t, err)
	assert.Len(t, remaining, 2, "only events after the trim handle should remain")
}

// TestSnapshotPlusTailEqualsFullReplay is the primary correctness test for the
// snapshot restore path: a World restored from a snapshot then folded with the
// tail events must equal a World folded from the complete event sequence.
func TestSnapshotPlusTailEqualsFullReplay(t *testing.T) {
	_, rdb := newTestRedis(t)
	store := NewRedisTimelineStore(staticAcquire(rdb))
	ctx := context.Background()
	const tenant = "tenant-snap-equiv"

	// Phase 1: append a fixed event sequence and record the mid-point seq.
	prefix := []brain.Event{
		brain.MissionStarted{ID: "m1", Goal: "scan", BeliefModel: "test"},
		brain.HostObserved{ScopeID: "s", Address: "10.0.0.1", OpenPorts: []int{22}, MissionID: "m1"},
		brain.WorkDispatched{ID: "w1", MissionID: "m1", ItemKind: "tool", Target: "scan", Input: `{}`},
	}
	tail := []brain.Event{
		brain.WorkCompleted{ID: "w1", Result: `{"open":[22]}`},
		brain.HostObserved{ScopeID: "s", Address: "10.0.0.2", OpenPorts: []int{443}, MissionID: "m1"},
	}

	var snapSeq string
	for _, ev := range prefix {
		seq, err := store.Append(ctx, tenant, ev)
		require.NoError(t, err)
		snapSeq = seq
	}
	for _, ev := range tail {
		_, err := store.Append(ctx, tenant, ev)
		require.NoError(t, err)
	}

	// Build the "expected" World by folding all events from scratch.
	all := append(append([]brain.Event(nil), prefix...), tail...)
	expEng := brain.NewEngine(tenant)
	for _, ev := range all {
		expEng.Submit(ev)
	}
	expEng.Tick()

	// Write a snapshot at snapSeq (after the prefix).
	snap := brain.SnapshotWorld(expEng.World, snapSeq)
	_, err := store.WriteSnapshot(ctx, tenant, snap)
	require.NoError(t, err)

	// Phase 2: restore via snapshot + tail replay.
	restored, err := brain.RestoreWorld(snap, tenant)
	require.NoError(t, err)
	tailEvs, err := store.LoadForReplay(ctx, tenant, snapSeq)
	require.NoError(t, err)
	for _, ev := range tailEvs {
		brain.Reduce(restored, ev)
	}

	// Both Worlds should have the same Hosts, Missions, and Work.
	assert.Equal(t, expEng.Hosts(), restored.Snapshot(),
		"hosts must match after snapshot restore + tail replay")
	assert.Equal(t, expEng.Work(), restored.WorkSnapshot(),
		"work must match after snapshot restore + tail replay")
	assert.Equal(t, expEng.Missions(), restored.MissionSnapshot(),
		"missions must match after snapshot restore + tail replay")
}

// TestLiveCadenceSnapshot_HydrateEquivalence exercises the live apply() +
// maybeSnapshot() cadence path end-to-end: it drives events through an engine
// with a small snapshot cadence (so a mid-stream snapshot+trim fires
// automatically), then hydrates a fresh engine and asserts the rehydrated World
// equals the original. This guards the AtSeq off-by-one: the snapshot must be
// taken AFTER the triggering event is folded, so that event is neither lost from
// the snapshot nor skipped by the exclusive-after-AtSeq tail replay.
func TestLiveCadenceSnapshot_HydrateEquivalence(t *testing.T) {
	_, rdb := newTestRedis(t)
	store := NewRedisTimelineStore(staticAcquire(rdb))
	const tenant = "tenant-live-cadence"

	// Cadence of 2 means a snapshot fires after every 2 persisted events, so with
	// 5 events at least two snapshots fire and the boundary event (the one that
	// triggers the snapshot) is exercised.
	live := brain.NewEngine(tenant)
	live.WithStore(store).WithSnapshotCadence(2)

	events := []brain.Event{
		brain.MissionStarted{ID: "m1", Goal: "scan", BeliefModel: "test"},
		brain.HostObserved{ScopeID: "s", Address: "10.0.0.1", OpenPorts: []int{22}, MissionID: "m1"},
		brain.WorkDispatched{ID: "w1", MissionID: "m1", ItemKind: "tool", Target: "scan", Input: `{}`},
		brain.WorkCompleted{ID: "w1", Result: `{"open":[22]}`},
		brain.HostObserved{ScopeID: "s", Address: "10.0.0.2", OpenPorts: []int{443}, MissionID: "m1"},
	}
	for _, ev := range events {
		live.Submit(ev)
	}
	live.Tick() // drains all events through apply(); snapshots fire at the cadence

	// Hydrate a fresh engine from the same store (snapshot + tail).
	fresh := brain.NewEngine(tenant)
	fresh.WithStore(store)
	fresh.Hydrate(context.Background())

	// The rehydrated World must equal the live World — no event lost at the
	// snapshot boundary.
	assert.Equal(t, live.Hosts(), fresh.Hosts(), "hosts must match after live-cadence snapshot + hydrate")
	assert.Equal(t, live.Work(), fresh.Work(), "work must match after live-cadence snapshot + hydrate")
	assert.Equal(t, live.Missions(), fresh.Missions(), "missions must match after live-cadence snapshot + hydrate")
}

// TestAcquirePerOp_EvictionRobustness is the regression test for gibson#1114
// (ADR-0011): after one Timeline operation releases its connection and the
// underlying *redis.Client is closed (simulating idle eviction), a subsequent
// operation via a fresh acquire still succeeds.
//
// The test wires a "rotating" acquire that alternates between two independent
// miniredis servers so we can close server A between operations and verify
// that operation B routes through server B without any "client is closed" error.
// The rotating acquire is the minimal simulation of the pool's per-op Conn
// acquisition: each call may legitimately return a different (but valid) client.
func TestAcquirePerOp_EvictionRobustness(t *testing.T) {
	ctx := context.Background()
	const tenant = "tenant-eviction"

	// Spin up two independent miniredis servers to simulate "old evicted client"
	// vs "new client from pool after eviction".
	mrA, err := miniredis.Run()
	require.NoError(t, err)
	defer mrA.Close()
	rdbA := goredis.NewClient(&goredis.Options{Addr: mrA.Addr()})
	defer rdbA.Close()

	mrB, err := miniredis.Run()
	require.NoError(t, err)
	defer mrB.Close()
	rdbB := goredis.NewClient(&goredis.Options{Addr: mrB.Addr()})
	defer rdbB.Close()

	// callCount tracks how many times acquire has been called so we can switch
	// clients between operations.
	callCount := 0
	acquire := func(_ context.Context) (*goredis.Client, func(), error) {
		callCount++
		if callCount == 1 {
			// First op uses rdbA (will be "closed" by eviction after this).
			return rdbA, func() {}, nil
		}
		// Subsequent ops use rdbB (fresh client from pool after eviction).
		return rdbB, func() {}, nil
	}

	store := NewRedisTimelineStore(acquire)

	// Operation 1: Append via rdbA.
	ev1 := brain.HostObserved{ScopeID: "s", Address: "10.0.0.1"}
	seq1, err := store.Append(ctx, tenant, ev1)
	require.NoError(t, err, "first Append (via rdbA) must succeed")
	require.NotEmpty(t, seq1)

	// Simulate idle eviction: close rdbA and stop mrA.
	// Any future use of rdbA would produce "redis: client is closed".
	rdbA.Close()
	mrA.Close()

	// Operation 2: Append via rdbB (fresh acquire after eviction).
	// This must NOT fail — the per-op acquire pattern guarantees a live client.
	ev2 := brain.HostObserved{ScopeID: "s", Address: "10.0.0.2"}
	seq2, err := store.Append(ctx, tenant, ev2)
	require.NoError(t, err, "second Append must succeed after eviction (per-op acquire, not stale client)")
	require.NotEmpty(t, seq2)

	// Operation 3: LoadForReplay via rdbB — only ev2 is on rdbB (rdbA is gone).
	loaded, err := store.LoadForReplay(ctx, tenant, "")
	require.NoError(t, err, "LoadForReplay must succeed on the live client")
	require.Len(t, loaded, 1, "only the event written to rdbB should be visible")
	assert.Equal(t, ev2, loaded[0], "the event on rdbB must be ev2")
}
