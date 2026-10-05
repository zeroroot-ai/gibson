// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package datapool

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
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
// pre-created client with a no-op release, and one in-memory Postgres history.
// This mirrors the "single live client" scenario used by tests that do not
// need to exercise pool eviction.
func staticAcquire(rdb *goredis.Client) func(ctx context.Context) (TimelineConn, func(), error) {
	return staticAcquireWith(rdb, &fakeHistorySQL{})
}

// staticAcquireWith is staticAcquire with the Postgres history as a parameter,
// for a test that reads the history or makes its writes fail.
func staticAcquireWith(rdb *goredis.Client, db SQL) func(ctx context.Context) (TimelineConn, func(), error) {
	return func(_ context.Context) (TimelineConn, func(), error) {
		return TimelineConn{Redis: rdb, SQL: db}, func() {}, nil
	}
}

// fakeHistorySQL is an in-memory timeline_events table. It runs the two
// statements of the Timeline store: the batch insert that skips a row that is
// there already, and the ordered page read after a stream id.
type fakeHistorySQL struct {
	mu      sync.Mutex
	rows    []fakeHistoryRow // in (ms, seq) order
	execErr error            // Exec returns this error while it is set
	execs   int
}

type fakeHistoryRow struct {
	ms, seq int64
	kind    string
	event   string
}

func (f *fakeHistorySQL) Exec(_ context.Context, sql string, args ...any) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.execs++
	if f.execErr != nil {
		return 0, f.execErr
	}
	if sql != insertHistorySQL || len(args) != 4 {
		return 0, fmt.Errorf("fakeHistorySQL: unexpected statement %q with %d args", sql, len(args))
	}
	ms, _ := args[0].([]int64)
	seq, _ := args[1].([]int64)
	kinds, _ := args[2].([]string)
	events, _ := args[3].([]string)
	if len(ms) != len(seq) || len(ms) != len(kinds) || len(ms) != len(events) {
		return 0, errors.New("fakeHistorySQL: the four arrays differ in length")
	}
	var inserted int64
	for i := range ms {
		exists := false
		for _, r := range f.rows {
			if r.ms == ms[i] && r.seq == seq[i] {
				exists = true
				break
			}
		}
		if exists {
			continue
		}
		f.rows = append(f.rows, fakeHistoryRow{ms: ms[i], seq: seq[i], kind: kinds[i], event: events[i]})
		inserted++
	}
	sort.Slice(f.rows, func(i, j int) bool {
		if f.rows[i].ms != f.rows[j].ms {
			return f.rows[i].ms < f.rows[j].ms
		}
		return f.rows[i].seq < f.rows[j].seq
	})
	return inserted, nil
}

func (f *fakeHistorySQL) QueryRow(context.Context, string, ...any) Row {
	panic("fakeHistorySQL: the Timeline store reads no single row")
}

func (f *fakeHistorySQL) Query(_ context.Context, sql string, args ...any) (Rows, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if sql != selectHistorySQL || len(args) != 3 {
		return nil, fmt.Errorf("fakeHistorySQL: unexpected query %q with %d args", sql, len(args))
	}
	afterMs, _ := args[0].(int64)
	afterSeq, _ := args[1].(int64)
	limit, _ := args[2].(int)
	var page []fakeHistoryRow
	for _, r := range f.rows {
		if r.ms > afterMs || (r.ms == afterMs && r.seq > afterSeq) {
			page = append(page, r)
			if len(page) == limit {
				break
			}
		}
	}
	return &fakeHistoryRows{rows: page, at: -1}, nil
}

func (f *fakeHistorySQL) kinds() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.rows))
	for _, r := range f.rows {
		out = append(out, r.kind)
	}
	return out
}

type fakeHistoryRows struct {
	rows []fakeHistoryRow
	at   int
}

func (r *fakeHistoryRows) Next() bool { r.at++; return r.at < len(r.rows) }
func (r *fakeHistoryRows) Err() error { return nil }
func (r *fakeHistoryRows) Close()     {}
func (r *fakeHistoryRows) Scan(dest ...any) error {
	row := r.rows[r.at]
	ms, ok1 := dest[0].(*int64)
	seq, ok2 := dest[1].(*int64)
	ev, ok3 := dest[2].(*string)
	if len(dest) != 3 || !ok1 || !ok2 || !ok3 {
		return errors.New("fakeHistoryRows: Scan wants (*int64, *int64, *string)")
	}
	*ms, *seq, *ev = row.ms, row.seq, row.event
	return nil
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

// TestTimelineStore_AppendLoad verifies that appended events are returned
// by LoadForReplay in the correct order.
func TestTimelineStore_AppendLoad(t *testing.T) {
	_, rdb := newTestRedis(t)
	store := NewTimelineStore(staticAcquire(rdb))
	ctx := context.Background()
	tenant := "tenant-a"

	evs := []brain.Event{
		brain.HostObserved{ScopeID: "s", Address: "10.0.0.1"},
		brain.WorkDispatched{ID: "w1", MissionID: "m1", ItemKind: "tool", Target: "scan"},
		brain.MissionDone{ID: "m1", Reason: "done", Outcome: brain.MissionCompleted},
	}

	for _, ev := range evs {
		_, err := store.Append(ctx, tenant, uuid.NewString(), ev)
		require.NoError(t, err)
	}

	loaded, err := store.LoadForReplay(ctx, tenant, "")
	require.NoError(t, err)
	require.Len(t, loaded, len(evs), "should get back all 3 events")

	for i, ev := range evs {
		assert.Equal(t, ev, loaded[i], "event at position %d should match", i)
	}
}

// TestTimelineStore_PerTenantIsolation verifies that two separate
// TimelineStore instances with different backing clients do not share
// events, even when the stream key scheme matches the same tenant name.
func TestTimelineStore_PerTenantIsolation(t *testing.T) {
	_, rdbA := newTestRedis(t)
	_, rdbB := newTestRedis(t)

	storeA := NewTimelineStore(staticAcquire(rdbA))
	storeB := NewTimelineStore(staticAcquire(rdbB))
	ctx := context.Background()
	tenant := "shared-tenant-name"

	evA := brain.HostObserved{ScopeID: "scope-a", Address: "10.0.0.1"}
	evB := brain.HostObserved{ScopeID: "scope-b", Address: "192.168.0.1"}

	_, err := storeA.Append(ctx, tenant, uuid.NewString(), evA)
	require.NoError(t, err)
	_, err = storeB.Append(ctx, tenant, uuid.NewString(), evB)
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
	store := NewTimelineStore(staticAcquire(rdb))

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
// ADR-0163 slice #1114: a fresh Engine hydrated from the persisted Timeline must
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
// ADR-0109 guarantee: the subscriber installed via OnEngine must NOT fire during
// Hydrate (replay is a pure fold; no side effects).
func TestHydrate_EquivalenceAfterRestart(t *testing.T) {
	const tenant = "tenant-hydrate"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, rdb := newTestRedis(t)
	store := NewTimelineStore(staticAcquire(rdb))

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
		_, err := store.Append(context.Background(), tenant, uuid.NewString(), ev)
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
	// Count subscribers fired during Hydrate (must be 0 — ADR-0109).
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

	// ADR-0109: no subscribers may fire during Hydrate (replay is a pure fold).
	// The subscriber was installed by OnEngine before Hydrate ran, so if it had
	// fired during the fold, replayDispatchCount would be > 0 here.
	assert.Equal(t, 0, replayDispatchCount,
		"no WorkDispatched subscribers may fire during Hydrate (ADR-0109: replay has no effects)")
}

// TestHydrate_InFlightWorkFailedOnRestart verifies that work still `running`
// in the persisted Timeline is transitioned to WorkFailed on hydration
// (ADR-0163: a crash IS a failure).
func TestHydrate_InFlightWorkFailedOnRestart(t *testing.T) {
	const tenant = "tenant-inflight"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, rdb := newTestRedis(t)
	store := NewTimelineStore(staticAcquire(rdb))

	// Append raw events so we can craft an exact "running but never completed"
	// scenario without running systems.
	events := []brain.Event{
		brain.MissionStarted{ID: "m1", Goal: "find open ports", BeliefModel: "test"},
		brain.WorkDispatched{ID: "work-orphan", MissionID: "m1", ItemKind: "tool", Target: "scan", Input: `{}`},
		// No WorkCompleted — simulates daemon crash mid-flight.
	}
	for _, ev := range events {
		_, err := store.Append(context.Background(), tenant, uuid.NewString(), ev)
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
	store := NewTimelineStore(staticAcquire(rdb))
	ctx := context.Background()
	tenant := "tenant-snap-rt"

	// Append one event to get a real seq id.
	seq, err := store.Append(ctx, tenant, uuid.NewString(), brain.HostObserved{ScopeID: "s", Address: "10.0.0.1"})
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
	store := NewTimelineStore(staticAcquire(rdb))
	ctx := context.Background()
	tenant := "tenant-trim"

	ev := brain.HostObserved{ScopeID: "s", Address: ""}
	var seqs []string
	for i := 0; i < 5; i++ {
		ev.Address = "10.0.0." + string(rune('1'+i))
		seq, err := store.Append(ctx, tenant, uuid.NewString(), ev)
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
	store := NewTimelineStore(staticAcquire(rdb))
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
		seq, err := store.Append(ctx, tenant, uuid.NewString(), ev)
		require.NoError(t, err)
		snapSeq = seq
	}
	for _, ev := range tail {
		_, err := store.Append(ctx, tenant, uuid.NewString(), ev)
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
	store := NewTimelineStore(staticAcquire(rdb))
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
	require.NoError(t, fresh.Hydrate(context.Background()))

	// The rehydrated World must equal the live World — no event lost at the
	// snapshot boundary.
	assert.Equal(t, live.Hosts(), fresh.Hosts(), "hosts must match after live-cadence snapshot + hydrate")
	assert.Equal(t, live.Work(), fresh.Work(), "work must match after live-cadence snapshot + hydrate")
	assert.Equal(t, live.Missions(), fresh.Missions(), "missions must match after live-cadence snapshot + hydrate")
}

// errAcquire returns an acquire closure that always returns the given error.
// Used by TestTimelineStore_AcquireError to cover the error branches in each
// TimelineStore method (lines 54-55, 82-83, 132-133, 151-152, 176-177).
func errAcquire(err error) func(ctx context.Context) (TimelineConn, func(), error) {
	return func(_ context.Context) (TimelineConn, func(), error) {
		return TimelineConn{}, nil, err
	}
}

// TestTimelineStore_AcquireError covers the acquire-error early-return branches
// in all five TimelineStore methods (Append, LoadForReplay, WriteSnapshot,
// LoadSnapshot, TrimTo). Each method must propagate the acquire error wrapped
// in a descriptive message — none should panic or return a nil error.
func TestTimelineStore_AcquireError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("pool evicted")
	store := NewTimelineStore(errAcquire(sentinel))
	ctx := context.Background()
	tenant := "tenant-err"

	t.Run("Append", func(t *testing.T) {
		_, err := store.Append(ctx, tenant, uuid.NewString(), brain.HostObserved{ScopeID: "s", Address: "10.0.0.1"})
		require.Error(t, err, "Append must return an error when acquire fails")
		require.ErrorIs(t, err, sentinel, "Append must wrap the acquire error")
	})

	t.Run("LoadForReplay", func(t *testing.T) {
		_, err := store.LoadForReplay(ctx, tenant, "")
		require.Error(t, err, "LoadForReplay must return an error when acquire fails")
		require.ErrorIs(t, err, sentinel, "LoadForReplay must wrap the acquire error")
	})

	t.Run("WriteSnapshot", func(t *testing.T) {
		snap := brain.WorldSnapshot{AtSeq: "0-1", Data: []byte(`{}`)}
		_, err := store.WriteSnapshot(ctx, tenant, snap)
		require.Error(t, err, "WriteSnapshot must return an error when acquire fails")
		require.ErrorIs(t, err, sentinel, "WriteSnapshot must wrap the acquire error")
	})

	t.Run("LoadSnapshot", func(t *testing.T) {
		_, err := store.LoadSnapshot(ctx, tenant)
		require.Error(t, err, "LoadSnapshot must return an error when acquire fails")
		require.ErrorIs(t, err, sentinel, "LoadSnapshot must wrap the acquire error")
	})

	t.Run("TrimTo", func(t *testing.T) {
		err := store.TrimTo(ctx, tenant, "0-1")
		require.Error(t, err, "TrimTo must return an error when acquire fails")
		require.ErrorIs(t, err, sentinel, "TrimTo must wrap the acquire error")
	})
}

// TestAcquirePerOp_EvictionRobustness is the regression test for gibson#1114
// (ADR-0163): after one Timeline operation releases its connection and the
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
	defer func() { _ = rdbA.Close() }()

	mrB, err := miniredis.Run()
	require.NoError(t, err)
	defer mrB.Close()
	rdbB := goredis.NewClient(&goredis.Options{Addr: mrB.Addr()})
	defer func() { _ = rdbB.Close() }()

	// callCount tracks how many times acquire has been called so we can switch
	// clients between operations.
	callCount := 0
	acquire := func(_ context.Context) (TimelineConn, func(), error) {
		callCount++
		if callCount == 1 {
			// First op uses rdbA (will be "closed" by eviction after this).
			return TimelineConn{Redis: rdbA}, func() {}, nil
		}
		// Subsequent ops use rdbB (fresh client from pool after eviction).
		return TimelineConn{Redis: rdbB}, func() {}, nil
	}

	store := NewTimelineStore(acquire)

	// Operation 1: Append via rdbA.
	ev1 := brain.HostObserved{ScopeID: "s", Address: "10.0.0.1"}
	seq1, err := store.Append(ctx, tenant, uuid.NewString(), ev1)
	require.NoError(t, err, "first Append (via rdbA) must succeed")
	require.NotEmpty(t, seq1)

	// Simulate idle eviction: close rdbA and stop mrA.
	// Any future use of rdbA would produce "redis: client is closed".
	_ = rdbA.Close()
	mrA.Close()

	// Operation 2: Append via rdbB (fresh acquire after eviction).
	// This must NOT fail — the per-op acquire pattern guarantees a live client.
	ev2 := brain.HostObserved{ScopeID: "s", Address: "10.0.0.2"}
	seq2, err := store.Append(ctx, tenant, uuid.NewString(), ev2)
	require.NoError(t, err, "second Append must succeed after eviction (per-op acquire, not stale client)")
	require.NotEmpty(t, seq2)

	// Operation 3: LoadForReplay via rdbB — only ev2 is on rdbB (rdbA is gone).
	loaded, err := store.LoadForReplay(ctx, tenant, "")
	require.NoError(t, err, "LoadForReplay must succeed on the live client")
	require.Len(t, loaded, 1, "only the event written to rdbB should be visible")
	assert.Equal(t, ev2, loaded[0], "the event on rdbB must be ev2")
}

// fakeConfigGetter stubs the redisConfigGetter surface so every AOF-guard
// path (appendonly=yes / no / missing key / command error) is testable
// without a real redis-stack — miniredis does not implement CONFIG.
type fakeConfigGetter struct {
	vals map[string]string
	err  error
}

func (f fakeConfigGetter) ConfigGet(ctx context.Context, parameter string) *goredis.MapStringStringCmd {
	cmd := goredis.NewMapStringStringCmd(ctx, "config", "get", parameter)
	if f.err != nil {
		cmd.SetErr(f.err)
	} else {
		cmd.SetVal(f.vals)
	}
	return cmd
}

// TestAssertAOFEnabled_Yes verifies the happy path: appendonly=yes passes the
// guard (gibson#1119).
func TestAssertAOFEnabled_Yes(t *testing.T) {
	t.Parallel()

	err := assertAOFEnabled(context.Background(), fakeConfigGetter{vals: map[string]string{"appendonly": "yes"}})
	assert.NoError(t, err)
}

// TestAssertAOFEnabled_No verifies the fail-fast path the boot guard exists
// for: a Redis with AOF disabled must be rejected loudly, not silently
// degrade to a Timeline that is lost on restart (gibson#1119, ADR-0163).
func TestAssertAOFEnabled_No(t *testing.T) {
	t.Parallel()

	err := assertAOFEnabled(context.Background(), fakeConfigGetter{vals: map[string]string{"appendonly": "no"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `appendonly="no"`)
	assert.Contains(t, err.Error(), "durable Timeline")
}

// TestAssertAOFEnabled_MissingKey verifies the guard fails closed when the
// CONFIG GET reply does not contain the appendonly parameter at all.
func TestAssertAOFEnabled_MissingKey(t *testing.T) {
	t.Parallel()

	err := assertAOFEnabled(context.Background(), fakeConfigGetter{vals: map[string]string{}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "returned no value")
}

// TestAssertAOFEnabled_CommandError verifies the guard fails closed when
// CONFIG GET itself errors (e.g. a managed Redis that disables the CONFIG
// command): durability that cannot be verified is treated as absent.
func TestAssertAOFEnabled_CommandError(t *testing.T) {
	t.Parallel()

	err := assertAOFEnabled(context.Background(), fakeConfigGetter{err: errors.New("ERR unknown command 'CONFIG'")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot verify AOF persistence")
}

// TestAssertTimelineAOF_FailsClosedWithoutConfigSupport exercises the
// dial-based wrapper against miniredis, which does not implement CONFIG:
// the guard must fail closed rather than assume durability.
func TestAssertTimelineAOF_FailsClosedWithoutConfigSupport(t *testing.T) {
	t.Parallel()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	gErr := AssertTimelineAOF(context.Background(), mr.Addr(), "")
	require.Error(t, gErr, "miniredis has no CONFIG support; the guard must fail closed")
	assert.Contains(t, gErr.Error(), "cannot verify AOF persistence")
}

// TestTimelineStore_AppendIsIdempotent proves the idempotency key of an
// append (ADR-0163, gibson#724): a second Append with the same key writes
// nothing and returns the seq of the first, and an Append with no key fails.
func TestTimelineStore_AppendIsIdempotent(t *testing.T) {
	_, client := newTestRedis(t)
	store := NewTimelineStore(staticAcquire(client))
	ctx := context.Background()
	const tenant = "tenant-idem"

	ev := brain.HostObserved{ScopeID: "s", Address: "10.0.0.1"}
	first, err := store.Append(ctx, tenant, "key-1", ev)
	require.NoError(t, err)

	// The retry after a lost reply: same key, same event.
	again, err := store.Append(ctx, tenant, "key-1", ev)
	require.NoError(t, err)
	require.Equal(t, first, again, "a retry must return the seq of the first append")

	evs, err := store.LoadForReplay(ctx, tenant, "")
	require.NoError(t, err)
	require.Len(t, evs, 1, "a retry with the same key must write nothing")

	// A new key writes a new entry.
	second, err := store.Append(ctx, tenant, "key-2", ev)
	require.NoError(t, err)
	require.NotEqual(t, first, second)
	evs, err = store.LoadForReplay(ctx, tenant, "")
	require.NoError(t, err)
	require.Len(t, evs, 2)

	_, err = store.Append(ctx, tenant, "", ev)
	require.Error(t, err, "an append with no idempotency key must fail")
}

// appendHosts appends n host events and returns the seq of each.
func appendHosts(t *testing.T, store *TimelineStore, tenant string, from, n int) []string {
	t.Helper()
	seqs := make([]string, 0, n)
	for i := from; i < from+n; i++ {
		seq, err := store.Append(context.Background(), tenant, uuid.NewString(),
			brain.HostObserved{ScopeID: "s", Address: fmt.Sprintf("10.0.%d.%d", i/250, i%250)})
		require.NoError(t, err)
		seqs = append(seqs, seq)
	}
	return seqs
}

func hostAddresses(t *testing.T, evs []brain.Event) []string {
	t.Helper()
	out := make([]string, 0, len(evs))
	for _, ev := range evs {
		h, ok := ev.(brain.HostObserved)
		require.True(t, ok, "unexpected event %T", ev)
		out = append(out, h.Address)
	}
	return out
}

// TestTimelineStore_TrimKeepsTheFullHistoryInPostgres is the acceptance test
// of gibson#786. It appends more events than one snapshot covers, trims two
// times, and reads the full ordered history: the trimmed events from Postgres,
// then the stream tail.
func TestTimelineStore_TrimKeepsTheFullHistoryInPostgres(t *testing.T) {
	_, rdb := newTestRedis(t)
	db := &fakeHistorySQL{}
	store := NewTimelineStore(staticAcquireWith(rdb, db))
	ctx := context.Background()
	const tenant = "tenant-history"

	first := appendHosts(t, store, tenant, 0, 120)
	require.NoError(t, store.TrimTo(ctx, tenant, first[99]), "the first snapshot covers 100 events")

	live, err := store.LoadForReplay(ctx, tenant, "")
	require.NoError(t, err)
	require.Len(t, live, 20, "the stream holds the live tail only")
	require.Len(t, db.kinds(), 100, "Postgres holds each event that the trim removed")

	second := appendHosts(t, store, tenant, 120, 130)
	require.NoError(t, store.TrimTo(ctx, tenant, second[79]), "the second snapshot covers 100 more")

	live, err = store.LoadForReplay(ctx, tenant, "")
	require.NoError(t, err)
	require.Len(t, live, 50)
	require.Len(t, db.kinds(), 200)
	for _, kind := range db.kinds() {
		require.Equal(t, "host.observed", kind, "each row holds the event kind")
	}

	history, err := store.LoadHistory(ctx, tenant)
	require.NoError(t, err)
	want := make([]string, 0, 250)
	for i := range 250 {
		want = append(want, fmt.Sprintf("10.0.%d.%d", i/250, i%250))
	}
	require.Equal(t, want, hostAddresses(t, history), "the history is each event, one time, in order")
}

// archiveErrorCount reads gibson_timeline_archive_errors_total for one tenant
// from the default registry, where the metrics package registers it.
func archiveErrorCount(t *testing.T, tenant string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, mf := range families {
		if mf.GetName() != "gibson_timeline_archive_errors_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "tenant" && l.GetValue() == tenant {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

// TestTimelineStore_FailedHistoryWriteDoesNotTrim proves that the stream keeps
// each entry when the Postgres write fails, that the error metric counts the
// failure, and that the next trim copies the entries.
func TestTimelineStore_FailedHistoryWriteDoesNotTrim(t *testing.T) {
	_, rdb := newTestRedis(t)
	db := &fakeHistorySQL{execErr: errors.New("postgres is down")}
	store := NewTimelineStore(staticAcquireWith(rdb, db))
	ctx := context.Background()
	const tenant = "tenant-history-fail"

	seqs := appendHosts(t, store, tenant, 0, 10)
	before := archiveErrorCount(t, tenant)

	err := store.TrimTo(ctx, tenant, seqs[5])
	require.Error(t, err)
	require.ErrorContains(t, err, "postgres is down")
	require.InDelta(t, before+1, archiveErrorCount(t, tenant), 1e-9,
		"the alert metric must count the failed write")

	live, err := store.LoadForReplay(ctx, tenant, "")
	require.NoError(t, err)
	require.Len(t, live, 10, "a failed history write must not trim the stream")

	// The database works again: the same trim copies the entries and trims.
	db.mu.Lock()
	db.execErr = nil
	db.mu.Unlock()
	require.NoError(t, store.TrimTo(ctx, tenant, seqs[5]))
	live, err = store.LoadForReplay(ctx, tenant, "")
	require.NoError(t, err)
	require.Len(t, live, 4)
	require.Len(t, db.kinds(), 6)

	history, err := store.LoadHistory(ctx, tenant)
	require.NoError(t, err)
	require.Len(t, history, 10)
}

// TestTimelineStore_HistoryCopiedButNotTrimmedIsReadOneTime covers the window
// between the copy and the trim: an entry that is in Postgres and in the
// stream is in the history one time, and a second copy writes no second row.
func TestTimelineStore_HistoryCopiedButNotTrimmedIsReadOneTime(t *testing.T) {
	_, rdb := newTestRedis(t)
	db := &fakeHistorySQL{}
	store := NewTimelineStore(staticAcquireWith(rdb, db))
	ctx := context.Background()
	const tenant = "tenant-history-overlap"

	seqs := appendHosts(t, store, tenant, 0, 8)
	conn, release, err := store.acquire(ctx)
	require.NoError(t, err)
	defer release()
	// Copy with no trim, two times.
	require.NoError(t, store.archive(ctx, conn, store.streamKey(tenant), seqs[4]))
	require.NoError(t, store.archive(ctx, conn, store.streamKey(tenant), seqs[4]))
	require.Len(t, db.kinds(), 5, "a second copy of the same entries writes nothing")

	history, err := store.LoadHistory(ctx, tenant)
	require.NoError(t, err)
	require.Len(t, history, 8, "an entry in Postgres and in the stream is read one time")
}

// TestTimelineStore_NoPostgresHandleRefusesTheTrim proves that a store with no
// Postgres handle never trims: a trim with no history write would lose events.
func TestTimelineStore_NoPostgresHandleRefusesTheTrim(t *testing.T) {
	_, rdb := newTestRedis(t)
	store := NewTimelineStore(staticAcquireWith(rdb, nil))
	ctx := context.Background()
	const tenant = "tenant-no-postgres"

	seqs := appendHosts(t, store, tenant, 0, 3)
	require.Error(t, store.TrimTo(ctx, tenant, seqs[1]))
	live, err := store.LoadForReplay(ctx, tenant, "")
	require.NoError(t, err)
	require.Len(t, live, 3)

	_, err = store.LoadHistory(ctx, tenant)
	require.Error(t, err)
}

func TestParseStreamID(t *testing.T) {
	ms, seq, err := parseStreamID("1751234567890-3")
	require.NoError(t, err)
	require.Equal(t, int64(1751234567890), ms)
	require.Equal(t, int64(3), seq)

	for _, bad := range []string{"", "12", "x-1", "1-y"} {
		_, _, err := parseStreamID(bad)
		require.Error(t, err, "stream id %q", bad)
	}
}
