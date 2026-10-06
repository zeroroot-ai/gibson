// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// faultyStore wraps memTimelineStore with faults that a test turns on: a
// number of appends that fail, appends whose reply is lost after the write,
// and loads that fail. It honors the idempotency key in the same way as the
// Redis store: an append with the key of the most recent append writes nothing.
type faultyStore struct {
	memTimelineStore

	fmu           sync.Mutex
	failAppends   int   // the next n appends fail and write nothing
	loseReplies   int   // the next n appends write, then return an error
	loadErr       error // LoadForReplay returns this error while set
	snapErr       error // LoadSnapshot returns this error while set
	appendCalls   int
	lastKey       string
	lastSeq       string
	keysPerAppend []string
}

var errStoreDown = errors.New("the store is down")

func (s *faultyStore) Append(ctx context.Context, tenant, key string, ev Event) (string, error) {
	s.fmu.Lock()
	defer s.fmu.Unlock()
	s.appendCalls++
	s.keysPerAppend = append(s.keysPerAppend, key)
	if s.failAppends > 0 {
		s.failAppends--
		return "", errStoreDown
	}
	if key == s.lastKey {
		return s.lastSeq, nil
	}
	seq, err := s.memTimelineStore.Append(ctx, tenant, key, ev)
	if err != nil {
		return "", err
	}
	s.lastKey, s.lastSeq = key, seq
	if s.loseReplies > 0 {
		s.loseReplies--
		return "", errStoreDown
	}
	return seq, nil
}

func (s *faultyStore) LoadForReplay(ctx context.Context, tenant, afterSeq string) ([]Event, error) {
	s.fmu.Lock()
	err := s.loadErr
	s.fmu.Unlock()
	if err != nil {
		return nil, err
	}
	return s.memTimelineStore.LoadForReplay(ctx, tenant, afterSeq)
}

func (s *faultyStore) LoadSnapshot(ctx context.Context, tenant string) (*WorldSnapshot, error) {
	s.fmu.Lock()
	err := s.snapErr
	s.fmu.Unlock()
	if err != nil {
		return nil, err
	}
	return s.memTimelineStore.LoadSnapshot(ctx, tenant)
}

func (s *faultyStore) set(fn func(*faultyStore)) {
	s.fmu.Lock()
	defer s.fmu.Unlock()
	fn(s)
}

func noRetryDelay(t *testing.T) {
	t.Helper()
	old := appendRetryDelay
	appendRetryDelay = 0
	t.Cleanup(func() { appendRetryDelay = old })
}

func host(addr string) HostObserved {
	return HostObserved{ScopeID: "s", Address: addr, OpenPorts: []int{22}}
}

// A failed append does not fold: the World and the in-memory Timeline hold
// only what the durable store holds, and the engine stops with the error.
func TestEngine_FailedAppendDoesNotFold(t *testing.T) {
	noRetryDelay(t)
	store := &faultyStore{}
	e := NewEngine("t1", store)

	e.Submit(host("10.0.0.1"))
	require.Equal(t, 1, e.Tick())
	require.NoError(t, e.Err())

	store.set(func(s *faultyStore) { s.failAppends = appendAttempts })
	e.Submit(host("10.0.0.2"))
	e.Submit(host("10.0.0.3"))
	require.Equal(t, 0, e.Tick(), "no event folds after the append fails")

	require.ErrorIs(t, e.Err(), errStoreDown)
	require.Len(t, e.Hosts(), 1, "the World must not hold the event that the Timeline lost")
	require.Len(t, e.Timeline.Events(), 1)
	require.Equal(t, 1, store.remaining())

	// A stopped engine stays stopped: it applies nothing and Submit does not block.
	for range intakeBuffer + 10 {
		e.Submit(host("10.0.0.9"))
	}
	require.Equal(t, 0, e.Tick())
	require.Len(t, e.Hosts(), 1)
}

// A transient failure is retried inside the tick, and the event then folds once.
func TestEngine_AppendRetriesThenFolds(t *testing.T) {
	noRetryDelay(t)
	store := &faultyStore{}
	store.failAppends = appendAttempts - 1
	e := NewEngine("t1", store)

	e.Submit(host("10.0.0.1"))
	require.Equal(t, 1, e.Tick())
	require.NoError(t, e.Err())
	require.Len(t, e.Hosts(), 1)
	require.Equal(t, 1, store.remaining())
	require.Equal(t, appendAttempts, store.appendCalls)
}

// A retry after a lost reply carries the same idempotency key, so the store
// writes the event once. Two different events carry two different keys.
func TestEngine_RetryAfterLostReplyWritesOnce(t *testing.T) {
	noRetryDelay(t)
	store := &faultyStore{}
	store.loseReplies = 1
	e := NewEngine("t1", store)

	e.Submit(host("10.0.0.1"))
	require.Equal(t, 1, e.Tick())
	require.NoError(t, e.Err())
	require.Equal(t, 2, store.appendCalls, "one lost reply, then one retry")
	require.Equal(t, store.keysPerAppend[0], store.keysPerAppend[1], "the retry must reuse the key")
	require.NotEmpty(t, store.keysPerAppend[0])
	require.Equal(t, 1, store.remaining(), "the event must be in the Timeline once")
	require.Len(t, e.Hosts(), 1)

	e.Submit(host("10.0.0.2"))
	require.Equal(t, 1, e.Tick())
	require.NotEqual(t, store.keysPerAppend[1], store.keysPerAppend[2], "a new event must carry a new key")
	require.Equal(t, 2, store.remaining())
}

// A hydrate with a load error returns the error and leaves the World empty,
// for each of the three load steps.
func TestEngine_HydrateErrorKeepsNoPartialWorld(t *testing.T) {
	seed := func(t *testing.T) *faultyStore {
		t.Helper()
		store := &faultyStore{}
		e := NewEngine("t1", store).WithSnapshotCadence(2)
		for _, a := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
			e.Submit(host(a))
		}
		require.Equal(t, 3, e.Tick())
		require.Equal(t, 1, store.remaining(), "the snapshot covers two events and one is the tail")
		return store
	}

	t.Run("the tail does not load", func(t *testing.T) {
		store := seed(t)
		store.loadErr = errStoreDown
		e := NewEngine("t1", store)
		require.ErrorIs(t, e.Hydrate(context.Background()), errStoreDown)
		require.Empty(t, e.Hosts(), "a failed hydrate must not keep the snapshot part of the World")
	})

	t.Run("the snapshot does not load", func(t *testing.T) {
		store := seed(t)
		store.snapErr = errStoreDown
		e := NewEngine("t1", store)
		require.ErrorIs(t, e.Hydrate(context.Background()), errStoreDown)
		require.Empty(t, e.Hosts(), "a replay without the snapshot must not become the World")
	})

	t.Run("the snapshot does not restore", func(t *testing.T) {
		store := seed(t)
		store.snap.Data = []byte("not a snapshot")
		e := NewEngine("t1", store)
		require.Error(t, e.Hydrate(context.Background()))
		require.Empty(t, e.Hosts())
	})

	t.Run("a good store hydrates the full World", func(t *testing.T) {
		store := seed(t)
		e := NewEngine("t1", store)
		require.NoError(t, e.Hydrate(context.Background()))
		require.Len(t, e.Hosts(), 3)
	})
}

// The Registry does not serve a tenant whose hydrate failed, and the next use
// of the tenant tries the hydrate again.
func TestRegistry_FailedHydrateIsRetriedOnNextUse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := &faultyStore{}
	seedEngine := NewEngine("a", store)
	seedEngine.Submit(host("10.0.0.1"))
	require.Equal(t, 1, seedEngine.Tick())

	hooks := 0
	r := NewRegistry(ctx, func(context.Context, string) (TimelineStore, error) { return store, nil })
	r.OnEngine(func(*Engine) { hooks++ })

	store.set(func(s *faultyStore) { s.loadErr = errStoreDown })
	bad := r.For("a")
	require.ErrorIs(t, bad.Err(), errStoreDown)
	require.Empty(t, bad.Hosts())
	require.Empty(t, r.Tenants(), "the Registry must not keep an engine that did not hydrate")
	require.Zero(t, hooks, "no hook runs for an engine that does not serve")
	bad.Submit(host("10.0.0.9")) // must not block and must not write
	require.Equal(t, 1, store.remaining())

	store.set(func(s *faultyStore) { s.loadErr = nil })
	good := r.For("a")
	require.NotSame(t, bad, good)
	require.NoError(t, good.Err())
	require.Len(t, good.Hosts(), 1)
	require.Equal(t, 1, hooks)
	require.Same(t, good, r.For("a"))
}

// An engine that stops on a failed append leaves the Registry. The next use of
// the tenant gets a new engine whose World is the fold of the durable Timeline.
func TestRegistry_StoppedEngineIsReplacedFromTheStore(t *testing.T) {
	noRetryDelay(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := &faultyStore{}
	r := NewRegistry(ctx, func(context.Context, string) (TimelineStore, error) { return store, nil })

	first := r.For("a")
	first.Submit(host("10.0.0.1"))
	waitFor(t, func() bool { return len(first.Hosts()) == 1 })

	store.set(func(s *faultyStore) { s.failAppends = appendAttempts })
	first.Submit(host("10.0.0.2"))
	waitFor(t, func() bool { return first.Err() != nil })
	require.ErrorIs(t, first.Err(), errStoreDown)
	waitFor(t, func() bool { return len(r.Tenants()) == 0 })

	second := r.For("a")
	require.NotSame(t, first, second)
	require.NoError(t, second.Err())
	require.Len(t, second.Hosts(), 1, "the new World must equal the fold of the durable Timeline")

	second.Submit(host("10.0.0.3"))
	waitFor(t, func() bool { return len(second.Hosts()) == 2 })
	require.Equal(t, 2, store.remaining())
}

// Run returns when the engine stops, so a stopped engine keeps no goroutine.
func TestEngine_RunReturnsWhenStopped(t *testing.T) {
	noRetryDelay(t)
	store := &faultyStore{}
	store.failAppends = appendAttempts
	e := NewEngine("t1", store)
	done := make(chan struct{})
	go func() {
		e.Run(context.Background())
		close(done)
	}()
	e.Submit(host("10.0.0.1"))
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the engine stopped")
	}
	require.ErrorIs(t, e.Err(), errStoreDown)
}

// gibson#726: a store factory that fails, or that returns no store, gives a
// stopped engine whose Err names the cause. The Registry does not keep it, no
// hook runs, and the next call tries the factory again.
func TestRegistry_StoreFactoryErrorStopsTheEngine(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hooks := 0
	calls := 0
	factoryErr := errStoreDown
	var factoryStore TimelineStore
	r := NewRegistry(ctx, func(context.Context, string) (TimelineStore, error) {
		calls++
		return factoryStore, factoryErr
	})
	r.OnEngine(func(*Engine) { hooks++ })

	failed := r.For("a")
	require.ErrorIs(t, failed.Err(), errStoreDown)
	require.ErrorContains(t, failed.Err(), `tenant "a"`)
	require.Empty(t, r.Tenants(), "the Registry must not keep an engine with no store")
	require.Zero(t, hooks)

	factoryErr = nil
	empty := r.For("a")
	require.ErrorIs(t, empty.Err(), errNoTimelineStore, "a nil store with no error is refused")
	require.Empty(t, r.Tenants())

	factoryStore = &faultyStore{}
	good := r.For("a")
	require.NoError(t, good.Err())
	require.Equal(t, 1, hooks)
	require.Equal(t, 3, calls, "each call after a failure tries the factory again")
}
