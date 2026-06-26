// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package fga_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-logr/logr/testr"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga"
)

// fakeFGAClient is a minimal stub that records Write/Delete calls. It lets
// us exercise WithEventPublisher in isolation without an actual FGA HTTP
// server.
type fakeFGAClient struct {
	mu      sync.Mutex
	writes  [][]fga.Tuple
	deletes [][]fga.Tuple
	err     error
}

func (f *fakeFGAClient) Write(_ context.Context, tuples []fga.Tuple) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.writes = append(f.writes, tuples)
	return nil
}

func (f *fakeFGAClient) Delete(_ context.Context, tuples []fga.Tuple) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.deletes = append(f.deletes, tuples)
	return nil
}

func (f *fakeFGAClient) Read(_ context.Context, _ fga.Tuple) ([]fga.Tuple, error) {
	return nil, nil
}

func (f *fakeFGAClient) Check(_ context.Context, _, _, _ string) (bool, error) {
	return false, nil
}

func (f *fakeFGAClient) Ping(_ context.Context) error { return nil }

// TestPublishingClient_PublishesOnWrite asserts that a successful Write fans
// one Event per tuple to the configured Redis pub/sub channel.
//
// This is the operator-side counterpart to the daemon's pubsub_test —
// dashboard membership cache invalidation must fire whether the FGA
// mutation came from the daemon or the operator.
func TestPublishingClient_PublishesOnWrite(t *testing.T) {
	mr := miniredis.RunT(t)

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	sub := rdb.Subscribe(context.Background(), fga.PubsubChannel)
	t.Cleanup(func() { _ = sub.Close() })
	_, err := sub.Receive(context.Background())
	require.NoError(t, err)

	pub := fga.NewRedisPublisher(rdb, fga.PubsubChannel, 500*time.Millisecond, testr.New(t))
	inner := &fakeFGAClient{}
	wrapped := fga.WithEventPublisher(inner, pub)

	tuples := []fga.Tuple{
		{User: "user:abc-123", Relation: "member", Object: "tenant:acme"},
	}
	require.NoError(t, wrapped.Write(context.Background(), tuples))

	require.Len(t, inner.writes, 1)

	got := receiveN(t, sub, 1, 2*time.Second)
	require.Len(t, got, 1)

	var evt fga.Event
	require.NoError(t, json.Unmarshal([]byte(got[0]), &evt))
	require.Equal(t, fga.EventOpWrite, evt.Op)
	require.Equal(t, "abc-123", evt.UserID)
	require.Equal(t, "acme", evt.Tenant)
	require.Equal(t, "member", evt.Relation)
	require.Equal(t, "tenant:acme", evt.Object)
}

// TestPublishingClient_PublishesOnDelete asserts that a successful Delete
// publishes an Event with op=delete. Required because TenantMember
// reconciliation removes member tuples on demotion / removal.
func TestPublishingClient_PublishesOnDelete(t *testing.T) {
	mr := miniredis.RunT(t)

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	sub := rdb.Subscribe(context.Background(), fga.PubsubChannel)
	t.Cleanup(func() { _ = sub.Close() })
	_, err := sub.Receive(context.Background())
	require.NoError(t, err)

	pub := fga.NewRedisPublisher(rdb, fga.PubsubChannel, 500*time.Millisecond, testr.New(t))
	wrapped := fga.WithEventPublisher(&fakeFGAClient{}, pub)

	tuples := []fga.Tuple{{User: "user:zzz", Relation: "member", Object: "tenant:acme"}}
	require.NoError(t, wrapped.Delete(context.Background(), tuples))

	got := receiveN(t, sub, 1, 2*time.Second)
	var evt fga.Event
	require.NoError(t, json.Unmarshal([]byte(got[0]), &evt))
	require.Equal(t, fga.EventOpDelete, evt.Op)
	require.Equal(t, "zzz", evt.UserID)
	require.Equal(t, "acme", evt.Tenant)
}

// TestPublishingClient_DoesNotPublishOnError asserts that the wrapper does
// NOT publish when the underlying FGA call fails. Subscribers must never
// see an event for a tuple that did not actually land in FGA.
func TestPublishingClient_DoesNotPublishOnError(t *testing.T) {
	counter := &countingPublisher{}
	wrapped := fga.WithEventPublisher(
		&fakeFGAClient{err: errors.New("boom")},
		counter,
	)

	err := wrapped.Write(context.Background(),
		[]fga.Tuple{{User: "user:x", Relation: "member", Object: "tenant:y"}})
	require.Error(t, err)
	require.Equal(t, int64(0), counter.count())

	err = wrapped.Delete(context.Background(),
		[]fga.Tuple{{User: "user:x", Relation: "member", Object: "tenant:y"}})
	require.Error(t, err)
	require.Equal(t, int64(0), counter.count())
}

// TestPublishingClient_NoopPublisherReturnsInner asserts that wiring a
// no-op publisher returns the inner client unchanged (no wrapper overhead
// when pub/sub is disabled).
func TestPublishingClient_NoopPublisherReturnsInner(t *testing.T) {
	inner := &fakeFGAClient{}
	out := fga.WithEventPublisher(inner, fga.NewNoopPublisher())
	require.Equal(t, fga.Client(inner), out)
}

// TestPublishingClient_PublishFailureSwallowed asserts that a publish
// error never fails the FGA Write — the wrapper is fire-and-forget.
func TestPublishingClient_PublishFailureSwallowed(t *testing.T) {
	mr := miniredis.RunT(t)

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	require.NoError(t, rdb.Close()) // every Publish call now returns an error

	pub := fga.NewRedisPublisher(rdb, fga.PubsubChannel, 50*time.Millisecond, testr.New(t))
	inner := &fakeFGAClient{}
	wrapped := fga.WithEventPublisher(inner, pub)

	err := wrapped.Write(context.Background(),
		[]fga.Tuple{{User: "user:x", Relation: "member", Object: "tenant:y"}})
	require.NoError(t, err)
	require.Len(t, inner.writes, 1)
}

// receiveN waits up to timeout for n messages on sub and returns their payloads.
func receiveN(t *testing.T, sub *redis.PubSub, n int, timeout time.Duration) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	out := make([]string, 0, n)
	ch := sub.Channel()
	for len(out) < n {
		select {
		case msg, ok := <-ch:
			if !ok {
				t.Fatalf("subscribe channel closed after %d messages", len(out))
			}
			out = append(out, msg.Payload)
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %d messages, got %d", n, len(out))
		}
	}
	return out
}

type countingPublisher struct{ n atomic.Int64 }

func (c *countingPublisher) Publish(_ context.Context, _ fga.Event) { c.n.Add(1) }
func (c *countingPublisher) count() int64                           { return c.n.Load() }
