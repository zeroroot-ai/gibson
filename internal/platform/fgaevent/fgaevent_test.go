// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fgaevent_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/gibson/internal/platform/fgaevent"
)

func stateClient(t *testing.T, mr *miniredis.Miniredis) *state.StateClient {
	t.Helper()
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	sc, err := state.NewStateClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sc.Close() })
	return sc
}

func waitSubscribed(t *testing.T, mr *miniredis.Miniredis) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for mr.PubSubNumSub(fgaevent.Channel)[fgaevent.Channel] == 0 {
		if time.Now().After(deadline) {
			t.Fatal("subscriber never subscribed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestPublishReachesSubscriber: an event published by one client arrives at
// a subscriber on another, with the wire fields intact.
func TestPublishReachesSubscriber(t *testing.T) {
	mr := miniredis.RunT(t)
	pub, sub := stateClient(t, mr), stateClient(t, mr)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	got := make(chan fgaevent.Event, 4)
	go fgaevent.Subscribe(ctx, sub, slog.Default(), func(e fgaevent.Event) { got <- e })
	waitSubscribed(t, mr)

	fgaevent.NewPublisher(pub, slog.Default(), 0).Publish(ctx, fgaevent.FromTuple(fgaevent.OpDelete, "user:100000000000000001", "writer", "tenant:acme"))
	select {
	case e := <-got:
		if e.UserID != "100000000000000001" || e.Op != fgaevent.OpDelete || e.Tenant != "acme" || e.Relation != "writer" || e.Object != "tenant:acme" {
			t.Fatalf("event = %+v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no event arrived")
	}
}

// TestSubscribeIgnoresJunk: an unparseable payload and an event with no user
// are dropped, and the subscription stays up for the next real event.
func TestSubscribeIgnoresJunk(t *testing.T) {
	mr := miniredis.RunT(t)
	sub := stateClient(t, mr)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	got := make(chan fgaevent.Event, 4)
	go fgaevent.Subscribe(ctx, sub, slog.Default(), func(e fgaevent.Event) { got <- e })
	waitSubscribed(t, mr)
	mr.Publish(fgaevent.Channel, "not json")
	mr.Publish(fgaevent.Channel, `{"op":"write","tenant":"acme","relation":"admin","object":"tenant:acme"}`)
	mr.Publish(fgaevent.Channel, `{"userId":"100000000000000002","op":"write","tenant":"acme","relation":"admin","object":"tenant:acme","extra":"tolerated"}`)
	select {
	case e := <-got:
		if e.UserID != "100000000000000002" {
			t.Fatalf("event = %+v, want the one real event", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the real event never arrived")
	}
	select {
	case e := <-got:
		t.Fatalf("unexpected extra event %+v", e)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestFromTupleSkipsNonUserSubjects: a tuple whose subject is not a user (an
// agent, a team) yields no user id, and the publisher sends nothing for it.
func TestFromTupleSkipsNonUserSubjects(t *testing.T) {
	mr := miniredis.RunT(t)
	pub := stateClient(t, mr)
	evt := fgaevent.FromTuple(fgaevent.OpWrite, "agent:abc", "member", "tenant:acme")
	if evt.UserID != "" {
		t.Fatalf("user id = %q, want none for a non-user subject", evt.UserID)
	}
	fgaevent.NewPublisher(pub, slog.Default(), 0).Publish(context.Background(), evt)
	if n := mr.PubSubNumSub(fgaevent.Channel)[fgaevent.Channel]; n != 0 {
		t.Fatalf("unexpected subscribers %d", n)
	}
}

// TestSubscribeRetriesAfterADrop: when the subscription drops, Subscribe
// comes back and receives again.
func TestSubscribeRetriesAfterADrop(t *testing.T) {
	mr := miniredis.RunT(t)
	sub := stateClient(t, mr)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	got := make(chan fgaevent.Event, 4)
	go fgaevent.Subscribe(ctx, sub, slog.Default(), func(e fgaevent.Event) { got <- e })
	waitSubscribed(t, mr)
	mr.Close()
	if err := mr.Restart(); err != nil {
		t.Fatal(err)
	}
	waitSubscribed(t, mr)
	mr.Publish(fgaevent.Channel, `{"userId":"100000000000000003","op":"delete","tenant":"acme","relation":"writer","object":"tenant:acme"}`)
	select {
	case e := <-got:
		if e.UserID != "100000000000000003" {
			t.Fatalf("event = %+v", e)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no event after the reconnect")
	}
}

type failingPublisher struct{ calls int }

func (f *failingPublisher) PublishMessage(context.Context, string, string) error {
	f.calls++
	return errors.New("redis down")
}

// TestPublishLogsAndContinuesOnFailure: a failed publish is logged, never
// returned; the tuple write it follows already landed.
func TestPublishLogsAndContinuesOnFailure(t *testing.T) {
	fp := &failingPublisher{}
	fgaevent.NewPublisher(fp, slog.Default(), time.Second).Publish(context.Background(), fgaevent.FromTuple(fgaevent.OpWrite, "user:100000000000000001", "member", "tenant:acme"))
	if fp.calls != 1 {
		t.Fatalf("publish calls = %d, want 1", fp.calls)
	}
}

type flakySubscriber struct {
	failures int
	calls    int
	payloads []string
}

func (f *flakySubscriber) SubscribeMessages(ctx context.Context, _ string, handle func(string)) error {
	f.calls++
	if f.calls <= f.failures {
		return errors.New("dropped")
	}
	for _, p := range f.payloads {
		handle(p)
	}
	<-ctx.Done()
	return nil
}

// TestSubscribeRetriesWithBackoff: dropped subscriptions are retried, and
// the events after the reconnect are handled.
func TestSubscribeRetriesWithBackoff(t *testing.T) {
	fs := &flakySubscriber{failures: 2, payloads: []string{`{"userId":"100000000000000009","op":"write","tenant":"acme","relation":"admin","object":"tenant:acme"}`}}
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan fgaevent.Event, 1)
	done := make(chan struct{})
	go func() { fgaevent.Subscribe(ctx, fs, slog.Default(), func(e fgaevent.Event) { got <- e }); close(done) }()
	select {
	case e := <-got:
		if e.UserID != "100000000000000009" {
			t.Fatalf("event = %+v", e)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no event after the retries")
	}
	if fs.calls != 3 {
		t.Fatalf("subscribe calls = %d, want 3 (two drops, one success)", fs.calls)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Subscribe did not return after cancel")
	}
}
