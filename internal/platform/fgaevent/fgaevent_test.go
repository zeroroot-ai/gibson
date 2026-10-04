// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fgaevent_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
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

// waitSubscribed waits up to within for the subscriber to be on the channel.
//
// The caller passes the bound because the two waits in this file are different
// questions. The FIRST subscription is immediate: Subscribe calls
// SubscribeMessages before any backoff, so a second is generous. A
// RESUBSCRIPTION happens on the retry schedule, and the gap can be as long as
// fgaevent.MaxBackoff — so a wait shorter than that is not a failing
// subscriber, it is a test that did not wait long enough. This used to be a
// fixed 5s and the resubscribe case flaked on a loaded runner, where two
// retries were burned while miniredis was restarting and the third was 2s out.
func waitSubscribed(t *testing.T, mr *miniredis.Miniredis, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for mr.PubSubNumSub(fgaevent.Channel)[fgaevent.Channel] == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("subscriber never subscribed within %v", within)
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
	waitSubscribed(t, mr, 5*time.Second)

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
	waitSubscribed(t, mr, 5*time.Second)
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
	waitSubscribed(t, mr, 5*time.Second)
	mr.Close()
	if err := mr.Restart(); err != nil {
		t.Fatal(err)
	}
	// The retry schedule, not a guess: a run of failures while the server is
	// down climbs toward MaxBackoff, so the longest a resubscribe can be away
	// is one full ceiling plus the time to connect.
	waitSubscribed(t, mr, fgaevent.MaxBackoff+5*time.Second)
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

// retryGapRecorder captures the retry_in value of every "subscription ended"
// log line. The gap is not otherwise observable from outside the package, and
// it is the thing that matters: during it, a demoted user keeps their rights.
type retryGapRecorder struct {
	slog.Handler
	mu   sync.Mutex
	gaps []string
}

func (r *retryGapRecorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *retryGapRecorder) Handle(_ context.Context, rec slog.Record) error {
	if !strings.Contains(rec.Message, "subscription ended") {
		return nil
	}
	rec.Attrs(func(a slog.Attr) bool {
		if a.Key == "retry_in" {
			r.mu.Lock()
			r.gaps = append(r.gaps, a.Value.String())
			r.mu.Unlock()
			return false
		}
		return true
	})
	return nil
}

func (r *retryGapRecorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *retryGapRecorder) WithGroup(string) slog.Handler      { return r }

func (r *retryGapRecorder) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.gaps...)
}

// heldSubscriber fails the first failures calls at once, then HOLDS one
// subscription for hold before dropping it, then fails at once again.
//
// The hold is what the reset turns on: a subscription that was genuinely up.
type heldSubscriber struct {
	failures int
	hold     time.Duration

	mu    sync.Mutex
	calls int
}

func (h *heldSubscriber) SubscribeMessages(ctx context.Context, _ string, _ func(string)) error {
	h.mu.Lock()
	h.calls++
	n := h.calls
	h.mu.Unlock()

	if n <= h.failures {
		return errors.New("dropped")
	}
	if n == h.failures+1 {
		select {
		case <-time.After(h.hold):
		case <-ctx.Done():
		}
		return errors.New("dropped after being up")
	}
	<-ctx.Done()
	return ctx.Err()
}

// TestSubscribeBackoffResetsAfterAHealthySubscription is the defect, not the
// schedule.
//
// backoff used to be declared outside the retry loop and only ever grew, for
// the lifetime of the process. A subscription that held for a week and then
// dropped waited the full MaxBackoff before its first retry, because earlier
// reconnects had already climbed the ceiling. During that gap the FGA decision
// cache TTL is the only bound on a revoked membership, which is the exact
// window this package exists to shorten.
//
// Two fast failures climb the schedule to 2s. Then one subscription holds
// longer than MinBackoff and drops. Its gap must be MinBackoff again.
func TestSubscribeBackoffResetsAfterAHealthySubscription(t *testing.T) {
	rec := &retryGapRecorder{}
	hs := &heldSubscriber{failures: 2, hold: fgaevent.MinBackoff + 100*time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	done := make(chan struct{})
	go func() {
		fgaevent.Subscribe(ctx, hs, slog.New(rec), func(fgaevent.Event) {})
		close(done)
	}()

	// Three gaps: two from the fast failures, one from the held subscription.
	deadline := time.Now().Add(20 * time.Second)
	for len(rec.seen()) < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d retry gaps were logged: %v", len(rec.seen()), rec.seen())
		}
		time.Sleep(20 * time.Millisecond)
	}
	gaps := rec.seen()

	want := []string{
		fgaevent.MinBackoff.String(),       // first drop
		(2 * fgaevent.MinBackoff).String(), // second drop, climbing
		fgaevent.MinBackoff.String(),       // after a subscription that was UP
	}
	for i, w := range want {
		if gaps[i] != w {
			t.Errorf("gap %d = %s, want %s (all gaps: %v)", i+1, gaps[i], w, gaps)
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Subscribe did not return after cancel")
	}
}

// And the reset must NOT fire for a subscription that never established. A
// run of immediate failures has to keep climbing, or a Redis that is down
// turns into a hot loop against it.
func TestSubscribeBackoffKeepsClimbingWhileNothingEstablishes(t *testing.T) {
	rec := &retryGapRecorder{}
	hs := &heldSubscriber{failures: 4}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go fgaevent.Subscribe(ctx, hs, slog.New(rec), func(fgaevent.Event) {})

	deadline := time.Now().Add(20 * time.Second)
	for len(rec.seen()) < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d retry gaps were logged: %v", len(rec.seen()), rec.seen())
		}
		time.Sleep(20 * time.Millisecond)
	}
	gaps := rec.seen()

	want := []string{
		fgaevent.MinBackoff.String(),
		(2 * fgaevent.MinBackoff).String(),
		(4 * fgaevent.MinBackoff).String(),
	}
	for i, w := range want {
		if gaps[i] != w {
			t.Errorf("gap %d = %s, want %s (all gaps: %v)", i+1, gaps[i], w, gaps)
		}
	}
}
