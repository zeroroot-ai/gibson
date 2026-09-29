// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"github.com/zeroroot-ai/gibson/internal/platform/fgaevent"
)

// TestFGAEventStateClient: no URL means no subscriber, a bad URL is an
// error, a good URL gives a client.
func TestFGAEventStateClient(t *testing.T) {
	if c, err := fgaEventStateClient(context.Background(), "", "x"); c != nil || err != nil {
		t.Fatalf("empty url: client=%v err=%v, want nil, nil", c, err)
	}
	if _, err := fgaEventStateClient(context.Background(), "not a url", ""); err == nil {
		t.Fatal("a bad url must be an error, never a silent no-subscriber")
	}
	mr := miniredis.RunT(t)
	c, err := fgaEventStateClient(context.Background(), "redis://"+mr.Addr(), "")
	if err != nil || c == nil {
		t.Fatalf("good url: client=%v err=%v", c, err)
	}
	t.Cleanup(func() { _ = c.Close() })
}

type recordingEvicter struct {
	mu   sync.Mutex
	seen []string
}

func (r *recordingEvicter) InvalidateSubject(subject string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, subject)
	return 1
}

// TestRunFGAEventSubscriber_EvictsTheUser: an event for a user evicts that
// user, keyed on the bare Zitadel id the cache uses.
func TestRunFGAEventSubscriber_EvictsTheUser(t *testing.T) {
	mr := miniredis.RunT(t)
	sc, err := fgaEventStateClient(context.Background(), "redis://"+mr.Addr(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sc.Close() })
	ev := &recordingEvicter{}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go runFGAEventSubscriber(ctx, sc, slog.Default(), ev)
	deadline := time.Now().Add(5 * time.Second)
	for mr.PubSubNumSub(fgaevent.Channel)[fgaevent.Channel] == 0 {
		if time.Now().After(deadline) {
			t.Fatal("subscriber never subscribed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	mr.Publish(fgaevent.Channel, `{"userId":"100000000000000001","op":"delete","tenant":"acme","relation":"writer","object":"tenant:acme"}`)
	deadline = time.Now().Add(5 * time.Second)
	for {
		ev.mu.Lock()
		n := len(ev.seen)
		ev.mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no eviction after the event")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ev.seen[0] != "100000000000000001" {
		t.Fatalf("evicted %q, want the bare user id", ev.seen[0])
	}
}

// TestStartFGAEventSubscriber: no URL and an unreachable URL start nothing
// and say so; a reachable one subscribes.
func TestStartFGAEventSubscriber(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ev := &recordingEvicter{}
	if startFGAEventSubscriber(ctx, slog.Default(), ev, "", "") {
		t.Fatal("no URL must start no subscriber")
	}
	if startFGAEventSubscriber(ctx, slog.Default(), ev, "redis://127.0.0.1:1", "") {
		t.Fatal("an unreachable Redis must start no subscriber")
	}
	mr := miniredis.RunT(t)
	if !startFGAEventSubscriber(ctx, slog.Default(), ev, "redis://"+mr.Addr(), "") {
		t.Fatal("a reachable Redis must start the subscriber")
	}
	deadline := time.Now().Add(5 * time.Second)
	for mr.PubSubNumSub(fgaevent.Channel)[fgaevent.Channel] == 0 {
		if time.Now().After(deadline) {
			t.Fatal("subscriber never subscribed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
