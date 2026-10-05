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

// TestRequiredStateClient: an empty URL, a bad URL and a Redis that does not
// answer are each an error. A good URL gives a client.
func TestRequiredStateClient(t *testing.T) {
	for name, rawURL := range map[string]string{
		"empty":       "",
		"blank":       "   ",
		"not a url":   "not a url",
		"unreachable": "redis://127.0.0.1:1",
	} {
		if c, err := requiredStateClient(context.Background(), rawURL, ""); err == nil {
			_ = c.Close()
			t.Fatalf("%s: got a client, want an error", name)
		}
	}
	mr := miniredis.RunT(t)
	c, err := requiredStateClient(context.Background(), "redis://"+mr.Addr(), "")
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
	sc, err := requiredStateClient(context.Background(), "redis://"+mr.Addr(), "")
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
