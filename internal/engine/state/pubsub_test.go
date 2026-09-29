// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package state

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

// TestPublishAndSubscribeMessages: a payload published on a channel reaches
// a subscriber on it, and the subscription ends cleanly with the context.
func TestPublishAndSubscribeMessages(t *testing.T) {
	mr := miniredis.RunT(t)
	cfg := DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	pub, err := NewStateClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pub.Close() })
	sub, err := NewStateClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan string, 2)
	done := make(chan error, 1)
	go func() { done <- sub.SubscribeMessages(ctx, "t:chan", func(p string) { got <- p }) }()
	deadline := time.Now().Add(5 * time.Second)
	for mr.PubSubNumSub("t:chan")["t:chan"] == 0 {
		if time.Now().After(deadline) {
			t.Fatal("never subscribed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := pub.PublishMessage(ctx, "t:chan", "hello"); err != nil {
		t.Fatalf("PublishMessage: %v", err)
	}
	select {
	case p := <-got:
		if p != "hello" {
			t.Fatalf("payload = %q", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no payload")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SubscribeMessages after cancel: %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SubscribeMessages did not return after cancel")
	}
}
