// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package state

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
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

// TestPubSubErrorsSurface: a Redis that is gone makes publish and subscribe
// return errors rather than hang or pretend.
func TestPubSubErrorsSurface(t *testing.T) {
	mr := miniredis.RunT(t)
	cfg := DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	c, err := NewStateClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	mr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.PublishMessage(ctx, "t:chan", "x"); err == nil {
		t.Fatal("publish to a closed Redis must fail")
	}
	if err := c.SubscribeMessages(ctx, "t:chan", func(string) {}); err == nil {
		t.Fatal("subscribe to a closed Redis must fail")
	}
}

// TestSubscribeMessagesReturnsOnADrop: when the server drops the connection,
// SubscribeMessages returns an error, so the caller sees the drop and
// resubscribes on its own schedule (gibson#944). go-redis would otherwise
// reconnect inside its channel and never return.
func TestSubscribeMessagesReturnsOnADrop(t *testing.T) {
	mr := miniredis.RunT(t)
	cfg := DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	c, err := NewStateClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- c.SubscribeMessages(ctx, "t:chan", func(string) {}) }()
	deadline := time.Now().Add(5 * time.Second)
	for mr.PubSubNumSub("t:chan")["t:chan"] == 0 {
		if time.Now().After(deadline) {
			t.Fatal("never subscribed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	mr.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a dropped subscription must return an error, not nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SubscribeMessages did not return after the drop")
	}
}

// TestSubscribeMessagesPingsAnIdleSubscription: with no message for one
// health interval, SubscribeMessages pings the server and stays subscribed.
func TestSubscribeMessagesPingsAnIdleSubscription(t *testing.T) {
	old := subscribeHealthInterval
	subscribeHealthInterval = 50 * time.Millisecond
	t.Cleanup(func() { subscribeHealthInterval = old })

	mr := miniredis.RunT(t)
	cfg := DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	c, err := NewStateClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan string, 1)
	done := make(chan error, 1)
	go func() { done <- c.SubscribeMessages(ctx, "t:chan", func(p string) { got <- p }) }()
	deadline := time.Now().Add(5 * time.Second)
	for mr.PubSubNumSub("t:chan")["t:chan"] == 0 {
		if time.Now().After(deadline) {
			t.Fatal("never subscribed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Several health intervals pass with no message.
	time.Sleep(300 * time.Millisecond)
	mr.Publish("t:chan", "after-idle")
	select {
	case p := <-got:
		if p != "after-idle" {
			t.Fatalf("payload = %q", p)
		}
	case err := <-done:
		t.Fatalf("SubscribeMessages returned on an idle, healthy connection: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("no payload after the idle time")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("after cancel: %v, want nil", err)
	}
}

// freezeProxy forwards TCP to a server until freeze is called. After that it
// keeps each connection open and forwards nothing: a half-open connection.
type freezeProxy struct {
	ln     net.Listener
	target string
	frozen atomic.Bool
}

func newFreezeProxy(t *testing.T, target string) *freezeProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &freezeProxy{ln: ln, target: target}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			in, err := ln.Accept()
			if err != nil {
				return
			}
			out, err := net.Dial("tcp", target)
			if err != nil {
				_ = in.Close()
				continue
			}
			t.Cleanup(func() { _ = in.Close(); _ = out.Close() })
			go p.pipe(out, in)
			go p.pipe(in, out)
		}
	}()
	return p
}

func (p *freezeProxy) pipe(dst, src net.Conn) {
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		if err != nil {
			return
		}
		if p.frozen.Load() {
			continue
		}
		if _, err := dst.Write(buf[:n]); err != nil {
			return
		}
	}
}

// TestSubscribeMessagesDropsAHalfOpenConnection: the server stops answering
// but the connection stays open. SubscribeMessages pings, gets no answer,
// and returns an error after two health intervals.
func TestSubscribeMessagesDropsAHalfOpenConnection(t *testing.T) {
	old := subscribeHealthInterval
	subscribeHealthInterval = 50 * time.Millisecond
	t.Cleanup(func() { subscribeHealthInterval = old })

	mr := miniredis.RunT(t)
	proxy := newFreezeProxy(t, mr.Addr())
	cfg := DefaultConfig()
	cfg.URL = "redis://" + proxy.ln.Addr().String()
	c, err := NewStateClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	got := make(chan string, 1)
	go func() { done <- c.SubscribeMessages(ctx, "t:chan", func(p string) { got <- p }) }()
	deadline := time.Now().Add(5 * time.Second)
	for mr.PubSubNumSub("t:chan")["t:chan"] == 0 {
		if time.Now().After(deadline) {
			t.Fatal("never subscribed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// One message proves that the read loop runs. Then the server goes silent.
	mr.Publish("t:chan", "warm")
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("no message before the freeze")
	}
	proxy.frozen.Store(true)
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "answered no ping") {
			t.Fatalf("err = %v, want the no-ping error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SubscribeMessages did not drop a half-open connection")
	}
}
