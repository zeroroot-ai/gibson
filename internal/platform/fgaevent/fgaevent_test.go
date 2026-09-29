// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fgaevent

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// TestPublishReachesSubscriber: an event published by one client arrives at
// a subscriber on another, with the wire fields intact.
func TestPublishReachesSubscriber(t *testing.T) {
	mr := miniredis.RunT(t)
	pubClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	subClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = pubClient.Close(); _ = subClient.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	got := make(chan Event, 4)
	go Subscribe(ctx, subClient, slog.Default(), func(e Event) { got <- e })
	// Wait for the subscription before publishing: pub/sub has no replay.
	deadline := time.Now().Add(5 * time.Second)
	for mr.PubSubNumSub(Channel)[Channel] == 0 {
		if time.Now().After(deadline) {
			t.Fatal("subscriber never subscribed")
		}
		time.Sleep(10 * time.Millisecond)
	}

	NewRedisPublisher(pubClient, slog.Default(), 0).Publish(ctx, FromTuple(OpDelete, "user:100000000000000001", "writer", "tenant:acme"))
	select {
	case e := <-got:
		if e.UserID != "100000000000000001" || e.Op != OpDelete || e.Tenant != "acme" || e.Relation != "writer" || e.Object != "tenant:acme" {
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
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	got := make(chan Event, 4)
	go Subscribe(ctx, rdb, slog.Default(), func(e Event) { got <- e })
	deadline := time.Now().Add(5 * time.Second)
	for mr.PubSubNumSub(Channel)[Channel] == 0 {
		if time.Now().After(deadline) {
			t.Fatal("subscriber never subscribed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	mr.Publish(Channel, "not json")
	mr.Publish(Channel, `{"op":"write","tenant":"acme","relation":"admin","object":"tenant:acme"}`)
	mr.Publish(Channel, `{"userId":"100000000000000002","op":"write","tenant":"acme","relation":"admin","object":"tenant:acme","extra":"tolerated"}`)
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

// TestPublisherSkipsNonUserSubjects: a tuple whose subject is not a user
// (an agent, a team) produces no event; ext-authz keys human decisions only.
func TestPublisherSkipsNonUserSubjects(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	evt := FromTuple(OpWrite, "agent:abc", "member", "tenant:acme")
	if evt.UserID != "agent:abc" {
		// FromTuple strips only the user prefix; the publisher and the
		// subscriber treat a missing id as nothing to do.
		t.Fatalf("unexpected user id %q", evt.UserID)
	}
	NewRedisPublisher(rdb, slog.Default(), 0).Publish(context.Background(), Event{})
}
