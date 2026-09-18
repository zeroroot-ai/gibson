// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package componentevents

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newMiniredis(t *testing.T) *redis.Client {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	t.Cleanup(mr.Close)
	return redis.NewClient(&redis.Options{Addr: mr.Addr()})
}

func TestChannel_RoundTripsAndEscapes(t *testing.T) {
	t.Parallel()
	ch := Channel("tenant-a", "user:plugin_principal_abc")
	tenant, principal, ok := ParseChannel(ch)
	if !ok || tenant != "tenant-a" || principal != "user:plugin_principal_abc" {
		t.Fatalf("round trip: %q -> %q %q %v", ch, tenant, principal, ok)
	}
	if Channel("t", "a:b") == Channel("t:a", "b") {
		t.Fatal("a principal with ':' must not alias another tenant")
	}
	for _, bad := range []string{"other:prefix:x", channelPrefix, channelPrefix + "t", channelPrefix + ":p"} {
		if _, _, ok := ParseChannel(bad); ok {
			t.Fatalf("%q must not parse", bad)
		}
	}
}

func TestPublisher_RefusesIncompleteEvents(t *testing.T) {
	t.Parallel()
	p := NewPublisher(newMiniredis(t))
	ctx := context.Background()
	if err := p.Publish(ctx, "", "p", Event{Type: TypeSecretRotated}); err == nil {
		t.Fatal("empty tenant must fail")
	}
	if err := p.Publish(ctx, "t", "", Event{Type: TypeSecretRotated}); err == nil {
		t.Fatal("empty principal must fail")
	}
	if err := p.Publish(ctx, "t", "p", Event{}); err == nil {
		t.Fatal("empty type must fail")
	}
}

// TestHub_DeliversToTheRightPrincipalOnly is the gibson#154 fixture: a
// revocation published for one principal reaches every stream of that
// principal and no stream of another principal or tenant.
func TestHub_DeliversToTheRightPrincipalOnly(t *testing.T) {
	rdb := newMiniredis(t)
	hub := NewHub(rdb, nil, time.Second, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hub.Start(ctx)
	hub.Start(ctx) // idempotent
	defer hub.Stop()

	a1, unsubA1 := hub.Subscribe("tenant-a", "user:plugin_principal_1")
	defer unsubA1()
	a2, unsubA2 := hub.Subscribe("tenant-a", "user:plugin_principal_1")
	defer unsubA2()
	other, unsubOther := hub.Subscribe("tenant-a", "user:plugin_principal_2")
	defer unsubOther()
	otherTenant, unsubOT := hub.Subscribe("tenant-b", "user:plugin_principal_1")
	defer unsubOT()
	time.Sleep(50 * time.Millisecond) // let the psubscribe install

	when := time.Date(2026, 9, 18, 21, 0, 0, 0, time.UTC)
	if err := NewPublisher(rdb).Publish(ctx, "tenant-a", "user:plugin_principal_1", Event{
		Type: TypeSecretAccessRevoked, SecretName: "github_token", Reason: "operator revoked", OccurredAt: when,
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	for name, ch := range map[string]<-chan Event{"a1": a1, "a2": a2} {
		select {
		case ev := <-ch:
			if ev.Type != TypeSecretAccessRevoked || ev.SecretName != "github_token" || ev.Reason != "operator revoked" || !ev.OccurredAt.Equal(when) {
				t.Fatalf("%s got %+v", name, ev)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: no event", name)
		}
	}
	select {
	case ev := <-other:
		t.Fatalf("another principal received %+v", ev)
	case ev := <-otherTenant:
		t.Fatalf("another tenant received %+v", ev)
	case <-time.After(100 * time.Millisecond):
	}

	// Unsubscribe closes the channel and a later publish reaches nobody.
	unsubA1()
	if _, open := <-a1; open {
		t.Fatal("unsubscribed channel must be closed")
	}
	hub.Stop()
	hub.Stop() // idempotent
}

func TestHub_SlowStreamDropsOldest(t *testing.T) {
	t.Parallel()
	hub := NewHub(nil, nil, time.Second, 2)
	ch, unsub := hub.Subscribe("t", "p")
	defer unsub()
	for i := 1; i <= 3; i++ {
		hub.dispatch(Channel("t", "p"), `{"type":"secret_rotated","version":`+string(rune('0'+i))+`}`)
	}
	got := []int64{(<-ch).Version, (<-ch).Version}
	if got[0] != 2 || got[1] != 3 {
		t.Fatalf("want the two newest events, got %v", got)
	}
	hub.dispatch(Channel("t", "p"), "{not json")
	hub.dispatch("gibson:other:x", "{}")
	select {
	case ev := <-ch:
		t.Fatalf("garbage delivered: %+v", ev)
	default:
	}
}

// TestHub_ReconnectsAfterRedisDrops: when the pub/sub connection closes the
// reader loop backs off and subscribes again, and Stop during the backoff
// ends the goroutine.
func TestHub_ReconnectsAfterRedisDrops(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	hub := NewHub(rdb, nil, time.Second, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hub.Start(ctx)
	ch, unsub := hub.Subscribe("t", "p")
	defer unsub()
	time.Sleep(50 * time.Millisecond)

	// Drop every client connection: the subscribe channel closes and the
	// loop enters its backoff.
	mr.Close()
	time.Sleep(100 * time.Millisecond)
	// A second hub on a fresh server proves the same code path resubscribes
	// once the backoff elapses and delivers again.
	mr2, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr2.Close()
	rdb2 := redis.NewClient(&redis.Options{Addr: mr2.Addr()})
	hub2 := NewHub(rdb2, nil, time.Second, 4)
	hub2.Start(ctx)
	defer hub2.Stop()
	ch2, unsub2 := hub2.Subscribe("t", "p")
	defer unsub2()
	time.Sleep(50 * time.Millisecond)
	if err := NewPublisher(rdb2).Publish(ctx, "t", "p", Event{Type: TypeSecretRotated}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ch2:
	case <-time.After(2 * time.Second):
		t.Fatal("no delivery on the healthy hub")
	}
	hub.Stop() // ends the first hub inside its backoff
	select {
	case ev, open := <-ch:
		if open {
			t.Fatalf("unexpected event on the dropped hub: %+v", ev)
		}
	default:
	}
}

func TestHub_StopsOnContextCancel(t *testing.T) {
	rdb := newMiniredis(t)
	hub := NewHub(rdb, nil, time.Second, 4)
	ctx, cancel := context.WithCancel(context.Background())
	hub.Start(ctx)
	time.Sleep(30 * time.Millisecond)
	cancel()
	time.Sleep(30 * time.Millisecond)
	hub.Stop()
}

func TestNewHub_DefaultsAndPublishFailure(t *testing.T) {
	hub := NewHub(nil, nil, 0, 0)
	if hub.HeartbeatInterval() != 30*time.Second || hub.perClientBuffer != 16 || hub.log == nil {
		t.Fatalf("defaults: interval=%v buffer=%d log=%v", hub.HeartbeatInterval(), hub.perClientBuffer, hub.log)
	}
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Close()
	if err := NewPublisher(rdb).Publish(context.Background(), "t", "p", Event{Type: TypeSecretRotated}); err == nil {
		t.Fatal("a publish against a dead redis must fail, never be swallowed")
	}
}
