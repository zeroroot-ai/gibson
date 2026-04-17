package manifest

import (
	"context"
	"testing"
	"time"

	manifestpb "github.com/zero-day-ai/sdk/api/gen/gibson/manifest/v1"
)

func TestWatchHub_DeliversToSubscribers(t *testing.T) {
	mr, rdb := newMiniredis(t)
	_ = mr
	hub := NewWatchHub(rdb, nil, 10*time.Second, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := hub.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer hub.Stop()

	ch, unsub := hub.Subscribe("tenant-a")
	defer unsub()

	// Give psubscribe a beat to install.
	time.Sleep(50 * time.Millisecond)

	inv := NewInvalidator(rdb, nil)
	inv.Publish(ctx, "tenant-a", "fga_tuple_write")

	select {
	case ev := <-ch:
		if ev == nil {
			t.Fatalf("nil event")
		}
		if ev.EventType != manifestpb.ManifestInvalidationEvent_EVENT_TYPE_INVALIDATED {
			t.Fatalf("event type = %v", ev.EventType)
		}
		if ev.TenantId != "tenant-a" || ev.Reason != "fga_tuple_write" {
			t.Fatalf("ev = %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for invalidation event")
	}
}

func TestWatchHub_FanoutToMultipleSubscribers(t *testing.T) {
	mr, rdb := newMiniredis(t)
	_ = mr
	hub := NewWatchHub(rdb, nil, 10*time.Second, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = hub.Start(ctx)
	defer hub.Stop()

	ch1, unsub1 := hub.Subscribe("tenant-a")
	ch2, unsub2 := hub.Subscribe("tenant-a")
	defer unsub1()
	defer unsub2()

	time.Sleep(50 * time.Millisecond)
	inv := NewInvalidator(rdb, nil)
	inv.Publish(ctx, "tenant-a", "component_registered")

	for i, c := range []<-chan *manifestpb.ManifestInvalidationEvent{ch1, ch2} {
		select {
		case <-c:
		case <-time.After(2 * time.Second):
			t.Fatalf("subscriber %d missed event", i)
		}
	}
}

func TestWatchHub_UnsubscribeCleansUp(t *testing.T) {
	mr, rdb := newMiniredis(t)
	_ = mr
	hub := NewWatchHub(rdb, nil, 10*time.Second, 4)
	_ = hub.Start(context.Background())
	defer hub.Stop()

	ch, unsub := hub.Subscribe("tenant-a")
	unsub()
	// ch must now be closed.
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatalf("expected channel closed after unsub")
		}
	case <-time.After(time.Second):
		t.Fatalf("channel not closed after unsub")
	}

	// perTenant map must be cleared.
	hub.mu.Lock()
	_, still := hub.perTenant["tenant-a"]
	hub.mu.Unlock()
	if still {
		t.Fatalf("perTenant retained empty subscriber set")
	}
}

func TestWatchHub_HeartbeatBuilder(t *testing.T) {
	ev := BuildHeartbeat("tenant-a")
	if ev.EventType != manifestpb.ManifestInvalidationEvent_EVENT_TYPE_HEARTBEAT {
		t.Fatalf("event type = %v", ev.EventType)
	}
	if ev.TenantId != "tenant-a" {
		t.Fatalf("tenant = %q", ev.TenantId)
	}
	if ev.EmittedAt == nil {
		t.Fatalf("EmittedAt should be set")
	}
}
