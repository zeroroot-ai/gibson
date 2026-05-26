package graph

import (
	"testing"
	"time"

	graphpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graph/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

func mustTenant(s string) auth.TenantID {
	t, err := auth.NewTenantID(s)
	if err != nil {
		panic(err)
	}
	return t
}

// ─────────────────────────────────────────────────────────────────────────────
// Subscribe, Publish, Receive
// ─────────────────────────────────────────────────────────────────────────────

func TestBus_SubscribePublishReceive(t *testing.T) {
	t.Parallel()
	bus := NewBus(nil)
	tenant := mustTenant("alpha")

	sub := bus.Subscribe(tenant)
	defer bus.Unsubscribe(sub)

	update := &graphpb.GraphUpdate{Kind: graphpb.GraphUpdate_NODE_ADDED}
	bus.Publish(tenant, update)

	select {
	case got := <-sub.Ch():
		if got.GetKind() != graphpb.GraphUpdate_NODE_ADDED {
			t.Errorf("got kind %v, want NODE_ADDED", got.GetKind())
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timed out waiting for published update")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-tenant isolation — publish to tenant A must not reach tenant B
// ─────────────────────────────────────────────────────────────────────────────

func TestBus_CrossTenantIsolation(t *testing.T) {
	t.Parallel()
	bus := NewBus(nil)
	tenantA := mustTenant("tenant-a")
	tenantB := mustTenant("tenant-b")

	subA := bus.Subscribe(tenantA)
	subB := bus.Subscribe(tenantB)
	defer bus.Unsubscribe(subA)
	defer bus.Unsubscribe(subB)

	// Publish to tenant A only.
	bus.Publish(tenantA, &graphpb.GraphUpdate{Kind: graphpb.GraphUpdate_NODE_ADDED})

	// subA should receive the update.
	select {
	case <-subA.Ch():
		// expected
	case <-time.After(200 * time.Millisecond):
		t.Fatal("tenant A subscription did not receive update")
	}

	// subB must NOT receive anything.
	select {
	case got := <-subB.Ch():
		t.Errorf("tenant B received unexpected update: %v", got)
	case <-time.After(50 * time.Millisecond):
		// expected — channel should be empty
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Slow subscriber — channel full → update dropped (non-blocking publish)
// ─────────────────────────────────────────────────────────────────────────────

func TestBus_SlowSubscriberDropped(t *testing.T) {
	t.Parallel()
	bus := NewBus(nil)
	tenant := mustTenant("slow")

	sub := bus.Subscribe(tenant)
	defer bus.Unsubscribe(sub)

	// Fill the channel completely.
	for i := 0; i < busChannelBuffer; i++ {
		bus.Publish(tenant, &graphpb.GraphUpdate{Kind: graphpb.GraphUpdate_NODE_ADDED})
	}

	// The next publish must return without blocking (drop).
	done := make(chan struct{})
	go func() {
		bus.Publish(tenant, &graphpb.GraphUpdate{Kind: graphpb.GraphUpdate_EDGE_ADDED})
		close(done)
	}()

	select {
	case <-done:
		// non-blocking as required
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Publish blocked on full channel — should drop")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Unsubscribe — channel is closed; subsequent reads drain and terminate
// ─────────────────────────────────────────────────────────────────────────────

func TestBus_UnsubscribeClosesChannel(t *testing.T) {
	t.Parallel()
	bus := NewBus(nil)
	tenant := mustTenant("unsub")

	sub := bus.Subscribe(tenant)
	bus.Publish(tenant, &graphpb.GraphUpdate{Kind: graphpb.GraphUpdate_NODE_ADDED})
	bus.Unsubscribe(sub)

	// Channel should be closed; reading from it should not block.
	// The published message was already in the buffer, so we drain first.
	timeout := time.After(200 * time.Millisecond)
	for {
		select {
		case _, open := <-sub.Ch():
			if !open {
				return // closed as expected
			}
			// This is the buffered message; keep looping.
		case <-timeout:
			t.Fatal("channel not closed after Unsubscribe")
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Unsubscribe twice is a no-op
// ─────────────────────────────────────────────────────────────────────────────

func TestBus_UnsubscribeTwice_NoOp(t *testing.T) {
	t.Parallel()
	bus := NewBus(nil)
	tenant := mustTenant("double-unsub")

	sub := bus.Subscribe(tenant)
	bus.Unsubscribe(sub)

	// Second call must not panic.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("second Unsubscribe panicked: %v", r)
		}
	}()
	bus.Unsubscribe(sub)
}

// ─────────────────────────────────────────────────────────────────────────────
// Len reflects active subscription count
// ─────────────────────────────────────────────────────────────────────────────

func TestBus_Len(t *testing.T) {
	t.Parallel()
	bus := NewBus(nil)
	tenant := mustTenant("len-test")

	if bus.Len() != 0 {
		t.Fatalf("expected 0 subscriptions, got %d", bus.Len())
	}

	sub1 := bus.Subscribe(tenant)
	sub2 := bus.Subscribe(tenant)

	if bus.Len() != 2 {
		t.Errorf("expected 2 subscriptions, got %d", bus.Len())
	}

	bus.Unsubscribe(sub1)
	if bus.Len() != 1 {
		t.Errorf("expected 1 subscription after unsub, got %d", bus.Len())
	}

	bus.Unsubscribe(sub2)
	if bus.Len() != 0 {
		t.Errorf("expected 0 subscriptions after all unsub, got %d", bus.Len())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Publish nil update is a no-op
// ─────────────────────────────────────────────────────────────────────────────

func TestBus_PublishNilNoOp(t *testing.T) {
	t.Parallel()
	bus := NewBus(nil)
	tenant := mustTenant("nil-publish")
	sub := bus.Subscribe(tenant)
	defer bus.Unsubscribe(sub)

	// Should not panic.
	bus.Publish(tenant, nil)

	select {
	case got := <-sub.Ch():
		t.Errorf("nil publish delivered unexpected message: %v", got)
	case <-time.After(50 * time.Millisecond):
		// expected — nothing delivered
	}
}
