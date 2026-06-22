package manifest

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestInvalidator_PublishDeliversToSubscriber(t *testing.T) {
	mr, rdb := newMiniredis(t)
	_ = mr
	i := NewInvalidator(rdb, nil)

	sub := rdb.Subscribe(context.Background(), invalidationChannel("tenant-x"))
	t.Cleanup(func() { _ = sub.Close() })
	// Wait for subscribe confirmation so we don't miss the message.
	if _, err := sub.Receive(context.Background()); err != nil {
		t.Fatalf("Subscribe receive confirm: %v", err)
	}
	ch := sub.Channel()

	i.Publish(context.Background(), "tenant-x", "fga_tuple_write")

	select {
	case msg := <-ch:
		if msg.Payload != "fga_tuple_write" {
			t.Fatalf("payload = %q, want fga_tuple_write", msg.Payload)
		}
		if msg.Channel != "tenant:tenant-x:manifest_invalidated" {
			t.Fatalf("channel = %q", msg.Channel)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for invalidation message")
	}
}

// failingPublishClient forces Publish to error; used to confirm the
// caller is never blocked or failed.
type failingPublishClient struct {
	calls int64
}

func (f *failingPublishClient) Publish(ctx context.Context, channel string, message any) *redis.IntCmd {
	atomic.AddInt64(&f.calls, 1)
	cmd := redis.NewIntCmd(ctx)
	cmd.SetErr(errors.New("redis unavailable"))
	return cmd
}

func TestInvalidator_PublishIsBestEffortOnRedisFailure(t *testing.T) {
	fp := &failingPublishClient{}
	i := NewInvalidator(fp, nil)
	// Must not panic, must not block.
	done := make(chan struct{})
	go func() {
		i.Publish(context.Background(), "tenant-y", "component_registered")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("Publish blocked on Redis failure (should be best-effort)")
	}
	if got := atomic.LoadInt64(&fp.calls); got != 1 {
		t.Fatalf("publish calls = %d, want 1", got)
	}
}

func TestInvalidator_EmptyTenantSkipped(t *testing.T) {
	fp := &failingPublishClient{}
	i := NewInvalidator(fp, nil)
	i.Publish(context.Background(), "", "whatever")
	if got := atomic.LoadInt64(&fp.calls); got != 0 {
		t.Fatalf("publish calls with empty tenant = %d, want 0", got)
	}
}

func TestInvalidationChannelFormat(t *testing.T) {
	got := InvalidationChannel("acme")
	want := "tenant:acme:manifest_invalidated"
	if got != want {
		t.Fatalf("InvalidationChannel = %q, want %q", got, want)
	}
	if InvalidationPattern != "tenant:*:manifest_invalidated" {
		t.Fatalf("InvalidationPattern = %q", InvalidationPattern)
	}
}
