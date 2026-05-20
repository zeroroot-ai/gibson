// Package graph — bus.go
//
// Bus is a lightweight in-process pub/sub for graph write notifications.
// It is consumed by graphServer.WatchGraphUpdates to fan out GraphUpdate
// messages to all active subscriptions for the calling tenant.
//
// Design D1 (design.md Component 5):
//   - Buffered channels at 256; non-blocking Publish drops on full channel.
//   - Per-tenant fan-out: Publish only delivers to subscriptions whose
//     tenant matches the published update's tenant.
//   - No external dependencies (Redis pub/sub deferred to v2).
//   - If a subscriber's channel is full, the update is dropped and a warn
//     is logged. The gRPC handler closes the stream with ResourceExhausted.
//
// Thread safety: all methods are safe for concurrent use.
//
// Spec: dashboard-knowledge-graph Phase 3, Task 8.
package graph

import (
	"log/slog"
	"sync"

	"github.com/google/uuid"
	graphpb "github.com/zero-day-ai/sdk/api/gen/gibson/graph/v1"
	"github.com/zero-day-ai/sdk/auth"
)

const busChannelBuffer = 256

// Bus is the in-process graph update bus.
// Construct with NewBus(); the zero value is not usable.
type Bus struct {
	mu     sync.RWMutex
	subs   map[string]*Subscription
	logger *slog.Logger
}

// Subscription represents a single subscriber's receive channel.
// It is created by Bus.Subscribe and torn down by Bus.Unsubscribe.
type Subscription struct {
	id     string
	tenant auth.TenantID
	ch     chan *graphpb.GraphUpdate
}

// Ch returns the receive-only channel for this subscription.
// The channel is closed when the subscription is unsubscribed.
func (s *Subscription) Ch() <-chan *graphpb.GraphUpdate {
	return s.ch
}

// NewBus creates a new Bus with an empty subscription set.
// logger may be nil; slog.Default() is used in that case.
func NewBus(logger *slog.Logger) *Bus {
	if logger == nil {
		logger = slog.Default()
	}
	return &Bus{
		subs:   make(map[string]*Subscription),
		logger: logger,
	}
}

// Subscribe registers a new subscription for the given tenant.
// The returned *Subscription's Ch() channel receives GraphUpdate messages
// published for the same tenant. The subscription remains active until
// Unsubscribe is called.
func (b *Bus) Subscribe(tenant auth.TenantID) *Subscription {
	sub := &Subscription{
		id:     uuid.New().String(),
		tenant: tenant,
		ch:     make(chan *graphpb.GraphUpdate, busChannelBuffer),
	}

	b.mu.Lock()
	b.subs[sub.id] = sub
	b.mu.Unlock()

	return sub
}

// Unsubscribe removes the subscription from the bus and closes its channel.
// After Unsubscribe returns, no further messages will be delivered to sub.Ch().
// Calling Unsubscribe on an already-unsubscribed subscription is a no-op.
func (b *Bus) Unsubscribe(sub *Subscription) {
	if sub == nil {
		return
	}

	b.mu.Lock()
	_, exists := b.subs[sub.id]
	if exists {
		delete(b.subs, sub.id)
	}
	b.mu.Unlock()

	if exists {
		close(sub.ch)
	}
}

// Publish delivers update to all active subscriptions whose tenant matches.
// Publish is non-blocking: if a subscription's channel is full, the update
// is dropped and a warning is logged (slow subscriber; the gRPC handler
// should close the stream with codes.ResourceExhausted in response to a
// full channel, but that is handled at the stream level, not here).
func (b *Bus) Publish(tenant auth.TenantID, update *graphpb.GraphUpdate) {
	if update == nil {
		return
	}

	b.mu.RLock()
	// Snapshot the list under read lock to avoid holding the lock during sends.
	targets := make([]*Subscription, 0)
	for _, sub := range b.subs {
		if sub.tenant == tenant {
			targets = append(targets, sub)
		}
	}
	b.mu.RUnlock()

	for _, sub := range targets {
		select {
		case sub.ch <- update:
			// delivered
		default:
			// Channel full — drop and warn. The gRPC stream handler detects
			// a full channel on its next receive and closes the stream.
			b.logger.Warn("graph bus: subscription channel full; update dropped",
				slog.String("tenant", tenant.String()),
				slog.String("sub_id", sub.id),
				slog.String("update_kind", update.GetKind().String()),
			)
		}
	}
}

// Len returns the current number of active subscriptions (for testing/observability).
func (b *Bus) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}
