// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package fga

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/redis/go-redis/v9"
)

// PubsubChannel is the Redis pub/sub channel where FGA-mutation events are
// published after a successful Write or Delete. The dashboard's R17
// membership cache subscribes to this channel and invalidates per-user
// `dashboard:memberships:user:<sub>` entries on every event.
//
// Keep this constant in sync with the daemon's
// core/gibson/internal/authz/pubsub.go FGAPubsubChannel.
const PubsubChannel = "gibson:fga.write"

// EventOp is the operation kind reported in the pub/sub payload.
type EventOp string

const (
	EventOpWrite  EventOp = "write"
	EventOpDelete EventOp = "delete"
)

// Event is the JSON payload published on PubsubChannel. Mirrors the daemon's
// FGAEvent — subscribers parse a single shape regardless of which side
// emitted the event.
type Event struct {
	UserID   string  `json:"userId"`
	Op       EventOp `json:"op"`
	Tenant   string  `json:"tenant"`
	Relation string  `json:"relation"`
	Object   string  `json:"object"`
}

// EventPublisher publishes Event payloads to Redis pub/sub.
//
// All Publish calls are best-effort and bounded by a short timeout; failures
// are logged at WARN and never block the FGA mutation that produced them.
type EventPublisher interface {
	Publish(ctx context.Context, evt Event)
}

type noopPublisher struct{}

func (noopPublisher) Publish(_ context.Context, _ Event) {}

// NewNoopPublisher returns a publisher that discards all events.
func NewNoopPublisher() EventPublisher { return noopPublisher{} }

type redisPublisher struct {
	rdb     *redis.Client
	channel string
	timeout time.Duration
	log     logr.Logger
}

// NewRedisPublisher returns a publisher that fans events to the given
// channel on the supplied Redis client. timeout bounds the publish call;
// pass 0 to use the default of 100ms.
//
// The publisher is fire-and-forget: a failed publish never blocks the FGA
// write that produced it — the operator's correctness does not depend on
// the dashboard cache being up to date, only on the FGA tuple landing.
func NewRedisPublisher(rdb *redis.Client, channel string, timeout time.Duration, log logr.Logger) EventPublisher {
	if rdb == nil {
		return NewNoopPublisher()
	}
	if channel == "" {
		channel = PubsubChannel
	}
	if timeout <= 0 {
		timeout = 100 * time.Millisecond
	}
	return &redisPublisher{
		rdb:     rdb,
		channel: channel,
		timeout: timeout,
		log:     log,
	}
}

func (p *redisPublisher) Publish(ctx context.Context, evt Event) {
	payload, err := json.Marshal(evt)
	if err != nil {
		p.log.Info("fga pubsub marshal failed",
			"channel", p.channel,
			"error", err.Error(),
		)
		return
	}
	pubCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	if err := p.rdb.Publish(pubCtx, p.channel, payload).Err(); err != nil {
		p.log.Info("fga pubsub publish failed",
			"channel", p.channel,
			"op", string(evt.Op),
			"user_id", evt.UserID,
			"tenant", evt.Tenant,
			"error", err.Error(),
		)
	}
}

// publishingClient wraps a Client and emits an Event to the configured
// publisher after every successful Write / Delete.
//
// Use WithEventPublisher to construct one. The wrapper preserves all
// interface semantics on the failure path — no event is published when
// the underlying call returns a non-nil error.
type publishingClient struct {
	Client
	pub EventPublisher
}

// WithEventPublisher wraps the given Client so that every successful
// Write / Delete fans a corresponding Event to the publisher. If pub is
// nil or a noopPublisher, the inner client is returned unchanged.
//
// The wrapper preserves all interface semantics: idempotency handling
// (ErrAlreadyExists, ErrNotFound) on Write/Delete happens in the inner
// HTTPClient; the publish step runs ONLY when the underlying call
// returns nil error. ErrAlreadyExists on Write is treated as a non-publish
// path because the tuple already existed — no membership change occurred.
func WithEventPublisher(inner Client, pub EventPublisher) Client {
	if inner == nil {
		return inner
	}
	if pub == nil {
		return inner
	}
	if _, ok := pub.(noopPublisher); ok {
		return inner
	}
	return &publishingClient{Client: inner, pub: pub}
}

// Write delegates to the inner client and, on success, publishes one Event
// per tuple to PubsubChannel.
func (p *publishingClient) Write(ctx context.Context, tuples []Tuple) error {
	if err := p.Client.Write(ctx, tuples); err != nil {
		return err
	}
	p.publishAll(ctx, EventOpWrite, tuples)
	return nil
}

// Delete delegates to the inner client and, on success, publishes one Event
// per tuple to PubsubChannel.
func (p *publishingClient) Delete(ctx context.Context, tuples []Tuple) error {
	if err := p.Client.Delete(ctx, tuples); err != nil {
		return err
	}
	p.publishAll(ctx, EventOpDelete, tuples)
	return nil
}

func (p *publishingClient) publishAll(ctx context.Context, op EventOp, tuples []Tuple) {
	for _, t := range tuples {
		evt := Event{
			UserID:   extractUserSub(t.User),
			Op:       op,
			Tenant:   extractTenantSlug(t.Object, t.User),
			Relation: t.Relation,
			Object:   t.Object,
		}
		p.pub.Publish(ctx, evt)
	}
}

// extractUserSub returns the bare Zitadel sub from `user:<sub>` references.
// Returns "" for any other shape (tenant:*#member, plugin_principal:*, etc.).
func extractUserSub(userRef string) string {
	const prefix = "user:"
	if !strings.HasPrefix(userRef, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(userRef, prefix)
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

// extractTenantSlug returns the tenant identifier referenced by a tuple.
//
//   - object="tenant:<slug>"        → "<slug>"
//   - object="tenant:<slug>#member" → "<slug>"
//   - user="tenant:<slug>#..."      → "<slug>"  (when the object is not a tenant)
//   - otherwise                     → ""
func extractTenantSlug(object, user string) string {
	if s := tenantFromRef(object); s != "" {
		return s
	}
	return tenantFromRef(user)
}

func tenantFromRef(ref string) string {
	const prefix = "tenant:"
	if !strings.HasPrefix(ref, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(ref, prefix)
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	return rest
}
