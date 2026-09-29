// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package fgaevent is the FGA write event: the daemon and the tenant-operator
// publish one on the Redis channel Channel for every tenant-role tuple they
// write or delete, and ext-authz subscribes and drops the affected decisions
// from its cache the moment the event arrives (hosted#204, ADR-0093).
//
// WHY THIS EXISTS. ext-authz caches FGA decisions per (subject, tenant,
// relation, object) for fga.DefaultCacheTTL. Without this event, a demoted
// or removed user kept their old rights for the whole TTL, and the only bound
// on "refused within seconds" was the TTL itself. The tenant-operator already
// published this event (operators/tenant/internal/clients/fga/pubsub.go) and
// nothing listened. This package is the daemon's publisher and ext-authz's
// subscriber for the same wire contract.
//
// WIRE CONTRACT, shared with the tenant-operator's copy (its module cannot
// import this one). Channel "gibson:fga.write", JSON:
//
//	{"userId": "<zitadel user id>", "op": "write"|"delete",
//	 "tenant": "<tenant id>", "relation": "<fga relation>", "object": "<fga object>"}
//
// A change here is a change there, and the subscriber tolerates unknown
// fields so the two may move one at a time.
//
// DELIVERY. Redis pub/sub is fire-and-forget: a subscriber that is not
// connected misses the event. That is acceptable because the cache TTL still
// bounds staleness at fga.DefaultCacheTTL; the event makes the common case
// instant, the TTL keeps the worst case bounded. The subscriber reconnects
// with backoff and logs every gap. The Redis client itself lives in
// internal/engine/state; this package sees only two methods of it.
package fgaevent

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"
)

// Channel is the Redis pub/sub channel. It is also the value of PubsubChannel
// in operators/tenant/internal/clients/fga/pubsub.go.
const Channel = "gibson:fga.write"

// Op is what happened to the tuple.
type Op string

// The two operations a tuple change can be.
const (
	// OpWrite: the tuple was written.
	OpWrite Op = "write"
	// OpDelete: the tuple was deleted.
	OpDelete Op = "delete"
)

// Event is one tuple change. The field names are the wire contract.
type Event struct {
	UserID   string `json:"userId"`
	Op       Op     `json:"op"`
	Tenant   string `json:"tenant"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

const (
	userPrefix   = "user:"
	tenantPrefix = "tenant:"
)

// FromTuple builds the event for a tuple. The user id is the subject without
// its FGA type prefix; the tenant is the object without its type prefix. A
// subject that is not a user yields an event with no user id, which the
// publisher and the subscriber ignore.
func FromTuple(op Op, user, relation, object string) Event {
	userID := ""
	if strings.HasPrefix(user, userPrefix) {
		userID = strings.TrimPrefix(user, userPrefix)
	}
	return Event{
		UserID:   userID,
		Op:       op,
		Tenant:   strings.TrimPrefix(object, tenantPrefix),
		Relation: relation,
		Object:   object,
	}
}

// MessagePublisher is the one method of the state client a publisher needs.
type MessagePublisher interface {
	PublishMessage(ctx context.Context, channel, payload string) error
}

// MessageSubscriber is the one method of the state client a subscriber needs.
type MessageSubscriber interface {
	SubscribeMessages(ctx context.Context, channel string, handle func(payload string)) error
}

// Publisher publishes events. Publish never blocks a write on Redis: it
// bounds its own time and logs a failure, because the tuple write that
// preceded it already landed and must be reported as landed.
type Publisher interface {
	Publish(ctx context.Context, evt Event)
}

// NewPublisher publishes on Channel through mp. timeout bounds each publish;
// zero means one second.
func NewPublisher(mp MessagePublisher, log *slog.Logger, timeout time.Duration) Publisher {
	if timeout <= 0 {
		timeout = time.Second
	}
	return &publisher{mp: mp, log: log, timeout: timeout}
}

type publisher struct {
	mp      MessagePublisher
	log     *slog.Logger
	timeout time.Duration
}

func (p *publisher) Publish(ctx context.Context, evt Event) {
	if evt.UserID == "" {
		return
	}
	payload, err := json.Marshal(evt)
	if err != nil {
		p.log.Warn("fgaevent: marshal failed", "error", err.Error())
		return
	}
	pubCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	if err := p.mp.PublishMessage(pubCtx, Channel, string(payload)); err != nil {
		p.log.Warn("fgaevent: publish failed; the cache TTL bounds this change",
			"user_id", evt.UserID, "tenant", evt.Tenant, "relation", evt.Relation, "error", err.Error())
	}
}

// Subscribe delivers every event on Channel to handle until ctx ends. A lost
// subscription is retried with backoff up to maxBackoff; each gap is logged,
// because during a gap the cache TTL is the only bound.
func Subscribe(ctx context.Context, ms MessageSubscriber, log *slog.Logger, handle func(Event)) {
	backoff := 500 * time.Millisecond
	const maxBackoff = 10 * time.Second
	for {
		err := ms.SubscribeMessages(ctx, Channel, func(payload string) {
			var evt Event
			if uerr := json.Unmarshal([]byte(payload), &evt); uerr != nil {
				log.Warn("fgaevent: bad payload ignored", "error", uerr.Error())
				return
			}
			if evt.UserID == "" {
				return
			}
			handle(evt)
		})
		if ctx.Err() != nil {
			return
		}
		log.Warn("fgaevent: subscription ended; the cache TTL bounds changes until it is back",
			"error", errString(err), "retry_in", backoff.String())
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
