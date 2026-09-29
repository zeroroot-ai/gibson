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
//	 "tenant": "<tenant id>", "relation": "<fga relation>", "object": "tenant:<tenant id>"}
//
// A change here is a change there, and the subscriber tolerates unknown
// fields so the two may move one at a time.
//
// DELIVERY. Redis pub/sub is fire-and-forget: a subscriber that is not
// connected misses the event. That is acceptable because the cache TTL still
// bounds staleness at fga.DefaultCacheTTL; the event makes the common case
// instant, the TTL keeps the worst case bounded. The subscriber reconnects
// with backoff and logs every gap.
package fgaevent

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Channel is the Redis pub/sub channel. It is also the value of PubsubChannel
// in operators/tenant/internal/clients/fga/pubsub.go.
const Channel = "gibson:fga.write"

// Op is what happened to the tuple.
type Op string

const (
	OpWrite  Op = "write"
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

// FromTuple builds the event for a tuple. The user id is the subject without
// its "user:" prefix; the tenant is the object without its "tenant:" prefix.
// A subject that is not a user, or an object that is not a tenant, yields an
// event with that field empty, which the subscriber ignores.
func FromTuple(op Op, user, relation, object string) Event {
	return Event{
		UserID:   strings.TrimPrefix(user, "user:"),
		Op:       op,
		Tenant:   strings.TrimPrefix(object, "tenant:"),
		Relation: relation,
		Object:   object,
	}
}

// Publisher publishes events. Publish never blocks a write on Redis: it
// bounds its own time and logs a failure, because the tuple write that
// preceded it already landed and must be reported as landed.
type Publisher interface {
	Publish(ctx context.Context, evt Event)
}

// NewRedisPublisher publishes on Channel through rdb. timeout bounds each
// publish; zero means one second.
func NewRedisPublisher(rdb redis.UniversalClient, log *slog.Logger, timeout time.Duration) Publisher {
	if timeout <= 0 {
		timeout = time.Second
	}
	return &redisPublisher{rdb: rdb, log: log, timeout: timeout}
}

type redisPublisher struct {
	rdb     redis.UniversalClient
	log     *slog.Logger
	timeout time.Duration
}

func (p *redisPublisher) Publish(ctx context.Context, evt Event) {
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
	if err := p.rdb.Publish(pubCtx, Channel, payload).Err(); err != nil {
		p.log.Warn("fgaevent: publish failed; the cache TTL bounds this change",
			"user_id", evt.UserID, "tenant", evt.Tenant, "relation", evt.Relation, "error", err.Error())
	}
}

// Subscribe delivers every event on Channel to handle until ctx ends. A lost
// connection is retried with backoff up to maxBackoff; each gap is logged,
// because during a gap the cache TTL is the only bound.
func Subscribe(ctx context.Context, rdb redis.UniversalClient, log *slog.Logger, handle func(Event)) {
	backoff := 500 * time.Millisecond
	const maxBackoff = 10 * time.Second
	for {
		err := subscribeOnce(ctx, rdb, log, handle)
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

func subscribeOnce(ctx context.Context, rdb redis.UniversalClient, log *slog.Logger, handle func(Event)) error {
	sub := rdb.Subscribe(ctx, Channel)
	defer func() { _ = sub.Close() }()
	// Receive confirms the subscription (or fails), so a bad address shows
	// up here rather than as silence.
	if _, err := sub.Receive(ctx); err != nil {
		return err
	}
	log.Info("fgaevent: subscribed", "channel", Channel)
	ch := sub.Channel()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg, ok := <-ch:
			if !ok {
				return errors.New("subscription channel closed")
			}
			var evt Event
			if err := json.Unmarshal([]byte(msg.Payload), &evt); err != nil {
				log.Warn("fgaevent: bad payload ignored", "error", err.Error())
				continue
			}
			if evt.UserID == "" {
				continue
			}
			handle(evt)
		}
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
