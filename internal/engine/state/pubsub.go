// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package state

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// PublishMessage publishes payload on a Redis pub/sub channel. Pub/sub is
// fire-and-forget: a subscriber that is not connected misses the message.
// The one caller today is the FGA write event (internal/platform/fgaevent),
// which tolerates that because a cache TTL bounds a missed eviction.
func (c *StateClient) PublishMessage(ctx context.Context, channel, payload string) error {
	if err := c.client.Publish(ctx, channel, payload).Err(); err != nil {
		return fmt.Errorf("state: publish on %s: %w", channel, err)
	}
	return nil
}

// subscribeHealthInterval is how often SubscribeMessages pings an idle
// subscription. A subscription that receives nothing, not even the answer
// to a ping, for two intervals is closed as dropped. A test sets a shorter
// interval.
var subscribeHealthInterval = 30 * time.Second

// SubscribeMessages delivers every payload on channel to handle until ctx
// ends or the subscription drops. It returns nil only when ctx ended; any
// other return is a dropped subscription the caller should retry.
//
// It reads the subscription itself and does not use PubSub.Channel. The
// channel of go-redis hides a dropped connection: it reconnects inside
// go-redis, on its own schedule, and never returns. The caller then cannot
// see the drop and cannot bound the time to resubscribe (gibson#944).
func (c *StateClient) SubscribeMessages(ctx context.Context, channel string, handle func(payload string)) error {
	sub := c.client.Subscribe(ctx, channel)
	defer func() { _ = sub.Close() }()

	// A blocked read watches neither ctx nor the health of the connection.
	// The watcher closes the subscription when ctx ends, or when nothing
	// arrived for two health intervals. The read then returns.
	interval := subscribeHealthInterval
	var lastSeen atomic.Int64
	lastSeen.Store(time.Now().UnixNano())
	var stale atomic.Bool
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				_ = sub.Close()
				return
			case <-stop:
				return
			case <-ticker.C:
				if time.Since(time.Unix(0, lastSeen.Load())) > 2*interval {
					stale.Store(true)
					_ = sub.Close()
					return
				}
				// The answer arrives in the read loop as a Pong.
				_ = sub.Ping(ctx)
			}
		}
	}()

	// Receive confirms the subscription (or fails), so a bad address shows
	// up here rather than as silence.
	if _, err := sub.Receive(ctx); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("state: subscribe to %s: %w", channel, err)
	}
	lastSeen.Store(time.Now().UnixNano())

	for {
		msg, err := sub.Receive(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			if stale.Load() {
				return fmt.Errorf("state: subscription to %s answered no ping for %v", channel, 2*interval)
			}
			return fmt.Errorf("state: subscription to %s dropped: %w", channel, err)
		}
		lastSeen.Store(time.Now().UnixNano())
		if m, ok := msg.(*redis.Message); ok {
			handle(m.Payload)
		}
	}
}
