// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package state

import (
	"context"
	"errors"
	"fmt"
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

// SubscribeMessages delivers every payload on channel to handle until ctx
// ends or the subscription drops. It returns nil only when ctx ended; any
// other return is a dropped subscription the caller should retry.
func (c *StateClient) SubscribeMessages(ctx context.Context, channel string, handle func(payload string)) error {
	sub := c.client.Subscribe(ctx, channel)
	defer func() { _ = sub.Close() }()
	// Receive confirms the subscription (or fails), so a bad address shows
	// up here rather than as silence.
	if _, err := sub.Receive(ctx); err != nil {
		return fmt.Errorf("state: subscribe to %s: %w", channel, err)
	}
	ch := sub.Channel()
	for {
		select {
		case <-ctx.Done():
			return nil
		case msg, ok := <-ch:
			if !ok {
				return errors.New("state: subscription channel closed")
			}
			handle(msg.Payload)
		}
	}
}
