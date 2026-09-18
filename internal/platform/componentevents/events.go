// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package componentevents carries lifecycle events from the daemon to one
// running component: secret_access_revoked and secret_rotated (gibson#154).
//
// A plugin that declares a secret subscribes at Serve through
// ComponentService/WatchComponentEvents. Before this stream existed a revoked
// secret kept working until the process restarted, so the SDK refuses to
// start such a plugin without it (sdk#55).
//
// The wire is one Redis pub/sub channel per (tenant, principal). Every daemon
// replica runs a Hub that psubscribes the whole prefix once and fans each
// message out to the connected streams for that principal, so a revocation
// written on one replica reaches a plugin streaming from another. The
// principal is the FGA user string the daemon authorizes the component as
// (componentFGAUser in internal/platform/component), which is also the user
// on the can_resolve tuple a revocation deletes. Keying on that string means
// a publisher and a subscriber that disagree on the principal's shape would
// also disagree with authorization, and that mismatch already surfaces on
// the first GetCredential.
package componentevents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Event types on the wire. The SDK subscriber drops any other type after a
// debug log, which is what a heartbeat relies on.
const (
	TypeSecretAccessRevoked = "secret_access_revoked"
	TypeSecretRotated       = "secret_rotated"
	TypeHeartbeat           = "heartbeat"
)

const channelPrefix = "gibson:component-events:"

// Event is one notification for one component.
type Event struct {
	Type       string    `json:"type"`
	SecretName string    `json:"secret_name,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	Version    int64     `json:"version,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
}

// Publisher is the write side: the admin servers publish, the Hub delivers.
type Publisher interface {
	Publish(ctx context.Context, tenantID, principal string, ev Event) error
}

// RedisPublishClient is the slice of go-redis the publisher needs.
type RedisPublishClient interface {
	Publish(ctx context.Context, channel string, message any) *redis.IntCmd
}

// Channel names the pub/sub channel for one (tenant, principal). Both parts
// are escaped so a principal containing ':' cannot cross into another key.
func Channel(tenantID, principal string) string {
	return channelPrefix + escape(tenantID) + ":" + escape(principal)
}

func escape(s string) string {
	return strings.NewReplacer("%", "%25", ":", "%3A").Replace(s)
}

func unescape(s string) string {
	return strings.NewReplacer("%3A", ":", "%25", "%").Replace(s)
}

// ParseChannel is the inverse of Channel.
func ParseChannel(ch string) (tenantID, principal string, ok bool) {
	rest, found := strings.CutPrefix(ch, channelPrefix)
	if !found {
		return "", "", false
	}
	t, p, found := strings.Cut(rest, ":")
	if !found || t == "" || p == "" {
		return "", "", false
	}
	return unescape(t), unescape(p), true
}

type redisPublisher struct {
	rdb RedisPublishClient
}

// NewPublisher returns a Publisher over Redis pub/sub.
func NewPublisher(rdb RedisPublishClient) Publisher {
	return &redisPublisher{rdb: rdb}
}

// Publish sends one event. An error is returned, never swallowed: a
// revocation that did not reach the wire is a security event the caller
// logs, and the audit line it writes beside it says the revocation landed.
func (p *redisPublisher) Publish(ctx context.Context, tenantID, principal string, ev Event) error {
	if tenantID == "" || principal == "" {
		return errors.New("componentevents: tenant and principal are required")
	}
	if ev.Type == "" {
		return errors.New("componentevents: event type is required")
	}
	if ev.OccurredAt.IsZero() {
		ev.OccurredAt = time.Now().UTC()
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("componentevents: encode: %w", err)
	}
	if _, err := p.rdb.Publish(ctx, Channel(tenantID, principal), payload).Result(); err != nil {
		return fmt.Errorf("componentevents: publish %s: %w", ev.Type, err)
	}
	return nil
}

// Hub multiplexes one Redis psubscribe across every stream a daemon replica
// serves. It mirrors manifest.WatchHub: one reader goroutine, per-key
// subscriber channels, oldest-dropped on a full buffer.
type Hub struct {
	rdb               redis.UniversalClient
	log               *slog.Logger
	heartbeatInterval time.Duration
	perClientBuffer   int

	mu      sync.Mutex
	subs    map[string]map[chan Event]struct{}
	started bool
	stopCh  chan struct{}
}

// NewHub constructs a Hub. Start must run before Subscribe delivers.
func NewHub(rdb redis.UniversalClient, log *slog.Logger, heartbeatInterval time.Duration, perClientBuffer int) *Hub {
	if log == nil {
		log = slog.Default()
	}
	if heartbeatInterval <= 0 {
		heartbeatInterval = 30 * time.Second
	}
	if perClientBuffer <= 0 {
		perClientBuffer = 16
	}
	return &Hub{
		rdb:               rdb,
		log:               log,
		heartbeatInterval: heartbeatInterval,
		perClientBuffer:   perClientBuffer,
		subs:              make(map[string]map[chan Event]struct{}),
		stopCh:            make(chan struct{}),
	}
}

// HeartbeatInterval is the cadence a stream handler sends heartbeats at.
func (h *Hub) HeartbeatInterval() time.Duration { return h.heartbeatInterval }

// Start opens the shared psubscribe. Repeated calls are no-ops.
func (h *Hub) Start(ctx context.Context) {
	h.mu.Lock()
	if h.started {
		h.mu.Unlock()
		return
	}
	h.started = true
	h.mu.Unlock()
	go h.run(ctx)
}

// Stop ends the reader goroutine. Safe to call more than once.
func (h *Hub) Stop() {
	h.mu.Lock()
	defer h.mu.Unlock()
	select {
	case <-h.stopCh:
	default:
		close(h.stopCh)
	}
}

func key(tenantID, principal string) string { return tenantID + "\x00" + principal }

// Subscribe registers a stream for one (tenant, principal) and returns the
// channel plus the cleanup the handler defers.
func (h *Hub) Subscribe(tenantID, principal string) (<-chan Event, func()) {
	ch := make(chan Event, h.perClientBuffer)
	k := key(tenantID, principal)
	h.mu.Lock()
	set, ok := h.subs[k]
	if !ok {
		set = map[chan Event]struct{}{}
		h.subs[k] = set
	}
	set[ch] = struct{}{}
	h.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			h.mu.Lock()
			defer h.mu.Unlock()
			if set, ok := h.subs[k]; ok {
				delete(set, ch)
				if len(set) == 0 {
					delete(h.subs, k)
				}
			}
			close(ch)
		})
	}
}

func (h *Hub) run(parentCtx context.Context) {
	backoff := 500 * time.Millisecond
	for {
		select {
		case <-h.stopCh:
			return
		case <-parentCtx.Done():
			return
		default:
		}
		pub := h.rdb.PSubscribe(parentCtx, channelPrefix+"*")
		ch := pub.Channel()
		h.log.Info("component events: hub subscribed", "pattern", channelPrefix+"*")
	readLoop:
		for {
			select {
			case <-h.stopCh:
				_ = pub.Close()
				return
			case <-parentCtx.Done():
				_ = pub.Close()
				return
			case msg, ok := <-ch:
				if !ok {
					break readLoop
				}
				h.dispatch(msg.Channel, msg.Payload)
			}
		}
		_ = pub.Close()
		select {
		case <-h.stopCh:
			return
		case <-parentCtx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 5*time.Second {
			backoff *= 2
		}
	}
}

// dispatch decodes one message and hands it to every stream on its key.
// A slow stream drops its oldest event: the SDK marks a secret revoked on
// the first revocation it sees and refuses to start without the stream, so
// a dropped duplicate costs nothing and a stuck stream must not stall the
// hub.
func (h *Hub) dispatch(channel, payload string) {
	tenantID, principal, ok := ParseChannel(channel)
	if !ok {
		return
	}
	var ev Event
	if err := json.Unmarshal([]byte(payload), &ev); err != nil {
		h.log.Warn("component events: undecodable payload dropped", "channel", channel, "error", err)
		return
	}
	h.mu.Lock()
	set := h.subs[key(tenantID, principal)]
	targets := make([]chan Event, 0, len(set))
	for c := range set {
		targets = append(targets, c)
	}
	h.mu.Unlock()
	for _, c := range targets {
		select {
		case c <- ev:
		default:
			select {
			case <-c:
			default:
			}
			select {
			case c <- ev:
			default:
			}
		}
	}
}
