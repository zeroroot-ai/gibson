//go:build !embedder_tests

package brain

import (
	"context"
	"fmt"

	redis "github.com/redis/go-redis/v9"
)

// RedisTimelineStore implements TimelineStore using Redis Streams (XADD/XRANGE).
// Per-tenant stream key: "gibson:timeline:<tenantID>"
// No blind MAXLEN trim is applied on XADD (ADR-0011 decision 3b).
type RedisTimelineStore struct {
	// client is the per-tenant Redis client. The caller (typically via
	// redisPerTenant.ForTenant) must hand a client already bound to the
	// correct tenant DB.
	client *redis.Client
}

// NewRedisTimelineStore creates a RedisTimelineStore backed by client.
// client must be bound to the tenant's dedicated Redis DB (never db 0).
func NewRedisTimelineStore(client *redis.Client) *RedisTimelineStore {
	return &RedisTimelineStore{client: client}
}

func (s *RedisTimelineStore) streamKey(tenant string) string {
	return "gibson:timeline:" + tenant
}

// Append durably persists ev to the tenant's Redis Stream. MaxLen 0 means no
// cap — the stream grows unbounded until TrimTo prunes it (ADR-0011).
func (s *RedisTimelineStore) Append(ctx context.Context, tenant string, ev Event) (string, error) {
	encoded, err := EncodeEvent(ev)
	if err != nil {
		return "", fmt.Errorf("brain/redis-timeline: encode event kind %q: %w", ev.Kind(), err)
	}
	seq, err := s.client.XAdd(ctx, &redis.XAddArgs{
		Stream: s.streamKey(tenant),
		MaxLen: 0, // no cap — ADR-0011 no blind trim
		ID:     "*",
		Values: map[string]any{"ev": string(encoded)},
	}).Result()
	if err != nil {
		return "", fmt.Errorf("brain/redis-timeline: XADD for tenant %q kind %q: %w", tenant, ev.Kind(), err)
	}
	return seq, nil
}

// replayBatchSize is the number of stream entries fetched per XRANGE call.
const replayBatchSize = 1000

// LoadForReplay returns all events after afterSeq (exclusive). Pass "" to
// load from the beginning. Events are returned in Timeline order.
func (s *RedisTimelineStore) LoadForReplay(ctx context.Context, tenant string, afterSeq string) ([]Event, error) {
	key := s.streamKey(tenant)
	start := "-"
	if afterSeq != "" {
		// XRANGE start is inclusive; to start *after* afterSeq we use the
		// exclusive form "(afterSeq" (requires Redis 6.2+, which is standard).
		// Miniredis supports this syntax as well.
		start = "(" + afterSeq
	}

	var out []Event
	cursor := start
	for {
		msgs, err := s.client.XRangeN(ctx, key, cursor, "+", replayBatchSize).Result()
		if err != nil {
			return nil, fmt.Errorf("brain/redis-timeline: XRANGE for tenant %q: %w", tenant, err)
		}
		for _, msg := range msgs {
			raw, ok := msg.Values["ev"]
			if !ok {
				return nil, fmt.Errorf("brain/redis-timeline: stream entry %q missing 'ev' field", msg.ID)
			}
			rawStr, ok := raw.(string)
			if !ok {
				return nil, fmt.Errorf("brain/redis-timeline: stream entry %q 'ev' is not a string", msg.ID)
			}
			ev, err := DecodeEvent([]byte(rawStr))
			if err != nil {
				return nil, fmt.Errorf("brain/redis-timeline: decode entry %q: %w", msg.ID, err)
			}
			out = append(out, ev)
		}
		if len(msgs) < replayBatchSize {
			break // last page
		}
		// Advance cursor past the last received ID for the next page.
		cursor = "(" + msgs[len(msgs)-1].ID
	}
	return out, nil
}

// WriteSnapshot is a stub; implemented in slice #1117.
func (s *RedisTimelineStore) WriteSnapshot(_ context.Context, _ string, _ WorldSnapshot) (string, error) {
	// TODO(#1117): implement snapshot persistence.
	return "", ErrNotImplemented
}

// LoadSnapshot is a stub; implemented in slice #1117.
func (s *RedisTimelineStore) LoadSnapshot(_ context.Context, _ string) (*WorldSnapshot, error) {
	// TODO(#1117): implement snapshot load.
	return nil, nil
}

// TrimTo is a stub; implemented in slice #1117.
func (s *RedisTimelineStore) TrimTo(_ context.Context, _ string, _ string) error {
	// TODO(#1117): implement snapshot-driven trim.
	return ErrNotImplemented
}
