//go:build !embedder_tests

package datapool

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	redis "github.com/redis/go-redis/v9"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// RedisTimelineStore implements brain.TimelineStore using Redis Streams
// (XADD/XRANGE).
// Per-tenant stream key: "gibson:timeline:<tenantID>"
// No blind MAXLEN trim is applied on XADD (ADR-0011 decision 3b).
//
// This type lives in internal/infra/datapool (not internal/engine/brain) so
// that raw store client imports stay confined to the data-plane allowlist
// (docs/data-plane.md, gibson#1145) — the brain package depends only on the
// brain.TimelineStore interface, no Redis types leak into internal/engine/brain.
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
func (s *RedisTimelineStore) Append(ctx context.Context, tenant string, ev brain.Event) (string, error) {
	encoded, err := brain.EncodeEvent(ev)
	if err != nil {
		return "", fmt.Errorf("datapool/redis-timeline: encode event kind %q: %w", ev.Kind(), err)
	}
	seq, err := s.client.XAdd(ctx, &redis.XAddArgs{
		Stream: s.streamKey(tenant),
		MaxLen: 0, // no cap — ADR-0011 no blind trim
		ID:     "*",
		Values: map[string]any{"ev": string(encoded)},
	}).Result()
	if err != nil {
		return "", fmt.Errorf("datapool/redis-timeline: XADD for tenant %q kind %q: %w", tenant, ev.Kind(), err)
	}
	return seq, nil
}

// replayBatchSize is the number of stream entries fetched per XRANGE call.
const replayBatchSize = 1000

// LoadForReplay returns all events after afterSeq (exclusive). Pass "" to
// load from the beginning. Events are returned in Timeline order.
func (s *RedisTimelineStore) LoadForReplay(ctx context.Context, tenant string, afterSeq string) ([]brain.Event, error) {
	key := s.streamKey(tenant)
	start := "-"
	if afterSeq != "" {
		// XRANGE start is inclusive; to start *after* afterSeq we use the
		// exclusive form "(afterSeq" (requires Redis 6.2+, which is standard).
		// Miniredis supports this syntax as well.
		start = "(" + afterSeq
	}

	var out []brain.Event
	cursor := start
	for {
		msgs, err := s.client.XRangeN(ctx, key, cursor, "+", replayBatchSize).Result()
		if err != nil {
			return nil, fmt.Errorf("datapool/redis-timeline: XRANGE for tenant %q: %w", tenant, err)
		}
		for _, msg := range msgs {
			raw, ok := msg.Values["ev"]
			if !ok {
				return nil, fmt.Errorf("datapool/redis-timeline: stream entry %q missing 'ev' field", msg.ID)
			}
			rawStr, ok := raw.(string)
			if !ok {
				return nil, fmt.Errorf("datapool/redis-timeline: stream entry %q 'ev' is not a string", msg.ID)
			}
			ev, err := brain.DecodeEvent([]byte(rawStr))
			if err != nil {
				return nil, fmt.Errorf("datapool/redis-timeline: decode entry %q: %w", msg.ID, err)
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

// WriteSnapshot persists a JSON-serialized brain.WorldSnapshot to Redis.
// Key: "gibson:snapshot:<tenant>"
// Returns snap.AtSeq as the handle.
func (s *RedisTimelineStore) WriteSnapshot(ctx context.Context, tenant string, snap brain.WorldSnapshot) (string, error) {
	key := "gibson:snapshot:" + tenant
	data, err := json.Marshal(snap)
	if err != nil {
		return "", fmt.Errorf("datapool/redis-timeline: marshal snapshot for tenant %q: %w", tenant, err)
	}
	if err := s.client.Set(ctx, key, data, 0).Err(); err != nil {
		return "", fmt.Errorf("datapool/redis-timeline: SET snapshot for tenant %q: %w", tenant, err)
	}
	return snap.AtSeq, nil
}

// LoadSnapshot loads the snapshot for tenant. Returns (nil, nil) if none exists.
func (s *RedisTimelineStore) LoadSnapshot(ctx context.Context, tenant string) (*brain.WorldSnapshot, error) {
	key := "gibson:snapshot:" + tenant
	data, err := s.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, fmt.Errorf("datapool/redis-timeline: GET snapshot for tenant %q: %w", tenant, err)
	}
	var snap brain.WorldSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("datapool/redis-timeline: unmarshal snapshot for tenant %q: %w", tenant, err)
	}
	return &snap, nil
}

// TrimTo removes stream entries up to and including handle using XTRIM MINID.
// XTrimMinID keeps entries with ID >= minid, so we compute handle+1 to exclude
// the snapshot entry itself — tail replay begins with the event after the snapshot.
func (s *RedisTimelineStore) TrimTo(ctx context.Context, tenant, handle string) error {
	key := s.streamKey(tenant)
	minid := streamIDNext(handle)
	if err := s.client.XTrimMinID(ctx, key, minid).Err(); err != nil {
		return fmt.Errorf("datapool/redis-timeline: XTRIM MINID tenant %q handle %q: %w", tenant, handle, err)
	}
	return nil
}

// streamIDNext returns the smallest Redis stream ID greater than id.
// Redis stream IDs have the form "<ms>-<seq>". We increment the seq component;
// if the seq component is missing we treat it as 0 and return "<ms>-1".
func streamIDNext(id string) string {
	parts := strings.SplitN(id, "-", 2)
	if len(parts) != 2 {
		// No sequence component; return ms-1 which is > ms-0 (the implicit default).
		return id + "-1"
	}
	ms := parts[0]
	seq, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		// Malformed seq — fall back to a suffix that sorts after any normal seq.
		return id + "z"
	}
	return ms + "-" + strconv.FormatUint(seq+1, 10)
}
