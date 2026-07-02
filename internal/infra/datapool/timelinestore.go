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
//
// acquire is called once per Timeline operation and must return the per-tenant
// *redis.Client plus a release function that returns the connection to the
// pool. This per-op acquire pattern prevents the "client is closed" error that
// occurs when a long-lived *redis.Client is closed by the idle evictor between
// operations (gibson#1114, ADR-0011).
type RedisTimelineStore struct {
	acquire func(ctx context.Context) (*redis.Client, func(), error)
}

// NewRedisTimelineStore creates a RedisTimelineStore backed by acquire.
// acquire must return a *redis.Client bound to the tenant's dedicated Redis DB
// (never db 0) and a release function that returns the connection to the pool.
// acquire is called once per Timeline operation so the evictor can never hand
// back a closed client.
func NewRedisTimelineStore(acquire func(ctx context.Context) (*redis.Client, func(), error)) *RedisTimelineStore {
	return &RedisTimelineStore{acquire: acquire}
}

func (s *RedisTimelineStore) streamKey(tenant string) string {
	return "gibson:timeline:" + tenant
}

// redisConfigGetter is the minimal Redis command surface the AOF boot guard
// needs. *redis.Client satisfies it; tests substitute a stub so the
// appendonly=no path is exercisable without a real redis-stack (miniredis
// does not implement CONFIG).
type redisConfigGetter interface {
	ConfigGet(ctx context.Context, parameter string) *redis.MapStringStringCmd
}

// assertAOFEnabled verifies that the Redis server behind client has
// append-only-file persistence enabled (CONFIG GET appendonly == "yes").
//
// The durable Timeline (ADR-0011, PRD gibson#1112) is only durable if the
// backing Redis persists its log: with AOF off, a Redis restart silently
// discards every Timeline event while the store keeps LOOKING durable. Any
// failure to positively confirm appendonly=yes — including a CONFIG GET
// error (e.g. a managed Redis that disables the CONFIG command) — is
// returned as an error so the caller fails closed rather than degrade
// silently (gibson#1119).
func assertAOFEnabled(ctx context.Context, client redisConfigGetter) error {
	vals, err := client.ConfigGet(ctx, "appendonly").Result()
	if err != nil {
		return fmt.Errorf("datapool/redis-timeline: CONFIG GET appendonly failed — cannot verify AOF persistence for the durable Timeline (ADR-0011): %w", err)
	}
	val, ok := vals["appendonly"]
	if !ok {
		return fmt.Errorf("datapool/redis-timeline: CONFIG GET appendonly returned no value — cannot verify AOF persistence for the durable Timeline (ADR-0011)")
	}
	if val != "yes" {
		return fmt.Errorf("datapool/redis-timeline: Redis AOF persistence is disabled (appendonly=%q, want \"yes\") — the durable Timeline (ADR-0011, gibson#1112) would silently lose all events on a Redis restart; enable AOF on the data-plane Redis (deploy#1063 sets appendonly=yes on the redis-stack chart) instead of running with a Timeline that only looks durable", val)
	}
	return nil
}

// AssertTimelineAOF dials the data-plane Redis server at addr and verifies
// that AOF persistence is enabled (CONFIG GET appendonly == "yes"). AOF is a
// server-level setting, so one boot-time check against DB 0 covers every
// per-tenant logical DB on that server.
//
// The daemon calls this once at startup, before wiring the Timeline store
// factory, and refuses to start on error (gibson#1119).
func AssertTimelineAOF(ctx context.Context, addr, password string) error {
	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     password,
		DB:           redisDB0,
		DialTimeout:  redisProductionOpts.DialTimeout,
		ReadTimeout:  redisProductionOpts.ReadTimeout,
		WriteTimeout: redisProductionOpts.WriteTimeout,
	})
	defer func() { _ = client.Close() }()
	return assertAOFEnabled(ctx, client)
}

// Append durably persists ev to the tenant's Redis Stream. MaxLen 0 means no
// cap — the stream grows unbounded until TrimTo prunes it (ADR-0011).
func (s *RedisTimelineStore) Append(ctx context.Context, tenant string, ev brain.Event) (string, error) {
	client, release, err := s.acquire(ctx)
	if err != nil {
		return "", fmt.Errorf("datapool/redis-timeline: acquire conn for XADD tenant %q: %w", tenant, err)
	}
	defer release()

	encoded, err := brain.EncodeEvent(ev)
	if err != nil {
		return "", fmt.Errorf("datapool/redis-timeline: encode event kind %q: %w", ev.Kind(), err)
	}
	seq, err := client.XAdd(ctx, &redis.XAddArgs{
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
	client, release, err := s.acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("datapool/redis-timeline: acquire conn for XRANGE tenant %q: %w", tenant, err)
	}
	defer release()

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
		msgs, err := client.XRangeN(ctx, key, cursor, "+", replayBatchSize).Result()
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
	client, release, err := s.acquire(ctx)
	if err != nil {
		return "", fmt.Errorf("datapool/redis-timeline: acquire conn for SET snapshot tenant %q: %w", tenant, err)
	}
	defer release()

	key := "gibson:snapshot:" + tenant
	data, err := json.Marshal(snap)
	if err != nil {
		return "", fmt.Errorf("datapool/redis-timeline: marshal snapshot for tenant %q: %w", tenant, err)
	}
	if err := client.Set(ctx, key, data, 0).Err(); err != nil {
		return "", fmt.Errorf("datapool/redis-timeline: SET snapshot for tenant %q: %w", tenant, err)
	}
	return snap.AtSeq, nil
}

// LoadSnapshot loads the snapshot for tenant. Returns (nil, nil) if none exists.
func (s *RedisTimelineStore) LoadSnapshot(ctx context.Context, tenant string) (*brain.WorldSnapshot, error) {
	client, release, err := s.acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("datapool/redis-timeline: acquire conn for GET snapshot tenant %q: %w", tenant, err)
	}
	defer release()

	key := "gibson:snapshot:" + tenant
	data, err := client.Get(ctx, key).Bytes()
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
	client, release, err := s.acquire(ctx)
	if err != nil {
		return fmt.Errorf("datapool/redis-timeline: acquire conn for XTRIM tenant %q: %w", tenant, err)
	}
	defer release()

	key := s.streamKey(tenant)
	minid := streamIDNext(handle)
	if err := client.XTrimMinID(ctx, key, minid).Err(); err != nil {
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
