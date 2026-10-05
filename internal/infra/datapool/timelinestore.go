// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package datapool

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	redis "github.com/redis/go-redis/v9"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	dpmetrics "github.com/zeroroot-ai/gibson/internal/infra/datapool/metrics"
)

// TimelineStore implements brain.TimelineStore (ADR-0163).
//
// The live tail of the Timeline is a Redis Stream (XADD/XRANGE), with the
// per-tenant key "gibson:timeline:<tenantID>". XADD sets no length cap.
//
// The full history is in the Postgres database of the tenant, in the table
// timeline_events (migration 013). TrimTo copies each stream entry that it
// removes into that table first. When the copy fails, TrimTo removes nothing,
// so no event exists in neither place (gibson#786). LoadHistory reads the
// table and then the stream tail.
//
// This type lives in internal/infra/datapool (not internal/engine/brain) so
// that raw store client imports stay confined to the data-plane allowlist
// (docs/data-plane.md, gibson#1145) — the brain package depends only on the
// brain.TimelineStore interface, no Redis types leak into internal/engine/brain.
//
// acquire is called once per Timeline operation and must return the tenant's
// handles plus a release function that returns the connection to the pool.
// This per-op acquire pattern prevents the "client is closed" error that
// occurs when a long-lived *redis.Client is closed by the idle evictor between
// operations (gibson#1114, ADR-0163).
type TimelineStore struct {
	acquire func(ctx context.Context) (TimelineConn, func(), error)
}

// TimelineConn is what one Timeline operation needs from the tenant Conn.
type TimelineConn struct {
	// Redis is the client bound to the tenant's dedicated Redis DB (never
	// db 0). It holds the live tail.
	Redis *redis.Client
	// SQL is the Postgres database of the tenant. It holds the full history.
	SQL SQL
}

// NewTimelineStore creates a TimelineStore backed by acquire. acquire is
// called once per Timeline operation so the evictor can never hand back a
// closed client.
func NewTimelineStore(acquire func(ctx context.Context) (TimelineConn, func(), error)) *TimelineStore {
	return &TimelineStore{acquire: acquire}
}

func (s *TimelineStore) streamKey(tenant string) string {
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
// The durable Timeline (ADR-0163, PRD gibson#1112) is only durable if the
// backing Redis persists its log: with AOF off, a Redis restart silently
// discards every Timeline event while the store keeps LOOKING durable. Any
// failure to positively confirm appendonly=yes — including a CONFIG GET
// error (e.g. a managed Redis that disables the CONFIG command) — is
// returned as an error so the caller fails closed rather than degrade
// silently (gibson#1119).
func assertAOFEnabled(ctx context.Context, client redisConfigGetter) error {
	vals, err := client.ConfigGet(ctx, "appendonly").Result()
	if err != nil {
		return fmt.Errorf("datapool/redis-timeline: CONFIG GET appendonly failed — cannot verify AOF persistence for the durable Timeline (ADR-0163): %w", err)
	}
	val, ok := vals["appendonly"]
	if !ok {
		return errors.New("datapool/redis-timeline: CONFIG GET appendonly returned no value — cannot verify AOF persistence for the durable Timeline (ADR-0163)")
	}
	if val != "yes" {
		return fmt.Errorf("datapool/redis-timeline: Redis AOF persistence is disabled (appendonly=%q, want \"yes\") — the durable Timeline (ADR-0163, gibson#1112) would silently lose all events on a Redis restart; enable AOF on the data-plane Redis (deploy#1063 sets appendonly=yes on the redis-stack chart) instead of running with a Timeline that only looks durable", val)
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

// appendOnceScript appends one event unless the idempotency key equals the key
// of the most recent append. In that case it writes nothing and returns the id
// of that append. The check and the write are one atomic step.
//
// KEYS[1] is the stream. KEYS[2] is the hash that holds the last key and id.
// ARGV[1] is the encoded event. ARGV[2] is the idempotency key.
var appendOnceScript = redis.NewScript(`
local last = redis.call('HMGET', KEYS[2], 'key', 'seq')
if last[1] == ARGV[2] then
  return last[2]
end
local id = redis.call('XADD', KEYS[1], '*', 'ev', ARGV[1])
redis.call('HSET', KEYS[2], 'key', ARGV[2], 'seq', id)
return id
`)

func (s *TimelineStore) lastAppendKey(tenant string) string {
	return "gibson:timeline-last-append:" + tenant
}

// Append durably persists ev to the tenant's Redis Stream. The stream has no
// length cap: it grows until TrimTo prunes it (ADR-0163).
//
// key is the idempotency key. A second Append with the key of the most recent
// append writes nothing and returns the seq of that append, so a retry after a
// lost reply does not write the event twice.
func (s *TimelineStore) Append(ctx context.Context, tenant, key string, ev brain.Event) (string, error) {
	if key == "" {
		return "", fmt.Errorf("datapool/redis-timeline: append for tenant %q kind %q has no idempotency key", tenant, ev.Kind())
	}
	conn, release, err := s.acquire(ctx)
	if err != nil {
		return "", fmt.Errorf("datapool/redis-timeline: acquire conn for XADD tenant %q: %w", tenant, err)
	}
	defer release()

	encoded, err := brain.EncodeEvent(ev)
	if err != nil {
		return "", fmt.Errorf("datapool/redis-timeline: encode event kind %q: %w", ev.Kind(), err)
	}
	seq, err := appendOnceScript.Run(ctx, conn.Redis,
		[]string{s.streamKey(tenant), s.lastAppendKey(tenant)},
		string(encoded), key,
	).Text()
	if err != nil {
		return "", fmt.Errorf("datapool/redis-timeline: XADD for tenant %q kind %q: %w", tenant, ev.Kind(), err)
	}
	return seq, nil
}

// replayBatchSize is the number of stream entries fetched per XRANGE call.
const replayBatchSize = 1000

// LoadForReplay returns all events after afterSeq (exclusive). Pass "" to
// load from the beginning. Events are returned in Timeline order.
func (s *TimelineStore) LoadForReplay(ctx context.Context, tenant, afterSeq string) ([]brain.Event, error) {
	conn, release, err := s.acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("datapool/redis-timeline: acquire conn for XRANGE tenant %q: %w", tenant, err)
	}
	defer release()

	start := "-"
	if afterSeq != "" {
		// XRANGE start is inclusive; to start *after* afterSeq we use the
		// exclusive form "(afterSeq" (requires Redis 6.2+, which is standard).
		// Miniredis supports this syntax as well.
		start = "(" + afterSeq
	}
	out, err := streamEvents(ctx, conn.Redis, s.streamKey(tenant), start)
	if err != nil {
		return nil, fmt.Errorf("datapool/redis-timeline: replay for tenant %q: %w", tenant, err)
	}
	return out, nil
}

// WriteSnapshot persists a JSON-serialized brain.WorldSnapshot to Redis.
// Key: "gibson:snapshot:<tenant>"
// Returns snap.AtSeq as the handle.
func (s *TimelineStore) WriteSnapshot(ctx context.Context, tenant string, snap brain.WorldSnapshot) (string, error) {
	conn, release, err := s.acquire(ctx)
	if err != nil {
		return "", fmt.Errorf("datapool/redis-timeline: acquire conn for SET snapshot tenant %q: %w", tenant, err)
	}
	defer release()

	key := "gibson:snapshot:" + tenant
	data, err := json.Marshal(snap)
	if err != nil {
		return "", fmt.Errorf("datapool/redis-timeline: marshal snapshot for tenant %q: %w", tenant, err)
	}
	if err := conn.Redis.Set(ctx, key, data, 0).Err(); err != nil {
		return "", fmt.Errorf("datapool/redis-timeline: SET snapshot for tenant %q: %w", tenant, err)
	}
	return snap.AtSeq, nil
}

// LoadSnapshot loads the snapshot for tenant. Returns (nil, nil) if none exists.
func (s *TimelineStore) LoadSnapshot(ctx context.Context, tenant string) (*brain.WorldSnapshot, error) {
	conn, release, err := s.acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("datapool/redis-timeline: acquire conn for GET snapshot tenant %q: %w", tenant, err)
	}
	defer release()

	key := "gibson:snapshot:" + tenant
	data, err := conn.Redis.Get(ctx, key).Bytes()
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

// insertHistorySQL copies one batch of stream entries into timeline_events.
// The four arrays hold one value for each entry. A row that is there already
// stays as it is, so a second copy of the same entries writes nothing.
const insertHistorySQL = `
INSERT INTO timeline_events (stream_ms, stream_seq, kind, event)
SELECT t.ms, t.seq, t.kind, t.ev::jsonb
FROM unnest($1::bigint[], $2::bigint[], $3::text[], $4::text[]) AS t(ms, seq, kind, ev)
ON CONFLICT (stream_ms, stream_seq) DO NOTHING`

// selectHistorySQL reads one page of the history after a stream id, in order.
const selectHistorySQL = `
SELECT stream_ms, stream_seq, event::text
FROM timeline_events
WHERE (stream_ms, stream_seq) > ($1, $2)
ORDER BY stream_ms, stream_seq
LIMIT $3`

// TrimTo removes the stream entries up to and including handle. Before it
// removes them, it copies each one into the Postgres history of the tenant
// (ADR-0163: the Timeline is the full history). When the copy fails, TrimTo
// counts the error, removes nothing and returns the error. The entries then
// stay in the stream, and the next snapshot tries again.
//
// XTrimMinID keeps entries with ID >= minid, so the trim uses handle+1 to
// exclude the snapshot entry itself — tail replay begins with the event after
// the snapshot.
func (s *TimelineStore) TrimTo(ctx context.Context, tenant, handle string) error {
	conn, release, err := s.acquire(ctx)
	if err != nil {
		return fmt.Errorf("datapool/redis-timeline: acquire conn for XTRIM tenant %q: %w", tenant, err)
	}
	defer release()

	key := s.streamKey(tenant)
	if err := s.archive(ctx, conn, key, handle); err != nil {
		dpmetrics.IncTimelineArchiveError(tenant)
		return fmt.Errorf("datapool/redis-timeline: tenant %q: the history write failed, so the stream is not trimmed: %w", tenant, err)
	}

	minid := streamIDNext(handle)
	if err := conn.Redis.XTrimMinID(ctx, key, minid).Err(); err != nil {
		return fmt.Errorf("datapool/redis-timeline: XTRIM MINID tenant %q handle %q: %w", tenant, handle, err)
	}
	return nil
}

// archive copies each stream entry up to and including handle into the
// Postgres history, one batch for each statement.
func (s *TimelineStore) archive(ctx context.Context, conn TimelineConn, key, handle string) error {
	if conn.SQL == nil {
		return errors.New("the tenant has no Postgres handle for the Timeline history")
	}
	cursor := "-"
	for {
		msgs, err := conn.Redis.XRangeN(ctx, key, cursor, handle, replayBatchSize).Result()
		if err != nil {
			return fmt.Errorf("XRANGE up to %q: %w", handle, err)
		}
		if len(msgs) == 0 {
			return nil
		}
		ms := make([]int64, 0, len(msgs))
		seq := make([]int64, 0, len(msgs))
		kinds := make([]string, 0, len(msgs))
		events := make([]string, 0, len(msgs))
		for _, msg := range msgs {
			entryMs, entrySeq, err := parseStreamID(msg.ID)
			if err != nil {
				return err
			}
			raw, err := streamEvent(msg)
			if err != nil {
				return err
			}
			var envelope struct {
				Kind string `json:"kind"`
			}
			if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
				return fmt.Errorf("stream entry %q is not an event envelope: %w", msg.ID, err)
			}
			if envelope.Kind == "" {
				return fmt.Errorf("stream entry %q holds no event kind", msg.ID)
			}
			ms = append(ms, entryMs)
			seq = append(seq, entrySeq)
			kinds = append(kinds, envelope.Kind)
			events = append(events, raw)
		}
		if _, err := conn.SQL.Exec(ctx, insertHistorySQL, ms, seq, kinds, events); err != nil {
			return fmt.Errorf("insert %d events into timeline_events: %w", len(msgs), err)
		}
		if len(msgs) < replayBatchSize {
			return nil
		}
		cursor = "(" + msgs[len(msgs)-1].ID
	}
}

// LoadHistory returns the full ordered history of the tenant: each event in
// the Postgres history, then each stream entry after the last of them. A
// stream entry that is also in Postgres (the copy ran and the trim did not)
// is returned one time.
func (s *TimelineStore) LoadHistory(ctx context.Context, tenant string) ([]brain.Event, error) {
	conn, release, err := s.acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("datapool/redis-timeline: acquire conn for the history of tenant %q: %w", tenant, err)
	}
	defer release()
	if conn.SQL == nil {
		return nil, fmt.Errorf("datapool/redis-timeline: tenant %q has no Postgres handle for the Timeline history", tenant)
	}

	var out []brain.Event
	// -1 is before each stream id: Redis assigns no negative part.
	lastMs, lastSeq := int64(-1), int64(-1)
	for {
		page, err := historyPage(ctx, conn.SQL, lastMs, lastSeq)
		if err != nil {
			return nil, fmt.Errorf("datapool/redis-timeline: read the history of tenant %q: %w", tenant, err)
		}
		for _, row := range page {
			out = append(out, row.event)
			lastMs, lastSeq = row.ms, row.seq
		}
		if len(page) < replayBatchSize {
			break
		}
	}

	start := "-"
	if lastMs >= 0 {
		start = "(" + strconv.FormatInt(lastMs, 10) + "-" + strconv.FormatInt(lastSeq, 10)
	}
	tail, err := streamEvents(ctx, conn.Redis, s.streamKey(tenant), start)
	if err != nil {
		return nil, fmt.Errorf("datapool/redis-timeline: read the stream tail of tenant %q: %w", tenant, err)
	}
	return append(out, tail...), nil
}

// historyRow is one decoded row of timeline_events.
type historyRow struct {
	ms, seq int64
	event   brain.Event
}

// historyPage reads the rows after the stream id (afterMs, afterSeq), at most
// replayBatchSize of them, in order.
func historyPage(ctx context.Context, db SQL, afterMs, afterSeq int64) ([]historyRow, error) {
	rows, err := db.Query(ctx, selectHistorySQL, afterMs, afterSeq, replayBatchSize)
	if err != nil {
		return nil, fmt.Errorf("select from timeline_events: %w", err)
	}
	defer rows.Close()

	var page []historyRow
	for rows.Next() {
		var row historyRow
		var raw string
		if err := rows.Scan(&row.ms, &row.seq, &raw); err != nil {
			return nil, fmt.Errorf("scan a timeline_events row: %w", err)
		}
		ev, err := brain.DecodeEvent([]byte(raw))
		if err != nil {
			return nil, fmt.Errorf("decode the event %d-%d: %w", row.ms, row.seq, err)
		}
		row.event = ev
		page = append(page, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read timeline_events: %w", err)
	}
	return page, nil
}

// streamEvent returns the encoded event of one stream entry.
func streamEvent(msg redis.XMessage) (string, error) {
	raw, ok := msg.Values["ev"]
	if !ok {
		return "", fmt.Errorf("datapool/redis-timeline: stream entry %q missing 'ev' field", msg.ID)
	}
	rawStr, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("datapool/redis-timeline: stream entry %q 'ev' is not a string", msg.ID)
	}
	return rawStr, nil
}

// streamEvents reads and decodes each stream entry from start to the end of
// the stream, in batches. start is an XRANGE start: "-" or "(<id>".
func streamEvents(ctx context.Context, client *redis.Client, key, start string) ([]brain.Event, error) {
	var out []brain.Event
	cursor := start
	for {
		msgs, err := client.XRangeN(ctx, key, cursor, "+", replayBatchSize).Result()
		if err != nil {
			return nil, fmt.Errorf("XRANGE: %w", err)
		}
		for _, msg := range msgs {
			raw, err := streamEvent(msg)
			if err != nil {
				return nil, err
			}
			ev, err := brain.DecodeEvent([]byte(raw))
			if err != nil {
				return nil, fmt.Errorf("datapool/redis-timeline: decode entry %q: %w", msg.ID, err)
			}
			out = append(out, ev)
		}
		if len(msgs) < replayBatchSize {
			return out, nil
		}
		// Advance cursor past the last received ID for the next page.
		cursor = "(" + msgs[len(msgs)-1].ID
	}
}

// parseStreamID splits a Redis stream id "<ms>-<seq>" into its two parts.
func parseStreamID(id string) (ms, seq int64, err error) {
	left, right, ok := strings.Cut(id, "-")
	if !ok {
		return 0, 0, fmt.Errorf("datapool/redis-timeline: stream id %q has no sequence part", id)
	}
	ms, err = strconv.ParseInt(left, 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("datapool/redis-timeline: stream id %q: %w", id, err)
	}
	seq, err = strconv.ParseInt(right, 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("datapool/redis-timeline: stream id %q: %w", id, err)
	}
	return ms, seq, nil
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
