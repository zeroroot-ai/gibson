package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/zero-day-ai/gibson/internal/auth"
	"github.com/zero-day-ai/gibson/internal/daemon/api"
	"github.com/zero-day-ai/gibson/internal/state"
)

const (
	// eventsStreamSuffix is appended to the tenant scope to form the stream key.
	// Full key: tenant:{tenantID}:events:stream
	eventsStreamSuffix = "events:stream"

	// xreadBlockTimeout is the duration passed to XREAD BLOCK.
	// After this period with no new entries, XREAD returns an empty result
	// (not an error) and the subscriber loop re-checks its context.
	xreadBlockTimeout = 5 * time.Second

	// maxEventStreamLen caps each tenant's event stream at approximately this
	// many entries. Redis trims with the ~ (approximate) flag for efficiency.
	maxEventStreamLen int64 = 10_000
)

// Stream entry field names stored in each Redis Stream message.
const (
	sfEventType = "event_type"
	sfTimestamp = "timestamp_ms"
	sfSource    = "source"
	sfPayload   = "payload"
	sfMissionID = "mission_id"
)

// RedisEventStream bridges the daemon EventBus to a per-tenant Redis Stream.
//
// Events are published via XADD to a key of the form:
//
//	tenant:{tenantID}:events:stream
//
// Subscribers use XREAD BLOCK in a loop, decoding each entry back into
// api.EventData and applying optional event-type and mission-ID filters
// before sending to the output channel.
//
// The stream is trimmed to maxEventStreamLen entries on every publish to
// prevent unbounded growth.
type RedisEventStream struct {
	stateClient *state.StateClient
	logger      *slog.Logger
}

// NewRedisEventStream creates a RedisEventStream backed by the given state
// client. The logger may be nil (defaults to slog.Default).
func NewRedisEventStream(sc *state.StateClient, logger *slog.Logger) *RedisEventStream {
	if logger == nil {
		logger = slog.Default()
	}
	return &RedisEventStream{
		stateClient: sc,
		logger:      logger.With("component", "redis_event_stream"),
	}
}

// TenantStreamKey returns the fully-qualified Redis Stream key for a tenant.
func (r *RedisEventStream) TenantStreamKey(tenant string) string {
	if tenant == "" {
		tenant = "default"
	}
	return auth.TenantScopedRedisKey(tenant, eventsStreamSuffix)
}

// PublishEvent appends event to the tenant's Redis Stream via XADD.
//
// The full event is stored as a JSON blob in the "payload" field so that
// subscribers can reconstruct it completely. Top-level scalar fields
// (event_type, timestamp_ms, source, mission_id) are also indexed as
// individual stream fields for potential future server-side filtering.
//
// The stream is trimmed to approximately maxEventStreamLen entries after each
// write using MAXLEN ~ to bound memory usage.
//
// Returns an error if stateClient is nil or the XADD command fails.
func (r *RedisEventStream) PublishEvent(ctx context.Context, tenant string, event api.EventData) error {
	if r.stateClient == nil {
		return fmt.Errorf("redis event stream: state client is nil")
	}

	if tenant == "" {
		tenant = "default"
	}

	streamKey := r.TenantStreamKey(tenant)

	payloadBytes, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("redis event stream: marshal event: %w", err)
	}

	missionID := extractMissionID(event)

	rc := r.stateClient.Client()
	_, err = rc.XAdd(ctx, &goredis.XAddArgs{
		Stream: streamKey,
		MaxLen: maxEventStreamLen,
		Approx: true,
		ID:     "*",
		Values: []any{
			sfEventType, event.EventType,
			sfTimestamp, event.Timestamp.UnixMilli(),
			sfSource, event.Source,
			sfMissionID, missionID,
			sfPayload, string(payloadBytes),
		},
	}).Result()
	if err != nil {
		return fmt.Errorf("redis event stream: XADD to %s: %w", streamKey, err)
	}

	r.logger.Debug("event published to redis stream",
		"stream", streamKey,
		"event_type", event.EventType,
		"tenant", tenant,
	)
	return nil
}

// SubscribeStream reads events from the tenant's Redis Stream using XREAD BLOCK.
//
// It starts reading from the current tail of the stream ("$") so only events
// published after the subscription starts are delivered. Filtering by event
// type and/or mission ID is applied client-side after deserialisation.
//
// The returned channel is closed when ctx is cancelled or an unrecoverable
// error occurs. The background goroutine exits cleanly; no goroutines are
// leaked after context cancellation.
//
// Parameters:
//   - ctx:        Subscription lifetime; cancel to unsubscribe.
//   - tenant:     Tenant ID for stream-key construction.
//   - eventTypes: Optional allow-list; empty slice means deliver all types.
//   - missionID:  Optional filter; empty string means deliver all missions.
//
// Returns an error only if the initial setup fails (e.g., nil stateClient).
func (r *RedisEventStream) SubscribeStream(
	ctx context.Context,
	tenant string,
	eventTypes []string,
	missionID string,
) (<-chan api.EventData, error) {
	if r.stateClient == nil {
		return nil, fmt.Errorf("redis event stream: state client is nil")
	}

	if tenant == "" {
		tenant = "default"
	}

	streamKey := r.TenantStreamKey(tenant)

	// Build O(1) lookup set for event-type filtering.
	typeFilter := make(map[string]bool, len(eventTypes))
	for _, et := range eventTypes {
		typeFilter[et] = true
	}

	out := make(chan api.EventData, 100)

	go func() {
		defer close(out)

		// "$" delivers only entries added after this subscription started.
		lastID := "$"

		for {
			// Check context before the blocking call.
			select {
			case <-ctx.Done():
				r.logger.Debug("redis stream subscriber: context cancelled before XREAD",
					"stream", streamKey)
				return
			default:
			}

			opts := &state.StreamReadOptions{
				LastID: lastID,
				Block:  xreadBlockTimeout,
				Count:  100,
			}

			entries, err := r.stateClient.StreamRead(ctx, []string{streamKey}, opts)
			if err != nil {
				// Exit cleanly on context cancellation.
				select {
				case <-ctx.Done():
					return
				default:
				}
				r.logger.Error("redis stream subscriber: XREAD error",
					"stream", streamKey, "error", err)
				// Brief delay to avoid tight retry loops on persistent errors.
				select {
				case <-ctx.Done():
					return
				case <-time.After(200 * time.Millisecond):
				}
				continue
			}

			streamEntries, ok := entries[streamKey]
			if !ok || len(streamEntries) == 0 {
				// XREAD timed out with no new entries; re-loop to re-check context.
				continue
			}

			for _, entry := range streamEntries {
				// Advance cursor past this entry for the next XREAD call.
				lastID = entry.ID

				event, err := decodeStreamEntry(entry)
				if err != nil {
					r.logger.Warn("redis stream subscriber: failed to decode entry",
						"id", entry.ID, "error", err)
					continue
				}

				// Apply event-type filter.
				if len(typeFilter) > 0 && !typeFilter[event.EventType] {
					continue
				}

				// Apply mission-ID filter.
				if missionID != "" {
					evtMission := extractMissionID(event)
					if evtMission != "" && evtMission != missionID {
						continue
					}
				}

				select {
				case out <- event:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	r.logger.Info("redis stream subscriber started",
		"stream", streamKey,
		"tenant", tenant,
		"event_types", eventTypes,
		"mission_id", missionID,
	)
	return out, nil
}

// decodeStreamEntry deserialises a Redis Stream entry into api.EventData.
//
// The full event is stored as JSON in the "payload" field. If the field is
// absent or malformed, a minimal EventData is reconstructed from the scalar
// fields (event_type, timestamp_ms, source).
func decodeStreamEntry(entry state.StreamEntry) (api.EventData, error) {
	// Prefer JSON payload for lossless reconstruction.
	if raw, ok := entry.Values[sfPayload]; ok {
		payloadStr := stringField(raw)
		if payloadStr != "" {
			var event api.EventData
			if err := json.Unmarshal([]byte(payloadStr), &event); err != nil {
				return api.EventData{}, fmt.Errorf("unmarshal stream payload: %w", err)
			}
			return event, nil
		}
	}

	// Fallback: reconstruct from scalar fields.
	event := api.EventData{
		EventType: stringField(entry.Values[sfEventType]),
		Source:    stringField(entry.Values[sfSource]),
		Timestamp: time.Now(),
	}
	if tsStr := stringField(entry.Values[sfTimestamp]); tsStr != "" {
		var tsMs int64
		if n, _ := fmt.Sscanf(tsStr, "%d", &tsMs); n == 1 {
			event.Timestamp = time.UnixMilli(tsMs)
		}
	}
	return event, nil
}

// stringField converts a Redis stream field value to a string.
func stringField(v any) string {
	if v == nil {
		return ""
	}
	switch s := v.(type) {
	case string:
		return s
	case []byte:
		return string(s)
	default:
		return fmt.Sprintf("%v", s)
	}
}
