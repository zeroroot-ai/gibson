package manifest

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	manifestpb "github.com/zeroroot-ai/sdk/api/gen/gibson/manifest/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// WatchHub multiplexes a single Redis psubscribe stream across many
// connected SDK clients. One goroutine reads Redis; per-tenant
// subscriber channels fan out to every client currently watching that
// tenant. Each client also receives a 30s heartbeat so a blocked
// pubsub (or long silent window) does not look like a disconnect.
type WatchHub struct {
	rdb               redis.UniversalClient
	log               *slog.Logger
	heartbeatInterval time.Duration
	perClientBuffer   int

	mu        sync.Mutex
	perTenant map[string]map[chan *manifestpb.ManifestInvalidationEvent]struct{}
	started   bool
	stopCh    chan struct{}
}

// NewWatchHub constructs a WatchHub. Caller must invoke Start before
// subscribers can receive events. heartbeatInterval <= 0 defaults to 30s.
// perClientBuffer <= 0 defaults to 16 (oldest-dropped when full).
func NewWatchHub(rdb redis.UniversalClient, log *slog.Logger, heartbeatInterval time.Duration, perClientBuffer int) *WatchHub {
	if log == nil {
		log = slog.Default()
	}
	if heartbeatInterval <= 0 {
		heartbeatInterval = 30 * time.Second
	}
	if perClientBuffer <= 0 {
		perClientBuffer = 16
	}
	return &WatchHub{
		rdb:               rdb,
		log:               log,
		heartbeatInterval: heartbeatInterval,
		perClientBuffer:   perClientBuffer,
		perTenant:         make(map[string]map[chan *manifestpb.ManifestInvalidationEvent]struct{}),
		stopCh:            make(chan struct{}),
	}
}

// Start opens the shared psubscribe and spins the fan-out goroutine.
// Idempotent — repeated calls are no-ops.
func (h *WatchHub) Start(ctx context.Context) error {
	h.mu.Lock()
	if h.started {
		h.mu.Unlock()
		return nil
	}
	h.started = true
	h.mu.Unlock()

	go h.run(ctx)
	return nil
}

// Stop tears down the fan-out goroutine. Safe to call more than once.
func (h *WatchHub) Stop() {
	h.mu.Lock()
	defer h.mu.Unlock()
	select {
	case <-h.stopCh:
		return
	default:
		close(h.stopCh)
	}
}

// Subscribe registers a per-client channel for tenantID and returns a
// cleanup func the caller must defer. The handler's per-connection
// goroutine selects on the returned channel, a heartbeat ticker, and
// its ctx.Done.
func (h *WatchHub) Subscribe(tenantID string) (<-chan *manifestpb.ManifestInvalidationEvent, func()) {
	ch := make(chan *manifestpb.ManifestInvalidationEvent, h.perClientBuffer)
	h.mu.Lock()
	set, ok := h.perTenant[tenantID]
	if !ok {
		set = map[chan *manifestpb.ManifestInvalidationEvent]struct{}{}
		h.perTenant[tenantID] = set
	}
	set[ch] = struct{}{}
	h.mu.Unlock()

	unsub := func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if set, ok := h.perTenant[tenantID]; ok {
			delete(set, ch)
			if len(set) == 0 {
				delete(h.perTenant, tenantID)
			}
		}
		close(ch)
	}
	return ch, unsub
}

// HeartbeatInterval reports the configured heartbeat cadence. Handlers
// use this to size their ticker.
func (h *WatchHub) HeartbeatInterval() time.Duration { return h.heartbeatInterval }

// run is the fan-out loop. It psubscribes once for every tenant and
// delivers events to each registered subscriber. On Redis disconnect
// the goroutine reconnects with a small backoff.
func (h *WatchHub) run(parentCtx context.Context) {
	backoff := 500 * time.Millisecond
	for {
		select {
		case <-h.stopCh:
			return
		case <-parentCtx.Done():
			return
		default:
		}

		pub := h.rdb.PSubscribe(parentCtx, InvalidationPattern)
		ch := pub.Channel()
		h.log.Info("manifest: watch hub subscribed", "pattern", InvalidationPattern)

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

		// Reconnect after backoff.
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

// dispatch routes one Redis message to every subscriber for the
// originating tenant. Slow subscribers drop the oldest event when
// their buffer is full — invalidation is best-effort (the TTL refresh
// is the correctness backstop).
func (h *WatchHub) dispatch(channel, payload string) {
	tenantID := tenantFromInvalidationChannel(channel)
	if tenantID == "" {
		return
	}
	ev := &manifestpb.ManifestInvalidationEvent{
		EventType: manifestpb.ManifestInvalidationEvent_EVENT_TYPE_INVALIDATED,
		TenantId:  tenantID,
		Reason:    payload,
		EmittedAt: timestamppb.Now(),
	}

	h.mu.Lock()
	subs := h.perTenant[tenantID]
	targets := make([]chan *manifestpb.ManifestInvalidationEvent, 0, len(subs))
	for ch := range subs {
		targets = append(targets, ch)
	}
	h.mu.Unlock()

	for _, ch := range targets {
		select {
		case ch <- ev:
		default:
			// Buffer full — drop oldest by consuming one, then retry-send.
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- ev:
			default:
				// Still full (new producer raced) — log and move on.
				h.log.Warn("manifest: watch subscriber dropped event", "tenant", tenantID)
			}
		}
	}
}

// BuildHeartbeat returns the EmittedAt-stamped HEARTBEAT event the
// per-connection handler sends on its ticker.
func BuildHeartbeat(tenantID string) *manifestpb.ManifestInvalidationEvent {
	return &manifestpb.ManifestInvalidationEvent{
		EventType: manifestpb.ManifestInvalidationEvent_EVENT_TYPE_HEARTBEAT,
		TenantId:  tenantID,
		EmittedAt: timestamppb.Now(),
	}
}

func tenantFromInvalidationChannel(channel string) string {
	// Format: "tenant:{id}:manifest_invalidated"
	const prefix = invalidationChannelPrefix
	const suffix = invalidationChannelSuffix
	if !strings.HasPrefix(channel, prefix) || !strings.HasSuffix(channel, suffix) {
		return ""
	}
	return channel[len(prefix) : len(channel)-len(suffix)]
}
