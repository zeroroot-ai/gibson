package component

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// WorkItem represents a unit of work dispatched to a remote component via Redis Streams.
// The orchestrator or harness enqueues work items; components poll and claim them.
type WorkItem struct {
	WorkID    string            `json:"work_id"`
	WorkType  string            `json:"work_type"`
	Payload   []byte            `json:"payload"`
	Context   map[string]string `json:"context"`
	TimeoutMs int64             `json:"timeout_ms"`
	CreatedAt time.Time         `json:"created_at"`
}

// WorkResult carries the outcome of a completed WorkItem back to the caller.
type WorkResult struct {
	WorkID string     `json:"work_id"`
	Result []byte     `json:"result"`
	Error  *WorkError `json:"error,omitempty"`
}

// WorkError describes a structured failure from a component's work execution.
// Retryable signals whether the orchestrator should re-enqueue the item.
type WorkError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// WorkQueue defines the contract for pull-based work dispatch over Redis Streams.
//
// Redis key layout:
//
//	Stream:        work:{tenant}:{kind}:{name}
//	Consumer group: workers
//	Result key:    result:{work_id}       (5-minute TTL)
//	Notify channel: result_notify:{work_id} (pub/sub)
type WorkQueue interface {
	// Enqueue appends a new WorkItem to the stream for the given component.
	// It returns the Redis stream message ID assigned to the item.
	Enqueue(ctx context.Context, tenant, kind, name string, item WorkItem) (string, error)

	// Claim blocks until a WorkItem is available for the given consumerID, or
	// until blockTimeout elapses. Returns nil, nil when no item arrives within
	// the timeout (the caller should loop).
	//
	// When tenant is "_system", Claim polls across all tenant-scoped streams
	// for the given kind+name, setting WorkItem.Context["tenant_id"] to the
	// originating tenant. See claimCrossTenant for details.
	Claim(ctx context.Context, tenant, kind, name, consumerID string, blockTimeout time.Duration) (*WorkItem, error)

	// DeliverResult stores the result under result:{work_id} with a 5-minute TTL
	// and publishes a notification on result_notify:{work_id} so that any caller
	// blocked in WaitForResult can unblock immediately.
	DeliverResult(ctx context.Context, workID string, result WorkResult) error

	// WaitForResult subscribes to result_notify:{work_id} and returns the result
	// as soon as it arrives, or reads it directly from result:{work_id} if it is
	// already present. Returns an error wrapping context.DeadlineExceeded when
	// timeout elapses without a result.
	WaitForResult(ctx context.Context, workID string, timeout time.Duration) (*WorkResult, error)

	// Acknowledge removes messageID from the pending-entries list of the consumer
	// group, marking the work item as successfully processed.
	Acknowledge(ctx context.Context, tenant, kind, name, messageID string) error

	// ReclaimAbandoned scans the pending-entries list for messages that have been
	// idle for longer than idleTimeout and transfers ownership to the caller's
	// consumer group so they can be reprocessed.
	ReclaimAbandoned(ctx context.Context, tenant, kind, name string, idleTimeout time.Duration) error
}

const (
	// workGroup is the fixed consumer group name used for all work streams.
	workGroup = "workers"

	// resultTTL is the time-to-live applied to result keys.
	resultTTL = 5 * time.Minute

	// reclaimConsumer is the consumer identity used when re-claiming abandoned messages.
	reclaimConsumer = "reclaimer"

	// reclaimBatchSize is the maximum number of pending messages inspected per
	// ReclaimAbandoned call.
	reclaimBatchSize = 100
)

// redisWorkQueue is the Redis-backed implementation of WorkQueue.
//
// crossTenantOffset drives fair round-robin tenant selection in
// claimCrossTenant. It is incremented atomically on every cross-tenant poll
// so that no single tenant stream is always checked first. atomic.Uint64
// avoids a mutex on the hot polling path.
type redisWorkQueue struct {
	client            redis.UniversalClient
	crossTenantOffset atomic.Uint64
}

// NewRedisWorkQueue constructs a WorkQueue backed by the provided redis.UniversalClient.
// The client must already be connected and healthy.
func NewRedisWorkQueue(client redis.UniversalClient) WorkQueue {
	return &redisWorkQueue{client: client}
}

// streamKey returns the Redis Stream key for a component's work queue.
//
//	work:{tenant}:{kind}:{name}
func streamKey(tenant, kind, name string) string {
	return fmt.Sprintf("work:%s:%s:%s", tenant, kind, name)
}

// resultKey returns the Redis key used to store a completed WorkResult.
//
//	result:{work_id}
func resultKey(workID string) string {
	return fmt.Sprintf("result:%s", workID)
}

// notifyChannel returns the pub/sub channel used to signal result delivery.
//
//	result_notify:{work_id}
func notifyChannel(workID string) string {
	return fmt.Sprintf("result_notify:%s", workID)
}

// Enqueue serializes item and appends it to the stream via XADD.
// It assigns a unique WorkID if the item does not already have one.
// Returns the Redis stream message ID (e.g., "1700000000000-0").
func (q *redisWorkQueue) Enqueue(ctx context.Context, tenant, kind, name string, item WorkItem) (string, error) {
	if tenant == "" {
		return "", fmt.Errorf("work queue enqueue: tenant cannot be empty")
	}
	if kind == "" {
		return "", fmt.Errorf("work queue enqueue: kind cannot be empty")
	}
	if name == "" {
		return "", fmt.Errorf("work queue enqueue: name cannot be empty")
	}

	if item.WorkID == "" {
		item.WorkID = uuid.New().String()
	}
	if item.CreatedAt.IsZero() {
		item.CreatedAt = time.Now().UTC()
	}

	// Serialize the entire WorkItem as a single JSON field so that the stream
	// entry stays self-contained and is easy to deserialize on the consumer side.
	data, err := json.Marshal(item)
	if err != nil {
		return "", fmt.Errorf("work queue enqueue: marshal work item: %w", err)
	}

	msgID, err := q.client.XAdd(ctx, &redis.XAddArgs{
		Stream: streamKey(tenant, kind, name),
		ID:     "*", // auto-generate
		Values: map[string]any{
			"work_item": string(data),
		},
	}).Result()
	if err != nil {
		return "", fmt.Errorf("work queue enqueue: XADD to stream %s: %w",
			streamKey(tenant, kind, name), err)
	}

	return msgID, nil
}

// Claim reads one pending WorkItem from the stream using XREADGROUP BLOCK.
// The consumer group is created automatically on first use (MKSTREAM).
// Returns nil, nil when blockTimeout elapses with no available message.
//
// When tenant is "_system", claimCrossTenant is called instead. It scans all
// tenant-scoped streams for the given kind+name (excluding _system streams)
// and reads the first available item, attaching the originating tenant to
// WorkItem.Context["tenant_id"]. This allows a single shared component
// deployment to serve work from every tenant's queue.
func (q *redisWorkQueue) Claim(ctx context.Context, tenant, kind, name, consumerID string, blockTimeout time.Duration) (*WorkItem, error) {
	if tenant == "" {
		return nil, fmt.Errorf("work queue claim: tenant cannot be empty")
	}
	if kind == "" {
		return nil, fmt.Errorf("work queue claim: kind cannot be empty")
	}
	if name == "" {
		return nil, fmt.Errorf("work queue claim: name cannot be empty")
	}
	if consumerID == "" {
		return nil, fmt.Errorf("work queue claim: consumerID cannot be empty")
	}

	// _system components poll across all tenant-scoped streams so that a single
	// shared deployment (e.g., nmap, httpx) can serve every tenant.
	if tenant == systemTenant {
		return q.claimCrossTenant(ctx, kind, name, consumerID, blockTimeout)
	}

	stream := streamKey(tenant, kind, name)

	// Ensure the consumer group exists. MKSTREAM creates the stream if absent.
	if err := q.ensureGroup(ctx, stream); err != nil {
		return nil, err
	}

	results, err := q.client.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group:    workGroup,
		Consumer: consumerID,
		Streams:  []string{stream, ">"},
		Count:    1,
		Block:    blockTimeout,
		NoAck:    true, // caller must call Acknowledge explicitly
	}).Result()
	if err != nil {
		if err == redis.Nil {
			// Timeout elapsed with no message — not an error.
			return nil, nil
		}
		return nil, fmt.Errorf("work queue claim: XREADGROUP on stream %s: %w", stream, err)
	}

	if len(results) == 0 || len(results[0].Messages) == 0 {
		return nil, nil
	}

	msg := results[0].Messages[0]
	item, err := unmarshalWorkItem(msg)
	if err != nil {
		return nil, fmt.Errorf("work queue claim: decode message %s: %w", msg.ID, err)
	}

	return item, nil
}

// claimCrossTenant is called by Claim when tenant == "_system".
//
// It discovers all active tenant-scoped streams for the given component
// kind+name via Redis SCAN (pattern: work:*:{kind}:{name}), excludes any
// _system-namespaced keys, then performs a non-blocking XREADGROUP on each
// stream in a fair round-robin order. The first stream that yields a message
// wins; its originating tenant is written into WorkItem.Context["tenant_id"]
// so the component can scope all downstream operations (tool calls, memory,
// findings) to the correct tenant.
//
// Fair polling strategy: the shared crossTenantOffset counter is incremented
// atomically on every call so that the starting position in the stream list
// rotates across successive polls, preventing any single tenant from being
// permanently favoured. A random shuffle is applied first so that tenants
// discovered later by SCAN are not always appended last.
//
// If no streams exist, or all streams are empty, nil, nil is returned and the
// caller's polling loop should sleep and retry (same semantics as a timeout on
// the single-tenant path).
//
// Note on BLOCK vs non-blocking: XREADGROUP BLOCK works efficiently only for a
// single stream. Implementing multi-stream blocking would require one goroutine
// per tenant stream, which is expensive and complex. Instead, claimCrossTenant
// does a fast non-blocking sweep. The blockTimeout parameter is accepted for
// interface compatibility but is not used; the calling poll loop controls the
// retry cadence via its own sleep interval.
func (q *redisWorkQueue) claimCrossTenant(
	ctx context.Context,
	kind, name, consumerID string,
	_ time.Duration, // blockTimeout: not used; see doc comment above
) (*WorkItem, error) {
	// Pattern matches every stream for this component type across all tenants.
	// Example for kind=tool, name=nmap: "work:*:tool:nmap"
	pattern := fmt.Sprintf("work:*:%s:%s", kind, name)

	// Collect matching stream keys via SCAN. SCAN is O(N) across the keyspace
	// but is non-blocking and cursor-based, making it safe at typical polling
	// cadences (e.g. once per second per component instance).
	var streams []string
	var cursor uint64
	for {
		keys, next, err := q.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return nil, fmt.Errorf("work queue claim cross-tenant: SCAN for %s: %w", pattern, err)
		}
		for _, k := range keys {
			// Exclude _system streams: those are the component's own queue,
			// not work enqueued by tenants.
			if !strings.HasPrefix(k, "work:"+systemTenant+":") {
				streams = append(streams, k)
			}
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}

	if len(streams) == 0 {
		return nil, nil
	}

	// Shuffle first so that tenants discovered later by SCAN (which may
	// consistently return keys in insertion order on small keyspaces) are not
	// always at the back.
	rand.Shuffle(len(streams), func(i, j int) { streams[i], streams[j] = streams[j], streams[i] })

	// Apply round-robin rotation using the atomic offset so that across
	// successive claimCrossTenant calls the starting tenant changes, ensuring
	// all tenants receive equal priority over time.
	offset := int(q.crossTenantOffset.Add(1)) % len(streams)
	streams = append(streams[offset:], streams[:offset]...)

	// Ensure the consumer group exists on every discovered stream before
	// attempting to read. This is idempotent (BUSYGROUP is ignored by
	// ensureGroup) and necessary because XREADGROUP returns NOGROUP if the
	// group has never been created on that stream.
	for _, s := range streams {
		if err := q.ensureGroup(ctx, s); err != nil {
			return nil, fmt.Errorf("work queue claim cross-tenant: ensure group on %s: %w", s, err)
		}
	}

	// Non-blocking sweep: try each stream in round-robin order and return the
	// first item found. redis.Nil and other transient errors are skipped so
	// that a single bad or empty tenant stream cannot stall the whole poll.
	for _, s := range streams {
		results, err := q.client.XReadGroup(ctx, &redis.XReadGroupArgs{
			Group:    workGroup,
			Consumer: consumerID,
			Streams:  []string{s, ">"},
			Count:    1,
			Block:    0, // non-blocking; poll loop drives retry cadence
			NoAck:    true,
		}).Result()
		if err != nil {
			// redis.Nil: stream has no new messages. Any other error: skip and
			// try the next stream to avoid one bad tenant blocking others.
			continue
		}
		if len(results) == 0 || len(results[0].Messages) == 0 {
			continue
		}

		msg := results[0].Messages[0]
		item, err := unmarshalWorkItem(msg)
		if err != nil {
			return nil, fmt.Errorf("work queue claim cross-tenant: decode message %s on %s: %w", msg.ID, s, err)
		}

		// Inject the originating tenant into the work item's context so the
		// component can scope all operations (memory, findings, tool calls)
		// to the correct tenant rather than assuming _system.
		originTenant := tenantFromStreamKey(s)
		if originTenant != "" {
			if item.Context == nil {
				item.Context = make(map[string]string)
			}
			item.Context["tenant_id"] = originTenant
		}

		return item, nil
	}

	// All streams were empty on this sweep.
	return nil, nil
}

// tenantFromStreamKey parses the tenant segment from a stream key of the form
// work:{tenant}:{kind}:{name}. Returns an empty string if the key does not
// match the expected format.
func tenantFromStreamKey(key string) string {
	// Strip the "work:" prefix.
	without := strings.TrimPrefix(key, "work:")
	if without == key {
		return "" // prefix absent — unexpected format
	}
	// Tenant is everything up to the next colon.
	idx := strings.Index(without, ":")
	if idx < 0 {
		return ""
	}
	return without[:idx]
}

// DeliverResult stores the result JSON under result:{work_id} with a 5-minute TTL,
// then publishes a signal on result_notify:{work_id}.
func (q *redisWorkQueue) DeliverResult(ctx context.Context, workID string, result WorkResult) error {
	if workID == "" {
		return fmt.Errorf("work queue deliver result: workID cannot be empty")
	}

	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("work queue deliver result: marshal result: %w", err)
	}

	// Persist result first so that a racing WaitForResult that misses the pub/sub
	// notification can still fetch it directly from the key.
	if err := q.client.Set(ctx, resultKey(workID), data, resultTTL).Err(); err != nil {
		return fmt.Errorf("work queue deliver result: SET result key for work %s: %w", workID, err)
	}

	// Publish a lightweight notification. WaitForResult subscribers will wake up
	// and then read the full result from the key.
	if err := q.client.Publish(ctx, notifyChannel(workID), workID).Err(); err != nil {
		// Non-fatal: the result is already persisted and WaitForResult will poll
		// the key on subscription errors. Log-worthy but not a hard failure.
		return fmt.Errorf("work queue deliver result: PUBLISH notify for work %s: %w", workID, err)
	}

	return nil
}

// WaitForResult subscribes to result_notify:{work_id} and returns as soon as a
// result arrives, or returns context.DeadlineExceeded if timeout elapses.
//
// It also checks result:{work_id} before blocking on pub/sub to handle the race
// where DeliverResult completes before the subscription is established.
func (q *redisWorkQueue) WaitForResult(ctx context.Context, workID string, timeout time.Duration) (*WorkResult, error) {
	if workID == "" {
		return nil, fmt.Errorf("work queue wait for result: workID cannot be empty")
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Subscribe before the GET so we cannot miss a notification that arrives
	// between the GET and the subscribe.
	pubsub := q.client.Subscribe(timeoutCtx, notifyChannel(workID))
	defer pubsub.Close()

	// Ensure the subscription handshake completes before we poll the key.
	if _, err := pubsub.Receive(timeoutCtx); err != nil {
		// Context cancelled or timeout before subscription established.
		return nil, fmt.Errorf("work queue wait for result: subscribe to notify channel: %w", err)
	}

	// Check if the result was already written before we subscribed.
	if result, err := q.fetchResult(timeoutCtx, workID); err == nil {
		return result, nil
	}

	msgChan := pubsub.Channel()

	for {
		select {
		case <-timeoutCtx.Done():
			return nil, fmt.Errorf("work queue wait for result: timeout waiting for work %s: %w",
				workID, timeoutCtx.Err())

		case _, ok := <-msgChan:
			if !ok {
				// Channel closed — context cancelled.
				return nil, fmt.Errorf("work queue wait for result: subscription closed for work %s",
					workID)
			}

			result, err := q.fetchResult(timeoutCtx, workID)
			if err != nil {
				// Result not yet visible (e.g., replication lag); keep waiting.
				continue
			}
			return result, nil
		}
	}
}

// Acknowledge calls XACK to remove messageID from the consumer group's PEL.
func (q *redisWorkQueue) Acknowledge(ctx context.Context, tenant, kind, name, messageID string) error {
	if tenant == "" {
		return fmt.Errorf("work queue acknowledge: tenant cannot be empty")
	}
	if kind == "" {
		return fmt.Errorf("work queue acknowledge: kind cannot be empty")
	}
	if name == "" {
		return fmt.Errorf("work queue acknowledge: name cannot be empty")
	}
	if messageID == "" {
		return fmt.Errorf("work queue acknowledge: messageID cannot be empty")
	}

	stream := streamKey(tenant, kind, name)
	count, err := q.client.XAck(ctx, stream, workGroup, messageID).Result()
	if err != nil {
		return fmt.Errorf("work queue acknowledge: XACK message %s on stream %s: %w",
			messageID, stream, err)
	}

	if count == 0 {
		// Message was already acknowledged or never belonged to this group.
		// This is benign — idempotent acknowledge is intentional.
		return nil
	}

	return nil
}

// ReclaimAbandoned queries XPENDING for messages that have been idle longer than
// idleTimeout and transfers ownership to reclaimConsumer via XCLAIM so they can
// be re-delivered and reprocessed.
func (q *redisWorkQueue) ReclaimAbandoned(ctx context.Context, tenant, kind, name string, idleTimeout time.Duration) error {
	if tenant == "" {
		return fmt.Errorf("work queue reclaim abandoned: tenant cannot be empty")
	}
	if kind == "" {
		return fmt.Errorf("work queue reclaim abandoned: kind cannot be empty")
	}
	if name == "" {
		return fmt.Errorf("work queue reclaim abandoned: name cannot be empty")
	}

	stream := streamKey(tenant, kind, name)

	// Ensure the group exists before querying pending entries.
	if err := q.ensureGroup(ctx, stream); err != nil {
		return err
	}

	// Retrieve pending messages across all consumers.
	pending, err := q.client.XPendingExt(ctx, &redis.XPendingExtArgs{
		Stream: stream,
		Group:  workGroup,
		Start:  "-",
		End:    "+",
		Count:  reclaimBatchSize,
	}).Result()
	if err != nil {
		if err == redis.Nil {
			return nil // No pending messages.
		}
		return fmt.Errorf("work queue reclaim abandoned: XPENDING on stream %s: %w", stream, err)
	}

	// Collect IDs of messages idle beyond the threshold.
	var staleIDs []string
	for _, msg := range pending {
		if msg.Idle >= idleTimeout {
			staleIDs = append(staleIDs, msg.ID)
		}
	}

	if len(staleIDs) == 0 {
		return nil
	}

	// Transfer ownership so the reclaimer (or the next Claim call) can reprocess them.
	_, err = q.client.XClaim(ctx, &redis.XClaimArgs{
		Stream:   stream,
		Group:    workGroup,
		Consumer: reclaimConsumer,
		MinIdle:  idleTimeout,
		Messages: staleIDs,
	}).Result()
	if err != nil && err != redis.Nil {
		return fmt.Errorf("work queue reclaim abandoned: XCLAIM %d messages on stream %s: %w",
			len(staleIDs), stream, err)
	}

	return nil
}

// ensureGroup creates the consumer group if it does not already exist.
// MKSTREAM creates the stream itself if it is absent.
// BUSYGROUP errors are treated as success (idempotent).
func (q *redisWorkQueue) ensureGroup(ctx context.Context, stream string) error {
	err := q.client.Do(ctx, "XGROUP", "CREATE", stream, workGroup, "0", "MKSTREAM").Err()
	if err != nil && !strings.Contains(err.Error(), "BUSYGROUP") {
		return fmt.Errorf("work queue: ensure consumer group on stream %s: %w", stream, err)
	}
	return nil
}

// fetchResult reads and deserializes a WorkResult from the result key.
// Returns an error when the key does not exist yet.
func (q *redisWorkQueue) fetchResult(ctx context.Context, workID string) (*WorkResult, error) {
	data, err := q.client.Get(ctx, resultKey(workID)).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("result not yet available for work %s", workID)
		}
		return nil, fmt.Errorf("work queue fetch result: GET for work %s: %w", workID, err)
	}

	var result WorkResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("work queue fetch result: unmarshal for work %s: %w", workID, err)
	}

	return &result, nil
}

// unmarshalWorkItem decodes a WorkItem from a Redis Stream message.
// The message must contain a "work_item" field holding JSON-encoded WorkItem bytes.
func unmarshalWorkItem(msg redis.XMessage) (*WorkItem, error) {
	raw, ok := msg.Values["work_item"]
	if !ok {
		return nil, fmt.Errorf("message %s missing work_item field", msg.ID)
	}

	var data string
	switch v := raw.(type) {
	case string:
		data = v
	default:
		return nil, fmt.Errorf("message %s work_item field has unexpected type %T", msg.ID, raw)
	}

	var item WorkItem
	if err := json.Unmarshal([]byte(data), &item); err != nil {
		return nil, fmt.Errorf("message %s: unmarshal work item: %w", msg.ID, err)
	}

	return &item, nil
}
