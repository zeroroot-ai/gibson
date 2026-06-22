// Package audit provides append-only audit logging to Redis Streams for compliance
// requirements including SOC 2 and GDPR. Each tenant's audit log is stored in a
// dedicated Redis Stream keyed as "tenant:{tenant_id}:audit:log".
//
// The AuditLogger is designed to be safe for concurrent use and never exposes
// delete or update operations — entries are strictly append-only.
//
// Log() and LogWithResult() are fire-and-forget: they enqueue the write to a
// bounded in-memory channel (capacity 1000) and return immediately. A background
// goroutine drains the channel and issues the XADD command. If the channel is
// full or the XADD fails, the entry is dropped and
// gibson_audit_write_drops_total is incremented.
//
// Usage:
//
//	logger := audit.NewAuditLogger(ctx, stateClient, slog.Default())
//
//	// Log an action — tenant and actor are extracted from context automatically.
//	logger.Log(ctx, "apikey.create", "apikey", keyID, map[string]any{
//	    "name": "ci-runner",
//	})
//
//	// Query recent entries for a tenant.
//	entries, err := logger.Query(ctx, "acme-corp", audit.AuditQueryOptions{
//	    Limit:  50,
//	    Action: "apikey",
//	})
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/redis/go-redis/v9"

	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/sdk/auth"
)

const (
	// auditStreamSuffix is the relative key suffix appended after the tenant prefix.
	// Full key: "tenant:{tenant_id}:audit:log"
	auditStreamSuffix = "audit:log"

	// auditStreamMaxLen is the approximate maximum number of entries kept per tenant
	// stream. Redis uses "~" (approximate trimming) for efficiency.
	auditStreamMaxLen = 10000

	// defaultQueryLimit is the number of entries returned when Limit is not specified.
	defaultQueryLimit = 100

	// resultSuccess and resultFailure are the canonical result strings stored in
	// audit entries.
	resultSuccess = "success"
	resultFailure = "failure"

	// writeQueueCap is the capacity of the in-memory write queue.
	writeQueueCap = 1000
)

// auditWriteDropsTotal counts write drops — either because the queue is full
// or because the XADD command failed.
var auditWriteDropsTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "gibson_audit_write_drops_total",
	Help: "Total number of audit write drops due to full queue or XADD error.",
})

// AuditEntry is a single immutable audit record. All fields are serialised as
// individual Redis Stream fields so they can be indexed and filtered without
// deserialising a JSON blob.
type AuditEntry struct {
	// ID is a UUID assigned at write time; also stored in the stream field "id".
	ID string `json:"id"`

	// Timestamp is when the entry was created.
	Timestamp time.Time `json:"timestamp"`

	// TenantID is the tenant that owns this entry.
	TenantID string `json:"tenant_id"`

	// ActorID is the authenticated subject (Subject claim from the identity token).
	// Set to "unknown" when no identity is present in the context.
	ActorID string `json:"actor_id"`

	// ActorEmail is the email address of the actor, if available.
	// Set to "unknown" when no identity is present or the identity has no email.
	ActorEmail string `json:"actor_email"`

	// Action identifies the operation performed, conventionally in dot-separated
	// notation: e.g. "tenant.create", "apikey.revoke", "mission.start".
	Action string `json:"action"`

	// Resource is the resource type the action was performed on.
	Resource string `json:"resource"`

	// ResourceID is the identifier of the specific resource instance.
	ResourceID string `json:"resource_id"`

	// Details holds arbitrary structured context about the action.
	// Stored as a JSON-encoded string in the stream field "details".
	Details map[string]any `json:"details"`

	// Result is either "success" or "failure".
	Result string `json:"result"`
}

// AuditQueryOptions configures the behaviour of AuditLogger.Query.
// All fields are optional; zero values disable the corresponding filter.
type AuditQueryOptions struct {
	// StartTime restricts results to entries at or after this time.
	// Zero value means "from the beginning of the stream".
	StartTime time.Time

	// EndTime restricts results to entries at or before this time.
	// Zero value means "up to the latest entry".
	EndTime time.Time

	// Action filters entries whose Action field starts with this prefix.
	// Empty string disables action filtering.
	Action string

	// ActorID filters entries to only those produced by this actor.
	// Empty string disables actor filtering.
	ActorID string

	// Limit is the maximum number of entries to return after post-filtering.
	// Defaults to 100 when zero.
	Limit int
}

// SignalProjector is the narrow interface AuditLogger uses to project each
// audit entry as a compliance signal. Production passes a function that
// wraps the ComplianceMiddleware's SignalSink; tests pass fakes.
//
// Projection is BEST-EFFORT — failures to project must never fail the
// Redis Streams write, which is the authoritative legal record
// (audit-compliance-emitter Requirement 9.4).
type SignalProjector func(ctx context.Context, entry AuditEntry)

// auditWrite holds the pre-computed parameters for a single XADD call.
type auditWrite struct {
	streamKey string
	values    map[string]any
	entry     AuditEntry // for projector; kept after enqueue
	projector SignalProjector
	loggerCtx context.Context // best-effort context for projector; may be cancelled
}

// AuditLogger writes audit entries to tenant-scoped Redis Streams and supports
// time-bounded, action-prefixed, and actor-scoped queries.
//
// AuditLogger is intentionally append-only: it exposes no delete or update
// methods.  This ensures entries are tamper-evident once written.
//
// AuditLogger is safe for concurrent use. Log() and LogWithResult() are
// non-blocking: they enqueue writes to a bounded channel and return
// immediately. A background goroutine drains the channel and issues XADD.
// Drops are counted via gibson_audit_write_drops_total.
type AuditLogger struct {
	client     *state.StateClient
	logger     *slog.Logger
	projector  SignalProjector // optional; nil-safe
	writeQueue chan auditWrite
	done       chan struct{}
}

// NewAuditLogger constructs an AuditLogger backed by the provided StateClient
// and starts the background drain goroutine. The goroutine runs until ctx is
// cancelled.
//
// Both client and logger must be non-nil.
func NewAuditLogger(ctx context.Context, client *state.StateClient, logger *slog.Logger) *AuditLogger {
	l := &AuditLogger{
		client:     client,
		logger:     logger.With("component", "audit_logger"),
		writeQueue: make(chan auditWrite, writeQueueCap),
		done:       make(chan struct{}),
	}
	go l.drainLoop(ctx)
	return l
}

// drainLoop is the background goroutine that issues XADD commands. It exits
// when ctx is cancelled, closing l.done.
func (l *AuditLogger) drainLoop(ctx context.Context) {
	defer close(l.done)
	for {
		select {
		case item := <-l.writeQueue:
			if err := l.doXAdd(item); err != nil {
				auditWriteDropsTotal.Inc()
				l.logger.Warn("audit write dropped: XADD error", "err", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

// doXAdd executes the XADD command and, on success, calls the projector.
func (l *AuditLogger) doXAdd(item auditWrite) error {
	_, err := l.client.Client().XAdd(context.Background(), &redis.XAddArgs{
		Stream: item.streamKey,
		MaxLen: auditStreamMaxLen,
		Approx: true,
		ID:     "*",
		Values: item.values,
	}).Result()
	if err != nil {
		return fmt.Errorf("audit: write entry to stream %s: %w", item.streamKey, err)
	}

	// Best-effort projection to the compliance signal pipeline. The Redis
	// Streams write above is the authoritative legal record — a projection
	// failure must never affect it (Requirement 9.4).
	if item.projector != nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					l.logger.Warn("audit: signal projection panicked", slog.Any("panic", r))
				}
			}()
			item.projector(item.loggerCtx, item.entry)
		}()
	}

	return nil
}

// SetSignalProjector installs a SignalProjector. Subsequent Log/LogWithResult
// calls will invoke the projector after the Redis write succeeds. Nil-safe
// — passing nil clears the projector.
//
// This is the integration seam for audit-compliance-emitter task 12: daemon
// startup wires the projector to call into ComplianceMiddleware's SignalSink
// so that every audit log entry also lands as a compliance_signal.
func (a *AuditLogger) SetSignalProjector(p SignalProjector) {
	a.projector = p
}

// Log enqueues an audit entry with result "success" for asynchronous write to
// the tenant's Redis Stream.
//
// The tenant is extracted from ctx via auth.TenantStringFromContext; the actor is
// extracted via auth.IdentityFromContext. If no tenant or identity is found in
// the context, sensible defaults ("unknown") are used so that logging never
// blocks the calling operation.
//
// Log is non-blocking. If the internal queue is full, the entry is dropped and
// gibson_audit_write_drops_total is incremented.
func (a *AuditLogger) Log(
	ctx context.Context,
	action, resource, resourceID string,
	details map[string]any,
) {
	a.LogWithResult(ctx, action, resource, resourceID, resultSuccess, details)
}

// LogWithResult enqueues an audit entry with the given result string for
// asynchronous write to the tenant's Redis Stream. Use "success" or "failure"
// as the result value; the constants audit.ResultSuccess and
// audit.ResultFailure are provided for convenience.
//
// Tenant and actor are extracted from ctx — see Log for details.
//
// LogWithResult is non-blocking. If the internal queue is full, the entry is
// dropped and gibson_audit_write_drops_total is incremented.
func (a *AuditLogger) LogWithResult(
	ctx context.Context,
	action, resource, resourceID, result string,
	details map[string]any,
) {
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		tenantID = "unknown"
	}

	actorID := "unknown"
	actorEmail := "unknown"
	if id, err := auth.IdentityFromContext(ctx); err == nil {
		if id.Subject != "" {
			actorID = id.Subject
			// For OIDC/Zitadel callers, Subject is the stable user identifier.
			// Email is not separately propagated in the signed header set;
			// use Subject as the audit actor for all credential types.
			actorEmail = id.Subject
		}
	}

	now := time.Now().UTC()
	entry := AuditEntry{
		ID:         uuid.New().String(),
		Timestamp:  now,
		TenantID:   tenantID,
		ActorID:    actorID,
		ActorEmail: actorEmail,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Details:    details,
		Result:     result,
	}

	detailsJSON, err := json.Marshal(entry.Details)
	if err != nil {
		// Non-fatal: log the issue and continue with an empty details blob so the
		// audit entry is still written.
		a.logger.WarnContext(ctx, "audit: failed to marshal details, using empty object",
			slog.String("action", action),
			slog.String("error", err.Error()),
		)
		detailsJSON = []byte("{}")
	}

	item := auditWrite{
		streamKey: a.streamKey(tenantID),
		values: map[string]any{
			"id":          entry.ID,
			"timestamp":   entry.Timestamp.Format(time.RFC3339Nano),
			"tenant_id":   entry.TenantID,
			"actor_id":    entry.ActorID,
			"actor_email": entry.ActorEmail,
			"action":      entry.Action,
			"resource":    entry.Resource,
			"resource_id": entry.ResourceID,
			"details":     string(detailsJSON),
			"result":      entry.Result,
		},
		entry:     entry,
		projector: a.projector,
		loggerCtx: ctx,
	}

	select {
	case a.writeQueue <- item:
	default:
		// Channel full — drop and count.
		auditWriteDropsTotal.Inc()
		a.logger.Warn("audit write dropped: queue full",
			slog.String("action", action),
			slog.String("tenant_id", tenantID),
		)
	}
}

// Query reads audit entries for the named tenant from its Redis Stream, applying
// the time range, action-prefix, actor, and limit filters specified in opts.
//
// Time-range filtering is performed at the Redis level using XRANGE with
// millisecond-precision stream IDs. Action-prefix and actor filtering are
// applied in-process after retrieval because Redis Streams do not support
// field-level filtering.
//
// tenant must be a non-empty string; it is the tenant whose stream is queried,
// not the tenant from ctx. This allows admin callers to query on behalf of a
// specific tenant.
func (a *AuditLogger) Query(ctx context.Context, tenant string, opts AuditQueryOptions) ([]AuditEntry, error) {
	if tenant == "" {
		return nil, fmt.Errorf("audit: tenant must not be empty")
	}

	limit := opts.Limit
	if limit <= 0 {
		limit = defaultQueryLimit
	}

	// Convert time bounds to Redis stream ID format (milliseconds-timestamp).
	// Redis stream IDs are "<ms>-<seq>", so "<ms>-0" matches the start of a
	// millisecond and "<ms>-18446744073709551615" (MaxUint64) matches the end.
	startID := "-"
	if !opts.StartTime.IsZero() {
		startID = fmt.Sprintf("%d-0", opts.StartTime.UnixMilli())
	}

	endID := "+"
	if !opts.EndTime.IsZero() {
		endID = fmt.Sprintf("%d-18446744073709551615", opts.EndTime.UnixMilli())
	}

	streamKey := a.streamKey(tenant)

	// Fetch a larger batch from Redis and post-filter below.
	// We read up to limit*10 to provide headroom for filtered-out entries while
	// avoiding unbounded memory usage.
	fetchCount := int64(limit * 10)
	if fetchCount > auditStreamMaxLen {
		fetchCount = auditStreamMaxLen
	}

	msgs, err := a.client.Client().XRangeN(ctx, streamKey, startID, endID, fetchCount).Result()
	if err != nil {
		return nil, fmt.Errorf("audit: query stream %s: %w", streamKey, err)
	}

	entries := make([]AuditEntry, 0, len(msgs))
	for _, msg := range msgs {
		entry, err := entryFromStreamValues(msg.Values)
		if err != nil {
			a.logger.WarnContext(ctx, "audit: skipping malformed stream entry",
				slog.String("stream_id", msg.ID),
				slog.String("error", err.Error()),
			)
			continue
		}

		// Post-filter: action prefix.
		if opts.Action != "" && !strings.HasPrefix(entry.Action, opts.Action) {
			continue
		}

		// Post-filter: actor ID.
		if opts.ActorID != "" && entry.ActorID != opts.ActorID {
			continue
		}

		entries = append(entries, entry)

		if len(entries) >= limit {
			break
		}
	}

	return entries, nil
}

// streamKey returns the fully qualified Redis Stream key for the given tenant.
// The format mirrors the TenantScopedRedisKey helper: "tenant:{tenant_id}:audit:log".
func (a *AuditLogger) streamKey(tenantID string) string {
	return auth.TenantScopedRedisKey(tenantID, auditStreamSuffix)
}

// entryFromStreamValues reconstructs an AuditEntry from the raw field-value map
// returned by XRANGE. All fields are strings in the stream; typed fields are
// parsed back to their Go types here.
func entryFromStreamValues(values map[string]any) (AuditEntry, error) {
	getString := func(key string) string {
		if v, ok := values[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
		return ""
	}

	timestampStr := getString("timestamp")
	var ts time.Time
	if timestampStr != "" {
		var parseErr error
		ts, parseErr = time.Parse(time.RFC3339Nano, timestampStr)
		if parseErr != nil {
			return AuditEntry{}, fmt.Errorf("parse timestamp %q: %w", timestampStr, parseErr)
		}
	}

	var details map[string]any
	if raw := getString("details"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &details); err != nil {
			// Degrade gracefully — return an empty map rather than failing.
			details = map[string]any{}
		}
	}

	return AuditEntry{
		ID:         getString("id"),
		Timestamp:  ts,
		TenantID:   getString("tenant_id"),
		ActorID:    getString("actor_id"),
		ActorEmail: getString("actor_email"),
		Action:     getString("action"),
		Resource:   getString("resource"),
		ResourceID: getString("resource_id"),
		Details:    details,
		Result:     getString("result"),
	}, nil
}
