// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package audit writes and reads the audit record of the platform.
//
// Postgres audit_log is the durable copy of each audit record (writer.go,
// chain.go, retention.go). An audit write never drops.
//
// AuditLogger is the entry point for a caller that has a request context.
// It builds the record from the context, hands it to the durable writer, and
// then puts a copy on the Redis Stream of the tenant, keyed
// "tenant:{tenant_id}:audit:log". The stream is the live tail for the
// console. Redis trims it, and the trim loses nothing, because Postgres has
// each record.
//
// Usage:
//
//	logger := audit.NewAuditLogger(ctx, stateClient, writer, slog.Default())
//
//	// Log an action — tenant and actor are extracted from context automatically.
//	logger.Log(ctx, "apikey.create", "apikey", keyID, map[string]any{
//	    "name": "ci-runner",
//	})
//
//	// Read the live tail of a tenant.
//	entries, err := logger.Query(ctx, "acme-corp", audit.AuditQueryOptions{
//	    Limit:  50,
//	    Action: "apikey",
//	})
package audit

import (
	"context"
	"encoding/json"
	"errors"
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

	// writeQueueCap is the capacity of the in-memory queue of the live tail.
	writeQueueCap = 1000
)

// auditTailErrorsTotal counts copies that did not reach the Redis live tail.
// The record is not lost: Postgres has it. The console does not show it.
var auditTailErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "gibson_audit_tail_errors_total",
	Help: "Total number of audit records that did not reach the Redis live tail. Postgres holds each of them.",
})

// auditActorlessTotal counts entries refused because the caller's context
// carried no identity. An audit record with no actor is not an audit record
// (gibson#544): the refusal is logged at ERROR with the action and resource,
// so the actorless code path is found and fixed instead of recorded as
// "unknown".
var auditActorlessTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "gibson_audit_actorless_refused_total",
	Help: "Total number of audit entries refused because the context carried no actor identity.",
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

	// ActorID is the authenticated subject (Subject claim from the identity
	// token). The logger refuses an entry whose context has no identity.
	ActorID string `json:"actor_id"`

	// ActorSource is the class of the actor: "user", "agent" or "system". The
	// logger derives it from the credential type of the identity, and it is
	// the actor_type column of the durable audit_log row.
	ActorSource string `json:"actor_source"`

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

// auditWrite holds the pre-computed parameters for a single XADD call.
type auditWrite struct {
	streamKey string
	values    map[string]any
	// entry names the record in the log line when XADD fails.
	entry AuditEntry
}

// AuditLogger builds an audit record from a request context. It hands the
// record to the durable writer (Postgres), then copies it to the Redis
// Stream of the tenant, which is the live tail for the console.
//
// The durable write comes first and never drops: when the queue of the
// writer is full, Log blocks until there is room. The copy to the tail is
// not the record. When Redis does not accept it, the logger counts the
// miss in gibson_audit_tail_errors_total and goes on.
//
// AuditLogger exposes no delete or update methods, and it is safe for
// concurrent use.
type AuditLogger struct {
	client     *state.StateClient
	durable    DurableWriter
	logger     *slog.Logger
	writeQueue chan auditWrite
	done       chan struct{}
}

// DurableWriter is the part of *Writer that the logger uses: the queued
// write that never drops, and the synchronous write that returns its error.
type DurableWriter interface {
	Emitter
	WriteSync(ctx context.Context, event Event) error
}

// NewAuditLogger constructs an AuditLogger and starts the goroutine that
// feeds the live tail. The goroutine runs until ctx is cancelled.
//
// durable receives each record. In production it is the *Writer on the
// platform database. All three of client, durable and logger must be
// non-nil: a logger with no durable writer would keep the audit record only
// in a stream that Redis trims.
func NewAuditLogger(ctx context.Context, client *state.StateClient, durable DurableWriter, logger *slog.Logger) *AuditLogger {
	if client == nil {
		panic("audit.NewAuditLogger: client must not be nil")
	}
	if durable == nil {
		panic("audit.NewAuditLogger: durable writer must not be nil")
	}
	if logger == nil {
		panic("audit.NewAuditLogger: logger must not be nil")
	}
	l := &AuditLogger{
		client:     client,
		durable:    durable,
		logger:     logger.With("component", "audit_logger"),
		writeQueue: make(chan auditWrite, writeQueueCap),
		done:       make(chan struct{}),
	}
	go l.drainLoop(ctx)
	return l
}

// drainLoop is the background goroutine that issues the XADD commands of the
// live tail. It exits when ctx is cancelled, closing l.done.
func (a *AuditLogger) drainLoop(ctx context.Context) {
	defer close(a.done)
	for {
		select {
		case item := <-a.writeQueue:
			if err := a.doXAdd(ctx, item); err != nil {
				auditTailErrorsTotal.Inc()
				a.logger.Warn("audit: the record did not reach the live tail, Postgres holds it",
					slog.String("stream", item.streamKey),
					slog.String("entry_id", item.entry.ID),
					slog.String("tenant_id", item.entry.TenantID),
					slog.String("action", item.entry.Action),
					slog.String("error", err.Error()),
				)
			}
		case <-ctx.Done():
			return
		}
	}
}

// doXAdd executes the XADD command for a single queued entry.
// ctx is the drainLoop's lifecycle context; passing it to XAdd ensures that
// an in-flight write is cancelled promptly when the logger is shut down,
// preventing a race between the background goroutine and client teardown.
func (a *AuditLogger) doXAdd(ctx context.Context, item auditWrite) error {
	_, err := a.client.Client().XAdd(ctx, &redis.XAddArgs{
		Stream: item.streamKey,
		MaxLen: auditStreamMaxLen,
		Approx: true,
		ID:     "*",
		Values: item.values,
	}).Result()
	if err != nil {
		return fmt.Errorf("audit: write entry to stream %s: %w", item.streamKey, err)
	}

	return nil
}

// Log records an audit entry with result "success".
//
// The tenant is extracted from ctx via auth.TenantStringFromContext; the actor is
// extracted via auth.IdentityFromContext. An entry with no actor is refused.
//
// Log hands the entry to the durable writer and blocks while the queue of
// that writer is full. It drops nothing.
func (a *AuditLogger) Log(
	ctx context.Context,
	action, resource, resourceID string,
	details map[string]any,
) {
	a.LogWithResult(ctx, action, resource, resourceID, resultSuccess, details)
}

// LogWithResult records an audit entry with the given result string. Use
// "success" or "failure" as the result value.
//
// Tenant and actor are extracted from ctx — see Log for details.
func (a *AuditLogger) LogWithResult(
	ctx context.Context,
	action, resource, resourceID, result string,
	details map[string]any,
) {
	rec, ok := a.build(ctx, action, resource, resourceID, result, details)
	if !ok {
		return
	}
	// The durable copy first. This call blocks while the queue of the
	// writer is full.
	a.durable.Log(rec.event)
	a.tail(rec)
}

// Record writes an audit entry for an action that changes state, and
// returns after Postgres has it. Call it BEFORE the action takes effect,
// and fail the action when it returns an error: then no state change
// exists without its durable audit record (D15, gibson#676).
//
// When the action then fails, record the failure with LogWithResult and
// the result "failure".
//
// Record returns ErrNoActor when the context carries no actor identity,
// and the error of the durable write when Postgres does not accept it.
func (a *AuditLogger) Record(
	ctx context.Context,
	action, resource, resourceID string,
	details map[string]any,
) error {
	rec, ok := a.build(ctx, action, resource, resourceID, resultSuccess, details)
	if !ok {
		return ErrNoActor
	}
	if err := a.durable.WriteSync(ctx, rec.event); err != nil {
		return fmt.Errorf("audit: record %q: %w", action, err)
	}
	a.tail(rec)
	return nil
}

// ErrNoActor is returned by Record for a context with no actor identity.
var ErrNoActor = errors.New("audit: the context carries no actor identity")

// built is one entry that the logger built from a context.
type built struct {
	entry       AuditEntry
	event       Event
	detailsJSON []byte
}

// build makes the entry and its audit_log row from the context. It reports
// false, and logs the refusal, when the context carries no actor.
func (a *AuditLogger) build(
	ctx context.Context,
	action, resource, resourceID, result string,
	details map[string]any,
) (built, bool) {
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		tenantID = "unknown"
	}

	// The actor is the identity on the context. For OIDC/Zitadel callers,
	// Subject is the stable user identifier. Email is not separately
	// propagated in the signed header set, so Subject is the audit actor for
	// all credential types. ListAuditEvents serves it as actor_user_id.
	id, err := auth.IdentityFromContext(ctx)
	if err != nil || id.Subject == "" {
		auditActorlessTotal.Inc()
		a.logger.ErrorContext(ctx, "audit: entry refused, the context carries no actor identity",
			slog.String("action", action),
			slog.String("resource", resource),
			slog.String("resource_id", resourceID),
			slog.String("tenant_id", tenantID),
		)
		return built{}, false
	}

	entry := AuditEntry{
		ID:          uuid.New().String(),
		Timestamp:   time.Now().UTC(),
		TenantID:    tenantID,
		ActorID:     id.Subject,
		ActorSource: actorTypeFor(id.CredentialType),
		ActorEmail:  id.Subject,
		Action:      action,
		Resource:    resource,
		ResourceID:  resourceID,
		Details:     details,
		Result:      result,
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
	return built{
		entry:       entry,
		event:       durableEvent(entry, detailsJSON),
		detailsJSON: detailsJSON,
	}, true
}

// tail puts a copy of the entry on the live tail. The record is already
// with the durable writer, so a tail that cannot take the copy does not
// hold the caller.
func (a *AuditLogger) tail(rec built) {
	entry := rec.entry
	item := auditWrite{
		streamKey: a.streamKey(entry.TenantID),
		entry:     entry,
		values: map[string]any{
			"id":           entry.ID,
			"timestamp":    entry.Timestamp.Format(time.RFC3339Nano),
			"tenant_id":    entry.TenantID,
			"actor_id":     entry.ActorID,
			"actor_source": entry.ActorSource,
			"actor_email":  entry.ActorEmail,
			"action":       entry.Action,
			"resource":     entry.Resource,
			"resource_id":  entry.ResourceID,
			"details":      string(rec.detailsJSON),
			"result":       entry.Result,
		},
	}
	select {
	case a.writeQueue <- item:
	default:
		auditTailErrorsTotal.Inc()
		a.logger.Warn("audit: the live tail queue is full, the record is not in the tail, Postgres holds it",
			slog.String("entry_id", entry.ID),
			slog.String("tenant_id", entry.TenantID),
			slog.String("action", entry.Action),
		)
	}
}

// durableEvent maps an entry of the logger onto a row of audit_log. The
// metadata holds the entry id, the result and the details, so the row has
// each field that the live tail has.
func durableEvent(entry AuditEntry, detailsJSON []byte) Event {
	meta, err := json.Marshal(struct {
		EntryID string          `json:"entry_id"`
		Result  string          `json:"result"`
		Details json.RawMessage `json:"details"`
	}{EntryID: entry.ID, Result: entry.Result, Details: detailsJSON})
	if err != nil {
		// detailsJSON is valid JSON from json.Marshal, so this cannot fail.
		// Keep the record with the fields that always encode.
		meta = []byte(`{"entry_id":"` + entry.ID + `"}`)
	}
	return Event{
		TenantID:   entry.TenantID,
		ActorID:    entry.ActorID,
		ActorType:  entry.ActorSource,
		Action:     entry.Action,
		TargetType: entry.Resource,
		TargetID:   entry.ResourceID,
		Metadata:   meta,
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
		ID:          getString("id"),
		Timestamp:   ts,
		TenantID:    getString("tenant_id"),
		ActorID:     getString("actor_id"),
		ActorSource: getString("actor_source"),
		ActorEmail:  getString("actor_email"),
		Action:      getString("action"),
		Resource:    getString("resource"),
		ResourceID:  getString("resource_id"),
		Details:     details,
		Result:      getString("result"),
	}, nil
}

// actorTypeFor maps the credential class of the caller onto the actor_type
// column of audit_log.
func actorTypeFor(c auth.CredentialType) string {
	switch c {
	case auth.CredentialClientCredentials:
		return "system"
	case auth.CredentialCapabilityGrant:
		return "agent"
	case auth.CredentialOIDCUser:
		return "user"
	default:
		return "user"
	}
}
