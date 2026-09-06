// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package audit — writer.go
//
// Writer is an asynchronous, batching writer for Postgres-backed audit events.
//
// Background flush goroutine:
//   - Accumulates events into a batch.
//   - Flushes when the batch reaches batchSize (100) OR the ticker fires (every
//     second), whichever comes first.
//   - Flush extends each tenant's hash chain (chain.go) and issues a single
//     parameterised bulk INSERT inside one transaction.
//
// # Enqueue behaviour under load
//
// Log applies bounded backpressure: it tries a non-blocking send first, and
// only if the buffer is full does it wait up to enqueueTimeout for space.
// That absorbs bursts — the flush loop drains 100 rows at a time — without
// letting an audit-backend outage block a request path indefinitely, which
// would turn a degraded audit pipeline into a full daemon outage.
//
// If the wait expires the event is dropped, and the drop is made loud rather
// than quiet: gibson_audit_dropped_total increments, the event identity is
// logged at ERROR, gibson_audit_last_drop_timestamp_seconds is stamped, and
// any registered DropObserver is invoked. Callers that cannot tolerate a
// drop at all must use WriteSync (sync_writer.go), which either persists or
// returns an error.
//
// Alert on drops — they mean audit records were lost:
//
//	increase(gibson_audit_dropped_total[5m]) > 0
//	increase(gibson_audit_write_drops_total[5m]) > 0
//
// Lifecycle:
//
//	w := audit.NewWriter(db, logger)
//	w.Start(ctx)
//	defer w.Stop(ctx)
//
// Prometheus metrics:
//
//	gibson_audit_events_total{action}              — events successfully enqueued
//	gibson_audit_dropped_total                     — events dropped after backpressure expired
//	gibson_audit_last_drop_timestamp_seconds       — unix time of the most recent drop
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	// writerBufferSize is the capacity of the channel-based event buffer.
	writerBufferSize = 1000

	// batchSize is the maximum number of events flushed in a single INSERT.
	batchSize = 100

	// flushInterval is the maximum duration between flushes when the batch is
	// not yet full.
	flushInterval = time.Second

	// enqueueTimeout bounds how long Log will wait for buffer space before
	// giving up and dropping. Long enough for the flush loop to turn over a
	// full batch, short enough that a wedged Postgres cannot stall a request
	// path for a noticeable time.
	enqueueTimeout = 250 * time.Millisecond
)

// ---------------------------------------------------------------------------
// Prometheus metrics (package-level, registered once per process)
// ---------------------------------------------------------------------------

var (
	metricsOnce        sync.Once
	auditEventsTotal   *prometheus.CounterVec
	auditDroppedTotal  prometheus.Counter
	auditLastDropStamp prometheus.Gauge
)

// initMetrics registers the Prometheus counters once per process lifetime
// using promauto (which panics on duplicate registration). The sync.Once
// guard ensures they are registered exactly once even when multiple Writers
// are created (e.g., in tests).
func initMetrics() {
	metricsOnce.Do(func() {
		auditEventsTotal = promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gibson_audit_events_total",
				Help: "Total number of audit events enqueued for writing, by action.",
			},
			[]string{"action"},
		)
		auditDroppedTotal = promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "gibson_audit_dropped_total",
				Help: "Total number of audit events LOST because the write buffer stayed full past the backpressure deadline. Any non-zero increase is an alertable audit-integrity event.",
			},
		)
		auditLastDropStamp = promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "gibson_audit_last_drop_timestamp_seconds",
				Help: "Unix timestamp of the most recent dropped audit event. Zero when no event has ever been dropped.",
			},
		)
	})
}

// ---------------------------------------------------------------------------
// Event type
// ---------------------------------------------------------------------------

// Event is a single audit record for the Postgres audit_log table.
//
// ActorType must be one of "user", "agent", or "system"; it defaults to
// "user" when empty.
// Decision must be one of "allow", "deny", or "" (empty for non-authz events).
// Metadata is stored as JSONB; pass nil or json.RawMessage("{}") for no
// additional context.
type Event struct {
	TenantID   string
	ActorID    string
	ActorType  string // "user", "agent", "system"
	Action     string // e.g. "grant_created", "agent_registered", "capability_executed"
	TargetType string // e.g. "component", "agent", "team", "user"
	TargetID   string
	Decision   string          // "allow", "deny", or "" for non-authz events
	Metadata   json.RawMessage // stored verbatim in the JSONB column

	// Tuple is the FGA tuple this event describes, serialised as
	// "{user}#{relation}@{object}". Non-empty only for access_tuple_change
	// events emitted by WriteAccessTuples; absent for non-tuple events.
	// Added by access-matrix-finish spec.
	Tuple string
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

// DropObserver is notified once per audit event that the Writer could not
// enqueue. It runs on the calling goroutine, so implementations must return
// promptly and must not call back into the Writer.
//
// The point of the hook is that a lost audit record should be able to reach
// something louder than a log line — a pager, a health signal, a refusal to
// serve. Wiring one is the deployment's decision; the Writer only guarantees
// it will be told.
type DropObserver func(event Event)

// Writer batches audit events and flushes them asynchronously to Postgres,
// extending a per-tenant hash chain as it goes (chain.go).
//
// Writer is safe for concurrent use. Log applies bounded backpressure and
// then drops loudly — see the package comment for the tradeoff and for the
// alert expression.
type Writer struct {
	db       *sql.DB
	buffer   chan Event
	logger   *slog.Logger
	done     chan struct{}
	stopping chan struct{}
	stopOnce sync.Once
	dropped  atomic.Int64
	onDrop   DropObserver
}

// NewWriter constructs a Writer. Both db and logger must be non-nil.
//
// The Writer must be started via Start() before Log() calls will be
// persisted. Events buffered before Start() (up to writerBufferSize) will be
// flushed once the background goroutine starts.
func NewWriter(db *sql.DB, logger *slog.Logger) *Writer {
	if db == nil {
		panic("audit.NewWriter: db must not be nil")
	}
	if logger == nil {
		panic("audit.NewWriter: logger must not be nil")
	}
	initMetrics()
	return &Writer{
		db:       db,
		buffer:   make(chan Event, writerBufferSize),
		logger:   logger.With("component", "audit.writer"),
		done:     make(chan struct{}),
		stopping: make(chan struct{}),
	}
}

// WithDropObserver registers the observer invoked for every dropped event
// and returns the Writer for chaining. Call before Start; the field is not
// guarded for concurrent mutation.
func (w *Writer) WithDropObserver(obs DropObserver) *Writer {
	w.onDrop = obs
	return w
}

// Dropped returns the number of audit events this Writer has lost. Non-zero
// means the audit record has gaps: treat it as an integrity incident, not as
// a capacity statistic.
func (w *Writer) Dropped() int64 { return w.dropped.Load() }

// Log enqueues an audit event for asynchronous persistence.
//
// Log tries a non-blocking send first. If the buffer is full it waits up to
// enqueueTimeout for space — bounded backpressure, so a burst is absorbed
// rather than discarded — and only then gives up. Giving up is reported via
// dropEvent: counter, ERROR log, timestamp gauge, and DropObserver.
//
// Log never blocks longer than enqueueTimeout, and never blocks at all once
// Stop has been called.
func (w *Writer) Log(event Event) {
	// Checked in its own select first: a select with both a ready send and a
	// closed channel picks between them at random, which would make
	// post-Stop behaviour a coin flip. After Stop the drain has already run,
	// so anything enqueued now would vanish uncounted — drop it loudly
	// instead.
	select {
	case <-w.stopping:
		w.dropEvent(event, "writer stopped")
		return
	default:
	}

	select {
	case w.buffer <- event:
		auditEventsTotal.WithLabelValues(event.Action).Inc()
		return
	default:
	}

	timer := time.NewTimer(enqueueTimeout)
	defer timer.Stop()

	select {
	case w.buffer <- event:
		auditEventsTotal.WithLabelValues(event.Action).Inc()
	case <-w.stopping:
		w.dropEvent(event, "writer stopped")
	case <-timer.C:
		w.dropEvent(event, "buffer full past the backpressure deadline")
	}
}

// dropEvent records the loss of an audit event as loudly as this layer can:
// a counter an alert can fire on, a wall-clock stamp, an ERROR log carrying
// enough identity to reconstruct what was lost, and the observer hook.
func (w *Writer) dropEvent(event Event, reason string) {
	w.dropped.Add(1)
	auditDroppedTotal.Inc()
	auditLastDropStamp.SetToCurrentTime()

	w.logger.Error("audit: EVENT LOST — audit record was not persisted",
		slog.String("reason", reason),
		slog.String("tenant_id", event.TenantID),
		slog.String("actor_id", event.ActorID),
		slog.String("action", event.Action),
		slog.String("target_type", event.TargetType),
		slog.String("target_id", event.TargetID),
		slog.String("decision", event.Decision),
		slog.Int64("dropped_total", w.dropped.Load()),
	)

	if w.onDrop != nil {
		w.onDrop(event)
	}
}

// dropBatch records the loss of a whole batch. It emits one ERROR rather
// than one per event — a wedged backend would otherwise flood the log at
// exactly the moment the log is what an operator is reading — but every
// event still counts towards gibson_audit_dropped_total and still reaches
// the DropObserver, so nothing is lost silently.
func (w *Writer) dropBatch(batch []Event, reason string) {
	if len(batch) == 0 {
		return
	}
	w.dropped.Add(int64(len(batch)))
	auditDroppedTotal.Add(float64(len(batch)))
	auditLastDropStamp.SetToCurrentTime()

	actions := make([]string, 0, len(batch))
	seen := make(map[string]struct{}, len(batch))
	for _, ev := range batch {
		if _, ok := seen[ev.Action]; ok {
			continue
		}
		seen[ev.Action] = struct{}{}
		actions = append(actions, ev.Action)
	}

	w.logger.Error("audit: BATCH LOST — audit records were not persisted",
		slog.String("reason", reason),
		slog.Int("batch_size", len(batch)),
		slog.String("actions", strings.Join(actions, ",")),
		slog.String("tenant_id", batch[0].TenantID),
		slog.Int64("dropped_total", w.dropped.Load()),
	)

	if w.onDrop != nil {
		for _, ev := range batch {
			w.onDrop(ev)
		}
	}
}

// Start launches the background flush goroutine. It returns immediately.
//
// The goroutine runs until Stop() is called or ctx is cancelled, at which
// point it flushes any remaining buffered events before exiting.
//
// Start must be called exactly once.
func (w *Writer) Start(ctx context.Context) {
	go w.run(ctx)
}

// Stop signals the background goroutine to stop, waits for remaining buffered
// events to be flushed, then returns.
//
// The provided context controls the deadline for the final flush. Stop blocks
// until the goroutine exits or ctx is cancelled. Stop is idempotent.
//
// Shutdown closes a separate `stopping` channel rather than the event buffer:
// closing the buffer would panic any Log call racing the shutdown, which is
// precisely the moment a caller is most likely to be emitting a
// shutdown-related audit event.
func (w *Writer) Stop(ctx context.Context) {
	w.stopOnce.Do(func() { close(w.stopping) })
	select {
	case <-w.done:
	case <-ctx.Done():
		w.logger.Warn("audit: Stop context expired before drain completed",
			slog.String("error", ctx.Err().Error()),
		)
	}
}

// run is the background goroutine started by Start(). It reads from the
// buffer channel, accumulates batches, and flushes them to Postgres.
func (w *Writer) run(ctx context.Context) {
	defer close(w.done)

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	batch := make([]Event, 0, batchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := w.flush(ctx, batch); err != nil {
			// The batch is gone. That is a lost audit record just as much as
			// a full buffer is, so it goes through the same loud path rather
			// than ending its life as one log line.
			w.dropBatch(batch, "flush failed: "+err.Error())
		}
		// Reset without reallocating.
		batch = batch[:0]
	}

	// drainAndExit empties whatever is already buffered, flushing as it goes.
	// Nothing new can be enqueued once stopping is closed, and a cancelled
	// ctx means the caller has already given up on us, so a non-blocking
	// drain terminates.
	drainAndExit := func() {
		for {
			select {
			case event := <-w.buffer:
				batch = append(batch, event)
				if len(batch) >= batchSize {
					flush()
				}
			default:
				flush()
				return
			}
		}
	}

	for {
		select {
		case event := <-w.buffer:
			batch = append(batch, event)
			if len(batch) >= batchSize {
				flush()
			}

		case <-ticker.C:
			flush()

		case <-w.stopping:
			drainAndExit()
			return

		case <-ctx.Done():
			drainAndExit()
			return
		}
	}
}

// flush writes batch to Postgres in a single transaction: it extends each
// tenant's hash chain, then issues one parameterised multi-row INSERT.
//
// The transaction is what makes the chain sound. Reading a tenant's chain
// head and appending to it is a read-modify-write, so two concurrent flushes
// — two Writers in one process, or two daemon replicas — would otherwise both
// read position N and both write N+1, forking the chain. Each tenant is
// therefore serialised on a transaction-scoped advisory lock, taken in
// sorted tenant order so two flushes touching the same pair of tenants
// cannot deadlock. The partial unique index on (tenant_id, chain_seq) is the
// backstop: if the locking were ever wrong, the second writer fails loudly
// instead of forking silently.
//
// created_at is assigned here rather than left to the column default,
// because the chain hash commits to it and both sides must agree on the
// exact value. It is truncated to microseconds — Postgres TIMESTAMPTZ
// resolution — so the hash still reproduces after a round trip.
func (w *Writer) flush(ctx context.Context, batch []Event) error {
	if len(batch) == 0 {
		return nil
	}

	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("audit: flush: begin transaction (%d rows): %w", len(batch), err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	createdAt := time.Now().UTC().Truncate(time.Microsecond)

	byTenant := make(map[string][]Event, 1)
	for _, ev := range batch {
		byTenant[ev.TenantID] = append(byTenant[ev.TenantID], ev)
	}
	tenants := make([]string, 0, len(byTenant))
	for tenant := range byTenant {
		tenants = append(tenants, tenant)
	}
	sort.Strings(tenants)

	rows := make([]chainRow, 0, len(batch))
	for _, tenant := range tenants {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, tenantAdvisoryKey(tenant)); err != nil {
			return fmt.Errorf("audit: flush: lock chain for tenant %q: %w", tenant, err)
		}

		seq, prevHash, err := chainHead(ctx, tx, tenant)
		if err != nil {
			return fmt.Errorf("audit: flush: %w", err)
		}

		for _, ev := range byTenant[tenant] {
			actorType := ev.ActorType
			if actorType == "" {
				actorType = "user"
			}
			meta := ev.Metadata
			if len(meta) == 0 {
				meta = json.RawMessage("{}")
			}

			seq++
			r := chainRow{
				Seq:        seq,
				TenantID:   tenant,
				ActorID:    ev.ActorID,
				ActorType:  actorType,
				Action:     ev.Action,
				TargetType: ev.TargetType,
				TargetID:   ev.TargetID,
				Decision:   ev.Decision,
				Metadata:   []byte(meta),
				CreatedAt:  createdAt,
				PrevHash:   prevHash,
			}
			r.EntryHash = computeEntryHash(r)
			prevHash = r.EntryHash
			rows = append(rows, r)
		}
	}

	const colsPerRow = 12

	placeholders := make([]string, len(rows))
	args := make([]interface{}, 0, len(rows)*colsPerRow)

	for i, r := range rows {
		base := i * colsPerRow
		placeholders[i] = fmt.Sprintf(
			"($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)",
			base+1, base+2, base+3, base+4, base+5, base+6,
			base+7, base+8, base+9, base+10, base+11, base+12,
		)

		// decision is stored as NULL when the string is empty. The chain
		// hashes the empty string; VerifyChain COALESCEs the column back to
		// "" on read, so the two agree.
		var decision interface{}
		if r.Decision != "" {
			decision = r.Decision
		}

		args = append(args,
			r.TenantID,
			r.ActorID,
			r.ActorType,
			r.Action,
			r.TargetType,
			r.TargetID,
			decision,
			r.Metadata,
			r.CreatedAt,
			r.Seq,
			r.PrevHash,
			r.EntryHash,
		)
	}

	query := `INSERT INTO audit_log
		(tenant_id, actor_id, actor_type, action, target_type, target_id, decision, metadata,
		 created_at, chain_seq, prev_hash, entry_hash)
		VALUES ` + strings.Join(placeholders, ", ")

	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("audit: flush: INSERT audit_log (%d rows): %w", len(rows), err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("audit: flush: commit (%d rows): %w", len(rows), err)
	}
	committed = true
	return nil
}
