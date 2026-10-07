// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package audit — writer.go
//
// Writer is the batching writer for the Postgres audit_log table. Postgres is
// the durable copy of each audit record.
//
// Background flush goroutine:
//   - Accumulates events into a batch.
//   - Flushes when the batch reaches batchSize (100) OR the ticker fires (every
//     second), whichever comes first.
//   - Flush extends each tenant's hash chain (chain.go) and issues a single
//     parameterised bulk INSERT inside one transaction.
//
// # An audit write never drops
//
// Log puts the event into a bounded queue. When the queue is full, Log
// blocks until there is room: a full queue slows the caller and drops
// nothing. When a flush fails, the writer keeps the batch and tries again
// with a backoff. During that time the queue fills and callers wait.
//
// A caller that changes state must not use Log. It uses WriteSync
// (sync_writer.go), which returns after Postgres has the record or returns
// an error, so the caller can fail its action.
//
// One loss remains. The queue is in memory, so a process that exits while
// Postgres does not answer loses the events that are still in the queue.
// The writer logs that loss at ERROR with the number of events.
//
// Each failed write increments gibson_audit_write_errors_total. Alert on it:
//
//	increase(gibson_audit_write_errors_total[5m]) > 0
//
// Lifecycle:
//
//	w := audit.NewWriter(db, logger)
//	w.Start(ctx)
//	defer w.Stop(ctx)
//
// Prometheus metrics:
//
//	gibson_audit_events_total{action}   — events accepted for writing
//	gibson_audit_write_errors_total     — failed writes to audit_log
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

	// minRetryBackoff and maxRetryBackoff bound the wait between two tries
	// of a batch that Postgres did not accept.
	minRetryBackoff = 500 * time.Millisecond
	maxRetryBackoff = 15 * time.Second

	// shutdownFlushTimeout bounds one write that the writer makes after it
	// was told to stop.
	shutdownFlushTimeout = 10 * time.Second
)

// ---------------------------------------------------------------------------
// Prometheus metrics (package-level, registered once per process)
// ---------------------------------------------------------------------------

var (
	metricsOnce           sync.Once
	auditEventsTotal      *prometheus.CounterVec
	auditWriteErrorsTotal prometheus.Counter
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
				Help: "Total number of audit events accepted for writing, by action.",
			},
			[]string{"action"},
		)
		auditWriteErrorsTotal = promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "gibson_audit_write_errors_total",
				Help: "Total number of failed writes to the Postgres audit_log table. Alert on any increase.",
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

}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

// Writer batches audit events and flushes them to Postgres, extending a
// per-tenant hash chain as it goes (chain.go).
//
// Writer is safe for concurrent use. Log blocks when the queue is full and
// drops nothing. See the package comment.
type Writer struct {
	db       *sql.DB
	buffer   chan Event
	logger   *slog.Logger
	done     chan struct{}
	stopping chan struct{}
	stopOnce sync.Once

	// minBackoff and maxBackoff bound the backoff between two tries of a
	// failed batch. Tests set shorter values.
	minBackoff time.Duration
	maxBackoff time.Duration
}

// NewWriter constructs a Writer. Both db and logger must be non-nil.
//
// Start the Writer before the first Log call. Log blocks on a full queue,
// and only the goroutine that Start launches makes room.
func NewWriter(db *sql.DB, logger *slog.Logger) *Writer {
	if db == nil {
		panic("audit.NewWriter: db must not be nil")
	}
	if logger == nil {
		panic("audit.NewWriter: logger must not be nil")
	}
	initMetrics()
	return &Writer{
		db:         db,
		buffer:     make(chan Event, writerBufferSize),
		logger:     logger.With("component", "audit.writer"),
		done:       make(chan struct{}),
		stopping:   make(chan struct{}),
		minBackoff: minRetryBackoff,
		maxBackoff: maxRetryBackoff,
	}
}

// Log queues an audit event for the next flush.
//
// When the queue is full, Log blocks until there is room. It drops nothing.
// Use Log for an event of a read. A caller that changes state uses WriteSync
// and fails its action on an error.
//
// After Stop, the flush goroutine is gone. Log then writes the event to
// Postgres itself before it returns.
func (w *Writer) Log(event Event) {
	// Checked in its own select first: a select with both a ready send and a
	// closed channel picks between them at random.
	auditEventsTotal.WithLabelValues(event.Action).Inc()
	select {
	case <-w.stopping:
		w.writeDirect(context.Background(), []Event{event})
		return
	default:
	}

	select {
	case w.buffer <- event:
	case <-w.stopping:
		w.writeDirect(context.Background(), []Event{event})
		return
	}

	// Stop can close the channel between the check and the send. The flush
	// goroutine may then have left before it saw this event. Take what is
	// still in the queue and write it here. Each queued event has exactly
	// one reader, so no event is written twice.
	select {
	case <-w.stopping:
		w.writeDirect(context.Background(), w.takeQueued())
	default:
	}
}

// takeQueued removes the events that are in the queue now and returns them.
func (w *Writer) takeQueued() []Event {
	var out []Event
	for {
		select {
		case ev := <-w.buffer:
			out = append(out, ev)
		default:
			return out
		}
	}
}

// writeDirect writes events to Postgres on the calling goroutine. The
// writer uses it after Stop, when no flush goroutine can retry. A failure
// here loses the events, and the log says so.
//
// The lifecycle context of the writer can be cancelled at this point, so
// each write runs under a context that ignores that cancel and has a
// timeout of its own.
func (w *Writer) writeDirect(parent context.Context, events []Event) {
	for start := 0; start < len(events); start += batchSize {
		batch := events[start:min(start+batchSize, len(events))]
		ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), shutdownFlushTimeout)
		err := w.flush(ctx, batch)
		cancel()
		if err != nil {
			w.writeError(batch, err, "the writer is stopped, these audit records are LOST")
		}
	}
}

// writeError records one failed write: the counter that the alert reads,
// and one ERROR log for the batch. One line for a batch keeps the log
// readable when Postgres is down.
func (w *Writer) writeError(batch []Event, err error, consequence string) {
	auditWriteErrorsTotal.Inc()
	if len(batch) == 0 {
		return
	}
	actions := make([]string, 0, len(batch))
	seen := make(map[string]struct{}, len(batch))
	for _, ev := range batch {
		if _, ok := seen[ev.Action]; ok {
			continue
		}
		seen[ev.Action] = struct{}{}
		actions = append(actions, ev.Action)
	}
	w.logger.Error("audit: write to audit_log failed",
		slog.String("consequence", consequence),
		slog.Int("batch_size", len(batch)),
		slog.String("actions", strings.Join(actions, ",")),
		slog.String("tenant_id", batch[0].TenantID),
		slog.String("error", err.Error()),
	)
}

// flushDurable writes batch to Postgres and returns after Postgres has it.
// When a write fails, it waits and tries again. The caller does not read the
// queue during that time, so the queue fills and Log callers wait.
//
// It gives up only when the writer stops. It then makes one last try and
// reports a loss if that try fails.
func (w *Writer) flushDurable(ctx context.Context, batch []Event) {
	backoff := w.minBackoff
	for {
		err := w.flush(ctx, batch)
		if err == nil {
			return
		}
		if ctx.Err() != nil {
			w.writeDirect(ctx, batch)
			return
		}
		w.writeError(batch, err, "the writer keeps the batch and tries again")

		timer := time.NewTimer(backoff)
		select {
		case <-timer.C:
		case <-w.stopping:
			timer.Stop()
			w.writeDirect(ctx, batch)
			return
		case <-ctx.Done():
			timer.Stop()
			w.writeDirect(ctx, batch)
			return
		}
		backoff = min(backoff*2, w.maxBackoff)
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
// events to be written, then returns.
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
		w.flushDurable(ctx, batch)
		// Reset without reallocating.
		batch = batch[:0]
	}

	// drainAndExit writes the batch in hand and what is in the queue. The
	// lifecycle context can be cancelled here, so each write gets a context
	// of its own. A Log call that races the stop writes its own event (see
	// Log), so a drain that does not block terminates.
	drainAndExit := func() {
		w.writeDirect(ctx, batch)
		w.writeDirect(ctx, w.takeQueued())
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
	_, err := w.insert(ctx, batch, false)
	return err
}

// insert is flush. With returnID it also returns the id of the one row of
// the batch, from INSERT ... RETURNING id.
func (w *Writer) insert(ctx context.Context, batch []Event, returnID bool) (int64, error) {
	if len(batch) == 0 {
		return 0, nil
	}

	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("audit: flush: begin transaction (%d rows): %w", len(batch), err)
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
			return 0, fmt.Errorf("audit: flush: lock chain for tenant %q: %w", tenant, err)
		}

		seq, prevHash, err := chainHead(ctx, tx, tenant)
		if err != nil {
			return 0, fmt.Errorf("audit: flush: %w", err)
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

	var id int64
	if returnID {
		if err := tx.QueryRowContext(ctx, query+" RETURNING id", args...).Scan(&id); err != nil {
			return 0, fmt.Errorf("audit: flush: INSERT audit_log (%d rows): %w", len(rows), err)
		}
	} else if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return 0, fmt.Errorf("audit: flush: INSERT audit_log (%d rows): %w", len(rows), err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("audit: flush: commit (%d rows): %w", len(rows), err)
	}
	committed = true
	return id, nil
}
