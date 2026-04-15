// Package audit — writer.go
//
// Writer is an asynchronous, batching writer for Postgres-backed audit events.
// Callers invoke Log() which is guaranteed to be non-blocking — if the internal
// buffer is full the event is dropped and a Prometheus counter is incremented.
//
// Background flush goroutine:
//   - Accumulates events into a batch.
//   - Flushes when the batch reaches batchSize (100) OR the ticker fires (every
//     second), whichever comes first.
//   - Flush is a single parameterised bulk INSERT.
//
// Lifecycle:
//
//	w := audit.NewWriter(db, logger)
//	w.Start(ctx)
//	defer w.Stop(ctx)
//
// Prometheus metrics:
//
//	gibson_audit_events_total{action}   — events successfully enqueued
//	gibson_audit_dropped_total          — events dropped due to full buffer
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
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
)

// ---------------------------------------------------------------------------
// Prometheus metrics (package-level, registered once per process)
// ---------------------------------------------------------------------------

var (
	metricsOnce       sync.Once
	auditEventsTotal  *prometheus.CounterVec
	auditDroppedTotal prometheus.Counter
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
				Help: "Total number of audit events dropped because the write buffer was full.",
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

// Writer batches audit events and flushes them asynchronously to Postgres.
//
// Writer is safe for concurrent use. Log() never blocks the caller.
type Writer struct {
	db     *sql.DB
	buffer chan Event
	logger *slog.Logger
	done   chan struct{}
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
		db:     db,
		buffer: make(chan Event, writerBufferSize),
		logger: logger.With("component", "audit.writer"),
		done:   make(chan struct{}),
	}
}

// Log enqueues an audit event for asynchronous persistence.
//
// Log never blocks: if the internal buffer is full the event is silently
// dropped and the gibson_audit_dropped_total counter is incremented.
func (w *Writer) Log(event Event) {
	select {
	case w.buffer <- event:
		auditEventsTotal.WithLabelValues(event.Action).Inc()
	default:
		auditDroppedTotal.Inc()
		w.logger.Warn("audit: buffer full, dropping event",
			slog.String("action", event.Action),
			slog.String("tenant_id", event.TenantID),
		)
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
// until the goroutine exits or ctx is cancelled.
func (w *Writer) Stop(ctx context.Context) {
	// Closing the channel signals run() to drain and exit.
	close(w.buffer)
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
			w.logger.Error("audit: flush failed",
				slog.Int("batch_size", len(batch)),
				slog.String("error", err.Error()),
			)
		}
		// Reset without reallocating.
		batch = batch[:0]
	}

	for {
		select {
		case event, ok := <-w.buffer:
			if !ok {
				// Channel closed: drain remaining and exit.
				flush()
				return
			}
			batch = append(batch, event)
			if len(batch) >= batchSize {
				flush()
			}

		case <-ticker.C:
			flush()

		case <-ctx.Done():
			// Context cancelled: drain what's left in the buffer, then exit.
			for {
				select {
				case event, ok := <-w.buffer:
					if !ok {
						flush()
						return
					}
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
	}
}

// flush writes batch to Postgres in a single parameterised multi-row INSERT.
//
// Each event maps to 8 columns; created_at is omitted and defaults to now()
// as defined in the DDL.
func (w *Writer) flush(ctx context.Context, batch []Event) error {
	if len(batch) == 0 {
		return nil
	}

	const colsPerRow = 8

	placeholders := make([]string, len(batch))
	args := make([]interface{}, 0, len(batch)*colsPerRow)

	for i, ev := range batch {
		base := i * colsPerRow
		placeholders[i] = fmt.Sprintf(
			"($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)",
			base+1, base+2, base+3, base+4,
			base+5, base+6, base+7, base+8,
		)

		actorType := ev.ActorType
		if actorType == "" {
			actorType = "user"
		}

		meta := ev.Metadata
		if len(meta) == 0 {
			meta = json.RawMessage("{}")
		}

		// decision is stored as NULL when the string is empty.
		var decision interface{}
		if ev.Decision != "" {
			decision = ev.Decision
		}

		args = append(args,
			ev.TenantID,
			ev.ActorID,
			actorType,
			ev.Action,
			ev.TargetType,
			ev.TargetID,
			decision,
			[]byte(meta),
		)
	}

	query := `INSERT INTO audit_log
		(tenant_id, actor_id, actor_type, action, target_type, target_id, decision, metadata)
		VALUES ` + strings.Join(placeholders, ", ")

	if _, err := w.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("audit: flush: INSERT audit_log (%d rows): %w", len(batch), err)
	}
	return nil
}
