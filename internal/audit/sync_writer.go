// Package audit — sync_writer.go
//
// WriteSync is a strict, blocking variant of Log() for callers that MUST
// know an audit event was persisted before they take a security-relevant
// action.
//
// Background:
//
//   - The default Writer.Log() is best-effort: it enqueues the event into
//     a 1000-slot buffer and returns immediately. If the buffer is full,
//     the event is dropped and `gibson_audit_dropped_total` increments.
//     This is the right tradeoff for the daemon's general audit pipeline
//     (high volume, callers cannot afford to block on Postgres I/O).
//
//   - The dispatch policy gate (R3.5) and the OverrideDispatchPolicy RPC
//     (R3.4) need a stronger guarantee: the audit row MUST hit Postgres
//     before the gate's allow/deny decision, or before the RPC's success
//     reply, is observable. Otherwise an attacker who races the audit
//     pipeline could see a deny silently dropped and replay the request.
//
// WriteSync writes the single event in its own bulk-INSERT (using the
// same `flush` path as the batched writer) and surfaces backend errors to
// the caller — the dispatch path is responsible for translating an error
// into an outright deny rather than a quiet best-effort emit.
//
// The existing Writer.Log() signature is unchanged; non-dispatch paths
// keep best-effort semantics.
//
// Spec: setec-sandbox-prod-default §"Audit pipeline" (R3.5).

package audit

import (
	"context"
	"fmt"
)

// WriteSync persists a single audit event synchronously: the call returns
// only after the underlying database has acknowledged the INSERT, OR with
// an error.
//
// Behaviour contract:
//   - On success, the event is durably stored before WriteSync returns.
//   - On backend error, the error is returned (NOT swallowed). Callers
//     in security-relevant paths (dispatch gate) MUST treat a non-nil
//     error as audit pipeline failure and refuse the dispatch.
//   - WriteSync does NOT increment `gibson_audit_dropped_total` (it
//     never drops; either it succeeds or it errors). It does increment
//     `gibson_audit_events_total` on success so dashboards reflect the
//     synchronous events alongside the asynchronous ones.
//
// This method shares the underlying flush implementation with the
// batching writer's run loop — see flush() in writer.go.
func (w *Writer) WriteSync(ctx context.Context, event Event) error {
	if w == nil {
		return fmt.Errorf("audit: WriteSync called on nil Writer")
	}
	if w.db == nil {
		return fmt.Errorf("audit: WriteSync: writer has nil db")
	}
	if err := w.flush(ctx, []Event{event}); err != nil {
		return err
	}
	auditEventsTotal.WithLabelValues(event.Action).Inc()
	return nil
}
