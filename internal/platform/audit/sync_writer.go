// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package audit — sync_writer.go
//
// WriteSync is the write for a caller that changes state. The caller must
// know that Postgres has the audit record before the action takes effect.
//
// Writer.Log queues the event and returns. It drops nothing, but it cannot
// tell the caller that a write failed. WriteSync writes the single event in
// its own transaction (the same flush path as the batching writer) and
// returns the backend error. The caller then fails its action.

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
//   - On backend error, the error is returned (NOT swallowed), and
//     gibson_audit_write_errors_total increments. The caller MUST fail its
//     action.
//   - On success it increments gibson_audit_events_total.
func (w *Writer) WriteSync(ctx context.Context, event Event) error {
	if w == nil {
		return fmt.Errorf("audit: WriteSync called on nil Writer")
	}
	if w.db == nil {
		return fmt.Errorf("audit: WriteSync: writer has nil db")
	}
	if err := w.flush(ctx, []Event{event}); err != nil {
		w.writeError([]Event{event}, err, "the caller gets the error and fails its action")
		return err
	}
	auditEventsTotal.WithLabelValues(event.Action).Inc()
	return nil
}
