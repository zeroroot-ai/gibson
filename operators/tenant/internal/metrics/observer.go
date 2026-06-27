// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package metrics

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
)

// ClassifyError maps a sentinel client error to the bounded label set accepted
// by gibson_tenant_subsystem_call_errors_total{class}.
//
// Mapping:
//
//	context.DeadlineExceeded / ErrUnreachable (timeout) → "timeout"
//	ErrAlreadyExists / ErrConflict             → "conflict"
//	ErrInvalidInput / ErrUnauthorized          → "validation"
//	ErrUnreachable (network)                   → "unreachable"
//	Postgres SQLSTATE XX000 / 40001 / 40P01    → "unreachable" (transient)
//	anything else                              → "unknown"
func ClassifyError(err error) string {
	if err == nil {
		return "ok"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, clients.ErrAlreadyExists) || errors.Is(err, clients.ErrConflict) {
		return "conflict"
	}
	if errors.Is(err, clients.ErrInvalidInput) || errors.Is(err, clients.ErrUnauthorized) {
		return "validation"
	}
	if errors.Is(err, clients.ErrUnreachable) || errors.Is(err, clients.ErrRateLimited) {
		return "unreachable"
	}
	if isTransientPostgresError(err) {
		return "unreachable"
	}
	return "unknown"
}

// isTransientPostgresError reports whether err is a Postgres error that should
// be retried (transient class, not permanent). Covers the SQLSTATE codes the
// tenant-operator's saga has observed under concurrent reconciles:
//
//   - XX000 "tuple concurrently deleted" — internal_error raised when two
//     transactions touch the same catalog row (pg_authid, pg_db_role_setting);
//     the second transaction sees the first one's commit invalidate its row
//     reference. Self-resolves on retry. (issue #48)
//   - 40001 serialization_failure — concurrent updates on a SERIALIZABLE
//     transaction; retry per Postgres docs.
//   - 40P01 deadlock_detected — Postgres aborted one of the participants;
//     retry per Postgres docs.
//
// The "tuple concurrently deleted" message check is belt-and-suspenders for
// older Postgres versions that emit the message without setting Code.
func isTransientPostgresError(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "XX000", "40001", "40P01":
			return true
		}
	}
	if err != nil && strings.Contains(err.Error(), "tuple concurrently deleted") {
		return true
	}
	return false
}

// ObserveSubsystemCall records a subsystem client call into the two shared
// histograms / counters. Call it after every external subsystem operation:
//
//	start := time.Now()
//	err := client.DoSomething(ctx, ...)
//	metrics.ObserveSubsystemCall("fga", "CreateOrganization", start, err)
//
// The duration is always recorded. The error counter is incremented only when
// err != nil (nil → no counter bump).
func ObserveSubsystemCall(subsystem, op string, start time.Time, err error) {
	elapsed := time.Since(start).Seconds()
	SubsystemCallDuration.WithLabelValues(subsystem, op).Observe(elapsed)
	if err != nil {
		class := ClassifyError(err)
		SubsystemCallErrors.WithLabelValues(subsystem, op, class).Inc()
	}
}

// ObserveStep records a single saga step execution into the per-step histogram.
// kind is the CRD kind (e.g. "Tenant"), step is the step name (e.g.
// "CreateOrganization"), and outcome is "ok" | "error" | "skipped" |
// "inprogress".
func ObserveStep(step, kind string, start time.Time, outcome string) {
	elapsed := time.Since(start).Seconds()
	SagaStepDuration.WithLabelValues(step, kind, outcome).Observe(elapsed)
}
