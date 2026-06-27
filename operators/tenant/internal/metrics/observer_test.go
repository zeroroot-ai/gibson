// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package metrics_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/metrics"
)

// counterValue returns the current value of a CounterVec label combination by
// reading the underlying dto.Metric directly — no need for the full registry.
func counterValue(t *testing.T, cv *prometheus.CounterVec, labels ...string) float64 {
	t.Helper()
	m := &dto.Metric{}
	c, err := cv.GetMetricWithLabelValues(labels...)
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues(%v): %v", labels, err)
	}
	if err := c.Write(m); err != nil {
		t.Fatalf("Write metric: %v", err)
	}
	return m.Counter.GetValue()
}

// histogramSampleCount returns the cumulative sample count for a HistogramVec
// label combination.
func histogramSampleCount(t *testing.T, hv *prometheus.HistogramVec, labels ...string) uint64 {
	t.Helper()
	m := &dto.Metric{}
	obs, err := hv.GetMetricWithLabelValues(labels...)
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues(%v): %v", labels, err)
	}
	if err := obs.(prometheus.Metric).Write(m); err != nil {
		t.Fatalf("Write metric: %v", err)
	}
	return m.Histogram.GetSampleCount()
}

// ---------------------------------------------------------------------------
// ClassifyError
// ---------------------------------------------------------------------------

func TestClassifyError_Nil(t *testing.T) {
	if got := metrics.ClassifyError(nil); got != "ok" {
		t.Errorf("nil: got %q, want %q", got, "ok")
	}
}

func TestClassifyError_Timeout(t *testing.T) {
	if got := metrics.ClassifyError(context.DeadlineExceeded); got != "timeout" {
		t.Errorf("DeadlineExceeded: got %q, want %q", got, "timeout")
	}
}

func TestClassifyError_Conflict_AlreadyExists(t *testing.T) {
	wrapped := fmt.Errorf("upstream: %w", clients.ErrAlreadyExists)
	if got := metrics.ClassifyError(wrapped); got != "conflict" {
		t.Errorf("ErrAlreadyExists wrapped: got %q, want %q", got, "conflict")
	}
}

func TestClassifyError_Conflict_ErrConflict(t *testing.T) {
	wrapped := fmt.Errorf("upstream: %w", clients.ErrConflict)
	if got := metrics.ClassifyError(wrapped); got != "conflict" {
		t.Errorf("ErrConflict wrapped: got %q, want %q", got, "conflict")
	}
}

func TestClassifyError_Validation_InvalidInput(t *testing.T) {
	wrapped := fmt.Errorf("upstream: %w", clients.ErrInvalidInput)
	if got := metrics.ClassifyError(wrapped); got != "validation" {
		t.Errorf("ErrInvalidInput wrapped: got %q, want %q", got, "validation")
	}
}

func TestClassifyError_Validation_Unauthorized(t *testing.T) {
	wrapped := fmt.Errorf("upstream: %w", clients.ErrUnauthorized)
	if got := metrics.ClassifyError(wrapped); got != "validation" {
		t.Errorf("ErrUnauthorized wrapped: got %q, want %q", got, "validation")
	}
}

func TestClassifyError_Unreachable(t *testing.T) {
	wrapped := fmt.Errorf("upstream: %w", clients.ErrUnreachable)
	if got := metrics.ClassifyError(wrapped); got != "unreachable" {
		t.Errorf("ErrUnreachable wrapped: got %q, want %q", got, "unreachable")
	}
}

func TestClassifyError_RateLimited_MapsToUnreachable(t *testing.T) {
	wrapped := fmt.Errorf("upstream: %w", clients.ErrRateLimited)
	if got := metrics.ClassifyError(wrapped); got != "unreachable" {
		t.Errorf("ErrRateLimited wrapped: got %q, want %q", got, "unreachable")
	}
}

func TestClassifyError_Unknown(t *testing.T) {
	if got := metrics.ClassifyError(errors.New("some random internal error")); got != "unknown" {
		t.Errorf("unknown error: got %q, want %q", got, "unknown")
	}
}

// Postgres SQLSTATE classification (issue #48). XX000, 40001, and 40P01 are
// retryable; the saga's classifier must see them as "unreachable" (transient)
// rather than "unknown" so a single race doesn't promote them to Blocked.

func TestClassifyError_PostgresXX000_TupleConcurrentlyDeleted(t *testing.T) {
	pgErr := &pgconn.PgError{Code: "XX000", Message: "tuple concurrently deleted"}
	if got := metrics.ClassifyError(pgErr); got != "unreachable" {
		t.Errorf("SQLSTATE XX000: got %q, want %q", got, "unreachable")
	}
}

func TestClassifyError_PostgresSerializationFailure(t *testing.T) {
	pgErr := &pgconn.PgError{Code: "40001", Message: "could not serialize access due to concurrent update"}
	if got := metrics.ClassifyError(pgErr); got != "unreachable" {
		t.Errorf("SQLSTATE 40001: got %q, want %q", got, "unreachable")
	}
}

func TestClassifyError_PostgresDeadlockDetected(t *testing.T) {
	pgErr := &pgconn.PgError{Code: "40P01", Message: "deadlock detected"}
	if got := metrics.ClassifyError(pgErr); got != "unreachable" {
		t.Errorf("SQLSTATE 40P01: got %q, want %q", got, "unreachable")
	}
}

func TestClassifyError_PostgresWrapped(t *testing.T) {
	// The dataplane wraps with fmt.Errorf; the classifier must see through
	// the wrap via errors.As.
	pgErr := &pgconn.PgError{Code: "XX000"}
	wrapped := fmt.Errorf("dataplane/postgres: grant connect: %w", pgErr)
	if got := metrics.ClassifyError(wrapped); got != "unreachable" {
		t.Errorf("wrapped XX000: got %q, want %q", got, "unreachable")
	}
}

func TestClassifyError_TupleConcurrentlyDeletedMessageFallback(t *testing.T) {
	// Older Postgres versions or driver wrappers may surface the message
	// without setting Code. The fallback string match still classifies it.
	err := errors.New("postgres: tuple concurrently deleted")
	if got := metrics.ClassifyError(err); got != "unreachable" {
		t.Errorf("message-only fallback: got %q, want %q", got, "unreachable")
	}
}

func TestClassifyError_OtherPgErrorIsUnknown(t *testing.T) {
	// A non-transient SQLSTATE (e.g. permission_denied 42501) should NOT be
	// reclassified as unreachable.
	pgErr := &pgconn.PgError{Code: "42501", Message: "permission denied for database"}
	if got := metrics.ClassifyError(pgErr); got != "unknown" {
		t.Errorf("non-transient SQLSTATE: got %q, want %q", got, "unknown")
	}
}

// ---------------------------------------------------------------------------
// ObserveSubsystemCall
// ---------------------------------------------------------------------------

func TestObserveSubsystemCall_NoError_HistogramIncrements(t *testing.T) {
	before := histogramSampleCount(t, metrics.SubsystemCallDuration, "fga", "CreateOrganization")
	metrics.ObserveSubsystemCall("fga", "CreateOrganization", time.Now().Add(-time.Millisecond), nil)
	after := histogramSampleCount(t, metrics.SubsystemCallDuration, "fga", "CreateOrganization")
	if after != before+1 {
		t.Errorf("histogram count after nil error: got %d, want %d", after, before+1)
	}
}

func TestObserveSubsystemCall_WithError_BothHistogramAndCounter(t *testing.T) {
	errBefore := counterValue(t, metrics.SubsystemCallErrors, "fga", "AddMember", "unreachable")
	histBefore := histogramSampleCount(t, metrics.SubsystemCallDuration, "fga", "AddMember")

	metrics.ObserveSubsystemCall("fga", "AddMember", time.Now(), fmt.Errorf("net: %w", clients.ErrUnreachable))

	errAfter := counterValue(t, metrics.SubsystemCallErrors, "fga", "AddMember", "unreachable")
	histAfter := histogramSampleCount(t, metrics.SubsystemCallDuration, "fga", "AddMember")

	if errAfter != errBefore+1 {
		t.Errorf("error counter: got %f, want %f", errAfter, errBefore+1)
	}
	if histAfter != histBefore+1 {
		t.Errorf("histogram always recorded: got %d, want %d", histAfter, histBefore+1)
	}
}

func TestObserveSubsystemCall_NoError_CounterNotIncremented(t *testing.T) {
	// Use unique op name to avoid cross-test interference.
	before := counterValue(t, metrics.SubsystemCallErrors, "fga", "WriteNoErr", "unknown")
	metrics.ObserveSubsystemCall("fga", "WriteNoErr", time.Now(), nil)
	after := counterValue(t, metrics.SubsystemCallErrors, "fga", "WriteNoErr", "unknown")
	if after != before {
		t.Errorf("error counter must not increment on nil error: delta=%f", after-before)
	}
}

func TestObserveSubsystemCall_TimeoutClass(t *testing.T) {
	before := counterValue(t, metrics.SubsystemCallErrors, "stripe", "CreateCustomer", "timeout")
	metrics.ObserveSubsystemCall("stripe", "CreateCustomer", time.Now(), context.DeadlineExceeded)
	after := counterValue(t, metrics.SubsystemCallErrors, "stripe", "CreateCustomer", "timeout")
	if after != before+1 {
		t.Errorf("timeout class counter: got %f, want %f", after, before+1)
	}
}

func TestObserveSubsystemCall_ConflictClass(t *testing.T) {
	before := counterValue(t, metrics.SubsystemCallErrors, "stripe", "CreateCustomer", "conflict")
	metrics.ObserveSubsystemCall("stripe", "CreateCustomer", time.Now(), fmt.Errorf("dup: %w", clients.ErrAlreadyExists))
	after := counterValue(t, metrics.SubsystemCallErrors, "stripe", "CreateCustomer", "conflict")
	if after != before+1 {
		t.Errorf("conflict class counter: got %f, want %f", after, before+1)
	}
}

// ---------------------------------------------------------------------------
// ObserveStep
// ---------------------------------------------------------------------------

func TestObserveStep_OkOutcome(t *testing.T) {
	before := histogramSampleCount(t, metrics.SagaStepDuration, "CreateOrganization", "Tenant", "ok")
	metrics.ObserveStep("CreateOrganization", "Tenant", time.Now().Add(-time.Millisecond), "ok")
	after := histogramSampleCount(t, metrics.SagaStepDuration, "CreateOrganization", "Tenant", "ok")
	if after != before+1 {
		t.Errorf("step ok histogram: got %d, want %d", after, before+1)
	}
}

func TestObserveStep_ErrorOutcome(t *testing.T) {
	before := histogramSampleCount(t, metrics.SagaStepDuration, "DeleteTenant", "Tenant", "error")
	metrics.ObserveStep("DeleteTenant", "Tenant", time.Now(), "error")
	after := histogramSampleCount(t, metrics.SagaStepDuration, "DeleteTenant", "Tenant", "error")
	if after != before+1 {
		t.Errorf("step error histogram: got %d, want %d", after, before+1)
	}
}

func TestObserveStep_SkippedOutcome(t *testing.T) {
	before := histogramSampleCount(t, metrics.SagaStepDuration, "StripeSetup", "Tenant", "skipped")
	metrics.ObserveStep("StripeSetup", "Tenant", time.Now(), "skipped")
	after := histogramSampleCount(t, metrics.SagaStepDuration, "StripeSetup", "Tenant", "skipped")
	if after != before+1 {
		t.Errorf("step skipped histogram: got %d, want %d", after, before+1)
	}
}

// ---------------------------------------------------------------------------
// CollectAndCount sanity — ensures descriptors are valid Prometheus families.
// ---------------------------------------------------------------------------

func TestMetricDescriptors_CollectAndCount(t *testing.T) {
	// Prime each metric with at least one observation so Collect emits it.
	metrics.ObserveSubsystemCall("neo4j", "InitTenantScope", time.Now(), nil)
	metrics.ObserveStep("TestStep", "TestKind", time.Now(), "ok")
	metrics.ReconcileDuration.WithLabelValues("TestKind", "ok").Observe(0.001)
	metrics.ReconcileErrors.WithLabelValues("TestKind", "unknown").Inc()
	metrics.PhaseGauge.WithLabelValues("TestKind", "Ready").Set(1)

	for _, tc := range []struct {
		name string
		c    prometheus.Collector
	}{
		{"SubsystemCallDuration", metrics.SubsystemCallDuration},
		{"SubsystemCallErrors", metrics.SubsystemCallErrors},
		{"SagaStepDuration", metrics.SagaStepDuration},
		{"ReconcileDuration", metrics.ReconcileDuration},
		{"ReconcileErrors", metrics.ReconcileErrors},
		{"PhaseGauge", metrics.PhaseGauge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := testutil.CollectAndCount(tc.c)
			if n == 0 {
				t.Errorf("%s: CollectAndCount returned 0 metric families", tc.name)
			}
		})
	}
}
