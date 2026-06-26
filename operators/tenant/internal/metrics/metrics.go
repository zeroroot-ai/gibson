// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package metrics registers Prometheus metrics used by every Gibson
// CRD controller. Metrics are published at controller-runtime's default
// metrics endpoint (port 8080 by default).
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// ReconcileDuration is a histogram of reconcile durations per CRD kind.
	ReconcileDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "gibson_tenant_reconcile_duration_seconds",
			Help:    "Duration of tenant-operator reconcile calls in seconds, labeled by CRD kind and outcome.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"kind", "outcome"},
	)

	// ReconcileErrors counts reconcile errors per CRD kind.
	ReconcileErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gibson_tenant_reconcile_errors_total",
			Help: "Number of tenant-operator reconcile errors, labeled by CRD kind and error class.",
		},
		[]string{"kind", "class"},
	)

	// PhaseGauge is the current count of CRs per phase per kind.
	PhaseGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gibson_tenant_phase_total",
			Help: "Number of CRs in each lifecycle phase, labeled by CRD kind and phase.",
		},
		[]string{"kind", "phase"},
	)

	// SubsystemCallDuration measures subsystem client call latency.
	SubsystemCallDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "gibson_tenant_subsystem_call_duration_seconds",
			Help:    "Duration of subsystem client calls in seconds, labeled by subsystem and operation.",
			Buckets: prometheus.ExponentialBuckets(0.005, 2, 12),
		},
		[]string{"subsystem", "operation"},
	)

	// SubsystemCallErrors counts subsystem errors.
	SubsystemCallErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gibson_tenant_subsystem_call_errors_total",
			Help: "Number of subsystem client errors, labeled by subsystem, operation, and error class.",
		},
		[]string{"subsystem", "operation", "class"},
	)

	// SagaStepDuration measures per-step execution time inside a saga run.
	SagaStepDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "gibson_tenant_saga_step_duration_seconds",
			Help:    "Duration of individual saga steps in seconds, labeled by step name, CRD kind, and outcome.",
			Buckets: prometheus.ExponentialBuckets(0.005, 2, 12),
		},
		[]string{"step", "kind", "outcome"},
	)

	// StripeDriftTotal counts billing state mismatches detected by the nightly
	// drift reconciler. The `field` label indicates which field drifted
	// (status, priceId, currentPeriodEnd). No auto-correction for the first
	// 30 days per spec stripe-billing-integration R10.2.
	StripeDriftTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gibson_stripe_drift_total",
			Help: "Number of billing state mismatches detected by the nightly drift reconciler, labeled by field.",
		},
		[]string{"field"},
	)

	// MigrationPending tracks, per-tenant per-subsystem, whether the tenant's
	// data-plane schema version is behind the latest embedded migration files.
	// Value is 1 when behind, 0 when current. Subsystem label values are
	// "postgres" and "neo4j". Emitted at the end of every successful Ready
	// reconcile of a Tenant CR — replaces the daemon's previous startup
	// emission per ADR-0023 (gibson#208 S6 / gibson#202 PRD).
	MigrationPending = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gibson_tenant_migration_pending",
			Help: "1 if the tenant's data-plane schema version is behind the latest local migration, 0 if current. Labeled by tenant and subsystem (postgres|neo4j).",
		},
		[]string{"tenant", "subsystem"},
	)
)

// Register wires all metrics into controller-runtime's registry. Safe to
// call multiple times (idempotent — already-registered errors are ignored).
func Register() {
	metrics.Registry.MustRegister(
		ReconcileDuration,
		ReconcileErrors,
		PhaseGauge,
		SubsystemCallDuration,
		SubsystemCallErrors,
		SagaStepDuration,
		StripeDriftTotal,
		MigrationPending,
	)
}
