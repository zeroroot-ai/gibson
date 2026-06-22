/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// OrphanFinalizersStrippedTotal counts finalizers removed by the reaper.
	// High rate indicates an upstream problem — see the
	// TenantOperatorOrphansAccumulating alert.
	OrphanFinalizersStrippedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gibson_tenant_operator_orphan_finalizers_stripped_total",
			Help: "Number of orphan finalizers stripped by the orphan reaper, labeled by kind and finalizer.",
		},
		[]string{"kind", "finalizer"},
	)

	// StuckTerminatingNamespaces is the current count of tenant namespaces
	// stuck in Terminating past the reaper grace period. Sampled every 30s.
	StuckTerminatingNamespaces = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "gibson_tenant_operator_stuck_terminating_namespaces",
			Help: "Current count of tenant-* namespaces that have been Terminating longer than the reaper grace period.",
		},
	)
)

func init() {
	metrics.Registry.MustRegister(
		OrphanFinalizersStrippedTotal,
		StuckTerminatingNamespaces,
	)
}
