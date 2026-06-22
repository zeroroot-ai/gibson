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

// TeardownLeakedTotal counts external resources the teardown saga
// could not delete and explicitly left orphaned. Labeled by the
// resource backend (e.g. "zitadel_org",
// "openbao_namespace") and the underlying reason ("unauthorized",
// "not_found", "transport"). A non-zero rate is operator-visible
// signal that backend credentials/RBAC need attention.
var TeardownLeakedTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "gibson_tenant_operator_teardown_resource_leaked_total",
		Help: "Resources the teardown saga deliberately left orphaned. Labeled by backend and reason.",
	},
	[]string{"backend", "reason"},
)

func init() {
	metrics.Registry.MustRegister(TeardownLeakedTotal)
}
