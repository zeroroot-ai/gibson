// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

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
