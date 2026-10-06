// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// FinalBackupFailures counts each delete pass in which the last backup of a
// tenant did not complete. While it grows, a tenant delete is stopped and has
// removed nothing. The reason label is one of: read_namespace, audit, create,
// read, backup_failed, timeout.
var FinalBackupFailures = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "gibson_tenant_operator_final_backup_failures_total",
		Help: "Number of tenant delete passes that stopped because the last backup of the tenant did not complete, by reason.",
	},
	[]string{"reason"},
)

func init() {
	metrics.Registry.MustRegister(FinalBackupFailures)
}
