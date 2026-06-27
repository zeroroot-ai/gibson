// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// daemon_call.go — observability for the operator's calls to the daemon over
// SPIFFE-mTLS gRPC (provision.EntitlementsGRPCClient, ADR-0002).
//
// gibson#1043 was a SPIFFE-allowlist omission that made the daemon deny the
// operator's admin-ops drain (~every 15s). The failure was SILENT — log-only,
// no metric, no alert — so it went unnoticed until a user was stuck in the
// signup "no access to workspace" loop. DaemonCallErrors makes ANY
// operator->daemon call failure queryable so a future regression pages first
// (alert: TenantOperatorDaemonCallsFailing, deploy chart prometheusrule.yaml).
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// DaemonCallErrors counts operator->daemon gRPC call failures, labeled by the
// logical RPC method and the gRPC outcome. Any non-nil response from the
// operator's daemon client increments it; nil → no bump. A sustained nonzero
// rate on outcome="permission_denied" is the signature of the gibson#1043
// authorization regression.
var DaemonCallErrors = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "gibson_tenant_operator_daemon_call_errors_total",
		Help: "Number of operator->daemon gRPC call failures, labeled by RPC method and gRPC outcome (permission_denied|unauthenticated|unavailable|deadline_exceeded|invalid_argument|not_found|already_exists|failed_precondition|resource_exhausted|aborted|other|no_status).",
	},
	[]string{"method", "outcome"},
)

func init() {
	metrics.Registry.MustRegister(DaemonCallErrors)
}

// classifyGRPCOutcome maps a gRPC error onto the bounded, low-cardinality
// outcome label set. A non-status error (e.g. a transport failure that never
// produced a status) maps to "no_status"; any status code outside the
// enumerated set maps to "other".
func classifyGRPCOutcome(err error) string {
	st, ok := grpcstatus.FromError(err)
	if !ok {
		return "no_status"
	}
	switch st.Code() {
	case codes.PermissionDenied:
		return "permission_denied"
	case codes.Unauthenticated:
		return "unauthenticated"
	case codes.Unavailable:
		return "unavailable"
	case codes.DeadlineExceeded:
		return "deadline_exceeded"
	case codes.InvalidArgument:
		return "invalid_argument"
	case codes.NotFound:
		return "not_found"
	case codes.AlreadyExists:
		return "already_exists"
	case codes.FailedPrecondition:
		return "failed_precondition"
	case codes.ResourceExhausted:
		return "resource_exhausted"
	case codes.Aborted:
		return "aborted"
	default:
		return "other"
	}
}

// ObserveDaemonCallError records an operator->daemon gRPC call outcome. It is a
// no-op on success (err == nil), and otherwise increments DaemonCallErrors with
// the classified gRPC outcome. `method` is the logical RPC name (e.g.
// "list-pending-tenant-ops"). Pass the RAW gRPC error (before any sentinel
// wrapping) so the status code is recoverable.
func ObserveDaemonCallError(method string, err error) {
	if err == nil {
		return
	}
	DaemonCallErrors.WithLabelValues(method, classifyGRPCOutcome(err)).Inc()
}
