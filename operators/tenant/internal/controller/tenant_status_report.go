// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// tenant_status_report.go — operator → daemon Tenant status report-back
// (E9, gibson#948, enables dashboard#813).
//
// With the dashboard losing all Kubernetes access (dashboard#813) it can no
// longer read the Tenant CR status to drive onboarding and signup-status
// surfaces. The daemon cannot read the CR either (ADR-0023). So the operator —
// the one component that watches Tenant CRs — REPORTS the observed status into
// the daemon (DaemonOperatorService.ReportTenantStatus); the daemon serves it
// back to the dashboard via TenantProvisioningService.GetTenantProvisioningStatus.
//
// The platform holds no billing state (ADR-0060, D54). Tenant activation is a
// neutral signal that the daemon owns; the operator does not read or stamp it.

package controller

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/log"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/provision"
)

// TenantStatusReporter reports observed Tenant status to the daemon.
// provision.EntitlementsGRPCClient satisfies it; tests pass a stub. It is
// ALWAYS non-nil on the reconcile path: main.go injects
// NoopTenantStatusReporter when the operator boots without a daemon address
// (GIBSON_DAEMON_GRPC_ADDRESS unset), so report-back is disabled by
// substituting a no-op rather than a nil-guard (no graceful-nil in the
// reconcile path — production-readiness [[0003]]).
type TenantStatusReporter interface {
	ReportTenantStatus(ctx context.Context, r provision.TenantStatusReport) error
}

// NoopTenantStatusReporter is the report-back-disabled implementation injected
// when the operator has no daemon address. It reports nothing, so
// reportStatusToDaemon becomes a cheap local no-op without a nil dependency.
type NoopTenantStatusReporter struct{}

// ReportTenantStatus does nothing.
func (NoopTenantStatusReporter) ReportTenantStatus(context.Context, provision.TenantStatusReport) error {
	return nil
}

// reportStatusToDaemon pushes the Tenant's observed status into the daemon so
// the dashboard can read it without Kubernetes access. Best-effort: a daemon
// blip logs and returns; it never fails the reconcile. StatusReporter is
// always non-nil (NoopTenantStatusReporter when report-back is disabled).
func (r *TenantReconciler) reportStatusToDaemon(ctx context.Context, tenant *gibsonv1alpha1.Tenant) {
	logger := log.FromContext(ctx).WithName("tenant-status-report")
	err := r.StatusReporter.ReportTenantStatus(ctx, provision.TenantStatusReport{
		TenantID:       tenant.Name,
		Phase:          string(tenant.Status.Phase),
		DataPlaneReady: tenant.Status.DataPlane.Ready,
		StorePostgres:  tenant.Status.DataPlane.Stores.Postgres.State,
		StoreRedis:     tenant.Status.DataPlane.Stores.Redis.State,
		StoreNeo4j:     tenant.Status.DataPlane.Stores.Neo4j.State,
		ZitadelOrgSlug: tenant.Status.ZitadelOrgSlug,
	})
	if err != nil {
		logger.Info("report tenant status to daemon failed (best-effort)", "tenant", tenant.Name, "err", err.Error())
	}
}

// reportTeardownToDaemon tells the daemon that a tenant is in teardown or is
// gone. It reports the given phase and a data plane that is not ready, so no
// reader of tenant_status serves the tenant again. Best-effort, as
// reportStatusToDaemon is: the deletion path reports on every pass, so a
// daemon blip on one pass is repaired by the next.
func (r *TenantReconciler) reportTeardownToDaemon(ctx context.Context, tenant *gibsonv1alpha1.Tenant, phase gibsonv1alpha1.TenantPhase) {
	logger := log.FromContext(ctx).WithName("tenant-status-report")
	err := r.StatusReporter.ReportTenantStatus(ctx, provision.TenantStatusReport{
		TenantID:       tenant.Name,
		Phase:          string(phase),
		DataPlaneReady: false,
		StorePostgres:  tenant.Status.DataPlane.Stores.Postgres.State,
		StoreRedis:     tenant.Status.DataPlane.Stores.Redis.State,
		StoreNeo4j:     tenant.Status.DataPlane.Stores.Neo4j.State,
		ZitadelOrgSlug: tenant.Status.ZitadelOrgSlug,
	})
	if err != nil {
		logger.Info("report tenant teardown to daemon failed (best-effort)", "tenant", tenant.Name, "phase", string(phase), "err", err.Error())
	}
}
