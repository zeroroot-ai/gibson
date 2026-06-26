// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// tenant_status_report.go — operator → daemon Tenant status report-back
// (E9, gibson#948, enables dashboard#813).
//
// With the dashboard losing all Kubernetes access (dashboard#813) it can no
// longer read the Tenant CR status to drive onboarding / signup-status /
// billing surfaces, nor patch the billing-active annotation from the Stripe
// webhook. The daemon cannot read the CR either (ADR-0023). So the operator —
// the one component that watches Tenant CRs — REPORTS the observed status into
// the daemon (DaemonOperatorService.ReportTenantStatus); the daemon serves it
// back to the dashboard via TenantProvisioningService.GetTenantProvisioningStatus.
//
// The same RPC echoes back the dashboard-recorded billing-active flag (set via
// TenantProvisioningService.SetTenantBillingActive from the Stripe webhook), and
// the operator stamps the gibson.zeroroot.ai/billing-active CR annotation from
// it — so the (closed-tier) billing saga step that waits on that annotation is
// unchanged. billing-active thus has a single writer here, sourced from the
// daemon, never from the web tier's cluster credentials.

package controller

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/provision"
)

// AnnotationBillingActive is stamped on the Tenant CR once billing is active.
// Byte-identical to the dashboard's prior webhook patch value so the
// operator-stamped annotation is indistinguishable from the dashboard-stamped
// one the (closed-tier) billing saga step waits on (tenant_types.go).
const AnnotationBillingActive = "gibson.zeroroot.ai/billing-active"

// TenantStatusReporter reports observed Tenant status to the daemon and returns
// the dashboard-recorded billing-active flag. provision.EntitlementsGRPCClient
// satisfies it; tests pass a stub. It is ALWAYS non-nil on the reconcile path:
// main.go injects NoopTenantStatusReporter when the operator boots without a
// daemon address (GIBSON_DAEMON_GRPC_ADDRESS unset), so report-back is disabled
// by substituting a no-op rather than a nil-guard (no graceful-nil in the
// reconcile path — production-readiness [[0003]]).
type TenantStatusReporter interface {
	ReportTenantStatus(ctx context.Context, r provision.TenantStatusReport) (bool, error)
}

// NoopTenantStatusReporter is the report-back-disabled implementation injected
// when the operator has no daemon address. It reports nothing and never marks
// billing active, so reportStatusToDaemon becomes a cheap local no-op without a
// nil dependency.
type NoopTenantStatusReporter struct{}

// ReportTenantStatus does nothing and reports billing inactive.
func (NoopTenantStatusReporter) ReportTenantStatus(context.Context, provision.TenantStatusReport) (bool, error) {
	return false, nil
}

// reportStatusToDaemon pushes the Tenant's observed status into the daemon so
// the dashboard can read it without Kubernetes access, and stamps the
// billing-active annotation when the daemon reports billing active. Best-effort:
// a daemon blip logs and returns; it never fails the reconcile. StatusReporter
// is always non-nil (NoopTenantStatusReporter when report-back is disabled).
func (r *TenantReconciler) reportStatusToDaemon(ctx context.Context, tenant *gibsonv1alpha1.Tenant) {
	logger := log.FromContext(ctx).WithName("tenant-status-report")

	stripeID := tenant.Status.Billing.CustomerID
	if stripeID == "" {
		stripeID = tenant.Status.StripeCustomerID
	}
	billingActive, err := r.StatusReporter.ReportTenantStatus(ctx, provision.TenantStatusReport{
		TenantID:         tenant.Name,
		Phase:            string(tenant.Status.Phase),
		DataPlaneReady:   tenant.Status.DataPlane.Ready,
		StorePostgres:    tenant.Status.DataPlane.Stores.Postgres.State,
		StoreRedis:       tenant.Status.DataPlane.Stores.Redis.State,
		StoreNeo4j:       tenant.Status.DataPlane.Stores.Neo4j.State,
		ZitadelOrgSlug:   tenant.Status.ZitadelOrgSlug,
		StripeCustomerID: stripeID,
	})
	if err != nil {
		logger.Info("report tenant status to daemon failed (best-effort)", "tenant", tenant.Name, "err", err.Error())
		return
	}
	if billingActive {
		if err := r.ensureBillingActiveAnnotation(ctx, tenant); err != nil {
			logger.Info("stamp billing-active annotation failed (best-effort)", "tenant", tenant.Name, "err", err.Error())
		}
	}
}

// ensureBillingActiveAnnotation stamps gibson.zeroroot.ai/billing-active=true on
// the Tenant CR if not already present. Idempotent; a no-op once set, so it
// patches at most once per tenant.
func (r *TenantReconciler) ensureBillingActiveAnnotation(ctx context.Context, tenant *gibsonv1alpha1.Tenant) error {
	if tenant.Annotations[AnnotationBillingActive] == "true" {
		return nil
	}
	base := tenant.DeepCopy()
	if tenant.Annotations == nil {
		tenant.Annotations = map[string]string{}
	}
	tenant.Annotations[AnnotationBillingActive] = "true"
	if err := r.Patch(ctx, tenant, client.MergeFrom(base)); err != nil {
		return fmt.Errorf("patch billing-active annotation on tenant %q: %w", tenant.Name, err)
	}
	return nil
}
