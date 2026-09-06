// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — server_pending_tenant_provisioning.go
//
// Operator-pull tenant provisioning (E9, gibson#948, enables dashboard#813).
//
// The daemon owns a pending-provisioning queue in the platform Postgres
// (pending_tenant_provisioning, migration 016). The Signup handler enqueues one
// row per self-serve signup once it has provisioned the founding-owner Zitadel
// user (gibson#812). The tenant-operator drains the queue via
// ListPendingTenantProvisioning, creates the Tenant CR for each pending record
// (the same spec the dashboard used to write), and acks each via
// AckTenantProvisioned.
//
// ADR-0023: the daemon never touches Kubernetes. These handlers only read/write
// the platform Postgres queue; the operator (which holds `tenants` create RBAC)
// owns all Tenant-CR creation.
package api

import (
	"context"
	"database/sql"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/plans"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	"github.com/zeroroot-ai/gibson/pkg/billing/entitlements"
)

// enqueuePendingTenantProvisioning records a tenant awaiting Tenant-CR creation.
// Called by the Signup handler after the founding-owner Zitadel user is
// provisioned. Idempotent on tenant_id: a retry that re-enqueues the same
// tenant leaves an existing (possibly already-claimed/done) row untouched,
// mirroring the already_existed handling in the owner-provisioning path —
// re-creating it would risk re-provisioning a tenant the operator already built.
//
// Returns (false, nil) when no platform DB is configured: enqueue is best-effort
// in dev/kind where Postgres may be absent, and the caller logs rather than
// failing the signup.
func (s *DaemonServer) enqueuePendingTenantProvisioning(ctx context.Context, p *daemonoperatorv1.PendingTenant) (bool, error) {
	db := s.entitlementsDB()
	if db == nil {
		return false, nil
	}
	if err := ensurePendingTenantProvisioningTable(ctx, db); err != nil {
		return false, fmt.Errorf("ensure table: %w", err)
	}
	const q = `
		INSERT INTO pending_tenant_provisioning
			(tenant_id, owner_user_id, owner_email, workspace_name, tier, stripe_customer_id, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'pending', NOW(), NOW())
		ON CONFLICT (tenant_id) DO NOTHING
	`
	res, err := db.ExecContext(ctx, q,
		p.GetTenantId(), p.GetOwnerUserId(), p.GetOwnerEmail(),
		p.GetWorkspaceName(), p.GetTier(), p.GetStripeCustomerId(),
	)
	if err != nil {
		return false, fmt.Errorf("insert pending_tenant_provisioning: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ListPendingTenantProvisioning returns the queue of tenants awaiting Tenant-CR
// creation (status=pending). Operator-only (platform_operator on system_tenant,
// enforced by ext-authz). The daemon never reads Kubernetes here — it only
// returns queue rows for the operator to act on.
//
// # Billing gate
//
// This is the platform's read point for billing_active on the provisioning
// path. billing_active is recorded by the Stripe-webhook path
// (SetTenantBillingActive) and echoed to the operator by ReportTenantStatus,
// which stamps the gibson.zeroroot.ai/billing-active CR annotation from it —
// but before this gate NOTHING consumed either the column or the annotation,
// so a paid-tier tenant provisioned whether or not it was ever paid for.
//
// When the deployment enforces entitlements (GIBSON_ENTITLEMENTS_REQUIRED=true,
// the SaaS overlay) a pending row whose plan is paid is WITHHELD from the drain
// until billing_active is true. Withheld rows are left in the queue at
// status='pending' and logged, so they drain automatically on the next operator
// poll after billing activates — nothing is dropped, and a stalled tenant is
// visible in the daemon log rather than silently provisioned for free.
//
// A pending row whose tier does not resolve to a canonical plan is also
// withheld: an unrecognised tier cannot be priced, so it fails closed.
//
// Self-hosted installs leave GIBSON_ENTITLEMENTS_REQUIRED unset and are
// unaffected (ADR-0006: the billing seam is bypassable on-prem by design).
func (s *DaemonServer) ListPendingTenantProvisioning(ctx context.Context, _ *daemonoperatorv1.ListPendingTenantProvisioningRequest) (*daemonoperatorv1.ListPendingTenantProvisioningResponse, error) {
	db := s.entitlementsDB()
	if db == nil {
		return nil, status.Error(codes.Unavailable, "platform Postgres not configured")
	}
	if err := ensurePendingTenantProvisioningTable(ctx, db); err != nil {
		return nil, status.Errorf(codes.Internal, "ensure table: %v", err)
	}
	// tenant_status is joined below; make sure it exists on a freshly-pointed
	// DB for the same reason the pending table is ensured above.
	if err := ensureTenantStatusTable(ctx, db); err != nil {
		return nil, status.Errorf(codes.Internal, "ensure table: %v", err)
	}
	// LEFT JOIN so a tenant the operator has not reported on yet (no
	// tenant_status row) reads as billing_active=false rather than vanishing
	// from the queue.
	const q = `
		SELECT p.tenant_id, p.owner_user_id, p.owner_email, p.workspace_name, p.tier,
		       p.stripe_customer_id, COALESCE(s.billing_active, FALSE)
		FROM pending_tenant_provisioning p
		LEFT JOIN tenant_status s ON s.tenant_id = p.tenant_id
		WHERE p.status = 'pending'
		ORDER BY p.created_at ASC
	`
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "query pending_tenant_provisioning: %v", err)
	}
	defer func() { _ = rows.Close() }()

	enforceBilling := entitlements.Required()

	out := &daemonoperatorv1.ListPendingTenantProvisioningResponse{}
	for rows.Next() {
		var (
			p             daemonoperatorv1.PendingTenant
			billingActive bool
		)
		if err := rows.Scan(
			&p.TenantId, &p.OwnerUserId, &p.OwnerEmail,
			&p.WorkspaceName, &p.Tier, &p.StripeCustomerId,
			&billingActive,
		); err != nil {
			return nil, status.Errorf(codes.Internal, "scan pending row: %v", err)
		}
		if reason, withhold := withholdPendingTenant(p.GetTier(), billingActive, enforceBilling); withhold {
			s.logger.Warn("pending tenant withheld from provisioning drain",
				"tenant_id", p.GetTenantId(),
				"tier", p.GetTier(),
				"reason", reason,
			)
			continue
		}
		out.Pending = append(out.Pending, &p)
	}
	if err := rows.Err(); err != nil {
		return nil, status.Errorf(codes.Internal, "iterate pending rows: %v", err)
	}
	return out, nil
}

// withholdPendingTenant decides whether one queued tenant may be handed to the
// operator, returning a human-readable reason when it may not.
//
// It is a pure function so the decision table is unit-testable without a
// database. enforceBilling is entitlements.Required() at the call site.
func withholdPendingTenant(tier string, billingActive, enforceBilling bool) (reason string, withhold bool) {
	if !enforceBilling {
		// Self-hosted / OSS: no billing to enforce (ADR-0006).
		return "", false
	}
	plan, ok := plans.Lookup(tier)
	if !ok {
		return "tier does not resolve to a canonical plan", true
	}
	if plan.Paid && !billingActive {
		return "paid plan without an active billing record", true
	}
	return "", false
}

// AckTenantProvisioned marks a pending record done after the operator has
// ensured the Tenant CR exists. Operator-only. Idempotent: acking an unknown or
// already-done tenant_id returns acked=false with no error.
//
// gibsoncheck:allow tenant-from-request — DaemonOperatorService: platform_operator on
// system_tenant at ext-authz, plus the SPIFFE peer allowlist.
func (s *DaemonServer) AckTenantProvisioned(ctx context.Context, req *daemonoperatorv1.AckTenantProvisionedRequest) (*daemonoperatorv1.AckTenantProvisionedResponse, error) {
	db := s.entitlementsDB()
	if db == nil {
		return nil, status.Error(codes.Unavailable, "platform Postgres not configured")
	}
	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id required")
	}
	if err := ensurePendingTenantProvisioningTable(ctx, db); err != nil {
		return nil, status.Errorf(codes.Internal, "ensure table: %v", err)
	}
	const q = `
		UPDATE pending_tenant_provisioning
		SET status = 'done', updated_at = NOW()
		WHERE tenant_id = $1 AND status <> 'done'
	`
	res, err := db.ExecContext(ctx, q, req.GetTenantId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "update pending_tenant_provisioning: %v", err)
	}
	n, _ := res.RowsAffected()
	return &daemonoperatorv1.AckTenantProvisionedResponse{Acked: n > 0}, nil
}

// ensurePendingTenantProvisioningTable creates pending_tenant_provisioning if it
// does not yet exist. Mirrors ensureTenantZitadelOrgsTable: migration 016 is
// authoritative, but this keeps the RPC working on a freshly-pointed DB before
// migrations run.
func ensurePendingTenantProvisioningTable(ctx context.Context, db *sql.DB) error {
	const create = `
		CREATE TABLE IF NOT EXISTS pending_tenant_provisioning (
			tenant_id          TEXT PRIMARY KEY,
			owner_user_id      TEXT NOT NULL DEFAULT '',
			owner_email        TEXT NOT NULL,
			workspace_name     TEXT NOT NULL,
			tier               TEXT NOT NULL,
			stripe_customer_id TEXT NOT NULL DEFAULT '',
			status             TEXT NOT NULL DEFAULT 'pending'
				CONSTRAINT pending_tenant_provisioning_status_check
				CHECK (status IN ('pending', 'claimed', 'done')),
			created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`
	if _, err := db.ExecContext(ctx, create); err != nil {
		return fmt.Errorf("create pending_tenant_provisioning: %w", err)
	}
	return nil
}

// EnqueueTenantProvisioning inserts a first-tenant provisioning op into the
// pending_tenant_provisioning queue, on the WORKLOAD-AUTHENTICATED operator
// surface (gibson#1496). It is the session-less equivalent of
// gibson.tenant.v1.AdminTenantService/AdminProvisionTenant: that RPC is gated
// by a session-revocation check only an interactive human login satisfies, so
// a headless self-hosted install cannot use it. This one lets the
// tenant-operator seed the FIRST tenant with its own SPIFFE identity, after
// which the existing ListPendingTenantProvisioning drain provisions it exactly
// as a signup-originated tenant (Tenant CR + Zitadel org).
//
// owner_user_id is deliberately empty: no Zitadel user exists yet. The Tenant
// CR's owner is the email, and bootstrap-tenant-owner creates the owner user +
// FGA tuple afterwards. Idempotent on tenant_id via the helper's ON CONFLICT.
// gibsoncheck:allow tenant-from-request — DaemonOperatorService:
// platform_operator on system_tenant, enforced at ext-authz (same rule as the
// ListPendingTenantProvisioning sibling). The tenant is caller-supplied by
// design: this seeds a NEW tenant that does not exist yet, so there is no
// context tenant to read.
func (s *DaemonServer) EnqueueTenantProvisioning(ctx context.Context, req *daemonoperatorv1.EnqueueTenantProvisioningRequest) (*daemonoperatorv1.EnqueueTenantProvisioningResponse, error) {
	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id required")
	}
	if req.GetOwnerEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "owner_email required")
	}
	tier := req.GetTier()
	if tier == "" {
		tier = defaultProvisionTier
	}
	inserted, err := s.enqueuePendingTenantProvisioning(ctx, &daemonoperatorv1.PendingTenant{
		TenantId:      req.GetTenantId(),
		OwnerEmail:    req.GetOwnerEmail(),
		WorkspaceName: req.GetDisplayName(),
		Tier:          tier,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "enqueue tenant provisioning: %v", err)
	}
	return &daemonoperatorv1.EnqueueTenantProvisioningResponse{AlreadyExisted: !inserted}, nil
}
