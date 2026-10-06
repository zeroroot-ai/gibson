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
	"errors"
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
//
// hold, when not nil, puts the row in status 'waiting_step': the operator does
// not see it until the external signup step is done (signup_step.go).
func (s *DaemonServer) enqueuePendingTenantProvisioning(ctx context.Context, p *daemonoperatorv1.PendingTenant, hold *signupStepHold) (bool, error) {
	db := s.entitlementsDB()
	if db == nil {
		return false, nil
	}
	if err := ensurePendingTenantProvisioningTable(ctx, db); err != nil {
		return false, fmt.Errorf("ensure table: %w", err)
	}
	const q = `
		INSERT INTO pending_tenant_provisioning
			(tenant_id, owner_user_id, owner_email, workspace_name, tier, status,
			 attempt_id, step_token_hash, step_expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
		ON CONFLICT (tenant_id) DO NOTHING
	`
	queueStatus, attemptID, tokenHash := "pending", "", ""
	var expiresAt sql.NullTime
	if hold != nil {
		queueStatus, attemptID, tokenHash = "waiting_step", hold.attemptID, hold.tokenHash
		expiresAt = sql.NullTime{Time: hold.expiresAt, Valid: true}
	}
	res, err := db.ExecContext(ctx, q,
		p.GetTenantId(), p.GetOwnerUserId(), p.GetOwnerEmail(),
		p.GetWorkspaceName(), p.GetTier(), queueStatus,
		attemptID, tokenHash, expiresAt,
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
// # Gates
//
// Only rows in status 'pending' are listed. A signup that waits for the
// external signup step is in status 'waiting_step' or 'step_failed', so the
// operator does not see it until ConnectionPointService.CompleteSignupStep
// reports the step done (ADR-0060, D54).
//
// When the deployment enforces entitlements (GIBSON_ENTITLEMENTS_REQUIRED=true)
// a pending row whose tier does not resolve to a canonical plan is withheld:
// an unrecognised tier cannot be priced, so it fails closed. Withheld rows stay
// in the queue and are logged.
func (s *DaemonServer) ListPendingTenantProvisioning(ctx context.Context, _ *daemonoperatorv1.ListPendingTenantProvisioningRequest) (*daemonoperatorv1.ListPendingTenantProvisioningResponse, error) {
	db := s.entitlementsDB()
	if db == nil {
		return nil, status.Error(codes.Unavailable, "platform Postgres not configured")
	}
	if err := ensurePendingTenantProvisioningTable(ctx, db); err != nil {
		return nil, status.Errorf(codes.Internal, "ensure table: %v", err)
	}
	const q = `
		SELECT tenant_id, owner_user_id, owner_email, workspace_name, tier
		FROM pending_tenant_provisioning
		WHERE status = 'pending'
		ORDER BY created_at ASC
	`
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "query pending_tenant_provisioning: %v", err)
	}
	defer func() { _ = rows.Close() }()

	enforce := entitlements.Required()

	out := &daemonoperatorv1.ListPendingTenantProvisioningResponse{}
	for rows.Next() {
		var p daemonoperatorv1.PendingTenant
		if err := rows.Scan(
			&p.TenantId, &p.OwnerUserId, &p.OwnerEmail,
			&p.WorkspaceName, &p.Tier,
		); err != nil {
			return nil, status.Errorf(codes.Internal, "scan pending row: %v", err)
		}
		if reason, withhold := withholdPendingTenant(p.GetTier(), enforce); withhold {
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
// database. enforce is entitlements.Required() at the call site.
func withholdPendingTenant(tier string, enforce bool) (reason string, withhold bool) {
	if !enforce {
		// Self-hosted / OSS: no entitlements to enforce (ADR-0074).
		return "", false
	}
	if _, ok := plans.Lookup(tier); !ok {
		return "tier does not resolve to a canonical plan", true
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
	if _, err := db.ExecContext(ctx, q, req.GetTenantId()); err != nil {
		return nil, status.Errorf(codes.Internal, "update pending_tenant_provisioning: %v", err)
	}
	return &daemonoperatorv1.AckTenantProvisionedResponse{}, nil
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
			status             TEXT NOT NULL DEFAULT 'pending'
				CONSTRAINT pending_tenant_provisioning_status_check
				CHECK (status IN ('waiting_step', 'step_failed', 'pending', 'claimed', 'done')),
			attempt_id         TEXT NOT NULL DEFAULT '',
			step_token_hash    TEXT NOT NULL DEFAULT '',
			step_expires_at    TIMESTAMPTZ,
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
// A row that still waits in pending takes the values of this call
// (rewritePendingSeed), so the queue holds the current intent.
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
	}, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "enqueue tenant provisioning: %v", err)
	}
	if !inserted {
		if err := s.rewritePendingSeed(ctx, req.GetTenantId(), req.GetOwnerEmail(), req.GetDisplayName(), tier); err != nil {
			return nil, status.Errorf(codes.Internal, "rewrite pending tenant provisioning: %v", err)
		}
	}
	return &daemonoperatorv1.EnqueueTenantProvisioningResponse{AlreadyExisted: !inserted}, nil
}

// rewritePendingSeed makes a queued seed row match the current intent of the
// operator (gibson#219). The seed is the one writer of this row. A row that
// still waits in 'pending' with an older owner, name or tier gets the new
// values, so a chart fix reaches a cluster whose first row cannot provision.
// A row that the operator claimed or finished stays as it is: the tenant
// exists, and the queue no longer decides anything for it.
func (s *DaemonServer) rewritePendingSeed(ctx context.Context, tenantID, ownerEmail, workspaceName, tier string) error {
	db := s.entitlementsDB()
	if db == nil {
		return nil
	}
	const q = `
		WITH prev AS (
			SELECT tenant_id, owner_email, workspace_name, tier
			FROM pending_tenant_provisioning
			WHERE tenant_id = $1 AND status = 'pending'
			FOR UPDATE
		)
		UPDATE pending_tenant_provisioning p
		SET owner_email = $2, workspace_name = $3, tier = $4, updated_at = NOW()
		FROM prev
		WHERE p.tenant_id = prev.tenant_id
		  AND (prev.owner_email, prev.workspace_name, prev.tier) IS DISTINCT FROM ($2, $3, $4)
		RETURNING prev.tier, prev.owner_email, prev.workspace_name
	`
	var oldTier, oldEmail, oldName string
	err := db.QueryRowContext(ctx, q, tenantID, ownerEmail, workspaceName, tier).Scan(&oldTier, &oldEmail, &oldName)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("update pending_tenant_provisioning: %w", err)
	}
	s.logger.Warn("queued first tenant did not match the operator configuration; rewrote the pending row",
		"tenant_id", tenantID,
		"queued_tier", oldTier, "configured_tier", tier,
		"queued_owner_email", oldEmail, "configured_owner_email", ownerEmail,
		"queued_workspace_name", oldName, "configured_workspace_name", workspaceName,
	)
	return nil
}
