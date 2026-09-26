// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package identity composes the per-tenant identity: the Zitadel organization
// the tenant's humans and machine accounts live under.
//
// It is a THIN orchestrator over the SAME client the Tenant provisioning saga
// uses today — zitadel.Client (CreateOrganization / GetOrganization /
// DeleteOrganization). It does NOT reinvent the Zitadel client; it exposes a
// single Provision/Deprovision surface (mirroring dataplane.Provisioner /
// secrets.Provisioner) so the declarative TenantIdentity controller and the
// imperative saga steps are two callers of ONE codepath (ADR-0027), not parallel
// reimplementations.
//
// The org-ensure / org-remove core (EnsureOrg / RemoveOrg) is exported so the
// Tenant saga's EnsureZitadelOrg / RemoveZitadelOrg steps call it too — exactly
// the shared-method extraction #802 did for the broker write. The saga steps
// keep their own saga-specific concerns (the RemoveZitadelOrg TenantMember
// precondition is K8s-list coupling that stays in the step); only the Zitadel
// client sequence lives here.
package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/zitadel"
)

// Provisioner is the narrow Provision/Deprovision surface the TenantIdentity
// controller delegates to. It mirrors dataplane.Provisioner / secrets.Provisioner
// so the controller pattern established by #801/#802 carries over unchanged. Both
// methods are idempotent: re-running for an already provisioned tenant is a
// no-op (drift is re-created), and Deprovision treats an already-gone org as
// success.
type Provisioner interface {
	// Provision ensures the per-tenant Zitadel organization exists, re-creating
	// it if it has drifted away. It returns the org's id and slug so the caller
	// can record them on status (the saga writes the same values to
	// Tenant.Status). Idempotent.
	Provision(ctx context.Context, req Request) (Result, error)

	// Deprovision tears down the per-tenant Zitadel organization. Idempotent: an
	// empty org id (never provisioned) or a not-found from Zitadel is success.
	Deprovision(ctx context.Context, orgID string) error
}

// Request is the per-tenant identity provisioning request. It carries exactly
// what the saga's EnsureZitadelOrg step passes to zitadel.CreateOrganization:
// the display name (org name) and the tenant id (slug).
type Request struct {
	// TenantID is the canonical tenant id, used as the Zitadel org slug.
	TenantID string
	// DisplayName is the human-readable org name. When empty the tenant id is
	// used (matching the saga's behaviour for tenants without a display name).
	DisplayName string
	// KnownOrgID, when non-empty, is the org id recorded on the last successful
	// provision. Provision verifies it still exists and re-creates on drift —
	// mirroring the saga's fast-path / fall-through.
	KnownOrgID string
}

// Result reports the org id and slug after a successful Provision.
type Result struct {
	OrgID string
	Slug  string
}

// New returns the production Provisioner wrapping the supplied Zitadel
// client. Both the client and projectID must be non-empty — either missing
// is operator misconfiguration and New panics so a misconfigured operator
// crash-loops at boot rather than silently no-op'ing identity provisioning
// (one-code-path). projectID is the gibson Zitadel project every tenant org
// is granted (ADR-0093 decision 2).
func New(z zitadel.Client, projectID string) Provisioner {
	if z == nil {
		panic("identity.New: zitadel client is nil (operator misconfigured)")
	}
	if projectID == "" {
		panic("identity.New: projectID is empty (operator misconfigured)")
	}
	return &provisioner{zitadel: z, projectID: projectID}
}

type provisioner struct {
	zitadel   zitadel.Client
	projectID string
}

// Provision ensures the per-tenant Zitadel org exists, and the gibson
// project is granted to it, by delegating to the shared EnsureOrg core.
func (p *provisioner) Provision(ctx context.Context, req Request) (Result, error) {
	return EnsureOrg(ctx, p.zitadel, p.projectID, req)
}

// Deprovision tears down the per-tenant Zitadel org by delegating to the shared
// RemoveOrg core — the SAME DeleteOrganization call the saga's RemoveZitadelOrg
// step runs (without the step's TenantMember precondition, which is saga-only).
func (p *provisioner) Deprovision(ctx context.Context, orgID string) error {
	return RemoveOrg(ctx, p.zitadel, orgID)
}

// EnsureOrg is the shared org-provisioning core called by BOTH the Tenant saga's
// EnsureZitadelOrg step and the identity.Provisioner, so there is exactly one
// Zitadel-org codepath (ADR-0027). It implements the saga's fast-path / drift
// re-create logic: if KnownOrgID is set and still resolves it returns unchanged;
// otherwise it creates the org. Either way, once the org exists it ensures the
// gibson project is granted to it with the four tenant roles (ADR-0093
// decision 2) — on the known-org path too, so a grant that drifted away (or
// never existed on an org provisioned before this project existed) is
// repaired on every reconcile. Permanent client errors are returned as-is so
// callers do not retry them.
func EnsureOrg(ctx context.Context, z zitadel.Client, projectID string, req Request) (Result, error) {
	if req.TenantID == "" {
		return Result{}, errors.New("identity.EnsureOrg: empty tenant id")
	}
	name := req.DisplayName
	if name == "" {
		name = req.TenantID
	}

	var orgID string

	// Fast path: org already provisioned — verify it still exists in Zitadel.
	if req.KnownOrgID != "" {
		_, err := z.GetOrganization(ctx, req.KnownOrgID)
		switch {
		case err == nil:
			orgID = req.KnownOrgID
		case !errors.Is(err, clients.ErrNotFound):
			if clients.IsPermanent(err) {
				return Result{}, err
			}
			return Result{}, fmt.Errorf("identity.EnsureOrg: GetOrganization: %w", err)
		}
		// Org is gone (ErrNotFound) — fall through to re-create.
	}

	if orgID == "" {
		created, err := z.CreateOrganization(ctx, name, req.TenantID)
		if err != nil {
			if clients.IsPermanent(err) {
				return Result{}, err
			}
			return Result{}, fmt.Errorf("identity.EnsureOrg: CreateOrganization: %w", err)
		}
		orgID = created
	}

	if err := z.EnsureProjectGrant(ctx, projectID, orgID, tenantrole.Keys()); err != nil {
		if clients.IsPermanent(err) {
			return Result{}, err
		}
		return Result{}, fmt.Errorf("identity.EnsureOrg: EnsureProjectGrant: %w", err)
	}
	return Result{OrgID: orgID, Slug: req.TenantID}, nil
}

// RemoveOrg is the shared org-teardown core called by BOTH the Tenant saga's
// RemoveZitadelOrg step and the identity.Provisioner. An empty org id (never
// provisioned) and a Zitadel not-found are both treated as success so teardown
// is idempotent.
func RemoveOrg(ctx context.Context, z zitadel.Client, orgID string) error {
	if orgID == "" {
		return nil
	}
	if err := z.DeleteOrganization(ctx, orgID); err != nil && !errors.Is(err, clients.ErrNotFound) {
		return fmt.Errorf("identity.RemoveOrg: DeleteOrganization: %w", err)
	}
	return nil
}
