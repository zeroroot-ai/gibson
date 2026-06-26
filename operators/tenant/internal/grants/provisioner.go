// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package grants composes the tenant-level platform FGA tuples — the
// relationships that register a tenant under the platform's system tenant so
// the daemon's catalog fan-out can see it (deploy#782 / gibson#715).
//
// It is a THIN orchestrator over the SAME fga.Client the Tenant provisioning
// saga uses today (the RegisterTenantWithPlatform step). It does NOT reinvent
// the OpenFGA client; it exposes a single Provision/Deprovision surface
// (mirroring secrets.Provisioner and identity.Provisioner) so the declarative
// TenantGrants controller and the imperative saga step are two callers of one
// codepath (ADR-0027), not parallel reimplementations.
//
// Both methods are idempotent and drift-correcting:
//
//   - Provision writes every desired tuple write-if-absent (read-before-write,
//     since OpenFGA rejects a duplicate write). Re-running for an
//     already-registered tenant is a no-op, and a tuple a previous reconcile
//     wrote but that has since been deleted out-of-band is re-created (drift
//     correction).
//   - Deprovision deletes every tuple; a not-found is treated as success.
package grants

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga"
)

// Provisioner is the narrow Provision/Deprovision surface the TenantGrants
// controller delegates to. It mirrors secrets.Provisioner / identity.Provisioner
// so the controller pattern established by #801/#802/#803 carries over
// unchanged. Provision is idempotent + drift-correcting; Deprovision treats
// already-gone tuples as success.
type Provisioner interface {
	// Provision ensures every supplied tuple exists in OpenFGA. Each tuple is
	// written write-if-absent (read-before-write), so re-running is a no-op and
	// a tuple deleted out-of-band is re-created. Idempotent.
	Provision(ctx context.Context, tuples []fga.Tuple) error

	// Deprovision deletes every supplied tuple from OpenFGA. A not-found tuple
	// is treated as success so teardown is idempotent.
	Deprovision(ctx context.Context, tuples []fga.Tuple) error
}

// NotFoundError reports whether err means a tuple was already gone. Supplied by
// the caller (cmd/main.go binds the operator's clients.ErrNotFound matcher) so
// this package takes no dependency on the operator's clients package. Defaults
// to "never not-found" when nil.
type NotFoundError func(error) bool

// PlatformRegistrationTuple returns the canonical tenant→platform registration
// tuple the RegisterTenantWithPlatform saga step writes:
//
//	(tenant:<tenantID>, parent, system_tenant:_system)
//
// This registers the tenant under the platform's system tenant. The daemon's
// catalog fan-out reconciler enumerates system_tenant:_system#parent@tenant:X
// to seed the ADR-0046 component:_system baseline plus the platform catalog
// onto every tenant; without this tuple the tenant is invisible to the fan-out
// (deploy#782 / gibson#715). Centralised here so the saga step and the
// declarative TenantGrants controller share one definition.
func PlatformRegistrationTuple(tenantID string) fga.Tuple {
	return fga.Tuple{
		User:     fmt.Sprintf("tenant:%s", tenantID),
		Relation: "parent",
		Object:   "system_tenant:_system",
	}
}

// New returns the production Provisioner over the supplied fga.Client. The
// client must be non-nil — a nil here is operator misconfiguration and New
// panics so a misconfigured operator crash-loops at boot rather than silently
// no-op'ing grant provisioning (one-code-path). isNotFound classifies a
// not-found from a Delete as success on the Deprovision path; nil means treat
// no error as not-found.
func New(client fga.Client, isNotFound NotFoundError) Provisioner {
	if client == nil {
		panic("grants.New: fga client is nil (operator misconfigured)")
	}
	if isNotFound == nil {
		isNotFound = func(error) bool { return false }
	}
	return &provisioner{client: client, isNotFound: isNotFound}
}

type provisioner struct {
	client     fga.Client
	isNotFound NotFoundError
}

// Provision writes every tuple write-if-absent. OpenFGA rejects a duplicate
// write, so each tuple is read first; only absent tuples are written. This keeps
// the step idempotent across reconciles AND drift-corrects: a tuple a previous
// reconcile wrote but that was deleted out-of-band reads back empty and is
// re-created.
func (p *provisioner) Provision(ctx context.Context, tuples []fga.Tuple) error {
	var missing []fga.Tuple
	for _, t := range tuples {
		existing, err := p.client.Read(ctx, t)
		if err != nil && !p.isNotFound(err) {
			return fmt.Errorf("grants.Provision: read tuple %s#%s@%s: %w", t.Object, t.Relation, t.User, err)
		}
		if len(existing) == 0 {
			missing = append(missing, t)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	if err := p.client.Write(ctx, missing); err != nil {
		return fmt.Errorf("grants.Provision: write %d tuple(s): %w", len(missing), err)
	}
	return nil
}

// Deprovision deletes every tuple. A not-found is treated as success so teardown
// is idempotent (the fga.HTTPClient already maps "tuple did not exist" to
// ErrNotFound, but we tolerate it here too in case a caller passes a stricter
// client).
func (p *provisioner) Deprovision(ctx context.Context, tuples []fga.Tuple) error {
	if len(tuples) == 0 {
		return nil
	}
	if err := p.client.Delete(ctx, tuples); err != nil && !p.isNotFound(err) {
		return fmt.Errorf("grants.Deprovision: delete %d tuple(s): %w", len(tuples), err)
	}
	return nil
}
