// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/zeroroot-ai/sdk/auth"
)

// bankTenantLister lists the tenants whose banks the reconciler serves. It
// reads the tenant_status table in platform Postgres, which the tenant
// operator fills through DaemonOperatorService.ReportTenantStatus.
//
// It replaces a Kubernetes dynamic client that listed Tenant resources. The
// daemon holds no Kubernetes client (ADR-0023, gibson#659). The reconciler
// needs tenant NAMES only, and it takes each tenant's own pool connection the
// ordinary way.
//
// The pool is resolved on each call because the daemon opens it after the
// bank runner is built, the same reason enrollmentRunLimits is lazy.
type bankTenantLister struct {
	db func() *sql.DB
}

var errBankPlatformDBUnset = errors.New("bank reconciler: platform Postgres not configured")

// bankTenantsQuery takes a tenant only when its data plane is ready and it is
// not on its way out. A bank member needs the tenant's database, so a tenant
// that is still in provisioning has nothing to reconcile yet. A tenant in
// teardown must get no new member. The old lister skipped a Tenant resource
// with a deletion timestamp for the same reason.
const bankTenantsQuery = `
	SELECT tenant_id
	FROM tenant_status
	WHERE data_plane_ready
	  AND phase NOT IN ('Terminating', 'Terminated')
	ORDER BY tenant_id`

// ListTenants returns the tenants to reconcile, in a stable order. A row whose
// id is not a tenant id is skipped: the bank of a name that cannot be a
// tenant cannot exist.
func (l *bankTenantLister) ListTenants(ctx context.Context) ([]auth.TenantID, error) {
	db := l.db()
	if db == nil {
		return nil, errBankPlatformDBUnset
	}
	rows, err := db.QueryContext(ctx, bankTenantsQuery)
	if err != nil {
		return nil, fmt.Errorf("list tenants from tenant_status: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []auth.TenantID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("read a tenant_status row: %w", err)
		}
		tid, err := auth.NewTenantID(id)
		if err != nil {
			continue
		}
		out = append(out, tid)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list tenants from tenant_status: %w", err)
	}
	return out, nil
}
