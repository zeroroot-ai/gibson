// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// tenant_status_gates_test.go — regression tests for the disclosure gate of
// TenantProvisioningService.GetTenantProvisioningStatus (gibson#1230,
// gibson#1339): it serves coarse progress only, to every caller.
package api

import (
	"context"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// GetTenantProvisioningStatus — cross-tenant disclosure
// ---------------------------------------------------------------------------

// statusRows builds the single-row result the coarse status query returns for
// "acme". GetTenantProvisioningStatus selects only the coarse columns, so this
// mirrors that shape.
func statusRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"phase", "data_plane_ready", "store_postgres", "store_redis", "store_neo4j",
		"zitadel_org_slug",
	}).AddRow("Provisioning", false, "Ready", "Provisioning", "", "acme-org")
}

// TestGetTenantProvisioningStatus_ServesCoarseToEveryCaller is the core
// regression: an anonymous caller, a caller authenticated to a DIFFERENT
// tenant, and even the tenant ITSELF all get the same coarse view — existence
// plus provisioning progress — and NONE of them get the Zitadel org slug from
// this RPC (gibson#1339).
func TestGetTenantProvisioningStatus_ServesCoarseToEveryCaller(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
	}{
		{"anonymous caller", context.Background()},
		{"caller authenticated to another tenant",
			auth.WithTenant(context.Background(), auth.MustNewTenantID("globex"))},
		{"the tenant itself — the slug is still not served by this RPC",
			auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()

			srv := newPendingServer()
			srv.platformDB = db

			expectEnsureTenantStatusTable(mock)
			mock.ExpectQuery("SELECT phase, data_plane_ready").
				WithArgs("acme").
				WillReturnRows(statusRows())

			resp, err := srv.GetTenantProvisioningStatus(tc.ctx,
				&tenantv1.GetTenantProvisioningStatusRequest{TenantId: "acme"})
			if err != nil {
				t.Fatalf("get: %v", err)
			}

			// Existence and coarse progress remain — the public signup page
			// needs them and they carry no identifier.
			if !resp.GetFound() {
				t.Error("existence must still be disclosed (slug-availability check)")
			}
			if resp.GetPhase() != "Provisioning" {
				t.Errorf("phase = %q, want the coarse progress to survive redaction", resp.GetPhase())
			}

			// The identifier must not.
			if resp.GetZitadelOrgSlug() != "" {
				t.Errorf("zitadel_org_slug leaked cross-tenant: %q", resp.GetZitadelOrgSlug())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GetTenantProvisioningStatus — zitadel_org_ready (gibson#1230 follow-through)
// ---------------------------------------------------------------------------

// statusRowsWithOrg is statusRows with the Zitadel org slug parameterised, so a
// test can distinguish "org not created yet" from "org created" independently
// of whether the caller is allowed to SEE the slug.
func statusRowsWithOrg(orgSlug string) *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"phase", "data_plane_ready", "store_postgres", "store_redis", "store_neo4j",
		"zitadel_org_slug",
	}).AddRow("Provisioning", false, "Ready", "Provisioning", "", orgSlug)
}

// TestGetTenantProvisioningStatus_OrgReadyReflectsOrgCreation pins the contract
// the signup poller depends on: the org-created EDGE is disclosed to EVERY
// caller (it names nothing), while the org SLUG it is derived from is served to
// NONE of them by this RPC.
//
// The poller reads its early-exit signal off this edge; before zitadel_org_ready
// existed it read the edge off the slug being non-empty, so once the slug stopped
// being served here every signup waited for phase=Ready and a slower-than-timeout
// data plane surfaced a "we'll email you" screen on an otherwise-successful
// signup. Each case fails if zitadel_org_ready is not derived from the operator-
// reported slug, or if the slug itself leaks through this coarse RPC.
func TestGetTenantProvisioningStatus_OrgReadyReflectsOrgCreation(t *testing.T) {
	anonymous := context.Background()
	otherTenant := auth.WithTenant(context.Background(), auth.MustNewTenantID("globex"))
	ownTenant := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))

	tests := []struct {
		name string
		ctx  context.Context
		// orgSlug is what the operator has reported into the row.
		orgSlug string
		// wantReady is the edge every caller may observe.
		wantReady bool
	}{
		{
			name:      "anonymous caller sees the org-created edge but not the slug",
			ctx:       anonymous,
			orgSlug:   "acme-org",
			wantReady: true,
		},
		{
			name:      "caller authenticated to another tenant likewise",
			ctx:       otherTenant,
			orgSlug:   "acme-org",
			wantReady: true,
		},
		{
			name:      "anonymous caller before the org exists reports not-ready",
			ctx:       anonymous,
			orgSlug:   "",
			wantReady: false,
		},
		{
			name:      "the tenant itself sees the edge but still not the slug here",
			ctx:       ownTenant,
			orgSlug:   "acme-org",
			wantReady: true,
		},
		{
			name:      "the tenant itself before the org exists reports not-ready",
			ctx:       ownTenant,
			orgSlug:   "",
			wantReady: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()

			srv := newPendingServer()
			srv.platformDB = db

			expectEnsureTenantStatusTable(mock)
			mock.ExpectQuery("SELECT phase, data_plane_ready").
				WithArgs("acme").
				WillReturnRows(statusRowsWithOrg(tc.orgSlug))

			resp, err := srv.GetTenantProvisioningStatus(tc.ctx,
				&tenantv1.GetTenantProvisioningStatusRequest{TenantId: "acme"})
			if err != nil {
				t.Fatalf("get: %v", err)
			}

			if got := resp.GetZitadelOrgReady(); got != tc.wantReady {
				t.Errorf("zitadel_org_ready = %v, want %v — the signup poller reads this edge", got, tc.wantReady)
			}
			// The slug is never served by this coarse RPC, for any caller.
			if got := resp.GetZitadelOrgSlug(); got != "" {
				t.Errorf("zitadel_org_slug = %q, want empty — this RPC does not serve the slug", got)
			}
		})
	}
}
