// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// tenant_status_gates_test.go — regression tests for the two authorization
// gates added to TenantProvisioningService (gibson#1230):
//
//   - SetTenantBillingActive refuses a caller that does not present a valid,
//     fresh, request-bound HMAC assertion.
//   - GetTenantProvisioningStatus withholds the cross-tenant identifiers and
//     the billing state from a caller whose authenticated tenant is not the
//     tenant being read.
//
// Every test here fails against the pre-fix handlers.
package api

import (
	"context"
	"database/sql"
	"strconv"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// testBillingSecret is the shared secret used by the billing-webhook tests.
const testBillingSecret = "test-billing-webhook-secret"

// newBillingServer returns a DaemonServer with the billing-webhook secret
// configured, i.e. a daemon capable of authenticating a webhook caller.
func newBillingServer() *DaemonServer {
	return newPendingServer().WithBillingWebhookSecret(testBillingSecret)
}

// signedBillingCtx builds an incoming context carrying a valid assertion for
// (tenantID, active) signed at issuedAt.
func signedBillingCtx(tenantID string, active bool, issuedAt time.Time) context.Context {
	ts := strconv.FormatInt(issuedAt.Unix(), 10)
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		BillingWebhookIssuedAtKey, ts,
		BillingWebhookSignatureKey, signBillingWebhook([]byte(testBillingSecret), tenantID, active, ts),
	))
}

// freshBillingCtx is signedBillingCtx at the current time — the normal case.
func freshBillingCtx(tenantID string, active bool) context.Context {
	return signedBillingCtx(tenantID, active, time.Now())
}

// ---------------------------------------------------------------------------
// SetTenantBillingActive — authentication
// ---------------------------------------------------------------------------

// TestSetTenantBillingActive_UnauthenticatedCallerRefused is the core
// regression: before the fix, any caller that reached the Envoy route could
// flip billing_active for any tenant with a bare request and no credential.
// The nil platformDB proves the refusal happens BEFORE the daemon touches the
// database — an unauthenticated caller gets PermissionDenied, not the
// Unavailable that a nil DB would otherwise produce.
func TestSetTenantBillingActive_UnauthenticatedCallerRefused(t *testing.T) {
	srv := newBillingServer()
	srv.platformDB = nil

	_, err := srv.SetTenantBillingActive(context.Background(),
		&tenantv1.SetTenantBillingActiveRequest{TenantId: "acme", Active: true})

	requireGRPCStatus(t, err, codes.PermissionDenied)
}

// TestSetTenantBillingActive_NoSecretConfiguredRefusesEveryone pins the
// fail-closed posture: a daemon with no webhook secret cannot authenticate
// anyone, so it authenticates no one. An unconfigured deployment must refuse
// the write, never accept every write.
func TestSetTenantBillingActive_NoSecretConfiguredRefusesEveryone(t *testing.T) {
	srv := newPendingServer() // no WithBillingWebhookSecret
	srv.platformDB = nil

	// Even a caller presenting a well-formed assertion signed with some secret
	// is refused, because the daemon holds nothing to check it against.
	_, err := srv.SetTenantBillingActive(freshBillingCtx("acme", true),
		&tenantv1.SetTenantBillingActiveRequest{TenantId: "acme", Active: true})

	requireGRPCStatus(t, err, codes.PermissionDenied)
}

// TestSetTenantBillingActive_SignatureIsBoundToTheRequest proves the assertion
// cannot be lifted from one call and replayed against a different tenant or a
// different billing value: both fields are inside the signed message.
func TestSetTenantBillingActive_SignatureIsBoundToTheRequest(t *testing.T) {
	tests := []struct {
		name          string
		signedTenant  string
		signedActive  bool
		requestTenant string
		requestActive bool
	}{
		{"replayed against another tenant", "acme", true, "globex", true},
		{"flipped from inactive to active", "acme", false, "acme", true},
		{"flipped from active to inactive", "acme", true, "acme", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newBillingServer()
			srv.platformDB = nil

			ctx := freshBillingCtx(tc.signedTenant, tc.signedActive)
			_, err := srv.SetTenantBillingActive(ctx, &tenantv1.SetTenantBillingActiveRequest{
				TenantId: tc.requestTenant,
				Active:   tc.requestActive,
			})

			requireGRPCStatus(t, err, codes.PermissionDenied)
		})
	}
}

// TestSetTenantBillingActive_StaleAssertionRefused bounds the replay window: a
// captured assertion stops working once it falls outside the freshness skew.
func TestSetTenantBillingActive_StaleAssertionRefused(t *testing.T) {
	for _, offset := range []time.Duration{
		-2 * billingWebhookSkew, // signed too far in the past
		2 * billingWebhookSkew,  // signed too far in the future
	} {
		srv := newBillingServer()
		srv.platformDB = nil

		ctx := signedBillingCtx("acme", true, time.Now().Add(offset))
		_, err := srv.SetTenantBillingActive(ctx,
			&tenantv1.SetTenantBillingActiveRequest{TenantId: "acme", Active: true})

		requireGRPCStatus(t, err, codes.PermissionDenied)
	}
}

// TestSetTenantBillingActive_MalformedAssertionRefused covers the structural
// failure branches: absent headers and an unparseable timestamp.
func TestSetTenantBillingActive_MalformedAssertionRefused(t *testing.T) {
	tests := []struct {
		name string
		md   metadata.MD
	}{
		{"no metadata at all", nil},
		{"signature without timestamp", metadata.Pairs(BillingWebhookSignatureKey, "deadbeef")},
		{"timestamp without signature", metadata.Pairs(BillingWebhookIssuedAtKey, "1750000000")},
		{"unparseable timestamp", metadata.Pairs(
			BillingWebhookIssuedAtKey, "not-a-number",
			BillingWebhookSignatureKey, "deadbeef",
		)},
		{"signature is not hex", metadata.Pairs(
			BillingWebhookIssuedAtKey, strconv.FormatInt(time.Now().Unix(), 10),
			BillingWebhookSignatureKey, "zzzz",
		)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newBillingServer()
			srv.platformDB = nil

			ctx := context.Background()
			if tc.md != nil {
				ctx = metadata.NewIncomingContext(ctx, tc.md)
			}
			_, err := srv.SetTenantBillingActive(ctx,
				&tenantv1.SetTenantBillingActiveRequest{TenantId: "acme", Active: true})

			requireGRPCStatus(t, err, codes.PermissionDenied)
		})
	}
}

// TestSetTenantBillingActive_ValidAssertionWrites confirms the gate does not
// break the legitimate caller: a correctly-signed request still performs the
// upsert.
func TestSetTenantBillingActive_ValidAssertionWrites(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	srv := newBillingServer()
	srv.platformDB = db

	expectEnsureTenantStatusTable(mock)
	mock.ExpectExec("INSERT INTO tenant_status").
		WithArgs("acme", true).
		WillReturnResult(sqlmock.NewResult(1, 1))

	resp, err := srv.SetTenantBillingActive(freshBillingCtx("acme", true),
		&tenantv1.SetTenantBillingActiveRequest{TenantId: "acme", Active: true})
	if err != nil {
		t.Fatalf("signed request must succeed, got: %v", err)
	}
	if !resp.GetUpdated() {
		t.Error("expected updated=true on insert")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetTenantProvisioningStatus — cross-tenant disclosure
// ---------------------------------------------------------------------------

// statusRows builds the single-row result the coarse status query returns for
// "acme". GetTenantProvisioningStatus selects only the coarse columns (no
// stripe_customer_id / billing_active), so this mirrors that shape.
func statusRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"phase", "data_plane_ready", "store_postgres", "store_redis", "store_neo4j",
		"zitadel_org_slug",
	}).AddRow("Provisioning", false, "Ready", "Provisioning", "", "acme-org")
}

// TestGetTenantProvisioningStatus_ServesCoarseToEveryCaller is the core
// regression: an anonymous caller, a caller authenticated to a DIFFERENT
// tenant, and even the tenant ITSELF all get the same coarse view — existence
// plus provisioning progress — and NONE of them get the Zitadel org slug, the
// Stripe customer id, or the billing state from this RPC.
//
// Before gibson#1339 the intent was that the tenant itself would see the full
// record here; but ext-authz never resolves a tenant on an unauthenticated-mode
// RPC, so that branch was unreachable and the billing portal 400'd for every
// tenant. The fix stops serving the identifiers/billing here entirely (they move
// to TenantService.GetTenantBilling / AdminTenantService.AdminGetTenantBilling),
// which is why even the own-tenant case below asserts them empty.
func TestGetTenantProvisioningStatus_ServesCoarseToEveryCaller(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
	}{
		{"anonymous caller", context.Background()},
		{"caller authenticated to another tenant",
			auth.WithTenant(context.Background(), auth.MustNewTenantID("globex"))},
		{"the tenant itself — billing still not served by this RPC",
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

			// The identifiers and the billing state must not.
			if resp.GetZitadelOrgSlug() != "" {
				t.Errorf("zitadel_org_slug leaked cross-tenant: %q", resp.GetZitadelOrgSlug())
			}
			if resp.GetStripeCustomerId() != "" {
				t.Errorf("stripe_customer_id leaked cross-tenant: %q", resp.GetStripeCustomerId())
			}
			if resp.GetBillingActive() {
				t.Error("billing_active leaked cross-tenant")
			}
		})
	}
}

// billingRows builds the single-row result the billing query returns.
func billingRows(stripeID string, active bool, orgSlug string) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"stripe_customer_id", "billing_active", "zitadel_org_slug"}).
		AddRow(stripeID, active, orgSlug)
}

// TestGetTenantBilling_OwnTenantReadsFromContext confirms the billing-portal
// path (dashboard#1016): a caller whose authenticated tenant ext-authz resolved
// (tenant_from_identity) reads its OWN billing identifiers. The tenant comes
// from context — no request tenant_id — so there is nothing to spoof.
func TestGetTenantBilling_OwnTenantReadsFromContext(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	srv := newPendingServer()
	srv.platformDB = db

	expectEnsureTenantStatusTable(mock)
	mock.ExpectQuery("SELECT stripe_customer_id, billing_active, zitadel_org_slug").
		WithArgs("acme").
		WillReturnRows(billingRows("cus_9", true, "acme-org"))

	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	resp, err := srv.GetTenantBilling(ctx, &tenantv1.GetTenantBillingRequest{})
	if err != nil {
		t.Fatalf("get billing: %v", err)
	}
	if !resp.GetFound() || resp.GetStripeCustomerId() != "cus_9" ||
		!resp.GetBillingActive() || resp.GetZitadelOrgSlug() != "acme-org" {
		t.Errorf("own-tenant billing read incomplete: %+v", resp)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// TestGetTenantBilling_NoTenantInContextIsDenied pins the fail-closed posture:
// with no resolved tenant (which ext-authz's rule-mode gate makes impossible in
// production, but a defense-in-depth check here still enforces) the handler
// refuses rather than reading an empty tenant.
func TestGetTenantBilling_NoTenantInContextIsDenied(t *testing.T) {
	srv := newPendingServer()
	srv.platformDB = nil // must not be reached
	_, err := srv.GetTenantBilling(context.Background(), &tenantv1.GetTenantBillingRequest{})
	requireGRPCStatus(t, err, codes.PermissionDenied)
}

// TestGetTenantBilling_UnknownTenantReturnsNotFound confirms an own-tenant read
// for a tenant with no provisioning row yet returns found=false, not an error.
func TestGetTenantBilling_UnknownTenantReturnsNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	srv := newPendingServer()
	srv.platformDB = db

	expectEnsureTenantStatusTable(mock)
	mock.ExpectQuery("SELECT stripe_customer_id, billing_active, zitadel_org_slug").
		WithArgs("ghost").
		WillReturnError(sql.ErrNoRows)

	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("ghost"))
	resp, err := srv.GetTenantBilling(ctx, &tenantv1.GetTenantBillingRequest{})
	if err != nil {
		t.Fatalf("get billing: %v", err)
	}
	if resp.GetFound() {
		t.Error("expected found=false for a tenant with no provisioning row")
	}
}

// TestAdminGetTenantBilling_CrossTenantRead confirms the trial-extension path
// (dashboard#1016): a platform operator (authorised by ext-authz's
// platform_operator gate before this handler runs) reads an ARBITRARY tenant's
// billing identifiers by naming it in the request.
func TestAdminGetTenantBilling_CrossTenantRead(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	srv := newPendingServer()
	srv.platformDB = db

	expectEnsureTenantStatusTable(mock)
	mock.ExpectQuery("SELECT stripe_customer_id, billing_active, zitadel_org_slug").
		WithArgs("globex").
		WillReturnRows(billingRows("cus_42", true, "globex-org"))

	// A staff operator names another tenant; the request tenant_id is the whole
	// point of this surface (ext-authz enforced platform_operator upstream).
	resp, err := srv.AdminGetTenantBilling(context.Background(),
		&tenantv1.AdminGetTenantBillingRequest{TenantId: "globex"})
	if err != nil {
		t.Fatalf("admin get billing: %v", err)
	}
	if !resp.GetFound() || resp.GetStripeCustomerId() != "cus_42" ||
		!resp.GetBillingActive() || resp.GetZitadelOrgSlug() != "globex-org" {
		t.Errorf("cross-tenant billing read incomplete: %+v", resp)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// TestAdminGetTenantBilling_MissingTenantID_InvalidArgument pins the required
// field.
func TestAdminGetTenantBilling_MissingTenantID_InvalidArgument(t *testing.T) {
	srv := newPendingServer()
	srv.platformDB = nil
	_, err := srv.AdminGetTenantBilling(context.Background(),
		&tenantv1.AdminGetTenantBillingRequest{TenantId: ""})
	requireGRPCStatus(t, err, codes.InvalidArgument)
}

// TestGetTenantBilling_NilDB_Unavailable covers the own-tenant read when the
// platform Postgres is not configured: readTenantBilling returns Unavailable and
// GetTenantBilling surfaces it (a resolved tenant is present, so the read is
// reached — distinct from the no-tenant-in-context deny above).
func TestGetTenantBilling_NilDB_Unavailable(t *testing.T) {
	srv := newPendingServer()
	srv.platformDB = nil
	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	_, err := srv.GetTenantBilling(ctx, &tenantv1.GetTenantBillingRequest{})
	requireGRPCStatus(t, err, codes.Unavailable)
}

// TestGetTenantBilling_QueryError_Internal covers the scan-error branch of
// readTenantBilling (a query failure that is not sql.ErrNoRows).
func TestGetTenantBilling_QueryError_Internal(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	srv := newPendingServer()
	srv.platformDB = db

	expectEnsureTenantStatusTable(mock)
	mock.ExpectQuery("SELECT stripe_customer_id, billing_active, zitadel_org_slug").
		WithArgs("acme").
		WillReturnError(errBoom)

	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	_, err = srv.GetTenantBilling(ctx, &tenantv1.GetTenantBillingRequest{})
	requireGRPCStatus(t, err, codes.Internal)
}

// TestGetTenantBilling_EnsureTableError_Internal covers readTenantBilling's
// ensure-table error branch.
func TestGetTenantBilling_EnsureTableError_Internal(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	srv := newPendingServer()
	srv.platformDB = db

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS tenant_status").WillReturnError(errBoom)

	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	_, err = srv.GetTenantBilling(ctx, &tenantv1.GetTenantBillingRequest{})
	requireGRPCStatus(t, err, codes.Internal)
}

// TestAdminGetTenantBilling_NilDB_Unavailable covers the cross-tenant read's
// error passthrough when the platform Postgres is not configured.
func TestAdminGetTenantBilling_NilDB_Unavailable(t *testing.T) {
	srv := newPendingServer()
	srv.platformDB = nil
	_, err := srv.AdminGetTenantBilling(context.Background(),
		&tenantv1.AdminGetTenantBillingRequest{TenantId: "globex"})
	requireGRPCStatus(t, err, codes.Unavailable)
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
