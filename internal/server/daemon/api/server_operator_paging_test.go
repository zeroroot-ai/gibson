// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	"github.com/zeroroot-ai/gibson/pkg/billing/entitlements"
)

// addRow queues one pending tenant, with a created_at after every earlier row.
func (q *fakePendingQueue) addRow(tenantID, state string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.clock++
	q.rows = append(q.rows, fakeQueueRow{
		tenantID: tenantID, ownerEmail: tenantID + "@example.test", workspaceName: tenantID, tier: "team",
		status: state, createdAt: fakeQueueEpoch.Add(time.Duration(q.clock) * time.Microsecond),
	})
}

// setStatus moves a queued tenant to another status, as an ack does.
func (q *fakePendingQueue) setStatus(tenantID, state string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i := range q.rows {
		if q.rows[i].tenantID == tenantID {
			q.rows[i].status = state
		}
	}
}

func pendingIDs(resp *daemonoperatorv1.ListPendingTenantProvisioningResponse) []string {
	ids := make([]string, 0, len(resp.GetPending()))
	for _, p := range resp.GetPending() {
		ids = append(ids, p.GetTenantId())
	}
	return ids
}

// A walk that changes the queue between pages returns each row that stayed
// pending once: a row that arrives is on a later page, and a row that leaves
// moves no other row.
func TestListPendingTenantProvisioning_WalkWithChangesBetweenPages(t *testing.T) {
	t.Setenv(entitlements.RequiredKnob, "")
	srv := newPendingServer()
	q := withPendingQueue(t, srv)
	for i := 1; i <= 5; i++ {
		q.addRow(fmt.Sprintf("t%d", i), "pending")
	}
	ctx := context.Background()

	p1, err := srv.ListPendingTenantProvisioning(ctx, &daemonoperatorv1.ListPendingTenantProvisioningRequest{PageSize: 2})
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if got := strings.Join(pendingIDs(p1), ","); got != "t1,t2" || p1.GetNextPageToken() == "" {
		t.Fatalf("page 1 = %s token %q, want t1,t2 and a token", got, p1.GetNextPageToken())
	}

	// The operator acks t1 (a row it has) and t4 (a row it has not). A new row
	// arrives.
	q.setStatus("t1", "done")
	q.setStatus("t4", "done")
	q.addRow("t6", "pending")

	seen := pendingIDs(p1)
	token := p1.GetNextPageToken()
	for pages := 0; token != ""; pages++ {
		if pages > 10 {
			t.Fatal("the walk does not end")
		}
		resp, err := srv.ListPendingTenantProvisioning(ctx, &daemonoperatorv1.ListPendingTenantProvisioningRequest{PageSize: 2, PageToken: token})
		if err != nil {
			t.Fatalf("page: %v", err)
		}
		seen = append(seen, pendingIDs(resp)...)
		token = resp.GetNextPageToken()
	}
	if got := strings.Join(seen, ","); got != "t1,t2,t3,t5,t6" {
		t.Fatalf("walk = %s, want t1,t2,t3,t5,t6: each row once", got)
	}
}

// A page of exactly the page size at the end of the list has no next token.
func TestListPendingTenantProvisioning_LastPageHasNoToken(t *testing.T) {
	t.Setenv(entitlements.RequiredKnob, "")
	srv := newPendingServer()
	q := withPendingQueue(t, srv)
	q.addRow("t1", "pending")
	q.addRow("t2", "pending")
	resp, err := srv.ListPendingTenantProvisioning(context.Background(), &daemonoperatorv1.ListPendingTenantProvisioningRequest{PageSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetPending()) != 2 || resp.GetNextPageToken() != "" {
		t.Fatalf("got %v token %q, want 2 rows and no token", pendingIDs(resp), resp.GetNextPageToken())
	}
}

// A withheld row counts as a row of its page, so the next token moves past it.
func TestListPendingTenantProvisioning_WithheldRowDoesNotStallThePage(t *testing.T) {
	t.Setenv(entitlements.RequiredKnob, "true")
	srv := newPendingServer()
	q := withPendingQueue(t, srv)
	q.addRow("t1", "pending")
	q.mu.Lock()
	q.rows[0].tier = "no-such-tier"
	q.mu.Unlock()
	q.addRow("t2", "pending")
	q.addRow("t3", "pending")
	ctx := context.Background()
	p1, err := srv.ListPendingTenantProvisioning(ctx, &daemonoperatorv1.ListPendingTenantProvisioningRequest{PageSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(p1.GetPending()) != 0 || p1.GetNextPageToken() == "" {
		t.Fatalf("page 1 = %v token %q, want no row and a token", pendingIDs(p1), p1.GetNextPageToken())
	}
	p2, err := srv.ListPendingTenantProvisioning(ctx, &daemonoperatorv1.ListPendingTenantProvisioningRequest{PageSize: 1, PageToken: p1.GetNextPageToken()})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(pendingIDs(p2), ","); got != "t2" {
		t.Fatalf("page 2 = %s, want t2", got)
	}
}

// microsEqual matches a timestamp argument at microsecond precision.
type microsEqual time.Time

func (m microsEqual) Match(v driver.Value) bool {
	got, ok := v.(time.Time)
	return ok && got.UnixMicro() == time.Time(m).UnixMicro()
}

var opsCols = []string{
	"op_id", "tenant_id", "op_type", "display_name", "display_name_set", "owner_email", "tier", "tier_set",
	"audit_record_id", "created_at",
}

// The ops page asks the table for the rows after the last row of the previous
// page, never for an offset.
func TestListPendingTenantOps_KeysetPages(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := newAdminOpsServer(t)
	srv.platformDB = db
	ctx := context.Background()
	t1 := time.Date(2026, 3, 1, 10, 0, 0, 123456000, time.UTC)
	t2 := t1.Add(time.Second)
	t3 := t2.Add(time.Second)

	expectEnsureAdminOpsTable(mock)
	mock.ExpectQuery(`ORDER BY created_at ASC, op_id ASC\s+LIMIT \$1`).WithArgs(3).
		WillReturnRows(sqlmock.NewRows(opsCols).
			AddRow("op-1", "a", "update", "", false, "", "", false, "", t1).
			AddRow("op-2", "b", "update", "", false, "", "", false, "", t2).
			AddRow("op-3", "c", "update", "", false, "", "", false, "", t3))
	p1, err := srv.ListPendingTenantOps(ctx, &daemonoperatorv1.ListPendingTenantOpsRequest{PageSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(p1.GetOps()) != 2 || p1.GetNextPageToken() == "" {
		t.Fatalf("page 1 = %v token %q, want 2 ops and a token", p1.GetOps(), p1.GetNextPageToken())
	}

	expectEnsureAdminOpsTable(mock)
	mock.ExpectQuery(`AND \(created_at, op_id\) > \(\$2, \$3\)`).WithArgs(3, microsEqual(t2), "op-2").
		WillReturnRows(sqlmock.NewRows(opsCols).AddRow("op-3", "c", "update", "", false, "", "", false, "", t3))
	p2, err := srv.ListPendingTenantOps(ctx, &daemonoperatorv1.ListPendingTenantOpsRequest{PageSize: 2, PageToken: p1.GetNextPageToken()})
	if err != nil {
		t.Fatal(err)
	}
	if len(p2.GetOps()) != 1 || p2.GetOps()[0].GetOpId() != "op-3" || p2.GetNextPageToken() != "" {
		t.Fatalf("page 2 = %v token %q, want op-3 and no token", p2.GetOps(), p2.GetNextPageToken())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestListDesiredCatalogPlugins_KeysetPagesAcrossAFilteredRow(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := newPendingServer()
	srv.platformDB = db
	ctx := context.Background()
	cols := []string{"tenant_id", "plugin_id", "phase", "last_error"}

	mock.ExpectQuery(`ORDER BY tenant_id, plugin_id\s+LIMIT\s+\$1`).WithArgs(2).
		WillReturnRows(sqlmock.NewRows(cols).
			AddRow("acme", "left-the-catalog", "Ready", "").
			AddRow("acme", "github", "Ready", ""))
	p1, err := srv.ListDesiredCatalogPlugins(ctx, &daemonoperatorv1.ListDesiredCatalogPluginsRequest{PageSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	// The row left the catalog, so the page is empty. The token still moves on.
	if len(p1.GetPlugins()) != 0 || p1.GetNextPageToken() == "" {
		t.Fatalf("page 1 = %v token %q, want no plugin and a token", p1.GetPlugins(), p1.GetNextPageToken())
	}

	mock.ExpectQuery(`WHERE\s+\(tenant_id, plugin_id\) > \(\$2, \$3\)`).WithArgs(2, "acme", "left-the-catalog").
		WillReturnRows(sqlmock.NewRows(cols).AddRow("acme", "github", "Ready", ""))
	p2, err := srv.ListDesiredCatalogPlugins(ctx, &daemonoperatorv1.ListDesiredCatalogPluginsRequest{PageSize: 1, PageToken: p1.GetNextPageToken()})
	if err != nil {
		t.Fatal(err)
	}
	if len(p2.GetPlugins()) != 1 || p2.GetPlugins()[0].GetPluginId() != "github" || p2.GetNextPageToken() != "" {
		t.Fatalf("page 2 = %v token %q, want github and no token", p2.GetPlugins(), p2.GetNextPageToken())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestListDesiredConnectors_KeysetPages(t *testing.T) {
	srv, mock := connectorServer(t)
	ctx := context.Background()
	cols := []string{"tenant_id", "connector_id", "phase", "discovered_tools", "last_error"}

	mock.ExpectQuery(`ORDER BY tenant_id, connector_id LIMIT \$1`).WithArgs(2).
		WillReturnRows(sqlmock.NewRows(cols).
			AddRow("acme", "gitlab", "Ready", 0, "").
			AddRow("globex", "gitlab", "Ready", 0, ""))
	p1, err := srv.ListDesiredConnectors(ctx, &daemonoperatorv1.ListDesiredConnectorsRequest{PageSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(p1.GetConnectors()) != 1 || p1.GetNextPageToken() == "" {
		t.Fatalf("page 1 = %v token %q, want 1 connector and a token", p1.GetConnectors(), p1.GetNextPageToken())
	}

	mock.ExpectQuery(`WHERE \(tenant_id, connector_id\) > \(\$2, \$3\)`).WithArgs(2, "acme", "gitlab").
		WillReturnRows(sqlmock.NewRows(cols).AddRow("globex", "gitlab", "Ready", 0, ""))
	p2, err := srv.ListDesiredConnectors(ctx, &daemonoperatorv1.ListDesiredConnectorsRequest{PageSize: 1, PageToken: p1.GetNextPageToken()})
	if err != nil {
		t.Fatal(err)
	}
	if len(p2.GetConnectors()) != 1 || p2.GetConnectors()[0].GetTenantId() != "globex" || p2.GetNextPageToken() != "" {
		t.Fatalf("page 2 = %v token %q, want globex and no token", p2.GetConnectors(), p2.GetNextPageToken())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

// A token that anyone edited, that another list wrote, or that is not a token
// at all is InvalidArgument, before the daemon reads any row.
func TestOperatorLists_ForgedTokenIsInvalidArgument(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := newAdminOpsServer(t)
	srv.platformDB = db
	ctx := context.Background()

	genuine := srv.pageToken(pageScopeDesiredConnectors, "acme", "gitlab")
	// Edit the key part: the signature no longer matches.
	_, signature, _ := strings.Cut(genuine, ".")
	edited := "WyJldmlsIiwiZ2l0bGFiIl0." + signature

	calls := map[string]func(token string) error{
		"ListPendingTenantProvisioning": func(tok string) error {
			_, err := srv.ListPendingTenantProvisioning(ctx, &daemonoperatorv1.ListPendingTenantProvisioningRequest{PageToken: tok})
			return err
		},
		"ListPendingTenantOps": func(tok string) error {
			_, err := srv.ListPendingTenantOps(ctx, &daemonoperatorv1.ListPendingTenantOpsRequest{PageToken: tok})
			return err
		},
		"ListDesiredCatalogPlugins": func(tok string) error {
			_, err := srv.ListDesiredCatalogPlugins(ctx, &daemonoperatorv1.ListDesiredCatalogPluginsRequest{PageToken: tok})
			return err
		},
		"ListDesiredConnectors": func(tok string) error {
			_, err := srv.ListDesiredConnectors(ctx, &daemonoperatorv1.ListDesiredConnectorsRequest{PageToken: tok})
			return err
		},
	}
	for name, call := range calls {
		for label, tok := range map[string]string{"edited": edited, "garbage": "not-a-token", "no-dot": "abc"} {
			if got := status.Code(call(tok)); got != codes.InvalidArgument {
				t.Errorf("%s with %s token: code = %v, want InvalidArgument", name, label, got)
			}
		}
	}
	// A genuine token of the connector list is a forgery for the other lists.
	for name, call := range calls {
		if name == "ListDesiredConnectors" {
			continue
		}
		if got := status.Code(call(genuine)); got != codes.InvalidArgument {
			t.Errorf("%s with a token of another list: code = %v, want InvalidArgument", name, got)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("a forged token reached the database: %v", err)
	}
}

// A signed token with a key that does not parse as a timestamp is refused.
func TestListPendingTenantOps_BadTimeKeyIsInvalidArgument(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := newAdminOpsServer(t)
	srv.platformDB = db
	_, err = srv.ListPendingTenantOps(context.Background(),
		&daemonoperatorv1.ListPendingTenantOpsRequest{PageToken: srv.pageToken(pageScopePendingTenantOps, "yesterday", "op-1")})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
}

// A daemon with no page token key refuses the lists and never serves an
// unsigned page.
func TestOperatorLists_NoKeyIsUnavailable(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := newPendingServer()
	srv.pageKeys = nil
	srv.platformDB = db
	ctx := context.Background()
	_, err1 := srv.ListPendingTenantProvisioning(ctx, &daemonoperatorv1.ListPendingTenantProvisioningRequest{})
	_, err2 := srv.ListPendingTenantOps(ctx, &daemonoperatorv1.ListPendingTenantOpsRequest{})
	_, err3 := srv.ListDesiredCatalogPlugins(ctx, &daemonoperatorv1.ListDesiredCatalogPluginsRequest{})
	_, err4 := srv.ListDesiredConnectors(ctx, &daemonoperatorv1.ListDesiredConnectorsRequest{})
	for i, err := range []error{err1, err2, err3, err4} {
		if status.Code(err) != codes.Unavailable {
			t.Errorf("list %d: code = %v, want Unavailable", i, status.Code(err))
		}
	}
}

func TestWithPageTokenKEK_RefusesAShortKey(t *testing.T) {
	if _, err := (&DaemonServer{}).WithPageTokenKEK([]byte("short")); err == nil {
		t.Fatal("a short KEK must be refused")
	}
}

// The sort key keeps any text in its fields, and a key with the wrong number
// of fields is refused.
func TestSortKey_RoundTrip(t *testing.T) {
	for _, fields := range [][]string{{"a", "b"}, {"", ""}, {"1:x", "2:"}, {"a:b:c", "\x00"}} {
		got, ok := splitKey(joinKey(fields...), 2)
		if !ok || got[0] != fields[0] || got[1] != fields[1] {
			t.Errorf("%q: got %q, %v", fields, got, ok)
		}
	}
	for _, bad := range []string{"", "x", "9:ab", "1:a", "1:a1:b2:c", "-1:a1:b", "1:a1:b "} {
		if _, ok := splitKey(bad, 2); ok {
			t.Errorf("splitKey(%q) accepted a bad key", bad)
		}
	}
}

// A signed key with the wrong number of fields is refused.
func TestOperatorLists_SignedKeyWithWrongFieldCountIsInvalidArgument(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := newPendingServer()
	srv.platformDB = db
	_, err = srv.ListDesiredConnectors(context.Background(),
		&daemonoperatorv1.ListDesiredConnectorsRequest{PageToken: srv.pageToken(pageScopeDesiredConnectors, "only-one")})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
}

func TestListPendingTenantProvisioning_BadTimeKeyIsInvalidArgument(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := newPendingServer()
	srv.platformDB = db
	_, err = srv.ListPendingTenantProvisioning(context.Background(),
		&daemonoperatorv1.ListPendingTenantProvisioningRequest{
			PageToken: srv.pageToken(pageScopePendingTenantProvisioning, "yesterday", "t1"),
		})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
}

// A database failure on any step of the two queue lists is Internal, and the
// list returns no partial page.
func TestPendingQueueLists_DatabaseFailuresAreInternal(t *testing.T) {
	ctx := context.Background()
	provCols := []string{"tenant_id", "owner_user_id", "owner_email", "workspace_name", "tier", "audit_record_id", "created_at"}
	type listFn func(srv *DaemonServer) error
	prov := func(srv *DaemonServer) error {
		_, err := srv.ListPendingTenantProvisioning(ctx, &daemonoperatorv1.ListPendingTenantProvisioningRequest{})
		return err
	}
	ops := func(srv *DaemonServer) error {
		_, err := srv.ListPendingTenantOps(ctx, &daemonoperatorv1.ListPendingTenantOpsRequest{})
		return err
	}
	ensureProv := func(m sqlmock.Sqlmock) { expectEnsureTable(m) }
	ensureOps := func(m sqlmock.Sqlmock) { expectEnsureAdminOpsTable(m) }
	cases := map[string]struct {
		call   listFn
		script func(m sqlmock.Sqlmock)
	}{
		"provisioning ensure table": {prov, func(m sqlmock.Sqlmock) {
			m.ExpectExec("CREATE TABLE IF NOT EXISTS pending_tenant_provisioning").WillReturnError(errors.New("down"))
		}},
		"provisioning query": {prov, func(m sqlmock.Sqlmock) {
			ensureProv(m)
			m.ExpectQuery("FROM pending_tenant_provisioning").WillReturnError(errors.New("down"))
		}},
		"provisioning scan": {prov, func(m sqlmock.Sqlmock) {
			ensureProv(m)
			m.ExpectQuery("FROM pending_tenant_provisioning").
				WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow("acme"))
		}},
		"provisioning rows": {prov, func(m sqlmock.Sqlmock) {
			ensureProv(m)
			m.ExpectQuery("FROM pending_tenant_provisioning").
				WillReturnRows(sqlmock.NewRows(provCols).AddRow("a", "u", "e", "w", "team", "", time.Now()).RowError(0, errors.New("row")))
		}},
		"ops ensure table": {ops, func(m sqlmock.Sqlmock) {
			m.ExpectExec("CREATE TABLE IF NOT EXISTS tenant_admin_ops").WillReturnError(errors.New("down"))
		}},
		"ops query": {ops, func(m sqlmock.Sqlmock) {
			ensureOps(m)
			m.ExpectQuery("FROM tenant_admin_ops").WillReturnError(errors.New("down"))
		}},
		"ops scan": {ops, func(m sqlmock.Sqlmock) {
			ensureOps(m)
			m.ExpectQuery("FROM tenant_admin_ops").WillReturnRows(sqlmock.NewRows([]string{"op_id"}).AddRow("op-1"))
		}},
		"ops rows": {ops, func(m sqlmock.Sqlmock) {
			ensureOps(m)
			m.ExpectQuery("FROM tenant_admin_ops").
				WillReturnRows(sqlmock.NewRows(opsCols).
					AddRow("op-1", "a", "update", "", false, "", "", false, "", time.Now()).RowError(0, errors.New("row")))
		}},
	}
	for name, c := range cases {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		srv := newAdminOpsServer(t)
		srv.platformDB = db
		c.script(mock)
		if got := status.Code(c.call(srv)); got != codes.Internal {
			t.Errorf("%s: code = %v, want Internal", name, got)
		}
		_ = db.Close()
	}
}
