package admin

import (
	"context"
	"regexp"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	tenantv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
)

// nowPlus is a future timestamp for sqlmock expires_at rows.
func nowPlus() time.Time { return time.Now().Add(time.Hour) }

// --- InviteMember handler guard tests (no DB) ---

func TestInviteMember_EmailRequired(t *testing.T) {
	srv := newMembersTestServer(t, &membersAuthorizer{}, nil)
	ctx := ctxWithTenant(t, "acme")
	_, err := srv.InviteMember(ctx, &tenantv1.InviteMemberRequest{Email: ""})
	if status_grpc.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for empty email, got %v", err)
	}
}

func TestInviteMember_BadRole(t *testing.T) {
	srv := newMembersTestServer(t, &membersAuthorizer{}, nil)
	ctx := ctxWithTenant(t, "acme")
	_, err := srv.InviteMember(ctx, &tenantv1.InviteMemberRequest{Email: "a@b.com", Role: "owner"})
	if status_grpc.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for role 'owner', got %v", err)
	}
}

func TestInviteMember_NilStoreUnavailable(t *testing.T) {
	// newMembersTestServer leaves Invitations unset → store nil.
	srv := newMembersTestServer(t, &membersAuthorizer{}, nil)
	ctx := ctxWithTenant(t, "acme")
	_, err := srv.InviteMember(ctx, &tenantv1.InviteMemberRequest{Email: "a@b.com", Role: "member"})
	if status_grpc.Code(err) != codes.Unavailable {
		t.Fatalf("expected Unavailable when invitation store is nil, got %v", err)
	}
}

func TestInviteMember_IssuesPendingInvitation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS tenant_invitations").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("CREATE UNIQUE INDEX").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO tenant_invitations")).
		WillReturnRows(sqlmock.NewRows([]string{"id", "expires_at"}).AddRow("inv-1", nowPlus()))

	srv := newMembersTestServer(t, &membersAuthorizer{}, nil)
	srv.invitations = NewInvitationStore(db)

	ctx := ctxWithTenant(t, "acme")
	resp, err := srv.InviteMember(ctx, &tenantv1.InviteMemberRequest{Email: "alice@example.com", Role: "member"})
	if err != nil {
		t.Fatalf("InviteMember: %v", err)
	}
	if resp.GetInvitationId() != "inv-1" {
		t.Fatalf("invitation_id: got %q, want inv-1", resp.GetInvitationId())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}

// --- store ListPending test ---

func TestInvitationStore_ListPending(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS tenant_invitations").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("CREATE UNIQUE INDEX").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT id, email, role, invited_by, expires_at").
		WithArgs("acme").
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "role", "invited_by", "expires_at"}).
			AddRow("inv-1", "bob@example.com", "member", "admin-1", nowPlus()))

	store := NewInvitationStore(db)
	pending, err := store.ListPending(context.Background(), "acme")
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(pending) != 1 || pending[0].Email != "bob@example.com" || pending[0].Role != "member" {
		t.Fatalf("unexpected pending: %+v", pending)
	}
}

// --- AcceptInvitation tests ---

func TestAcceptInvitation_HappyPath(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// GetByTokenHash → ensureTable + SELECT returning a pending, future invite.
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS tenant_invitations").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("CREATE UNIQUE INDEX").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT id, tenant_id, email, role, status, expires_at").
		WillReturnRows(sqlmock.NewRows([]string{"id", "tenant_id", "email", "role", "status", "expires_at"}).
			AddRow("inv-1", "acme", "bob@example.com", "member", "pending", nowPlus()))
	// SetStatus accepted.
	mock.ExpectExec("UPDATE tenant_invitations SET status").WillReturnResult(sqlmock.NewResult(0, 1))

	az := &membersAuthorizer{}
	idpC := &membersIdPClient{ensureUserID: "user-bob"}
	srv := newMembersTestServer(t, az, idpC)
	srv.invitations = NewInvitationStore(db)
	srv.orgResolver = staticOrgResolver{orgID: "org-1"}

	resp, err := srv.AcceptInvitation(context.Background(), &tenantv1.AcceptInvitationRequest{Token: "rawtoken"})
	if err != nil {
		t.Fatalf("AcceptInvitation: %v", err)
	}
	if resp.GetTenantId() != "acme" || resp.GetUserId() != "user-bob" {
		t.Fatalf("unexpected resp: %+v", resp)
	}
	// dual-write happened: Zitadel member add recorded + FGA tuple written.
	if len(idpC.added) != 1 || idpC.added[0].UserID != "user-bob" {
		t.Fatalf("expected AddTenantMember for user-bob, got %v", idpC.added)
	}
	if len(idpC.ensuredEmails) != 1 || idpC.ensuredEmails[0] != "bob@example.com" {
		t.Fatalf("expected EnsureHumanUser for bob, got %v", idpC.ensuredEmails)
	}
}

func TestAcceptInvitation_UnknownToken(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS tenant_invitations").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("CREATE UNIQUE INDEX").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT id, tenant_id, email, role, status, expires_at").
		WillReturnError(sqlmock.ErrCancelled) // any non-rows error path is Internal; use no-rows below instead

	srv := newMembersTestServer(t, &membersAuthorizer{}, &membersIdPClient{})
	srv.invitations = NewInvitationStore(db)
	srv.orgResolver = staticOrgResolver{orgID: "org-1"}
	_, err = srv.AcceptInvitation(context.Background(), &tenantv1.AcceptInvitationRequest{Token: "nope"})
	if err == nil {
		t.Fatal("expected error for unknown/failed token lookup")
	}
}

func TestCancelInvitation_MarksCancelled(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS tenant_invitations").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("CREATE UNIQUE INDEX").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT id, tenant_id, email, role, status, expires_at").
		WithArgs("acme", "carol@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"id", "tenant_id", "email", "role", "status", "expires_at"}).
			AddRow("inv-2", "acme", "carol@example.com", "member", "pending", nowPlus()))
	mock.ExpectExec("UPDATE tenant_invitations SET status").WillReturnResult(sqlmock.NewResult(0, 1))

	srv := newMembersTestServer(t, &membersAuthorizer{}, nil)
	srv.invitations = NewInvitationStore(db)
	ctx := ctxWithTenant(t, "acme")
	if _, err := srv.CancelInvitation(ctx, &tenantv1.CancelInvitationRequest{Email: "carol@example.com"}); err != nil {
		t.Fatalf("CancelInvitation: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock: %v", err)
	}
}
