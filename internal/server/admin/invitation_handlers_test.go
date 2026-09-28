// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package admin

import (
	"context"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/mailer"
	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
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
	srv.inviteMailer = &captureInviteMailer{}
	srv.inviteBaseURL = "https://app.example.com"

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

// An unconfigured mailer must not let InviteMember report success. The
// invitation row is written, but no email went out, so the admin has to be told
// — otherwise they wait on an invitee who never received a link.
func TestInviteMember_UnconfiguredMailerRefuses(t *testing.T) {
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
	// inviteMailer and inviteBaseURL deliberately left unset.

	ctx := ctxWithTenant(t, "acme")
	_, err = srv.InviteMember(ctx, &tenantv1.InviteMemberRequest{Email: "alice@example.com", Role: "member"})
	if err == nil {
		t.Fatal("InviteMember reported success with no mailer configured; nothing was delivered")
	}
	if got := status_grpc.Code(err); got != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (%v)", got, err)
	}
}

// captureInviteMailer records the last invitation email for assertions.
type captureInviteMailer struct {
	last mailer.InvitationEmail
	err  error

	lastConflict    mailer.InvitationConflictEmail
	conflictCalls   int
	conflictSendErr error
}

func (c *captureInviteMailer) SendInvitation(_ context.Context, inv mailer.InvitationEmail) error {
	c.last = inv
	return c.err
}

func (c *captureInviteMailer) SendInvitationConflict(_ context.Context, conflict mailer.InvitationConflictEmail) error {
	c.lastConflict = conflict
	c.conflictCalls++
	return c.conflictSendErr
}

func TestInviteMember_EmailsAcceptLink(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS tenant_invitations").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("CREATE UNIQUE INDEX").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO tenant_invitations")).
		WillReturnRows(sqlmock.NewRows([]string{"id", "expires_at"}).AddRow("inv-1", nowPlus()))

	cap := &captureInviteMailer{}
	srv := newMembersTestServer(t, &membersAuthorizer{}, nil)
	srv.invitations = NewInvitationStore(db)
	srv.inviteMailer = cap
	srv.inviteBaseURL = "https://app.example.com/"

	ctx := ctxWithTenant(t, "acme")
	if _, err := srv.InviteMember(ctx, &tenantv1.InviteMemberRequest{Email: "alice@example.com", Role: "admin"}); err != nil {
		t.Fatalf("InviteMember: %v", err)
	}
	if cap.last.To != "alice@example.com" || cap.last.Role != "admin" {
		t.Errorf("email = %+v, want to=alice role=admin", cap.last)
	}
	// Base URL trailing slash is normalised; the raw token follows /invite/.
	if !strings.HasPrefix(cap.last.AcceptURL, "https://app.example.com/invite/") ||
		cap.last.AcceptURL == "https://app.example.com/invite/" {
		t.Errorf("accept URL = %q, want https://app.example.com/invite/<token>", cap.last.AcceptURL)
	}
}

func TestInviteMember_SendFailureSurfaces(t *testing.T) {
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
	srv.inviteMailer = &captureInviteMailer{err: errors.New("smtp down")}
	srv.inviteBaseURL = "https://app.example.com"

	ctx := ctxWithTenant(t, "acme")
	if _, err := srv.InviteMember(ctx, &tenantv1.InviteMemberRequest{Email: "alice@example.com", Role: "member"}); err == nil {
		t.Fatal("expected InviteMember to surface a send failure")
	}
}

// --- InviteMember cross-tenant conflict tests (hosted#203) ---

// TestInviteMember_ConflictingAddressReportsSentButOnlyNotifiesInvitee is the
// core hosted#203 case: the invited address already belongs to a DIFFERENT
// tenant's org (ADR-0093 decision 1). The inviter must see a normal success
// response; no invitation row is written; only the invitee is emailed, and
// with the conflict notice, never the accept-link email.
func TestInviteMember_ConflictingAddressReportsSentButOnlyNotifiesInvitee(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	az := &membersAuthorizer{}
	idpC := &membersIdPClient{findByEmailUserID: "user-elsewhere"}
	srv := newMembersTestServer(t, az, idpC)
	// Configured but never touched: the conflict branch returns before any
	// invitation row would be read or written.
	srv.invitations = NewInvitationStore(db)
	srv.orgResolver = staticOrgResolver{orgID: "org-1"}
	tuples, err := tenantrole.AuthzTuples(az)
	if err != nil {
		t.Fatalf("AuthzTuples: %v", err)
	}
	grants := newFakeGrants()
	// user-elsewhere holds a grant, but in a DIFFERENT org than "acme"'s
	// (org-1) — belongs to another tenant.
	if _, err := grants.Create(context.Background(), "org-999", "user-elsewhere", tenantrole.Viewer); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	srv.roles = tenantrole.NewSyncer(grants, tuples, nil)
	capture := &captureInviteMailer{}
	srv.inviteMailer = capture
	srv.inviteBaseURL = "https://app.example.com"

	ctx := ctxWithTenant(t, "acme")
	resp, err := srv.InviteMember(ctx, &tenantv1.InviteMemberRequest{Email: "taken@example.com", Role: "member"})
	if err != nil {
		t.Fatalf("InviteMember must report success on a conflict, got error: %v", err)
	}
	if resp.GetInvitationId() == "" {
		t.Error("InvitationId empty; a fabricated response must look like a real one")
	}
	if resp.GetExpiresAt() == nil {
		t.Error("ExpiresAt empty; a fabricated response must look like a real one")
	}
	if capture.conflictCalls != 1 || capture.lastConflict.To != "taken@example.com" {
		t.Fatalf("conflict notice: calls=%d to=%q, want 1 call to taken@example.com", capture.conflictCalls, capture.lastConflict.To)
	}
	if capture.last != (mailer.InvitationEmail{}) {
		t.Errorf("the normal accept-link email must never be sent on a conflict, got %+v", capture.last)
	}
}

// TestInviteMember_SameTenantMemberProceedsNormally: the invited address
// already has a Zitadel account, but it is already a member of the SAME
// tenant — not the sensitive case (the inviter already knows their own
// tenant's membership), so the normal invitation flow runs.
func TestInviteMember_SameTenantMemberProceedsNormally(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS tenant_invitations").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("CREATE UNIQUE INDEX").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO tenant_invitations")).
		WillReturnRows(sqlmock.NewRows([]string{"id", "expires_at"}).AddRow("inv-1", nowPlus()))

	az := &membersAuthorizer{}
	idpC := &membersIdPClient{findByEmailUserID: "user-here"}
	srv := newMembersTestServer(t, az, idpC)
	srv.invitations = NewInvitationStore(db)
	srv.orgResolver = staticOrgResolver{orgID: "org-1"}
	tuples, err := tenantrole.AuthzTuples(az)
	if err != nil {
		t.Fatalf("AuthzTuples: %v", err)
	}
	grants := newFakeGrants()
	if _, err := grants.Create(context.Background(), "org-1", "user-here", tenantrole.Viewer); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	srv.roles = tenantrole.NewSyncer(grants, tuples, nil)
	capture := &captureInviteMailer{}
	srv.inviteMailer = capture
	srv.inviteBaseURL = "https://app.example.com"

	ctx := ctxWithTenant(t, "acme")
	if _, err := srv.InviteMember(ctx, &tenantv1.InviteMemberRequest{Email: "alice@example.com", Role: "member"}); err != nil {
		t.Fatalf("InviteMember: %v", err)
	}
	if capture.conflictCalls != 0 {
		t.Errorf("expected no conflict notice for an existing same-tenant member, got %d", capture.conflictCalls)
	}
	if capture.last.To != "alice@example.com" {
		t.Errorf("expected the normal accept-link email to be sent, got %+v", capture.last)
	}
}

// TestInviteMember_UnusedAddressProceedsNormally: FindUserIDByEmail's
// default (idp.ErrNotFound) must not block the ordinary invite path even
// when idpClient/orgResolver/roles are fully configured.
func TestInviteMember_UnusedAddressProceedsNormally(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS tenant_invitations").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("CREATE UNIQUE INDEX").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO tenant_invitations")).
		WillReturnRows(sqlmock.NewRows([]string{"id", "expires_at"}).AddRow("inv-1", nowPlus()))

	az := &membersAuthorizer{}
	idpC := &membersIdPClient{} // FindUserIDByEmail defaults to ErrNotFound
	srv := newMembersTestServer(t, az, idpC)
	srv.invitations = NewInvitationStore(db)
	srv.orgResolver = staticOrgResolver{orgID: "org-1"}
	tuples, err := tenantrole.AuthzTuples(az)
	if err != nil {
		t.Fatalf("AuthzTuples: %v", err)
	}
	srv.roles = tenantrole.NewSyncer(newFakeGrants(), tuples, nil)
	capture := &captureInviteMailer{}
	srv.inviteMailer = capture
	srv.inviteBaseURL = "https://app.example.com"

	ctx := ctxWithTenant(t, "acme")
	if _, err := srv.InviteMember(ctx, &tenantv1.InviteMemberRequest{Email: "fresh@example.com", Role: "member"}); err != nil {
		t.Fatalf("InviteMember: %v", err)
	}
	if capture.conflictCalls != 0 || capture.last.To != "fresh@example.com" {
		t.Errorf("expected the normal invite flow, got conflictCalls=%d last=%+v", capture.conflictCalls, capture.last)
	}
}

// TestInviteMember_DirectoryLookupErrorProceedsNormally: a directory that
// cannot answer must not block the invite or disclose anything — same
// rationale as signup's existingSignupUserID.
func TestInviteMember_DirectoryLookupErrorProceedsNormally(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS tenant_invitations").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("CREATE UNIQUE INDEX").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO tenant_invitations")).
		WillReturnRows(sqlmock.NewRows([]string{"id", "expires_at"}).AddRow("inv-1", nowPlus()))

	az := &membersAuthorizer{}
	idpC := &membersIdPClient{findByEmailErr: errors.New("directory down")}
	srv := newMembersTestServer(t, az, idpC)
	srv.invitations = NewInvitationStore(db)
	srv.orgResolver = staticOrgResolver{orgID: "org-1"}
	tuples, err := tenantrole.AuthzTuples(az)
	if err != nil {
		t.Fatalf("AuthzTuples: %v", err)
	}
	srv.roles = tenantrole.NewSyncer(newFakeGrants(), tuples, nil)
	capture := &captureInviteMailer{}
	srv.inviteMailer = capture
	srv.inviteBaseURL = "https://app.example.com"

	ctx := ctxWithTenant(t, "acme")
	if _, err := srv.InviteMember(ctx, &tenantv1.InviteMemberRequest{Email: "someone@example.com", Role: "member"}); err != nil {
		t.Fatalf("InviteMember: %v", err)
	}
	if capture.conflictCalls != 0 || capture.last.To != "someone@example.com" {
		t.Errorf("expected the normal invite flow on a directory error, got conflictCalls=%d last=%+v", capture.conflictCalls, capture.last)
	}
}

// TestInviteMember_RolesNilAfterFindingExistingUserIsInternalError: the
// address exists elsewhere, but there is no Syncer to ask which tenant —
// this must fail loudly (Internal), never disclose-by-guessing.
func TestInviteMember_RolesNilAfterFindingExistingUserIsInternalError(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	idpC := &membersIdPClient{findByEmailUserID: "user-elsewhere"}
	srv := newMembersTestServer(t, &membersAuthorizer{}, idpC)
	srv.invitations = NewInvitationStore(db)
	srv.orgResolver = staticOrgResolver{orgID: "org-1"}
	// srv.roles deliberately left nil.

	ctx := ctxWithTenant(t, "acme")
	_, ierr := srv.InviteMember(ctx, &tenantv1.InviteMemberRequest{Email: "taken@example.com", Role: "member"})
	if status_grpc.Code(ierr) != codes.Internal {
		t.Fatalf("InviteMember code = %v (err=%v), want Internal", status_grpc.Code(ierr), ierr)
	}
}

// TestInviteMember_ConflictNoticeSendFailureStillReportsSent: a delivery
// failure on the invitee-only notice must not turn into a visible error for
// the inviter — that would itself disclose that something about this
// address is unusual.
func TestInviteMember_ConflictNoticeSendFailureStillReportsSent(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	az := &membersAuthorizer{}
	idpC := &membersIdPClient{findByEmailUserID: "user-elsewhere"}
	srv := newMembersTestServer(t, az, idpC)
	srv.invitations = NewInvitationStore(db)
	srv.orgResolver = staticOrgResolver{orgID: "org-1"}
	tuples, err := tenantrole.AuthzTuples(az)
	if err != nil {
		t.Fatalf("AuthzTuples: %v", err)
	}
	grants := newFakeGrants()
	if _, err := grants.Create(context.Background(), "org-999", "user-elsewhere", tenantrole.Viewer); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	srv.roles = tenantrole.NewSyncer(grants, tuples, nil)
	capture := &captureInviteMailer{conflictSendErr: errors.New("smtp down")}
	srv.inviteMailer = capture

	ctx := ctxWithTenant(t, "acme")
	resp, err := srv.InviteMember(ctx, &tenantv1.InviteMemberRequest{Email: "taken@example.com", Role: "member"})
	if err != nil {
		t.Fatalf("InviteMember must still report success when the conflict notice fails to send, got: %v", err)
	}
	if resp.GetInvitationId() == "" {
		t.Error("InvitationId empty")
	}
	if capture.conflictCalls != 1 {
		t.Errorf("expected 1 attempted conflict notice, got %d", capture.conflictCalls)
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
	// The setup link must be built from this — the product-surface origin
	// (GIBSON_APP_URL) — never from any issuer or Zitadel endpoint
	// (gibson#254: the Platform owner's own setup link was built from an
	// issuer that resolved to an in-cluster address on kind).
	srv.inviteBaseURL = "https://app.example.com"
	tuples, err := tenantrole.AuthzTuples(az)
	if err != nil {
		t.Fatalf("AuthzTuples: %v", err)
	}
	grants := newFakeGrants()
	srv.roles = tenantrole.NewSyncer(grants, tuples, nil)

	resp, err := srv.AcceptInvitation(context.Background(), &tenantv1.AcceptInvitationRequest{Token: "rawtoken"})
	if err != nil {
		t.Fatalf("AcceptInvitation: %v", err)
	}
	if resp.GetTenantId() != "acme" || resp.GetUserId() != "user-bob" {
		t.Fatalf("unexpected resp: %+v", resp)
	}
	// The role write happened through the Syncer: a Zitadel grant for
	// user-bob, mapped from the invitation's "member" relation to Viewer.
	got, err := grants.List(context.Background(), "org-1", []string{"user-bob"})
	if err != nil {
		t.Fatalf("grants.List: %v", err)
	}
	if len(got) != 1 || !got[0].Active || len(got[0].RoleKeys) != 1 || got[0].RoleKeys[0] != string(tenantrole.Viewer) {
		t.Fatalf("expected an active viewer grant for user-bob, got %+v", got)
	}
	// The invitee is created with the same no-password create as the
	// Platform owner and the first tenant Owner, in the tenant's own org. A
	// v1 Management create left the user INITIAL, which the Login v2 app
	// refuses (hosted#208).
	// The invitee's two session tuples are seeded, or ext-authz's session
	// gate denies every call they make, starting at sign-in (hosted#208).

	wantTuples := []authz.ConditionalTuple{
		authz.ActiveSessionUserTuple("user-bob"),
		authz.ActiveSessionTuple("user-bob", "acme"),
	}
	if !reflect.DeepEqual(az.conditionalWrites, wantTuples) {
		t.Fatalf("session tuples = %+v, want %+v", az.conditionalWrites, wantTuples)
	}
	if len(idpC.ensuredEmails) != 1 || idpC.ensuredEmails[0] != "bob@example.com" {
		t.Fatalf("expected EnsureHumanUserNoPassword for bob, got %v", idpC.ensuredEmails)
	}
	if len(idpC.ensuredOrgIDs) != 1 || idpC.ensuredOrgIDs[0] != "org-1" {
		t.Fatalf("expected the invitee created in org-1, got %v", idpC.ensuredOrgIDs)
	}
	// A setup link was minted for the same user, in the same org, built from
	// the product-surface origin — and rides back in the response for the
	// dashboard to redirect to.
	if len(idpC.setupLinkUserIDs) != 1 || idpC.setupLinkUserIDs[0] != "user-bob" || idpC.setupLinkOrgIDs[0] != "org-1" {
		t.Fatalf("expected CreateSetupLink(org-1, user-bob), got users=%v orgs=%v", idpC.setupLinkUserIDs, idpC.setupLinkOrgIDs)
	}
	if len(idpC.setupLinkAppURLs) != 1 || idpC.setupLinkAppURLs[0] != "https://app.example.com" {
		t.Fatalf("expected CreateSetupLink called with appURL=https://app.example.com (inviteBaseURL), got %v", idpC.setupLinkAppURLs)
	}
	if resp.GetSetupUrl() == "" {
		t.Error("SetupUrl empty; the dashboard has nowhere to send the invitee to set a credential")
	}
	if !strings.HasPrefix(resp.GetSetupUrl(), "https://app.example.com") {
		t.Errorf("SetupUrl = %q, want it to start at the product-surface origin", resp.GetSetupUrl())
	}
}

// TestAcceptInvitation_CreateSetupLinkErrorIsInternal: a setup-link mint
// failure must fail the call (Internal), and — crucially — must happen
// BEFORE SetStatus marks the invitation accepted, so a retry can redeem the
// same token again (EnsureHumanUser and Roles.Assign are both idempotent).
func TestAcceptInvitation_CreateSetupLinkErrorIsInternal(t *testing.T) {
	srv := acceptInvitationFixture(t, &membersIdPClient{ensureUserID: "user-bob", setupLinkErr: errors.New("zitadel boom")})

	_, err := srv.AcceptInvitation(context.Background(), &tenantv1.AcceptInvitationRequest{Token: "rawtoken"})
	if status_grpc.Code(err) != codes.Internal {
		t.Fatalf("AcceptInvitation code = %v (err=%v), want Internal", status_grpc.Code(err), err)
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

// acceptInvitationFixture builds a server ready to reach AcceptInvitation's
// role-write step (a pending, unexpired invitation on file), so a test only
// has to vary the one collaborator it wants to fail.
func acceptInvitationFixture(t *testing.T, idpC *membersIdPClient) *TenantAdminServer {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS tenant_invitations").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("CREATE UNIQUE INDEX").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT id, tenant_id, email, role, status, expires_at").
		WillReturnRows(sqlmock.NewRows([]string{"id", "tenant_id", "email", "role", "status", "expires_at"}).
			AddRow("inv-1", "acme", "bob@example.com", "member", "pending", nowPlus()))

	az := &membersAuthorizer{}
	srv := newMembersTestServer(t, az, idpC)
	srv.invitations = NewInvitationStore(db)
	srv.orgResolver = staticOrgResolver{orgID: "org-1"}
	tuples, err := tenantrole.AuthzTuples(az)
	if err != nil {
		t.Fatalf("AuthzTuples: %v", err)
	}
	srv.roles = tenantrole.NewSyncer(newFakeGrants(), tuples, nil)
	return srv
}

func TestAcceptInvitation_UnavailableWithoutRoles(t *testing.T) {
	srv := acceptInvitationFixture(t, &membersIdPClient{ensureUserID: "user-bob"})
	srv.roles = nil

	_, err := srv.AcceptInvitation(context.Background(), &tenantv1.AcceptInvitationRequest{Token: "rawtoken"})
	if status_grpc.Code(err) != codes.Unavailable {
		t.Fatalf("AcceptInvitation code = %v (err=%v), want Unavailable", status_grpc.Code(err), err)
	}
}

func TestAcceptInvitation_EnsureHumanUserErrorIsInternal(t *testing.T) {
	srv := acceptInvitationFixture(t, &membersIdPClient{ensureErr: errors.New("idp boom")})

	_, err := srv.AcceptInvitation(context.Background(), &tenantv1.AcceptInvitationRequest{Token: "rawtoken"})
	if status_grpc.Code(err) != codes.Internal {
		t.Fatalf("AcceptInvitation code = %v (err=%v), want Internal", status_grpc.Code(err), err)
	}
}

func TestAcceptInvitation_AssignErrorIsInternal(t *testing.T) {
	srv := acceptInvitationFixture(t, &membersIdPClient{ensureUserID: "user-bob"})
	grants := newFakeGrants()
	grants.createErr = errors.New("create boom")
	tuples, err := tenantrole.AuthzTuples(srv.authorizer)
	if err != nil {
		t.Fatalf("AuthzTuples: %v", err)
	}
	srv.roles = tenantrole.NewSyncer(grants, tuples, nil)

	_, err = srv.AcceptInvitation(context.Background(), &tenantv1.AcceptInvitationRequest{Token: "rawtoken"})
	if status_grpc.Code(err) != codes.Internal {
		t.Fatalf("AcceptInvitation code = %v (err=%v), want Internal", status_grpc.Code(err), err)
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
	// The caller's tenant must ride the UPDATE as $3, not just the id.
	mock.ExpectExec("UPDATE tenant_invitations SET status").
		WithArgs("inv-2", "cancelled", "acme").
		WillReturnResult(sqlmock.NewResult(0, 1))

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

// --- SetStatus tenant-predicate tests ---

// The UPDATE must carry a tenant predicate. Without it, tenant_invitations is a
// shared table keyed only by a UUID, so possession of an id from another tenant
// is enough to mutate that tenant's row.
func TestInvitationStore_SetStatus_CarriesTenantPredicate(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectExec(regexp.QuoteMeta("WHERE id = $1 AND tenant_id = $3")).
		WithArgs("inv-1", "accepted", "acme").
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := NewInvitationStore(db).SetStatus(context.Background(), "acme", "inv-1", "accepted"); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock: %v", err)
	}
}

// An id belonging to another tenant matches no row, and the caller is told
// "not found" — the same answer as a nonexistent id, so nothing leaks about
// whether the invitation exists elsewhere.
func TestInvitationStore_SetStatus_RefusesCrossTenantID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// victim tenant's invitation id, attacker's tenant → zero rows.
	mock.ExpectExec("UPDATE tenant_invitations SET status").
		WithArgs("inv-victim", "cancelled", "attacker-tenant").
		WillReturnResult(sqlmock.NewResult(0, 0))

	err = NewInvitationStore(db).SetStatus(context.Background(), "attacker-tenant", "inv-victim", "cancelled")
	if !errors.Is(err, ErrInvitationNotFound) {
		t.Fatalf("cross-tenant SetStatus err = %v, want ErrInvitationNotFound", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock: %v", err)
	}
}

// An empty tenant must not degrade to an id-only UPDATE.
func TestInvitationStore_SetStatus_RequiresTenant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// No ExpectExec: the store must not reach the DB at all.
	if err := NewInvitationStore(db).SetStatus(context.Background(), "", "inv-1", "cancelled"); err == nil {
		t.Fatal("SetStatus with an empty tenant succeeded; want an error")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock: %v", err)
	}
}

// TestAcceptInvitation_SessionSeedErrorIsInternal pins that a failed session
// seed fails the accept rather than leaving a member ext-authz will deny on
// every call. The invitation stays pending, so a retry repairs it.
func TestAcceptInvitation_SessionSeedErrorIsInternal(t *testing.T) {
	srv := acceptInvitationFixture(t, &membersIdPClient{ensureUserID: "user-bob"})
	srv.authorizer.(*membersAuthorizer).conditionalErr = errors.New("fga boom")

	_, err := srv.AcceptInvitation(context.Background(), &tenantv1.AcceptInvitationRequest{Token: "rawtoken"})
	if status_grpc.Code(err) != codes.Internal {
		t.Fatalf("AcceptInvitation code = %v (err=%v), want Internal", status_grpc.Code(err), err)
	}
}

// TestSeedSessionTuples_Failures pins both failure paths of the session seed:
// an authorizer that cannot write conditional tuples, and a failed per-tenant
// write after the user-scoped one succeeded. Either one fails the accept.
func TestSeedSessionTuples_Failures(t *testing.T) {
	t.Run("authorizer without conditional writes", func(t *testing.T) {
		s := &TenantAdminServer{authorizer: newOwnershipAuthorizer()}
		if err := s.seedSessionTuples(context.Background(), "user-bob", "acme"); err == nil {
			t.Fatal("expected an error from an authorizer that cannot write session tuples")
		}
	})
	t.Run("per-tenant write fails", func(t *testing.T) {
		az := &membersAuthorizer{conditionalFailObject: "tenant:acme"}
		s := &TenantAdminServer{authorizer: az}
		err := s.seedSessionTuples(context.Background(), "user-bob", "acme")
		if err == nil || !strings.Contains(err.Error(), "tenant acme") {
			t.Fatalf("err = %v, want the per-tenant write failure", err)
		}
		if !reflect.DeepEqual(az.conditionalWrites, []authz.ConditionalTuple{authz.ActiveSessionUserTuple("user-bob")}) {
			t.Fatalf("writes = %+v, want only the user-scoped tuple before the failure", az.conditionalWrites)
		}
	})
}
