// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// expectPendingInsert wires a sqlmock platform DB that accepts one pending
// tenant and keeps the audit_record_id it was given.
func expectPendingInsert(t *testing.T, srv *DaemonServer) (*captureArg, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv.platformDB = db
	expectEnsureTable(mock)
	recordID := &captureArg{}
	mock.ExpectExec("INSERT INTO pending_tenant_provisioning").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), recordID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	return recordID, mock
}

// recordWithAction returns the one event with action, or fails.
func recordWithAction(t *testing.T, events []audit.Event, action string) audit.Event {
	t.Helper()
	for _, ev := range events {
		if ev.Action == action {
			return ev
		}
	}
	t.Fatalf("no %q record in %+v", action, events)
	return audit.Event{}
}

// A self-serve signup records the request with the new owner as actor, and
// the queue entry carries the record id (gibson#583).
func TestSignup_QueueEntryNamesTheRequestRecord(t *testing.T) {
	h := newSignupHarness(t)
	writer := &fakeAuditWriter{}
	h.srv.tenantAdminAuditWriter = writer
	session := h.requestAndRedeem(t)
	h.idp.createHumanFn = func(_ context.Context, _ idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
		return idp.CreateHumanUserResult{UserID: "user-owner"}, nil
	}
	recordID, mock := expectPendingInsert(t, h.srv)

	if _, err := h.srv.Signup(context.Background(), &tenantv1.SignupRequest{
		AttemptId: testAttemptID, VerifiedSessionToken: session, Password: "s3cret-passw0rd!",
	}); err != nil {
		t.Fatalf("Signup: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
	ev := recordWithAction(t, writer.events, auditActionSignupTenantRequested)
	if ev.ActorID != "user-owner" || ev.TargetType != "tenant" || ev.TenantID != ev.TargetID {
		t.Fatalf("record = %+v", ev)
	}
	if recordID.got == "" || !strings.Contains(string(ev.Metadata), `"entry_id":"`+recordID.got+`"`) {
		t.Fatalf("queued audit_record_id %q is not the entry_id of %s", recordID.got, ev.Metadata)
	}
}

// With no signup record, nothing is queued.
func TestSignup_NoRecordNoQueue(t *testing.T) {
	h := newSignupHarness(t)
	h.srv.tenantAdminAuditWriter = &fakeAuditWriter{syncErr: errAuditDown}
	session := h.requestAndRedeem(t)
	h.idp.createHumanFn = func(_ context.Context, _ idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
		return idp.CreateHumanUserResult{UserID: "user-owner"}, nil
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	h.srv.platformDB = db

	_, err = h.srv.Signup(context.Background(), &tenantv1.SignupRequest{
		AttemptId: testAttemptID, VerifiedSessionToken: session, Password: "s3cret-passw0rd!",
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("status = %v, want Unavailable", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("a tenant was queued with no record: %v", err)
	}
}

// An approval queues the tenant with the id of the approval record, so the
// operator records name the approving administrator (gibson#583).
func TestAdminApproveRegistration_QueueEntryNamesTheApproval(t *testing.T) {
	h, writer := newApprovalHarness(t)
	reg, err := h.srv.Register(context.Background(), registerRequest())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	recordID, mock := expectPendingInsert(t, h.srv)

	if _, err := h.srv.AdminApproveRegistration(adminCtx("admin-1"),
		&tenantv1.AdminApproveRegistrationRequest{RegistrationId: reg.GetRegistrationId()}); err != nil {
		t.Fatalf("AdminApproveRegistration: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
	ev := recordWithAction(t, writer.events, "signup_registration.approved")
	if ev.ActorID != "admin-1" || recordID.got == "" ||
		!strings.Contains(string(ev.Metadata), `"entry_id":"`+recordID.got+`"`) {
		t.Fatalf("queued audit_record_id %q does not name the approval %+v", recordID.got, ev)
	}
}
