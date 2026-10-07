// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/zeroroot-ai/gibson/internal/platform/mailer"
)

// fakeWelcome records each owner welcome and can fail.
type fakeWelcome struct {
	sent []mailer.OwnerWelcomeEmail
	err  error
}

func (f *fakeWelcome) SendOwnerWelcome(_ context.Context, w mailer.OwnerWelcomeEmail) error {
	f.sent = append(f.sent, w)
	return f.err
}

const welcomeClaim = "UPDATE pending_tenant_provisioning SET welcome_sent_at = NOW\\(\\)"

func welcomeServer(t *testing.T, sender OwnerWelcomeSender) (*DaemonServer, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv := newPendingServer().WithOwnerWelcome(sender, "https://app.example.test/", "https://api.example.test")
	srv.platformDB = db
	return srv, mock
}

// Two ready reports send one email: the second claim finds the row already
// sent. The email names the tenant and both origins.
func TestOwnerWelcome_OneSendPerTenant(t *testing.T) {
	sender := &fakeWelcome{}
	srv, mock := welcomeServer(t, sender)
	ctx := context.Background()

	expectEnsureTable(mock)
	mock.ExpectQuery(welcomeClaim).WithArgs("acme").
		WillReturnRows(sqlmock.NewRows([]string{"owner_email"}).AddRow("owner@acme.example"))
	srv.welcomeOwnerIfReady(ctx, srv.platformDB, "acme", tenantPhaseReady, true)

	expectEnsureTable(mock)
	mock.ExpectQuery(welcomeClaim).WithArgs("acme").WillReturnRows(sqlmock.NewRows([]string{"owner_email"}))
	srv.welcomeOwnerIfReady(ctx, srv.platformDB, "acme", tenantPhaseReady, true)

	if len(sender.sent) != 1 {
		t.Fatalf("sent %d emails, want 1", len(sender.sent))
	}
	got := sender.sent[0]
	want := mailer.OwnerWelcomeEmail{
		To: "owner@acme.example", TenantID: "acme",
		AppURL: "https://app.example.test", APIURL: "https://api.example.test",
	}
	if got != want {
		t.Fatalf("welcome = %+v, want %+v", got, want)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// A report of a tenant that is not ready touches nothing.
func TestOwnerWelcome_NotReadyDoesNothing(t *testing.T) {
	sender := &fakeWelcome{}
	srv, mock := welcomeServer(t, sender)
	srv.welcomeOwnerIfReady(context.Background(), srv.platformDB, "acme", "Provisioning", true)
	srv.welcomeOwnerIfReady(context.Background(), srv.platformDB, "acme", tenantPhaseReady, false)
	if len(sender.sent) != 0 {
		t.Fatalf("sent %d emails for a tenant that is not ready", len(sender.sent))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// A failed send releases the claim, so the next ready report tries again.
func TestOwnerWelcome_AFailedSendReleasesTheClaim(t *testing.T) {
	sender := &fakeWelcome{err: errors.New("smtp down")}
	srv, mock := welcomeServer(t, sender)

	expectEnsureTable(mock)
	mock.ExpectQuery(welcomeClaim).WithArgs("acme").
		WillReturnRows(sqlmock.NewRows([]string{"owner_email"}).AddRow("owner@acme.example"))
	mock.ExpectExec("SET welcome_sent_at = NULL").WithArgs("acme").WillReturnResult(sqlmock.NewResult(0, 1))
	if err := srv.welcomeOwner(context.Background(), srv.platformDB, "acme"); err == nil {
		t.Fatal("welcomeOwner reported success for a failed send")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// An install with no mail transport keeps the claim and sends nothing, so the
// skip is logged once and the signup does not fail.
func TestOwnerWelcome_NoTransportSkips(t *testing.T) {
	srv, mock := welcomeServer(t, nil)
	expectEnsureTable(mock)
	mock.ExpectQuery(welcomeClaim).WithArgs("acme").
		WillReturnRows(sqlmock.NewRows([]string{"owner_email"}).AddRow("owner@acme.example"))
	if err := srv.welcomeOwner(context.Background(), srv.platformDB, "acme"); err != nil {
		t.Fatalf("welcomeOwner with no transport: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// A claim error is reported, and nothing is sent.
func TestOwnerWelcome_ClaimError(t *testing.T) {
	sender := &fakeWelcome{}
	srv, mock := welcomeServer(t, sender)
	expectEnsureTable(mock)
	mock.ExpectQuery(welcomeClaim).WillReturnError(errors.New("down"))
	if err := srv.welcomeOwner(context.Background(), srv.platformDB, "acme"); err == nil {
		t.Fatal("welcomeOwner hid a claim error")
	}
	if len(sender.sent) != 0 {
		t.Fatal("sent an email after a claim error")
	}
}
