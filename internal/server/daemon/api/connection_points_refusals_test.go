// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/url"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	connectionv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/connection/v1"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

var errDB = errors.New("db down")

// mockedConnectionServer is a connection point server on a sqlmock database.
func mockedConnectionServer(t *testing.T) (*DaemonServer, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv := connectionServer()
	srv.platformDB = db
	return srv, mock
}

func wantCode(t *testing.T, name string, err error, want codes.Code) {
	t.Helper()
	if status.Code(err) != want {
		t.Errorf("%s: code %v (%v), want %v", name, status.Code(err), err, want)
	}
}

// A peer that is not a TLS peer with a SPIFFE URI has no SVID.
func TestTLSPeerSVID_RefusesEachOtherPeer(t *testing.T) {
	plain := peer.NewContext(context.Background(), &peer.Peer{})
	noCert := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{}})
	httpURI, _ := url.Parse("https://example.com/x")
	notSpiffe := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{httpURI}}},
	}}})
	for name, ctx := range map[string]context.Context{"no peer": context.Background(), "not TLS": plain, "no cert": noCert, "not spiffe": notSpiffe} {
		if _, ok := tlsPeerSVID(ctx); ok {
			t.Errorf("%s: got an SVID", name)
		}
	}
}

func TestCompleteSignupStep_RefusesWhatItCannotServe(t *testing.T) {
	ctx := peerCtx(t, testCompleterSVID)
	done := connectionv1.SignupStepOutcome_SIGNUP_STEP_OUTCOME_DONE
	srv, mock := mockedConnectionServer(t)

	_, err := srv.CompleteSignupStep(ctx, &connectionv1.CompleteSignupStepRequest{Outcome: done})
	wantCode(t, "no token", err, codes.InvalidArgument)
	_, err = srv.CompleteSignupStep(ctx, &connectionv1.CompleteSignupStepRequest{StepToken: "t", Outcome: connectionv1.SignupStepOutcome(99)})
	wantCode(t, "unknown outcome", err, codes.InvalidArgument)

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS pending_tenant_provisioning").WillReturnError(errDB)
	_, err = srv.CompleteSignupStep(ctx, &connectionv1.CompleteSignupStepRequest{StepToken: "t", Outcome: done})
	wantCode(t, "ensure table", err, codes.Internal)

	expectEnsureTable(mock)
	mock.ExpectExec("UPDATE pending_tenant_provisioning").WillReturnError(errDB)
	_, err = srv.CompleteSignupStep(ctx, &connectionv1.CompleteSignupStepRequest{StepToken: "t", Outcome: done})
	wantCode(t, "update fails", err, codes.Unavailable)

	expectEnsureTable(mock)
	mock.ExpectExec("UPDATE pending_tenant_provisioning").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT EXISTS").WillReturnError(errDB)
	_, err = srv.CompleteSignupStep(ctx, &connectionv1.CompleteSignupStepRequest{StepToken: "t", Outcome: done})
	wantCode(t, "read fails", err, codes.Unavailable)

	noDB := connectionServer()
	_, err = noDB.CompleteSignupStep(ctx, &connectionv1.CompleteSignupStepRequest{StepToken: "t", Outcome: done})
	wantCode(t, "no Postgres", err, codes.Unavailable)
}

func TestSetTenantActivation_RefusesWhatItCannotServe(t *testing.T) {
	ctx := peerCtx(t, testActivationSVID)
	active := connectionv1.TenantActivationState_TENANT_ACTIVATION_STATE_ACTIVE
	srv, mock := mockedConnectionServer(t)

	_, err := srv.SetTenantActivation(ctx, &connectionv1.SetTenantActivationRequest{State: active})
	wantCode(t, "no tenant", err, codes.InvalidArgument)
	_, err = srv.SetTenantActivation(ctx, &connectionv1.SetTenantActivationRequest{TenantId: "acme"})
	wantCode(t, "no state", err, codes.InvalidArgument)

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS tenant_status").WillReturnError(errDB)
	_, err = srv.SetTenantActivation(ctx, &connectionv1.SetTenantActivationRequest{TenantId: "acme", State: active})
	wantCode(t, "ensure table", err, codes.Internal)

	expectEnsureTenantStatusTable(mock)
	mock.ExpectQuery("SELECT activation FROM tenant_status").WillReturnError(errDB)
	_, err = srv.SetTenantActivation(ctx, &connectionv1.SetTenantActivationRequest{TenantId: "acme", State: active})
	wantCode(t, "read fails", err, codes.Unavailable)

	expectEnsureTenantStatusTable(mock)
	mock.ExpectQuery("SELECT activation FROM tenant_status").
		WillReturnRows(sqlmock.NewRows([]string{"activation"}).AddRow("suspended"))
	mock.ExpectExec("UPDATE tenant_status SET activation").WillReturnError(errDB)
	_, err = srv.SetTenantActivation(ctx, &connectionv1.SetTenantActivationRequest{TenantId: "acme", State: active})
	wantCode(t, "write fails", err, codes.Unavailable)

	expectEnsureTenantStatusTable(mock)
	mock.ExpectQuery("SELECT activation FROM tenant_status").
		WillReturnRows(sqlmock.NewRows([]string{"activation"}).AddRow("active"))
	resp, err := srv.SetTenantActivation(ctx, &connectionv1.SetTenantActivationRequest{TenantId: "acme", State: active})
	if err != nil || resp.GetChanged() {
		t.Errorf("same state: %v, changed %v, want no change", err, resp.GetChanged())
	}

	noDB := connectionServer()
	_, err = noDB.SetTenantActivation(ctx, &connectionv1.SetTenantActivationRequest{TenantId: "acme", State: active})
	wantCode(t, "no Postgres", err, codes.Unavailable)
}

func TestListTenantUsage_RefusesWhatItCannotServe(t *testing.T) {
	ctx := peerCtx(t, testActivationSVID)
	srv, mock := mockedConnectionServer(t)

	_, err := srv.ListTenantUsage(ctx, &connectionv1.ListTenantUsageRequest{})
	wantCode(t, "no budget counters", err, codes.Unavailable)

	srv.budgetEnforcer = usageEnforcer{}
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS tenant_status").WillReturnError(errDB)
	_, err = srv.ListTenantUsage(ctx, &connectionv1.ListTenantUsageRequest{})
	wantCode(t, "ensure table", err, codes.Internal)

	noDB := connectionServer()
	noDB.budgetEnforcer = usageEnforcer{}
	_, err = noDB.ListTenantUsage(ctx, &connectionv1.ListTenantUsageRequest{})
	wantCode(t, "no Postgres", err, codes.Unavailable)
}

func TestGetSignupStep_RefusesWhatItCannotServe(t *testing.T) {
	const attempt = "8f14e45f-ceea-467f-a8f5-9b2c1d2e3f40"
	_, err := connectionServer().GetSignupStep(context.Background(), &tenantv1.GetSignupStepRequest{AttemptId: attempt})
	wantCode(t, "no Postgres", err, codes.Unavailable)

	srv, mock := mockedConnectionServer(t)
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS pending_tenant_provisioning").WillReturnError(errDB)
	_, err = srv.GetSignupStep(context.Background(), &tenantv1.GetSignupStepRequest{AttemptId: attempt})
	wantCode(t, "ensure table", err, codes.Internal)
}

// The activation gate reads the database once, keeps the answer, refuses a
// suspended tenant, and lets work through when the read fails.
func TestRequireActiveTenant_CacheAndReadFailure(t *testing.T) {
	srv, mock := mockedConnectionServer(t)
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	srv.signupClock = func() time.Time { return now }

	mock.ExpectQuery("SELECT activation FROM tenant_status").WithArgs("acme").
		WillReturnRows(sqlmock.NewRows([]string{"activation"}).AddRow("suspended"))
	for i := 0; i < 2; i++ {
		wantCode(t, "suspended", srv.requireActiveTenant(context.Background(), "acme"), codes.FailedPrecondition)
	}

	mock.ExpectQuery("SELECT activation FROM tenant_status").WithArgs("globex").WillReturnError(errDB)
	if err := srv.requireActiveTenant(context.Background(), "globex"); err != nil {
		t.Errorf("read failure: %v, want no refusal", err)
	}
	if err := srv.requireActiveTenant(context.Background(), ""); err != nil {
		t.Errorf("no tenant: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// A hold has a token only when a step is configured.
func TestHoldForSignupStep(t *testing.T) {
	srv := connectionServer()
	if hold, tok, err := srv.holdForSignupStep("a"); hold != nil || tok != "" || err != nil {
		t.Fatalf("no step URL: %v %q %v", hold, tok, err)
	}
	srv.WithSignupStepURL("https://billing.example/step")
	hold, tok, err := srv.holdForSignupStep("a")
	if err != nil || hold == nil || tok == "" || hold.tokenHash != hashSignupStepToken(tok) {
		t.Fatalf("step URL: %+v %q %v", hold, tok, err)
	}
}
