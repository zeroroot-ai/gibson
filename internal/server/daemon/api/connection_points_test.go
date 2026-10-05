// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	connectionv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/connection/v1"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

const (
	testCompleterSVID  = "spiffe://zeroroot.ai/component/step-completer"
	testActivationSVID = "spiffe://zeroroot.ai/component/activation"
	testEnvoySVID      = "spiffe://zeroroot.ai/platform/envoy"
)

// peerCtx returns a context whose TLS peer carries svid.
func peerCtx(t *testing.T, svid string) context.Context {
	t.Helper()
	u, err := url.Parse(svid)
	if err != nil {
		t.Fatal(err)
	}
	info := credentials.TLSInfo{State: tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{u}}},
	}}
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: info})
}

func connectionServer() *DaemonServer {
	return newPendingServer().WithConnectionPointCallers(ConnectionPointCallers{
		SignupStepCompleter: testCompleterSVID,
		TenantActivation:    testActivationSVID,
	})
}

// Only the configured identity completes a step. Envoy, the other connection
// point identity and a call with no TLS peer get a refusal, and the database
// is never touched.
func TestCompleteSignupStep_RefusesEveryOtherCaller(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := connectionServer()
	srv.platformDB = db

	req := &connectionv1.CompleteSignupStepRequest{
		StepToken: "tok",
		Outcome:   connectionv1.SignupStepOutcome_SIGNUP_STEP_OUTCOME_DONE,
	}
	for name, ctx := range map[string]context.Context{
		"envoy":                      peerCtx(t, testEnvoySVID),
		"the activation identity":    peerCtx(t, testActivationSVID),
		"no TLS peer":                context.Background(),
		"an identity of another org": peerCtx(t, "spiffe://example.org/component/step-completer"),
	} {
		if _, err := srv.CompleteSignupStep(ctx, req); status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: code = %v, want PermissionDenied", name, status.Code(err))
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("a refused caller touched the database: %v", err)
	}
}

// With no identity configured, no caller is accepted.
func TestConnectionPoints_NoConfiguredCallerAcceptsNobody(t *testing.T) {
	srv := newPendingServer()
	_, err := srv.CompleteSignupStep(peerCtx(t, testCompleterSVID), &connectionv1.CompleteSignupStepRequest{
		StepToken: "tok", Outcome: connectionv1.SignupStepOutcome_SIGNUP_STEP_OUTCOME_DONE,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("CompleteSignupStep code = %v, want PermissionDenied", status.Code(err))
	}
	_, err = srv.SetTenantActivation(peerCtx(t, testActivationSVID), &connectionv1.SetTenantActivationRequest{
		TenantId: "acme", State: connectionv1.TenantActivationState_TENANT_ACTIVATION_STATE_SUSPENDED,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("SetTenantActivation code = %v, want PermissionDenied", status.Code(err))
	}
	if _, err := srv.ListTenantUsage(peerCtx(t, testActivationSVID), &connectionv1.ListTenantUsageRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ListTenantUsage code = %v, want PermissionDenied", status.Code(err))
	}
}

// DONE moves the row of the token to 'pending', where the operator drain sees
// it. The query matches the token by its hash, never by the raw value.
func TestCompleteSignupStep_DoneReleasesTheTenant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := connectionServer()
	srv.platformDB = db

	expectEnsureTable(mock)
	mock.ExpectExec("UPDATE pending_tenant_provisioning").
		WithArgs(hashSignupStepToken("tok"), true, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	_, err = srv.CompleteSignupStep(peerCtx(t, testCompleterSVID), &connectionv1.CompleteSignupStepRequest{
		StepToken: "tok", Outcome: connectionv1.SignupStepOutcome_SIGNUP_STEP_OUTCOME_DONE,
	})
	if err != nil {
		t.Fatalf("CompleteSignupStep: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// An unknown or expired token, and so the token of a signup that does not
// exist, gets NotFound.
func TestCompleteSignupStep_UnknownTokenIsNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := connectionServer()
	srv.platformDB = db

	expectEnsureTable(mock)
	mock.ExpectExec("UPDATE pending_tenant_provisioning").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs(hashSignupStepToken("nope")).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	_, err = srv.CompleteSignupStep(peerCtx(t, testCompleterSVID), &connectionv1.CompleteSignupStepRequest{
		StepToken: "nope", Outcome: connectionv1.SignupStepOutcome_SIGNUP_STEP_OUTCOME_DONE,
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v, want NotFound", status.Code(err))
	}
}

// A retry after the step is done succeeds and changes nothing.
func TestCompleteSignupStep_ARetryAfterDoneSucceeds(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := connectionServer()
	srv.platformDB = db

	expectEnsureTable(mock)
	mock.ExpectExec("UPDATE pending_tenant_provisioning").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT EXISTS").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	_, err = srv.CompleteSignupStep(peerCtx(t, testCompleterSVID), &connectionv1.CompleteSignupStepRequest{
		StepToken: "tok", Outcome: connectionv1.SignupStepOutcome_SIGNUP_STEP_OUTCOME_DONE,
	})
	if err != nil {
		t.Fatalf("a retry after done must succeed: %v", err)
	}
}

func TestCompleteSignupStep_RefusesAnUnspecifiedOutcome(t *testing.T) {
	srv := connectionServer()
	_, err := srv.CompleteSignupStep(peerCtx(t, testCompleterSVID), &connectionv1.CompleteSignupStepRequest{StepToken: "tok"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
}

func TestStepStateOf(t *testing.T) {
	cases := []struct {
		status, hash string
		want         tenantv1.SignupStepState
	}{
		{"pending", "", tenantv1.SignupStepState_SIGNUP_STEP_STATE_NONE},
		{"waiting_step", "h", tenantv1.SignupStepState_SIGNUP_STEP_STATE_WAITING},
		{"step_failed", "h", tenantv1.SignupStepState_SIGNUP_STEP_STATE_FAILED},
		{"pending", "h", tenantv1.SignupStepState_SIGNUP_STEP_STATE_DONE},
		{"done", "h", tenantv1.SignupStepState_SIGNUP_STEP_STATE_DONE},
	}
	for _, c := range cases {
		if got := stepStateOf(c.status, c.hash); got != c.want {
			t.Errorf("stepStateOf(%q, %q) = %v, want %v", c.status, c.hash, got, c.want)
		}
	}
}

// Two tokens are never equal, and the stored form is not the token.
func TestNewSignupStepToken_IsRandomAndStoredHashed(t *testing.T) {
	a, ha, err := newSignupStepToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := newSignupStepToken()
	if err != nil {
		t.Fatal(err)
	}
	if a == b || len(a) < 40 {
		t.Fatalf("tokens %q and %q are not random 32-byte values", a, b)
	}
	if ha == a || ha != hashSignupStepToken(a) {
		t.Fatal("the stored form must be the hash of the token")
	}
}

// A suspended tenant cannot start new work. A tenant with no row is active.
func TestRequireActiveTenant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := newPendingServer()
	srv.platformDB = db

	mock.ExpectQuery("SELECT activation FROM tenant_status").WithArgs("acme").
		WillReturnRows(sqlmock.NewRows([]string{"activation"}).AddRow("suspended"))
	if err := srv.requireActiveTenant(context.Background(), "acme"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("suspended tenant: code = %v, want FailedPrecondition", status.Code(err))
	}

	mock.ExpectQuery("SELECT activation FROM tenant_status").WithArgs("globex").
		WillReturnRows(sqlmock.NewRows([]string{"activation"}))
	if err := srv.requireActiveTenant(context.Background(), "globex"); err != nil {
		t.Fatalf("a tenant with no row must be active: %v", err)
	}

	// SetTenantActivation drops the cached read, so the next call reads again.
	srv.tenantActivation.forget("acme")
	mock.ExpectQuery("SELECT activation FROM tenant_status").WithArgs("acme").
		WillReturnRows(sqlmock.NewRows([]string{"activation"}).AddRow("active"))
	if err := srv.requireActiveTenant(context.Background(), "acme"); err != nil {
		t.Fatalf("an active tenant must pass: %v", err)
	}
}

func TestSetTenantActivation_SuspendsAKnownTenant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := connectionServer()
	srv.platformDB = db

	expectEnsureTenantStatusTable(mock)
	mock.ExpectQuery("SELECT activation FROM tenant_status").WithArgs("acme").
		WillReturnRows(sqlmock.NewRows([]string{"activation"}).AddRow("active"))
	mock.ExpectExec("UPDATE tenant_status SET activation").WithArgs("acme", "suspended").
		WillReturnResult(sqlmock.NewResult(0, 1))

	resp, err := srv.SetTenantActivation(peerCtx(t, testActivationSVID), &connectionv1.SetTenantActivationRequest{
		TenantId: "acme", State: connectionv1.TenantActivationState_TENANT_ACTIVATION_STATE_SUSPENDED,
	})
	if err != nil {
		t.Fatalf("SetTenantActivation: %v", err)
	}
	if !resp.GetChanged() {
		t.Fatal("changed = false, want true")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSetTenantActivation_UnknownTenantIsNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := connectionServer()
	srv.platformDB = db

	expectEnsureTenantStatusTable(mock)
	mock.ExpectQuery("SELECT activation FROM tenant_status").WithArgs("ghost").
		WillReturnRows(sqlmock.NewRows([]string{"activation"}))

	_, err = srv.SetTenantActivation(peerCtx(t, testActivationSVID), &connectionv1.SetTenantActivationRequest{
		TenantId: "ghost", State: connectionv1.TenantActivationState_TENANT_ACTIVATION_STATE_ACTIVE,
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v, want NotFound", status.Code(err))
	}
}
