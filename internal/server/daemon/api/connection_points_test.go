// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	connectionv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/connection/v1"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

const (
	testCompleterSVID  = "spiffe://zeroroot.ai/component/step-completer"
	testActivationSVID = "spiffe://zeroroot.ai/component/activation"
	testEnvoySVID      = "spiffe://zeroroot.ai/platform/envoy"
)

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

// usageEnforcer is a budget enforcer that also reads the usage of a tenant.
type usageEnforcer struct {
	budgetEnforcerIface
	usage map[string][2]int64
}

func (u usageEnforcer) TenantPeriodUsage(_ context.Context, tenantID string) (tokens, cost int64, resetAt time.Time) {
	v := u.usage[tenantID]
	return v[0], v[1], time.Time{}
}

// The usage report gives one row for each known tenant and the bounds of the
// budget period. Only the activation identity may read it.
func TestListTenantUsage(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := connectionServer()
	srv.platformDB = db
	srv.budgetEnforcer = usageEnforcer{usage: map[string][2]int64{"acme": {1200, 34}}}
	srv.signupClock = func() time.Time { return time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC) }

	if _, err := srv.ListTenantUsage(peerCtx(t, testCompleterSVID), &connectionv1.ListTenantUsageRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("another caller: code = %v, want PermissionDenied", status.Code(err))
	}

	expectEnsureTenantStatusTable(mock)
	mock.ExpectQuery("SELECT tenant_id FROM tenant_status").
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow("acme").AddRow("globex"))
	resp, err := srv.ListTenantUsage(peerCtx(t, testActivationSVID), &connectionv1.ListTenantUsageRequest{})
	if err != nil {
		t.Fatalf("ListTenantUsage: %v", err)
	}
	rows := resp.GetTenants()
	if len(rows) != 2 || rows[0].GetTenantId() != "acme" || rows[0].GetTokens() != 1200 || rows[0].GetCostUsdCents() != 34 ||
		rows[1].GetTenantId() != "globex" || rows[1].GetTokens() != 0 {
		t.Fatalf("tenants = %v", rows)
	}
	if resp.GetPeriodStartUnix() >= resp.GetPeriodEndUnix() {
		t.Errorf("period %d..%d is empty", resp.GetPeriodStartUnix(), resp.GetPeriodEndUnix())
	}

	expectEnsureTenantStatusTable(mock)
	mock.ExpectQuery("SELECT tenant_id FROM tenant_status").WillReturnError(errors.New("db down"))
	if _, err := srv.ListTenantUsage(peerCtx(t, testActivationSVID), &connectionv1.ListTenantUsageRequest{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("db error: code = %v, want Unavailable", status.Code(err))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// The dashboard reads the state of the step of an attempt. An unknown attempt
// reads as NONE, and a database error is Unavailable.
func TestGetSignupStep(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := connectionServer()
	srv.platformDB = db
	const attempt = "8f14e45f-ceea-467f-a8f5-9b2c1d2e3f40"

	if _, err := srv.GetSignupStep(context.Background(), &tenantv1.GetSignupStepRequest{AttemptId: "nope"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad attempt id: code = %v, want InvalidArgument", status.Code(err))
	}

	cases := []struct {
		rows *sqlmock.Rows
		want tenantv1.SignupStepState
	}{
		{sqlmock.NewRows([]string{"status", "step_token_hash"}).AddRow("waiting_step", "h"), tenantv1.SignupStepState_SIGNUP_STEP_STATE_WAITING},
		{sqlmock.NewRows([]string{"status", "step_token_hash"}), tenantv1.SignupStepState_SIGNUP_STEP_STATE_NONE},
	}
	for _, c := range cases {
		expectEnsureTable(mock)
		mock.ExpectQuery("SELECT status, step_token_hash FROM pending_tenant_provisioning").WithArgs(attempt).WillReturnRows(c.rows)
		resp, err := srv.GetSignupStep(context.Background(), &tenantv1.GetSignupStepRequest{AttemptId: attempt})
		if err != nil || resp.GetState() != c.want {
			t.Fatalf("GetSignupStep = %v, %v, want %v", resp.GetState(), err, c.want)
		}
	}

	expectEnsureTable(mock)
	mock.ExpectQuery("SELECT status, step_token_hash FROM pending_tenant_provisioning").WillReturnError(errors.New("db down"))
	if _, err := srv.GetSignupStep(context.Background(), &tenantv1.GetSignupStepRequest{AttemptId: attempt}); status.Code(err) != codes.Unavailable {
		t.Fatalf("db error: code = %v, want Unavailable", status.Code(err))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
