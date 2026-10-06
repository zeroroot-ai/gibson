// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	connectionv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/connection/v1"
)

// The step completer reads the tenant, the plan and the owner address of a
// known token (gibson#943).
func TestDescribeSignupStep_KnownToken(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := connectionServer()
	srv.platformDB = db

	expectEnsureTable(mock)
	mock.ExpectQuery("SELECT tenant_id, tier, owner_email FROM pending_tenant_provisioning").
		WithArgs(hashSignupStepToken("tok"), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id", "tier", "owner_email"}).
			AddRow("acme", "team", "owner@acme.example"))

	got, err := srv.DescribeSignupStep(peerCtx(t, testCompleterSVID), &connectionv1.DescribeSignupStepRequest{StepToken: "tok"})
	if err != nil {
		t.Fatalf("DescribeSignupStep: %v", err)
	}
	if got.GetTenantId() != "acme" || got.GetPlanId() != "team" || got.GetOwnerEmail() != "owner@acme.example" {
		t.Fatalf("DescribeSignupStep = %+v, want acme, team, owner@acme.example", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// An unknown or expired token gets NotFound. A read error is Unavailable.
func TestDescribeSignupStep_UnknownTokenAndReadError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := connectionServer()
	srv.platformDB = db
	ctx := peerCtx(t, testCompleterSVID)

	expectEnsureTable(mock)
	mock.ExpectQuery("SELECT tenant_id, tier, owner_email").
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id", "tier", "owner_email"}))
	if _, err := srv.DescribeSignupStep(ctx, &connectionv1.DescribeSignupStepRequest{StepToken: "nope"}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown token: code = %v, want NotFound", status.Code(err))
	}

	expectEnsureTable(mock)
	mock.ExpectQuery("SELECT tenant_id, tier, owner_email").WillReturnError(errors.New("down"))
	if _, err := srv.DescribeSignupStep(ctx, &connectionv1.DescribeSignupStepRequest{StepToken: "tok"}); status.Code(err) != codes.Unavailable {
		t.Fatalf("read error: code = %v, want Unavailable", status.Code(err))
	}

	if _, err := srv.DescribeSignupStep(ctx, &connectionv1.DescribeSignupStepRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty token: code = %v, want InvalidArgument", status.Code(err))
	}
	srv.platformDB = nil
	if _, err := srv.DescribeSignupStep(ctx, &connectionv1.DescribeSignupStepRequest{StepToken: "tok"}); status.Code(err) != codes.Unavailable {
		t.Fatalf("no database: code = %v, want Unavailable", status.Code(err))
	}
}

// Only the step completer identity may read a signup. Every other caller is
// refused before the database.
func TestDescribeSignupStep_RefusesEveryOtherCaller(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := connectionServer()
	srv.platformDB = db

	for name, ctx := range map[string]context.Context{
		"envoy":                   peerCtx(t, testEnvoySVID),
		"the activation identity": peerCtx(t, testActivationSVID),
		"no TLS peer":             context.Background(),
	} {
		if _, err := srv.DescribeSignupStep(ctx, &connectionv1.DescribeSignupStepRequest{StepToken: "tok"}); status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: code = %v, want PermissionDenied", name, status.Code(err))
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("a refused caller touched the database: %v", err)
	}
}
