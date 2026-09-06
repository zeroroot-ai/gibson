// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// server_enqueue_tenant_provisioning_test.go — tests for the workload-authed
// EnqueueTenantProvisioning handler used by the first-tenant seed (gibson#1496).
package api

import (
	"context"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

func TestEnqueueTenantProvisioning_EmptyTenantID_InvalidArgument(t *testing.T) {
	srv := newPendingServer()
	_, err := srv.EnqueueTenantProvisioning(context.Background(),
		&daemonoperatorv1.EnqueueTenantProvisioningRequest{OwnerEmail: "a@b.test"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", err)
	}
}

func TestEnqueueTenantProvisioning_EmptyOwnerEmail_InvalidArgument(t *testing.T) {
	srv := newPendingServer()
	_, err := srv.EnqueueTenantProvisioning(context.Background(),
		&daemonoperatorv1.EnqueueTenantProvisioningRequest{TenantId: "acme"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", err)
	}
}

func TestEnqueueTenantProvisioning_FreshInsert_DefaultsTier(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	srv := newPendingServer()
	srv.platformDB = db

	expectEnsureTable(mock)
	// owner_user_id is empty (no Zitadel user yet); tier defaults to "team".
	mock.ExpectExec("INSERT INTO pending_tenant_provisioning").
		WithArgs("acme", "", "owner@acme.test", "Acme Inc", "team", "").
		WillReturnResult(sqlmock.NewResult(1, 1))

	resp, err := srv.EnqueueTenantProvisioning(context.Background(),
		&daemonoperatorv1.EnqueueTenantProvisioningRequest{
			TenantId:    "acme",
			DisplayName: "Acme Inc",
			OwnerEmail:  "owner@acme.test",
		})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if resp.GetAlreadyExisted() {
		t.Errorf("expected already_existed=false on fresh insert")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestEnqueueTenantProvisioning_Conflict_AlreadyExisted(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	srv := newPendingServer()
	srv.platformDB = db

	expectEnsureTable(mock)
	mock.ExpectExec("INSERT INTO pending_tenant_provisioning").
		WithArgs("acme", "", "owner@acme.test", "", "enterprise", "").
		WillReturnResult(sqlmock.NewResult(0, 0))

	resp, err := srv.EnqueueTenantProvisioning(context.Background(),
		&daemonoperatorv1.EnqueueTenantProvisioningRequest{
			TenantId:   "acme",
			OwnerEmail: "owner@acme.test",
			Tier:       "enterprise",
		})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if !resp.GetAlreadyExisted() {
		t.Errorf("expected already_existed=true on conflict")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestEnqueueTenantProvisioning_DBError_Internal(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	srv := newPendingServer()
	srv.platformDB = db

	expectEnsureTable(mock)
	mock.ExpectExec("INSERT INTO pending_tenant_provisioning").
		WillReturnError(context.DeadlineExceeded)

	_, err = srv.EnqueueTenantProvisioning(context.Background(),
		&daemonoperatorv1.EnqueueTenantProvisioningRequest{
			TenantId:   "acme",
			OwnerEmail: "owner@acme.test",
		})
	if status.Code(err) != codes.Internal {
		t.Fatalf("want Internal on DB error, got %v", err)
	}
}
