// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// server_tenant_admin_gate_test.go — tests for requireTenantAdmin and
// isTenantAdmin, the admin gates of the tenant RPCs.
package api

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/sdk/auth"
)

func newAdminGateTestServer() *DaemonServer {
	return &DaemonServer{
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
}

// With no authorizer wired at all, the admin gate refuses with Unavailable. It
// never lets the request through.
func TestRequireTenantAdmin_NoAuthorizer_Unavailable(t *testing.T) {
	srv := newAdminGateTestServer() // authorizer intentionally left nil
	ctx := auth.WithIdentity(context.Background(), auth.Identity{Subject: "an-admin"})
	requireGRPCStatus(t, srv.requireTenantAdmin(ctx, "acme"), codes.Unavailable)
}

func requireGRPCStatus(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected gRPC %s, got nil", want)
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status, got %T %v", err, err)
	}
	if st.Code() != want {
		t.Fatalf("expected gRPC code %s, got %s (%v)", want, st.Code(), err)
	}
}

// A SPIFFE caller holds its tenant relation as "user:<id>" with the scheme
// stripped (principal.FGAUser). The admin gate asks FGA in that form, so a
// SPIFFE admin passes it.
func TestRequireTenantAdmin_ASPIFFECallerIsCheckedInItsTupleForm(t *testing.T) {
	srv := newAdminGateTestServer()
	srv.WithAuthorizer(newFakeAuthorizer().allow("user:zeroroot.ai/platform/e2e-runner", "admin", "tenant:acme"))
	ctx := auth.WithIdentity(context.Background(), auth.Identity{Subject: "spiffe://zeroroot.ai/platform/e2e-runner"})
	if err := srv.requireTenantAdmin(ctx, "acme"); err != nil {
		t.Fatalf("requireTenantAdmin: %v", err)
	}
}

// A tuple in the old "user:spiffe://..." form grants nothing: the gate asks in
// the stripped form only.
func TestRequireTenantAdmin_TheOldSPIFFETupleFormGrantsNothing(t *testing.T) {
	srv := newAdminGateTestServer()
	srv.WithAuthorizer(newFakeAuthorizer().allow("user:spiffe://zeroroot.ai/platform/e2e-runner", "admin", "tenant:acme"))
	ctx := auth.WithIdentity(context.Background(), auth.Identity{Subject: "spiffe://zeroroot.ai/platform/e2e-runner"})
	requireGRPCStatus(t, srv.requireTenantAdmin(ctx, "acme"), codes.PermissionDenied)
}

// A typed component principal is checked as itself, not as a user. The FGA
// model gives it no admin relation, so the gate refuses it.
func TestRequireTenantAdmin_AComponentPrincipalIsCheckedAsItself(t *testing.T) {
	srv := newAdminGateTestServer()
	srv.WithAuthorizer(newFakeAuthorizer().allow("user:tool_principal:nmap", "admin", "tenant:acme"))
	ctx := auth.WithIdentity(context.Background(), auth.Identity{Subject: "tool_principal:nmap"})
	requireGRPCStatus(t, srv.requireTenantAdmin(ctx, "acme"), codes.PermissionDenied)
}

// isTenantAdmin (budgets, usage) asks in the same form as requireTenantAdmin,
// so the two gates agree for a SPIFFE admin.
func TestIsTenantAdmin_ASPIFFECallerIsCheckedInItsTupleForm(t *testing.T) {
	srv := newAdminGateTestServer()
	srv.WithAuthorizer(newFakeAuthorizer().allow("user:zeroroot.ai/platform/e2e-runner", "admin", "tenant:acme"))
	ctx := auth.WithIdentity(context.Background(), auth.Identity{Subject: "spiffe://zeroroot.ai/platform/e2e-runner"})
	_, admin, err := srv.isTenantAdmin(ctx, "acme")
	if err != nil || !admin {
		t.Fatalf("isTenantAdmin = %v, %v; want an admin", admin, err)
	}
}
