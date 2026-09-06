// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package admin

import (
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// TestAddTeamMember_RejectsUserOutsideTenant is the regression test for
// identity-assertion-gaps finding 4: AddTeamMember must verify the target
// user actually belongs to the caller's tenant before writing a team
// membership tuple for them. Before the fix, AddTeamMember only checked
// that the TEAM belongs to the caller's tenant — it never checked the
// USER — so a caller could add an arbitrary caller-supplied user_id (one
// from a different tenant, or simply a guessed ID) to one of their own
// teams and hand that user whatever access the team grants.
func TestAddTeamMember_RejectsUserOutsideTenant(t *testing.T) {
	// present seeds only the team-ownership tuple; the target user's tenant
	// membership tuple is deliberately absent, simulating a user who does
	// not belong to "zero-root" at all.
	sa := &stubAuthorizer{present: map[string]bool{
		"tenant:zero-root|parent|team:zero-root/red": true,
	}}
	srv, _, _, _, _, _, _ := newTenantTestServer(t)
	srv.authorizer = sa

	ctx := adminCtx(t, "zero-root")
	_, err := srv.AddTeamMember(ctx, &tenantv1.AddTeamMemberRequest{
		TeamId: "red",
		UserId: "outsider-id",
	})
	if err == nil {
		t.Fatal("REGRESSION (identity-assertion-gaps finding 4): expected PermissionDenied when the target " +
			"user is not a member of the caller's tenant; got nil (cross-tenant team-membership escalation)")
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", got)
	}
	if len(sa.wrote) != 0 {
		t.Errorf("wrote %d tuples, want 0 (tenant-membership check must reject before any write)", len(sa.wrote))
	}
}

// TestAddTeamMember_TenantMembershipCheckErrorFailsClosed covers the
// fail-closed path when the tenant-membership Check itself errors (e.g. an
// FGA outage) — must reject with Internal and write nothing, not silently
// treat the error as "not a member" or, worse, as "is a member".
func TestAddTeamMember_TenantMembershipCheckErrorFailsClosed(t *testing.T) {
	sa := &stubAuthorizer{
		present: map[string]bool{
			"tenant:zero-root|parent|team:zero-root/red": true,
		},
		checkErrFor: map[string]error{
			"user:flaky-id|member|tenant:zero-root": errors.New("fga unavailable"),
		},
	}
	srv, _, _, _, _, _, _ := newTenantTestServer(t)
	srv.authorizer = sa

	ctx := adminCtx(t, "zero-root")
	_, err := srv.AddTeamMember(ctx, &tenantv1.AddTeamMemberRequest{
		TeamId: "red",
		UserId: "flaky-id",
	})
	if err == nil {
		t.Fatal("expected Internal error when the tenant-membership Check fails; got nil")
	}
	if got := status.Code(err); got != codes.Internal {
		t.Errorf("code = %v, want Internal", got)
	}
	if len(sa.wrote) != 0 {
		t.Errorf("wrote %d tuples, want 0", len(sa.wrote))
	}
}

// TestAddTeamMember_AllowsUserInsideTenant is the paired happy-path: a user
// who genuinely holds the tenant "member" relation can be added to one of
// that tenant's teams, and exactly one (user, member, team) tuple is
// written.
func TestAddTeamMember_AllowsUserInsideTenant(t *testing.T) {
	sa := &stubAuthorizer{present: map[string]bool{
		"tenant:zero-root|parent|team:zero-root/red": true,
		"user:insider-id|member|tenant:zero-root":    true,
	}}
	srv, _, _, _, _, _, _ := newTenantTestServer(t)
	srv.authorizer = sa

	ctx := adminCtx(t, "zero-root")
	_, err := srv.AddTeamMember(ctx, &tenantv1.AddTeamMemberRequest{
		TeamId: "red",
		UserId: "insider-id",
	})
	if err != nil {
		t.Fatalf("AddTeamMember: unexpected error: %v", err)
	}
	if len(sa.wrote) != 1 {
		t.Fatalf("expected exactly 1 written tuple, got %d: %+v", len(sa.wrote), sa.wrote)
	}
	got := sa.wrote[0]
	if got.User != "user:insider-id" || got.Relation != "member" || got.Object != "team:zero-root/red" {
		t.Errorf("tuple = %+v, want {user:insider-id member team:zero-root/red}", got)
	}
}
