// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package admin

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// The RPCs in this package are authorized by ext-authz against an object
// derived from the CALLER's identity, so a tenant_id carried in the request
// body is authorized by nothing. These tests pin the resulting contract:
// a request naming a tenant other than the caller's is rejected, and no FGA
// tuple, invitation, or Zitadel org membership is produced as a side effect.

const (
	scopeCallerTenant  = "acme"
	scopeForeignTenant = "victim-co"
)

// grpcCodeOf extracts the gRPC status code from an error, or codes.OK for nil.
func grpcCodeOf(err error) codes.Code {
	if err == nil {
		return codes.OK
	}
	st, ok := status.FromError(err)
	if !ok {
		return codes.Unknown
	}
	return st.Code()
}

// TestSetTenantRole_ForeignTenantRejected is the highest-severity case in the
// package: SetTenantRole writes an FGA role tuple AND projects Zitadel org
// membership. If the request tenant selected the object, a tenant admin could
// grant themselves a role on a tenant they hold no relation on.
func TestSetTenantRole_ForeignTenantRejected(t *testing.T) {
	cases := []struct {
		name         string
		reqTenantID  string
		wantCode     codes.Code
		wantTenantIn string // FGA object the tuple must name, "" when none written
	}{
		{
			name:        "foreign tenant is rejected",
			reqTenantID: scopeForeignTenant,
			wantCode:    codes.PermissionDenied,
		},
		{
			name:        "foreign tenant with an explicit type prefix is rejected",
			reqTenantID: "tenant:" + scopeForeignTenant,
			wantCode:    codes.PermissionDenied,
		},
		{
			name:         "own tenant is served",
			reqTenantID:  scopeCallerTenant,
			wantCode:     codes.OK,
			wantTenantIn: "tenant:" + scopeCallerTenant,
		},
		{
			name:         "omitted tenant falls to the caller's own tenant",
			reqTenantID:  "",
			wantCode:     codes.OK,
			wantTenantIn: "tenant:" + scopeCallerTenant,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// checkResult=false so an accepted call actually performs the
			// Write, letting the test read back the object it named.
			az := &tenantScopeAuthorizer{checkResult: false}
			idpC := &membersIdPClient{}
			srv := newMembersTestServer(t, &membersAuthorizer{}, idpC)
			srv.authorizer = az
			srv.orgResolver = staticOrgResolver{orgID: "org-123"}

			ctx := ctxWithTenant(t, scopeCallerTenant)
			_, err := srv.SetTenantRole(ctx, &tenantv1.SetTenantRoleRequest{
				TenantId: tc.reqTenantID,
				UserId:   "attacker-id",
				Role:     "owner",
			})
			if got := grpcCodeOf(err); got != tc.wantCode {
				t.Fatalf("SetTenantRole code = %v (err=%v), want %v", got, err, tc.wantCode)
			}

			if tc.wantCode != codes.OK {
				// A rejected call must leave no trace on either projection.
				if len(az.wrote) != 0 {
					t.Errorf("rejected call wrote FGA tuples: %+v", az.wrote)
				}
				if len(idpC.added) != 0 {
					t.Errorf("rejected call added Zitadel org members: %+v", idpC.added)
				}
				return
			}

			if len(az.wrote) != 1 {
				t.Fatalf("expected exactly 1 written tuple, got %d: %+v", len(az.wrote), az.wrote)
			}
			if got := az.wrote[0].Object; got != tc.wantTenantIn {
				t.Errorf("tuple object = %q, want %q", got, tc.wantTenantIn)
			}
		})
	}
}

// TestTransferOwnership_ForeignTenantRejected covers the other destructive
// role RPC: it deletes every existing owner tuple on the named tenant before
// installing a new one.
func TestTransferOwnership_ForeignTenantRejected(t *testing.T) {
	az := &tenantScopeAuthorizer{checkResult: true}
	srv := newMembersTestServer(t, &membersAuthorizer{}, nil)
	srv.authorizer = az

	ctx := ctxWithTenant(t, scopeCallerTenant)
	_, err := srv.TransferOwnership(ctx, &tenantv1.TransferOwnershipRequest{
		TenantId:       scopeForeignTenant,
		NewOwnerUserId: "attacker-id",
	})
	if got := grpcCodeOf(err); got != codes.PermissionDenied {
		t.Fatalf("TransferOwnership code = %v (err=%v), want PermissionDenied", got, err)
	}
	if len(az.deleted) != 0 || len(az.wrote) != 0 {
		t.Errorf("rejected call mutated FGA: wrote=%+v deleted=%+v", az.wrote, az.deleted)
	}
}

// TestTeamRPCs_ForeignTenantRejected sweeps the team-management surface. Each
// of these used to derive BOTH sides of its "cross-tenant denial" FGA check
// from the request, which made the guard always pass.
func TestTeamRPCs_ForeignTenantRejected(t *testing.T) {
	cases := []struct {
		name string
		call func(srv *TenantAdminServer, ctx context.Context) error
	}{
		{"ListTeams", func(srv *TenantAdminServer, ctx context.Context) error {
			_, err := srv.ListTeams(ctx, &tenantv1.ListTeamsRequest{TenantId: scopeForeignTenant})
			return err
		}},
		{"ListTeamMembers", func(srv *TenantAdminServer, ctx context.Context) error {
			_, err := srv.ListTeamMembers(ctx, &tenantv1.ListTeamMembersRequest{
				TenantId: scopeForeignTenant, TeamId: "victim-team",
			})
			return err
		}},
		{"CreateTeam", func(srv *TenantAdminServer, ctx context.Context) error {
			_, err := srv.CreateTeam(ctx, &tenantv1.CreateTeamRequest{
				TenantId: scopeForeignTenant, TeamId: "planted-team",
			})
			return err
		}},
		{"DeleteTeam", func(srv *TenantAdminServer, ctx context.Context) error {
			_, err := srv.DeleteTeam(ctx, &tenantv1.DeleteTeamRequest{
				TenantId: scopeForeignTenant, TeamId: "victim-team",
			})
			return err
		}},
		{"AddTeamMember", func(srv *TenantAdminServer, ctx context.Context) error {
			_, err := srv.AddTeamMember(ctx, &tenantv1.AddTeamMemberRequest{
				TenantId: scopeForeignTenant, TeamId: "victim-team", UserId: "attacker-id",
			})
			return err
		}},
		{"RemoveTeamMember", func(srv *TenantAdminServer, ctx context.Context) error {
			_, err := srv.RemoveTeamMember(ctx, &tenantv1.RemoveTeamMemberRequest{
				TenantId: scopeForeignTenant, TeamId: "victim-team", UserId: "victim-user",
			})
			return err
		}},
		{"SetTeamAdmin", func(srv *TenantAdminServer, ctx context.Context) error {
			_, err := srv.SetTeamAdmin(ctx, &tenantv1.SetTeamAdminRequest{
				TenantId: scopeForeignTenant, TeamId: "victim-team",
				UserId: "attacker-id", IsAdmin: true,
			})
			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// checkResult=true reproduces exactly what the old self-satisfying
			// parent guard saw. The request must still be rejected, before FGA
			// is consulted at all.
			az := &tenantScopeAuthorizer{checkResult: true}
			srv, _, _, _, _, _, _ := newTenantTestServer(t)
			srv.authorizer = az

			err := tc.call(srv, ctxWithTenant(t, scopeCallerTenant))
			if got := grpcCodeOf(err); got != codes.PermissionDenied {
				t.Fatalf("%s code = %v (err=%v), want PermissionDenied", tc.name, got, err)
			}
			if len(az.wrote) != 0 || len(az.deleted) != 0 {
				t.Errorf("rejected call mutated FGA: wrote=%+v deleted=%+v", az.wrote, az.deleted)
			}
		})
	}
}

// TestRequireCallerTenant_NoTenantInContext pins the fail-closed branch: a
// context carrying no authenticated tenant at all (never produced by a real
// ext-authz-authorized call, but not something this function may trust blindly)
// must be rejected with PermissionDenied rather than falling through with an
// empty caller tenant. Uses a real proto request type (any tenantScopedRequest
// will do) rather than a hand-rolled one, so the interface satisfaction has no
// var-naming friction with GetTenantId's protoc-gen-go casing.
func TestRequireCallerTenant_NoTenantInContext(t *testing.T) {
	_, err := requireCallerTenant(context.Background(), &tenantv1.GetTenantQuotaRequest{})
	if err == nil {
		t.Fatal("requireCallerTenant: expected error for a context with no tenant, got nil")
	}
	if grpcCodeOf(err) != codes.PermissionDenied {
		t.Errorf("requireCallerTenant: code = %v, want %v (err: %v)", grpcCodeOf(err), codes.PermissionDenied, err)
	}
}

// TestInvitationRPCs_ForeignTenantRejected covers the invitation chain, where
// a pending invitation is a bearer capability that AcceptInvitation converts
// into a real membership tuple on whichever tenant it was minted against.
func TestInvitationRPCs_ForeignTenantRejected(t *testing.T) {
	cases := []struct {
		name string
		call func(srv *TenantAdminServer, ctx context.Context) error
	}{
		{"InviteMember", func(srv *TenantAdminServer, ctx context.Context) error {
			_, err := srv.InviteMember(ctx, &tenantv1.InviteMemberRequest{
				TenantId: scopeForeignTenant, Email: "attacker@example.test", Role: "admin",
			})
			return err
		}},
		{"ResendInvitation", func(srv *TenantAdminServer, ctx context.Context) error {
			_, err := srv.ResendInvitation(ctx, &tenantv1.ResendInvitationRequest{
				TenantId: scopeForeignTenant, Email: "victim@example.test",
			})
			return err
		}},
		{"CancelInvitation", func(srv *TenantAdminServer, ctx context.Context) error {
			_, err := srv.CancelInvitation(ctx, &tenantv1.CancelInvitationRequest{
				TenantId: scopeForeignTenant, Email: "victim@example.test",
			})
			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The invitation store is deliberately left unwired: a rejected
			// call must fail on the tenant scope (PermissionDenied) before it
			// reaches the nil-store check (Unavailable).
			srv := newMembersTestServer(t, &membersAuthorizer{}, &membersIdPClient{})

			err := tc.call(srv, ctxWithTenant(t, scopeCallerTenant))
			if got := grpcCodeOf(err); got != codes.PermissionDenied {
				t.Fatalf("%s code = %v (err=%v), want PermissionDenied", tc.name, got, err)
			}
		})
	}
}

// tenantScopeAuthorizer answers every Check with checkResult and records every
// mutation, so a test can prove a request was rejected on the tenant scope
// rather than on a downstream FGA answer — and can inspect exactly which
// object an accepted request wrote against.
type tenantScopeAuthorizer struct {
	checkResult bool
	wrote       []authz.Tuple
	deleted     []authz.Tuple
}

func (a *tenantScopeAuthorizer) Check(_ context.Context, _, _, _ string) (bool, error) {
	return a.checkResult, nil
}
func (a *tenantScopeAuthorizer) BatchCheck(_ context.Context, checks []authz.CheckRequest) ([]bool, error) {
	out := make([]bool, len(checks))
	for i := range out {
		out[i] = a.checkResult
	}
	return out, nil
}
func (a *tenantScopeAuthorizer) Write(_ context.Context, tuples []authz.Tuple) error {
	a.wrote = append(a.wrote, tuples...)
	return nil
}
func (a *tenantScopeAuthorizer) Delete(_ context.Context, tuples []authz.Tuple) error {
	a.deleted = append(a.deleted, tuples...)
	return nil
}
func (a *tenantScopeAuthorizer) ListObjects(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (a *tenantScopeAuthorizer) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (a *tenantScopeAuthorizer) StoreID() string { return "test" }
func (a *tenantScopeAuthorizer) ModelID() string { return "test" }
func (a *tenantScopeAuthorizer) Close() error    { return nil }

// ListUsersOfType is a security gate in this package; a double that is
// not set up for it must fail the gate loudly rather than answer "nobody".
func (a *tenantScopeAuthorizer) ListUsersOfType(context.Context, string, string, string, string) ([]string, error) {
	return nil, errListUsersOfTypeNotStubbed
}
