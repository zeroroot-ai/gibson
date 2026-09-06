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

// componentOpsAuthorizer is a minimal authz.Authorizer for
// GrantComponentPermissions tests. BatchCheck reports true for any
// (user, relation, object) key present in `granted`; Write records every
// written tuple.
type componentOpsAuthorizer struct {
	granted map[string]bool
	wrote   []authz.Tuple
}

func componentOpsKey(user, relation, object string) string {
	return user + "|" + relation + "|" + object
}

func (a *componentOpsAuthorizer) Check(context.Context, string, string, string) (bool, error) {
	return false, nil
}
func (a *componentOpsAuthorizer) BatchCheck(_ context.Context, checks []authz.CheckRequest) ([]bool, error) {
	out := make([]bool, len(checks))
	for i, c := range checks {
		out[i] = a.granted[componentOpsKey(c.User, c.Relation, c.Object)]
	}
	return out, nil
}
func (a *componentOpsAuthorizer) Write(_ context.Context, tuples []authz.Tuple) error {
	a.wrote = append(a.wrote, tuples...)
	return nil
}
func (a *componentOpsAuthorizer) Delete(context.Context, []authz.Tuple) error { return nil }
func (a *componentOpsAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}
func (a *componentOpsAuthorizer) ListUsers(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}
func (a *componentOpsAuthorizer) StoreID() string { return "test" }
func (a *componentOpsAuthorizer) ModelID() string { return "test" }
func (a *componentOpsAuthorizer) Close() error    { return nil }

func (a *componentOpsAuthorizer) hasWritten(user, relation, object string) bool {
	for _, tup := range a.wrote {
		if tup.User == user && tup.Relation == relation && tup.Object == object {
			return true
		}
	}
	return false
}

// TestGrantComponentPermissions_HappyPath pins the fix for the regression
// that shipped in the first cut of this handler: a dashboard-minted
// agent_installation_id (`${randomUUID()}-${tenantId}`, see
// installAgent.ts) has NO pre-existing `belongs_to` tuple, so gating on an
// FGA Check for it denied every real install. The fix verifies the id's own
// tenant suffix against the caller's authenticated tenant instead, and
// self-heals the belongs_to tuple as part of the grant.
func TestGrantComponentPermissions_HappyPath(t *testing.T) {
	const installationID = "3fa85f64-5717-4562-b3fc-2c963f66afa6-acme"
	az := &componentOpsAuthorizer{granted: map[string]bool{
		componentOpsKey("user:user-1", "can_execute", "component:plugin/gitlab"): true,
	}}
	srv, _, _, _, _, _, _ := newTenantTestServer(t)
	srv.authorizer = az

	ctx := ctxWithTenant(t, "acme")
	resp, err := srv.GrantComponentPermissions(ctx, &tenantv1.GrantComponentPermissionsRequest{
		AgentInstallationId: installationID,
		Approvals: []*tenantv1.ComponentApproval{
			{Target: "component:plugin/gitlab", Action: "execute"},
		},
	})
	if err != nil {
		t.Fatalf("GrantComponentPermissions: unexpected error: %v", err)
	}
	if resp.GetAgentInstallationId() != installationID {
		t.Errorf("agent_installation_id = %q, want %q", resp.GetAgentInstallationId(), installationID)
	}

	agentRef := "agent_principal:" + installationID
	if !az.hasWritten("tenant:acme", "belongs_to", agentRef) {
		t.Errorf("expected a self-healed belongs_to tuple (tenant:acme, belongs_to, %s); wrote: %+v", agentRef, az.wrote)
	}
	if !az.hasWritten(agentRef, "component_execute_enabled", "component:plugin/gitlab") {
		t.Errorf("expected the component_execute_enabled grant to be written; wrote: %+v", az.wrote)
	}
}

// TestGrantComponentPermissions_RejectsForeignTenantSuffix locks the actual
// authorization boundary: a caller authenticated as tenant "acme" cannot
// forward a grant to a principal id minted under a different tenant's
// suffix, even though nothing in FGA would have stopped an unconditional
// Write (there is no pre-existing belongs_to tuple to contradict either
// tenant's claim). The suffix comparison is against the caller's own
// ctx-derived tenant, so an attacker cannot choose which tenant they're
// compared against.
func TestGrantComponentPermissions_RejectsForeignTenantSuffix(t *testing.T) {
	const installationID = "3fa85f64-5717-4562-b3fc-2c963f66afa6-victim-co"
	az := &componentOpsAuthorizer{granted: map[string]bool{
		componentOpsKey("user:user-1", "can_execute", "component:plugin/gitlab"): true,
	}}
	srv, _, _, _, _, _, _ := newTenantTestServer(t)
	srv.authorizer = az

	ctx := ctxWithTenant(t, "acme")
	_, err := srv.GrantComponentPermissions(ctx, &tenantv1.GrantComponentPermissionsRequest{
		AgentInstallationId: installationID,
		Approvals: []*tenantv1.ComponentApproval{
			{Target: "component:plugin/gitlab", Action: "execute"},
		},
	})
	if err == nil {
		t.Fatal("GrantComponentPermissions: expected error for a foreign-tenant-suffixed installation id, got nil")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("code = %v, want %v (err: %v)", status.Code(err), codes.PermissionDenied, err)
	}
	if len(az.wrote) != 0 {
		t.Errorf("expected no tuples written on rejection, got %+v", az.wrote)
	}
}

// TestGrantComponentPermissions_RejectsSuffixCollision guards the exact-split
// design in agentInstallationTenantSuffix against a naive
// strings.HasSuffix("-"+tenant) implementation: tenant slugs may themselves
// contain hyphens, so an id honestly minted for tenant "my-acme" also ends
// with "-acme" as a raw string. A caller authenticated as tenant "acme" must
// not be able to piggyback on that collision.
func TestGrantComponentPermissions_RejectsSuffixCollision(t *testing.T) {
	// 36-char UUID + "-my-acme": ends in "-acme" as a bare string, but the
	// exact post-UUID remainder is "my-acme", not "acme".
	const installationID = "3fa85f64-5717-4562-b3fc-2c963f66afa6-my-acme"
	az := &componentOpsAuthorizer{granted: map[string]bool{
		componentOpsKey("user:user-1", "can_execute", "component:plugin/gitlab"): true,
	}}
	srv, _, _, _, _, _, _ := newTenantTestServer(t)
	srv.authorizer = az

	ctx := ctxWithTenant(t, "acme")
	_, err := srv.GrantComponentPermissions(ctx, &tenantv1.GrantComponentPermissionsRequest{
		AgentInstallationId: installationID,
		Approvals: []*tenantv1.ComponentApproval{
			{Target: "component:plugin/gitlab", Action: "execute"},
		},
	})
	if err == nil {
		t.Fatal("GrantComponentPermissions: expected error, exact-remainder \"my-acme\" != caller tenant \"acme\"")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("code = %v, want %v (err: %v)", status.Code(err), codes.PermissionDenied, err)
	}
	if len(az.wrote) != 0 {
		t.Errorf("expected no tuples written on rejection, got %+v", az.wrote)
	}
}

// TestGrantComponentPermissions_RejectsMalformedID covers ids that are too
// short to carry a UUID + separator, or that omit the separator entirely.
func TestGrantComponentPermissions_RejectsMalformedID(t *testing.T) {
	cases := []string{
		"acme",              // far too short
		"not-a-uuid-at-all", // no correctly placed separator at offset 36
	}
	for _, id := range cases {
		t.Run(id, func(t *testing.T) {
			az := &componentOpsAuthorizer{granted: map[string]bool{}}
			srv, _, _, _, _, _, _ := newTenantTestServer(t)
			srv.authorizer = az

			ctx := ctxWithTenant(t, "acme")
			_, err := srv.GrantComponentPermissions(ctx, &tenantv1.GrantComponentPermissionsRequest{
				AgentInstallationId: id,
				Approvals: []*tenantv1.ComponentApproval{
					{Target: "component:plugin/gitlab", Action: "execute"},
				},
			})
			if err == nil {
				t.Fatal("expected error for malformed agent_installation_id")
			}
			if status.Code(err) != codes.PermissionDenied {
				t.Errorf("code = %v, want %v (err: %v)", status.Code(err), codes.PermissionDenied, err)
			}
		})
	}
}

// TestGrantComponentPermissions_CallerLacksAccess confirms the caller-access
// intersection still rejects forwarding a capability the caller does not
// hold, and that nothing (including the belongs_to self-heal) is written
// when that check fails.
func TestGrantComponentPermissions_CallerLacksAccess(t *testing.T) {
	const installationID = "3fa85f64-5717-4562-b3fc-2c963f66afa6-acme"
	az := &componentOpsAuthorizer{granted: map[string]bool{}} // caller has nothing
	srv, _, _, _, _, _, _ := newTenantTestServer(t)
	srv.authorizer = az

	ctx := ctxWithTenant(t, "acme")
	_, err := srv.GrantComponentPermissions(ctx, &tenantv1.GrantComponentPermissionsRequest{
		AgentInstallationId: installationID,
		Approvals: []*tenantv1.ComponentApproval{
			{Target: "component:plugin/gitlab", Action: "execute"},
		},
	})
	if err == nil {
		t.Fatal("expected error when the caller lacks access on the target component")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("code = %v, want %v (err: %v)", status.Code(err), codes.PermissionDenied, err)
	}
	if len(az.wrote) != 0 {
		t.Errorf("expected no tuples written (not even belongs_to) when caller-access fails, got %+v", az.wrote)
	}
}

// ListUsersOfType is a security gate in this package; a double that is
// not set up for it must fail the gate loudly rather than answer "nobody".
func (a *componentOpsAuthorizer) ListUsersOfType(context.Context, string, string, string, string) ([]string, error) {
	return nil, errListUsersOfTypeNotStubbed
}
