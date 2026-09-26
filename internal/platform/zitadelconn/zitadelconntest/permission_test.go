// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadelconntest_test

import (
	"net/http"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn/zitadelconntest"
)

// TestGrantRoles_Unrestricted_ByDefault verifies an Identity that never calls
// GrantRoles enforces nothing — every test written before this permission
// gate existed keeps passing unchanged.
func TestGrantRoles_Unrestricted_ByDefault(t *testing.T) {
	id, ep := newFake(t)
	orgID := id.AddOrg("acme")

	status := postWithOrg(t, ep, "/management/v1/orgs/me/members", orgID,
		map[string]any{"userId": "u1", "roles": []string{"ORG_OWNER"}}, nil)
	if status != http.StatusOK {
		t.Fatalf("AddOrgMember: expected 200 with no grant configured, got %d", status)
	}
}

// TestGrantRoles_NoRolesGranted_RefusesEveryGatedCall verifies that once
// GrantRoles is called at all (even with an empty set), every gated call is
// refused the way a real Zitadel credential with no roles is refused.
func TestGrantRoles_NoRolesGranted_RefusesEveryGatedCall(t *testing.T) {
	id, ep := newFake(t)
	id.GrantRoles() // explicit: no roles at all
	orgID := id.AddOrg("acme")

	status := postWithOrg(t, ep, "/management/v1/orgs/me/members", orgID,
		map[string]any{"userId": "u1", "roles": []string{"ORG_OWNER"}}, nil)
	if status != http.StatusForbidden {
		t.Fatalf("AddOrgMember with no roles granted: expected 403, got %d", status)
	}

	var resp map[string]any
	status = post(t, ep, "/zitadel.authorization.v2.AuthorizationService/CreateAuthorization",
		map[string]any{"userId": "u1", "projectId": "p1", "organizationId": orgID, "roleKeys": []string{"owner"}}, &resp)
	if status != http.StatusForbidden {
		t.Fatalf("CreateAuthorization with no roles granted: expected 403, got %d", status)
	}
	if resp["code"] != "permission_denied" {
		t.Fatalf("expected a permission_denied Connect error, got %v", resp)
	}
}

// TestGrantRoles_NoRolesGranted_RefusesEveryGatedEndpoint exercises the
// refusal branch of every endpoint this package gates behind a permission,
// not just the two calls hosted#199/#200 care about most (org member,
// authorizations) — a permission check that compiles but is never exercised
// on its refusing path is the kind of guard that cannot fail.
func TestGrantRoles_NoRolesGranted_RefusesEveryGatedEndpoint(t *testing.T) {
	id, ep := newFake(t)
	id.GrantRoles() // no roles at all
	projectID := id.AddProject(id.AddOrg("platform"), "gibson")

	cases := []struct {
		name string
		path string
		body map[string]any
	}{
		{"ListProjectRoles", "/zitadel.project.v2.ProjectService/ListProjectRoles", map[string]any{"projectId": projectID}},
		{"AddProjectRole", "/zitadel.project.v2.ProjectService/AddProjectRole", map[string]any{"projectId": projectID, "roleKey": "owner"}},
		{"UpdateProjectRole", "/zitadel.project.v2.ProjectService/UpdateProjectRole", map[string]any{"projectId": projectID, "roleKey": "owner"}},
		{"RemoveProjectRole", "/zitadel.project.v2.ProjectService/RemoveProjectRole", map[string]any{"projectId": projectID, "roleKey": "owner"}},
		{"ListProjectGrants", "/zitadel.project.v2.ProjectService/ListProjectGrants", map[string]any{}},
		{"CreateProjectGrant", "/zitadel.project.v2.ProjectService/CreateProjectGrant", map[string]any{"projectId": projectID, "grantedOrganizationId": "org-1"}},
		{"UpdateProjectGrant", "/zitadel.project.v2.ProjectService/UpdateProjectGrant", map[string]any{"projectId": projectID, "grantedOrganizationId": "org-1"}},
		{"UpdateAuthorization", "/zitadel.authorization.v2.AuthorizationService/UpdateAuthorization", map[string]any{"id": "grant-1"}},
		{"DeleteAuthorization", "/zitadel.authorization.v2.AuthorizationService/DeleteAuthorization", map[string]any{"id": "grant-1"}},
		{"ListAuthorizations", "/zitadel.authorization.v2.AuthorizationService/ListAuthorizations", map[string]any{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if status := post(t, ep, c.path, c.body, nil); status != http.StatusForbidden {
				t.Fatalf("%s with no roles granted: expected 403, got %d", c.name, status)
			}
		})
	}
}

// TestGrantRoles_IAMOrgManager_CoversDaemonAndTenantOperatorCalls proves the
// role hosted#199/#200 chose (IAM_ORG_MANAGER, no IAM_OWNER) actually covers
// every call this fake implements that the daemon and the tenant-operator
// make: adding an org member, granting the gibson project to a tenant org,
// and creating/listing/updating/deleting a tenant role authorization.
func TestGrantRoles_IAMOrgManager_CoversDaemonAndTenantOperatorCalls(t *testing.T) {
	id, ep := newFake(t)
	id.GrantRoles("IAM_ORG_MANAGER")

	platformOrg := id.AddOrg("platform")
	tenantOrg := id.AddOrg("acme")
	projectID := id.AddProject(platformOrg, "gibson")
	userID := id.AddUser(tenantOrg, "owner@acme.example")

	// Seed the project's roles the way platform-operator's EnsureProjectRoles
	// does, via the same wire path CreateProjectGrant/CreateAuthorization
	// validate role keys against.
	if status := post(t, ep, "/zitadel.project.v2.ProjectService/AddProjectRole",
		map[string]any{"projectId": projectID, "roleKey": "owner", "displayName": "Owner"}, nil); status != http.StatusOK {
		t.Fatalf("AddProjectRole: expected 200, got %d", status)
	}

	// Tenant-operator: grant the gibson project to the new tenant org.
	if status := post(t, ep, "/zitadel.project.v2.ProjectService/CreateProjectGrant",
		map[string]any{"projectId": projectID, "grantedOrganizationId": tenantOrg, "roleKeys": []string{"owner"}}, nil); status != http.StatusOK {
		t.Fatalf("CreateProjectGrant: expected 200, got %d", status)
	}
	var listResp map[string]any
	if status := post(t, ep, "/zitadel.project.v2.ProjectService/ListProjectGrants",
		map[string]any{"filters": []map[string]any{{"inProjectIdsFilter": map[string]any{"ids": []string{projectID}}}}}, &listResp); status != http.StatusOK {
		t.Fatalf("ListProjectGrants: expected 200, got %d", status)
	}

	// Tenant-operator / daemon: add the founding member to the tenant org.
	if status := postWithOrg(t, ep, "/management/v1/orgs/me/members", tenantOrg,
		map[string]any{"userId": userID, "roles": []string{"ORG_OWNER"}}, nil); status != http.StatusOK {
		t.Fatalf("AddOrgMember: expected 200, got %d", status)
	}

	// Daemon / bootstrap-tenant-owner: grant the tenant role (an
	// authorization) and read it back.
	var createResp struct {
		ID string `json:"id"`
	}
	if status := post(t, ep, "/zitadel.authorization.v2.AuthorizationService/CreateAuthorization",
		map[string]any{"userId": userID, "projectId": projectID, "organizationId": tenantOrg, "roleKeys": []string{"owner"}}, &createResp); status != http.StatusOK {
		t.Fatalf("CreateAuthorization: expected 200, got %d", status)
	}
	if createResp.ID == "" {
		t.Fatal("CreateAuthorization: expected a grant id")
	}
	if status := post(t, ep, "/zitadel.authorization.v2.AuthorizationService/ListAuthorizations",
		map[string]any{"filters": []map[string]any{{"organizationId": map[string]string{"id": tenantOrg}}}}, nil); status != http.StatusOK {
		t.Fatalf("ListAuthorizations: expected 200, got %d", status)
	}
	if status := post(t, ep, "/zitadel.authorization.v2.AuthorizationService/UpdateAuthorization",
		map[string]any{"id": createResp.ID, "roleKeys": []string{"owner"}}, nil); status != http.StatusOK {
		t.Fatalf("UpdateAuthorization: expected 200, got %d", status)
	}
	// Session revocation and user CRUD are not modeled by this fake's HTTP
	// routes yet (see the k3d acceptance script for those, against a live
	// Zitadel); DeleteAuthorization closes the tenant-role lifecycle this
	// fake does model.
	if status := post(t, ep, "/zitadel.authorization.v2.AuthorizationService/DeleteAuthorization",
		map[string]any{"id": createResp.ID}, nil); status != http.StatusOK {
		t.Fatalf("DeleteAuthorization: expected 200, got %d", status)
	}
}

// TestGrantRoles_IAMUserManager_MissingOrgMemberWrite is the evidence behind
// hosted#199/#200's role choice: IAM_USER_MANAGER is not enough because it
// carries no org.member.write, so adding a tenant org member — a call both
// the daemon and the tenant-operator make — is refused, while a user-grant
// call the same credential IS allowed for still succeeds. This is why
// IAM_ORG_MANAGER, not IAM_USER_MANAGER, was chosen.
func TestGrantRoles_IAMUserManager_MissingOrgMemberWrite(t *testing.T) {
	id, ep := newFake(t)
	id.GrantRoles("IAM_USER_MANAGER")
	orgID := id.AddOrg("acme")

	status := postWithOrg(t, ep, "/management/v1/orgs/me/members", orgID,
		map[string]any{"userId": "u1", "roles": []string{"ORG_OWNER"}}, nil)
	if status != http.StatusForbidden {
		t.Fatalf("AddOrgMember under IAM_USER_MANAGER: expected 403 (no org.member.write), got %d", status)
	}

	// The same credential's user.grant.read is fine.
	if status := post(t, ep, "/zitadel.authorization.v2.AuthorizationService/ListAuthorizations",
		map[string]any{"filters": []map[string]any{{"organizationId": map[string]string{"id": orgID}}}}, nil); status != http.StatusOK {
		t.Fatalf("ListAuthorizations under IAM_USER_MANAGER: expected 200, got %d", status)
	}
}

// TestBuiltinRolePermissions_IAMOrgManagerExcludesIAMPermissions pins the
// finding that makes IAM_ORG_MANAGER strictly narrower than IAM_OWNER: it
// does not carry the iam.* family (instance-wide IAM member/IdP/action/flow/
// feature management), which only IAM_OWNER has.
func TestBuiltinRolePermissions_IAMOrgManagerExcludesIAMPermissions(t *testing.T) {
	perms := zitadelconntest.BuiltinRolePermissions["IAM_ORG_MANAGER"]
	for _, p := range perms {
		if p == zitadelconntest.PermIAMMemberWrite {
			t.Fatal("IAM_ORG_MANAGER must not carry an iam.* permission")
		}
	}
	ownerPerms := zitadelconntest.BuiltinRolePermissions["IAM_OWNER"]
	found := false
	for _, p := range ownerPerms {
		if p == zitadelconntest.PermIAMMemberWrite {
			found = true
		}
	}
	if !found {
		t.Fatal("IAM_OWNER must carry the iam.* permission this test compares against")
	}
}
