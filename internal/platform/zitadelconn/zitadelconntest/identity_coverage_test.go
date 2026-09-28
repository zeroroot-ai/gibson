// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadelconntest_test

import (
	"net/http"
	"strings"
	"testing"
)

// TestIdentity_ProjectRoleNotFoundBranches exercises every "unknown
// project" refusal across the project-role, project-grant and
// authorization handlers.
func TestIdentity_ProjectRoleNotFoundBranches(t *testing.T) {
	id, e := newFake(t)
	tenantOrg := id.AddOrg("tenant-1")

	cases := []struct {
		name string
		path string
		body map[string]any
	}{
		{"ListProjectRoles unknown project", "/zitadel.project.v2.ProjectService/ListProjectRoles",
			map[string]any{"projectId": "no-such-project"}},
		{"AddProjectRole unknown project", "/zitadel.project.v2.ProjectService/AddProjectRole",
			map[string]any{"projectId": "no-such-project", "roleKey": "owner", "displayName": "Owner"}},
		{"UpdateProjectRole unknown project", "/zitadel.project.v2.ProjectService/UpdateProjectRole",
			map[string]any{"projectId": "no-such-project", "roleKey": "owner", "displayName": "Owner"}},
		{"RemoveProjectRole unknown project", "/zitadel.project.v2.ProjectService/RemoveProjectRole",
			map[string]any{"projectId": "no-such-project", "roleKey": "owner"}},
		{"CreateProjectGrant unknown project", "/zitadel.project.v2.ProjectService/CreateProjectGrant",
			map[string]any{"projectId": "no-such-project", "grantedOrganizationId": tenantOrg, "roleKeys": []string{"owner"}}},
		{"UpdateProjectGrant unknown project", "/zitadel.project.v2.ProjectService/UpdateProjectGrant",
			map[string]any{"projectId": "no-such-project", "grantedOrganizationId": tenantOrg, "roleKeys": []string{"owner"}}},
		{"CreateAuthorization unknown project", "/zitadel.authorization.v2.AuthorizationService/CreateAuthorization",
			map[string]any{"userId": "no-such-user", "projectId": "no-such-project", "organizationId": tenantOrg, "roleKeys": []string{"owner"}}},
		{"UpdateAuthorization unknown grant", "/zitadel.authorization.v2.AuthorizationService/UpdateAuthorization",
			map[string]any{"id": "no-such-grant", "roleKeys": []string{"owner"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var errBody map[string]any
			status := post(t, e, tc.path, tc.body, &errBody)
			if status != http.StatusNotFound && status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 404 or 400 for %s", status, tc.name)
			}
			if s, _ := errBody["code"].(string); s == "" {
				t.Errorf("expected a Connect error code in the body, got %v", errBody)
			}
		})
	}
}

// TestIdentity_UpdateAndRemoveProjectRole_RoleNotFound covers the
// role-not-found branch on an EXISTING project (distinct from the
// project-not-found branch above).
func TestIdentity_UpdateAndRemoveProjectRole_RoleNotFound(t *testing.T) {
	id, e := newFake(t)
	platformOrg := id.AddOrg("platform")
	projectID := id.AddProject(platformOrg, "gibson")

	var errBody map[string]any
	status := post(t, e, "/zitadel.project.v2.ProjectService/UpdateProjectRole", map[string]any{
		"projectId": projectID, "roleKey": "no-such-role", "displayName": "X",
	}, &errBody)
	if status != http.StatusNotFound {
		t.Fatalf("UpdateProjectRole status = %d, want 404 (Errors.Project.Role.NotFound)", status)
	}

	status = post(t, e, "/zitadel.project.v2.ProjectService/RemoveProjectRole", map[string]any{
		"projectId": projectID, "roleKey": "no-such-role",
	}, &errBody)
	if status != http.StatusNotFound {
		t.Fatalf("RemoveProjectRole status = %d, want 404 (Errors.Project.Role.NotFound)", status)
	}
}

// TestIdentity_UpdateProjectRole_RenamesAnExistingRole covers
// UpdateProjectRole's success path.
func TestIdentity_UpdateProjectRole_RenamesAnExistingRole(t *testing.T) {
	id, e := newFake(t)
	platformOrg := id.AddOrg("platform")
	projectID := id.AddProject(platformOrg, "gibson")
	addRole(t, e, projectID, "owner", "Owner")

	status := post(t, e, "/zitadel.project.v2.ProjectService/UpdateProjectRole", map[string]any{
		"projectId": projectID, "roleKey": "owner", "displayName": "Renamed Owner",
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("UpdateProjectRole status = %d, want 200", status)
	}

	var listed struct {
		ProjectRoles []struct {
			Key         string `json:"key"`
			DisplayName string `json:"displayName"`
		} `json:"projectRoles"`
	}
	post(t, e, "/zitadel.project.v2.ProjectService/ListProjectRoles", map[string]any{"projectId": projectID}, &listed)
	if len(listed.ProjectRoles) != 1 || listed.ProjectRoles[0].Key != "owner" || listed.ProjectRoles[0].DisplayName != "Renamed Owner" {
		t.Fatalf("roles after rename = %+v", listed.ProjectRoles)
	}
}

// TestIdentity_UpdateProjectGrant_RoleNotFoundAndGrantNotFound covers both
// UpdateProjectGrant refusals on an existing project: an unknown role key,
// and no existing grant for the target org.
func TestIdentity_UpdateProjectGrant_RoleNotFoundAndGrantNotFound(t *testing.T) {
	id, e := newFake(t)
	platformOrg := id.AddOrg("platform")
	projectID := id.AddProject(platformOrg, "gibson")
	tenantOrg := id.AddOrg("tenant-1")
	addRole(t, e, projectID, "owner", "Owner")

	var errBody map[string]any
	status := post(t, e, "/zitadel.project.v2.ProjectService/UpdateProjectGrant", map[string]any{
		"projectId": projectID, "grantedOrganizationId": tenantOrg, "roleKeys": []string{"no-such-role"},
	}, &errBody)
	if status != http.StatusBadRequest {
		t.Fatalf("UpdateProjectGrant (bad role) status = %d, want 400", status)
	}

	status = post(t, e, "/zitadel.project.v2.ProjectService/UpdateProjectGrant", map[string]any{
		"projectId": projectID, "grantedOrganizationId": tenantOrg, "roleKeys": []string{"owner"},
	}, &errBody)
	if status != http.StatusNotFound {
		t.Fatalf("UpdateProjectGrant (no grant) status = %d, want 404", status)
	}
}

// TestIdentity_UpdateAuthorization_RoleNotAllowed covers
// UpdateAuthorization's role-restriction check on an existing, active grant.
func TestIdentity_UpdateAuthorization_RoleNotAllowed(t *testing.T) {
	id, e := newFake(t)
	platformOrg := id.AddOrg("platform")
	projectID := id.AddProject(platformOrg, "gibson")
	tenantOrg := id.AddOrg("tenant-1")
	addRole(t, e, projectID, "owner", "Owner")
	grantProject(t, e, projectID, tenantOrg, []string{"owner"})
	userID := id.AddUser(tenantOrg, "x@example.com")

	var grantID string
	post(t, e, "/zitadel.authorization.v2.AuthorizationService/CreateAuthorization", map[string]any{
		"userId": userID, "projectId": projectID, "organizationId": tenantOrg, "roleKeys": []string{"owner"},
	}, &struct {
		ID *string `json:"id"`
	}{&grantID})

	var errBody map[string]any
	status := post(t, e, "/zitadel.authorization.v2.AuthorizationService/UpdateAuthorization", map[string]any{
		"id": grantID, "roleKeys": []string{"not-a-declared-role"},
	}, &errBody)
	if status != http.StatusBadRequest {
		t.Fatalf("UpdateAuthorization (bad role) status = %d, want 400", status)
	}
}

// TestIdentity_AddOrgMember_DecodeErrorAndUnknownOrg covers the
// malformed-body and unknown-org branches of AddOrgMember.
func TestIdentity_AddOrgMember_DecodeErrorAndUnknownOrg(t *testing.T) {
	id, e := newFake(t)
	orgID := id.AddOrg("tenant-1")

	// Malformed JSON body.
	req, err := http.NewRequest(http.MethodPost, e.URL("/management/v1/orgs/me/members"), strings.NewReader("{not json"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-zitadel-orgid", orgID)
	hc := &http.Client{Transport: e.Transport(nil)}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed AddOrgMember body: status = %d, want 400", resp.StatusCode)
	}

	// Unknown org id in the header.
	status := postWithOrg(t, e, "/management/v1/orgs/me/members", "no-such-org", map[string]any{
		"userId": "u1", "roles": []string{"ORG_OWNER"},
	}, nil)
	if status != http.StatusNotFound {
		t.Fatalf("unknown org AddOrgMember: status = %d, want 404", status)
	}
}

// TestIdentity_ListProjectGrants_NoFilterAndProjectFilterOnly covers the
// zero-filter and project-only-filter branches (the orgID-only branch is
// already exercised elsewhere).
func TestIdentity_ListProjectGrants_NoFilterAndProjectFilterOnly(t *testing.T) {
	id, e := newFake(t)
	platformOrg := id.AddOrg("platform")
	projectID := id.AddProject(platformOrg, "gibson")
	tenantOrg := id.AddOrg("tenant-1")
	addRole(t, e, projectID, "owner", "Owner")
	grantProject(t, e, projectID, tenantOrg, []string{"owner"})

	var noFilterResp struct {
		ProjectGrants []map[string]any `json:"projectGrants"`
	}
	status := post(t, e, "/zitadel.project.v2.ProjectService/ListProjectGrants", map[string]any{}, &noFilterResp)
	if status != http.StatusOK || len(noFilterResp.ProjectGrants) != 1 {
		t.Fatalf("no-filter ListProjectGrants status=%d grants=%v", status, noFilterResp.ProjectGrants)
	}

	var projFilterResp struct {
		ProjectGrants []map[string]any `json:"projectGrants"`
	}
	status = post(t, e, "/zitadel.project.v2.ProjectService/ListProjectGrants", map[string]any{
		"filters": []any{map[string]any{"inProjectIdsFilter": map[string]any{"ids": []string{projectID}}}},
	}, &projFilterResp)
	if status != http.StatusOK || len(projFilterResp.ProjectGrants) != 1 {
		t.Fatalf("project-filter ListProjectGrants status=%d grants=%v", status, projFilterResp.ProjectGrants)
	}
}

// TestIdentity_Grants_FiltersByOrg covers the "grant belongs to a different
// org" skip branch in Identity.Grants.
func TestIdentity_Grants_FiltersByOrg(t *testing.T) {
	id, e := newFake(t)
	platformOrg := id.AddOrg("platform")
	projectID := id.AddProject(platformOrg, "gibson")
	tenantOrg := id.AddOrg("tenant-1")
	otherOrg := id.AddOrg("tenant-2")
	addRole(t, e, projectID, "owner", "Owner")
	grantProject(t, e, projectID, tenantOrg, []string{"owner"})
	grantProject(t, e, projectID, otherOrg, []string{"owner"})
	u1 := id.AddUser(tenantOrg, "a@example.com")
	u2 := id.AddUser(otherOrg, "b@example.com")

	post(t, e, "/zitadel.authorization.v2.AuthorizationService/CreateAuthorization", map[string]any{
		"userId": u1, "projectId": projectID, "organizationId": tenantOrg, "roleKeys": []string{"owner"},
	}, nil)
	post(t, e, "/zitadel.authorization.v2.AuthorizationService/CreateAuthorization", map[string]any{
		"userId": u2, "projectId": projectID, "organizationId": otherOrg, "roleKeys": []string{"owner"},
	}, nil)

	got := id.Grants(tenantOrg)
	if len(got) != 1 || got[0].UserID != u1 {
		t.Fatalf("Grants(tenantOrg) = %+v, want only u1's grant", got)
	}
}
