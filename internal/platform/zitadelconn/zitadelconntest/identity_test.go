// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadelconntest_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn"
	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn/zitadelconntest"
)

// post sends a Connect-style unary JSON request to path and decodes the
// response into out. It returns the HTTP status.
func post(t *testing.T, e zitadelconn.Endpoint, path string, body, out any) int {
	t.Helper()
	return postWithOrg(t, e, path, "", body, out)
}

// postWithOrg is post, and also sets x-zitadel-orgid, as the v1 Management
// AddOrgMember call requires.
func postWithOrg(t *testing.T, e zitadelconn.Endpoint, path, orgID string, body, out any) int {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, e.URL(path), bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if orgID != "" {
		req.Header.Set("x-zitadel-orgid", orgID)
	}
	hc := &http.Client{Timeout: 5 * time.Second, Transport: e.Transport(nil)}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func newFake(t *testing.T) (*zitadelconntest.Identity, zitadelconn.Endpoint) {
	t.Helper()
	id := zitadelconntest.NewIdentity()
	srv := zitadelconntest.New(t, "", id.Handler())
	return id, srv.Endpoint(t)
}

// --- the two acceptance rejections (section 11 item 4) --------------------

func TestIdentity_AddOrgMemberRefusesAGibsonRole(t *testing.T) {
	id, e := newFake(t)
	orgID := id.AddOrg("tenant-1")
	userID := id.AddUser(orgID, "owner@example.com")

	var errBody map[string]any
	status := postWithOrg(t, e, "/management/v1/orgs/me/members", orgID, map[string]any{
		"userId": userID, "roles": []string{"gibson.owner"},
	}, &errBody)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if msg, _ := errBody["message"].(string); !strings.Contains(msg, "Errors.Org.MemberInvalid") {
		t.Errorf("message = %v, want Errors.Org.MemberInvalid", errBody["message"])
	}
}

func TestIdentity_AddOrgMemberAcceptsAnOrgRole(t *testing.T) {
	id, e := newFake(t)
	orgID := id.AddOrg("tenant-1")
	userID := id.AddUser(orgID, "owner@example.com")

	status := postWithOrg(t, e, "/management/v1/orgs/me/members", orgID, map[string]any{
		"userId": userID, "roles": []string{"ORG_OWNER"},
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	members := id.OrgMembers()
	if len(members) != 1 || members[0].UserID != userID {
		t.Errorf("OrgMembers = %+v", members)
	}
}

func TestIdentity_CreateAuthorizationRefusesAnUnknownRole(t *testing.T) {
	id, e := newFake(t)
	platformOrg := id.AddOrg("platform")
	tenantOrg := id.AddOrg("tenant-1")
	projectID := id.AddProject(platformOrg, "gibson")
	userID := id.AddUser(tenantOrg, "owner@example.com")
	addRole(t, e, projectID, "owner", "Owner")
	grantProject(t, e, projectID, tenantOrg, []string{"owner"})

	var errBody map[string]any
	status := post(t, e, "/zitadel.authorization.v2.AuthorizationService/CreateAuthorization", map[string]any{
		"userId": userID, "projectId": projectID, "organizationId": tenantOrg,
		"roleKeys": []string{"superuser"},
	}, &errBody)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if msg, _ := errBody["message"].(string); !strings.Contains(msg, "Errors.Project.Role.NotFound") {
		t.Errorf("message = %v, want Errors.Project.Role.NotFound", errBody["message"])
	}
}

func TestIdentity_CreateAuthorizationRefusesAnOrgWithNoProjectGrant(t *testing.T) {
	id, e := newFake(t)
	platformOrg := id.AddOrg("platform")
	tenantOrg := id.AddOrg("tenant-1")
	projectID := id.AddProject(platformOrg, "gibson")
	userID := id.AddUser(tenantOrg, "owner@example.com")
	addRole(t, e, projectID, "owner", "Owner")
	// No CreateProjectGrant call: tenantOrg has no grant.

	var errBody map[string]any
	status := post(t, e, "/zitadel.authorization.v2.AuthorizationService/CreateAuthorization", map[string]any{
		"userId": userID, "projectId": projectID, "organizationId": tenantOrg,
		"roleKeys": []string{"owner"},
	}, &errBody)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if msg, _ := errBody["message"].(string); !strings.Contains(msg, "Errors.Project.Grant.NotFound") {
		t.Errorf("message = %v, want Errors.Project.Grant.NotFound", errBody["message"])
	}
}

// --- broader wire coverage, exercised again by tenantrole in a later PR ---

func addRole(t *testing.T, e zitadelconn.Endpoint, projectID, key, name string) {
	t.Helper()
	status := post(t, e, "/zitadel.project.v2.ProjectService/AddProjectRole", map[string]any{
		"projectId": projectID, "roleKey": key, "displayName": name,
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("AddProjectRole(%s) status = %d", key, status)
	}
}

func grantProject(t *testing.T, e zitadelconn.Endpoint, projectID, orgID string, keys []string) {
	t.Helper()
	status := post(t, e, "/zitadel.project.v2.ProjectService/CreateProjectGrant", map[string]any{
		"projectId": projectID, "grantedOrganizationId": orgID, "roleKeys": keys,
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("CreateProjectGrant status = %d", status)
	}
}

func TestIdentity_ProjectRolesRoundTripAndCascadeOnRemove(t *testing.T) {
	id, e := newFake(t)
	platformOrg := id.AddOrg("platform")
	projectID := id.AddProject(platformOrg, "gibson")
	tenantOrg := id.AddOrg("tenant-1")
	userID := id.AddUser(tenantOrg, "owner@example.com")

	for _, r := range []struct{ key, name string }{
		{"owner", "Owner"}, {"admin", "Admin"}, {"editor", "Editor"}, {"viewer", "Viewer"},
	} {
		addRole(t, e, projectID, r.key, r.name)
	}
	// Duplicate role key is already_exists.
	if status := post(t, e, "/zitadel.project.v2.ProjectService/AddProjectRole", map[string]any{
		"projectId": projectID, "roleKey": "owner", "displayName": "Owner",
	}, nil); status != http.StatusConflict {
		t.Errorf("duplicate AddProjectRole status = %d, want 409", status)
	}

	var listed struct {
		ProjectRoles []struct {
			Key string `json:"key"`
		} `json:"projectRoles"`
	}
	if status := post(t, e, "/zitadel.project.v2.ProjectService/ListProjectRoles", map[string]any{"projectId": projectID}, &listed); status != http.StatusOK {
		t.Fatalf("ListProjectRoles status = %d", status)
	}
	if len(listed.ProjectRoles) != 4 {
		t.Fatalf("roles = %v, want 4", listed.ProjectRoles)
	}

	grantProject(t, e, projectID, tenantOrg, []string{"owner", "admin", "editor", "viewer"})

	var grantID string
	if status := post(t, e, "/zitadel.authorization.v2.AuthorizationService/CreateAuthorization", map[string]any{
		"userId": userID, "projectId": projectID, "organizationId": tenantOrg, "roleKeys": []string{"owner"},
	}, &struct {
		ID *string `json:"id"`
	}{&grantID}); status != http.StatusOK {
		t.Fatalf("CreateAuthorization status = %d", status)
	}
	if grantID == "" {
		t.Fatal("CreateAuthorization returned no id")
	}
	if got := id.Grants(tenantOrg); len(got) != 1 || got[0].RoleKeys[0] != "owner" {
		t.Fatalf("Grants = %+v", got)
	}

	// RemoveProjectRole cascades into the project grant and the user grant.
	if status := post(t, e, "/zitadel.project.v2.ProjectService/RemoveProjectRole", map[string]any{
		"projectId": projectID, "roleKey": "owner",
	}, nil); status != http.StatusOK {
		t.Fatalf("RemoveProjectRole status = %d", status)
	}
	if got := id.Grants(tenantOrg); len(got) != 1 || len(got[0].RoleKeys) != 0 {
		t.Fatalf("Grants after cascade = %+v, want the owner key gone", got)
	}
}

func TestIdentity_UpdateAndDeleteAuthorization(t *testing.T) {
	id, e := newFake(t)
	platformOrg := id.AddOrg("platform")
	projectID := id.AddProject(platformOrg, "gibson")
	tenantOrg := id.AddOrg("tenant-1")
	userID := id.AddUser(tenantOrg, "member@example.com")
	addRole(t, e, projectID, "owner", "Owner")
	addRole(t, e, projectID, "admin", "Admin")
	grantProject(t, e, projectID, tenantOrg, []string{"owner", "admin"})

	var grantID string
	post(t, e, "/zitadel.authorization.v2.AuthorizationService/CreateAuthorization", map[string]any{
		"userId": userID, "projectId": projectID, "organizationId": tenantOrg, "roleKeys": []string{"admin"},
	}, &struct {
		ID *string `json:"id"`
	}{&grantID})

	if status := post(t, e, "/zitadel.authorization.v2.AuthorizationService/UpdateAuthorization", map[string]any{
		"id": grantID, "roleKeys": []string{"owner"},
	}, nil); status != http.StatusOK {
		t.Fatalf("UpdateAuthorization status = %d", status)
	}
	if got := id.Grants(tenantOrg); len(got) != 1 || got[0].RoleKeys[0] != "owner" {
		t.Fatalf("Grants after update = %+v", got)
	}

	if status := post(t, e, "/zitadel.authorization.v2.AuthorizationService/DeleteAuthorization", map[string]any{
		"id": grantID,
	}, nil); status != http.StatusOK {
		t.Fatalf("DeleteAuthorization status = %d", status)
	}
	// Absent id is still success.
	if status := post(t, e, "/zitadel.authorization.v2.AuthorizationService/DeleteAuthorization", map[string]any{
		"id": grantID,
	}, nil); status != http.StatusOK {
		t.Fatalf("DeleteAuthorization (already gone) status = %d, want 200", status)
	}
	if got := id.Grants(tenantOrg); len(got) != 0 {
		t.Fatalf("Grants after delete = %+v, want none", got)
	}
}

func TestIdentity_ListAuthorizationsFiltersAndPaginates(t *testing.T) {
	id, e := newFake(t)
	platformOrg := id.AddOrg("platform")
	projectID := id.AddProject(platformOrg, "gibson")
	tenantOrg := id.AddOrg("tenant-1")
	addRole(t, e, projectID, "viewer", "Viewer")
	grantProject(t, e, projectID, tenantOrg, []string{"viewer"})

	for range 3 {
		u := id.AddUser(tenantOrg, "u@example.com")
		post(t, e, "/zitadel.authorization.v2.AuthorizationService/CreateAuthorization", map[string]any{
			"userId": u, "projectId": projectID, "organizationId": tenantOrg, "roleKeys": []string{"viewer"},
		}, nil)
	}

	var page struct {
		Authorizations []struct {
			ID    string `json:"id"`
			State string `json:"state"`
			User  struct {
				ID             string `json:"id"`
				OrganizationID string `json:"organizationId"`
			} `json:"user"`
			Roles []struct {
				Key string `json:"key"`
			} `json:"roles"`
		} `json:"authorizations"`
		Pagination struct {
			TotalResult int `json:"totalResult"`
		} `json:"pagination"`
	}
	status := post(t, e, "/zitadel.authorization.v2.AuthorizationService/ListAuthorizations", map[string]any{
		"pagination": map[string]any{"offset": 1, "limit": 1},
		"filters":    []any{map[string]any{"organizationId": map[string]any{"id": tenantOrg}}},
	}, &page)
	if status != http.StatusOK {
		t.Fatalf("ListAuthorizations status = %d", status)
	}
	if page.Pagination.TotalResult != 3 {
		t.Fatalf("totalResult = %d, want 3 (page is smaller, total is not)", page.Pagination.TotalResult)
	}
	if len(page.Authorizations) != 1 {
		t.Fatalf("page = %v, want exactly one row", page.Authorizations)
	}
	got := page.Authorizations[0]
	if got.State != "STATE_ACTIVE" || got.User.OrganizationID != tenantOrg || len(got.Roles) != 1 || got.Roles[0].Key != "viewer" {
		t.Errorf("row = %+v", got)
	}
}

func TestIdentity_CreateProjectGrantRefusesTheOwningOrgAndADuplicate(t *testing.T) {
	id, e := newFake(t)
	platformOrg := id.AddOrg("platform")
	projectID := id.AddProject(platformOrg, "gibson")
	tenantOrg := id.AddOrg("tenant-1")
	addRole(t, e, projectID, "owner", "Owner")

	if status := post(t, e, "/zitadel.project.v2.ProjectService/CreateProjectGrant", map[string]any{
		"projectId": projectID, "grantedOrganizationId": platformOrg, "roleKeys": []string{"owner"},
	}, nil); status != http.StatusBadRequest {
		t.Errorf("grant to owning org status = %d, want 400", status)
	}

	grantProject(t, e, projectID, tenantOrg, []string{"owner"})
	if status := post(t, e, "/zitadel.project.v2.ProjectService/CreateProjectGrant", map[string]any{
		"projectId": projectID, "grantedOrganizationId": tenantOrg, "roleKeys": []string{"owner"},
	}, nil); status != http.StatusConflict {
		t.Errorf("duplicate grant status = %d, want 409", status)
	}
}
