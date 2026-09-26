// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadelconntest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

// Identity is a stateful fake of the parts of Zitadel v4.18.0 that hold
// users, orgs, project roles, project grants, user grants and org members
// (ADR-0093). It rejects what the real one rejects, so a client proven
// against it survives contact with staging.
//
// Pass Handler() to New to serve it behind the instance-header check.
// IDs are 18-digit decimal strings, as Zitadel issues them.
type Identity struct {
	mu sync.Mutex

	counter int64

	orgs     map[string]*fakeOrg
	users    map[string]*fakeUser
	projects map[string]*fakeProject

	// projectGrants is keyed by projectID+"/"+orgID.
	projectGrants map[string]*fakeProjectGrant
	userGrants    map[string]*fakeUserGrant
	orgMembers    []OrgMember

	// grantedPermissions restricts every request this Identity serves to
	// exactly this set (see GrantRoles in permission.go). nil (the zero
	// value) means unrestricted — every gated call succeeds — so an
	// Identity that never calls GrantRoles behaves exactly as before this
	// field existed.
	grantedPermissions map[Permission]bool
}

type fakeOrg struct {
	ID   string
	Name string
}

type fakeUser struct {
	ID    string
	OrgID string
	Email string
}

// ProjectRole is one role key declared on a project.
type ProjectRole struct {
	Key         string
	DisplayName string
}

type fakeProject struct {
	ID         string
	OwnerOrgID string
	Name       string
	roles      []ProjectRole // order preserved, matches ListProjectRoles
}

type fakeProjectGrant struct {
	ProjectID string
	OrgID     string
	RoleKeys  []string
}

type fakeUserGrant struct {
	ID        string
	UserID    string
	UserOrgID string
	ProjectID string
	OrgID     string
	RoleKeys  []string
	Active    bool
}

// Grant is one Zitadel authorization on a project, returned by Grants for
// test assertions. Its shape mirrors what a real client reads back from
// ListAuthorizations.
type Grant struct {
	ID        string
	UserID    string
	UserOrgID string
	ProjectID string
	OrgID     string
	RoleKeys  []string
	Active    bool
}

// NewIdentity returns an empty fake: no orgs, users, projects or grants.
func NewIdentity() *Identity {
	return &Identity{
		orgs:          make(map[string]*fakeOrg),
		users:         make(map[string]*fakeUser),
		projects:      make(map[string]*fakeProject),
		projectGrants: make(map[string]*fakeProjectGrant),
		userGrants:    make(map[string]*fakeUserGrant),
	}
}

// AddOrg creates an org and returns its id.
func (f *Identity) AddOrg(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := f.nextIDLocked()
	f.orgs[id] = &fakeOrg{ID: id, Name: name}
	return id
}

// AddProject creates a project owned by ownerOrgID and returns its id. It
// starts with no roles; ensure them with a call through EnsureProjectRoles
// (production code) or AddProjectRole (the wire path) in a test.
func (f *Identity) AddProject(ownerOrgID, name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := f.nextIDLocked()
	f.projects[id] = &fakeProject{ID: id, OwnerOrgID: ownerOrgID, Name: name}
	return id
}

// AddUser creates a human user in orgID and returns its id. A user belongs
// to exactly one org, as ADR-0093 decision 1 requires of a real tenant user.
func (f *Identity) AddUser(orgID, email string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := f.nextIDLocked()
	f.users[id] = &fakeUser{ID: id, OrgID: orgID, Email: email}
	return id
}

// Grants returns every user grant belonging to orgID, for test assertions.
func (f *Identity) Grants(orgID string) []Grant {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Grant, 0, len(f.userGrants))
	for _, g := range f.userGrants {
		if g.OrgID != orgID {
			continue
		}
		out = append(out, Grant{
			ID: g.ID, UserID: g.UserID, UserOrgID: g.UserOrgID,
			ProjectID: g.ProjectID, OrgID: g.OrgID,
			RoleKeys: append([]string(nil), g.RoleKeys...), Active: g.Active,
		})
	}
	return out
}

// OrgMembers returns every accepted AddOrgMember call, for test assertions.
func (f *Identity) OrgMembers() []OrgMember {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]OrgMember(nil), f.orgMembers...)
}

// OrgMember is one accepted AddOrgMember call, returned by OrgMembers.
type OrgMember struct {
	OrgID  string
	UserID string
	Roles  []string
}

func (f *Identity) nextIDLocked() string {
	f.counter++
	return fmt.Sprintf("%018d", 100000000000000000+f.counter)
}

// Handler returns the http.Handler that serves this fake's routes. Pass it
// to zitadelconntest.New; the instance-header check happens there, so this
// handler assumes it already passed.
func (f *Identity) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/management/v1/orgs/me/members", f.handleAddOrgMember)
	mux.HandleFunc("/zitadel.project.v2.ProjectService/ListProjectRoles", f.handleListProjectRoles)
	mux.HandleFunc("/zitadel.project.v2.ProjectService/AddProjectRole", f.handleAddProjectRole)
	mux.HandleFunc("/zitadel.project.v2.ProjectService/UpdateProjectRole", f.handleUpdateProjectRole)
	mux.HandleFunc("/zitadel.project.v2.ProjectService/RemoveProjectRole", f.handleRemoveProjectRole)
	mux.HandleFunc("/zitadel.project.v2.ProjectService/ListProjectGrants", f.handleListProjectGrants)
	mux.HandleFunc("/zitadel.project.v2.ProjectService/CreateProjectGrant", f.handleCreateProjectGrant)
	mux.HandleFunc("/zitadel.project.v2.ProjectService/UpdateProjectGrant", f.handleUpdateProjectGrant)
	mux.HandleFunc("/zitadel.authorization.v2.AuthorizationService/CreateAuthorization", f.handleCreateAuthorization)
	mux.HandleFunc("/zitadel.authorization.v2.AuthorizationService/UpdateAuthorization", f.handleUpdateAuthorization)
	mux.HandleFunc("/zitadel.authorization.v2.AuthorizationService/DeleteAuthorization", f.handleDeleteAuthorization)
	mux.HandleFunc("/zitadel.authorization.v2.AuthorizationService/ListAuthorizations", f.handleListAuthorizations)
	return mux
}

// --- wire helpers -----------------------------------------------------

// connectStatus maps a Connect error code to its HTTP status, per the
// Connect protocol's unary-over-HTTP mapping used by Zitadel v2 services.
var connectStatus = map[string]int{
	"invalid_argument":    http.StatusBadRequest,
	"failed_precondition": http.StatusBadRequest,
	"already_exists":      http.StatusConflict,
	"not_found":           http.StatusNotFound,
	"unauthenticated":     http.StatusUnauthorized,
	"permission_denied":   http.StatusForbidden,
	"unavailable":         http.StatusServiceUnavailable,
	"deadline_exceeded":   http.StatusGatewayTimeout,
}

// writeConnectError writes a Connect JSON error body: {"code","message"}.
// key and id compose the message as "<key> (<id>)", matching Zitadel's own
// "Errors.X.Y (COMMAND-abcd1)" convention, so a client that maps by
// substring in a test can still assert on it.
func writeConnectError(w http.ResponseWriter, code, key, id string) {
	status, ok := connectStatus[code]
	if !ok {
		status = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"code":    code,
		"message": fmt.Sprintf("%s (%s)", key, id),
	})
}

// writeManagementError writes a v1 Management API error body:
// {"code":<int>,"message":"<key> (<id>)"}, gRPC-code numbered (3 =
// InvalidArgument), matching what AddOrgMember answers on staging.
func writeManagementError(w http.ResponseWriter, status, grpcCode int, key, id string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"code":    grpcCode,
		"message": fmt.Sprintf("%s (%s)", key, id),
	})
}

func writeOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if v == nil {
		v = map[string]any{}
	}
	_ = json.NewEncoder(w).Encode(v)
}

func decode(r *http.Request, v any) error {
	defer func() { _ = r.Body.Close() }()
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return fmt.Errorf("zitadelconntest: decode request body: %w", err)
	}
	return nil
}

// --- v1 Management: org members ---------------------------------------

// validOrgRoles is the v4.18.0 default org role mapping (cmd/defaults.yaml).
// AddOrgMember refuses any role outside it.
var validOrgRoles = map[string]bool{
	"ORG_OWNER":                     true,
	"ORG_OWNER_VIEWER":              true,
	"ORG_USER_MANAGER":              true,
	"ORG_USER_PERMISSION_EDITOR":    true,
	"ORG_PROJECT_PERMISSION_EDITOR": true,
	"ORG_PROJECT_CREATOR":           true,
	"ORG_ADMIN_IMPERSONATOR":        true,
	"ORG_END_USER_IMPERSONATOR":     true,
	"ORG_SETTINGS_MANAGER":          true,
}

func (f *Identity) handleAddOrgMember(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !f.requirePermission(w, PermOrgMemberWrite, false) {
		return
	}
	orgID := r.Header.Get("x-zitadel-orgid")
	var req struct {
		UserID string   `json:"userId"`
		Roles  []string `json:"roles"`
	}
	if err := decode(r, &req); err != nil {
		writeManagementError(w, http.StatusBadRequest, 3, "Errors.Org.MemberInvalid", "Org-decode")
		return
	}
	f.mu.Lock()
	_, orgKnown := f.orgs[orgID]
	f.mu.Unlock()
	if !orgKnown {
		writeManagementError(w, http.StatusNotFound, 5, "Errors.Org.NotFound", "Org-nf001")
		return
	}
	for _, role := range req.Roles {
		if !validOrgRoles[role] {
			writeManagementError(w, http.StatusBadRequest, 3, "Errors.Org.MemberInvalid", "Org-4N8es")
			return
		}
	}
	f.mu.Lock()
	f.orgMembers = append(f.orgMembers, OrgMember{OrgID: orgID, UserID: req.UserID, Roles: req.Roles})
	f.mu.Unlock()
	writeOK(w, nil)
}

// --- v2 ProjectService: roles -------------------------------------------

func (f *Identity) handleListProjectRoles(w http.ResponseWriter, r *http.Request) {
	if !f.requirePermission(w, PermProjectRoleRead, true) {
		return
	}
	var req struct {
		ProjectID string `json:"projectId"`
	}
	_ = decode(r, &req)
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.projects[req.ProjectID]
	if p == nil {
		writeConnectError(w, "not_found", "Errors.Project.NotFound", "PROJ-nf001")
		return
	}
	// The real ListProjectRolesResponse: {pagination, projectRoles[]}, each
	// with "key", not the request-side "roleKey".
	type roleOut struct {
		ProjectID   string `json:"projectId"`
		Key         string `json:"key"`
		DisplayName string `json:"displayName"`
	}
	roles := make([]roleOut, 0, len(p.roles))
	for _, rr := range p.roles {
		roles = append(roles, roleOut{ProjectID: req.ProjectID, Key: rr.Key, DisplayName: rr.DisplayName})
	}
	writeOK(w, map[string]any{
		"projectRoles": roles,
		"pagination":   map[string]any{"totalResult": len(roles)},
	})
}

type projectRoleReq struct {
	ProjectID   string `json:"projectId"`
	RoleKey     string `json:"roleKey"`
	DisplayName string `json:"displayName"`
}

func (f *Identity) handleAddProjectRole(w http.ResponseWriter, r *http.Request) {
	if !f.requirePermission(w, PermProjectRoleWrite, true) {
		return
	}
	var req projectRoleReq
	_ = decode(r, &req)
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.projects[req.ProjectID]
	if p == nil {
		writeConnectError(w, "not_found", "Errors.Project.NotFound", "PROJ-nf002")
		return
	}
	for _, rr := range p.roles {
		if rr.Key == req.RoleKey {
			writeConnectError(w, "already_exists", "Errors.Project.Role.AlreadyExists", "COMMAND-r0le1")
			return
		}
	}
	p.roles = append(p.roles, ProjectRole{Key: req.RoleKey, DisplayName: req.DisplayName})
	writeOK(w, nil)
}

func (f *Identity) handleUpdateProjectRole(w http.ResponseWriter, r *http.Request) {
	if !f.requirePermission(w, PermProjectRoleWrite, true) {
		return
	}
	var req projectRoleReq
	_ = decode(r, &req)
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.projects[req.ProjectID]
	if p == nil {
		writeConnectError(w, "not_found", "Errors.Project.NotFound", "PROJ-nf003")
		return
	}
	for i, rr := range p.roles {
		if rr.Key == req.RoleKey {
			p.roles[i].DisplayName = req.DisplayName
			writeOK(w, nil)
			return
		}
	}
	writeConnectError(w, "not_found", "Errors.Project.Role.NotFound", "COMMAND-mm9F4")
}

func (f *Identity) handleRemoveProjectRole(w http.ResponseWriter, r *http.Request) {
	if !f.requirePermission(w, PermProjectRoleWrite, true) {
		return
	}
	var req projectRoleReq
	_ = decode(r, &req)
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.projects[req.ProjectID]
	if p == nil {
		writeConnectError(w, "not_found", "Errors.Project.NotFound", "PROJ-nf004")
		return
	}
	found := false
	kept := p.roles[:0]
	for _, rr := range p.roles {
		if rr.Key == req.RoleKey {
			found = true
			continue
		}
		kept = append(kept, rr)
	}
	if !found {
		writeConnectError(w, "not_found", "Errors.Project.Role.NotFound", "COMMAND-mm9F4")
		return
	}
	p.roles = kept
	// Cascade: the role disappears from every grant that named it.
	for _, pg := range f.projectGrants {
		if pg.ProjectID == req.ProjectID {
			pg.RoleKeys = removeString(pg.RoleKeys, req.RoleKey)
		}
	}
	for _, ug := range f.userGrants {
		if ug.ProjectID == req.ProjectID {
			ug.RoleKeys = removeString(ug.RoleKeys, req.RoleKey)
		}
	}
	writeOK(w, nil)
}

func removeString(in []string, s string) []string {
	out := in[:0]
	for _, v := range in {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}

// --- v2 ProjectService: grants -------------------------------------------

type grantFilter struct {
	InProjectIDsFilter *struct {
		IDs []string `json:"ids"`
	} `json:"inProjectIdsFilter,omitempty"`
	GrantedOrganizationIDFilter *struct {
		ID string `json:"id"`
	} `json:"grantedOrganizationIdFilter,omitempty"`
}

func (f *Identity) handleListProjectGrants(w http.ResponseWriter, r *http.Request) {
	if !f.requirePermission(w, PermProjectGrantRead, true) {
		return
	}
	var req struct {
		Filters []grantFilter `json:"filters"`
	}
	_ = decode(r, &req)
	var projectIDs map[string]bool
	var orgID string
	for _, flt := range req.Filters {
		if flt.InProjectIDsFilter != nil {
			projectIDs = map[string]bool{}
			for _, id := range flt.InProjectIDsFilter.IDs {
				projectIDs[id] = true
			}
		}
		if flt.GrantedOrganizationIDFilter != nil {
			orgID = flt.GrantedOrganizationIDFilter.ID
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	// The real ProjectGrant (zitadel.project.v2) names its keys
	// "grantedRoleKeys"; the Create/Update requests say "roleKeys".
	type grantOut struct {
		ProjectID             string   `json:"projectId"`
		GrantedOrganizationID string   `json:"grantedOrganizationId"`
		GrantedRoleKeys       []string `json:"grantedRoleKeys"`
	}
	out := make([]grantOut, 0)
	for _, pg := range f.projectGrants {
		if projectIDs != nil && !projectIDs[pg.ProjectID] {
			continue
		}
		if orgID != "" && pg.OrgID != orgID {
			continue
		}
		out = append(out, grantOut{ProjectID: pg.ProjectID, GrantedOrganizationID: pg.OrgID, GrantedRoleKeys: append([]string(nil), pg.RoleKeys...)})
	}
	writeOK(w, map[string]any{
		"projectGrants": out,
		"pagination":    map[string]any{"totalResult": len(out)},
	})
}

type projectGrantReq struct {
	ProjectID             string   `json:"projectId"`
	GrantedOrganizationID string   `json:"grantedOrganizationId"`
	RoleKeys              []string `json:"roleKeys"`
}

func (f *Identity) validRoleKeysLocked(p *fakeProject, keys []string) bool {
	allowed := map[string]bool{}
	for _, rr := range p.roles {
		allowed[rr.Key] = true
	}
	for _, k := range keys {
		if !allowed[k] {
			return false
		}
	}
	return true
}

func (f *Identity) handleCreateProjectGrant(w http.ResponseWriter, r *http.Request) {
	if !f.requirePermission(w, PermProjectGrantWrite, true) {
		return
	}
	var req projectGrantReq
	_ = decode(r, &req)
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.projects[req.ProjectID]
	if p == nil {
		writeConnectError(w, "not_found", "Errors.Project.NotFound", "PROJ-nf005")
		return
	}
	if req.GrantedOrganizationID == p.OwnerOrgID {
		writeConnectError(w, "failed_precondition", "Errors.Project.Grant.AlreadyOwned", "COMMAND-own001")
		return
	}
	if !f.validRoleKeysLocked(p, req.RoleKeys) {
		writeConnectError(w, "failed_precondition", "Errors.Project.Role.NotFound", "COMMAND-mm9F4")
		return
	}
	key := req.ProjectID + "/" + req.GrantedOrganizationID
	if _, exists := f.projectGrants[key]; exists {
		writeConnectError(w, "already_exists", "Errors.Project.Grant.AlreadyExists", "COMMAND-pg0001")
		return
	}
	f.projectGrants[key] = &fakeProjectGrant{ProjectID: req.ProjectID, OrgID: req.GrantedOrganizationID, RoleKeys: append([]string(nil), req.RoleKeys...)}
	writeOK(w, nil)
}

func (f *Identity) handleUpdateProjectGrant(w http.ResponseWriter, r *http.Request) {
	if !f.requirePermission(w, PermProjectGrantWrite, true) {
		return
	}
	var req projectGrantReq
	_ = decode(r, &req)
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.projects[req.ProjectID]
	if p == nil {
		writeConnectError(w, "not_found", "Errors.Project.NotFound", "PROJ-nf006")
		return
	}
	if !f.validRoleKeysLocked(p, req.RoleKeys) {
		writeConnectError(w, "failed_precondition", "Errors.Project.Role.NotFound", "COMMAND-mm9F4")
		return
	}
	key := req.ProjectID + "/" + req.GrantedOrganizationID
	pg, ok := f.projectGrants[key]
	if !ok {
		writeConnectError(w, "not_found", "Errors.Project.Grant.NotFound", "COMMAND-4m9ff")
		return
	}
	pg.RoleKeys = append([]string(nil), req.RoleKeys...)
	writeOK(w, nil)
}

// --- v2 AuthorizationService: user grants --------------------------------

type authorizationReq struct {
	ID             string   `json:"id"`
	UserID         string   `json:"userId"`
	ProjectID      string   `json:"projectId"`
	OrganizationID string   `json:"organizationId"`
	RoleKeys       []string `json:"roleKeys"`
}

// allowedKeysLocked returns the role keys a grant in orgID for projectID may
// use: the project's own roles when orgID owns the project, or the project
// grant's keys otherwise. ok is false when orgID has no project grant and
// does not own the project.
func (f *Identity) allowedKeysLocked(p *fakeProject, orgID string) (keys map[string]bool, ok bool) {
	if orgID == p.OwnerOrgID {
		keys = map[string]bool{}
		for _, rr := range p.roles {
			keys[rr.Key] = true
		}
		return keys, true
	}
	pg, exists := f.projectGrants[p.ID+"/"+orgID]
	if !exists {
		return nil, false
	}
	keys = map[string]bool{}
	for _, k := range pg.RoleKeys {
		keys[k] = true
	}
	return keys, true
}

func (f *Identity) handleCreateAuthorization(w http.ResponseWriter, r *http.Request) {
	if !f.requirePermission(w, PermUserGrantWrite, true) {
		return
	}
	var req authorizationReq
	_ = decode(r, &req)
	f.mu.Lock()
	defer f.mu.Unlock()

	user, ok := f.users[req.UserID]
	if !ok {
		writeConnectError(w, "failed_precondition", "Errors.User.NotFound", "COMMAND-usr404")
		return
	}
	p := f.projects[req.ProjectID]
	if p == nil {
		writeConnectError(w, "not_found", "Errors.Project.NotFound", "PROJ-nf007")
		return
	}
	allowed, ok := f.allowedKeysLocked(p, req.OrganizationID)
	if !ok {
		writeConnectError(w, "failed_precondition", "Errors.Project.Grant.NotFound", "COMMAND-4m9ff")
		return
	}
	for _, k := range req.RoleKeys {
		if !allowed[k] {
			writeConnectError(w, "failed_precondition", "Errors.Project.Role.NotFound", "COMMAND-mm9F4")
			return
		}
	}
	for _, ug := range f.userGrants {
		if ug.UserID == req.UserID && ug.ProjectID == req.ProjectID && ug.OrgID == req.OrganizationID && ug.Active {
			writeConnectError(w, "already_exists", "Errors.UserGrant.AlreadyExists", "COMMAND-ug0001")
			return
		}
	}
	id := f.nextIDLocked()
	f.userGrants[id] = &fakeUserGrant{
		ID: id, UserID: req.UserID, UserOrgID: user.OrgID,
		ProjectID: req.ProjectID, OrgID: req.OrganizationID,
		RoleKeys: append([]string(nil), req.RoleKeys...), Active: true,
	}
	writeOK(w, map[string]string{"id": id})
}

func (f *Identity) handleUpdateAuthorization(w http.ResponseWriter, r *http.Request) {
	if !f.requirePermission(w, PermUserGrantWrite, true) {
		return
	}
	var req authorizationReq
	_ = decode(r, &req)
	f.mu.Lock()
	defer f.mu.Unlock()

	ug, ok := f.userGrants[req.ID]
	if !ok || !ug.Active {
		writeConnectError(w, "not_found", "Errors.UserGrant.NotFound", "COMMAND-ug0002")
		return
	}
	p := f.projects[ug.ProjectID]
	if p == nil {
		writeConnectError(w, "not_found", "Errors.Project.NotFound", "PROJ-nf008")
		return
	}
	allowed, ok := f.allowedKeysLocked(p, ug.OrgID)
	if !ok {
		writeConnectError(w, "failed_precondition", "Errors.Project.Grant.NotFound", "COMMAND-4m9ff")
		return
	}
	for _, k := range req.RoleKeys {
		if !allowed[k] {
			writeConnectError(w, "failed_precondition", "Errors.Project.Role.NotFound", "COMMAND-mm9F4")
			return
		}
	}
	ug.RoleKeys = append([]string(nil), req.RoleKeys...)
	writeOK(w, nil)
}

func (f *Identity) handleDeleteAuthorization(w http.ResponseWriter, r *http.Request) {
	if !f.requirePermission(w, PermUserGrantDelete, true) {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	_ = decode(r, &req)
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.userGrants, req.ID) // an absent id is success, like the real one
	writeOK(w, nil)
}

type authListFilter struct {
	OrganizationID *struct {
		ID string `json:"id"`
	} `json:"organizationId,omitempty"`
	ProjectID *struct {
		ID string `json:"id"`
	} `json:"projectId,omitempty"`
	InUserIDs *struct {
		IDs []string `json:"ids"`
	} `json:"inUserIds,omitempty"`
}

func (f *Identity) handleListAuthorizations(w http.ResponseWriter, r *http.Request) {
	if !f.requirePermission(w, PermUserGrantRead, true) {
		return
	}
	var req struct {
		Pagination struct {
			Offset int `json:"offset"`
			Limit  int `json:"limit"`
		} `json:"pagination"`
		Filters []authListFilter `json:"filters"`
	}
	_ = decode(r, &req)

	var orgID, projectID string
	var userIDs map[string]bool
	for _, flt := range req.Filters {
		if flt.OrganizationID != nil {
			orgID = flt.OrganizationID.ID
		}
		if flt.ProjectID != nil {
			projectID = flt.ProjectID.ID
		}
		if flt.InUserIDs != nil {
			userIDs = map[string]bool{}
			for _, id := range flt.InUserIDs.IDs {
				userIDs[id] = true
			}
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	type idOut struct {
		ID string `json:"id"`
	}
	type roleOut struct {
		Key string `json:"key"`
	}
	// project carries organizationId too, per section 2 fact 4.
	type projectOut struct {
		ID             string `json:"id"`
		OrganizationID string `json:"organizationId"`
	}
	type userOut struct {
		ID             string `json:"id"`
		OrganizationID string `json:"organizationId"`
	}
	type authFull struct {
		ID           string     `json:"id"`
		Project      projectOut `json:"project"`
		Organization idOut      `json:"organization"`
		User         userOut    `json:"user"`
		State        string     `json:"state"`
		Roles        []roleOut  `json:"roles"`
	}

	matched := make([]*fakeUserGrant, 0, len(f.userGrants))
	for _, ug := range f.userGrants {
		if orgID != "" && ug.OrgID != orgID {
			continue
		}
		if projectID != "" && ug.ProjectID != projectID {
			continue
		}
		if userIDs != nil && !userIDs[ug.UserID] {
			continue
		}
		matched = append(matched, ug)
	}
	total := len(matched)

	limit := req.Pagination.Limit
	offset := req.Pagination.Offset
	if limit <= 0 {
		limit = total
	}
	end := offset + limit
	if offset > total {
		offset = total
	}
	if end > total {
		end = total
	}
	page := matched[offset:end]

	out := make([]authFull, 0, len(page))
	for _, ug := range page {
		state := "STATE_ACTIVE"
		if !ug.Active {
			state = "STATE_INACTIVE"
		}
		roles := make([]roleOut, 0, len(ug.RoleKeys))
		for _, k := range ug.RoleKeys {
			roles = append(roles, roleOut{Key: k})
		}
		out = append(out, authFull{
			ID:           ug.ID,
			Project:      projectOut{ID: ug.ProjectID, OrganizationID: f.projects[ug.ProjectID].OwnerOrgID},
			Organization: idOut{ID: ug.OrgID},
			User:         userOut{ID: ug.UserID, OrganizationID: ug.UserOrgID},
			State:        state,
			Roles:        roles,
		})
	}
	writeOK(w, map[string]any{
		"authorizations": out,
		"pagination":     map[string]any{"totalResult": total},
	})
}
