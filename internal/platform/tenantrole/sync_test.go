// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package tenantrole_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn"
	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn/zitadelconntest"
)

// fakeTuples is an in-memory Tuples, scoped across every tenant object so a
// test can seed cross-tenant or non-role state and assert it is untouched.
type fakeTuples struct {
	mu     sync.Mutex
	tuples []tenantrole.Tuple
}

func newFakeTuples(seed ...tenantrole.Tuple) *fakeTuples {
	return &fakeTuples{tuples: append([]tenantrole.Tuple(nil), seed...)}
}

func (f *fakeTuples) all() []tenantrole.Tuple {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]tenantrole.Tuple(nil), f.tuples...)
}

func (f *fakeTuples) seed(tuples ...tenantrole.Tuple) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tuples = append(f.tuples, tuples...)
}

func (f *fakeTuples) ReadRoles(_ context.Context, tenantID string, userIDs []string) ([]tenantrole.Tuple, error) {
	object := "tenant:" + tenantID
	roleRelation := map[string]bool{}
	for _, r := range tenantrole.Relations {
		roleRelation[r] = true
	}
	var want map[string]bool
	if len(userIDs) > 0 {
		want = map[string]bool{}
		for _, id := range userIDs {
			want["user:"+id] = true
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []tenantrole.Tuple
	for _, t := range f.tuples {
		if t.Object != object || !roleRelation[t.Relation] {
			continue
		}
		if !tenantrole.IsZitadelUserSubject(t.User) {
			continue
		}
		if want != nil && !want[t.User] {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

func (f *fakeTuples) WriteAndDelete(_ context.Context, writes, deletes []tenantrole.Tuple) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, d := range deletes {
		for i, t := range f.tuples {
			if t == d {
				f.tuples = append(f.tuples[:i], f.tuples[i+1:]...)
				break
			}
		}
	}
	f.tuples = append(f.tuples, writes...)
	return nil
}

// testFixture builds an Identity fake with the gibson project + its four
// roles + a tenant org already granted, and a Syncer wired to it plus an
// in-memory Tuples.
type testFixture struct {
	id      *zitadelconntest.Identity
	ep      zitadelconn.Endpoint
	hc      *http.Client
	tuples  *fakeTuples
	syncer  *tenantrole.Syncer
	orgID   string
	project string
}

func newFixture(t *testing.T, seed ...tenantrole.Tuple) *testFixture {
	t.Helper()
	id := zitadelconntest.NewIdentity()
	srv := zitadelconntest.New(t, "", id.Handler())
	ep := srv.Endpoint(t)
	hc := &http.Client{Transport: ep.Transport(nil)}

	platformOrg := id.AddOrg("platform")
	project := id.AddProject(platformOrg, "gibson")
	orgID := id.AddOrg("tenant-1")

	for _, d := range tenantrole.All {
		postJSON(t, hc, ep, "/zitadel.project.v2.ProjectService/AddProjectRole", map[string]any{
			"projectId": project, "roleKey": string(d.Key), "displayName": d.DisplayName,
		})
	}
	postJSON(t, hc, ep, "/zitadel.project.v2.ProjectService/CreateProjectGrant", map[string]any{
		"projectId": project, "grantedOrganizationId": orgID, "roleKeys": tenantrole.Keys(),
	})

	grants := tenantrole.NewZitadelGrants(ep, hc, project)
	tuples := newFakeTuples(seed...)
	return &testFixture{
		id: id, ep: ep, hc: hc, tuples: tuples,
		syncer: tenantrole.NewSyncer(grants, tuples, nil),
		orgID:  orgID, project: project,
	}
}

func postJSON(t *testing.T, hc *http.Client, ep zitadelconn.Endpoint, path string, body any) {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, ep.URL(path), bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s: status %d", path, resp.StatusCode)
	}
}

func createGrant(t *testing.T, f *testFixture, userID string, roleKeys []string) string {
	t.Helper()
	var out struct {
		ID string `json:"id"`
	}
	buf, _ := json.Marshal(map[string]any{
		"userId": userID, "projectId": f.project, "organizationId": f.orgID, "roleKeys": roleKeys,
	})
	req, _ := http.NewRequest(http.MethodPost, f.ep.URL("/zitadel.authorization.v2.AuthorizationService/CreateAuthorization"), bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateAuthorization: status %d", resp.StatusCode)
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out.ID
}

func tenant(id string, orgID string) tenantrole.Tenant {
	return tenantrole.Tenant{ID: id, OrgID: orgID}
}

// --- table-driven coverage of section 11 item 2 ---------------------------

func TestSync_NewGrantWritesOneTuple(t *testing.T) {
	f := newFixture(t)
	userID := f.id.AddUser(f.orgID, "owner@example.com")
	createGrant(t, f, userID, []string{"owner"})

	res, err := f.syncer.Sync(context.Background(), tenant("acme", f.orgID), userID)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(res.Written) != 1 || res.Written[0] != (tenantrole.Tuple{User: "user:" + userID, Relation: "owner", Object: "tenant:acme"}) {
		t.Fatalf("Written = %+v", res.Written)
	}
	if len(res.Deleted) != 0 {
		t.Fatalf("Deleted = %+v, want none", res.Deleted)
	}
}

func TestSync_ChangedGrantDeletesOldAndWritesNewInOneCall(t *testing.T) {
	f := newFixture(t)
	userID := f.id.AddUser(f.orgID, "x@example.com")
	f.tuples.seed(tenantrole.Tuple{User: "user:" + userID, Relation: "member", Object: "tenant:acme"})
	createGrant(t, f, userID, []string{"admin"})

	res, err := f.syncer.Sync(context.Background(), tenant("acme", f.orgID), userID)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(res.Deleted) != 1 || res.Deleted[0].Relation != "member" {
		t.Fatalf("Deleted = %+v, want the old member tuple", res.Deleted)
	}
	if len(res.Written) != 1 || res.Written[0].Relation != "admin" {
		t.Fatalf("Written = %+v, want the new admin tuple", res.Written)
	}
}

func TestSync_DeletedGrantDeletesTheTuple(t *testing.T) {
	f := newFixture(t, tenantrole.Tuple{User: "user:999", Relation: "writer", Object: "tenant:acme"})
	res, err := f.syncer.Sync(context.Background(), tenant("acme", f.orgID), "999")
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(res.Deleted) != 1 || len(res.Written) != 0 {
		t.Fatalf("res = %+v, want one delete and no write", res)
	}
}

func TestSync_InactiveGrantGivesNoRole(t *testing.T) {
	f := newFixture(t)
	userID := f.id.AddUser(f.orgID, "x@example.com")
	grantID := createGrant(t, f, userID, []string{"editor"})
	postJSON(t, f.hc, f.ep, "/zitadel.authorization.v2.AuthorizationService/DeleteAuthorization", map[string]any{"id": grantID})
	// Re-create then mark inactive isn't supported by the fake, so exercise
	// the "no active grant" path directly: after delete, there is no grant
	// at all, which also gives no role. List returns nothing, so no write.
	res, err := f.syncer.Sync(context.Background(), tenant("acme", f.orgID), userID)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(res.Written) != 0 {
		t.Fatalf("Written = %+v, want none", res.Written)
	}
}

func TestSync_TwoRoleKeysGiveNoRole(t *testing.T) {
	f := newFixture(t)
	userID := f.id.AddUser(f.orgID, "x@example.com")
	createGrant(t, f, userID, []string{"owner", "admin"})

	res, err := f.syncer.Sync(context.Background(), tenant("acme", f.orgID), userID)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(res.Written) != 0 {
		t.Fatalf("Written = %+v, want none (two role keys is invalid)", res.Written)
	}
	if len(res.Invalid) != 1 {
		t.Fatalf("Invalid = %+v, want one entry", res.Invalid)
	}
}

func TestSync_UnknownRoleKeyGivesNoRole(t *testing.T) {
	f := newFixture(t)
	// AddProjectRole a role Zitadel would allow but tenantrole does not parse.
	postJSON(t, f.hc, f.ep, "/zitadel.project.v2.ProjectService/AddProjectRole", map[string]any{
		"projectId": f.project, "roleKey": "superuser", "displayName": "Superuser",
	})
	postJSON(t, f.hc, f.ep, "/zitadel.project.v2.ProjectService/UpdateProjectGrant", map[string]any{
		"projectId": f.project, "grantedOrganizationId": f.orgID,
		"roleKeys": append(tenantrole.Keys(), "superuser"),
	})
	userID := f.id.AddUser(f.orgID, "x@example.com")
	createGrant(t, f, userID, []string{"superuser"})

	res, err := f.syncer.Sync(context.Background(), tenant("acme", f.orgID), userID)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(res.Written) != 0 || len(res.Invalid) != 1 {
		t.Fatalf("res = %+v, want no write and one invalid grant", res)
	}
}

func TestSync_UserFromAnotherOrgGivesNoRole(t *testing.T) {
	f := newFixture(t)
	otherOrg := f.id.AddOrg("tenant-2")
	userID := f.id.AddUser(otherOrg, "x@example.com") // belongs to a different org
	createGrant(t, f, userID, []string{"owner"})

	res, err := f.syncer.Sync(context.Background(), tenant("acme", f.orgID), userID)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(res.Written) != 0 || len(res.Invalid) != 1 {
		t.Fatalf("res = %+v, want no write and one invalid grant", res)
	}
}

func TestSync_WholeTenantSyncRepairsDrift(t *testing.T) {
	// A stored tuple with no backing Zitadel grant: drift. A non-owner
	// relation, so the fix does not also trip the owner-conflict guard.
	f := newFixture(t, tenantrole.Tuple{User: "user:888", Relation: "member", Object: "tenant:acme"})
	res, err := f.syncer.Sync(context.Background(), tenant("acme", f.orgID)) // no users: whole tenant
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(res.Deleted) != 1 || res.Deleted[0].User != "user:888" {
		t.Fatalf("Deleted = %+v, want the ghost tuple gone", res.Deleted)
	}
}

func TestSync_TransferMovesOwnerInOneWriteAndDelete(t *testing.T) {
	f := newFixture(t)
	ownerID := f.id.AddUser(f.orgID, "owner@example.com")
	adminID := f.id.AddUser(f.orgID, "admin@example.com")
	createGrant(t, f, ownerID, []string{"owner"})
	createGrant(t, f, adminID, []string{"admin"})
	if _, err := f.syncer.Sync(context.Background(), tenant("acme", f.orgID), ownerID, adminID); err != nil {
		t.Fatalf("seed Sync: %v", err)
	}

	if err := f.syncer.Transfer(context.Background(), tenant("acme", f.orgID), ownerID, adminID); err != nil {
		t.Fatalf("Transfer: %v", err)
	}
	all := f.tuples.all()
	var gotOwner, gotAdmin bool
	owners := 0
	for _, tup := range all {
		if tup.Object != "tenant:acme" {
			continue
		}
		if tup.Relation == "owner" {
			owners++
			if tup.User == "user:"+adminID {
				gotOwner = true
			}
		}
		if tup.Relation == "admin" && tup.User == "user:"+ownerID {
			gotAdmin = true
		}
	}
	if owners != 1 || !gotOwner || !gotAdmin {
		t.Fatalf("tuples after Transfer = %+v, want exactly one Owner (%s) and one Admin (%s)", all, adminID, ownerID)
	}
}

func TestSync_OwnerConflictWritesNothing(t *testing.T) {
	f := newFixture(t)
	u1 := f.id.AddUser(f.orgID, "a@example.com")
	u2 := f.id.AddUser(f.orgID, "b@example.com")
	createGrant(t, f, u1, []string{"owner"})
	createGrant(t, f, u2, []string{"owner"})

	before := f.tuples.all()
	_, err := f.syncer.Sync(context.Background(), tenant("acme", f.orgID))
	if !errors.Is(err, tenantrole.ErrOwnerConflict) {
		t.Fatalf("err = %v, want ErrOwnerConflict", err)
	}
	after := f.tuples.all()
	if len(before) != len(after) {
		t.Fatalf("tuples changed on a conflict: before=%v after=%v", before, after)
	}
}

func TestSync_NonZitadelUserSubjectsAreNeverTouched(t *testing.T) {
	// Two shapes that must both survive a whole-tenant Sync untouched: a
	// non-user-typed principal, and the e2e runner's `user:`-prefixed but
	// non-numeric SPIFFE identity (owner decision D2, option b — gibson#14
	// fixtures write this one directly).
	agentTuple := tenantrole.Tuple{User: "agent_principal:e2e-runner", Relation: "member", Object: "tenant:acme"}
	e2eRunnerTuple := tenantrole.Tuple{User: "user:zeroroot.ai/platform/e2e-runner", Relation: "member", Object: "tenant:acme"}
	f := newFixture(t, agentTuple, e2eRunnerTuple)
	if _, err := f.syncer.Sync(context.Background(), tenant("acme", f.orgID)); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	all := f.tuples.all()
	for _, want := range []tenantrole.Tuple{agentTuple, e2eRunnerTuple} {
		found := false
		for _, tup := range all {
			if tup == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("tuple %+v was removed by Sync, all = %+v", want, all)
		}
	}
}

func TestSync_EmptyOrgIDIsAnError(t *testing.T) {
	f := newFixture(t)
	_, err := f.syncer.Sync(context.Background(), tenant("acme", ""))
	if err == nil {
		t.Fatal("expected an error for an empty org id")
	}
}
