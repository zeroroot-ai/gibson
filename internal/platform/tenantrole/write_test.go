// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package tenantrole_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
)

// fakeGrants is an in-memory tenantrole.Grants whose four calls can each be
// forced to fail, for the write.go error-wrapping branches the real
// zitadelGrants-over-HTTP fixture cannot reach without a genuine transport
// failure.
type fakeGrants struct {
	grants map[string]tenantrole.Grant
	nextID int
	listN  int

	listErr, createErr, updateErr, deleteErr error
	// listErrOnCall, when non-zero, fails only the Nth List call (1-based)
	// instead of every call — for a test that needs the first lookup (e.g.
	// Transfer's activeGrant(from)) to succeed and a later one to fail.
	listErrOnCall int
}

func newFakeGrants() *fakeGrants { return &fakeGrants{grants: map[string]tenantrole.Grant{}} }

func (f *fakeGrants) List(_ context.Context, orgID string, userIDs []string) ([]tenantrole.Grant, error) {
	f.listN++
	if f.listErrOnCall != 0 && f.listN == f.listErrOnCall {
		return nil, f.listErr
	}
	if f.listErrOnCall == 0 && f.listErr != nil {
		return nil, f.listErr
	}
	want := map[string]bool{}
	for _, id := range userIDs {
		want[id] = true
	}
	var out []tenantrole.Grant
	for _, g := range f.grants {
		if g.OrgID != orgID {
			continue
		}
		if len(want) > 0 && !want[g.UserID] {
			continue
		}
		out = append(out, g)
	}
	return out, nil
}

func (f *fakeGrants) Create(_ context.Context, orgID, userID string, r tenantrole.Role) (string, error) {
	if f.createErr != nil {
		return "", f.createErr
	}
	f.nextID++
	id := "grant-" + strconv.Itoa(f.nextID)
	f.grants[id] = tenantrole.Grant{ID: id, UserID: userID, UserOrgID: orgID, OrgID: orgID, RoleKeys: []string{string(r)}, Active: true}
	return id, nil
}

func (f *fakeGrants) Update(_ context.Context, grantID string, r tenantrole.Role) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	g := f.grants[grantID]
	g.RoleKeys = []string{string(r)}
	f.grants[grantID] = g
	return nil
}

func (f *fakeGrants) Delete(_ context.Context, grantID string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.grants, grantID)
	return nil
}

// --- Assign -----------------------------------------------------------

func TestAssign_RequiresATenantIDAndOrgID(t *testing.T) {
	f := newFixture(t)
	err := f.syncer.Assign(context.Background(), tenantrole.Tenant{ID: "acme", OrgID: ""}, "u1", tenantrole.Owner)
	if err == nil || !strings.Contains(err.Error(), "tenant id and org id") {
		t.Fatalf("Assign with no org id: err = %v, want a tenant/org id error", err)
	}
}

func TestAssign_RequiresAUserID(t *testing.T) {
	f := newFixture(t)
	err := f.syncer.Assign(context.Background(), tenant("acme", f.orgID), "", tenantrole.Owner)
	if err == nil || !strings.Contains(err.Error(), "userID") {
		t.Fatalf("Assign with no userID: err = %v, want a userID error", err)
	}
}

func TestAssign_CreatesAGrantWhenNoneExistsAndWritesTheTuple(t *testing.T) {
	f := newFixture(t)
	userID := f.id.AddUser(f.orgID, "new@example.com")

	if err := f.syncer.Assign(context.Background(), tenant("acme", f.orgID), userID, tenantrole.Editor); err != nil {
		t.Fatalf("Assign: %v", err)
	}

	found := false
	for _, tup := range f.tuples.all() {
		if tup.User == "user:"+userID && tup.Relation == "writer" && tup.Object == "tenant:acme" {
			found = true
		}
	}
	if !found {
		t.Fatalf("tuples after Assign = %+v, want a writer tuple for %s", f.tuples.all(), userID)
	}
}

func TestAssign_UpdatesAnExistingGrantInPlace(t *testing.T) {
	f := newFixture(t)
	userID := f.id.AddUser(f.orgID, "existing@example.com")
	createGrant(t, f, userID, []string{"viewer"})
	if _, err := f.syncer.Sync(context.Background(), tenant("acme", f.orgID), userID); err != nil {
		t.Fatalf("seed Sync: %v", err)
	}

	if err := f.syncer.Assign(context.Background(), tenant("acme", f.orgID), userID, tenantrole.Admin); err != nil {
		t.Fatalf("Assign: %v", err)
	}

	var relations []string
	for _, tup := range f.tuples.all() {
		if tup.User == "user:"+userID && tup.Object == "tenant:acme" {
			relations = append(relations, tup.Relation)
		}
	}
	if len(relations) != 1 || relations[0] != "admin" {
		t.Fatalf("relations for %s after re-Assign = %v, want exactly [admin] (the old grant updated in place, not a second one created)", userID, relations)
	}
}

// --- Revoke -------------------------------------------------------------

func TestRevoke_RequiresATenantIDAndOrgID(t *testing.T) {
	f := newFixture(t)
	err := f.syncer.Revoke(context.Background(), tenantrole.Tenant{ID: "acme", OrgID: ""}, "u1")
	if err == nil || !strings.Contains(err.Error(), "tenant id and org id") {
		t.Fatalf("Revoke with no org id: err = %v, want a tenant/org id error", err)
	}
}

func TestRevoke_RequiresAUserID(t *testing.T) {
	f := newFixture(t)
	err := f.syncer.Revoke(context.Background(), tenant("acme", f.orgID), "")
	if err == nil || !strings.Contains(err.Error(), "userID") {
		t.Fatalf("Revoke with no userID: err = %v, want a userID error", err)
	}
}

func TestRevoke_DeletesTheActiveGrantAndTheTuple(t *testing.T) {
	f := newFixture(t)
	userID := f.id.AddUser(f.orgID, "revoke-me@example.com")
	createGrant(t, f, userID, []string{"admin"})
	if _, err := f.syncer.Sync(context.Background(), tenant("acme", f.orgID), userID); err != nil {
		t.Fatalf("seed Sync: %v", err)
	}

	if err := f.syncer.Revoke(context.Background(), tenant("acme", f.orgID), userID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	for _, tup := range f.tuples.all() {
		if tup.User == "user:"+userID && tup.Object == "tenant:acme" {
			t.Fatalf("tuples after Revoke = %+v, want no role tuple left for %s", f.tuples.all(), userID)
		}
	}
}

func TestRevoke_NoActiveGrantIsANoOpNotAnError(t *testing.T) {
	f := newFixture(t)
	userID := f.id.AddUser(f.orgID, "never-granted@example.com")

	if err := f.syncer.Revoke(context.Background(), tenant("acme", f.orgID), userID); err != nil {
		t.Fatalf("Revoke with no existing grant: %v, want nil (idempotent)", err)
	}
}

// --- Transfer: the branches TestSync_TransferMovesOwnerInOneWriteAndDelete
// does not reach (both users already granted) ----------------------------

func TestTransfer_RequiresATenantIDAndOrgID(t *testing.T) {
	f := newFixture(t)
	err := f.syncer.Transfer(context.Background(), tenantrole.Tenant{ID: "acme", OrgID: ""}, "a", "b")
	if err == nil || !strings.Contains(err.Error(), "tenant id and org id") {
		t.Fatalf("Transfer with no org id: err = %v, want a tenant/org id error", err)
	}
}

func TestTransfer_RequiresTwoDistinctUsers(t *testing.T) {
	f := newFixture(t)
	tests := []struct {
		name     string
		from, to string
	}{
		{"empty from", "", "b"},
		{"empty to", "a", ""},
		{"same user", "a", "a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := f.syncer.Transfer(context.Background(), tenant("acme", f.orgID), tt.from, tt.to)
			if err == nil || !strings.Contains(err.Error(), "two distinct users") {
				t.Fatalf("Transfer(%q, %q): err = %v, want a distinct-users error", tt.from, tt.to, err)
			}
		})
	}
}

func TestTransfer_CreatesGrantsWhenNeitherUserHasOneYet(t *testing.T) {
	f := newFixture(t)
	from := f.id.AddUser(f.orgID, "from@example.com")
	to := f.id.AddUser(f.orgID, "to@example.com")

	if err := f.syncer.Transfer(context.Background(), tenant("acme", f.orgID), from, to); err != nil {
		t.Fatalf("Transfer: %v", err)
	}

	var gotOwner, gotAdmin bool
	for _, tup := range f.tuples.all() {
		if tup.Object != "tenant:acme" {
			continue
		}
		if tup.Relation == "owner" && tup.User == "user:"+to {
			gotOwner = true
		}
		if tup.Relation == "admin" && tup.User == "user:"+from {
			gotAdmin = true
		}
	}
	if !gotOwner || !gotAdmin {
		t.Fatalf("tuples after Transfer with no prior grants = %+v, want a fresh owner grant for %s and admin grant for %s", f.tuples.all(), to, from)
	}
}

func TestTransfer_PromotesToWhenOnlyToHasAPriorGrant(t *testing.T) {
	f := newFixture(t)
	from := f.id.AddUser(f.orgID, "from2@example.com")
	to := f.id.AddUser(f.orgID, "to2@example.com")
	createGrant(t, f, to, []string{"viewer"})
	if _, err := f.syncer.Sync(context.Background(), tenant("acme", f.orgID), to); err != nil {
		t.Fatalf("seed Sync: %v", err)
	}

	if err := f.syncer.Transfer(context.Background(), tenant("acme", f.orgID), from, to); err != nil {
		t.Fatalf("Transfer: %v", err)
	}

	var gotOwner, gotAdmin bool
	for _, tup := range f.tuples.all() {
		if tup.Object != "tenant:acme" {
			continue
		}
		if tup.Relation == "owner" && tup.User == "user:"+to {
			gotOwner = true
		}
		if tup.Relation == "admin" && tup.User == "user:"+from {
			gotAdmin = true
		}
	}
	if !gotOwner || !gotAdmin {
		t.Fatalf("tuples after Transfer (to pre-granted) = %+v, want %s promoted to owner and %s created as admin", f.tuples.all(), to, from)
	}
}

// erroringTuples is a Tuples whose ReadRoles always fails, to force Sync
// itself to fail from inside Assign/Revoke/Transfer without needing a real
// owner-conflict scenario.
type erroringTuples struct{ err error }

func (e erroringTuples) ReadRoles(context.Context, string, []string) ([]tenantrole.Tuple, error) {
	return nil, e.err
}
func (e erroringTuples) WriteAndDelete(context.Context, []tenantrole.Tuple, []tenantrole.Tuple) error {
	return e.err
}

// --- Assign: wrapped errors from each collaborator ----------------------

func TestAssign_WrapsAnActiveGrantLookupError(t *testing.T) {
	grants := newFakeGrants()
	grants.listErr = errors.New("list boom")
	syncer := tenantrole.NewSyncer(grants, newFakeTuples(), nil)

	err := syncer.Assign(context.Background(), tenant("acme", "ORG-1"), "u1", tenantrole.Owner)
	if err == nil || !strings.Contains(err.Error(), "list boom") {
		t.Fatalf("Assign: err = %v, want it to wrap the List error", err)
	}
}

func TestAssign_WrapsAnUpdateError(t *testing.T) {
	grants := newFakeGrants()
	id, _ := grants.Create(context.Background(), "ORG-1", "u1", tenantrole.Viewer)
	_ = id
	grants.updateErr = errors.New("update boom")
	syncer := tenantrole.NewSyncer(grants, newFakeTuples(), nil)

	err := syncer.Assign(context.Background(), tenant("acme", "ORG-1"), "u1", tenantrole.Owner)
	if err == nil || !strings.Contains(err.Error(), "update boom") {
		t.Fatalf("Assign: err = %v, want it to wrap the Update error", err)
	}
}

func TestAssign_WrapsACreateError(t *testing.T) {
	grants := newFakeGrants()
	grants.createErr = errors.New("create boom")
	syncer := tenantrole.NewSyncer(grants, newFakeTuples(), nil)

	err := syncer.Assign(context.Background(), tenant("acme", "ORG-1"), "u1", tenantrole.Owner)
	if err == nil || !strings.Contains(err.Error(), "create boom") {
		t.Fatalf("Assign: err = %v, want it to wrap the Create error", err)
	}
}

func TestAssign_WrapsASyncError(t *testing.T) {
	grants := newFakeGrants()
	syncer := tenantrole.NewSyncer(grants, erroringTuples{err: errors.New("sync boom")}, nil)

	err := syncer.Assign(context.Background(), tenant("acme", "ORG-1"), "u1", tenantrole.Owner)
	if err == nil || !strings.Contains(err.Error(), "sync boom") {
		t.Fatalf("Assign: err = %v, want it to wrap the Sync error", err)
	}
}

// --- Revoke: wrapped errors from each collaborator -----------------------

func TestRevoke_WrapsAListError(t *testing.T) {
	grants := newFakeGrants()
	grants.listErr = errors.New("list boom")
	syncer := tenantrole.NewSyncer(grants, newFakeTuples(), nil)

	err := syncer.Revoke(context.Background(), tenant("acme", "ORG-1"), "u1")
	if err == nil || !strings.Contains(err.Error(), "list boom") {
		t.Fatalf("Revoke: err = %v, want it to wrap the List error", err)
	}
}

func TestRevoke_WrapsADeleteError(t *testing.T) {
	grants := newFakeGrants()
	_, _ = grants.Create(context.Background(), "ORG-1", "u1", tenantrole.Admin)
	grants.deleteErr = errors.New("delete boom")
	syncer := tenantrole.NewSyncer(grants, newFakeTuples(), nil)

	err := syncer.Revoke(context.Background(), tenant("acme", "ORG-1"), "u1")
	if err == nil || !strings.Contains(err.Error(), "delete boom") {
		t.Fatalf("Revoke: err = %v, want it to wrap the Delete error", err)
	}
}

func TestRevoke_WrapsASyncError(t *testing.T) {
	grants := newFakeGrants()
	syncer := tenantrole.NewSyncer(grants, erroringTuples{err: errors.New("sync boom")}, nil)

	err := syncer.Revoke(context.Background(), tenant("acme", "ORG-1"), "u1")
	if err == nil || !strings.Contains(err.Error(), "sync boom") {
		t.Fatalf("Revoke: err = %v, want it to wrap the Sync error", err)
	}
}

// --- Transfer: wrapped errors from each collaborator ---------------------

func TestTransfer_WrapsAnActiveGrantLookupError(t *testing.T) {
	grants := newFakeGrants()
	grants.listErr = errors.New("list boom")
	syncer := tenantrole.NewSyncer(grants, newFakeTuples(), nil)

	err := syncer.Transfer(context.Background(), tenant("acme", "ORG-1"), "from", "to")
	if err == nil || !strings.Contains(err.Error(), "list boom") {
		t.Fatalf("Transfer: err = %v, want it to wrap the List error", err)
	}
}

func TestTransfer_WrapsAnUpdateErrorPromotingTo(t *testing.T) {
	grants := newFakeGrants()
	_, _ = grants.Create(context.Background(), "ORG-1", "to", tenantrole.Viewer)
	grants.updateErr = errors.New("promote boom")
	syncer := tenantrole.NewSyncer(grants, newFakeTuples(), nil)

	err := syncer.Transfer(context.Background(), tenant("acme", "ORG-1"), "from", "to")
	if err == nil || !strings.Contains(err.Error(), "promote boom") {
		t.Fatalf("Transfer: err = %v, want it to wrap the promote Update error", err)
	}
}

func TestTransfer_WrapsACreateErrorPromotingTo(t *testing.T) {
	grants := newFakeGrants()
	grants.createErr = errors.New("promote create boom")
	syncer := tenantrole.NewSyncer(grants, newFakeTuples(), nil)

	err := syncer.Transfer(context.Background(), tenant("acme", "ORG-1"), "from", "to")
	if err == nil || !strings.Contains(err.Error(), "promote create boom") {
		t.Fatalf("Transfer: err = %v, want it to wrap the promote Create error", err)
	}
}

func TestTransfer_WrapsAnUpdateErrorDemotingFrom(t *testing.T) {
	grants := newFakeGrants()
	_, _ = grants.Create(context.Background(), "ORG-1", "from", tenantrole.Owner)
	// "to" has no prior grant, so promoting to creates rather than updates —
	// only the demote (from) Update below must fail.
	syncer := tenantrole.NewSyncer(grants, newFakeTuples(), nil)
	grants.updateErr = errors.New("demote boom")

	err := syncer.Transfer(context.Background(), tenant("acme", "ORG-1"), "from", "to")
	if err == nil || !strings.Contains(err.Error(), "demote boom") {
		t.Fatalf("Transfer: err = %v, want it to wrap the demote Update error", err)
	}
}

func TestTransfer_WrapsASyncError(t *testing.T) {
	grants := newFakeGrants()
	syncer := tenantrole.NewSyncer(grants, erroringTuples{err: errors.New("sync boom")}, nil)

	err := syncer.Transfer(context.Background(), tenant("acme", "ORG-1"), "from", "to")
	if err == nil || !strings.Contains(err.Error(), "sync boom") {
		t.Fatalf("Transfer: err = %v, want it to wrap the Sync error", err)
	}
}

func TestRevoke_SkipsGrantsThatAreNotTheActiveMatch(t *testing.T) {
	grants := newFakeGrants()
	// A grant for a different user and an inactive grant for this user, both
	// returned by List (a real Grants might over-return on a loose filter):
	// neither must be deleted.
	grants.grants["g-other-user"] = tenantrole.Grant{ID: "g-other-user", UserID: "someone-else", OrgID: "ORG-1", Active: true}
	inactiveID, _ := grants.Create(context.Background(), "ORG-1", "u1", tenantrole.Admin)
	g := grants.grants[inactiveID]
	g.Active = false
	grants.grants[inactiveID] = g
	syncer := tenantrole.NewSyncer(grants, newFakeTuples(), nil)

	if err := syncer.Revoke(context.Background(), tenant("acme", "ORG-1"), "u1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, stillThere := grants.grants["g-other-user"]; !stillThere {
		t.Error("Revoke must never delete a grant belonging to a different user")
	}
	if _, stillThere := grants.grants[inactiveID]; !stillThere {
		t.Error("Revoke must never delete an already-inactive grant")
	}
}

func TestTransfer_WrapsAnActiveGrantLookupErrorForTo(t *testing.T) {
	grants := newFakeGrants()
	grants.listErrOnCall = 2 // let activeGrant(from) succeed, fail activeGrant(to)
	grants.listErr = errors.New("list boom for to")
	syncer := tenantrole.NewSyncer(grants, newFakeTuples(), nil)

	err := syncer.Transfer(context.Background(), tenant("acme", "ORG-1"), "from", "to")
	if err == nil || !strings.Contains(err.Error(), "list boom for to") {
		t.Fatalf("Transfer: err = %v, want it to wrap the second List error", err)
	}
}

func TestTransfer_WrapsACreateErrorDemotingFrom(t *testing.T) {
	grants := newFakeGrants()
	// "to" already has a grant, so promoting it takes the Update path
	// (succeeds); "from" has none, so demoting it takes the Create path,
	// which is the one that must fail here.
	_, _ = grants.Create(context.Background(), "ORG-1", "to", tenantrole.Viewer)
	grants.createErr = errors.New("demote create boom")
	syncer := tenantrole.NewSyncer(grants, newFakeTuples(), nil)

	err := syncer.Transfer(context.Background(), tenant("acme", "ORG-1"), "from", "to")
	if err == nil || !strings.Contains(err.Error(), "demote create boom") {
		t.Fatalf("Transfer: err = %v, want it to wrap the demote Create error", err)
	}
}
