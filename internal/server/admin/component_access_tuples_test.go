// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package admin

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// accessTestTenant is the tenant ref catalogCtx() puts on the context, and
	// so the subject the ownership gate must ask about.
	accessTestTenant = "tenant:acme"
	// accessTestComponent is the normalised object ref for the component every
	// test in this file reconciles.
	accessTestComponent = "component:agent/zerocool-http8"
)

// accessFGA records writes/deletes and replays a canned ListUsers result, so a
// full reconcile can be checked without OpenFGA.
//
// Both read methods are keyed on the full argument set rather than answering a
// constant. That is not tidiness: SetComponentAccess writes to a component
// object SHARED across tenants, and the only thing standing between a tenant
// admin and another tenant's access on it is the "parent" ownership gate
// (gibson#1289). A double that answered from the relation alone would return
// the same verdict whether or not that gate still scoped to the caller's
// tenant, so every test here would have passed with the gate deleted.
type accessFGA struct {
	fakeAuthorizerCatalog

	// callerTenant is the tenant ref the ownership gate is expected to name,
	// and ownedTeams the team refs that tenant parents. A gate that stopped
	// passing the caller's tenant, or stopped naming the team, gets a deny.
	callerTenant string
	ownedTeams   []string

	// listObject/listRelation/listUserType are the question `existing` answers.
	// Any other question answers empty, so the fixture cannot stand in for a
	// listing that has drifted to a different object, relation, or subject type.
	listObject   string
	listRelation string
	listUserType string
	existing     []string

	// members are user refs that are members of callerTenant (user-scope
	// ownership gate).
	members []string

	written []authz.Tuple
	deleted []authz.Tuple
}

func (f *accessFGA) ListUsers(_ context.Context, objectType, object, relation string) ([]string, error) {
	if objectType != "component" || object != f.listObject || relation != f.listRelation {
		return nil, nil
	}
	return f.existing, nil
}

// ListUsersOfType is the reconcile's real enumeration path (tenant_*_disabled
// does not admit "user", so a plain ListUsers cannot enumerate it). Keyed on the
// full argument set for the same reason ListUsers is.
func (f *accessFGA) ListUsersOfType(_ context.Context, objectType, object, relation, userType string) ([]string, error) {
	if objectType != "component" || object != f.listObject || relation != f.listRelation || userType != f.listUserType {
		return nil, nil
	}
	return f.existing, nil
}

// Check answers the caller-tenant "parent" ownership gate from the subject and
// the object it is asked about, so the deny side is reachable — see
// TestSetComponentAccess_RefusesATeamOutsideTheCallersTenant and
// TestSetComponentAccess_LeavesAnotherTenantsTupleAlone, which exercise it.
//
// Relations other than "parent" deny: this double stands in for the ownership
// gate only, and a caller reaching it with some other question is a defect the
// tests should see rather than absorb.
func (f *accessFGA) Check(_ context.Context, user, relation, object string) (bool, error) {
	switch relation {
	case "parent": // team-scope ownership: caller's tenant parents the team object
		return user == f.callerTenant && slices.Contains(f.ownedTeams, object), nil
	case "member": // user-scope ownership: user is a member of the caller's tenant
		return object == f.callerTenant && slices.Contains(f.members, user), nil
	default:
		return false, nil
	}
}

func (f *accessFGA) Write(_ context.Context, tuples []authz.Tuple) error {
	f.written = append(f.written, tuples...)
	return nil
}

func (f *accessFGA) Delete(_ context.Context, tuples []authz.Tuple) error {
	f.deleted = append(f.deleted, tuples...)
	return nil
}

func accessEntry(relation, teamID string, disabled bool) *tenantv1.ComponentAccessEntry {
	return &tenantv1.ComponentAccessEntry{Relation: relation, TeamId: teamID, Disabled: disabled}
}

// TestSetComponentAccess_WritesTheUsersetTheModelDeclares is the regression for
// gibson#1237.
//
// model.fga declares `team_write_disabled: [team#member]` — a userset. The
// writer emitted a bare "team:<id>", which OpenFGA rejects with a
// validation_error, so this RPC could not write any tuple at all.
func TestSetComponentAccess_WritesTheUsersetTheModelDeclares(t *testing.T) {
	fga := &accessFGA{callerTenant: accessTestTenant, ownedTeams: []string{"team:acme/red-team"}}
	srv := &TenantAdminServer{authorizer: fga}

	_, err := srv.SetComponentAccess(catalogCtx(), &tenantv1.SetComponentAccessRequest{
		Component: "component:agent/zerocool-http8",
		Entries:   []*tenantv1.ComponentAccessEntry{accessEntry("team_write_disabled", "red-team", true)},
	})
	if err != nil {
		t.Fatalf("SetComponentAccess: %v", err)
	}
	if len(fga.written) != 1 {
		t.Fatalf("wrote %d tuples, want 1", len(fga.written))
	}
	got := fga.written[0]
	if got.User != "team:acme/red-team#member" {
		t.Errorf("subject = %q, want the userset team:acme/red-team#member", got.User)
	}
	if got.Relation != "team_write_disabled" || got.Object != "component:agent/zerocool-http8" {
		t.Errorf("tuple = %+v, want the requested relation on the component object", got)
	}
}

// TestSetComponentAccess_RejectsARelationItDoesNotOwn is the other half of
// gibson#1237: any relation name reached FGA paired with a team subject, so
// `tenant_write_disabled` — declared `[tenant]` — produced a tuple the model
// rejects, reported to the caller as "fga service unavailable".
func TestSetComponentAccess_RejectsARelationItDoesNotOwn(t *testing.T) {
	for _, relation := range []string{
		"can_execute",            // a computed relation, not a settable deny
		"team_admin",             // not a component deny relation
		"bogus_relation",         // unknown
		"component_read_enabled", // a GRANT, owned by GrantComponentPermissions
	} {
		t.Run(relation, func(t *testing.T) {
			// The team IS the caller's, so an InvalidArgument here can only
			// come from the relation — the thing this test is about.
			fga := &accessFGA{callerTenant: accessTestTenant, ownedTeams: []string{"team:acme/zerocool-lab"}}
			srv := &TenantAdminServer{authorizer: fga}

			_, err := srv.SetComponentAccess(catalogCtx(), &tenantv1.SetComponentAccessRequest{
				Component: "component:agent/zerocool-http8",
				Entries:   []*tenantv1.ComponentAccessEntry{accessEntry(relation, "zerocool-lab", false)},
			})
			if err == nil {
				t.Fatalf("relation %q was accepted; it is not one this RPC owns", relation)
			}
			if got := status.Code(err); got != codes.InvalidArgument {
				t.Errorf("status = %s, want InvalidArgument (a caller bug, not an FGA outage)", got)
			}
			if !strings.Contains(err.Error(), relation) {
				t.Errorf("error = %v, want it to name the offending relation", err)
			}
			if len(fga.written) != 0 {
				t.Errorf("a rejected relation still reached FGA: %+v", fga.written)
			}
		})
	}
}

func TestSetComponentAccess_AcceptsEveryRelationItOwns(t *testing.T) {
	for _, relation := range []string{"team_read_disabled", "team_write_disabled", "team_execute_disabled"} {
		t.Run(relation, func(t *testing.T) {
			fga := &accessFGA{callerTenant: accessTestTenant, ownedTeams: []string{"team:acme/red-team"}}
			srv := &TenantAdminServer{authorizer: fga}

			if _, err := srv.SetComponentAccess(catalogCtx(), &tenantv1.SetComponentAccessRequest{
				Component: "component:agent/zerocool-http8",
				Entries:   []*tenantv1.ComponentAccessEntry{accessEntry(relation, "red-team", true)},
			}); err != nil {
				t.Fatalf("SetComponentAccess(%s): %v", relation, err)
			}
			if len(fga.written) != 1 || fga.written[0].Relation != relation {
				t.Errorf("wrote %+v, want one %s tuple", fga.written, relation)
			}
		})
	}
}

// TestSetComponentAccess_ReconcileRoundTrips guards the normalisation: FGA
// returns subjects as stored (usersets) while the desired set is keyed by the
// team object. Without normalising both sides nothing ever matches, so an
// already-correct tuple is deleted and rewritten on every call.
func TestSetComponentAccess_ReconcileRoundTrips(t *testing.T) {
	fga := &accessFGA{
		callerTenant: accessTestTenant,
		ownedTeams:   []string{"team:acme/red-team"},
		listObject:   accessTestComponent,
		listRelation: "team_write_disabled",
		listUserType: "team",
		existing:     []string{"team:acme/red-team#member"},
	}
	srv := &TenantAdminServer{authorizer: fga}

	// Ask for exactly what is already stored.
	if _, err := srv.SetComponentAccess(catalogCtx(), &tenantv1.SetComponentAccessRequest{
		Component: "component:agent/zerocool-http8",
		Entries:   []*tenantv1.ComponentAccessEntry{accessEntry("team_write_disabled", "red-team", true)},
	}); err != nil {
		t.Fatalf("SetComponentAccess: %v", err)
	}
	if len(fga.written) != 0 {
		t.Errorf("rewrote a tuple that was already present: %+v", fga.written)
	}
	if len(fga.deleted) != 0 {
		t.Errorf("deleted a tuple that was desired: %+v", fga.deleted)
	}
}

func TestSetComponentAccess_RemovesAnEntryNoLongerWanted(t *testing.T) {
	fga := &accessFGA{
		callerTenant: accessTestTenant,
		ownedTeams:   []string{"team:acme/red-team", "team:acme/blue-team"},
		listObject:   accessTestComponent,
		listRelation: "team_write_disabled",
		listUserType: "team",
		existing:     []string{"team:acme/red-team#member"},
	}
	srv := &TenantAdminServer{authorizer: fga}

	// Same relation, a different team: the stored one is no longer desired.
	if _, err := srv.SetComponentAccess(catalogCtx(), &tenantv1.SetComponentAccessRequest{
		Component: "component:agent/zerocool-http8",
		Entries:   []*tenantv1.ComponentAccessEntry{accessEntry("team_write_disabled", "blue-team", true)},
	}); err != nil {
		t.Fatalf("SetComponentAccess: %v", err)
	}
	if len(fga.deleted) != 1 || fga.deleted[0].User != "team:acme/red-team#member" {
		t.Fatalf("deleted %+v, want the stored userset removed", fga.deleted)
	}
	if len(fga.written) != 1 || fga.written[0].User != "team:acme/blue-team#member" {
		t.Fatalf("wrote %+v, want the newly desired userset", fga.written)
	}
}

// --- cross-tenant ownership gate: the deny side (gibson#1289 / gibson#1310) ---
//
// SetComponentAccess mutates tuples on a component object that is SHARED
// across tenants, so the object alone grants no isolation. The whole isolation
// property rests on one gate — every team named on the request, and every
// existing team tuple considered for deletion, must be parented by the
// caller's tenant.
//
// Until these two tests that gate had no deny-side coverage in this package:
// every case named a team the caller owned, so the gate could have been
// deleted outright and the suite stayed green.

// TestSetComponentAccess_RefusesATeamOutsideTheCallersTenant covers the
// request path. A tenant admin naming another tenant's team must be refused
// before anything is written — otherwise they can grant or revoke that
// tenant's access on a component both of them use.
func TestSetComponentAccess_RefusesATeamOutsideTheCallersTenant(t *testing.T) {
	fga := &accessFGA{
		callerTenant: accessTestTenant,
		// victim-team is deliberately absent: it is a real team, on a real
		// shared component, that this caller's tenant does not parent.
		ownedTeams: []string{"team:acme/red-team"},
	}
	srv := &TenantAdminServer{authorizer: fga}

	_, err := srv.SetComponentAccess(catalogCtx(), &tenantv1.SetComponentAccessRequest{
		Component: "component:agent/zerocool-http8",
		Entries:   []*tenantv1.ComponentAccessEntry{accessEntry("team_write_disabled", "victim-team", false)},
	})

	if err == nil {
		t.Fatal("a team outside the caller's tenant was accepted: a tenant admin could set another " +
			"tenant's component access on a shared object")
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Errorf("status = %s, want PermissionDenied", got)
	}
	if !strings.Contains(err.Error(), "victim-team") {
		t.Errorf("error = %v, want it to name the refused team", err)
	}
	if len(fga.written) != 0 || len(fga.deleted) != 0 {
		t.Errorf("a refused request still mutated FGA: written=%+v deleted=%+v", fga.written, fga.deleted)
	}
}

// TestSetComponentAccess_LeavesAnotherTenantsTupleAlone covers the reconcile
// path, which is the subtler half. Listing a shared component returns other
// tenants' team tuples too, and every one of them is "not desired" by this
// caller. Without the ownership check the reconcile would read that as
// "remove it", so a caller could revoke another tenant's access without ever
// naming their team.
func TestSetComponentAccess_LeavesAnotherTenantsTupleAlone(t *testing.T) {
	fga := &accessFGA{
		callerTenant: accessTestTenant,
		ownedTeams:   []string{"team:acme/red-team"},
		listObject:   accessTestComponent,
		listRelation: "team_write_disabled",
		listUserType: "team",
		existing:     []string{"team:victim-co/victim-team#member", "team:acme/red-team#member"},
	}
	srv := &TenantAdminServer{authorizer: fga}

	// Ask for the caller's own team only.
	if _, err := srv.SetComponentAccess(catalogCtx(), &tenantv1.SetComponentAccessRequest{
		Component: "component:agent/zerocool-http8",
		Entries:   []*tenantv1.ComponentAccessEntry{accessEntry("team_write_disabled", "red-team", true)},
	}); err != nil {
		t.Fatalf("SetComponentAccess: %v", err)
	}

	for _, d := range fga.deleted {
		if strings.Contains(d.User, "victim-team") {
			t.Errorf("deleted another tenant's tuple %+v; the reconcile owns only the caller's teams", d)
		}
	}
	if len(fga.deleted) != 0 {
		t.Errorf("deleted %+v, want nothing: red-team is desired and victim-team is not the caller's "+
			"to remove", fga.deleted)
	}
}

func TestTeamUsersetHelpers_AreInverses(t *testing.T) {
	if got := teamMemberUserset("team:acme/red-team"); got != "team:acme/red-team#member" {
		t.Errorf("teamMemberUserset = %q", got)
	}
	// Idempotent: an already-userset subject must not gain a second suffix.
	if got := teamMemberUserset("team:acme/red-team#member"); got != "team:acme/red-team#member" {
		t.Errorf("teamMemberUserset doubled the suffix: %q", got)
	}
	if got := teamObjectRef("team:acme/red-team#member"); got != "team:acme/red-team" {
		t.Errorf("teamObjectRef = %q", got)
	}
	if got := teamObjectRef("team:acme/red-team"); got != "team:acme/red-team" {
		t.Errorf("teamObjectRef changed a bare object: %q", got)
	}
}

// --- generalized scopes (#1577): tenant and user, not just team ---

// TestSetComponentAccess_TenantScopeRoundTrips: a tenant admin disables a
// component for their OWN tenant. Subject is derived as tenant:<id> from the
// tenant_* relation, never from a caller field.
func TestSetComponentAccess_TenantScopeRoundTrips(t *testing.T) {
	fga := &accessFGA{callerTenant: accessTestTenant, listUserType: "tenant"}
	srv := &TenantAdminServer{authorizer: fga}

	if _, err := srv.SetComponentAccess(catalogCtx(), &tenantv1.SetComponentAccessRequest{
		Component: "component:agent/zerocool-http8",
		Entries:   []*tenantv1.ComponentAccessEntry{accessEntry("tenant_read_disabled", "acme", true)},
	}); err != nil {
		t.Fatalf("SetComponentAccess(tenant_read_disabled): %v", err)
	}
	if len(fga.written) != 1 {
		t.Fatalf("wrote %d tuples, want 1", len(fga.written))
	}
	got := fga.written[0]
	if got.User != "tenant:acme" || got.Relation != "tenant_read_disabled" || got.Object != accessTestComponent {
		t.Errorf("tuple = %+v, want tenant:acme / tenant_read_disabled on the component", got)
	}
}

// TestSetComponentAccess_ClearsASubjectsOwnKillSwitch is the regression for the
// inversion bug: an existing tenant_read_disabled on the caller's own tenant is
// REMOVED when the request asks for it off (disabled=false). Before the fix,
// desired keyed on !GetDisabled() and the delete loop keyed on mere presence,
// so a single-entry toggle naming the subject could never clear its own kill
// switch — the dashboard's "enable read" left the deny in place (and toggling
// "on" installed one).
func TestSetComponentAccess_ClearsASubjectsOwnKillSwitch(t *testing.T) {
	fga := &accessFGA{
		callerTenant: accessTestTenant,
		listObject:   accessTestComponent,
		listRelation: "tenant_read_disabled",
		listUserType: "tenant",
		existing:     []string{"tenant:acme"},
	}
	srv := &TenantAdminServer{authorizer: fga}

	if _, err := srv.SetComponentAccess(catalogCtx(), &tenantv1.SetComponentAccessRequest{
		Component: "component:agent/zerocool-http8",
		Entries:   []*tenantv1.ComponentAccessEntry{accessEntry("tenant_read_disabled", "acme", false)},
	}); err != nil {
		t.Fatalf("SetComponentAccess(clear tenant_read_disabled): %v", err)
	}
	if len(fga.written) != 0 {
		t.Errorf("clearing a kill switch must not write: %+v", fga.written)
	}
	if len(fga.deleted) != 1 || fga.deleted[0].User != "tenant:acme" ||
		fga.deleted[0].Relation != "tenant_read_disabled" {
		t.Fatalf("deleted %+v, want the tenant:acme tenant_read_disabled removed", fga.deleted)
	}
}

// TestSetComponentAccess_TenantScopeRefusesAnotherTenant: a tenant admin may
// only disable for their own tenant — naming another tenant fails closed.
func TestSetComponentAccess_TenantScopeRefusesAnotherTenant(t *testing.T) {
	fga := &accessFGA{callerTenant: accessTestTenant, listUserType: "tenant"}
	srv := &TenantAdminServer{authorizer: fga}

	_, err := srv.SetComponentAccess(catalogCtx(), &tenantv1.SetComponentAccessRequest{
		Component: "component:agent/zerocool-http8",
		Entries:   []*tenantv1.ComponentAccessEntry{accessEntry("tenant_read_disabled", "rival-co", false)},
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("status = %s, want PermissionDenied", status.Code(err))
	}
	if len(fga.written) != 0 || len(fga.deleted) != 0 {
		t.Errorf("a refused cross-tenant request still mutated FGA: %+v %+v", fga.written, fga.deleted)
	}
}

// TestSetComponentAccess_UserScopeRoundTrips: a user_* deny writes user:<id>,
// gated on the user being a member of the caller's tenant.
func TestSetComponentAccess_UserScopeRoundTrips(t *testing.T) {
	fga := &accessFGA{callerTenant: accessTestTenant, listUserType: "user", members: []string{"user:alice"}}
	srv := &TenantAdminServer{authorizer: fga}

	if _, err := srv.SetComponentAccess(catalogCtx(), &tenantv1.SetComponentAccessRequest{
		Component: "component:agent/zerocool-http8",
		Entries:   []*tenantv1.ComponentAccessEntry{accessEntry("user_execute_disabled", "alice", true)},
	}); err != nil {
		t.Fatalf("SetComponentAccess(user_execute_disabled): %v", err)
	}
	if len(fga.written) != 1 {
		t.Fatalf("wrote %d tuples, want 1", len(fga.written))
	}
	got := fga.written[0]
	if got.User != "user:alice" || got.Relation != "user_execute_disabled" {
		t.Errorf("tuple = %+v, want user:alice / user_execute_disabled", got)
	}
}

// TestSetComponentAccess_UserScopeRefusesANonMember: a user outside the caller's
// tenant cannot be denied by this caller.
func TestSetComponentAccess_UserScopeRefusesANonMember(t *testing.T) {
	fga := &accessFGA{callerTenant: accessTestTenant, listUserType: "user"} // members empty
	srv := &TenantAdminServer{authorizer: fga}

	_, err := srv.SetComponentAccess(catalogCtx(), &tenantv1.SetComponentAccessRequest{
		Component: "component:agent/zerocool-http8",
		Entries:   []*tenantv1.ComponentAccessEntry{accessEntry("user_read_disabled", "stranger", false)},
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("status = %s, want PermissionDenied", status.Code(err))
	}
	if len(fga.written) != 0 {
		t.Errorf("a refused user request still wrote: %+v", fga.written)
	}
}

// TestComponentDenyScopes_ScopeMatchesRelationPrefix guards the map: every
// relation's fgaType agrees with its scope prefix, and exactly the 9 deny
// relations are present (3 scopes × read/write/execute).
func TestComponentDenyScopes_ScopeMatchesRelationPrefix(t *testing.T) {
	if len(componentDenyScopes) != 9 {
		t.Fatalf("componentDenyScopes has %d entries, want 9 (tenant/team/user × read/write/execute)", len(componentDenyScopes))
	}
	for relation, scope := range componentDenyScopes {
		prefix, _, _ := strings.Cut(relation, "_")
		if scope.fgaType != prefix {
			t.Errorf("relation %q has fgaType %q, want %q (subject type must match the relation scope)", relation, scope.fgaType, prefix)
		}
		if !strings.HasSuffix(relation, "_disabled") {
			t.Errorf("relation %q is not a *_disabled deny relation", relation)
		}
	}
}
