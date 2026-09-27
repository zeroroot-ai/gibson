// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package admin

// tenant_admin_ownership_test.go covers the Owner-rules fix (hosted#190,
// ADR-0093 §5):
//
//   - Only the tenant's current Owner may call TransferOwnership; an Admin is
//     refused.
//   - The transfer target must be an existing tenant user.
//   - The transfer (delete old owner, write new owner, write old owner as
//     admin) is a single atomic FGA write: a failure leaves the tenant with
//     exactly one Owner, the original one, unchanged.
//   - After a successful transfer the previous Owner holds admin.
//   - SetTenantRole refuses role "owner" in both directions, and refuses to
//     touch a user_id that already holds the tenant's owner relation, so the
//     Owner can never be demoted or removed through SetTenantRole.

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// ownershipAuthorizer: a small in-memory FGA model faithful enough to prove
// atomicity and the owner/admin/writer/member hierarchy declared in
// model.fga (owner ⊆ admin ⊆ writer ⊆ member, each an "or" computed union
// over the one below).
// ---------------------------------------------------------------------------

// ownershipTenant is the direct (stored) tuple state for one tenant object.
// isX methods answer the EFFECTIVE (derived) question Check asks; the raw
// maps answer the STORED question ReadTuples asks — the same split the real
// fgaAuthorizer/TupleReader draw, and the one TransferOwnership's admin-write
// idempotency depends on.
type ownershipTenant struct {
	owner  string
	admin  map[string]bool
	writer map[string]bool
	member map[string]bool
}

func newOwnershipTenant(owner string) *ownershipTenant {
	return &ownershipTenant{owner: owner, admin: map[string]bool{}, writer: map[string]bool{}, member: map[string]bool{}}
}

func (ft *ownershipTenant) isOwner(u string) bool  { return ft.owner == u }
func (ft *ownershipTenant) isAdmin(u string) bool  { return ft.isOwner(u) || ft.admin[u] }
func (ft *ownershipTenant) isWriter(u string) bool { return ft.isAdmin(u) || ft.writer[u] }
func (ft *ownershipTenant) isMember(u string) bool { return ft.isWriter(u) || ft.member[u] }

// direct reports whether (user, relation) is a STORED tuple on ft — never
// derived through the hierarchy. Mirrors what OpenFGA's Read API would answer.
func (ft *ownershipTenant) direct(user, relation string) bool {
	switch relation {
	case "owner":
		return ft.owner == user
	case "admin":
		return ft.admin[user]
	case "writer":
		return ft.writer[user]
	case "member":
		return ft.member[user]
	default:
		return false
	}
}

func (ft *ownershipTenant) write(user, relation string) {
	switch relation {
	case "owner":
		ft.owner = user
	case "admin":
		ft.admin[user] = true
	case "writer":
		ft.writer[user] = true
	case "member":
		ft.member[user] = true
	}
}

func (ft *ownershipTenant) delete(user, relation string) {
	switch relation {
	case "owner":
		if ft.owner == user {
			ft.owner = ""
		}
	case "admin":
		delete(ft.admin, user)
	case "writer":
		delete(ft.writer, user)
	case "member":
		delete(ft.member, user)
	}
}

// ownershipAuthorizer implements authz.Authorizer, authz.AtomicWriter, and
// authz.TupleReader over an in-memory set of ownershipTenant objects, keyed
// by the FGA tenant object ref (e.g. "tenant:acme").
type ownershipAuthorizer struct {
	tenants map[string]*ownershipTenant

	// writeAndDeleteErr, when set, is returned by WriteAndDelete WITHOUT
	// applying anything — modelling an OpenFGA transaction that fails and
	// leaves the store exactly as it was.
	writeAndDeleteErr error

	writeAndDeleteCalls int
	lastWrites          []authz.Tuple
	lastDeletes         []authz.Tuple

	// checkErr, keyed by relation, is returned by Check for that relation
	// instead of a decision — models FGA being unreachable mid-request.
	checkErr map[string]error

	// readTuplesErr, when set, is returned by ReadTuples.
	readTuplesErr error
}

func newOwnershipAuthorizer() *ownershipAuthorizer {
	return &ownershipAuthorizer{tenants: map[string]*ownershipTenant{}}
}

func (a *ownershipAuthorizer) tenant(object string) *ownershipTenant {
	ft, ok := a.tenants[object]
	if !ok {
		ft = newOwnershipTenant("")
		a.tenants[object] = ft
	}
	return ft
}

func (a *ownershipAuthorizer) Check(_ context.Context, user, relation, object string) (bool, error) {
	if err := a.checkErr[relation]; err != nil {
		return false, err
	}
	ft, ok := a.tenants[object]
	if !ok {
		return false, nil
	}
	switch relation {
	case "owner":
		return ft.isOwner(user), nil
	case "admin":
		return ft.isAdmin(user), nil
	case "writer":
		return ft.isWriter(user), nil
	case "member":
		return ft.isMember(user), nil
	default:
		return false, nil
	}
}

func (a *ownershipAuthorizer) BatchCheck(ctx context.Context, checks []authz.CheckRequest) ([]bool, error) {
	out := make([]bool, len(checks))
	for i, c := range checks {
		v, err := a.Check(ctx, c.User, c.Relation, c.Object)
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}

func (a *ownershipAuthorizer) Write(_ context.Context, tuples []authz.Tuple) error {
	for _, t := range tuples {
		a.tenant(t.Object).write(t.User, t.Relation)
	}
	return nil
}

func (a *ownershipAuthorizer) Delete(_ context.Context, tuples []authz.Tuple) error {
	for _, t := range tuples {
		a.tenant(t.Object).delete(t.User, t.Relation)
	}
	return nil
}

func (a *ownershipAuthorizer) ListObjects(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}

func (a *ownershipAuthorizer) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}

func (a *ownershipAuthorizer) ListUsersOfType(context.Context, string, string, string, string) ([]string, error) {
	return nil, errListUsersOfTypeNotStubbed
}

func (a *ownershipAuthorizer) StoreID() string { return "test" }
func (a *ownershipAuthorizer) ModelID() string { return "test" }
func (a *ownershipAuthorizer) Close() error    { return nil }

// ReadTuples implements authz.TupleReader: it answers the STORED question,
// never derived through owner/admin/writer/member. An empty user or relation
// is a wildcard on that field (matching OpenFGA's Read semantics, and
// exercised by tenantrole.Syncer.Sync, which reads every direct role tuple
// on an object with both fields empty).
func (a *ownershipAuthorizer) ReadTuples(_ context.Context, user, relation, object string) ([]authz.Tuple, error) {
	if a.readTuplesErr != nil {
		return nil, a.readTuplesErr
	}
	ft, ok := a.tenants[object]
	if !ok {
		return nil, nil
	}
	var out []authz.Tuple
	add := func(u, rel string) {
		if user != "" && user != u {
			return
		}
		if relation != "" && relation != rel {
			return
		}
		out = append(out, authz.Tuple{User: u, Relation: rel, Object: object})
	}
	if ft.owner != "" {
		add(ft.owner, "owner")
	}
	for u := range ft.admin {
		add(u, "admin")
	}
	for u := range ft.writer {
		add(u, "writer")
	}
	for u := range ft.member {
		add(u, "member")
	}
	return out, nil
}

// WriteAndDelete implements authz.AtomicWriter. It models OpenFGA's real
// transactional behaviour on two points that this test suite relies on:
//
//  1. All-or-nothing: on writeAndDeleteErr, NOTHING is applied.
//  2. A write naming a tuple that is already directly stored is rejected —
//     exactly OpenFGA's "cannot write a tuple which already exists" — and
//     that rejection aborts the WHOLE call, including any deletes in the
//     same request. This is what proves TransferOwnership's admin-write
//     idempotency check (via TupleReader) is load-bearing, not decorative.
func (a *ownershipAuthorizer) WriteAndDelete(_ context.Context, writes, deletes []authz.Tuple) error {
	a.writeAndDeleteCalls++
	a.lastWrites = append([]authz.Tuple(nil), writes...)
	a.lastDeletes = append([]authz.Tuple(nil), deletes...)

	if a.writeAndDeleteErr != nil {
		return a.writeAndDeleteErr
	}
	for _, t := range writes {
		if a.tenant(t.Object).direct(t.User, t.Relation) {
			return fmt.Errorf("already exists: cannot write a tuple which already exists: %s#%s@%s", t.Object, t.Relation, t.User)
		}
	}
	for _, t := range deletes {
		a.tenant(t.Object).delete(t.User, t.Relation)
	}
	for _, t := range writes {
		a.tenant(t.Object).write(t.User, t.Relation)
	}
	return nil
}

// ---------------------------------------------------------------------------
// TransferOwnership
// ---------------------------------------------------------------------------

const (
	ownTenant   = "acme"
	ownTenantID = "tenant:" + ownTenant
	ownCaller   = "user:user-1" // Subject baked into ctxWithTenant
)

func newOwnershipTestServer(t *testing.T, az *ownershipAuthorizer) *TenantAdminServer {
	t.Helper()
	srv := newMembersTestServer(t, &membersAuthorizer{}, nil).withAuthorizer(az)
	tuples, err := tenantrole.AuthzTuples(az)
	if err != nil {
		t.Fatalf("AuthzTuples: %v", err)
	}
	srv.roles = tenantrole.NewSyncer(newFakeGrants(), tuples, nil)
	srv.orgResolver = staticOrgResolver{orgID: "org-1"}
	return srv
}

// withAuthorizer swaps in az and returns srv, for a fluent one-liner in each
// test's setup.
func (s *TenantAdminServer) withAuthorizer(az authz.Authorizer) *TenantAdminServer {
	s.authorizer = az
	return s
}

// TestTransferOwnership_NoIdentityInContext covers the fail-closed identity
// check (gibsoncheck's privileged-fallback analyzer, G3): a context that
// carries no Identity at all must be refused explicitly, never fall through
// with a zero-value subject. TransferOwnership checks identity before tenant
// scoping (same order as GrantComponentPermissions) specifically so this
// branch is reachable: auth.TenantFromContext derives the tenant from the
// SAME Identity, so an identity-less context also has no tenant, and
// checking identity first is what makes IT the branch that fires.
func TestTransferOwnership_NoIdentityInContext(t *testing.T) {
	az := newOwnershipAuthorizer()
	srv := newOwnershipTestServer(t, az)

	_, err := srv.TransferOwnership(context.Background(), &tenantv1.TransferOwnershipRequest{
		NewOwnerUserId: "bob-id",
	})
	if got := grpcCodeOf(err); got != codes.PermissionDenied {
		t.Fatalf("TransferOwnership code = %v (err=%v), want PermissionDenied", got, err)
	}
	if az.writeAndDeleteCalls != 0 {
		t.Errorf("must not reach FGA with no identity in context; writeAndDeleteCalls = %d", az.writeAndDeleteCalls)
	}
}

func TestTransferOwnership_OnlyOwnerMayCall(t *testing.T) {
	az := newOwnershipAuthorizer()
	ft := newOwnershipTenant("user:owner-x")
	ft.admin[ownCaller] = true // the caller is an Admin, not the Owner
	ft.member["user:bob-id"] = true
	az.tenants[ownTenantID] = ft
	srv := newOwnershipTestServer(t, az)

	ctx := ctxWithTenant(t, ownTenant)
	_, err := srv.TransferOwnership(ctx, &tenantv1.TransferOwnershipRequest{
		NewOwnerUserId: "bob-id",
	})
	if got := grpcCodeOf(err); got != codes.PermissionDenied {
		t.Fatalf("TransferOwnership code = %v (err=%v), want PermissionDenied", got, err)
	}
	if az.writeAndDeleteCalls != 0 {
		t.Errorf("an Admin's call must never reach FGA; writeAndDeleteCalls = %d", az.writeAndDeleteCalls)
	}
	if !ft.isOwner("user:owner-x") {
		t.Error("the original Owner must be unchanged")
	}
}

func TestTransferOwnership_TargetMustBeExistingTenantUser(t *testing.T) {
	az := newOwnershipAuthorizer()
	az.tenants[ownTenantID] = newOwnershipTenant(ownCaller) // caller is Owner
	srv := newOwnershipTestServer(t, az)

	ctx := ctxWithTenant(t, ownTenant)
	_, err := srv.TransferOwnership(ctx, &tenantv1.TransferOwnershipRequest{
		NewOwnerUserId: "stranger-id", // holds no relation on the tenant
	})
	if got := grpcCodeOf(err); got != codes.InvalidArgument {
		t.Fatalf("TransferOwnership code = %v (err=%v), want InvalidArgument", got, err)
	}
	if az.writeAndDeleteCalls != 0 {
		t.Errorf("a call to a non-member target must never reach FGA; writeAndDeleteCalls = %d", az.writeAndDeleteCalls)
	}
}

func TestTransferOwnership_SucceedsAndPreviousOwnerBecomesAdmin(t *testing.T) {
	az := newOwnershipAuthorizer()
	ft := newOwnershipTenant(ownCaller)
	ft.member["user:bob-id"] = true
	az.tenants[ownTenantID] = ft
	srv := newOwnershipTestServer(t, az)

	ctx := ctxWithTenant(t, ownTenant)
	if _, err := srv.TransferOwnership(ctx, &tenantv1.TransferOwnershipRequest{
		NewOwnerUserId: "bob-id",
	}); err != nil {
		t.Fatalf("TransferOwnership: %v", err)
	}

	if az.writeAndDeleteCalls != 1 {
		t.Fatalf("expected exactly 1 atomic write, got %d", az.writeAndDeleteCalls)
	}
	if !ft.isOwner("user:bob-id") {
		t.Error("new owner must hold the owner relation")
	}
	if ft.isOwner(ownCaller) {
		t.Error("previous owner must no longer hold the owner relation")
	}
	if !ft.isAdmin(ownCaller) {
		t.Error("previous owner must hold admin after the transfer")
	}
}

func TestTransferOwnership_SelfTransferIsNoOpButStillRequiresOwner(t *testing.T) {
	az := newOwnershipAuthorizer()
	az.tenants[ownTenantID] = newOwnershipTenant(ownCaller)
	srv := newOwnershipTestServer(t, az)

	ctx := ctxWithTenant(t, ownTenant)
	if _, err := srv.TransferOwnership(ctx, &tenantv1.TransferOwnershipRequest{
		NewOwnerUserId: "user-1", // caller's own id
	}); err != nil {
		t.Fatalf("TransferOwnership (self): %v", err)
	}
	if az.writeAndDeleteCalls != 0 {
		t.Errorf("transferring to oneself must be a no-op; writeAndDeleteCalls = %d", az.writeAndDeleteCalls)
	}
}

// TestTransferOwnership_AtomicFailureLeavesExactlyOneOwner is the injected-
// failure acceptance test: WriteAndDelete fails, and the tenant must still
// have exactly one Owner — the original one — never zero, never two.
func TestTransferOwnership_AtomicFailureLeavesExactlyOneOwner(t *testing.T) {
	az := newOwnershipAuthorizer()
	ft := newOwnershipTenant(ownCaller)
	ft.member["user:bob-id"] = true
	az.tenants[ownTenantID] = ft
	az.writeAndDeleteErr = errors.New("fga: unavailable")
	srv := newOwnershipTestServer(t, az)

	ctx := ctxWithTenant(t, ownTenant)
	_, err := srv.TransferOwnership(ctx, &tenantv1.TransferOwnershipRequest{
		NewOwnerUserId: "bob-id",
	})
	if got := grpcCodeOf(err); got != codes.Internal {
		t.Fatalf("TransferOwnership code = %v (err=%v), want Internal", got, err)
	}
	if az.writeAndDeleteCalls != 1 {
		t.Fatalf("expected exactly 1 attempted atomic write, got %d", az.writeAndDeleteCalls)
	}

	owners := 0
	if ft.isOwner(ownCaller) {
		owners++
	}
	if ft.isOwner("user:bob-id") {
		owners++
	}
	if owners != 1 {
		t.Fatalf("tenant must have exactly one Owner after a failed transfer, got %d", owners)
	}
	if !ft.isOwner(ownCaller) {
		t.Error("the ORIGINAL Owner must be the one still holding ownership")
	}
	if ft.admin[ownCaller] {
		t.Error("the failed transfer must not have written a direct admin tuple for the original Owner")
	}
}

// TestTransferOwnership_PreviousOwnerWithExistingDirectAdmin_NoDuplicateWrite
// covers a real FGA edge case: a user promoted to Owner while already
// holding a DIRECT admin tuple (granted before they became Owner) keeps that
// tuple. A naive re-grant of "admin" on transfer would collide with it and
// OpenFGA would reject the whole write (see ownershipAuthorizer.WriteAndDelete),
// aborting the owner move too. The handler must skip the redundant write.
//
// This needs the previous owner's existing tuple to actually be visible to
// Sync's drift comparison, which since D2 (corrected) only recognizes a
// `user:`-typed subject whose id is a real-shaped Zitadel numeric id — so
// this test uses its own numeric caller identity rather than the package's
// shared ownCaller ("user:user-1", chosen for readability everywhere else
// in this file, none of which touches Sync's read-back path the way
// TransferOwnership does).
func TestTransferOwnership_PreviousOwnerWithExistingDirectAdmin_NoDuplicateWrite(t *testing.T) {
	const numericCaller = "user:100000000000000001"
	az := newOwnershipAuthorizer()
	ft := newOwnershipTenant(numericCaller)
	ft.admin[numericCaller] = true // pre-existing DIRECT admin tuple
	ft.member["user:bob-id"] = true
	az.tenants[ownTenantID] = ft
	srv := newOwnershipTestServer(t, az)

	tid, err := auth.NewTenantID(ownTenant)
	if err != nil {
		t.Fatalf("NewTenantID: %v", err)
	}
	ctx := auth.WithIdentity(context.Background(), auth.Identity{Tenant: tid, Subject: "100000000000000001"})
	if _, err := srv.TransferOwnership(ctx, &tenantv1.TransferOwnershipRequest{
		NewOwnerUserId: "bob-id",
	}); err != nil {
		t.Fatalf("TransferOwnership: %v", err)
	}
	if !ft.isOwner("user:bob-id") {
		t.Error("new owner must hold the owner relation")
	}
	if !ft.isAdmin(numericCaller) {
		t.Error("previous owner must still hold admin")
	}
	for _, w := range az.lastWrites {
		if w.User == numericCaller && w.Relation == "admin" {
			t.Error("must not re-write an admin tuple the previous owner already directly holds")
		}
	}
}

// ---------------------------------------------------------------------------
// SetTenantRole Owner rules
// ---------------------------------------------------------------------------

func TestSetTenantRole_RefusesOwnerRole(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(fmt.Sprintf("remove=%v", remove), func(t *testing.T) {
			az := newOwnershipAuthorizer()
			az.tenants[ownTenantID] = newOwnershipTenant("user:someone-else")
			srv := newOwnershipTestServer(t, az)

			ctx := ctxWithTenant(t, ownTenant)
			_, err := srv.SetTenantRole(ctx, &tenantv1.SetTenantRoleRequest{
				UserId: "target-id",
				Role:   "owner",
				Remove: remove,
			})
			if got := grpcCodeOf(err); got != codes.InvalidArgument {
				t.Fatalf("SetTenantRole code = %v (err=%v), want InvalidArgument", got, err)
			}
			if az.tenants[ownTenantID].isOwner("user:target-id") {
				t.Error("role \"owner\" must never be grantable via SetTenantRole")
			}
		})
	}
}

func TestSetTenantRole_RefusesTouchingCurrentOwner(t *testing.T) {
	for _, tc := range []struct {
		name   string
		role   string
		remove bool
	}{
		{"grant admin to the Owner", "admin", false},
		{"remove admin from the Owner", "admin", true},
		{"remove member from the Owner", "member", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			az := newOwnershipAuthorizer()
			az.tenants[ownTenantID] = newOwnershipTenant("user:owner-x")
			srv := newOwnershipTestServer(t, az)

			ctx := ctxWithTenant(t, ownTenant)
			_, err := srv.SetTenantRole(ctx, &tenantv1.SetTenantRoleRequest{
				UserId: "owner-x",
				Role:   tc.role,
				Remove: tc.remove,
			})
			if got := grpcCodeOf(err); got != codes.PermissionDenied {
				t.Fatalf("SetTenantRole code = %v (err=%v), want PermissionDenied", got, err)
			}
			if !az.tenants[ownTenantID].isOwner("user:owner-x") {
				t.Error("the Owner must be unaffected by a refused SetTenantRole call")
			}
		})
	}
}

// TestSetTenantRole_NonOwnerTargetStillWorks pins that the new Owner-rule
// checks do not regress the ordinary path: an Admin assigning a role to a
// user who is not the Owner still succeeds.
func TestSetTenantRole_NonOwnerTargetStillWorks(t *testing.T) {
	az := newOwnershipAuthorizer()
	az.tenants[ownTenantID] = newOwnershipTenant("user:owner-x")
	srv := newOwnershipTestServer(t, az)

	ctx := ctxWithTenant(t, ownTenant)
	if _, err := srv.SetTenantRole(ctx, &tenantv1.SetTenantRoleRequest{
		UserId: "carol-id",
		Role:   "writer",
	}); err != nil {
		t.Fatalf("SetTenantRole: %v", err)
	}
	if !az.tenants[ownTenantID].isWriter("user:carol-id") {
		t.Error("expected carol-id to hold writer")
	}
}

// TestSetTenantRole_OwnerCheckErrorIsInternal covers the FGA-unavailable
// branch of the new Owner-check: an error from Check must surface as
// Internal, never be swallowed into either an allow or a plain deny.
func TestSetTenantRole_OwnerCheckErrorIsInternal(t *testing.T) {
	az := newOwnershipAuthorizer()
	az.tenants[ownTenantID] = newOwnershipTenant("user:owner-x")
	az.checkErr = map[string]error{"owner": errors.New("fga: unavailable")}
	srv := newOwnershipTestServer(t, az)

	ctx := ctxWithTenant(t, ownTenant)
	_, err := srv.SetTenantRole(ctx, &tenantv1.SetTenantRoleRequest{
		UserId: "carol-id",
		Role:   "writer",
	})
	if got := grpcCodeOf(err); got != codes.Internal {
		t.Fatalf("SetTenantRole code = %v (err=%v), want Internal", got, err)
	}
}

// ---------------------------------------------------------------------------
// TransferOwnership: FGA-unavailable and unsupported-authorizer branches
// ---------------------------------------------------------------------------

func TestTransferOwnership_OwnerCheckErrorIsInternal(t *testing.T) {
	az := newOwnershipAuthorizer()
	az.tenants[ownTenantID] = newOwnershipTenant(ownCaller)
	az.checkErr = map[string]error{"owner": errors.New("fga: unavailable")}
	srv := newOwnershipTestServer(t, az)

	ctx := ctxWithTenant(t, ownTenant)
	_, err := srv.TransferOwnership(ctx, &tenantv1.TransferOwnershipRequest{
		NewOwnerUserId: "bob-id",
	})
	if got := grpcCodeOf(err); got != codes.Internal {
		t.Fatalf("TransferOwnership code = %v (err=%v), want Internal", got, err)
	}
	if az.writeAndDeleteCalls != 0 {
		t.Errorf("must not reach FGA when the owner Check itself errors; writeAndDeleteCalls = %d", az.writeAndDeleteCalls)
	}
}

func TestTransferOwnership_MemberCheckErrorIsInternal(t *testing.T) {
	az := newOwnershipAuthorizer()
	ft := newOwnershipTenant(ownCaller)
	ft.member["user:bob-id"] = true
	az.tenants[ownTenantID] = ft
	az.checkErr = map[string]error{"member": errors.New("fga: unavailable")}
	srv := newOwnershipTestServer(t, az)

	ctx := ctxWithTenant(t, ownTenant)
	_, err := srv.TransferOwnership(ctx, &tenantv1.TransferOwnershipRequest{
		NewOwnerUserId: "bob-id",
	})
	if got := grpcCodeOf(err); got != codes.Internal {
		t.Fatalf("TransferOwnership code = %v (err=%v), want Internal", got, err)
	}
	if az.writeAndDeleteCalls != 0 {
		t.Errorf("must not reach FGA when the member Check itself errors; writeAndDeleteCalls = %d", az.writeAndDeleteCalls)
	}
}

func TestTransferOwnership_ReadTuplesErrorIsInternal(t *testing.T) {
	az := newOwnershipAuthorizer()
	ft := newOwnershipTenant(ownCaller)
	ft.member["user:bob-id"] = true
	az.tenants[ownTenantID] = ft
	az.readTuplesErr = errors.New("fga: unavailable")
	srv := newOwnershipTestServer(t, az)

	ctx := ctxWithTenant(t, ownTenant)
	_, err := srv.TransferOwnership(ctx, &tenantv1.TransferOwnershipRequest{
		NewOwnerUserId: "bob-id",
	})
	if got := grpcCodeOf(err); got != codes.Internal {
		t.Fatalf("TransferOwnership code = %v (err=%v), want Internal", got, err)
	}
	if az.writeAndDeleteCalls != 0 {
		t.Errorf("must not reach the atomic write when ReadTuples errors; writeAndDeleteCalls = %d", az.writeAndDeleteCalls)
	}
}

// TestAuthzTuples_RefusesAnAuthorizerWithoutAtomicWriter covers the
// defensive check that used to live inside TransferOwnership's type
// assertion and now lives at Syncer-construction time: an Authorizer that
// cannot make the all-or-nothing guarantee must never be wrapped into a
// Syncer, so the daemon refuses to start rather than falling back to a
// non-atomic delete-then-write (the exact bug hosted#190 removed).
// authorizerWithoutTupleSupport implements exactly authz.Authorizer — no
// TupleReader, no AtomicWriter — for the one test that needs an authorizer
// AuthzTuples must refuse. Every other test double in this package also
// implements TupleReader/AtomicWriter so it can be wired into a Syncer.
type authorizerWithoutTupleSupport struct{}

func (a *authorizerWithoutTupleSupport) Check(context.Context, string, string, string) (bool, error) {
	return false, nil
}
func (a *authorizerWithoutTupleSupport) BatchCheck(context.Context, []authz.CheckRequest) ([]bool, error) {
	return nil, nil
}
func (a *authorizerWithoutTupleSupport) Write(context.Context, []authz.Tuple) error  { return nil }
func (a *authorizerWithoutTupleSupport) Delete(context.Context, []authz.Tuple) error { return nil }
func (a *authorizerWithoutTupleSupport) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}
func (a *authorizerWithoutTupleSupport) ListUsers(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}
func (a *authorizerWithoutTupleSupport) ListUsersOfType(context.Context, string, string, string, string) ([]string, error) {
	return nil, errListUsersOfTypeNotStubbed
}
func (a *authorizerWithoutTupleSupport) StoreID() string { return "test" }
func (a *authorizerWithoutTupleSupport) ModelID() string { return "test" }
func (a *authorizerWithoutTupleSupport) Close() error    { return nil }

func TestAuthzTuples_RefusesAnAuthorizerWithoutAtomicWriter(t *testing.T) {
	if _, err := tenantrole.AuthzTuples(&authorizerWithoutTupleSupport{}); err == nil {
		t.Fatal("AuthzTuples: expected an error for an authorizer without AtomicWriter/TupleReader")
	}
}

// TestTransferOwnership_UnavailableWithoutRoles covers the RPC-level half of
// the same story: a TenantAdminServer built without a Roles Syncer (as it
// would be if AuthzTuples had refused the authorizer at startup) answers
// Unavailable, never falls back to a direct FGA write.
func TestTransferOwnership_UnavailableWithoutRoles(t *testing.T) {
	az := &tenantScopeAuthorizer{checkResult: true}
	srv := newMembersTestServer(t, &membersAuthorizer{}, nil)
	srv.authorizer = az

	ctx := ctxWithTenant(t, ownTenant)
	_, err := srv.TransferOwnership(ctx, &tenantv1.TransferOwnershipRequest{
		NewOwnerUserId: "bob-id",
	})
	if got := grpcCodeOf(err); got != codes.Unavailable {
		t.Fatalf("TransferOwnership code = %v (err=%v), want Unavailable", got, err)
	}
	if len(az.wrote) != 0 || len(az.deleted) != 0 {
		t.Errorf("must not fall back to non-atomic Write/Delete: wrote=%+v deleted=%+v", az.wrote, az.deleted)
	}
}

// ---------------------------------------------------------------------------
// SetTenantRole / tenantOf / TransferOwnership: the collaborator-error and
// unavailable-dependency branches the happy-path tests above do not reach.
// ---------------------------------------------------------------------------

// newOwnershipTestServerWithGrants is newOwnershipTestServer, but also
// returns the fakeGrants double so a test can inject a Zitadel-side error.
func newOwnershipTestServerWithGrants(t *testing.T, az *ownershipAuthorizer) (*TenantAdminServer, *fakeGrants) {
	t.Helper()
	srv := newMembersTestServer(t, &membersAuthorizer{}, nil).withAuthorizer(az)
	tuples, err := tenantrole.AuthzTuples(az)
	if err != nil {
		t.Fatalf("AuthzTuples: %v", err)
	}
	grants := newFakeGrants()
	srv.roles = tenantrole.NewSyncer(grants, tuples, nil)
	srv.orgResolver = staticOrgResolver{orgID: "org-1"}
	return srv, grants
}

func TestSetTenantRole_UnavailableWithoutRoles(t *testing.T) {
	az := newOwnershipAuthorizer()
	az.tenants[ownTenantID] = newOwnershipTenant("user:owner-x")
	srv := newMembersTestServer(t, &membersAuthorizer{}, nil).withAuthorizer(az)
	srv.orgResolver = staticOrgResolver{orgID: "org-1"}
	// srv.roles left nil.

	ctx := ctxWithTenant(t, ownTenant)
	_, err := srv.SetTenantRole(ctx, &tenantv1.SetTenantRoleRequest{UserId: "carol-id", Role: "writer"})
	if got := grpcCodeOf(err); got != codes.Unavailable {
		t.Fatalf("SetTenantRole code = %v (err=%v), want Unavailable", got, err)
	}
}

func TestSetTenantRole_TenantOfErrorPropagates(t *testing.T) {
	az := newOwnershipAuthorizer()
	az.tenants[ownTenantID] = newOwnershipTenant("user:owner-x")
	srv, _ := newOwnershipTestServerWithGrants(t, az)
	srv.orgResolver = staticOrgResolver{err: errors.New("resolver boom")}

	ctx := ctxWithTenant(t, ownTenant)
	_, err := srv.SetTenantRole(ctx, &tenantv1.SetTenantRoleRequest{UserId: "carol-id", Role: "writer"})
	if got := grpcCodeOf(err); got != codes.Internal {
		t.Fatalf("SetTenantRole code = %v (err=%v), want Internal (tenantOf's error passed through)", got, err)
	}
}

func TestSetTenantRole_RevokeErrorIsInternal(t *testing.T) {
	az := newOwnershipAuthorizer()
	az.tenants[ownTenantID] = newOwnershipTenant("user:owner-x")
	srv, grants := newOwnershipTestServerWithGrants(t, az)
	grants.listErr = errors.New("list boom")

	ctx := ctxWithTenant(t, ownTenant)
	_, err := srv.SetTenantRole(ctx, &tenantv1.SetTenantRoleRequest{UserId: "carol-id", Role: "writer", Remove: true})
	if got := grpcCodeOf(err); got != codes.Internal {
		t.Fatalf("SetTenantRole(remove) code = %v (err=%v), want Internal", got, err)
	}
}

func TestSetTenantRole_AssignErrorIsInternal(t *testing.T) {
	az := newOwnershipAuthorizer()
	az.tenants[ownTenantID] = newOwnershipTenant("user:owner-x")
	srv, grants := newOwnershipTestServerWithGrants(t, az)
	grants.createErr = errors.New("create boom")

	ctx := ctxWithTenant(t, ownTenant)
	_, err := srv.SetTenantRole(ctx, &tenantv1.SetTenantRoleRequest{UserId: "carol-id", Role: "writer"})
	if got := grpcCodeOf(err); got != codes.Internal {
		t.Fatalf("SetTenantRole code = %v (err=%v), want Internal", got, err)
	}
}

func TestTenantOf_NoOrgResolverConfigured(t *testing.T) {
	az := newOwnershipAuthorizer()
	az.tenants[ownTenantID] = newOwnershipTenant("user:owner-x")
	srv, _ := newOwnershipTestServerWithGrants(t, az)
	srv.orgResolver = nil

	if _, err := srv.tenantOf(context.Background(), ownTenant); grpcCodeOf(err) != codes.Unavailable {
		t.Fatalf("tenantOf with no resolver: code = %v (err=%v), want Unavailable", grpcCodeOf(err), err)
	}
}

func TestTenantOf_ResolverErrorIsInternal(t *testing.T) {
	az := newOwnershipAuthorizer()
	az.tenants[ownTenantID] = newOwnershipTenant("user:owner-x")
	srv, _ := newOwnershipTestServerWithGrants(t, az)
	srv.orgResolver = staticOrgResolver{err: errors.New("resolver boom")}

	if _, err := srv.tenantOf(context.Background(), ownTenant); grpcCodeOf(err) != codes.Internal {
		t.Fatalf("tenantOf with a resolver error: code = %v (err=%v), want Internal", grpcCodeOf(err), err)
	}
}

func TestTenantOf_EmptyOrgIDIsFailedPrecondition(t *testing.T) {
	az := newOwnershipAuthorizer()
	az.tenants[ownTenantID] = newOwnershipTenant("user:owner-x")
	srv, _ := newOwnershipTestServerWithGrants(t, az)
	srv.orgResolver = staticOrgResolver{orgID: ""}

	if _, err := srv.tenantOf(context.Background(), ownTenant); grpcCodeOf(err) != codes.FailedPrecondition {
		t.Fatalf("tenantOf with no org yet: code = %v (err=%v), want FailedPrecondition", grpcCodeOf(err), err)
	}
}

func TestTransferOwnership_TenantOfErrorPropagates(t *testing.T) {
	az := newOwnershipAuthorizer()
	ft := newOwnershipTenant(ownCaller)
	ft.member["user:bob-id"] = true
	az.tenants[ownTenantID] = ft
	srv, _ := newOwnershipTestServerWithGrants(t, az)
	srv.orgResolver = staticOrgResolver{err: errors.New("resolver boom")}

	ctx := ctxWithTenant(t, ownTenant)
	_, err := srv.TransferOwnership(ctx, &tenantv1.TransferOwnershipRequest{NewOwnerUserId: "bob-id"})
	if got := grpcCodeOf(err); got != codes.Internal {
		t.Fatalf("TransferOwnership code = %v (err=%v), want Internal (tenantOf's error passed through)", got, err)
	}
}
