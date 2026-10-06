// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package admin — tenant_admin_component_ops.go
//
// TenantAdminServer component-access, role, ownership, and grant handlers
// implementing the RPC surface added by platform-sdk issues #397 and #398.
//
// SetComponentAccess (admin on tenant):
//
//	Reconciles the set of (relation, team_id, disabled) access-control entries
//	for a single component object. Reads the existing tuples, deletes the
//	superseded ones, and writes the new ones atomically.
//
// SetTenantRole (admin on tenant):
//
//	Writes or removes a role (admin / member / writer) tuple for a user on the
//	caller's tenant. Never "owner" — see TransferOwnership (hosted#190).
//
// TransferOwnership (owner on tenant):
//
//	Atomically moves the owner relation from the caller to the new owner and
//	grants the caller admin, in one FGA write. Only the current Owner may
//	call it (hosted#190, ADR-0093 §5).
//
// Spec: tenant-service-admin-handlers issues #397 and #398.
package admin

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// SetCatalogEnabled (ADR-0041 remaining gap — catalog-enablement daemon route)
// ---------------------------------------------------------------------------

// SetCatalogEnabled writes or deletes the FGA tenant_enabled tuple for a
// (tenant, component) pair, making the component appear in (or disappear
// from) the tenant's catalog. This is the daemon-side replacement for the
// dashboard's previous direct ComponentGrant CRD write.
//
// When enabled is true the tuple is written (idempotent if already present).
// When enabled is false the tuple is deleted (idempotent if already absent).
//
// ADR-0041: catalog-enablement write routed through the daemon so the
// dashboard can delete its direct K8s client; the ComponentGrant reconciler
// in tenant-operator is superseded for new grants and can be retired once
// existing CRDs are cleaned up.
func (s *TenantAdminServer) SetCatalogEnabled(ctx context.Context, req *tenantv1.SetCatalogEnabledRequest) (*tenantv1.SetCatalogEnabledResponse, error) {
	if s.authorizer == nil {
		return nil, status.Error(codes.Unavailable, "authorizer not configured")
	}
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if req.GetComponentRef() == "" {
		return nil, status.Error(codes.InvalidArgument, "component_ref is required")
	}

	componentRef, err := componentObjectRef(req.GetComponentRef())
	if err != nil {
		return nil, err
	}

	tenantRef := "tenant:" + tenant.String()
	// The default posture a tenant gets when an admin enables a catalog
	// component (ADR-0067 §5, same as plugins and connectors): the item is in
	// the tenant catalog AND every member may read and execute it; the
	// per-scope deny toggles (SetComponentAccess) narrow from there. Writing
	// only tenant_enabled left a catalog agent visible but never executable:
	// can_execute needs direct_execute, and a catalog component has no owner
	// tenant to inherit it from.
	posture := catalogEnablePosture(tenantRef, componentRef)
	if req.GetEnabled() {
		var missing []authz.Tuple
		for _, t := range posture {
			present, err := s.authorizer.Check(ctx, t.User, t.Relation, t.Object)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "fga Check %s: %v", t.Relation, err)
			}
			if !present {
				missing = append(missing, t)
			}
		}
		if len(missing) == 0 {
			return &tenantv1.SetCatalogEnabledResponse{Written: false}, nil
		}
		if err := s.authorizer.Write(ctx, missing); err != nil {
			return nil, status.Errorf(codes.Internal, "fga Write catalog posture: %v", err)
		}
		return &tenantv1.SetCatalogEnabledResponse{Written: true}, nil
	}
	// Delete path: remove whatever part of the posture is present.
	var present []authz.Tuple
	for _, t := range posture {
		ok, err := s.authorizer.Check(ctx, t.User, t.Relation, t.Object)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "fga Check %s: %v", t.Relation, err)
		}
		if ok {
			present = append(present, t)
		}
	}
	if len(present) == 0 {
		return &tenantv1.SetCatalogEnabledResponse{Deleted: false}, nil
	}
	if err := s.authorizer.Delete(ctx, present); err != nil {
		return nil, status.Errorf(codes.Internal, "fga Delete catalog posture: %v", err)
	}
	return &tenantv1.SetCatalogEnabledResponse{Deleted: true}, nil
}

// catalogEnablePosture is the tuple set "enabled for this tenant" means:
// in the catalog, and readable and executable by every tenant member.
func catalogEnablePosture(tenantRef, componentRef string) []authz.Tuple {
	return []authz.Tuple{
		{User: tenantRef, Relation: "tenant_enabled", Object: componentRef},
		{User: tenantRef + "#member", Relation: "direct_read", Object: componentRef},
		{User: tenantRef + "#member", Relation: "direct_execute", Object: componentRef},
	}
}

// ---------------------------------------------------------------------------
// SetComponentAccess (#397)
// ---------------------------------------------------------------------------

// SetComponentAccess reconciles the access-control entries for a single
// component. Each ComponentAccessEntry carries a relation (e.g.
// "team_execute_disabled"), a team_id, and whether the entry is disabled.
//
// The implementation:
//  1. Lists all existing tuples for the component where the user is
//     "team:<team_id>" (team-scoped component tuples).
//  2. Deletes tuples not in the incoming set.
//  3. Writes tuples in the incoming set that are not already present.
//
// Relations supported here follow the FGA model's team_*_disabled pattern used
// to selectively gate component access for specific teams.
func (s *TenantAdminServer) SetComponentAccess(ctx context.Context, req *tenantv1.SetComponentAccessRequest) (*tenantv1.SetComponentAccessResponse, error) {
	if s.authorizer == nil {
		return nil, status.Error(codes.Unavailable, "authorizer not configured")
	}
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if req.GetComponent() == "" {
		return nil, status.Error(codes.InvalidArgument, "component required")
	}
	callerTenant := tenant.String()
	callerTenantRef := tenantRefFromID(callerTenant)

	// Normalise to component:<kind>/<name>; a non-component or bare ref fails closed.
	componentRef, err := componentObjectRef(req.GetComponent())
	if err != nil {
		return nil, err
	}

	// Desired end-state: for each (relation, plain subject ref), should the deny
	// tuple be present. The subject TYPE is derived from the relation (never from
	// a caller field), so a tenant id can never be written onto a team-typed
	// relation (the gibson#1237 subject-confusion class).
	type entryKey struct{ relation, subject string }
	desired := make(map[entryKey]bool, len(req.GetEntries()))
	relations := make(map[string]struct{})

	for _, e := range req.GetEntries() {
		relation := e.GetRelation()
		subjectID := e.GetTeamId() // the subject id; the field name is legacy (holds the tenant/team/user id per scope)
		if relation == "" || subjectID == "" {
			return nil, status.Error(codes.InvalidArgument, "each entry requires relation and team_id")
		}
		scope, ok := componentDenyScopes[relation]
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument,
				"relation %q not allowed; must be a component deny relation "+
					"(tenant_/team_/user_ {read,write,execute}_disabled)", relation)
		}
		subjectRef, err := scope.subjectRef(callerTenant, subjectID)
		if err != nil {
			return nil, err
		}
		owned, err := scope.ownedByCaller(ctx, s, callerTenantRef, subjectRef)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "fga ownership check for %s: %v", subjectRef, err)
		}
		if !owned {
			return nil, status.Errorf(codes.PermissionDenied,
				"subject %q is not in the caller's tenant", subjectID)
		}
		// disabled=true means the restriction is ON: the deny tuple should be
		// PRESENT (proto contract). The old !GetDisabled() inverted this, so the
		// dashboard toggling access ON wrote the *_disabled kill switch instead of
		// clearing it (and nothing could clear it — see the delete loop below).
		desired[entryKey{relation, subjectRef}] = e.GetDisabled()
		relations[relation] = struct{}{}
	}

	// Reconcile each relation against the current tuples, but only over subjects
	// the caller owns (component objects are shared across tenants).
	var toWrite, toDelete []authz.Tuple
	for relation := range relations {
		scope := componentDenyScopes[relation]
		existing, err := s.authorizer.ListUsersOfType(ctx, "component", componentRef, relation, scope.fgaType)
		if err != nil {
			return nil, status.Errorf(codes.Internal,
				"fga ListUsersOfType(%s, %s) for %s: %v", relation, scope.fgaType, componentRef, err)
		}
		for _, listed := range existing {
			plain := scope.plain(listed)
			owned, err := scope.ownedByCaller(ctx, s, callerTenantRef, plain)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "fga ownership check for %s: %v", plain, err)
			}
			if !owned {
				continue // another tenant's tuple on the shared object — leave it
			}
			key := entryKey{relation, plain}
			// Delete an existing deny that is NOT wanted present: either the request
			// omitted this subject (full-replace) OR it asked for it to be off
			// (disabled=false). Keying on the VALUE, not mere presence, is what lets a
			// single-entry toggle actually clear a subject's own kill switch.
			if !desired[key] {
				toDelete = append(toDelete, authz.Tuple{User: scope.stored(plain), Relation: relation, Object: componentRef})
			}
			delete(desired, key)
		}
	}

	for key, active := range desired {
		if !active {
			continue // deny not wanted and not present — nothing to do
		}
		scope := componentDenyScopes[key.relation]
		toWrite = append(toWrite, authz.Tuple{User: scope.stored(key.subject), Relation: key.relation, Object: componentRef})
	}

	if len(toDelete) > 0 {
		if err := s.authorizer.Delete(ctx, toDelete); err != nil {
			return nil, status.Errorf(codes.Internal, "fga Delete component access: %v", err)
		}
	}
	if len(toWrite) > 0 {
		if err := s.authorizer.Write(ctx, toWrite); err != nil {
			return nil, status.Errorf(codes.Internal, "fga Write component access: %v", err)
		}
	}

	return &tenantv1.SetComponentAccessResponse{}, nil
}

// ---------------------------------------------------------------------------
// SetTenantRole (#397)
// ---------------------------------------------------------------------------

// componentDenyScope carries everything SetComponentAccess needs to handle one
// scope of component deny relation. The subject TYPE is fixed by the relation
// (tenant_*_disabled -> tenant, team_*_disabled -> team#member, user_*_disabled
// -> user), matching each relation's declared FGA subject type in model.fga, so
// the caller never chooses the subject type. TestComponentDenyScopes_MatchModel
// asserts fgaType agrees with the model.
type componentDenyScope struct {
	// fgaType is the ListUsersOfType filter (tenant_*_disabled does NOT admit
	// "user", so a plain ListUsers cannot enumerate it — ListUsersOfType must).
	fgaType string
	// subjectRef builds the plain (comparison-key) subject ref from the caller's
	// tenant and the entry's subject id.
	subjectRef func(callerTenant, id string) (string, error)
	// stored is the exact user written/deleted (a team subject adds "#member").
	stored func(plain string) string
	// plain normalises a ListUsersOfType result back to the comparison key.
	plain func(listed string) string
	// ownedByCaller reports whether the caller may set a deny for this subject.
	ownedByCaller func(ctx context.Context, s *TenantAdminServer, callerTenantRef, plain string) (bool, error)
}

// componentDenyScopes maps every component deny relation to its scope. It
// replaces the team-only allow-list: the presence of a relation here is what
// SetComponentAccess accepts (gibson#1237 fail-closed guard, generalised).
var componentDenyScopes = buildComponentDenyScopes()

func buildComponentDenyScopes() map[string]componentDenyScope {
	tenantScope := componentDenyScope{
		fgaType:    "tenant",
		subjectRef: func(_, id string) (string, error) { return tenantRefFromID(id), nil },
		stored:     func(p string) string { return p },
		plain:      func(l string) string { return l },
		// A tenant admin may only disable a component for their OWN tenant.
		ownedByCaller: func(_ context.Context, _ *TenantAdminServer, callerTenantRef, plain string) (bool, error) {
			return plain == callerTenantRef, nil
		},
	}
	teamScope := componentDenyScope{
		fgaType:    "team",
		subjectRef: teamRef,
		stored:     teamMemberUserset,
		plain:      teamObjectRef,
		ownedByCaller: func(ctx context.Context, s *TenantAdminServer, callerTenantRef, plain string) (bool, error) {
			return s.authorizer.Check(ctx, callerTenantRef, "parent", plain)
		},
	}
	userScope := componentDenyScope{
		fgaType:    "user",
		subjectRef: func(_, id string) (string, error) { return "user:" + id, nil },
		stored:     func(p string) string { return p },
		plain:      func(l string) string { return l },
		// The user must be a member of the caller's tenant (covers "my access",
		// where the caller is the subject and is a member of their own tenant).
		ownedByCaller: func(ctx context.Context, s *TenantAdminServer, callerTenantRef, plain string) (bool, error) {
			return s.authorizer.Check(ctx, plain, "member", callerTenantRef)
		},
	}
	m := make(map[string]componentDenyScope, 9)
	for _, action := range []string{"read", "write", "execute"} {
		m["tenant_"+action+"_disabled"] = tenantScope
		m["team_"+action+"_disabled"] = teamScope
		m["user_"+action+"_disabled"] = userScope
	}
	return m
}

// teamObjectRef strips the userset suffix, giving back the plain team object.
// FGA returns subjects as stored ("team:<id>#member") while the desired set is
// keyed by the team object, so both sides must normalise — otherwise nothing
// ever matches and the reconcile rewrites every tuple on every call.
func teamObjectRef(userRef string) string {
	return strings.TrimSuffix(userRef, "#member")
}

// teamMemberUserset is the subject shape the team_*_disabled relations declare.
//
// model.fga says `define team_write_disabled: [team#member]` — a userset, not a
// bare object. Writing "team:<id>" was rejected by FGA with the same
// validation_error class as the wrong relation type, so this RPC could not
// write any tuple at all.
func teamMemberUserset(teamRef string) string {
	if strings.HasSuffix(teamRef, "#member") {
		return teamRef
	}
	return teamRef + "#member"
}

// componentObjectPrefix is the only FGA object type SetComponentAccess may
// write to.
const componentObjectPrefix = "component:"

// componentObjectRef turns a caller-supplied component reference into an FGA
// object reference of type component, or rejects it.
//
// A bare name is prefixed. A reference already typed "component:" is kept. Any
// OTHER type is refused rather than passed through. Every RPC in this file
// normalised by prefixing only when the string had no colon, which meant an
// already-typed reference was forwarded verbatim — the caller got to choose the
// object TYPE, not just which object, and the tuples this file writes
// (tenant_enabled, tenant_published, team_*_disabled, the per-action component
// grants) landed on whatever type they named. Mirrors allowedTenantRoles below:
// the caller names WHICH thing, never WHAT KIND of thing.
func componentObjectRef(component string) (string, error) {
	if component == "" {
		return "", status.Error(codes.InvalidArgument, "a component reference is required")
	}
	// Canonicalize to component:<kind>/<name> (ADR-0136). This accepts an
	// already-canonical ref, a kind-qualified "<kind>:<name>", or the legacy
	// colon object, and fails closed on a bare, kind-less reference — the kind
	// is part of the object identity, so "component:<name>" is not valid.
	ref, err := authz.CanonicalComponentResource(component)
	if err != nil {
		return "", status.Errorf(codes.InvalidArgument, "%v", err)
	}
	name, isComponent := strings.CutPrefix(ref, componentObjectPrefix)
	if !isComponent || !strings.Contains(name, "/") {
		objType, _, _ := strings.Cut(component, ":")
		return "", status.Errorf(codes.InvalidArgument,
			"%q names an object of type %q; this RPC only operates on component objects",
			component, objType)
	}
	return ref, nil
}

// allowedTenantRoles is the set of roles SetTenantRole accepts. Anything else
// is rejected as InvalidArgument before any FGA tuple is touched.
//
// "owner" is deliberately absent (hosted#190): assigning a role can never set
// or clear the tenant's Owner. TransferOwnership is the only way Owner
// changes.
var allowedTenantRoles = map[string]struct{}{
	"admin":  {},
	"member": {},
	"writer": {},
}

// SetTenantRole writes or removes a role relation for a user on the caller's
// tenant. When remove is true the tuple is deleted; otherwise it is written.
// Idempotent in both directions.
//
// Owner rules (hosted#190, ADR-0093 §5): "owner" is refused as a role value in
// both directions — it is not in allowedTenantRoles — and the RPC refuses to
// touch a user_id that currently holds the tenant's owner relation at all, so
// the Owner can never be demoted or removed through this path, only through
// TransferOwnership.
func (s *TenantAdminServer) SetTenantRole(ctx context.Context, req *tenantv1.SetTenantRoleRequest) (*tenantv1.SetTenantRoleResponse, error) {
	if s.authorizer == nil {
		return nil, status.Error(codes.Unavailable, "authorizer not configured")
	}
	tenantID, err := requireCallerTenant(ctx, req)
	if err != nil {
		return nil, err
	}
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id required")
	}
	if _, valid := allowedTenantRoles[req.GetRole()]; !valid {
		return nil, status.Errorf(codes.InvalidArgument, "role %q not allowed; must be one of admin, member, writer", req.GetRole())
	}

	tenantRef := "tenant:" + tenantID
	userRef := "user:" + req.GetUserId()
	role := req.GetRole()

	// The Owner's role can be changed only through TransferOwnership. Refuse
	// both a grant and a removal aimed at the current Owner, before any FGA
	// mutation, so an Admin can never strip or dilute the Owner this way.
	isOwner, err := s.authorizer.Check(ctx, userRef, "owner", tenantRef)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fga Check owner: %v", err)
	}
	if isOwner {
		return nil, status.Error(codes.PermissionDenied,
			"user_id is the tenant's Owner; the Owner's role can be changed only through TransferOwnership")
	}

	if s.roles == nil {
		return nil, status.Error(codes.Unavailable, "role sync not configured")
	}
	t, err := s.tenantOf(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Under ADR-0093 a tenant user holds one role, stored as one Zitadel
	// grant. "remove" therefore means "remove the tenant role" — there is no
	// separate FGA-only relation to drop. Roles.Assign / Roles.Revoke write
	// the Zitadel grant first and then copy it into FGA in the same call
	// (Roles.Sync), so this handler never touches FGA directly.
	if req.GetRemove() {
		if err := s.roles.Revoke(tenantrole.WithCaller(ctx, "daemon"), t, req.GetUserId()); err != nil {
			return nil, status.Errorf(codes.Internal, "revoke tenant role: %v", err)
		}
	} else {
		roleValue, ok := tenantrole.FromRelation(role)
		if !ok {
			return nil, status.Errorf(codes.Internal, "role %q has no tenant-role mapping", role)
		}
		if err := s.roles.Assign(tenantrole.WithCaller(ctx, "daemon"), t, req.GetUserId(), roleValue); err != nil {
			return nil, status.Errorf(codes.Internal, "assign tenant role: %v", err)
		}
	}
	return &tenantv1.SetTenantRoleResponse{}, nil
}

// tenantOf resolves tenantID into a tenantrole.Tenant using the configured
// TenantZitadelOrgResolver. An unmapped tenant (no Zitadel org yet) is a
// FailedPrecondition: a role write with nowhere to land in Zitadel is a bug
// to surface, never a silent skip.
func (s *TenantAdminServer) tenantOf(ctx context.Context, tenantID string) (tenantrole.Tenant, error) {
	if s.orgResolver == nil {
		return tenantrole.Tenant{}, status.Error(codes.Unavailable, "zitadel org resolver not configured")
	}
	orgID, err := s.orgResolver.ZitadelOrgID(ctx, tenantID)
	if err != nil {
		return tenantrole.Tenant{}, status.Errorf(codes.Internal, "resolve zitadel org for tenant %q: %v", tenantID, err)
	}
	if orgID == "" {
		return tenantrole.Tenant{}, status.Errorf(codes.FailedPrecondition, "tenant %q is still provisioning: no Zitadel org yet", tenantID)
	}
	return tenantrole.Tenant{ID: tenantID, OrgID: orgID}, nil
}

// ---------------------------------------------------------------------------
// TransferOwnership (#397)
// ---------------------------------------------------------------------------

// TransferOwnership moves the Owner role from the caller to
// new_owner_user_id and makes the caller an Admin (hosted#190, ADR-0093 §5).
// Zitadel owns tenant roles: Roles.Transfer writes the two Zitadel grants
// first, then Roles.Sync copies them into FGA.
//
// Rules, each enforced before any FGA mutation:
//   - Only the tenant's current Owner may call this RPC. The authz registry
//     gates the RPC on the "owner" relation (not "admin"), and the handler
//     re-checks it directly so the invariant holds even if a caller reaches
//     this code by some path other than the ext-authz-fronted one.
//   - new_owner_user_id must already be a member of the caller's tenant
//     (holds at least the "member" relation, which every tenant role implies).
//   - The FGA copy of the transfer — delete the caller's owner tuple, write
//     the new owner's owner tuple, write the caller's admin tuple — is one
//     WriteAndDelete, so FGA never holds zero or two Owners. The Zitadel
//     write comes before it and is not in the same transaction.
//
// Transferring ownership to oneself is a no-op: it still requires the caller
// to already be Owner, and performs no FGA write.
func (s *TenantAdminServer) TransferOwnership(ctx context.Context, req *tenantv1.TransferOwnershipRequest) (*tenantv1.TransferOwnershipResponse, error) {
	if s.authorizer == nil {
		return nil, status.Error(codes.Unavailable, "authorizer not configured")
	}
	// Identity is fetched and checked before tenant scoping: a fail-closed
	// check on this specific error,
	// not a discard, so an absent identity can never flow on as a zero-value
	// tenant/subject.
	identity, identityErr := auth.IdentityFromContext(ctx)
	if identityErr != nil {
		return nil, status.Error(codes.PermissionDenied, "no identity in context")
	}
	tenantID, err := requireCallerTenant(ctx, req)
	if err != nil {
		return nil, err
	}
	if req.GetNewOwnerUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "new_owner_user_id required")
	}

	tenantRef := "tenant:" + tenantID
	callerRef := "user:" + identity.Subject
	newOwnerRef := "user:" + req.GetNewOwnerUserId()

	// Only the tenant's current Owner may transfer ownership.
	callerIsOwner, err := s.authorizer.Check(ctx, callerRef, "owner", tenantRef)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fga Check owner: %v", err)
	}
	if !callerIsOwner {
		return nil, status.Error(codes.PermissionDenied, "only the tenant's Owner may transfer ownership")
	}

	if newOwnerRef == callerRef {
		// Already the Owner; nothing changes.
		return &tenantv1.TransferOwnershipResponse{}, nil
	}

	// The target must be an existing tenant user. "member" is implied by
	// every tenant role (owner > admin > writer > member in model.fga), so
	// one Check covers all of them.
	targetIsTenantUser, err := s.authorizer.Check(ctx, newOwnerRef, "member", tenantRef)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fga Check member: %v", err)
	}
	if !targetIsTenantUser {
		return nil, status.Error(codes.InvalidArgument, "new_owner_user_id must be an existing user of this tenant")
	}

	if s.roles == nil {
		return nil, status.Error(codes.Unavailable, "role sync not configured")
	}
	t, err := s.tenantOf(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Roles.Transfer writes the two Zitadel grants (new owner promoted, caller
	// demoted to admin), then Roles.Sync copies both into FGA in one
	// WriteAndDelete — Sync only writes a tuple that is not already there, so
	// a caller who already held a direct admin tuple is left untouched.
	if err := s.roles.Transfer(tenantrole.WithCaller(ctx, "daemon"), t, identity.Subject, req.GetNewOwnerUserId()); err != nil {
		if errors.Is(err, tenantrole.ErrOwnerConflict) {
			return nil, status.Error(codes.Aborted, "ownership transfer conflicted with a concurrent change; retry")
		}
		return nil, status.Errorf(codes.Internal, "transfer ownership: %v", err)
	}

	return &tenantv1.TransferOwnershipResponse{}, nil
}

// SetCatalogPublished writes or deletes the FGA tenant_published tuple for a
// component owned by the caller's tenant — the bring-your-own (BYO) connector
// path (gibson#683). Mirrors SetCatalogEnabled but on the tenant_published
// relation: published = "this tenant owns/offers it" (its private registry),
// distinct from tenant_enabled = "this tenant has it switched on".
func (s *TenantAdminServer) SetCatalogPublished(ctx context.Context, req *tenantv1.SetCatalogPublishedRequest) (*tenantv1.SetCatalogPublishedResponse, error) {
	if s.authorizer == nil {
		return nil, status.Error(codes.Unavailable, "authorizer not configured")
	}
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if req.GetComponentRef() == "" {
		return nil, status.Error(codes.InvalidArgument, "component_ref is required")
	}

	componentRef, err := componentObjectRef(req.GetComponentRef())
	if err != nil {
		return nil, err
	}

	tenantRef := "tenant:" + tenant.String()

	tuple := authz.Tuple{
		User:     tenantRef,
		Relation: "tenant_published",
		Object:   componentRef,
	}

	if req.GetPublished() {
		present, err := s.authorizer.Check(ctx, tenantRef, "tenant_published", componentRef)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "fga Check tenant_published: %v", err)
		}
		if present {
			return &tenantv1.SetCatalogPublishedResponse{Written: false}, nil
		}
		if err := s.authorizer.Write(ctx, []authz.Tuple{tuple}); err != nil {
			return nil, status.Errorf(codes.Internal, "fga Write tenant_published: %v", err)
		}
		return &tenantv1.SetCatalogPublishedResponse{Written: true}, nil
	}

	present, err := s.authorizer.Check(ctx, tenantRef, "tenant_published", componentRef)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fga Check tenant_published: %v", err)
	}
	if !present {
		return &tenantv1.SetCatalogPublishedResponse{Deleted: false}, nil
	}
	if err := s.authorizer.Delete(ctx, []authz.Tuple{tuple}); err != nil {
		return nil, status.Errorf(codes.Internal, "fga Delete tenant_published: %v", err)
	}
	return &tenantv1.SetCatalogPublishedResponse{Deleted: true}, nil
}
