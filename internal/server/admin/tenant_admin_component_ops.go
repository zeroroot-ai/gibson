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
//	Writes or removes a role (admin / member / owner) tuple for a user on the
//	caller's tenant.
//
// TransferOwnership (admin on tenant):
//
//	Atomically swaps the owner tuple from the current owner to the new owner.
//
// GrantComponentPermissions (member on tenant, issue #398):
//
//	Enforces caller-access intersection: only capabilities the caller already
//	holds (component_*_enabled tuples on agent_principal:<agent_installation_id>)
//	may be forwarded to the agent installation principal. The server checks each
//	requested action against the caller's own access before writing tuples.
//
// Spec: tenant-service-admin-handlers issues #397 and #398.
package admin

import (
	"context"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/idp"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// tenantRoleRelations are the FGA relations that make a user a member of a
// tenant. SetTenantRole removes Zitadel org membership only when none remain.
var tenantRoleRelations = []string{"owner", "admin", "member", "writer"}

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

	return &tenantv1.SetComponentAccessResponse{
		TuplesWritten: int32(len(toWrite)),
		TuplesDeleted: int32(len(toDelete)),
	}, nil
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
	// Canonicalize to component:<kind>/<name> (ADR-0015). This accepts an
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
var allowedTenantRoles = map[string]struct{}{
	"admin":  {},
	"member": {},
	"owner":  {},
	"writer": {},
}

// SetTenantRole writes or removes a role relation for a user on the caller's
// tenant. When remove is true the tuple is deleted; otherwise it is written.
// Idempotent in both directions.
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
		return nil, status.Errorf(codes.InvalidArgument, "role %q not allowed; must be one of admin, member, owner, writer", req.GetRole())
	}

	tenantRef := "tenant:" + tenantID
	userRef := "user:" + req.GetUserId()
	role := req.GetRole()

	tuple := authz.Tuple{User: userRef, Relation: role, Object: tenantRef}

	if req.GetRemove() {
		// FGA first (revoke authority), then Zitadel (drop org membership only
		// when no tenant role remains). On Zitadel failure the FGA tuple is
		// already gone — fail-closed on authority; an idempotent retry and the
		// operator's reconciler converge the org side (ADR-0043).
		present, err := s.authorizer.Check(ctx, userRef, role, tenantRef)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "fga Check %s: %v", role, err)
		}
		if present {
			if err := s.authorizer.Delete(ctx, []authz.Tuple{tuple}); err != nil {
				return nil, status.Errorf(codes.Internal, "fga Delete %s: %v", role, err)
			}
		}
		if err := s.maybeRemoveZitadelMember(ctx, tenantID, req.GetUserId()); err != nil {
			return nil, err
		}
	} else {
		// Zitadel first (ensure org membership, idempotent), then FGA write. On
		// FGA failure the user is in the org but holds no authority — fail-closed.
		if err := s.addZitadelMember(ctx, tenantID, req.GetUserId(), role); err != nil {
			return nil, err
		}
		present, err := s.authorizer.Check(ctx, userRef, role, tenantRef)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "fga Check %s: %v", role, err)
		}
		if !present {
			if err := s.authorizer.Write(ctx, []authz.Tuple{tuple}); err != nil {
				return nil, status.Errorf(codes.Internal, "fga Write %s: %v", role, err)
			}
		}
	}
	return &tenantv1.SetTenantRoleResponse{}, nil
}

// resolveTenantOrgID returns the IdP org id seeded for the tenant, or "" when
// the Zitadel-membership projection should be skipped (no resolver, no idp
// client, or no mapping yet — the operator backfill/reconcile converges it).
func (s *TenantAdminServer) resolveTenantOrgID(ctx context.Context, tenantID string) (string, error) {
	if s.orgResolver == nil || s.idpClient == nil {
		return "", nil
	}
	orgID, err := s.orgResolver.ZitadelOrgID(ctx, tenantID)
	if err != nil {
		return "", status.Errorf(codes.Internal, "resolve zitadel org for tenant %q: %v", tenantID, err)
	}
	return orgID, nil
}

// addZitadelMember writes the Zitadel half of a role-add: ensure the user is a
// member of the tenant's per-tenant org with the given role. Idempotent.
func (s *TenantAdminServer) addZitadelMember(ctx context.Context, tenantID, userID, role string) error {
	orgID, err := s.resolveTenantOrgID(ctx, tenantID)
	if err != nil {
		return err
	}
	if orgID == "" {
		return nil
	}
	if err := s.idpClient.AddTenantMember(ctx, idp.TenantMembershipRequest{OrgID: orgID, UserID: userID, Role: role}); err != nil {
		return status.Errorf(codes.Internal, "zitadel add member: %v", err)
	}
	return nil
}

// maybeRemoveZitadelMember removes the user from the tenant's per-tenant org,
// but only when they retain no tenant role (Zitadel org membership is binary,
// not per-role). Idempotent.
func (s *TenantAdminServer) maybeRemoveZitadelMember(ctx context.Context, tenantID, userID string) error {
	orgID, err := s.resolveTenantOrgID(ctx, tenantID)
	if err != nil {
		return err
	}
	if orgID == "" {
		return nil
	}
	tenantRef := "tenant:" + tenantID
	userRef := "user:" + userID
	for _, r := range tenantRoleRelations {
		present, cerr := s.authorizer.Check(ctx, userRef, r, tenantRef)
		if cerr != nil {
			return status.Errorf(codes.Internal, "fga Check %s: %v", r, cerr)
		}
		if present {
			// Still a tenant member via another role — keep org membership.
			return nil
		}
	}
	if err := s.idpClient.RemoveTenantMember(ctx, idp.TenantMembershipRequest{OrgID: orgID, UserID: userID}); err != nil {
		return status.Errorf(codes.Internal, "zitadel remove member: %v", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// TransferOwnership (#397)
// ---------------------------------------------------------------------------

// TransferOwnership atomically swaps the owner tuple from the current owner to
// the new owner. It:
//  1. Lists all users with the owner relation on the tenant.
//  2. Deletes all existing owner tuples.
//  3. Writes (user:newOwner, owner, tenant:X).
//
// If new_owner_user_id already holds the owner relation, the operation is a
// no-op beyond verifying the FGA state.
func (s *TenantAdminServer) TransferOwnership(ctx context.Context, req *tenantv1.TransferOwnershipRequest) (*tenantv1.TransferOwnershipResponse, error) {
	if s.authorizer == nil {
		return nil, status.Error(codes.Unavailable, "authorizer not configured")
	}
	tenantID, err := requireCallerTenant(ctx, req)
	if err != nil {
		return nil, err
	}
	if req.GetNewOwnerUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "new_owner_user_id required")
	}

	tenantRef := "tenant:" + tenantID
	newOwnerRef := "user:" + req.GetNewOwnerUserId()

	// List current owners.
	currentOwners, err := s.authorizer.ListUsers(ctx, "tenant", tenantRef, "owner")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fga ListUsers(owner): %v", err)
	}

	// Delete all existing owner tuples.
	var toDelete []authz.Tuple
	for _, ownerRef := range currentOwners {
		if ownerRef == newOwnerRef {
			continue // already the owner — skip
		}
		toDelete = append(toDelete, authz.Tuple{
			User:     ownerRef,
			Relation: "owner",
			Object:   tenantRef,
		})
	}
	if len(toDelete) > 0 {
		if err := s.authorizer.Delete(ctx, toDelete); err != nil {
			return nil, status.Errorf(codes.Internal, "fga Delete owner: %v", err)
		}
	}

	// Write new owner tuple (idempotent: check first).
	newOwnerPresent, err := s.authorizer.Check(ctx, newOwnerRef, "owner", tenantRef)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fga Check new owner: %v", err)
	}
	if !newOwnerPresent {
		if err := s.authorizer.Write(ctx, []authz.Tuple{
			{User: newOwnerRef, Relation: "owner", Object: tenantRef},
		}); err != nil {
			return nil, status.Errorf(codes.Internal, "fga Write new owner: %v", err)
		}
	}

	return &tenantv1.TransferOwnershipResponse{}, nil
}

// ---------------------------------------------------------------------------
// GrantComponentPermissions (#398)
// ---------------------------------------------------------------------------

// actionToComponentRelation maps the human-readable action name to the FGA
// component_*_enabled relation on the agent_principal.
var actionToComponentRelation = map[string]string{
	"read":    "component_read_enabled",
	"write":   "component_write_enabled",
	"execute": "component_execute_enabled",
}

// actionToCallerRelation maps the action name to the FGA relation the caller
// must hold on the component object for the caller-access intersection check.
var actionToCallerRelation = map[string]string{
	"read":    "can_read",
	"write":   "can_configure",
	"execute": "can_execute",
}

// agentInstallationUUIDLen is the length of the canonical 8-4-4-4-12 UUID
// string emitted by the dashboard's crypto.randomUUID() (installAgent.ts).
const agentInstallationUUIDLen = 36

// agentInstallationTenantSuffix splits a dashboard-minted agent_installation_id
// of the form "<uuid>-<tenantId>" (installAgent.ts: `${randomUUID()}-${tenantId}`)
// into its tenant portion. It reports ok=false if the id is not at least
// long enough to carry a UUID plus a "-" separator.
//
// This is a fixed-offset split, not a suffix search: index [0:36] is treated
// as the UUID and [37:] as the WHOLE remainder, compared for exact equality
// by the caller — never a strings.HasSuffix/Contains check. Tenant slugs may
// themselves contain hyphens (auth.NewTenantID's grammar allows it), so a
// naive "ends with '-'+tenant" test is ambiguous: an id mistakenly minted
// under a tenant whose slug itself ends in another tenant's slug (e.g.
// "my-acme" ending in "acme") would satisfy a suffix check for tenant "acme"
// too. Exact equality of the entire post-UUID remainder has no such
// collision, regardless of what hyphens either tenant slug contains.
func agentInstallationTenantSuffix(installationID string) (tenant string, ok bool) {
	if len(installationID) <= agentInstallationUUIDLen+1 {
		return "", false
	}
	if installationID[agentInstallationUUIDLen] != '-' {
		return "", false
	}
	return installationID[agentInstallationUUIDLen+1:], true
}

// GrantComponentPermissions writes component_*_enabled FGA tuples for an agent
// installation principal after enforcing caller-access intersection. Only
// capabilities the caller already holds on each target component may be
// forwarded to the agent installation principal.
//
// The caller-access intersection check prevents privilege escalation: a tenant
// admin who cannot execute component:gitlab cannot grant execute access on that
// component to any agent installation.
func (s *TenantAdminServer) GrantComponentPermissions(ctx context.Context, req *tenantv1.GrantComponentPermissionsRequest) (*tenantv1.GrantComponentPermissionsResponse, error) {
	if s.authorizer == nil {
		return nil, status.Error(codes.Unavailable, "authorizer not configured")
	}
	identity, identityErr := auth.IdentityFromContext(ctx)
	if identityErr != nil {
		return nil, status.Error(codes.PermissionDenied, "no identity in context")
	}
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if req.GetAgentInstallationId() == "" {
		return nil, status.Error(codes.InvalidArgument, "agent_installation_id required")
	}
	if len(req.GetApprovals()) == 0 {
		// Trivially a no-op, but we return early rather than error — the
		// caller may be testing the endpoint or clearing all grants.
		return &tenantv1.GrantComponentPermissionsResponse{
			AgentInstallationId: req.GetAgentInstallationId(),
		}, nil
	}

	// Validate all actions before touching FGA.
	for i, approval := range req.GetApprovals() {
		if approval.GetTarget() == "" {
			return nil, status.Errorf(codes.InvalidArgument, "approvals[%d].target is required", i)
		}
		if _, valid := actionToComponentRelation[approval.GetAction()]; !valid {
			return nil, status.Errorf(codes.InvalidArgument,
				"approvals[%d].action %q not allowed; must be one of read, write, execute", i, approval.GetAction())
		}
	}

	// Normalise the caller's user ref.
	callerRef := "user:" + identity.Subject
	agentPrincipalRef := "agent_principal:" + req.GetAgentInstallationId()

	// Bind the grant RECIPIENT to the caller's tenant. The caller-access
	// intersection below bounds WHICH capability may be forwarded; without this
	// check it does not bound WHO receives it, so a caller could forward their
	// own component access to a principal in another tenant.
	//
	// This is NOT GrantsAdminServer.validateTargetAndTenant's shape: that path
	// resolves an ALREADY-PROVISIONED principal through the identity lookup
	// service, which only knows principals CreateAgentIdentity provisioned
	// through the IdP. An agent-installation principal is different — it is
	// minted client-side by the dashboard install flow (installAgent.ts:
	// `${randomUUID()}-${tenantId}`) and nothing writes a `belongs_to` tuple
	// for it ahead of a grant, so an FGA Check here can never succeed; it
	// denied every real caller (the regression this replaces).
	//
	// The actual anchor is the id's own tenant suffix, verified against the
	// CALLER'S authenticated tenant (ctx-derived — ext-authz sets it from the
	// caller's verified membership, never from anything the request body or
	// the id string itself asserts). A caller authenticated as tenant A can
	// only ever compute wantTenant="A" here, so they cannot construct an id
	// that resolves to tenant B's suffix while acting as A: the check is an
	// equality against A, not a property of the id alone. See
	// agentInstallationTenantSuffix for why this is an exact split on the
	// fixed-width UUID prefix rather than a suffix/Contains match (tenant
	// slugs may themselves contain hyphens).
	//
	// Once the suffix is verified, the belongs_to tuple is queued for the same
	// atomic Write as the component grants below (self-healing, mirroring the
	// belongs_to-heal pattern in mission_handlers.go) — nothing is written
	// yet if the caller-access intersection check below still has to reject
	// the request. Write is idempotent (a no-op if the tuple already exists
	// per the authz.Authorizer contract), so queuing it unconditionally here
	// is safe and turns the principal's tenancy into a real, queryable FGA
	// fact from its first successful grant onward (visible to ListPrincipals
	// / a later CreateAgentIdentity reconciliation) rather than leaving a
	// Check here that could never be satisfied.
	gotTenant, suffixOK := agentInstallationTenantSuffix(req.GetAgentInstallationId())
	if !suffixOK || gotTenant != tenant.String() {
		s.logger.WarnContext(ctx, "GrantComponentPermissions: agent_installation_id does not belong to the caller's tenant",
			slog.String("caller", callerRef),
			slog.String("agent_installation_id", req.GetAgentInstallationId()),
		)
		return nil, status.Error(codes.PermissionDenied, "target principal is not in your tenant")
	}
	belongsToTuple := authz.Tuple{User: tenantRefFromID(tenant.String()), Relation: "belongs_to", Object: agentPrincipalRef}

	// Caller-access intersection check: batch-check the caller's access on
	// every (target, action) pair before writing any tuples. This prevents
	// privilege escalation.
	checks := make([]authz.CheckRequest, len(req.GetApprovals()))
	for i, approval := range req.GetApprovals() {
		targetRef, refErr := componentObjectRef(approval.GetTarget())
		if refErr != nil {
			return nil, refErr
		}
		callerRelation := actionToCallerRelation[approval.GetAction()]
		checks[i] = authz.CheckRequest{
			User:     callerRef,
			Relation: callerRelation,
			Object:   targetRef,
		}
	}
	callerHasAccess, err := s.authorizer.BatchCheck(ctx, checks)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fga BatchCheck caller access: %v", err)
	}

	// Reject if the caller lacks access to any approval.
	for i, allowed := range callerHasAccess {
		if !allowed {
			s.logger.WarnContext(ctx, "GrantComponentPermissions: caller-access intersection failed",
				slog.String("caller", callerRef),
				slog.String("target", req.GetApprovals()[i].GetTarget()),
				slog.String("action", req.GetApprovals()[i].GetAction()),
			)
			return nil, status.Errorf(codes.PermissionDenied,
				"caller does not have %s access on %s",
				req.GetApprovals()[i].GetAction(), req.GetApprovals()[i].GetTarget())
		}
	}

	// Build the tuples to write. Check which already exist to avoid errors.
	candidateTuples := make([]authz.Tuple, len(req.GetApprovals()))
	for i, approval := range req.GetApprovals() {
		targetRef, refErr := componentObjectRef(approval.GetTarget())
		if refErr != nil {
			return nil, refErr
		}
		candidateTuples[i] = authz.Tuple{
			User:     agentPrincipalRef,
			Relation: actionToComponentRelation[approval.GetAction()],
			Object:   targetRef,
		}
	}

	existChecks := make([]authz.CheckRequest, len(candidateTuples))
	for i, t := range candidateTuples {
		existChecks[i] = authz.CheckRequest{User: t.User, Relation: t.Relation, Object: t.Object}
	}
	alreadyPresent, err := s.authorizer.BatchCheck(ctx, existChecks)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fga BatchCheck existing grants: %v", err)
	}

	// belongs_to is queued unconditionally (Write is idempotent), so it is
	// (re)established on every successful grant even if it was somehow
	// deleted since the principal's last grant.
	toWrite := []authz.Tuple{belongsToTuple}
	for i, present := range alreadyPresent {
		if !present {
			toWrite = append(toWrite, candidateTuples[i])
		}
	}

	if err := s.authorizer.Write(ctx, toWrite); err != nil {
		return nil, status.Errorf(codes.Internal, "fga Write component grants: %v", err)
	}

	return &tenantv1.GrantComponentPermissionsResponse{
		AgentInstallationId: req.GetAgentInstallationId(),
	}, nil
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
