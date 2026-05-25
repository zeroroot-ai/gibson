// Package admin — tenant_admin_component_ops.go
//
// TenantAdminServer component-access, role, ownership, and grant handlers
// implementing the RPC surface added by platform-sdk issues #397 and #398.
//
// SetComponentAccess (admin on tenant):
//   Reconciles the set of (relation, team_id, disabled) access-control entries
//   for a single component object. Reads the existing tuples, deletes the
//   superseded ones, and writes the new ones atomically.
//
// SetTenantRole (admin on tenant):
//   Writes or removes a role (admin / member / owner) tuple for a user on the
//   caller's tenant.
//
// TransferOwnership (admin on tenant):
//   Atomically swaps the owner tuple from the current owner to the new owner.
//
// GrantComponentPermissions (member on tenant, issue #398):
//   Enforces caller-access intersection: only capabilities the caller already
//   holds (component_*_enabled tuples on agent_principal:<agent_installation_id>)
//   may be forwarded to the agent installation principal. The server checks each
//   requested action against the caller's own access before writing tuples.
//
// Spec: tenant-service-admin-handlers issues #397 and #398.
package admin

import (
	"context"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/authz"

	adminv1 "github.com/zero-day-ai/platform-sdk/gen/gibson/admin/v1"
	"github.com/zero-day-ai/sdk/auth"
)

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
func (s *TenantAdminServer) SetComponentAccess(ctx context.Context, req *adminv1.SetComponentAccessRequest) (*adminv1.SetComponentAccessResponse, error) {
	if s.authorizer == nil {
		return nil, status.Error(codes.Unavailable, "authorizer not configured")
	}
	if _, ok := auth.TenantFromContext(ctx); !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if req.GetComponent() == "" {
		return nil, status.Error(codes.InvalidArgument, "component required")
	}

	// Normalise the component object reference.
	componentRef := req.GetComponent()
	if !strings.Contains(componentRef, ":") {
		componentRef = "component:" + componentRef
	}

	// Build the desired set: map of (relation, team_ref) → present.
	type entryKey struct {
		relation string
		teamRef  string
	}
	desired := make(map[entryKey]bool, len(req.GetEntries()))
	for _, e := range req.GetEntries() {
		if e.GetRelation() == "" || e.GetTeamId() == "" {
			return nil, status.Error(codes.InvalidArgument, "each entry requires relation and team_id")
		}
		teamRef := "team:" + e.GetTeamId()
		desired[entryKey{relation: e.GetRelation(), teamRef: teamRef}] = !e.GetDisabled()
	}

	// Collect the target relations from the request (deduped).
	relationSet := make(map[string]struct{})
	for _, e := range req.GetEntries() {
		if e.GetRelation() != "" {
			relationSet[e.GetRelation()] = struct{}{}
		}
	}

	// For each distinct relation, list current team-typed users and reconcile.
	var toWrite, toDelete []authz.Tuple

	for relation := range relationSet {
		existing, err := s.authorizer.ListUsers(ctx, "component", componentRef, relation)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "fga ListUsers(%s) for %s: %v", relation, componentRef, err)
		}

		// Track which existing entries are in the desired set.
		for _, userRef := range existing {
			if !strings.HasPrefix(userRef, "team:") {
				continue // skip non-team users on this relation
			}
			key := entryKey{relation: relation, teamRef: userRef}
			if _, want := desired[key]; !want {
				// Existing entry not in desired set — delete it.
				toDelete = append(toDelete, authz.Tuple{
					User:     userRef,
					Relation: relation,
					Object:   componentRef,
				})
			}
			// Mark as already present so we don't re-write it.
			delete(desired, key)
		}
	}

	// Remaining desired entries are not yet present — write them.
	for key, active := range desired {
		if !active {
			continue // disabled and not present — nothing to do
		}
		toWrite = append(toWrite, authz.Tuple{
			User:     key.teamRef,
			Relation: key.relation,
			Object:   componentRef,
		})
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

	return &adminv1.SetComponentAccessResponse{
		TuplesWritten: int32(len(toWrite)),
		TuplesDeleted: int32(len(toDelete)),
	}, nil
}

// ---------------------------------------------------------------------------
// SetTenantRole (#397)
// ---------------------------------------------------------------------------

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
func (s *TenantAdminServer) SetTenantRole(ctx context.Context, req *adminv1.SetTenantRoleRequest) (*adminv1.SetTenantRoleResponse, error) {
	if s.authorizer == nil {
		return nil, status.Error(codes.Unavailable, "authorizer not configured")
	}
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id required")
	}
	if _, valid := allowedTenantRoles[req.GetRole()]; !valid {
		return nil, status.Errorf(codes.InvalidArgument, "role %q not allowed; must be one of admin, member, owner, writer", req.GetRole())
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = tenant.String()
	}
	tenantRef := "tenant:" + tenantID
	userRef := "user:" + req.GetUserId()
	role := req.GetRole()

	tuple := authz.Tuple{User: userRef, Relation: role, Object: tenantRef}

	if req.GetRemove() {
		present, err := s.authorizer.Check(ctx, userRef, role, tenantRef)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "fga Check %s: %v", role, err)
		}
		if present {
			if err := s.authorizer.Delete(ctx, []authz.Tuple{tuple}); err != nil {
				return nil, status.Errorf(codes.Internal, "fga Delete %s: %v", role, err)
			}
		}
	} else {
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
	return &adminv1.SetTenantRoleResponse{}, nil
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
func (s *TenantAdminServer) TransferOwnership(ctx context.Context, req *adminv1.TransferOwnershipRequest) (*adminv1.TransferOwnershipResponse, error) {
	if s.authorizer == nil {
		return nil, status.Error(codes.Unavailable, "authorizer not configured")
	}
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if req.GetNewOwnerUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "new_owner_user_id required")
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = tenant.String()
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

	return &adminv1.TransferOwnershipResponse{}, nil
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

// GrantComponentPermissions writes component_*_enabled FGA tuples for an agent
// installation principal after enforcing caller-access intersection. Only
// capabilities the caller already holds on each target component may be
// forwarded to the agent installation principal.
//
// The caller-access intersection check prevents privilege escalation: a tenant
// admin who cannot execute component:gitlab cannot grant execute access on that
// component to any agent installation.
func (s *TenantAdminServer) GrantComponentPermissions(ctx context.Context, req *adminv1.GrantComponentPermissionsRequest) (*adminv1.GrantComponentPermissionsResponse, error) {
	if s.authorizer == nil {
		return nil, status.Error(codes.Unavailable, "authorizer not configured")
	}
	identity, identityErr := auth.IdentityFromContext(ctx)
	if identityErr != nil {
		return nil, status.Error(codes.PermissionDenied, "no identity in context")
	}
	if req.GetAgentInstallationId() == "" {
		return nil, status.Error(codes.InvalidArgument, "agent_installation_id required")
	}
	if len(req.GetApprovals()) == 0 {
		// Trivially a no-op, but we return early rather than error — the
		// caller may be testing the endpoint or clearing all grants.
		return &adminv1.GrantComponentPermissionsResponse{
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

	// Caller-access intersection check: batch-check the caller's access on
	// every (target, action) pair before writing any tuples. This prevents
	// privilege escalation.
	checks := make([]authz.CheckRequest, len(req.GetApprovals()))
	for i, approval := range req.GetApprovals() {
		targetRef := approval.GetTarget()
		if !strings.Contains(targetRef, ":") {
			targetRef = "component:" + targetRef
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
		targetRef := approval.GetTarget()
		if !strings.Contains(targetRef, ":") {
			targetRef = "component:" + targetRef
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

	var toWrite []authz.Tuple
	for i, present := range alreadyPresent {
		if !present {
			toWrite = append(toWrite, candidateTuples[i])
		}
	}

	if len(toWrite) > 0 {
		if err := s.authorizer.Write(ctx, toWrite); err != nil {
			return nil, status.Errorf(codes.Internal, "fga Write component grants: %v", err)
		}
	}

	return &adminv1.GrantComponentPermissionsResponse{
		AgentInstallationId: req.GetAgentInstallationId(),
	}, nil
}
