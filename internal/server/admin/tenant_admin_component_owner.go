// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package admin — tenant_admin_component_owner.go
//
// The owner of an agent, tool or plugin identity is the person who is
// accountable for it (gibson#568). Two records hold the owner: the FGA tuple
// `user:<id> owner <kind>_principal:<id>`, and the user_id of the capability
// grant rows of the principal, which a verified CG-JWT carries as
// OwnerUserID. A removal moves both to a person who is still in the tenant,
// so a component never runs with a dead owner. ReassignAgentIdentity moves
// them on to the right person.
package admin

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// principalTypes are the FGA types of the identities a user can own.
var principalTypes = []string{"agent_principal", "tool_principal", "plugin_principal"}

// ComponentOwnerStore moves the owner user of the capability grant rows of a
// principal. *capabilitygrant.CapabilityGrantStore satisfies it.
type ComponentOwnerStore interface {
	ReassignOwner(ctx context.Context, tenantID, principalRef, toUserID string) (int64, error)
}

// ReassignAgentIdentity makes new_owner_user_id the owner of one identity of
// the caller's tenant. The caller must be a tenant admin (authz registry).
func (s *TenantAdminServer) ReassignAgentIdentity(ctx context.Context, req *tenantv1.ReassignAgentIdentityRequest) (*tenantv1.ReassignAgentIdentityResponse, error) {
	if s.authorizer == nil {
		return nil, status.Error(codes.Unavailable, "authorizer not configured")
	}
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	principalID := req.GetPrincipalId()
	if !isPrincipalRef(principalID) {
		return nil, status.Error(codes.InvalidArgument, "principal_id must be an agent, tool or plugin principal")
	}
	newOwner := req.GetNewOwnerUserId()
	if newOwner == "" || strings.Contains(newOwner, ":") {
		return nil, status.Error(codes.InvalidArgument, "new_owner_user_id must be a bare user id")
	}
	tenantRef := "tenant:" + tenantID

	// The identity must be this tenant's. Another tenant's identity reads as
	// not found, so the answer does not leak that it exists (gibson#606).
	inTenant, err := s.authorizer.Check(ctx, tenantRef, "belongs_to", principalID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fga Check belongs_to: %v", err)
	}
	if !inTenant {
		return nil, status.Error(codes.NotFound, "principal not found")
	}
	// The new owner must be a user of this tenant: member is implied by each
	// tenant role.
	isMember, err := s.authorizer.Check(ctx, "user:"+newOwner, "member", tenantRef)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fga Check member: %v", err)
	}
	if !isMember {
		return nil, status.Error(codes.InvalidArgument, "new_owner_user_id must be a user of this tenant")
	}

	owners, err := s.authorizer.ListUsersOfType(ctx, principalTypeOf(principalID), principalID, "owner", "user")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fga ListUsers owner: %v", err)
	}
	if err := s.moveOwner(ctx, tenantID, principalID, owners, newOwner); err != nil {
		return nil, err
	}
	return &tenantv1.ReassignAgentIdentityResponse{}, nil
}

// reassignOwnedPrincipals moves every identity of the tenant that fromUserID
// owns to toUserID, and returns the identities it moved. It is idempotent: a
// retry after a partial failure moves the rest.
func (s *TenantAdminServer) reassignOwnedPrincipals(ctx context.Context, tenantID, fromUserID, toUserID string) ([]string, error) {
	tenantRef := "tenant:" + tenantID
	fromRef := "user:" + fromUserID
	var moved []string
	for _, fgaType := range principalTypes {
		owned, err := s.authorizer.ListObjects(ctx, fromRef, "owner", fgaType)
		if err != nil {
			return moved, status.Errorf(codes.Internal, "fga ListObjects owner %s: %v", fgaType, err)
		}
		for _, principalID := range owned {
			// A user can own identities of one tenant only today, but the
			// tuple does not say so. Move only the ones of this tenant.
			inTenant, err := s.authorizer.Check(ctx, tenantRef, "belongs_to", principalID)
			if err != nil {
				return moved, status.Errorf(codes.Internal, "fga Check belongs_to: %v", err)
			}
			if !inTenant {
				continue
			}
			if err := s.moveOwner(ctx, tenantID, principalID, []string{fromRef}, toUserID); err != nil {
				return moved, err
			}
			moved = append(moved, principalID)
		}
	}
	return moved, nil
}

// moveOwner writes the new owner first and then removes the old owners, so
// the identity always has an owner. It then moves the owner user of the
// capability grant rows.
func (s *TenantAdminServer) moveOwner(ctx context.Context, tenantID, principalID string, oldOwners []string, toUserID string) error {
	toRef := "user:" + toUserID
	if err := s.authorizer.Write(ctx, []authz.Tuple{{User: toRef, Relation: "owner", Object: principalID}}); err != nil {
		return status.Errorf(codes.Internal, "fga Write owner of %s: %v", principalID, err)
	}
	var stale []authz.Tuple
	for _, old := range oldOwners {
		if old == toRef {
			continue
		}
		stale = append(stale, authz.Tuple{User: old, Relation: "owner", Object: principalID})
	}
	if len(stale) > 0 {
		if err := s.authorizer.Delete(ctx, stale); err != nil {
			return status.Errorf(codes.Internal, "fga Delete old owner of %s: %v", principalID, err)
		}
	}
	if s.componentOwners != nil {
		if _, err := s.componentOwners.ReassignOwner(ctx, tenantID, principalID, toUserID); err != nil {
			return status.Errorf(codes.Internal, "move the enrollment owner of %s: %v", principalID, err)
		}
	}
	s.logger.InfoContext(ctx, "component identity owner moved",
		slog.String("tenant_id", tenantID),
		slog.String("principal_id", principalID),
		slog.String("new_owner_user_id", toUserID),
	)
	return nil
}

// tenantOwnerUserID returns the bare user id of the tenant's Owner.
func (s *TenantAdminServer) tenantOwnerUserID(ctx context.Context, tenantID string) (string, error) {
	users, err := s.authorizer.ListUsers(ctx, "tenant", "tenant:"+tenantID, "owner")
	if err != nil {
		return "", fmt.Errorf("list the tenant owner: %w", err)
	}
	for _, u := range users {
		if id, ok := strings.CutPrefix(u, "user:"); ok && id != "" {
			return id, nil
		}
	}
	return "", fmt.Errorf("tenant %q has no owner", tenantID)
}

// isPrincipalRef reports whether ref is "<kind>_principal:<id>".
func isPrincipalRef(ref string) bool {
	t := principalTypeOf(ref)
	if t == "" {
		return false
	}
	return len(ref) > len(t)+1
}

// principalTypeOf returns the FGA type of a principal reference, or "".
func principalTypeOf(ref string) string {
	typ, _, ok := strings.Cut(ref, ":")
	if !ok {
		return ""
	}
	for _, t := range principalTypes {
		if typ == t {
			return t
		}
	}
	return ""
}
