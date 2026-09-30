// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — user_resolve.go implements UserService.ResolveUsers.
//
// Missions, jobs and banks record who created or opened them as a Zitadel
// user id, never as a name (hosted#205: a removed user's work shows "removed
// user", nothing is copied at creation). GetUserProfile is self-only and
// ListMembers is admin-only, so a dashboard reader has no way to turn another
// member's id into a name. ResolveUsers is that way: any member of the
// tenant resolves the ids the tenant's records carry.
//
// The membership check is the tenant boundary. An id that is not a member of
// the caller's tenant resolves to REMOVED with no name: a person who left,
// and a person who never belonged, look the same, so nothing about a user
// of another tenant leaks through this RPC.
package api

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// maxResolveUsers bounds one request. A list page names far fewer people.
const maxResolveUsers = 100

// ResolveUsers turns user ids into names for display, scoped to the caller's
// tenant. See the file header for the boundary it enforces.
func (s *DaemonServer) ResolveUsers(ctx context.Context, req *tenantv1.ResolveUsersRequest) (*tenantv1.ResolveUsersResponse, error) {
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Error(codes.Unauthenticated, "no tenant in caller identity")
	}
	ids := distinctUserIDs(req.GetUserIds())
	if len(ids) > maxResolveUsers {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "at most %d user ids per request, got %d", maxResolveUsers, len(ids))
	}
	if len(ids) == 0 {
		return &tenantv1.ResolveUsersResponse{}, nil
	}
	if s.authorizer == nil || s.idpAdminClient == nil {
		return nil, status_grpc.Error(codes.Unavailable, "user resolution is not configured")
	}

	members, err := s.tenantMembers(ctx, tenantID, ids)
	if err != nil {
		s.logger.ErrorContext(ctx, "ResolveUsers: membership check failed", "tenant_id", tenantID, "error", err.Error())
		return nil, status_grpc.Error(codes.Unavailable, "membership check failed")
	}

	out := make([]*tenantv1.UserRef, 0, len(ids))
	for i, id := range ids {
		ref := &tenantv1.UserRef{UserId: id, State: tenantv1.UserRefState_USER_REF_STATE_REMOVED}
		if members[i] {
			ref.State = tenantv1.UserRefState_USER_REF_STATE_MEMBER
			if err := s.fillUserRef(ctx, ref); err != nil {
				s.logger.ErrorContext(ctx, "ResolveUsers: profile lookup failed", "user_id", id, "error", err.Error())
				return nil, status_grpc.Error(codes.Unavailable, "identity provider unavailable")
			}
		}
		out = append(out, ref)
	}
	return &tenantv1.ResolveUsersResponse{Users: out}, nil
}

// distinctUserIDs drops empty and repeated ids and keeps request order.
func distinctUserIDs(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, id := range in {
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

// tenantMembers answers, per id, whether the user is a member of the tenant.
func (s *DaemonServer) tenantMembers(ctx context.Context, tenantID string, ids []string) ([]bool, error) {
	checks := make([]authz.CheckRequest, len(ids))
	for i, id := range ids {
		checks[i] = authz.CheckRequest{User: "user:" + id, Relation: "member", Object: "tenant:" + tenantID}
	}
	held, err := s.authorizer.BatchCheck(ctx, checks)
	if err != nil {
		return nil, fmt.Errorf("batch check: %w", err)
	}
	if len(held) != len(ids) {
		return nil, fmt.Errorf("batch check returned %d results for %d checks", len(held), len(ids))
	}
	return held, nil
}

// fillUserRef reads a member's name from the identity provider. A member the
// provider no longer knows keeps its MEMBER state with empty names: the
// tenant still holds the membership, and the caller sees the id.
func (s *DaemonServer) fillUserRef(ctx context.Context, ref *tenantv1.UserRef) error {
	profile, err := s.idpAdminClient.GetUserProfile(ctx, ref.GetUserId())
	if errors.Is(err, idp.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("get user profile: %w", err)
	}
	ref.DisplayName = profile.DisplayName
	ref.Email = profile.Email
	return nil
}
