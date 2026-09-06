// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — tenant_admin_revoke.go implements TenantAdminService.RevokeAgentIdentity.
//
// Security: cross-tenant denial uses an identical error message to "not found"
// so that the response does not leak the existence of principals across tenants.
package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	tenantpb "github.com/zeroroot-ai/sdk/api/gen/gibson/agentidentity/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// RevokeAgentIdentity permanently revokes a machine identity.
// Idempotent: a second call after success returns codes.NotFound.
// Cross-tenant: a call for a principal owned by another tenant returns
// codes.NotFound (not PermissionDenied) to avoid leaking existence.
func (s *DaemonServer) RevokeAgentIdentity(ctx context.Context, req *tenantpb.RevokeAgentIdentityRequest) (*tenantpb.RevokeAgentIdentityResponse, error) {
	callerID, err := auth.IdentityFromContext(ctx)
	if err != nil {
		return nil, status_grpc.Error(codes.Unauthenticated, "not authenticated")
	}

	if req.PrincipalId == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "principal_id is required")
	}

	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant ID not found in request context")
	}

	if s.idpAdminClient == nil {
		return nil, status_grpc.Error(codes.Unavailable,
			"identity provider not configured; set GIBSON_IDP_PROVIDER and related env vars")
	}

	// FGA is the tenancy authority. Machine users live in a single shared IdP
	// org, so we MUST confirm the principal belongs to the caller's tenant
	// before deleting it — otherwise a tenant-admin could revoke another
	// tenant's identity by ID. Without the authorizer we cannot verify
	// ownership, so fail closed rather than delete blind (gibson#606).
	accountID, fgaType, err := parsePrincipalID(req.PrincipalId)
	if err != nil {
		// Invalid format — treat as NotFound to avoid leaking info.
		return nil, status_grpc.Errorf(codes.NotFound, "principal not found")
	}

	if s.authorizer == nil {
		return nil, status_grpc.Error(codes.Unavailable, "authorization not configured")
	}
	owned, err := s.authorizer.Check(ctx,
		"tenant:"+tenantID,
		"belongs_to",
		req.PrincipalId,
	)
	if err != nil {
		// An authorizer error: fail closed, never delete blind.
		return nil, status_grpc.Error(codes.NotFound, "principal not found")
	}
	if !owned {
		// No belongs_to tuple. Either the principal is another tenant's, or it
		// is an orphan: the IdP account exists in THIS tenant's scope but its
		// FGA tuples never landed or were already cleaned. The IdP scopes the
		// list by tenant, so an account that appears there is the caller's to
		// revoke; otherwise answer NotFound (cross-tenant non-existence,
		// gibson#606).
		orphan, lerr := s.serviceAccountInTenantScope(ctx, tenantID, fgaType, accountID)
		if lerr != nil || !orphan {
			return nil, status_grpc.Error(codes.NotFound, "principal not found")
		}
		s.logger.WarnContext(ctx, "RevokeAgentIdentity: principal has no belongs_to tuple; revoking orphaned IdP account",
			slog.String("tenant_id", tenantID),
			slog.String("principal_id", req.PrincipalId),
		)
	}

	// Delete the service account from the IdP.
	if err := s.idpAdminClient.DeleteServiceAccount(ctx, accountID); err != nil {
		if errors.Is(err, idp.ErrNotFound) {
			// Already deleted — idempotent NotFound.
			return nil, status_grpc.Error(codes.NotFound, "principal not found or already revoked")
		}
		s.logger.ErrorContext(ctx, "RevokeAgentIdentity: IdP delete failed",
			slog.String("tenant_id", tenantID),
			slog.String("account_id", accountID),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "failed to revoke identity in identity provider")
	}

	// Delete all FGA tuples where this principal appears (authorizer is
	// guaranteed non-nil — ownership was verified above).
	tuplesToDelete := []authz.Tuple{
		{User: "tenant:" + tenantID, Relation: "belongs_to", Object: req.PrincipalId},
	}
	// Also try to delete the owner tuple. If we don't know the exact owner
	// subject, we use ListUsers to find it first (best-effort).
	if owners, lerr := s.authorizer.ListUsers(ctx, fgaType, req.PrincipalId, "owner"); lerr == nil {
		for _, owner := range owners {
			tuplesToDelete = append(tuplesToDelete, authz.Tuple{
				User:     owner,
				Relation: "owner",
				Object:   req.PrincipalId,
			})
		}
	}
	if derr := s.authorizer.Delete(ctx, tuplesToDelete); derr != nil {
		// Non-fatal: log but don't fail the RPC. The IdP revocation already
		// happened; FGA cleanup can be retried manually.
		s.logger.WarnContext(ctx, "RevokeAgentIdentity: FGA tuple cleanup failed (IdP revocation succeeded)",
			slog.String("tenant_id", tenantID),
			slog.String("principal_id", req.PrincipalId),
			slog.String("error", derr.Error()),
		)
	}

	// Emit audit event.
	if s.tenantAdminAuditWriter != nil {
		s.tenantAdminAuditWriter.Log(audit.Event{
			TenantID:   tenantID,
			ActorID:    callerID.Subject,
			ActorType:  "user",
			Action:     "agent_identity.revoked",
			TargetType: fgaType,
			TargetID:   accountID,
			Decision:   "allow",
		})
	}

	s.logger.InfoContext(ctx, "agent identity revoked",
		slog.String("tenant_id", tenantID),
		slog.String("principal_id", req.PrincipalId),
		slog.String("actor", callerID.Subject),
	)

	return &tenantpb.RevokeAgentIdentityResponse{}, nil
}

// parsePrincipalID splits "agent_principal:some-uuid" into ("some-uuid", "agent_principal").
// Returns an error if the format is invalid or the type is not a known principal type.
func parsePrincipalID(principalID string) (accountID, fgaType string, err error) {
	for _, t := range []string{"agent_principal", "tool_principal", "plugin_principal"} {
		prefix := t + ":"
		if strings.HasPrefix(principalID, prefix) {
			return strings.TrimPrefix(principalID, prefix), t, nil
		}
	}
	return "", "", status_grpc.Errorf(codes.InvalidArgument, "invalid principal_id format: %q", principalID)
}

// serviceAccountInTenantScope reports whether the IdP lists accountID among
// the caller tenant's service accounts of the principal's kind. The IdP list
// is tenant-scoped, so a hit is proof of tenancy when FGA has no tuple.
func (s *DaemonServer) serviceAccountInTenantScope(ctx context.Context, tenantID, fgaType, accountID string) (bool, error) {
	var role idp.Role
	switch fgaType {
	case "agent_principal":
		role = idp.RoleAgent
	case "tool_principal":
		role = idp.RoleTool
	case "plugin_principal":
		role = idp.RolePlugin
	default:
		return false, fmt.Errorf("unknown principal type %q", fgaType)
	}
	pageToken := ""
	for range 100 {
		resp, err := s.idpAdminClient.ListServiceAccounts(ctx, idp.ListServiceAccountsRequest{
			TenantScopeID: tenantID,
			RoleFilter:    role,
			PageToken:     pageToken,
		})
		if err != nil {
			return false, fmt.Errorf("list service accounts for tenant %s: %w", tenantID, err)
		}
		for _, sa := range resp.ServiceAccounts {
			if sa.AccountID == accountID {
				return true, nil
			}
		}
		if resp.NextPageToken == "" {
			return false, nil
		}
		pageToken = resp.NextPageToken
	}
	return false, nil
}
