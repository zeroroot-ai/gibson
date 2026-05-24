// Package api — tenant_admin_list.go implements TenantAdminService.ListAgentIdentities.
package api

import (
	"context"
	"log/slog"

	"github.com/zero-day-ai/gibson/internal/idp"
	tenantpb "github.com/zero-day-ai/sdk/api/gen/gibson/tenant/v1"
	"github.com/zero-day-ai/sdk/auth"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	defaultPageSize = 50
	maxPageSize     = 200
)

// ListAgentIdentities returns all agent/tool/plugin identities in the caller's tenant.
func (s *DaemonServer) ListAgentIdentities(ctx context.Context, req *tenantpb.ListAgentIdentitiesRequest) (*tenantpb.ListAgentIdentitiesResponse, error) {
	if _, err := auth.IdentityFromContext(ctx); err != nil {
		return nil, status_grpc.Error(codes.Unauthenticated, "not authenticated")
	}

	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant ID not found in request context")
	}

	if s.idpAdminClient == nil {
		return nil, status_grpc.Error(codes.Unavailable,
			"identity provider not configured; set GIBSON_IDP_PROVIDER and related env vars")
	}

	// Normalise pagination parameters.
	pageSize := int(req.PageSize)
	if pageSize <= 0 {
		pageSize = defaultPageSize
	} else if pageSize > maxPageSize {
		pageSize = maxPageSize
	}

	// Map proto kind filter to idp role filter.
	var roleFilter idp.Role
	if req.KindFilter != tenantpb.PrincipalKind_PRINCIPAL_KIND_UNSPECIFIED {
		var fgaType string
		var err error
		roleFilter, fgaType, err = principalKindToRole(req.KindFilter)
		if err != nil {
			return nil, status_grpc.Error(codes.InvalidArgument, err.Error())
		}
		_ = fgaType
	}

	listReq := idp.ListServiceAccountsRequest{
		TenantScopeID: tenantID,
		PageSize:      pageSize,
		PageToken:     req.PageToken,
		RoleFilter:    roleFilter,
	}

	resp, err := s.idpAdminClient.ListServiceAccounts(ctx, listReq)
	if err != nil {
		s.logger.ErrorContext(ctx, "ListAgentIdentities: IdP list failed",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "failed to list identities from identity provider")
	}

	identities := make([]*tenantpb.AgentIdentity, 0, len(resp.ServiceAccounts))
	for _, sa := range resp.ServiceAccounts {
		kind := roleToProtoKind(sa.Role)
		entry := &tenantpb.AgentIdentity{
			PrincipalId: idpRoleFGAType(sa.Role) + ":" + sa.AccountID,
			Kind:        kind,
			Name:        sa.Name,
			Description: sa.Description,
			CreatedAt:   timestamppb.New(sa.CreatedAt),
			// LastAuthenticatedAt is nil when IdP doesn't track it; proto null
			// is the zero value so we leave it unset when nil.
		}
		if sa.LastAuthenticatedAt != nil {
			entry.LastAuthenticatedAt = timestamppb.New(*sa.LastAuthenticatedAt)
		}
		identities = append(identities, entry)
	}

	return &tenantpb.ListAgentIdentitiesResponse{
		Identities:    identities,
		NextPageToken: resp.NextPageToken,
	}, nil
}

// roleToProtoKind converts an idp.Role to a proto PrincipalKind.
func roleToProtoKind(r idp.Role) tenantpb.PrincipalKind {
	switch r {
	case idp.RoleAgent:
		return tenantpb.PrincipalKind_PRINCIPAL_KIND_AGENT
	case idp.RoleTool:
		return tenantpb.PrincipalKind_PRINCIPAL_KIND_TOOL
	case idp.RolePlugin:
		return tenantpb.PrincipalKind_PRINCIPAL_KIND_PLUGIN
	default:
		return tenantpb.PrincipalKind_PRINCIPAL_KIND_UNSPECIFIED
	}
}

// idpRoleFGAType returns the FGA type string for a given role.
func idpRoleFGAType(r idp.Role) string {
	switch r {
	case idp.RoleAgent:
		return "agent_principal"
	case idp.RoleTool:
		return "tool_principal"
	case idp.RolePlugin:
		return "plugin_principal"
	default:
		return "agent_principal"
	}
}
