// Package api — tenant_admin_list.go implements TenantAdminService.ListAgentIdentities.
package api

import (
	"context"
	"log/slog"

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	tenantpb "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
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

	// FGA is the tenancy authority. Machine users live in a single shared IdP
	// org, so the IdP listing below is NOT tenant-scoped — we MUST filter it to
	// the principals FGA says belong to this tenant
	// (`tenant:<id> belongs_to <kind>_principal:<sub>`). Without the authorizer
	// we cannot scope safely, so fail closed rather than leak every tenant's
	// identities (gibson#606). The username prefix is a naming convention, not
	// an isolation boundary, and must never be used for scoping.
	if s.authorizer == nil {
		return nil, status_grpc.Error(codes.Unavailable, "authorization not configured")
	}
	allowed, err := s.tenantPrincipalSet(ctx, tenantID, req.KindFilter)
	if err != nil {
		s.logger.ErrorContext(ctx, "ListAgentIdentities: FGA scope lookup failed",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "failed to resolve tenant identities")
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
		principalID := idpRoleFGAType(sa.Role) + ":" + sa.AccountID
		// Drop any service account FGA does not attribute to this tenant. The
		// IdP list spans the shared org; this is the isolation boundary.
		if !allowed[principalID] {
			continue
		}
		kind := roleToProtoKind(sa.Role)
		entry := &tenantpb.AgentIdentity{
			PrincipalId: principalID,
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

// tenantPrincipalSet returns the set of FGA principal IDs
// ("<kind>_principal:<sub>") that belong to the given tenant, via the
// `tenant:<id> belongs_to <kind>_principal:<sub>` tuples written at
// registration. When kindFilter is set, only that principal type is queried;
// otherwise all three are unioned. This set is the authoritative tenant scope
// for ListAgentIdentities.
func (s *DaemonServer) tenantPrincipalSet(ctx context.Context, tenantID string, kindFilter tenantpb.PrincipalKind) (map[string]bool, error) {
	fgaTypes := []string{"agent_principal", "tool_principal", "plugin_principal"}
	if kindFilter != tenantpb.PrincipalKind_PRINCIPAL_KIND_UNSPECIFIED {
		_, fgaType, err := principalKindToRole(kindFilter)
		if err != nil {
			return nil, err
		}
		fgaTypes = []string{fgaType}
	}

	user := "tenant:" + tenantID
	set := make(map[string]bool)
	for _, fgaType := range fgaTypes {
		objects, err := s.authorizer.ListObjects(ctx, user, "belongs_to", fgaType)
		if err != nil {
			return nil, err
		}
		for _, obj := range objects {
			set[obj] = true
		}
	}
	return set, nil
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
