// Package api — server_capabilitygrant.go
//
// This file implements the Agent Auth Protocol gRPC handlers introduced in
// agent-auth-fga-integration:
//
//   - RegisterCapabilityGrant
//   - ExecuteAgentCapability
//   - ListAgentCapabilities
//   - GetCapabilityGrantStatus
//   - RevokeCapabilityGrant
//   - ListCapabilityGrantAgents
//   - CreateHostRegistrationToken
//   - ListComponentGrants
//   - BatchGrantComponentAccessV2
//   - ListAuditLog
//
// Each handler follows the thin-wrapper pattern: validate the request, delegate
// to capabilityGrantService (which holds the real logic), map domain results back to
// proto response types.
//
// Error mapping:
//
//	capabilityGrantService not wired     → codes.Unavailable
//	missing required fields         → codes.InvalidArgument
//	agent/resource not found        → codes.NotFound
//	FGA permission denied           → codes.PermissionDenied
//	everything else                 → codes.Internal
package api

import (
	"context"
	"encoding/json"
	"log/slog"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/capabilitygrant"
	"github.com/zero-day-ai/gibson/internal/identity"
)

// ---------------------------------------------------------------------------
// RegisterCapabilityGrant
// ---------------------------------------------------------------------------

// RegisterCapabilityGrant upserts a host record, creates an agent record, resolves
// FGA capability grants, writes grants to the store, and emits an audit event.
func (s *DaemonServer) RegisterCapabilityGrant(ctx context.Context, req *RegisterCapabilityGrantRequest) (*RegisterCapabilityGrantResponse, error) {
	if s.capabilityGrantService == nil {
		return nil, status_grpc.Error(codes.Unavailable, "agent auth service not configured")
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = identity.TenantFromContext(ctx)
	}
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}
	if req.GetOwnerUserId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "owner_user_id is required")
	}
	if req.GetAgentName() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "agent_name is required")
	}

	result, err := s.capabilityGrantService.RegisterCapabilityGrant(
		ctx,
		tenantID,
		req.GetOwnerUserId(),
		req.GetAgentName(),
		req.GetAgentMode(),
		json.RawMessage(req.GetHostPublicKeyJwk()),
		json.RawMessage(req.GetAgentPublicKeyJwk()),
		req.GetBootstrapType(),
		req.GetBootstrapCredential(),
	)
	if err != nil {
		s.logger.ErrorContext(ctx, "RegisterCapabilityGrant: service error",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "failed to register agent")
	}

	caps := make([]*AgentCapabilityGrant, 0, len(result.Capabilities))
	for _, c := range result.Capabilities {
		caps = append(caps, &AgentCapabilityGrant{
			CapabilityName: c.Name,
			ComponentRef:   c.ComponentRef,
			Description:    c.Description,
		})
	}

	return &RegisterCapabilityGrantResponse{
		AgentId:      result.AgentID,
		HostId:       result.HostID,
		Capabilities: caps,
		Status:       result.Status,
	}, nil
}

// ---------------------------------------------------------------------------
// ExecuteAgentCapability
// ---------------------------------------------------------------------------

// ExecuteAgentCapability checks FGA permission, records an audit event, and
// dispatches the request to the target component via the ComponentDispatcher.
func (s *DaemonServer) ExecuteAgentCapability(ctx context.Context, req *ExecuteAgentCapabilityRequest) (*ExecuteAgentCapabilityResponse, error) {
	if s.capabilityGrantService == nil {
		return nil, status_grpc.Error(codes.Unavailable, "agent auth service not configured")
	}
	if req.GetAgentId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "agent_id is required")
	}
	if req.GetCapabilityName() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "capability_name is required")
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = identity.TenantFromContext(ctx)
	}

	result, err := s.capabilityGrantService.ExecuteAgentCapability(
		ctx,
		req.GetAgentId(),
		req.GetCapabilityName(),
		req.GetArguments(),
		tenantID,
	)
	if err != nil {
		s.logger.ErrorContext(ctx, "ExecuteAgentCapability: service error",
			slog.String("agent_id", req.GetAgentId()),
			slog.String("capability", req.GetCapabilityName()),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "capability execution failed")
	}

	if result.Status == "error" && result.ErrorMessage == "permission denied: insufficient FGA grants" {
		return nil, status_grpc.Error(codes.PermissionDenied, result.ErrorMessage)
	}

	return &ExecuteAgentCapabilityResponse{
		Result:       result.Result,
		Status:       result.Status,
		ErrorMessage: result.ErrorMessage,
	}, nil
}

// ---------------------------------------------------------------------------
// ListAgentCapabilities
// ---------------------------------------------------------------------------

// ListAgentCapabilities resolves FGA capabilities for a user and returns them.
func (s *DaemonServer) ListAgentCapabilities(ctx context.Context, req *ListAgentCapabilitiesRequest) (*ListAgentCapabilitiesResponse, error) {
	if s.capabilityGrantService == nil {
		return nil, status_grpc.Error(codes.Unavailable, "agent auth service not configured")
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = identity.TenantFromContext(ctx)
	}
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}
	if req.GetUserId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "user_id is required")
	}

	caps, err := s.capabilityGrantService.ListAgentCapabilities(ctx, tenantID, req.GetUserId())
	if err != nil {
		s.logger.ErrorContext(ctx, "ListAgentCapabilities: service error",
			slog.String("tenant_id", tenantID),
			slog.String("user_id", req.GetUserId()),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "failed to list capabilities")
	}

	pbCaps := make([]*AgentCapabilityGrant, 0, len(caps))
	for _, c := range caps {
		pbCaps = append(pbCaps, &AgentCapabilityGrant{
			CapabilityName: c.Name,
			ComponentRef:   c.ComponentRef,
			Description:    c.Description,
		})
	}

	return &ListAgentCapabilitiesResponse{
		Capabilities: pbCaps,
	}, nil
}

// ---------------------------------------------------------------------------
// GetCapabilityGrantStatus
// ---------------------------------------------------------------------------

// GetCapabilityGrantStatus returns the current agent status and its capability grants.
func (s *DaemonServer) GetCapabilityGrantStatus(ctx context.Context, req *GetCapabilityGrantStatusRequest) (*GetCapabilityGrantStatusResponse, error) {
	if s.capabilityGrantService == nil {
		return nil, status_grpc.Error(codes.Unavailable, "agent auth service not configured")
	}
	if req.GetAgentId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "agent_id is required")
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = identity.TenantFromContext(ctx)
	}

	result, err := s.capabilityGrantService.GetCapabilityGrantStatus(ctx, req.GetAgentId(), tenantID)
	if err != nil {
		s.logger.ErrorContext(ctx, "GetCapabilityGrantStatus: service error",
			slog.String("agent_id", req.GetAgentId()),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "failed to get agent status")
	}
	if result == nil {
		return nil, status_grpc.Error(codes.NotFound, "agent not found")
	}

	// Build capability grant list from store grants.
	caps := make([]*AgentCapabilityGrant, 0, len(result.Grants))
	for _, g := range result.Grants {
		caps = append(caps, &AgentCapabilityGrant{
			CapabilityName: g.CapabilityName,
			ComponentRef:   g.ComponentRef,
		})
	}

	ag := result.Agent
	var lastActiveUnix int64
	if ag.LastActiveAt != nil {
		lastActiveUnix = ag.LastActiveAt.Unix()
	}

	return &GetCapabilityGrantStatusResponse{
		AgentId:      ag.ID,
		HostId:       ag.HostID,
		Status:       ag.Status,
		Mode:         ag.Mode,
		OwnerUserId:  ag.UserID,
		Capabilities: caps,
		LastActiveAt: lastActiveUnix,
		CreatedAt:    ag.CreatedAt.Unix(),
	}, nil
}

// ---------------------------------------------------------------------------
// RevokeCapabilityGrant
// ---------------------------------------------------------------------------

// RevokeCapabilityGrant revokes the agent, all its grants, and emits an audit event.
func (s *DaemonServer) RevokeCapabilityGrant(ctx context.Context, req *RevokeCapabilityGrantRequest) (*RevokeCapabilityGrantResponse, error) {
	if s.capabilityGrantService == nil {
		return nil, status_grpc.Error(codes.Unavailable, "agent auth service not configured")
	}
	if req.GetAgentId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "agent_id is required")
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = identity.TenantFromContext(ctx)
	}

	// Extract actor ID from the auth context for audit.
	actorID := ""
	if id, err := identity.IdentityFromContext(ctx); err == nil {
		actorID = id.Subject
	}

	if err := s.capabilityGrantService.RevokeCapabilityGrant(ctx, req.GetAgentId(), tenantID, actorID); err != nil {
		s.logger.ErrorContext(ctx, "RevokeCapabilityGrant: service error",
			slog.String("agent_id", req.GetAgentId()),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "failed to revoke agent")
	}

	return &RevokeCapabilityGrantResponse{}, nil
}

// ---------------------------------------------------------------------------
// ListCapabilityGrantAgents
// ---------------------------------------------------------------------------

// ListCapabilityGrantAgents returns a paginated list of agents registered in a tenant.
func (s *DaemonServer) ListCapabilityGrantAgents(ctx context.Context, req *ListCapabilityGrantAgentsRequest) (*ListCapabilityGrantAgentsResponse, error) {
	if s.capabilityGrantService == nil {
		return nil, status_grpc.Error(codes.Unavailable, "agent auth service not configured")
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = identity.TenantFromContext(ctx)
	}
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}

	result, err := s.capabilityGrantService.ListCapabilityGrantAgents(
		ctx,
		tenantID,
		int(req.GetLimit()),
		int(req.GetOffset()),
	)
	if err != nil {
		s.logger.ErrorContext(ctx, "ListCapabilityGrantAgents: service error",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "failed to list agents")
	}

	pbAgents := make([]*GetCapabilityGrantStatusResponse, 0, len(result.Agents))
	for _, ag := range result.Agents {
		var lastActiveUnix int64
		if ag.LastActiveAt != nil {
			lastActiveUnix = ag.LastActiveAt.Unix()
		}
		pbAgents = append(pbAgents, &GetCapabilityGrantStatusResponse{
			AgentId:      ag.ID,
			HostId:       ag.HostID,
			Status:       ag.Status,
			Mode:         ag.Mode,
			OwnerUserId:  ag.UserID,
			LastActiveAt: lastActiveUnix,
			CreatedAt:    ag.CreatedAt.Unix(),
		})
	}

	return &ListCapabilityGrantAgentsResponse{
		Agents: pbAgents,
		Total:  int32(result.Total),
	}, nil
}

// ---------------------------------------------------------------------------
// CreateHostRegistrationToken
// ---------------------------------------------------------------------------

// CreateHostRegistrationToken issues a single-use host API key for the tenant.
func (s *DaemonServer) CreateHostRegistrationToken(ctx context.Context, req *CreateHostRegistrationTokenRequest) (*CreateHostRegistrationTokenResponse, error) {
	if s.capabilityGrantService == nil {
		return nil, status_grpc.Error(codes.Unavailable, "agent auth service not configured")
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = identity.TenantFromContext(ctx)
	}
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}

	// Extract actor ID for the key's created_by field.
	createdBy := ""
	if id, err := identity.IdentityFromContext(ctx); err == nil {
		createdBy = id.Subject
	}

	result, err := s.capabilityGrantService.CreateHostRegistrationToken(
		ctx,
		tenantID,
		req.GetName(),
		createdBy,
		int(req.GetTtlHours()),
	)
	if err != nil {
		s.logger.ErrorContext(ctx, "CreateHostRegistrationToken: service error",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "failed to create host registration token")
	}

	return &CreateHostRegistrationTokenResponse{
		RawToken:  result.RawToken,
		KeyId:     result.KeyID,
		ExpiresAt: result.ExpiresAt.Unix(),
	}, nil
}

// ---------------------------------------------------------------------------
// ListComponentGrants
// ---------------------------------------------------------------------------

// ListComponentGrants enumerates FGA component grants for all users in a tenant.
func (s *DaemonServer) ListComponentGrants(ctx context.Context, req *ListComponentGrantsRequest) (*ListComponentGrantsResponse, error) {
	if s.capabilityGrantService == nil {
		return nil, status_grpc.Error(codes.Unavailable, "agent auth service not configured")
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = identity.TenantFromContext(ctx)
	}
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}

	grants, err := s.capabilityGrantService.ListComponentGrants(ctx, tenantID)
	if err != nil {
		s.logger.ErrorContext(ctx, "ListComponentGrants: service error",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "failed to list component grants")
	}

	pbGrants := make([]*AgentComponentGrant, 0, len(grants))
	for _, g := range grants {
		pbGrants = append(pbGrants, &AgentComponentGrant{
			UserId:       g.UserID,
			ComponentRef: g.ComponentRef,
			CanExecute:   g.CanExecute,
			CanConfigure: g.CanConfigure,
			CanRead:      g.CanRead,
			GrantSource:  g.GrantSource,
		})
	}

	return &ListComponentGrantsResponse{
		Grants: pbGrants,
	}, nil
}

// ---------------------------------------------------------------------------
// BatchGrantComponentAccessV2
// ---------------------------------------------------------------------------

// BatchGrantComponentAccessV2 applies bulk FGA grant/revoke operations.
func (s *DaemonServer) BatchGrantComponentAccessV2(ctx context.Context, req *BatchGrantComponentAccessV2Request) (*BatchGrantComponentAccessV2Response, error) {
	if s.capabilityGrantService == nil {
		return nil, status_grpc.Error(codes.Unavailable, "agent auth service not configured")
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = identity.TenantFromContext(ctx)
	}
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}
	if len(req.GetChanges()) == 0 {
		return &BatchGrantComponentAccessV2Response{Applied: 0}, nil
	}

	actorID := ""
	if id, err := identity.IdentityFromContext(ctx); err == nil {
		actorID = id.Subject
	}

	changes := make([]capabilitygrant.GrantChangeV2, 0, len(req.GetChanges()))
	for _, c := range req.GetChanges() {
		changes = append(changes, capabilitygrant.GrantChangeV2{
			UserID:        c.GetUserId(),
			PrincipalType: c.GetPrincipalType(),
			ComponentRef:  c.GetComponentRef(),
			Action:        c.GetAction(),
			Grant:         c.GetGrant(),
		})
	}

	applied, err := s.capabilityGrantService.BatchGrantComponentAccessV2(ctx, tenantID, actorID, changes)
	if err != nil {
		s.logger.ErrorContext(ctx, "BatchGrantComponentAccessV2: service error",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "batch grant operation failed")
	}

	return &BatchGrantComponentAccessV2Response{
		Applied: int32(applied),
	}, nil
}

// ---------------------------------------------------------------------------
// ListAuditLog
// ---------------------------------------------------------------------------

// ListAuditLog returns paginated Postgres audit log entries for a tenant.
func (s *DaemonServer) ListAuditLog(ctx context.Context, req *ListAuditLogRequest) (*ListAuditLogResponse, error) {
	if s.capabilityGrantService == nil {
		return nil, status_grpc.Error(codes.Unavailable, "agent auth service not configured")
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = identity.TenantFromContext(ctx)
	}
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}

	entries, total, err := s.capabilityGrantService.ListAuditLog(
		ctx,
		tenantID,
		req.GetActorId(),
		req.GetAction(),
		req.GetTargetType(),
		int(req.GetLimit()),
		int(req.GetOffset()),
	)
	if err != nil {
		s.logger.ErrorContext(ctx, "ListAuditLog: service error",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "failed to query audit log")
	}

	pbEntries := make([]*AuditLogEntry, 0, len(entries))
	for _, e := range entries {
		pbEntries = append(pbEntries, &AuditLogEntry{
			Id:         e.ID,
			ActorId:    e.ActorID,
			ActorType:  e.ActorType,
			Action:     e.Action,
			TargetType: e.TargetType,
			TargetId:   e.TargetID,
			Decision:   e.Decision,
			Metadata:   []byte(e.Metadata),
			CreatedAt:  e.CreatedAt.Unix(),
		})
	}

	return &ListAuditLogResponse{
		Entries: pbEntries,
		Total:   int32(total),
	}, nil
}
