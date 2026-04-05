package component

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	componentpb "github.com/zero-day-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zero-day-ai/gibson/internal/auth"
)

// DelegateToAgent dispatches a sub-task to another agent and returns its result.
func (s *ComponentServiceServer) DelegateToAgent(ctx context.Context, req *componentpb.DelegateToAgentRequest) (*componentpb.DelegateToAgentResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}
	if s.agentDelegator == nil {
		return nil, status.Error(codes.Unimplemented, "agent delegation not configured")
	}
	resultJSON, err := s.agentDelegator.DelegateToAgent(ctx, tenant, req.GetAgentName(), req.GetTaskJson())
	if err != nil {
		s.logger.Error("DelegateToAgent failed", "tenant", tenant, "agent", req.GetAgentName(), "error", err)
		return nil, status.Errorf(codes.Internal, "delegation failed: %v", err)
	}
	return &componentpb.DelegateToAgentResponse{ResultJson: resultJSON}, nil
}

// ListAgents returns descriptors for all agents visible to the caller's tenant.
func (s *ComponentServiceServer) ListAgents(ctx context.Context, req *componentpb.ListAgentsRequest) (*componentpb.ListAgentsResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}
	if s.componentLister == nil {
		return nil, status.Error(codes.Unimplemented, "component listing not configured")
	}
	agents, err := s.componentLister.ListAgents(ctx, tenant)
	if err != nil {
		s.logger.Error("ListAgents failed", "tenant", tenant, "error", err)
		return nil, status.Errorf(codes.Internal, "list failed: %v", err)
	}
	pbAgents := make([]*componentpb.AgentDescriptorProto, len(agents))
	for i, a := range agents {
		pbAgents[i] = &componentpb.AgentDescriptorProto{
			Name:         a.Name,
			Version:      a.Version,
			Description:  a.Description,
			Capabilities: a.Capabilities,
			TargetTypes:  a.TargetTypes,
		}
	}
	return &componentpb.ListAgentsResponse{Agents: pbAgents}, nil
}

// ListTools returns descriptors for all tools visible to the caller's tenant.
func (s *ComponentServiceServer) ListTools(ctx context.Context, req *componentpb.ListToolsRequest) (*componentpb.ListToolsResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}
	if s.componentLister == nil {
		return nil, status.Error(codes.Unimplemented, "component listing not configured")
	}
	tools, err := s.componentLister.ListTools(ctx, tenant)
	if err != nil {
		s.logger.Error("ListTools failed", "tenant", tenant, "error", err)
		return nil, status.Errorf(codes.Internal, "list failed: %v", err)
	}
	pbTools := make([]*componentpb.ToolDescriptorProto, len(tools))
	for i, t := range tools {
		pbTools[i] = &componentpb.ToolDescriptorProto{
			Name:              t.Name,
			Version:           t.Version,
			Description:       t.Description,
			Tags:              t.Tags,
			InputMessageType:  t.InputMessageType,
			OutputMessageType: t.OutputMessageType,
		}
	}
	return &componentpb.ListToolsResponse{Tools: pbTools}, nil
}
