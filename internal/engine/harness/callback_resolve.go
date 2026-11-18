// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
)

// WithModelGateway sets the public model gateway that ResolveModel returns.
func WithModelGateway(gw GatewayInfo) CallbackServiceOption {
	return func(s *HarnessCallbackService) { s.modelGateway = gw }
}

// WithAgentGateway sets the public Agent gateway that ResolveAgent returns.
func WithAgentGateway(gw GatewayInfo) CallbackServiceOption {
	return func(s *HarnessCallbackService) { s.agentGateway = gw }
}

// ResolveModel resolves a slot of the run to one exact model name and gives
// the agent what it needs to call the model gateway (gibson#1392).
func (s *HarnessCallbackService) ResolveModel(
	ctx context.Context, req *harnesspb.ResolveModelRequest,
) (*harnesspb.ResolveModelResponse, error) {
	h, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	res, err := ResolveModel(ctx, h, auth.TenantStringFromContext(ctx), req.GetSlot(), s.modelGateway)
	if err != nil {
		return nil, ResolveModelStatus(err)
	}
	return &harnesspb.ResolveModelResponse{
		Model: res.Model, Provider: res.Provider, GatewayUrl: res.GatewayURL, RouteHeaders: res.RouteHeaders,
		ContextWindow: res.ContextWindow, MaxOutputTokens: res.MaxOutputTokens, GatewayCaPem: res.GatewayCAPEM,
	}, nil
}

// ResolveModelStatus maps an error of ResolveModel to a gRPC status.
func ResolveModelStatus(err error) error {
	switch {
	case errors.Is(err, ErrResolveSlotRequired):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, ErrResolveNoGateway):
		return status.Error(codes.Unavailable, err.Error())
	case errors.Is(err, ErrResolveNoModel):
		return status.Error(codes.NotFound, err.Error())
	default:
		return status.Error(codes.PermissionDenied, err.Error())
	}
}

// ResolveAgent gives the agent the route of a target agent on the Agent
// gateway. The delegation right is checked at the gateway.
func (s *HarnessCallbackService) ResolveAgent(
	ctx context.Context, req *harnesspb.ResolveAgentRequest,
) (*harnesspb.ResolveAgentResponse, error) {
	if _, err := s.getHarness(ctx, req.GetContext()); err != nil {
		return nil, err
	}
	tenant := auth.TenantStringFromContext(ctx)
	if req.GetName() != "" {
		exists, err := s.agentExists(ctx, tenant, req.GetName())
		if err != nil {
			return nil, status.Error(codes.Unavailable, "resolve agent: "+err.Error())
		}
		if !exists {
			return nil, ResolveAgentStatus(ErrResolveAgentNotFound)
		}
	}
	res, err := BuildAgentResolution(tenant, req.GetName(), req.GetBankId(), s.agentGateway)
	if err != nil {
		return nil, ResolveAgentStatus(err)
	}
	return &harnesspb.ResolveAgentResponse{
		GatewayUrl: res.GatewayURL, RouteHeaders: res.RouteHeaders, GatewayCaPem: res.GatewayCAPEM,
		AgentCardUrl: res.AgentCardURL,
	}, nil
}

// ResolveAgentStatus maps an error of BuildAgentResolution to a gRPC status.
func ResolveAgentStatus(err error) error {
	switch {
	case errors.Is(err, ErrResolveAgentNameRequired):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, ErrResolveAgentNoGateway):
		return status.Error(codes.Unavailable, err.Error())
	case errors.Is(err, ErrResolveAgentNotFound):
		return status.Error(codes.NotFound, err.Error())
	default:
		return status.Error(codes.PermissionDenied, err.Error())
	}
}

// agentExists reports whether the tenant can reach an agent of this name: a
// live registered agent or an agent of the catalog.
func (s *HarnessCallbackService) agentExists(ctx context.Context, tenant, name string) (bool, error) {
	if _, ok := componentcatalog.LookupAgent(name); ok {
		return true, nil
	}
	if s.componentRegistry == nil {
		return false, nil
	}
	instances, err := s.componentRegistry.Discover(ctx, tenant, "agent", name)
	if err != nil {
		return false, err //nolint:wrapcheck // the handler wraps it
	}
	return len(instances) > 0, nil
}
