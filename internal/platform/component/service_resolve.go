// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/llm/modelgate"
	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/agentcall"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// ResolvedSlot is the model that a slot uses. The model is one exact name.
type ResolvedSlot struct {
	Provider string
	Model    string
	// ContextWindow is in tokens. Zero means unknown.
	ContextWindow int
}

// SlotModelResolver resolves a slot to a provider and one exact model name in
// the provider set of a tenant. The pin is the slot pin of the mission node
// that dispatched the work. Nil means no pin. The resolution applies the model
// access gate. It makes no model call.
type SlotModelResolver interface {
	ResolveSlotModel(ctx context.Context, tenant, slot string, pin *agent.SlotConfig) (ResolvedSlot, error)
}

// GatewayInfo is a public gateway that an agent calls: its base URL and the
// PEM bundle of the private CA that signs its certificate. An empty bundle
// means the system roots.
type GatewayInfo struct {
	URL   string
	CAPEM string
}

// WithSlotModelResolver sets the resolver that ResolveModel uses.
func (s *ComponentServiceServer) WithSlotModelResolver(r SlotModelResolver) *ComponentServiceServer {
	s.slotModels = r
	return s
}

// WithGateways sets the public model gateway and Agent gateway that
// ResolveModel and ResolveAgent return.
func (s *ComponentServiceServer) WithGateways(model, agentGW GatewayInfo) *ComponentServiceServer {
	s.modelGateway, s.agentGateway = model, agentGW
	return s
}

// ResolveModel resolves a slot of the work item to one exact model name and
// gives the agent what it needs to call the model gateway.
func (s *ComponentServiceServer) ResolveModel(
	ctx context.Context, req *componentpb.ResolveModelRequest,
) (*componentpb.ResolveModelResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}
	slot := strings.TrimSpace(req.GetSlot())
	if slot == "" {
		return nil, status.Error(codes.InvalidArgument, "slot is required")
	}
	if s.slotModels == nil || s.modelGateway.URL == "" {
		return nil, status.Error(codes.Unavailable, "the model gateway is not configured on this server")
	}
	owner, err := s.claimedWorkOwner(ctx, tenant, req.GetWorkId())
	if err != nil {
		return nil, err
	}
	pin, err := s.nodeSlotPin(ctx, tenant, owner, req.GetWorkId(), slot)
	if err != nil {
		return nil, err
	}
	picked, err := s.slotModels.ResolveSlotModel(ctx, tenant, slot, pin)
	if err != nil {
		if errors.Is(err, modelgate.ErrDenied) && !errors.Is(err, modelgate.ErrUnavailable) {
			return nil, status.Errorf(codes.PermissionDenied, "slot %q: the model gate refused the model", slot)
		}
		s.logger.WarnContext(ctx, "resolve model: the slot has no model", "slot", slot, "error", err.Error())
		return nil, status.Errorf(codes.NotFound, "slot %q has no model", slot)
	}
	if picked.Model == "" || picked.Provider == "" {
		return nil, status.Errorf(codes.NotFound, "slot %q has no model", slot)
	}
	headers := map[string]string{}
	for _, h := range modelcall.RouteHeaders(tenant, picked.Provider) {
		headers[h.Name] = h.Value
	}
	return &componentpb.ResolveModelResponse{
		Model: picked.Model, Provider: picked.Provider, GatewayUrl: strings.TrimRight(s.modelGateway.URL, "/"),
		RouteHeaders: headers, ContextWindow: int32(picked.ContextWindow), //nolint:gosec // bounded at save
		GatewayCaPem: s.modelGateway.CAPEM,
	}, nil
}

// ResolveAgent gives the agent the route of a target agent on the Agent
// gateway. The delegation right is checked at the gateway.
func (s *ComponentServiceServer) ResolveAgent(
	ctx context.Context, req *componentpb.ResolveAgentRequest,
) (*componentpb.ResolveAgentResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}
	name := strings.TrimSpace(req.GetName())
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if s.agentGateway.URL == "" {
		return nil, status.Error(codes.Unavailable, "the agent gateway is not configured on this server")
	}
	if _, err := s.claimedWorkOwner(ctx, tenant, req.GetWorkId()); err != nil {
		return nil, err
	}
	if _, ok := componentcatalog.LookupAgent(name); !ok {
		instances, err := s.registry.Discover(ctx, tenant, "agent", name)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "resolve agent: %v", err)
		}
		if len(instances) == 0 {
			return nil, status.Errorf(codes.NotFound, "agent %q is not available for this tenant", name)
		}
	}
	headers := map[string]string{}
	for _, h := range agentcall.RouteHeaders(tenant, name, req.GetBankId()) {
		headers[h.Name] = h.Value
	}
	base := strings.TrimRight(s.agentGateway.URL, "/")
	return &componentpb.ResolveAgentResponse{
		GatewayUrl: base, RouteHeaders: headers, GatewayCaPem: s.agentGateway.CAPEM,
		AgentCardUrl: base + agentcall.CardPath,
	}, nil
}
