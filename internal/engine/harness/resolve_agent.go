// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"errors"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/agentcall"
)

// Errors of ResolveAgent. A handler maps them to InvalidArgument, NotFound and
// Unavailable.
var (
	ErrResolveAgentNameRequired = errors.New("resolve agent: the agent name is required")
	ErrResolveAgentNotFound     = errors.New("resolve agent: the agent is not available for this tenant")
	ErrResolveAgentNoGateway    = errors.New("resolve agent: the agent gateway is not configured")
)

// AgentResolution is the answer of ResolveAgent.
type AgentResolution struct {
	// GatewayURL is the JSON-RPC interface URL of the agent on the Agent gateway.
	GatewayURL string
	// RouteHeaders are sent unchanged.
	RouteHeaders map[string]string
	// GatewayCAPEM is the PEM bundle of the private CA of the gateway.
	GatewayCAPEM string
	// AgentCardURL is the Agent Card of the agent on the gateway.
	AgentCardURL string
}

// BuildAgentResolution builds the reply of ResolveAgent for an agent that
// exists. The caller checks the existence. The delegation right is checked at
// the gateway, by ext-authz.
func BuildAgentResolution(tenant, name, bank string, gw GatewayInfo) (*AgentResolution, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrResolveAgentNameRequired
	}
	if gw.URL == "" {
		return nil, ErrResolveAgentNoGateway
	}
	if tenant == "" {
		return nil, errors.New("resolve agent: the tenant is required")
	}
	headers := map[string]string{}
	for _, h := range agentcall.RouteHeaders(tenant, name, bank) {
		headers[h.Name] = h.Value
	}
	return &AgentResolution{
		GatewayURL: gw.URLFor(agentcall.RouteA2A), RouteHeaders: headers, GatewayCAPEM: gw.CAPEM,
		AgentCardURL: gw.URLFor(agentcall.CardPath),
	}, nil
}
