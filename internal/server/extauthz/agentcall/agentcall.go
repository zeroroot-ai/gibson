// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package agentcall holds the names that an A2A call to a Gibson agent shares
// between the daemon (ResolveAgent, the A2A listener) and ext-authz. It sits
// next to modelcall, which does the same for a model call.
package agentcall

import "github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"

// The route headers of an agent call. The caller claims its tenant with
// modelcall.HeaderRouteTenant. These two name the target.
const (
	// HeaderRouteAgent names the agent that receives the message.
	HeaderRouteAgent = "x-gibson-route-agent"
	// HeaderRouteBank names the bank that runs the agent. Optional. Unset
	// means an ephemeral agent.
	HeaderRouteBank = "x-gibson-route-bank"
)

// RouteHeaders returns the headers that select the route of one agent call. An
// empty bank id adds no bank header.
func RouteHeaders(tenant, agent, bank string) []modelcall.RouteHeader {
	h := []modelcall.RouteHeader{
		{Name: modelcall.HeaderRouteTenant, Value: tenant},
		{Name: HeaderRouteAgent, Value: agent},
	}
	if bank != "" {
		h = append(h, modelcall.RouteHeader{Name: HeaderRouteBank, Value: bank})
	}
	return h
}

// CardPath is the path of the Agent Card on the agent listener.
const CardPath = "/.well-known/agent-card.json"
