// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package agentcall holds the names that an A2A call to a Gibson agent shares
// between the daemon (ResolveAgent, the A2A listener) and ext-authz. It sits
// next to modelcall, which does the same for a model call.
package agentcall

import (
	"strings"
	"unicode"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

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

// RouteA2A is the path of the A2A JSON-RPC endpoint of an agent on the Agent
// gateway. The Edge removes the /gateway/agent prefix, so the gateway sees the
// root path.
const RouteA2A = "/"

// GrantRoutes returns the routes that a task grant lists so that its holder can
// send an A2A message through the Agent gateway.
func GrantRoutes() []string { return []string{RouteA2A} }

// Reasons that ClaimedRoute gives for a route header that it cannot use.
const (
	ReasonMissingHeader  = "missing_route_header"
	ReasonRepeatedHeader = "repeated_route_header"
	ReasonBadValue       = "bad_route_value"
)

// ClaimedRoute reads the claimed tenant, the target agent and the optional bank
// from the headers of a request. The tenant and the agent are required. A
// header that is repeated arrives as one value with a comma, and it is refused.
// A value with a slash, a space or a control character is refused, because the
// agent and the bank name FGA objects.
func ClaimedRoute(headers map[string]string) (tenant, agent, bank, reason string) {
	tenant, reason = modelcall.ClaimedRouteTenant(headers)
	if reason != "" {
		return "", "", "", reason
	}
	agent, reason = readValue(headers, HeaderRouteAgent, true)
	if reason != "" {
		return "", "", "", reason
	}
	bank, reason = readValue(headers, HeaderRouteBank, false)
	if reason != "" {
		return "", "", "", reason
	}
	return tenant, agent, bank, ""
}

func readValue(headers map[string]string, name string, required bool) (string, string) {
	v := strings.TrimSpace(headers[name])
	switch {
	case v == "" && required:
		return "", ReasonMissingHeader
	case v == "":
		return "", ""
	case strings.Contains(v, ","):
		return "", ReasonRepeatedHeader
	case strings.ContainsFunc(v, func(r rune) bool {
		return r == '/' || r == '#' || r == ':' || unicode.IsSpace(r) || unicode.IsControl(r)
	}):
		return "", ReasonBadValue
	}
	return v, ""
}

const (
	cardPrefix = "/agents/"
	cardSuffix = CardPath
)

// CardPathName returns the agent name of an Agent Card path of the form
// /agents/<name>/.well-known/agent-card.json. It returns false for any other
// path.
func CardPathName(path string) (string, bool) {
	rest, ok := strings.CutPrefix(path, cardPrefix)
	if !ok {
		return "", false
	}
	name, ok := strings.CutSuffix(rest, cardSuffix)
	if !ok || name == "" || strings.Contains(name, "/") {
		return "", false
	}
	return name, true
}

// IsA2APath reports whether path is the A2A endpoint or the Agent Card of an
// agent.
func IsA2APath(path string) bool {
	if path == RouteA2A {
		return true
	}
	_, ok := CardPathName(path)
	return ok
}
