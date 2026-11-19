// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package agentcall holds the names that an A2A call to a Gibson agent shares
// between the daemon (ResolveAgent, the A2A listener) and ext-authz. It sits
// next to modelcall, which does the same for a model call.
package agentcall

import (
	"regexp"
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

func readValue(headers map[string]string, name string, required bool) (value, reason string) {
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

// CardPathFor returns the Agent Card path of one agent,
// /agents/<name>/.well-known/agent-card.json. It is the one writer of the form
// that CardPathName reads.
func CardPathFor(name string) string { return cardPrefix + name + cardSuffix }

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

// The inbound A2A path (epic gibson#1367). An outside A2A client calls a Gibson
// agent through the Edge, and the call does not cross the Agent gateway. The
// agent is a segment of the path, because the Edge sets no route header for it.
// ext-authz and the daemon read the agent with InboundPathAgent, so they cannot
// disagree about it.
const (
	// InboundPrefix is the path prefix that the Edge routes to the daemon.
	InboundPrefix = "/a2a/inbound/"
)

// inboundAgentPattern is a DNS label. The same rule holds for the agent name of
// a published mission definition.
var inboundAgentPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// InboundPathFor returns the path of the A2A JSON-RPC endpoint of one published
// agent.
func InboundPathFor(agent string) string { return InboundPrefix + agent }

// InboundCardPathFor returns the path of the Agent Card of one published agent.
func InboundCardPathFor(agent string) string { return InboundPathFor(agent) + CardPath }

// IsInboundPath reports whether a path is on the inbound prefix. It says nothing
// about the rest of the path.
func IsInboundPath(path string) bool { return strings.HasPrefix(path, InboundPrefix) }

// InboundPathAgent returns the agent name of an inbound path and whether the
// path is the Agent Card of the agent. The two forms are /a2a/inbound/<agent>
// and /a2a/inbound/<agent>/.well-known/agent-card.json. It returns ok=false for
// any other path, and for a name that is not a DNS label.
func InboundPathAgent(path string) (agent string, card, ok bool) {
	rest, found := strings.CutPrefix(path, InboundPrefix)
	if !found {
		return "", false, false
	}
	if name, isCard := strings.CutSuffix(rest, CardPath); isCard {
		rest, card = name, true
	}
	if !inboundAgentPattern.MatchString(rest) {
		return "", false, false
	}
	return rest, card, true
}
