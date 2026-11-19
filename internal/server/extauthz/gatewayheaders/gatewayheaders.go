// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package gatewayheaders holds the one list of the Gibson headers that a route
// of the model gateway or of the agent gateway removes before a call leaves
// Gibson. The renderers of the tenant operator use it for each route.
package gatewayheaders

import (
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/agentcall"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/headers"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

// HeaderCapabilityGrant is the header of the Capability Grant of the caller.
const HeaderCapabilityGrant = "x-capability-grant"

// Trusted returns the headers that ext-authz sets on an allowed gateway call.
// A caller never sends them.
func Trusted() []string {
	return []string{
		modelcall.HeaderTenant, modelcall.HeaderSubject, modelcall.HeaderMission, modelcall.HeaderTask,
	}
}

// Removed returns the headers that a gateway route removes before the call
// leaves Gibson. They are the trusted headers of ext-authz, the identity
// headers of the Edge, the route headers and the Capability Grant. A model
// provider and an outside agent get none of them.
func Removed() []string {
	out := Trusted()
	return append(out,
		headers.HeaderSubject, headers.HeaderIssuer, headers.HeaderCredentialType,
		headers.HeaderTenant, headers.HeaderIssuedAt,
		modelcall.HeaderRouteTenant, modelcall.HeaderRouteProvider,
		agentcall.HeaderRouteAgent, agentcall.HeaderRouteBank,
		HeaderCapabilityGrant,
	)
}
