// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package server

import (
	"context"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/zeroroot-ai/gibson/internal/platform/capname"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/agentcall"
)

// Reasons for a refused inbound A2A call. They are the label of
// extauthz_inbound_a2a_denied_total.
const (
	inboundDenyPath      = "path"
	inboundDenyNoToken   = "no_capability_grant"
	inboundDenyTokenType = "not_a_component_token"
	inboundDenyCeiling   = "no_originate_ceiling"
	inboundDenyExtraBit  = "extra_ceiling"
)

var extauthzInboundA2ADeniedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "extauthz_inbound_a2a_denied_total",
	Help: "Inbound A2A calls that ext-authz refused, by reason.",
}, []string{"reason"})

func denyInbound(reason string, resp *authv3.CheckResponse) *authv3.CheckResponse {
	extauthzInboundA2ADeniedTotal.WithLabelValues(reason).Inc()
	return resp
}

// inboundA2AResponse authorizes one inbound A2A call of the Edge identity (epic
// gibson#1367, gibson#1410). The path is the A2A endpoint of one published agent,
// or the Agent Card of it. The call does not cross the Agent gateway.
//
// The only credential is the Capability Grant JWT of an enrolled agent identity
// in x-capability-grant (ADR-0045). A Zitadel token, an API key and a daemon
// task grant are not accepted, and a request that carries a Zitadel token and
// no such JWT is refused. The checks, in order:
//
//  1. The token verifies against the key descriptor of the daemon, which ext-authz
//     reads for this call and never from its cache, so a revoke applies at once. The token
//     names the exact path, it is short lived and it is single use. A revoked or
//     lapsed identity has no descriptor, so it fails here.
//  2. The descriptor lists the ceiling mission:originate.
//  3. FGA shows can_originate from the principal of the descriptor to the
//     published definition of the agent in the path.
//
// The tenant is the tenant of the descriptor. The caller cannot name it, and no
// route header is read. On allow, ext-authz sets x-gibson-tenant and
// x-gibson-subject with overwrite, and it removes the mission and task headers,
// because a call that starts a mission has neither. The daemon reads the agent
// from the path.
func (s *EnvoyAuthzServer) inboundA2AResponse(ctx context.Context, req *authv3.CheckRequest) *authv3.CheckResponse {
	path := extractMethod(req)
	httpHeaders := req.GetAttributes().GetRequest().GetHttp().GetHeaders()

	if _, _, ok := agentcall.InboundPathAgent(path); !ok {
		s.log.WarnContext(ctx, "ext-authz: an inbound A2A path that names no valid agent", "path", path)
		return denyInbound(inboundDenyPath, denyForbidden())
	}

	token := extractCapabilityGrant(httpHeaders)
	if token == "" {
		s.log.WarnContext(ctx, "ext-authz: inbound A2A call without a Capability Grant", "path", path)
		extauthzUnauthenticatedTotal.WithLabelValues(agentcall.InboundPrefix).Inc()
		return denyInbound(inboundDenyNoToken, denyUnauthenticated())
	}
	if tokenType(token) != componentTokenType {
		// A daemon task grant is not an identity of an outside caller.
		s.log.WarnContext(ctx, "ext-authz: inbound A2A call with a token that is not a component token", "path", path)
		return denyInbound(inboundDenyTokenType, denyForbidden())
	}
	cid, deny, _ := s.verifyComponentWith(ctx, path, httpHeaders, s.component.VerifyFresh)
	if deny != nil {
		return deny
	}

	if !cid.Has(capname.MissionOriginate) {
		s.log.InfoContext(ctx, "ext-authz: inbound A2A caller has no mission:originate ceiling",
			"path", path, "principal", cid.Principal, "tenant", cid.Tenant)
		return denyInbound(inboundDenyCeiling, denyForbidden())
	}

	// A caller identity has the one ceiling mission:originate. An identity with
	// another session bit is not a caller identity.
	for _, c := range cid.Capabilities {
		if c != capname.MissionOriginate {
			s.log.WarnContext(ctx, "ext-authz: inbound A2A caller holds another capability",
				"path", path, "principal", cid.Principal, "capability", c)
			return denyInbound(inboundDenyExtraBit, denyForbidden())
		}
	}

	extauthzAllowedTotal.WithLabelValues(agentcall.InboundPrefix).Inc()
	return modelOKResponse(cid.Tenant, modelCaller{subject: cid.Principal})
}
