// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package server

import (
	"context"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/cgjwt"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

// The gateway forward class (the sandbox path).
//
// A sandbox reaches the cluster only through the Edge, never through an
// in-cluster service name. The Edge has two routes, /gateway/model/ and
// /gateway/agent/, that forward to the listeners of the gateway and remove the
// prefix. For a call on these prefixes, ext-authz does ONE thing for the Edge
// identity: it verifies the Capability Grant (the signature, the expiry, the
// key descriptor) and checks that the tenant of the grant is the tenant of the
// header x-gibson-route-tenant. It sets no trusted header. The full
// authorization (FGA, the mission gate, the trusted headers) stays at the
// gateway, where ext-authz runs again with the gateway identity.
//
// The replay state is not touched. A task grant is not single use, so the check
// at the gateway a moment later passes. A daemon call grant is single use and
// never comes through the Edge, so the class refuses it before it reads the
// replay state.

// Reasons of a refusal of the class, the label of
// extauthz_edge_forward_denied_total.
const (
	forwardDenyNoGrant        = "no_grant"
	forwardDenyDaemonCall     = "daemon_call_grant"
	forwardDenyComponentToken = "component_token"
	forwardDenyInvalid        = "grant_invalid"
	forwardDenyTenant         = "tenant_mismatch"
)

// edgeForwardResponse decides a call of the Edge identity on a gateway forward
// prefix. It returns an allow with no header change, or a refusal.
func (s *EnvoyAuthzServer) edgeForwardResponse(ctx context.Context, req *authv3.CheckRequest) *authv3.CheckResponse {
	path := extractMethod(req)
	headers := req.GetAttributes().GetRequest().GetHttp().GetHeaders()

	token := extractCapabilityGrant(headers)
	switch {
	case token == "":
		return s.forwardDeny(ctx, forwardDenyNoGrant, path, denyUnauthenticated())
	case cgjwt.IsDaemonCallToken(token):
		// A daemon call grant is for a call of the daemon at the gateway. It is
		// refused here, and its replay record is not written.
		return s.forwardDeny(ctx, forwardDenyDaemonCall, path, denyForbidden())
	case tokenType(token) == componentTokenType:
		return s.forwardDeny(ctx, forwardDenyComponentToken, path, denyForbidden())
	}
	claims, deny := s.verifyTaskGrantToken(ctx, path, token)
	if deny != nil {
		return s.forwardDeny(ctx, forwardDenyInvalid, path, deny)
	}
	tenant, reason := modelcall.ClaimedRouteTenant(headers)
	if reason != "" {
		return s.forwardDeny(ctx, reason, path, denyForbidden())
	}
	if tenant != claims.Tenant.String() {
		s.log.WarnContext(ctx, "ext-authz: the grant tenant is not the claimed route tenant on a forward call",
			"path", path, "grant_tenant", claims.Tenant.String(), "route_tenant", tenant)
		return s.forwardDeny(ctx, forwardDenyTenant, path, denyForbidden())
	}
	extauthzEdgeForwardAllowedTotal.Inc()
	return &authv3.CheckResponse{
		Status:       &rpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{OkResponse: &authv3.OkHttpResponse{}},
	}
}

func (s *EnvoyAuthzServer) forwardDeny(
	ctx context.Context, reason, path string, resp *authv3.CheckResponse,
) *authv3.CheckResponse {
	extauthzEdgeForwardDeniedTotal.WithLabelValues(reason).Inc()
	s.log.WarnContext(ctx, "ext-authz: a gateway forward call is refused", "reason", reason, "path", path)
	return resp
}
