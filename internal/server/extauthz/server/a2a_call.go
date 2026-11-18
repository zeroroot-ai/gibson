// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package server

import (
	"context"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/agentcall"
)

// FGA relations of an A2A call. Delegation to a bank is the right to send to the
// bank. Delegation to an ephemeral agent, and a look at the Agent Card, are the
// right to execute the agent, which is the relation of the dispatch gate and of
// the catalog search filter.
const (
	relationCanSend    = "can_send"
	relationCanExecute = "can_execute"
)

// Reasons for a refused A2A call. They are the label of
// extauthz_a2a_call_denied_total.
const (
	a2aDenyPath           = "path"
	a2aDenyRoute          = "route_header"
	a2aDenyCardAgent      = "card_path_agent"
	a2aDenyTenant         = "tenant_mismatch"
	a2aDenyMission        = "mission_not_active"
	a2aDenyFGA            = "fga_denied"
	a2aDenyFGAUnavailable = "fga_unavailable"
)

var extauthzA2ACallDeniedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "extauthz_a2a_call_denied_total",
	Help: "ext-authz A2A calls refused, by reason.",
}, []string{"reason"})

func denyA2A(reason string, resp *authv3.CheckResponse) *authv3.CheckResponse {
	extauthzA2ACallDeniedTotal.WithLabelValues(reason).Inc()
	return resp
}

// a2aCallResponse authorizes one A2A call of the gateway peer (gibson#1401). The
// path is the A2A endpoint, or the Agent Card of one agent.
//
// The caller is the task grant in x-capability-grant. The grant must list the
// A2A route. The tenant of the grant must be the claimed tenant of the route
// headers. The mission of the grant must be active. FGA must then show that the
// caller may reach the target of x-gibson-route-agent and x-gibson-route-bank:
// can_send on the bank when there is one, and can_execute on the agent
// otherwise. A call to the Agent Card needs no right to delegate. It needs only
// the right to see the agent, which is can_execute on the agent.
//
// On allow, ext-authz sets x-gibson-tenant, x-gibson-subject, x-gibson-mission
// and x-gibson-task with overwrite. It keeps the route headers, which the
// daemon reads for the target.
func (s *EnvoyAuthzServer) a2aCallResponse(ctx context.Context, req *authv3.CheckRequest) *authv3.CheckResponse {
	path := extractMethod(req)
	httpHeaders := req.GetAttributes().GetRequest().GetHttp().GetHeaders()

	isCard := false
	if name, ok := agentcall.CardPathName(path); ok {
		isCard = true
		// The path and the route name the same agent, or the gateway routed a
		// path that the route does not match.
		if routeAgent := httpHeaders[agentcall.HeaderRouteAgent]; routeAgent != name {
			s.log.WarnContext(ctx, "ext-authz: the card path and the route header name different agents", "path", path)
			return denyA2A(a2aDenyCardAgent, denyForbidden())
		}
	} else if path != agentcall.RouteA2A {
		s.log.WarnContext(ctx, "ext-authz: the gateway sent a path that is not an A2A path", "path", path)
		return denyA2A(a2aDenyPath, denyForbidden())
	}

	routeTenant, agentName, bank, reason := agentcall.ClaimedRoute(httpHeaders)
	if reason != "" {
		s.log.WarnContext(ctx, "ext-authz: the route headers of an A2A call are not usable", "path", path, "reason", reason)
		return denyA2A(a2aDenyRoute, denyForbidden())
	}

	// The grant must list the A2A route. The card path needs the same grant.
	claims, deny, handled := s.verifyTaskGrant(ctx, agentcall.RouteA2A, httpHeaders)
	if !handled {
		s.log.WarnContext(ctx, "ext-authz: A2A call without a task grant", "path", path)
		extauthzUnauthenticatedTotal.WithLabelValues(path).Inc()
		return denyA2A("unauthenticated", denyUnauthenticated())
	}
	if deny != nil {
		return deny
	}
	caller, deny2 := s.taskGrantCaller(ctx, path, httpHeaders, claims)
	if deny2 != nil {
		return deny2
	}
	if caller.tenant != routeTenant {
		s.log.WarnContext(ctx, "ext-authz: grant tenant is not the tenant of the route",
			"path", path, "subject", caller.subject, "grant_tenant", caller.tenant, "route_tenant", routeTenant)
		return denyA2A(a2aDenyTenant, denyForbidden())
	}
	// The grant verifier refuses a grant with no mission or no task, so the
	// caller here always has both.

	active, err := s.cache.CheckRelation(ctx, "tenant:"+caller.tenant,
		authz.RelationMissionActive, authz.MissionObject(caller.mission), nil)
	if err != nil {
		extauthzFGAUnavailableTotal.Inc()
		s.log.ErrorContext(ctx, "ext-authz: FGA unavailable (A2A mission gate)", "mission", caller.mission, "err", err)
		return denyA2A(a2aDenyFGAUnavailable, denyResponse(codes.Unavailable, typev3.StatusCode_ServiceUnavailable, bodyUnavailable))
	}
	if !active {
		s.log.InfoContext(ctx, "ext-authz: A2A call of a mission that is not active",
			"path", path, "subject", caller.subject, "mission", caller.mission, "task", caller.task)
		extauthzDeniedTotal.WithLabelValues(path).Inc()
		return denyA2A(a2aDenyMission, denyForbidden())
	}

	relation, object := a2aTarget(isCard, agentName, bank)
	allowed, fgaErr := s.checkAny(ctx, caller.fgaUsers, relation, object)
	if fgaErr != nil {
		extauthzFGAUnavailableTotal.Inc()
		s.log.ErrorContext(ctx, "ext-authz: FGA unavailable (A2A call)", "path", path, "err", fgaErr)
		return denyA2A(a2aDenyFGAUnavailable, denyResponse(codes.Unavailable, typev3.StatusCode_ServiceUnavailable, bodyUnavailable))
	}
	if !allowed {
		s.log.InfoContext(ctx, "ext-authz: A2A call denied by FGA",
			"path", path, "subject", caller.subject, "tenant", routeTenant, "agent", agentName, "bank", bank)
		extauthzDeniedTotal.WithLabelValues(path).Inc()
		return denyA2A(a2aDenyFGA, denyForbidden())
	}

	extauthzAllowedTotal.WithLabelValues(path).Inc()
	return modelOKResponse(routeTenant, caller)
}

// a2aTarget returns the FGA relation and object of an A2A call. A card needs
// can_execute on the agent. A delegation to a bank needs can_send on the bank.
// A delegation to an agent with no bank needs can_execute on the agent.
func a2aTarget(isCard bool, agentName, bank string) (relation, object string) {
	if !isCard && bank != "" {
		return relationCanSend, "bank:" + bank
	}
	return relationCanExecute, authz.ComponentObject(authz.KindAgent, agentName)
}

// checkAny reports whether any user holds the relation on the object. An FGA
// error is returned, and the caller denies on it unless another user is allowed.
func (s *EnvoyAuthzServer) checkAny(ctx context.Context, users []string, relation, object string) (bool, error) {
	var firstErr error
	for _, user := range users {
		if user == "" {
			continue
		}
		ok, err := s.cache.CheckRelation(ctx, user, relation, object, nil)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if ok {
			return true, nil
		}
	}
	return false, firstErr
}
