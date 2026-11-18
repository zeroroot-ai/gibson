// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package server

import (
	"context"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

// relationCanUse is the FGA relation of a model access grant (model.fga, types
// provider and model).
const relationCanUse = "can_use"

// Reasons for a refused model call. They are the label of
// extauthz_model_call_denied_total.
const (
	modelDenyRoute          = "route_config"
	modelDenyEdgeModelPath  = "model_path_from_edge"
	modelDenyA2A            = "a2a_not_served"
	modelDenyPath           = "path"
	modelDenyNoModel        = "no_model"
	modelDenyTenant         = "tenant_mismatch"
	modelDenyFGA            = "fga_denied"
	modelDenyFGAUnavailable = "fga_unavailable"
	modelDenyObject         = "object"
	modelDenyMission        = "mission_not_active"
)

var extauthzModelCallDeniedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "extauthz_model_call_denied_total",
	Help: "ext-authz model calls refused, by reason.",
}, []string{"reason"})

// modelCaller is who makes a model call, after the credential is verified.
type modelCaller struct {
	// subject is the value of x-gibson-subject.
	subject string
	// fgaUsers are the FGA users that the access check asks about, in order.
	fgaUsers []string
	tenant   string
	mission  string
	task     string
}

// modelName reads the exact model name that the gateway computed from the body.
func modelName(req *authv3.CheckRequest) string {
	md := req.GetAttributes().GetMetadataContext().GetFilterMetadata()[modelcall.MetadataNamespace]
	return md.GetFields()[modelcall.MetadataModel].GetStringValue()
}

func denyModel(reason string, resp *authv3.CheckResponse) *authv3.CheckResponse {
	extauthzModelCallDeniedTotal.WithLabelValues(reason).Inc()
	return resp
}

// gatewayCallResponse decides a call of the gateway peer. A model path is a model
// call: the claimed tenant and provider come from the two route headers. Any
// other path is an A2A call, which no part of ext-authz serves yet, so it is
// refused with its own reason.
func (s *EnvoyAuthzServer) gatewayCallResponse(ctx context.Context, req *authv3.CheckRequest) *authv3.CheckResponse {
	path := extractMethod(req)
	if !modelcall.IsModelPath(path) {
		s.log.WarnContext(ctx, "ext-authz: the gateway sent a path that is not a model path, and no A2A call is served",
			"path", path)
		return denyModel(modelDenyA2A, denyForbidden())
	}
	tenant, provider, reason := modelcall.ClaimedRoute(req.GetAttributes().GetRequest().GetHttp().GetHeaders())
	if reason != "" {
		s.log.WarnContext(ctx, "ext-authz: the route headers of a model call are not usable", "path", path, "reason", reason)
		return denyModel(reason, denyForbidden())
	}
	return s.modelCallResponse(ctx, req, tenant, provider)
}

// modelCallResponse authorizes one model call (gibson#1388).
//
// The caller is the Capability Grant in x-capability-grant: a task grant, or a
// component token. The tenant of the grant must be the claimed tenant of the
// route headers. FGA must show can_use on the exact model, or on the provider, for the
// tenant members or for the component. A call of the model list route has no
// model name and needs the provider relation.
//
// On allow, ext-authz sets x-gibson-tenant, x-gibson-subject, x-gibson-mission
// and x-gibson-task. It sets each one on each call and removes the ones that it
// has no value for, so a copy from the caller never passes.
func (s *EnvoyAuthzServer) modelCallResponse(
	ctx context.Context, req *authv3.CheckRequest, routeTenant, provider string,
) *authv3.CheckResponse {
	path := extractMethod(req)
	httpHeaders := req.GetAttributes().GetRequest().GetHttp().GetHeaders()

	if routeTenant == "" {
		s.log.ErrorContext(ctx, "ext-authz: model route sends no tenant", "path", path, "provider", provider)
		return denyModel(modelDenyRoute, denyForbidden())
	}
	isList := path == modelcall.RouteModels
	if !isList && !modelcall.IsCallRoute(path) {
		s.log.WarnContext(ctx, "ext-authz: unknown model route", "path", path)
		return denyModel(modelDenyPath, denyForbidden())
	}

	caller, deny := s.authenticateModelCaller(ctx, path, httpHeaders)
	if deny != nil {
		return deny
	}
	if caller.tenant != routeTenant {
		s.log.WarnContext(ctx, "ext-authz: grant tenant is not the tenant of the route",
			"path", path, "subject", caller.subject, "grant_tenant", caller.tenant, "route_tenant", routeTenant)
		return denyModel(modelDenyTenant, denyForbidden())
	}

	providerObject, err := authz.ProviderObject(routeTenant, provider)
	if err != nil {
		return denyModel(modelDenyObject, denyForbidden())
	}
	objects := []string{providerObject}
	if !isList {
		model := modelName(req)
		if model == "" {
			s.log.WarnContext(ctx, "ext-authz: model call names no model", "path", path, "subject", caller.subject)
			return denyModel(modelDenyNoModel, denyForbidden())
		}
		modelObject, mErr := authz.ModelObject(routeTenant, model)
		if mErr != nil {
			s.log.WarnContext(ctx, "ext-authz: model name cannot form an FGA object", "model", model)
			return denyModel(modelDenyObject, denyForbidden())
		}
		// The model first, then the provider: a grant on either one allows.
		objects = []string{modelObject, providerObject}
	}

	// A model call of a mission that is not active is refused (gibson#1389). The
	// daemon changes the FGA tuple when the mission is paused or ends. A call with
	// no mission, such as a component call, has no mission to gate.
	if caller.mission != "" {
		active, aErr := s.cache.CheckRelation(ctx, "tenant:"+caller.tenant,
			authz.RelationMissionActive, authz.MissionObject(caller.mission), nil)
		if aErr != nil {
			extauthzFGAUnavailableTotal.Inc()
			s.log.ErrorContext(ctx, "ext-authz: FGA unavailable (mission gate)",
				"path", path, "mission", caller.mission, "err", aErr)
			return denyModel(modelDenyFGAUnavailable,
				denyResponse(codes.Unavailable, typev3.StatusCode_ServiceUnavailable, bodyUnavailable))
		}
		if !active {
			s.log.InfoContext(ctx, "ext-authz: model call of a mission that is not active",
				"path", path, "subject", caller.subject, "mission", caller.mission, "task", caller.task)
			extauthzDeniedTotal.WithLabelValues(path).Inc()
			return denyModel(modelDenyMission, denyForbidden())
		}
	}

	allowed, fgaErr := s.canUse(ctx, caller.fgaUsers, objects)
	if fgaErr != nil {
		extauthzFGAUnavailableTotal.Inc()
		s.log.ErrorContext(ctx, "ext-authz: FGA unavailable (model call)", "path", path, "err", fgaErr)
		return denyModel(modelDenyFGAUnavailable,
			denyResponse(codes.Unavailable, typev3.StatusCode_ServiceUnavailable, bodyUnavailable))
	}
	if !allowed {
		s.log.InfoContext(ctx, "ext-authz: model call denied by FGA",
			"path", path, "subject", caller.subject, "tenant", routeTenant, "provider", provider)
		extauthzDeniedTotal.WithLabelValues(path).Inc()
		return denyModel(modelDenyFGA, denyForbidden())
	}

	extauthzAllowedTotal.WithLabelValues(path).Inc()
	return modelOKResponse(routeTenant, caller)
}

// authenticateModelCaller verifies the credential of a model call. It reuses the
// two paths of every other call: the task grant, then the component token.
func (s *EnvoyAuthzServer) authenticateModelCaller(
	ctx context.Context, path string, httpHeaders map[string]string,
) (modelCaller, *authv3.CheckResponse) {
	if claims, deny, handled := s.verifyTaskGrant(ctx, path, httpHeaders); handled {
		if deny != nil {
			return modelCaller{}, deny
		}
		tenant := claims.Tenant.String()
		// The subject of a task grant ("component:agent:name") is not an FGA
		// user. The FGA subject is the person who created the mission, from the
		// signed claim of the grant, as the slot gate did. A user of the tenant
		// passes the default grant of the tenant members through that
		// membership. A grant with no such claim is a mission that no person
		// created. The tenant members are then the subject.
		fgaUsers := []string{"tenant:" + tenant + "#member"}
		if ini := modelcall.ClaimString(extractCapabilityGrant(httpHeaders), modelcall.InitiatorClaim); ini != "" {
			if !validInitiator(ini) {
				s.log.WarnContext(ctx, "ext-authz: the initiator claim is not an FGA user", "path", path)
				return modelCaller{}, denyModel(modelDenyObject, denyForbidden())
			}
			fgaUsers = []string{ini}
		}
		return modelCaller{
			subject:  claims.Subject,
			fgaUsers: fgaUsers,
			tenant:   tenant,
			mission:  claims.MissionID,
			task:     claims.TaskID,
		}, nil
	}
	if cid, deny, handled := s.verifyComponent(ctx, path, httpHeaders); handled {
		if deny != nil {
			return modelCaller{}, deny
		}
		return modelCaller{
			subject:  cid.Principal,
			fgaUsers: []string{cid.Principal, "tenant:" + cid.Tenant + "#member"},
			tenant:   cid.Tenant,
		}, nil
	}
	s.log.WarnContext(ctx, "ext-authz: model call without a grant", "path", path)
	extauthzUnauthenticatedTotal.WithLabelValues(path).Inc()
	return modelCaller{}, denyModel("unauthenticated", denyUnauthenticated())
}

// canUse reports whether any user holds can_use on any object. It stops at the
// first yes. An FGA error is an error, and the caller denies on it.
func (s *EnvoyAuthzServer) canUse(ctx context.Context, users, objects []string) (bool, error) {
	var firstErr error
	for _, user := range users {
		if user == "" {
			continue
		}
		for _, object := range objects {
			ok, err := s.cache.CheckRelation(ctx, user, relationCanUse, object, nil)
			if err != nil {
				// A caller that has no relation can still pass by another user.
				// A failure of FGA is kept, and it decides if nothing allows.
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			if ok {
				return true, nil
			}
		}
	}
	return false, firstErr
}

// modelOKResponse is the allow of a model call. It sets the four trusted headers
// with OVERWRITE_IF_EXISTS_OR_ADD, and it removes the ones that have no value.
func modelOKResponse(tenant string, c modelCaller) *authv3.CheckResponse {
	values := []struct{ key, value string }{
		{modelcall.HeaderTenant, tenant},
		{modelcall.HeaderSubject, c.subject},
		{modelcall.HeaderMission, c.mission},
		{modelcall.HeaderTask, c.task},
	}
	ok := &authv3.OkHttpResponse{}
	for _, v := range values {
		if v.value == "" {
			ok.HeadersToRemove = append(ok.HeadersToRemove, v.key)
			continue
		}
		ok.Headers = append(ok.Headers, &corev3.HeaderValueOption{
			Header:       &corev3.HeaderValue{Key: v.key, Value: v.value},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}
	return &authv3.CheckResponse{
		Status:       &rpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{OkResponse: ok},
	}
}

// validInitiator reports whether the initiator claim has the form of an FGA user
// of type user: "user:<id>", with no userset marker and no space.
func validInitiator(v string) bool {
	id, ok := strings.CutPrefix(v, "user:")
	return ok && id != "" && !strings.ContainsAny(id, "# \t\r\n")
}
