// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package server

import (
	"context"

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

// modelRoute reports the route facts that the gateway sent, and whether the
// request is a model call at all. The context extensions come from the gateway
// config. A caller cannot set them.
func modelRoute(req *authv3.CheckRequest) (tenant, provider string, ok bool) {
	ext := req.GetAttributes().GetContextExtensions()
	provider = ext[modelcall.ExtProvider]
	if provider == "" {
		return "", "", false
	}
	return ext[modelcall.ExtTenant], provider, true
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

// modelCallResponse authorizes one model call (gibson#1388).
//
// The caller is the Capability Grant in x-capability-grant: a task grant, or a
// component token. The tenant of the grant must be the fixed tenant of the
// route. FGA must show can_use on the exact model, or on the provider, for the
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
		return modelCaller{
			subject: claims.Subject,
			// The subject of a task grant ("component:agent:name") is not an FGA
			// user. The tenant members are the subject of the default grant.
			fgaUsers: []string{"tenant:" + tenant + "#member"},
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
