// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package modelcall holds the names that the gateway, ext-authz and the grant
// minter share for a model call (gibson#1388, ADR-0172).
//
// A model call goes through agentgateway to a model provider. ext-authz runs at
// the Gateway level, before any route, so it knows no route. The facts of the
// route arrive in two ways, and the caller cannot make either one trusted by
// itself:
//
//   - The caller sends two route headers, HeaderRouteTenant and
//     HeaderRouteProvider. The HTTPRoute of a ModelProvider matches exactly
//     these headers, so a call can reach the backend of a provider only with the
//     headers of that provider. ext-authz refuses a call whose tenant header is
//     not the tenant of the Capability Grant. A caller of tenant A that sends
//     the header of tenant B is refused. A caller can match only the routes of
//     its own tenant.
//   - The exact model name is a CEL result of the request body. It arrives in
//     attributes.metadata_context.filter_metadata, under the namespace
//     MetadataNamespace, in the field MetadataModel. The gateway config sets it
//     with protocol.grpc.metadata and the expression
//     {"model": json(request.body).model}.
//
// A call is a gateway call when the TLS peer of ext-authz has the SPIFFE
// identity of the gateway. The path then tells the kind: a model path is a model
// call, and any other path is an A2A call.
package modelcall

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// The routes of a model call. The route is the method name of a task grant: a
// grant that does not list a route cannot call it.
const (
	// RouteResponses is an Open Responses call (ADR-0173).
	RouteResponses = "/v1/responses"
	// RouteEmbeddings is an OpenAI Embeddings call.
	RouteEmbeddings = "/v1/embeddings"
	// RouteModels lists the models of a provider. It carries no model name.
	RouteModels = "/v1/models"
)

// The metadata that the gateway route computes from the request body.
const (
	MetadataNamespace = "gibson"
	MetadataModel     = "model"
)

// ModelExpression is the CEL expression that the install sets in the ext-authz
// policy of the Gateway, as the metadata of the gRPC check. It reads the exact
// model name from the request body.
const ModelExpression = `{"model": json(request.body).model}`

// The route headers. The HTTPRoute of a provider matches them, the model client
// sends them, and ext-authz reads them as the claimed tenant and provider. They
// differ from HeaderTenant, which ext-authz sets with the verified tenant.
const (
	HeaderRouteTenant   = "x-gibson-route-tenant"
	HeaderRouteProvider = "x-gibson-route-provider"
)

// RouteHeader is one header that a call must carry to match the route of a
// provider.
type RouteHeader struct{ Name, Value string }

// RouteHeaders returns the headers that select the route of one provider of one
// tenant. The HTTPRoute of the ModelProvider matches exactly these headers, and
// each model client sends exactly these headers. One function builds both, so
// the names cannot drift.
func RouteHeaders(tenant, provider string) []RouteHeader {
	return []RouteHeader{
		{Name: HeaderRouteTenant, Value: tenant},
		{Name: HeaderRouteProvider, Value: provider},
	}
}

func readRouteHeader(headers map[string]string, name string) (string, string) {
	v := strings.TrimSpace(headers[name])
	switch {
	case v == "":
		return "", "missing_route_header"
	case strings.Contains(v, ","):
		return "", "repeated_route_header"
	}
	return v, ""
}

// ClaimedRouteTenant reads the claimed tenant from the headers of a request. It
// returns a reason when the header is missing, empty or repeated. A repeated
// header arrives as one value with a comma.
func ClaimedRouteTenant(headers map[string]string) (tenant, reason string) {
	return readRouteHeader(headers, HeaderRouteTenant)
}

// ClaimedRoute reads the claimed tenant and provider from the headers of a
// request. It returns a reason when a header is missing, empty or repeated.
func ClaimedRoute(headers map[string]string) (tenant, provider, reason string) {
	tenant, reason = readRouteHeader(headers, HeaderRouteTenant)
	if reason != "" {
		return "", "", reason
	}
	provider, reason = readRouteHeader(headers, HeaderRouteProvider)
	if reason != "" {
		return "", "", reason
	}
	return tenant, provider, ""
}

// IsModelPath reports whether path is one of the three model routes.
func IsModelPath(path string) bool {
	return IsCallRoute(path) || path == RouteModels
}

// Headers that ext-authz sets on an allowed model call. ext-authz sets each one
// on every call, so a copy from the caller never reaches the provider side.
const (
	HeaderTenant  = "x-gibson-tenant"
	HeaderSubject = "x-gibson-subject"
	HeaderMission = "x-gibson-mission"
	HeaderTask    = "x-gibson-task"
)

// InitiatorClaim is the signed claim of a task grant that names the person who
// created the mission, as an FGA user ("user:<id>"). The daemon sets it when it
// mints the grant. A fork and a renewal keep it. ext-authz uses it as the FGA
// subject of the model access check, as the slot gate did (hosted#358). A grant
// of a mission that no person created has no such claim.
const InitiatorClaim = "ini"

// ClaimString reads one string claim from the payload of a compact JWT. The
// caller must have verified the signature. It returns "" for a token that it
// cannot read and for a claim that is absent or not a string.
func ClaimString(token, name string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var payload map[string]any
	if json.Unmarshal(raw, &payload) != nil {
		return ""
	}
	v, _ := payload[name].(string)
	return v
}

// IsCallRoute reports whether path is a route that carries a model name.
func IsCallRoute(path string) bool {
	return path == RouteResponses || path == RouteEmbeddings
}

// GrantRoutes returns the routes that a task grant lists so that its holder can
// call a model. A task grant does not list RouteModels: the daemon lists models
// with its own identity.
func GrantRoutes() []string {
	return []string{RouteResponses, RouteEmbeddings}
}

// The daemon call grant is the credential of a model call that the daemon makes
// for itself with no mission (embeddings at ingest, dashboard chat, provider
// test and model list). It is a short token that the daemon signs with the same
// keys as a task grant. Its own type header and its own claims keep the two
// kinds apart: ext-authz never reads it as a task grant, and never reads a task
// grant as it.
const (
	// DaemonCallTokenType is the `typ` header of a daemon call grant.
	DaemonCallTokenType = "daemon-call+jwt"
	// DaemonCallMaxLifetime is the longest lifetime of a daemon call grant.
	DaemonCallMaxLifetime = 60 * time.Second

	// ClaimPurpose and ClaimRoute are the signed claims that only a daemon call
	// grant holds. A daemon call grant holds no mission and no task claim.
	ClaimPurpose = "purpose"
	ClaimRoute   = "route"
)

// The closed set of purposes of a daemon call grant.
const (
	PurposeEmbedding     = "embedding"
	PurposeChat          = "chat"
	PurposeProviderProbe = "provider_probe"
	PurposeModelList     = "model_list"
)

// PurposeRoute returns the one route that a purpose may call, and false for a
// purpose that is not in the closed set.
func PurposeRoute(purpose string) (string, bool) {
	switch purpose {
	case PurposeEmbedding:
		return RouteEmbeddings, true
	case PurposeChat:
		return RouteResponses, true
	case PurposeProviderProbe, PurposeModelList:
		return RouteModels, true
	}
	return "", false
}

// DaemonSubject is the subject of a daemon call for a purpose.
func DaemonSubject(purpose string) string { return "component:daemon:" + purpose }

// The sandbox path. A sandbox reaches the cluster only through the Edge. The
// Edge has two routes that forward to the gateway listeners and remove the
// prefix. ext-authz checks the Capability Grant of a call on these prefixes
// (the gateway forward class) and does nothing else. The full authorization
// stays at the gateway, with the gateway identity.
const (
	// EdgeModelPrefix is the Edge route to the model listener.
	EdgeModelPrefix = "/gateway/model/"
	// EdgeAgentPrefix is the Edge route to the agent listener.
	EdgeAgentPrefix = "/gateway/agent/"
)

// IsEdgeForwardPath reports whether a path of an Edge call is on one of the two
// gateway forward prefixes.
func IsEdgeForwardPath(path string) bool {
	return strings.HasPrefix(path, EdgeModelPrefix) || strings.HasPrefix(path, EdgeAgentPrefix)
}
