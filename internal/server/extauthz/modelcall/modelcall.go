// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package modelcall holds the names that the gateway, ext-authz and the grant
// minter share for a model call (gibson#1388, ADR-0172).
//
// A model call goes through agentgateway to a model provider. Each route of the
// gateway belongs to one tenant and one provider. The gateway sends these facts
// to ext-authz in the CheckRequest, and the caller cannot change them:
//
//   - The tenant and the provider are static values of the route. They arrive
//     in attributes.context_extensions, under ExtTenant and ExtProvider.
//     The gateway config sets them with protocol.grpc.context.
//   - The exact model name is a CEL result of the request body. It arrives in
//     attributes.metadata_context.filter_metadata, under the namespace
//     MetadataNamespace, in the field MetadataModel. The gateway config sets it
//     with protocol.grpc.metadata and the expression
//     {"model": json(request.body).model}.
package modelcall

import (
	"encoding/base64"
	"encoding/json"
	"strings"
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

// Context extension keys that the gateway route sets with fixed values.
const (
	ExtTenant   = "gibson-tenant"
	ExtProvider = "gibson-provider"
)

// ExtAgent is the context extension of a route of the agent gateway (A2A). The
// route sets the name of the agent. A request with ExtAgent or ExtProvider comes
// from the gateway. Any other request comes from the Edge.
const ExtAgent = "gibson-agent"

// IsGatewayCall reports whether the context extensions of a check mark a call
// of the model gateway or of the agent gateway. The gateway config sets the
// extensions, and a caller cannot.
func IsGatewayCall(contextExtensions map[string]string) bool {
	return contextExtensions[ExtProvider] != "" || contextExtensions[ExtAgent] != ""
}

// The metadata that the gateway route computes from the request body.
const (
	MetadataNamespace = "gibson"
	MetadataModel     = "model"
)

// HeaderProvider is the route header that names the provider of a tenant. The
// route of a provider matches it together with HeaderTenant. ext-authz sets
// HeaderTenant again with the tenant of the grant, so a copy of a caller never
// passes.
const HeaderProvider = "x-gibson-provider"

// RouteHeader is one header that a call must carry to match the route of a
// provider.
type RouteHeader struct{ Name, Value string }

// RouteHeaders returns the headers that select the route of one provider of one
// tenant. The HTTPRoute of the ModelProvider matches exactly these headers, and
// each model client sends exactly these headers. One function builds both, so
// the names cannot drift.
func RouteHeaders(tenant, provider string) []RouteHeader {
	return []RouteHeader{
		{Name: HeaderTenant, Value: tenant},
		{Name: HeaderProvider, Value: provider},
	}
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
