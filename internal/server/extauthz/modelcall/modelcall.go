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

// The metadata that the gateway route computes from the request body.
const (
	MetadataNamespace = "gibson"
	MetadataModel     = "model"
)

// Headers that ext-authz sets on an allowed model call. ext-authz sets each one
// on every call, so a copy from the caller never reaches the provider side.
const (
	HeaderTenant  = "x-gibson-tenant"
	HeaderSubject = "x-gibson-subject"
	HeaderMission = "x-gibson-mission"
	HeaderTask    = "x-gibson-task"
)

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
