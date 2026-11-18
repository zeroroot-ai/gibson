// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package modelclient is the model client of the daemon (gibson#1392,
// ADR-0172, ADR-0173).
//
// The daemon calls no model provider. It sends each model call to the model
// gateway, which holds the provider credentials. A call is an Open Responses
// request over HTTP. The same client also sends an embedding call (OpenAI
// Embeddings format) and a model list call to the gateway.
//
// Three facts shape each call:
//
//   - A Target names one provider of one tenant and one exact model name. The
//     caller resolves a slot to a Target before the call. The gateway never
//     sees a slot.
//   - The route headers come from modelcall.RouteHeaders, the same function
//     that the ModelProvider render uses for the route match. The names cannot
//     drift.
//   - The identity of the call is a Capability Grant that the daemon signs. A
//     GrantSource returns it for one Caller. ext-authz checks the grant, the
//     tenant of the route, the model name and the state of the mission.
//
// The package holds no credential and calls no provider.
package modelclient
