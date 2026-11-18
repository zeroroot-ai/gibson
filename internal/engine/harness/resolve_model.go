// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

// The ResolveModel server side (gibson#1392, ADR-0172 decision 4).
//
// An SDK agent calls ResolveModel with a slot name and gets back one exact model
// name, the route headers and the gateway to call. The agent then sends its own
// Open Responses call to the model gateway with the task grant of its run.
//
// This file holds the logic with no generated type, so it needs only the
// request fields (the slot) and the response fields (ModelResolution). The two
// RPC handlers (HarnessCallbackService.ResolveModel and
// ComponentService.ResolveModel) only map the generated messages onto it. They
// wait for the SDK module with the RPC (branch epic/aaif-alignment of the sdk).

// Errors of ResolveModel. A handler maps them to InvalidArgument, NotFound and
// Unavailable.
var (
	ErrResolveSlotRequired = errors.New("resolve model: the slot is required")
	ErrResolveNoModel      = errors.New("resolve model: the slot has no model")
	ErrResolveNoGateway    = errors.New("resolve model: the model gateway is not configured")
)

// GatewayInfo is what an agent needs to reach the model gateway. The daemon
// reads it from GIBSON_MODEL_GATEWAY_URL and from the file named by
// GIBSON_MODEL_GATEWAY_CA_FILE.
type GatewayInfo struct {
	// URL is the base URL. The agent calls POST {URL}/v1/responses.
	URL string
	// CAPEM is the PEM bundle of the CA that signs the gateway certificate.
	CAPEM string
}

// ModelResolution is the answer of ResolveModel.
type ModelResolution struct {
	Model    string
	Provider string
	// GatewayURL is the base URL of the model gateway.
	GatewayURL string
	// RouteHeaders are sent unchanged. They come from modelcall.RouteHeaders, the
	// function that the ModelProvider render also uses.
	RouteHeaders    map[string]string
	ContextWindow   int32
	MaxOutputTokens int32
	// GatewayCAPEM is the PEM bundle of the private CA of the gateway.
	GatewayCAPEM string
}

// ResolveModel resolves a slot of the harness of a run to one exact model name.
// The harness honors the node pin and the model access gate, as a call through
// it does. The tenant is the tenant of the run. The result holds no credential.
func ResolveModel(
	ctx context.Context, h AgentHarness, tenant, slot string, gw GatewayInfo,
) (*ModelResolution, error) {
	slot = strings.TrimSpace(slot)
	if slot == "" {
		return nil, ErrResolveSlotRequired
	}
	if gw.URL == "" {
		return nil, ErrResolveNoGateway
	}
	if tenant == "" {
		return nil, errors.New("resolve model: the tenant is required")
	}
	r, ok := h.(SlotModelResolver)
	if !ok {
		return nil, fmt.Errorf("resolve model: the harness %T cannot resolve a slot to a model", h)
	}
	picked, err := r.ResolveSlotModel(ctx, slot)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrResolveNoModel, err)
	}
	if picked.Model == "" || picked.Provider == "" {
		return nil, ErrResolveNoModel
	}
	headers := map[string]string{}
	for _, rh := range modelcall.RouteHeaders(tenant, picked.Provider) {
		headers[rh.Name] = rh.Value
	}
	return &ModelResolution{
		Model: picked.Model, Provider: picked.Provider, GatewayURL: strings.TrimRight(gw.URL, "/"),
		RouteHeaders: headers, ContextWindow: int32(picked.ContextWindow), //nolint:gosec // bounded by maxContextWindow at save
		GatewayCAPEM: gw.CAPEM,
	}, nil
}
