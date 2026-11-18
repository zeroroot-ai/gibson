// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

type resolverHarness struct {
	AgentHarness
	slotSeen string
	picked   SlotModel
	err      error
}

func (r *resolverHarness) ResolveSlotModel(_ context.Context, slot string) (SlotModel, error) {
	r.slotSeen = slot
	return r.picked, r.err
}

func TestResolveModel_GivesOneExactModelAndTheRouteHeaders(t *testing.T) {
	h := &resolverHarness{picked: SlotModel{Provider: "claude", Model: "claude-sonnet-4-5", ContextWindow: 200000}}
	res, err := ResolveModel(context.Background(), h, "acme", " primary ", GatewayInfo{URL: "https://gw.example/", CAPEM: "PEM"})
	if err != nil {
		t.Fatalf("ResolveModel: %v", err)
	}
	if h.slotSeen != "primary" {
		t.Errorf("slot = %q", h.slotSeen)
	}
	if res.Model != "claude-sonnet-4-5" || res.Provider != "claude" || res.ContextWindow != 200000 {
		t.Errorf("result = %+v", res)
	}
	if res.GatewayURL != "https://gw.example" || res.GatewayCAPEM != "PEM" {
		t.Errorf("gateway = %q, ca = %q", res.GatewayURL, res.GatewayCAPEM)
	}
	for _, rh := range modelcall.RouteHeaders("acme", "claude") {
		if res.RouteHeaders[rh.Name] != rh.Value {
			t.Errorf("header %s = %q, want %q", rh.Name, res.RouteHeaders[rh.Name], rh.Value)
		}
	}
	if len(res.RouteHeaders) != 2 {
		t.Errorf("route headers = %v, want the two route headers and no other", res.RouteHeaders)
	}
}

func TestResolveModel_Refusals(t *testing.T) {
	ok := &resolverHarness{picked: SlotModel{Provider: "p", Model: "m"}}
	gw := GatewayInfo{URL: "https://gw"}
	ctx := context.Background()
	if _, err := ResolveModel(ctx, ok, "acme", "  ", gw); !errors.Is(err, ErrResolveSlotRequired) {
		t.Errorf("no slot: %v", err)
	}
	if _, err := ResolveModel(ctx, ok, "acme", "s", GatewayInfo{}); !errors.Is(err, ErrResolveNoGateway) {
		t.Errorf("no gateway: %v", err)
	}
	if _, err := ResolveModel(ctx, ok, "", "s", gw); err == nil {
		t.Error("no tenant was accepted")
	}
	bad := &resolverHarness{err: errors.New("no provider")}
	if _, err := ResolveModel(ctx, bad, "acme", "s", gw); !errors.Is(err, ErrResolveNoModel) {
		t.Errorf("slot with no model: %v", err)
	}
	empty := &resolverHarness{}
	if _, err := ResolveModel(ctx, empty, "acme", "s", gw); !errors.Is(err, ErrResolveNoModel) {
		t.Errorf("empty pick: %v", err)
	}
	if _, err := ResolveModel(ctx, struct{ AgentHarness }{}, "acme", "s", gw); err == nil {
		t.Error("a harness that cannot resolve a slot was accepted")
	}
}
