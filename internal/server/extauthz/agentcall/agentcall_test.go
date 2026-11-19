// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package agentcall

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

func TestClaimedRoute(t *testing.T) {
	ok := map[string]string{modelcall.HeaderRouteTenant: "acme", HeaderRouteAgent: "scout"}
	tenant, agent, bank, reason := ClaimedRoute(ok)
	if tenant != "acme" || agent != "scout" || bank != "" || reason != "" {
		t.Fatalf("got %q %q %q %q", tenant, agent, bank, reason)
	}
	ok[HeaderRouteBank] = "b1"
	if _, _, bank, _ := ClaimedRoute(ok); bank != "b1" {
		t.Fatalf("bank = %q", bank)
	}
	for name, h := range map[string]map[string]string{
		"no tenant":      {HeaderRouteAgent: "scout"},
		"no agent":       {modelcall.HeaderRouteTenant: "acme"},
		"repeated agent": {modelcall.HeaderRouteTenant: "acme", HeaderRouteAgent: "a,b"},
		"slash agent":    {modelcall.HeaderRouteTenant: "acme", HeaderRouteAgent: "a/b"},
		"space agent":    {modelcall.HeaderRouteTenant: "acme", HeaderRouteAgent: "a b"},
		"hash bank":      {modelcall.HeaderRouteTenant: "acme", HeaderRouteAgent: "a", HeaderRouteBank: "b#x"},
		"colon bank":     {modelcall.HeaderRouteTenant: "acme", HeaderRouteAgent: "a", HeaderRouteBank: "b:x"},
	} {
		if _, _, _, reason := ClaimedRoute(h); reason == "" {
			t.Errorf("%s: want a reason", name)
		}
	}
}

func TestCardPathName(t *testing.T) {
	if n, ok := CardPathName("/agents/scout/.well-known/agent-card.json"); !ok || n != "scout" {
		t.Fatalf("got %q %v", n, ok)
	}
	for _, p := range []string{"/", "/agents//.well-known/agent-card.json", "/agents/a/b/.well-known/agent-card.json",
		"/agents/scout", "/x/scout/.well-known/agent-card.json"} {
		if n, ok := CardPathName(p); ok {
			t.Errorf("%q gave %q", p, n)
		}
	}
}

func TestCardPathFor_IsReadByCardPathName(t *testing.T) {
	p := CardPathFor("scout")
	if p != "/agents/scout/.well-known/agent-card.json" {
		t.Fatalf("CardPathFor = %q", p)
	}
	if n, ok := CardPathName(p); !ok || n != "scout" {
		t.Errorf("CardPathName(%q) = %q, %v", p, n, ok)
	}
}
