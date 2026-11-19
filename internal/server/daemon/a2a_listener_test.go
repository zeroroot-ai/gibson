// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

// cardRegistry answers Discover with one agent. The other methods are not used.
type cardRegistry struct{ component.ComponentRegistry }

func (cardRegistry) Discover(_ context.Context, _, kind, name string) ([]component.ComponentInfo, error) {
	return []component.ComponentInfo{{Kind: kind, Name: name, Version: "1.0.0"}}, nil
}

// The card of an agent lists the A2A endpoint that a caller can use through the
// Edge. The Edge matches the prefix /gateway/agent/ with the slash, so the
// interface URL ends with the slash. It is the URL that ResolveAgent gives.
func TestRegistryCards_TheInterfaceURLHasTheEdgePrefix(t *testing.T) {
	cards := registryCards{
		registry: cardRegistry{},
		gateway:  component.GatewayInfo{URL: "https://api.localhost.zeroroot.ai:443/gateway/agent"},
	}
	card, err := cards.Card(context.Background(), "acme", "e2e-a2a-callee")
	if err != nil {
		t.Fatalf("Card: %v", err)
	}
	if len(card.SupportedInterfaces) != 1 {
		t.Fatalf("interfaces = %d, want 1", len(card.SupportedInterfaces))
	}
	const want = "https://api.localhost.zeroroot.ai:443/gateway/agent/"
	if got := card.SupportedInterfaces[0].URL; got != want {
		t.Fatalf("interface URL = %q, want %q", got, want)
	}
}
