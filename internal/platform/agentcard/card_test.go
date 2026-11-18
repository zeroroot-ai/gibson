// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package agentcard

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/a2aproject/a2a-go/v2/a2a"

	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

func TestBuild_FromTheCatalogEntry(t *testing.T) {
	info := component.ComponentInfo{
		Kind: "agent", Name: "scout", Version: "1.4.0", Description: "Maps a network.",
		CardSkills: []component.CardSkillInfo{{
			ID: "map", Name: "Map hosts", Description: "List hosts.", Tags: []string{"recon"},
			Examples: []string{"map 10.0.0.0/24"}, InputModes: []string{"application/json"},
		}},
		DefaultInputModes:  []string{"text/plain"},
		DefaultOutputModes: []string{"application/json"},
	}
	card, err := Build(info, "https://edge.example/gateway/agent")
	if err != nil {
		t.Fatal(err)
	}
	if card.Name != "scout" || card.Version != "1.4.0" || card.Description != "Maps a network." {
		t.Fatalf("card = %+v", card)
	}
	if len(card.SupportedInterfaces) != 1 {
		t.Fatalf("interfaces = %+v", card.SupportedInterfaces)
	}
	if i := card.SupportedInterfaces[0]; i.URL != "https://edge.example/gateway/agent" ||
		i.ProtocolBinding != a2a.TransportProtocolJSONRPC {
		t.Fatalf("interface = %+v", i)
	}
	if len(card.Skills) != 1 || card.Skills[0].ID != "map" || card.Skills[0].InputModes[0] != "application/json" {
		t.Fatalf("skills = %+v", card.Skills)
	}
	if card.DefaultInputModes[0] != "text/plain" || card.DefaultOutputModes[0] != "application/json" {
		t.Fatalf("modes = %v %v", card.DefaultInputModes, card.DefaultOutputModes)
	}
	scheme, ok := card.SecuritySchemes[GrantScheme].(a2a.APIKeySecurityScheme)
	if !ok || scheme.Name != "x-capability-grant" || scheme.Location != a2a.APIKeySecuritySchemeLocationHeader {
		t.Fatalf("security schemes = %+v", card.SecuritySchemes)
	}
	if len(card.SecurityRequirements) != 1 {
		t.Fatalf("security requirements = %+v", card.SecurityRequirements)
	}
	// The card must encode as JSON for the well-known path.
	raw, err := json.Marshal(card)
	if err != nil {
		t.Fatal(err)
	}
	var back a2a.AgentCard
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("round trip: %v (%s)", err, raw)
	}
}

func TestBuild_DefaultsAndRefusals(t *testing.T) {
	card, err := Build(component.ComponentInfo{Kind: "agent", Name: "a", Metadata: map[string]string{"description": "d"}},
		"https://edge.example/gateway/agent")
	if err != nil {
		t.Fatal(err)
	}
	if card.Description != "d" || card.DefaultInputModes[0] != "text/plain" || card.Skills == nil {
		t.Fatalf("card = %+v", card)
	}
	if _, err := Build(component.ComponentInfo{Kind: "tool", Name: "t"}, "https://x"); !errors.Is(err, ErrNotAnAgent) {
		t.Fatalf("err = %v", err)
	}
	if _, err := Build(component.ComponentInfo{Kind: "agent", Name: "a"}, " "); err == nil {
		t.Fatal("an empty gateway URL must fail")
	}
}
