// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package agentcard builds the A2A Agent Card of a Gibson agent from its catalog
// entry.
package agentcard

import (
	"errors"
	"strings"

	"github.com/a2aproject/a2a-go/v2/a2a"

	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

// GrantHeader is the header that carries the task grant on a call
// to the Agent gateway.
const GrantHeader = "x-capability-grant"

// GrantScheme is the name of the security scheme of the Agent Card.
const GrantScheme a2a.SecuritySchemeName = "capabilityGrant"

// defaultCardMode is the media type that a card lists when the agent
// registered none.
const defaultCardMode = "text/plain"

// ErrNotAnAgent reports that the entry is not an agent. Only an agent has
// an Agent Card.
var ErrNotAnAgent = errors.New("agent card: the catalog entry is not an agent")

// Build builds the A2A Agent Card of an agent from its catalog entry.
// gatewayURL is the public URL of the Agent gateway. The card lists it as the
// JSON-RPC interface. It says that a caller sends the task grant in the header
// x-capability-grant. The card says nothing about a bank or a tenant, so it
// holds no secret and no identity.
//
// The card skills are A2A AgentSkill entries of the card. They are not Agent
// Skills in the SKILL.md format.
func Build(info component.ComponentInfo, gatewayURL string) (*a2a.AgentCard, error) {
	return build(info, gatewayURL, "The task grant of the caller. The Agent gateway checks it for each call.")
}

// BuildInbound builds the A2A Agent Card of a published agent for an outside
// caller (epic gibson#1367). inboundURL is the public Edge URL of the agent. The
// card says that a caller signs each call with the Capability Grant JWT of its
// enrolled agent identity and sends it in the header x-capability-grant. Only
// that credential is accepted.
func BuildInbound(info component.ComponentInfo, inboundURL string) (*a2a.AgentCard, error) {
	return build(info, inboundURL, "The Capability Grant JWT of an enrolled agent identity, signed for the "+
		"path of the call. It carries the ceiling mission:originate. Gibson accepts no other credential.")
}

func build(info component.ComponentInfo, gatewayURL, schemeDescription string) (*a2a.AgentCard, error) {
	if info.Kind != "agent" {
		return nil, ErrNotAnAgent
	}
	gatewayURL = strings.TrimSpace(gatewayURL)
	if gatewayURL == "" {
		return nil, errors.New("agent card: the public URL of the Agent gateway is empty")
	}
	inputModes := nonEmpty(info.DefaultInputModes)
	outputModes := nonEmpty(info.DefaultOutputModes)
	description := info.Description
	if description == "" {
		description = info.Metadata["description"]
	}
	card := &a2a.AgentCard{
		Name:                info.Name,
		Description:         description,
		Version:             info.Version,
		SupportedInterfaces: []*a2a.AgentInterface{a2a.NewAgentInterface(gatewayURL, a2a.TransportProtocolJSONRPC)},
		DefaultInputModes:   inputModes,
		DefaultOutputModes:  outputModes,
		SecuritySchemes: a2a.NamedSecuritySchemes{
			GrantScheme: a2a.APIKeySecurityScheme{
				Description: schemeDescription,
				Location:    a2a.APIKeySecuritySchemeLocationHeader,
				Name:        GrantHeader,
			},
		},
		SecurityRequirements: a2a.SecurityRequirementsOptions{
			{GrantScheme: a2a.SecuritySchemeScopes{}},
		},
		Skills: []a2a.AgentSkill{},
	}
	for _, cs := range info.CardSkills {
		skill := a2a.AgentSkill{
			ID: cs.ID, Name: cs.Name, Description: cs.Description,
			Tags: cs.Tags, Examples: cs.Examples, InputModes: cs.InputModes, OutputModes: cs.OutputModes,
		}
		if skill.Tags == nil {
			skill.Tags = []string{}
		}
		card.Skills = append(card.Skills, skill)
	}
	return card, nil
}

func nonEmpty(modes []string) []string {
	if len(modes) == 0 {
		return []string{defaultCardMode}
	}
	return modes
}
