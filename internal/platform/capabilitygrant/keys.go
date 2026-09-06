// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package capabilitygrant

import (
	"context"
	"fmt"
	"time"
)

// AgentKeyDescriptor returns the per-kid key descriptor for the agent whose id
// is kid (ADR-0045, gibson#648). The descriptor is a JWKS superset:
//
//	{"keys":[{ed25519 jwk}], "principal":"agent_principal:<acct>",
//	 "tenant":"<tenant>", "status":"active"}
//
// ext-authz fetches this by kid to verify a component's self-signed agent+jwt
// (kid = agent row id) and then runs its NORMAL per-method FGA check on the
// daemon-asserted `principal`/`tenant` — it trusts no caller-asserted identity.
// Only active agents resolve: a revoked/expired agent's key is withheld so its
// signed tokens fail verification.
func (s *CapabilityGrantService) AgentKeyDescriptor(ctx context.Context, kid string) ([]byte, error) {
	agent, err := s.store.GetAgent(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: AgentKeyDescriptor: lookup %q: %w", kid, err)
	}
	if agent == nil {
		return nil, fmt.Errorf("capabilitygrant: AgentKeyDescriptor: agent %q not found", kid)
	}
	if agent.Status != "active" {
		return nil, fmt.Errorf("capabilitygrant: AgentKeyDescriptor: agent %q status %q (not active)", kid, agent.Status)
	}
	// Withhold a lapsed agent's key. Without this the sentence above about
	// expired agents was decoration: ext-authz would keep fetching the key and
	// keep accepting tokens the agent signed long after its registered lifetime
	// ran out. The caller renders every error from here as a flat 404, so
	// refusing here tells an unauthenticated fetcher nothing it did not already
	// know from asking for an unknown kid.
	if agentCredentialLapsed(agent, time.Now()) {
		return nil, fmt.Errorf("capabilitygrant: AgentKeyDescriptor: agent %q lapsed at %s",
			kid, agent.ExpiresAt.Format(time.RFC3339))
	}
	pub, err := parseJWKEd25519(agent.PublicKeyJWK)
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: AgentKeyDescriptor: parse %q public key: %w", kid, err)
	}
	return buildKeyDescriptor(pub, kid, agent.PrincipalRef, agent.TenantID, agent.Status)
}
