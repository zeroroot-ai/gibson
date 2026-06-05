package capabilitygrant

import (
	"context"
	"fmt"
)

// AgentPublicKeyJWKS returns a single-key JWKS document for the agent whose id is
// kid, keyed by that id. ext-authz fetches this per-kid to verify a component's
// self-signed agent+jwt (kid = agentID; see ADR-0045, gibson#648). Only active
// agents resolve — a revoked/expired agent's key is withheld so its signed
// tokens fail verification.
func (s *CapabilityGrantService) AgentPublicKeyJWKS(ctx context.Context, kid string) ([]byte, error) {
	agent, err := s.store.GetAgent(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: AgentPublicKeyJWKS: lookup %q: %w", kid, err)
	}
	if agent.Status != "active" {
		return nil, fmt.Errorf("capabilitygrant: AgentPublicKeyJWKS: agent %q status %q (not active)", kid, agent.Status)
	}
	pub, err := parseJWKEd25519(agent.PublicKeyJWK)
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: AgentPublicKeyJWKS: parse %q public key: %w", kid, err)
	}
	return buildJWKS(pub, kid)
}
