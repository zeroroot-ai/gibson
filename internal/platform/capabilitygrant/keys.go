// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package capabilitygrant

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrKeyNotAvailable reports that an agent has no key to serve: the row does not
// exist, the agent is not active, its credential lapsed, or its key does not parse.
// The key server answers 404 for it. Any other error of AgentKeyDescriptor is a store
// error, and the key server answers 503, so a short database problem is not taken for
// an unknown kid.
var ErrKeyNotAvailable = errors.New("capabilitygrant: no key is available for the agent")

// AgentKeyDescriptor returns the per-kid key descriptor for the agent whose id
// is kid (ADR-0045, gibson#648). The descriptor is a JWKS superset:
//
//	{"keys":[{ed25519 jwk}], "principal":"agent_principal:<acct>",
//	 "tenant":"<tenant>", "status":"active", "capabilities":["mission:originate"]}
//
// capabilities lists every capability name that the agent holds in an active grant,
// in name order. The list is absent when the agent holds none. ext-authz reads it
// without a database. An inbound A2A call needs mission:originate (gibson#1410), and
// it refuses a caller that holds any other name, because a caller identity has the
// one ceiling mission:originate.
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
		return nil, fmt.Errorf("%w: agent %q not found", ErrKeyNotAvailable, kid)
	}
	if agent.Status != "active" {
		return nil, fmt.Errorf("%w: agent %q status %q (not active)", ErrKeyNotAvailable, kid, agent.Status)
	}
	// Withhold a lapsed agent's key. Without this the sentence above about
	// expired agents was decoration: ext-authz would keep fetching the key and
	// keep accepting tokens the agent signed long after its registered lifetime
	// ran out. The caller renders every error from here as a flat 404, so
	// refusing here tells an unauthenticated fetcher nothing it did not already
	// know from asking for an unknown kid.
	if agentCredentialLapsed(agent, time.Now()) {
		return nil, fmt.Errorf("%w: agent %q lapsed at %s",
			ErrKeyNotAvailable, kid, agent.ExpiresAt.Format(time.RFC3339))
	}
	pub, err := parseJWKEd25519(agent.PublicKeyJWK)
	if err != nil {
		return nil, fmt.Errorf("%w: parse the public key of %q: %w", ErrKeyNotAvailable, kid, err)
	}
	held, err := s.store.ActiveCapabilityNames(ctx, agent.TenantID, agent.PrincipalRef)
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: AgentKeyDescriptor: read the capabilities of %q: %w", kid, err)
	}
	return buildKeyDescriptor(pub, kid, agent.PrincipalRef, agent.TenantID, agent.Status, held)
}
