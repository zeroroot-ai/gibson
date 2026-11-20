// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package incidentreport

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
)

// GrantSource reads one grant of one tenant by its id.
// *capabilitygrant.CapabilityGrantStore implements it.
type GrantSource interface {
	GrantByID(ctx context.Context, tenantID, grantID string) (*capabilitygrant.AgentGrant, error)
}

// StoreGrants resolves the grant of a response action from the grant store.
type StoreGrants struct {
	Source GrantSource
}

// GrantByID returns the grant with the id, or nil when the tenant holds none.
// The id comes from the event of the call, so the report never guesses a grant
// from the name of an agent.
func (g StoreGrants) GrantByID(ctx context.Context, tenant, grantID string) (*Grant, error) {
	gr, err := g.Source.GrantByID(ctx, tenant, grantID)
	if err != nil {
		return nil, fmt.Errorf("incidentreport: grant %q: %w", grantID, err)
	}
	if gr == nil {
		return nil, nil //nolint:nilnil // nil means that the tenant holds no grant with the id
	}
	return &Grant{
		ID: gr.ID, Capability: gr.CapabilityName,
		GrantedBy: gr.OwnerUserID, GrantedAtUnix: gr.GrantedAt.Unix(),
	}, nil
}
