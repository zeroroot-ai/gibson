// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package incidentreport

import (
	"context"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/blueteam"
	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
)

// GrantSource reads one grant of one tenant by its id.
// *capabilitygrant.CapabilityGrantStore implements it.
type GrantSource interface {
	GrantByID(ctx context.Context, tenantID, grantID string) (*capabilitygrant.AgentGrant, error)
}

// GrantChangeSource reads the audit records of the grant changes of one agent
// principal in one tenant: agent_grant_added and agent_grant_removed, up to the
// time until. The person who gave a grant is the actor of its record.
type GrantChangeSource interface {
	GrantChanges(ctx context.Context, tenant, principal string, until time.Time) ([]audit.PgEntry, error)
}

// StoreGrants resolves the grant of a response action from the grant store, and
// the person who gave it from the audit record of the grant.
type StoreGrants struct {
	Source  GrantSource
	Changes GrantChangeSource
}

// GrantByID returns the grant with the id, or nil when the tenant holds none.
// The id comes from the event of the call, so the report never guesses a grant
// from the name of an agent. GrantedBy is the person who gave the grant, read
// from the audit record of the change that was in force at the time of the call.
// It is empty when no such record exists, and when the call has no time. It is never the owner of the agent,
// because the owner of an agent did not give each grant of it.
func (g StoreGrants) GrantByID(ctx context.Context, tenant, grantID string, at time.Time) (*Grant, error) {
	gr, err := g.Source.GrantByID(ctx, tenant, grantID)
	if err != nil {
		return nil, fmt.Errorf("incidentreport: grant %q: %w", grantID, err)
	}
	if gr == nil {
		return nil, nil //nolint:nilnil // nil means that the tenant holds no grant with the id
	}
	out := &Grant{ID: gr.ID, Capability: gr.CapabilityName, GrantedAtUnix: gr.GrantedAt.Unix()}
	// A call with no time has no grantor. The grant in force today is not the grant
	// of a call in the past.
	if g.Changes == nil || gr.PrincipalRef == "" || at.IsZero() {
		return out, nil
	}
	changes, err := g.Changes.GrantChanges(ctx, tenant, gr.PrincipalRef, at)
	if err != nil {
		return nil, fmt.Errorf("incidentreport: grant changes of %q: %w", gr.PrincipalRef, err)
	}
	if grantor, when, ok := blueteam.GrantorOf(changes, gr.PrincipalRef, gr.ComponentRef, at); ok {
		out.GrantedBy, out.GrantedAtUnix = grantor, when.Unix()
	}
	return out, nil
}
