// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package capabilitygrant

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// AgentGrant is a grant with the person who owns the agent.
type AgentGrant struct {
	Grant
	// OwnerUserID is the person who owns the agent and gave the grant. It is
	// empty for an autonomous agent with no owner.
	OwnerUserID string
}

// GrantByID returns one grant of the tenant with the owner of its agent, or
// nil when the tenant holds no grant with the id. The incident report reads the
// grant that the Timeline event of a call names (gibson#1478). The tenant is a
// predicate of the query, so an id of another tenant reads nothing.
func (s *CapabilityGrantStore) GrantByID(ctx context.Context, tenantID, grantID string) (*AgentGrant, error) {
	if tenantID == "" {
		return nil, errors.New("capabilitygrant: GrantByID: tenant is required")
	}
	if grantID == "" {
		return nil, errors.New("capabilitygrant: GrantByID: grant id is required")
	}
	const query = `
SELECT g.id, g.agent_id, g.capability_name, g.component_ref, g.status, g.granted_at, COALESCE(a.user_id, '')
FROM   capability_grant_grants g
JOIN   capability_grant_agents a ON a.id = g.agent_id
WHERE  a.tenant_id = $1
  AND  g.id = $2`
	var g AgentGrant
	var grantedAt time.Time
	err := s.db.QueryRowContext(ctx, query, tenantID, grantID).
		Scan(&g.ID, &g.AgentID, &g.CapabilityName, &g.ComponentRef, &g.Status, &grantedAt, &g.OwnerUserID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil //nolint:nilnil // nil means that the tenant holds no grant with the id
	case err != nil:
		return nil, fmt.Errorf("capabilitygrant: GrantByID %q: %w", grantID, err)
	}
	g.GrantedAt = grantedAt
	return &g, nil
}

// ConnectorGrantID returns the id of the active grant that lets the principal
// execute the tools of the connector, or "" when it holds none. A grant names
// the connector by its component (component:connector/<id>) or by the
// capability execute:tool:mcp:<id>. The daemon writes the id on the record of
// each allowed connector call (gibson#1474).
func (s *CapabilityGrantStore) ConnectorGrantID(ctx context.Context, tenantID, principalRef, connector string) (string, error) {
	if tenantID == "" || principalRef == "" || connector == "" {
		return "", errors.New("capabilitygrant: ConnectorGrantID: tenant, principal and connector are required")
	}
	const query = `
SELECT g.id
FROM   capability_grant_grants g
JOIN   capability_grant_agents a ON a.id = g.agent_id
WHERE  a.tenant_id = $1
  AND  a.principal_ref = $2
  AND  a.status = 'active'
  AND  g.status = 'active'
  AND  (g.component_ref = $3 OR g.capability_name = $4)
ORDER BY g.granted_at ASC
LIMIT 1`
	var id string
	err := s.db.QueryRowContext(ctx, query, tenantID, principalRef,
		authz.ConnectorComponentObject(connector), "execute:tool:mcp:"+connector).Scan(&id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", nil
	case err != nil:
		return "", fmt.Errorf("capabilitygrant: ConnectorGrantID %q: %w", connector, err)
	}
	return id, nil
}
