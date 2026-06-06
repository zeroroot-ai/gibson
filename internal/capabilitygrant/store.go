// Package capabilitygrant — store.go
//
// CapabilityGrantStore is the Postgres-backed CRUD layer for the Capability Grant Protocol.
// It operates against the three tables created by platform migration 008
// (pkg/platform/migrations/postgres/platform/008_capability_grant.up.sql):
//
//   - capability_grant_hosts   — registered host machines / runners
//   - capability_grant_agents  — LLM-driven agents registered under hosts
//   - capability_grant_grants  — capability grants issued to agents
//
// Design principles (mirrors provisioner/signup_state.go):
//   - No business logic. The store is a thin CRUD layer.
//   - No retries. Callers own retry decisions.
//   - Fail fast on database errors. Every method returns the raw error.
//   - Parameterised queries only ($1, $2, …). No string interpolation.
//   - Cascade revocations (RevokeAgent, RevokeHost) run in a single
//     database transaction so partial revocations cannot occur.
package capabilitygrant

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

// Host represents a registered end-user machine or CI runner.
type Host struct {
	ID           string
	TenantID     string
	UserID       string // may be empty for service-level registrations
	DisplayName  string
	PublicKeyJWK json.RawMessage
	Status       string
	// PrincipalRef is the typed FGA principal this host's agents authenticate
	// as (ADR-0045, gibson#648). Stored on the host so re-registration via a
	// host+jwt (which carries no bootstrap claims) can copy it onto each newly
	// registered agent. Set at first registration from the bootstrap claims.
	PrincipalRef string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Agent represents an LLM-driven worker registered under a Host.
type Agent struct {
	ID           string
	HostID       string
	TenantID     string
	UserID       string // may be empty for autonomous agents
	Name         string
	Mode         string // "delegated" or "autonomous"
	PublicKeyJWK json.RawMessage
	Status       string
	// PrincipalRef is the typed FGA principal this agent authenticates as,
	// e.g. "agent_principal:<zitadel-sa-account-id>" (ADR-0045). It is NOT the
	// agent row ID (that is the per-RPC agent+jwt `sub`/`kid`). The per-kid key
	// descriptor serves it so ext-authz can run its FGA check on the
	// daemon-asserted principal. Set at registration from the bootstrap claims.
	PrincipalRef string
	SessionTTL   int
	MaxLifetime  int
	LastActiveAt *time.Time
	ExpiresAt    *time.Time
	CreatedAt    time.Time
}

// Grant records a capability that an Agent is permitted to exercise.
type Grant struct {
	ID             string
	AgentID        string
	CapabilityName string
	ComponentRef   string
	Constraints    json.RawMessage
	Status         string
	GrantedAt      time.Time
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

// CapabilityGrantStore provides CRUD operations for Capability Grant Protocol data.
// All methods are safe for concurrent use.
type CapabilityGrantStore struct {
	db *sql.DB
}

// NewCapabilityGrantStore creates an CapabilityGrantStore backed by the given *sql.DB.
// The db must be non-nil.
func NewCapabilityGrantStore(db *sql.DB) *CapabilityGrantStore {
	if db == nil {
		panic("capabilitygrant: db must not be nil")
	}
	return &CapabilityGrantStore{db: db}
}

// ---------------------------------------------------------------------------
// Host operations
// ---------------------------------------------------------------------------

// UpsertHost inserts a new host record or updates the existing one on
// conflict (matched by primary key id). The updated_at timestamp is always
// refreshed on update.
func (s *CapabilityGrantStore) UpsertHost(ctx context.Context, host Host) error {
	const query = `
INSERT INTO capability_grant_hosts (
    id, tenant_id, user_id, display_name, public_key_jwk, status,
    principal_ref, created_at, updated_at
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, now(), now()
)
ON CONFLICT (id) DO UPDATE SET
    tenant_id      = EXCLUDED.tenant_id,
    user_id        = EXCLUDED.user_id,
    display_name   = EXCLUDED.display_name,
    public_key_jwk = EXCLUDED.public_key_jwk,
    status         = EXCLUDED.status,
    -- Preserve an existing principal_ref when a re-registration upsert carries
    -- an empty one (host+jwt path derives it from the row, not the request).
    principal_ref  = CASE WHEN EXCLUDED.principal_ref <> '' THEN EXCLUDED.principal_ref
                          ELSE capability_grant_hosts.principal_ref END,
    updated_at     = now()`

	_, err := s.db.ExecContext(ctx, query,
		host.ID,
		host.TenantID,
		nullableString(host.UserID),
		host.DisplayName,
		[]byte(host.PublicKeyJWK),
		host.Status,
		host.PrincipalRef,
	)
	if err != nil {
		return fmt.Errorf("capabilitygrant: UpsertHost %q: %w", host.ID, err)
	}
	return nil
}

// GetHost retrieves the host with the given ID.
// Returns (nil, nil) when no record exists.
func (s *CapabilityGrantStore) GetHost(ctx context.Context, hostID string) (*Host, error) {
	const query = `
SELECT id, tenant_id, COALESCE(user_id, ''), display_name,
       public_key_jwk, status, COALESCE(principal_ref, ''), created_at, updated_at
FROM   capability_grant_hosts
WHERE  id = $1`

	var h Host
	var jwk []byte
	err := s.db.QueryRowContext(ctx, query, hostID).Scan(
		&h.ID,
		&h.TenantID,
		&h.UserID,
		&h.DisplayName,
		&jwk,
		&h.Status,
		&h.PrincipalRef,
		&h.CreatedAt,
		&h.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: GetHost %q: %w", hostID, err)
	}
	h.PublicKeyJWK = json.RawMessage(jwk)
	return &h, nil
}

// ---------------------------------------------------------------------------
// Agent operations
// ---------------------------------------------------------------------------

// CreateAgent inserts a new agent record. It returns an error if an agent
// with the same ID already exists.
func (s *CapabilityGrantStore) CreateAgent(ctx context.Context, agent Agent) error {
	const query = `
INSERT INTO capability_grant_agents (
    id, host_id, tenant_id, user_id, name, mode,
    public_key_jwk, status, session_ttl_s, max_lifetime_s,
    last_active_at, expires_at, principal_ref, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10,
    $11, $12, $13, now()
)`

	_, err := s.db.ExecContext(ctx, query,
		agent.ID,
		agent.HostID,
		agent.TenantID,
		nullableString(agent.UserID),
		agent.Name,
		agent.Mode,
		[]byte(agent.PublicKeyJWK),
		agent.Status,
		agent.SessionTTL,
		agent.MaxLifetime,
		nullableTime(agent.LastActiveAt),
		nullableTime(agent.ExpiresAt),
		agent.PrincipalRef,
	)
	if err != nil {
		return fmt.Errorf("capabilitygrant: CreateAgent %q: %w", agent.ID, err)
	}
	return nil
}

// GetAgent retrieves the agent with the given ID.
// Returns (nil, nil) when no record exists.
func (s *CapabilityGrantStore) GetAgent(ctx context.Context, agentID string) (*Agent, error) {
	const query = `
SELECT a.id, a.host_id, a.tenant_id, COALESCE(a.user_id, ''), a.name, a.mode,
       a.public_key_jwk, a.status, a.session_ttl_s, a.max_lifetime_s,
       a.last_active_at, a.expires_at, COALESCE(a.principal_ref, ''), a.created_at
FROM   capability_grant_agents a
WHERE  a.id = $1`

	var ag Agent
	var jwk []byte
	var lastActive sql.NullTime
	var expiresAt sql.NullTime

	err := s.db.QueryRowContext(ctx, query, agentID).Scan(
		&ag.ID,
		&ag.HostID,
		&ag.TenantID,
		&ag.UserID,
		&ag.Name,
		&ag.Mode,
		&jwk,
		&ag.Status,
		&ag.SessionTTL,
		&ag.MaxLifetime,
		&lastActive,
		&expiresAt,
		&ag.PrincipalRef,
		&ag.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: GetAgent %q: %w", agentID, err)
	}
	ag.PublicKeyJWK = json.RawMessage(jwk)
	if lastActive.Valid {
		ag.LastActiveAt = &lastActive.Time
	}
	if expiresAt.Valid {
		ag.ExpiresAt = &expiresAt.Time
	}
	return &ag, nil
}

// ListAgentsByTenant returns a paginated slice of agents belonging to the
// given tenant, along with the total count of matching rows (for pagination
// metadata). Rows are ordered by created_at descending (newest first).
func (s *CapabilityGrantStore) ListAgentsByTenant(
	ctx context.Context,
	tenantID string,
	limit, offset int,
) ([]Agent, int, error) {
	const countQuery = `SELECT COUNT(*) FROM capability_grant_agents WHERE tenant_id = $1`

	var total int
	if err := s.db.QueryRowContext(ctx, countQuery, tenantID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("capabilitygrant: ListAgentsByTenant %q: count: %w", tenantID, err)
	}
	if total == 0 {
		return nil, 0, nil
	}

	const listQuery = `
SELECT id, host_id, tenant_id, COALESCE(user_id, ''), name, mode,
       public_key_jwk, status, session_ttl_s, max_lifetime_s,
       last_active_at, expires_at, created_at
FROM   capability_grant_agents
WHERE  tenant_id = $1
ORDER BY created_at DESC
LIMIT  $2 OFFSET $3`

	rows, err := s.db.QueryContext(ctx, listQuery, tenantID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("capabilitygrant: ListAgentsByTenant %q: query: %w", tenantID, err)
	}
	defer rows.Close()

	var agents []Agent
	for rows.Next() {
		var ag Agent
		var jwk []byte
		var lastActive sql.NullTime
		var expiresAt sql.NullTime

		if err := rows.Scan(
			&ag.ID,
			&ag.HostID,
			&ag.TenantID,
			&ag.UserID,
			&ag.Name,
			&ag.Mode,
			&jwk,
			&ag.Status,
			&ag.SessionTTL,
			&ag.MaxLifetime,
			&lastActive,
			&expiresAt,
			&ag.CreatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("capabilitygrant: ListAgentsByTenant %q: scan: %w", tenantID, err)
		}
		ag.PublicKeyJWK = json.RawMessage(jwk)
		if lastActive.Valid {
			ag.LastActiveAt = &lastActive.Time
		}
		if expiresAt.Valid {
			ag.ExpiresAt = &expiresAt.Time
		}
		agents = append(agents, ag)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("capabilitygrant: ListAgentsByTenant %q: rows: %w", tenantID, err)
	}
	return agents, total, nil
}

// UpdateAgentStatus sets the status column for the given agent.
func (s *CapabilityGrantStore) UpdateAgentStatus(ctx context.Context, agentID, status string) error {
	const query = `UPDATE capability_grant_agents SET status = $2 WHERE id = $1`
	if _, err := s.db.ExecContext(ctx, query, agentID, status); err != nil {
		return fmt.Errorf("capabilitygrant: UpdateAgentStatus %q → %q: %w", agentID, status, err)
	}
	return nil
}

// UpdateAgentLastActive stamps last_active_at = now() for the given agent.
func (s *CapabilityGrantStore) UpdateAgentLastActive(ctx context.Context, agentID string) error {
	const query = `UPDATE capability_grant_agents SET last_active_at = now() WHERE id = $1`
	if _, err := s.db.ExecContext(ctx, query, agentID); err != nil {
		return fmt.Errorf("capabilitygrant: UpdateAgentLastActive %q: %w", agentID, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Grant operations
// ---------------------------------------------------------------------------

// SetGrants replaces all grants for the given agent in a single transaction.
// The existing grants are deleted first, then the new slice is inserted.
// Passing an empty grants slice effectively clears all grants for the agent.
func (s *CapabilityGrantStore) SetGrants(ctx context.Context, agentID string, grants []Grant) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("capabilitygrant: SetGrants %q: begin tx: %w", agentID, err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.ExecContext(ctx,
		`DELETE FROM capability_grant_grants WHERE agent_id = $1`, agentID,
	); err != nil {
		return fmt.Errorf("capabilitygrant: SetGrants %q: delete: %w", agentID, err)
	}

	for i, g := range grants {
		constraints := g.Constraints
		if len(constraints) == 0 {
			constraints = json.RawMessage("{}")
		}
		const insertQuery = `
INSERT INTO capability_grant_grants (
    agent_id, capability_name, component_ref, constraints, status
) VALUES ($1, $2, $3, $4, $5)`

		if _, err = tx.ExecContext(ctx, insertQuery,
			agentID,
			g.CapabilityName,
			g.ComponentRef,
			[]byte(constraints),
			g.Status,
		); err != nil {
			return fmt.Errorf("capabilitygrant: SetGrants %q: insert[%d]: %w", agentID, i, err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("capabilitygrant: SetGrants %q: commit: %w", agentID, err)
	}
	return nil
}

// GetGrants returns all grants for the given agent, ordered by granted_at
// ascending (oldest first).
func (s *CapabilityGrantStore) GetGrants(ctx context.Context, agentID string) ([]Grant, error) {
	const query = `
SELECT id, agent_id, capability_name, component_ref, constraints, status, granted_at
FROM   capability_grant_grants
WHERE  agent_id = $1
ORDER BY granted_at ASC`

	rows, err := s.db.QueryContext(ctx, query, agentID)
	if err != nil {
		return nil, fmt.Errorf("capabilitygrant: GetGrants %q: %w", agentID, err)
	}
	defer rows.Close()

	var grants []Grant
	for rows.Next() {
		var g Grant
		var constraints []byte
		if err := rows.Scan(
			&g.ID,
			&g.AgentID,
			&g.CapabilityName,
			&g.ComponentRef,
			&constraints,
			&g.Status,
			&g.GrantedAt,
		); err != nil {
			return nil, fmt.Errorf("capabilitygrant: GetGrants %q: scan: %w", agentID, err)
		}
		g.Constraints = json.RawMessage(constraints)
		grants = append(grants, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("capabilitygrant: GetGrants %q: rows: %w", agentID, err)
	}
	return grants, nil
}

// ---------------------------------------------------------------------------
// Cascade revocations
// ---------------------------------------------------------------------------

// RevokeAgent sets the agent's status to 'revoked' and revokes all of its
// grants in a single transaction.
func (s *CapabilityGrantStore) RevokeAgent(ctx context.Context, agentID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("capabilitygrant: RevokeAgent %q: begin tx: %w", agentID, err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.ExecContext(ctx,
		`UPDATE capability_grant_agents SET status = 'revoked' WHERE id = $1`,
		agentID,
	); err != nil {
		return fmt.Errorf("capabilitygrant: RevokeAgent %q: update agent: %w", agentID, err)
	}

	if _, err = tx.ExecContext(ctx,
		`UPDATE capability_grant_grants SET status = 'revoked' WHERE agent_id = $1`,
		agentID,
	); err != nil {
		return fmt.Errorf("capabilitygrant: RevokeAgent %q: update grants: %w", agentID, err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("capabilitygrant: RevokeAgent %q: commit: %w", agentID, err)
	}
	return nil
}

// RevokeHost sets the host's status to 'revoked', revokes all agents that
// belong to the host, and revokes all grants belonging to those agents — all
// in a single transaction.
func (s *CapabilityGrantStore) RevokeHost(ctx context.Context, hostID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("capabilitygrant: RevokeHost %q: begin tx: %w", hostID, err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.ExecContext(ctx,
		`UPDATE capability_grant_hosts SET status = 'revoked', updated_at = now() WHERE id = $1`,
		hostID,
	); err != nil {
		return fmt.Errorf("capabilitygrant: RevokeHost %q: update host: %w", hostID, err)
	}

	// Revoke grants for all agents under this host in one UPDATE via a subquery.
	if _, err = tx.ExecContext(ctx, `
UPDATE capability_grant_grants
SET    status = 'revoked'
WHERE  agent_id IN (SELECT id FROM capability_grant_agents WHERE host_id = $1)`,
		hostID,
	); err != nil {
		return fmt.Errorf("capabilitygrant: RevokeHost %q: update grants: %w", hostID, err)
	}

	if _, err = tx.ExecContext(ctx,
		`UPDATE capability_grant_agents SET status = 'revoked' WHERE host_id = $1`,
		hostID,
	); err != nil {
		return fmt.Errorf("capabilitygrant: RevokeHost %q: update agents: %w", hostID, err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("capabilitygrant: RevokeHost %q: commit: %w", hostID, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Nullable helpers
// ---------------------------------------------------------------------------

// nullableString converts an empty string to a sql.NullString (NULL in the
// database) and a non-empty string to a valid sql.NullString.
func nullableString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

// nullableTime converts a nil *time.Time to a sql.NullTime (NULL in the
// database) and a non-nil pointer to a valid sql.NullTime.
func nullableTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}
