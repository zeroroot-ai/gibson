// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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
//
// Tenant scoping — two deliberately different shapes:
//
//   - Tenant-facing reads and writes take tenantID as their FIRST identifying
//     argument and carry it into the WHERE clause. A row belonging to another
//     tenant is invisible to them, so a caller that supplies an id it merely
//     guessed reads and writes nothing.
//   - Identity resolution (GetAgent, GetHost, UpdateAgentLastActive) takes NO
//     tenant, by construction: these back credential verification, where the key
//     id IS the claimed identity and the tenant is the ANSWER rather than an
//     input. Adding a tenant argument there would mean trusting a caller-asserted
//     tenant during authentication. They are named "…" without a tenant
//     parameter precisely so a tenant-facing caller cannot reach for one by
//     accident; use the tenant-scoped method for anything a request can name.
package capabilitygrant

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Sentinel errors callers distinguish from an infrastructure failure.
var (
	// ErrBootstrapCredentialConsumed reports that the enrollment credential
	// presented has already been exchanged for an identity. ADR-0045 makes the
	// credential one-time: the holder trades it for a persistent host key on
	// first registration and authenticates with that key from then on.
	ErrBootstrapCredentialConsumed = errors.New("capabilitygrant: enrollment credential has already been used")

	// ErrHostNotRegistrable reports that the host id is held by another tenant,
	// or that the host has been revoked. Either way the registration is refused
	// rather than allowed to overwrite the existing row.
	ErrHostNotRegistrable = errors.New("capabilitygrant: host is registered to another tenant or has been revoked")

	// ErrAgentNotInTenant reports that no agent with the given id exists inside
	// the given tenant.
	ErrAgentNotInTenant = errors.New("capabilitygrant: agent does not exist in this tenant")

	// ErrHostNotInTenant reports that no host with the given id exists inside
	// the given tenant.
	ErrHostNotInTenant = errors.New("capabilitygrant: host does not exist in this tenant")
)

// sweepSpentEnrollmentsQuery drops consumption records that can no longer match
// a live credential. A credential cannot outlive maxBootstrapTTL (24h), so a
// record older than that is unreachable; the 48h interval keeps the sweep
// insensitive to clock skew between the minting and registering daemons.
//
// The name deliberately avoids "credential": gosec's G101 reads any constant
// whose name matches its credential vocabulary as a hardcoded secret, and this
// one is a SQL statement.
const sweepSpentEnrollmentsQuery = `
DELETE FROM capability_grant_bootstrap_consumptions
WHERE  consumed_at < now() - INTERVAL '48 hours'`

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
// Enrollment (the single write path for registration)
// ---------------------------------------------------------------------------

// Enrollment is everything one accepted registration writes: the host, the
// agent registered under it, that agent's resolved grants, and — for a first
// registration — the record that burns the enrollment credential.
type Enrollment struct {
	// Host is the machine or runner the component runs on. Inserted, or updated
	// in place when the same host key registers again.
	Host Host

	// Agent is the component identity created under Host. Always a fresh row.
	Agent Agent

	// Grants are the capabilities resolved for Agent. They replace whatever the
	// agent held before.
	Grants []Grant

	// BootstrapTokenHash is the hex SHA-256 of the enrollment credential the
	// caller presented, and is consumed by this enrollment. Empty ONLY when the
	// caller authenticated with a host key it already holds (re-registration),
	// which is proof of possession rather than a one-time credential.
	//
	// When set, the record is written in the same transaction as the host and
	// agent rows: the second registration that presents the same credential
	// conflicts on the primary key, the whole transaction aborts, and no second
	// identity comes into existence.
	BootstrapTokenHash string
}

// Enroll writes one registration atomically: consume the credential, upsert the
// host, insert the agent, replace the agent's grants — or write nothing at all.
//
// It returns ErrBootstrapCredentialConsumed when the credential has already been
// exchanged, and ErrHostNotRegistrable when the host id belongs to another
// tenant or has been revoked.
func (s *CapabilityGrantStore) Enroll(ctx context.Context, e Enrollment) (err error) {
	if e.Host.TenantID == "" || e.Agent.TenantID == "" {
		return errors.New("capabilitygrant: Enroll: host and agent tenant are required")
	}
	if e.Host.TenantID != e.Agent.TenantID {
		return fmt.Errorf("capabilitygrant: Enroll: host tenant %q does not match agent tenant %q",
			e.Host.TenantID, e.Agent.TenantID)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("capabilitygrant: Enroll %q: begin tx: %w", e.Agent.ID, err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// Each step assigns the NAMED return before checking it — that is what the
	// deferred rollback reads. A `:=` here would shadow it and leave a failed
	// enrollment committed.
	if e.BootstrapTokenHash != "" {
		err = consumeBootstrapCredential(ctx, tx, e)
		if err != nil {
			return err
		}
	}
	err = upsertHostTx(ctx, tx, e.Host)
	if err != nil {
		return err
	}
	err = createAgentTx(ctx, tx, e.Agent)
	if err != nil {
		return err
	}
	err = replaceGrantsTx(ctx, tx, e.Agent.TenantID, e.Agent.ID, e.Grants)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("capabilitygrant: Enroll %q: commit: %w", e.Agent.ID, err)
	}
	return nil
}

// consumeBootstrapCredential records the credential as spent, and reports
// ErrBootstrapCredentialConsumed when it already was. ON CONFLICT DO NOTHING
// plus a zero-row check is the whole enforcement: the primary key resolves the
// race between two simultaneous presentations of the same credential inside the
// database, so exactly one of them can proceed.
func consumeBootstrapCredential(ctx context.Context, tx *sql.Tx, e Enrollment) error {
	const query = `
INSERT INTO capability_grant_bootstrap_consumptions (
    token_hash, tenant_id, host_id, agent_id
) VALUES ($1, $2, $3, $4)
ON CONFLICT (token_hash) DO NOTHING`

	res, err := tx.ExecContext(ctx, query,
		e.BootstrapTokenHash, e.Agent.TenantID, e.Host.ID, e.Agent.ID)
	if err != nil {
		return fmt.Errorf("capabilitygrant: Enroll: consume credential: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("capabilitygrant: Enroll: consume credential: rows affected: %w", err)
	}
	if n == 0 {
		return ErrBootstrapCredentialConsumed
	}

	// Sweep records that can no longer match a live credential. Enrollment is
	// rare, so folding the sweep in here keeps the table bounded without a
	// separate job that could be forgotten in a self-hosted install.
	if _, err := tx.ExecContext(ctx, sweepSpentEnrollmentsQuery); err != nil {
		return fmt.Errorf("capabilitygrant: Enroll: sweep consumed credentials: %w", err)
	}
	return nil
}

// upsertHostTx inserts the host, or updates it in place when the same host key
// registers again.
//
// The ON CONFLICT branch is guarded, and the guard is the point: an existing row
// is only ever updated by ITS OWN tenant, and never once revoked. Without the
// guard the primary key alone decided the outcome, so a registration could move
// a host to a different tenant or return a revoked host to active — undoing a
// revocation with a write the revoker never sees. tenant_id is also absent from
// the SET list: a host belongs to the tenant that first registered it, for life.
func upsertHostTx(ctx context.Context, tx *sql.Tx, host Host) error {
	const query = `
INSERT INTO capability_grant_hosts (
    id, tenant_id, user_id, display_name, public_key_jwk, status,
    principal_ref, created_at, updated_at
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, now(), now()
)
ON CONFLICT (id) DO UPDATE SET
    user_id        = EXCLUDED.user_id,
    display_name   = EXCLUDED.display_name,
    public_key_jwk = EXCLUDED.public_key_jwk,
    status         = EXCLUDED.status,
    -- Preserve an existing principal_ref when a re-registration upsert carries
    -- an empty one (host+jwt path derives it from the row, not the request).
    principal_ref  = CASE WHEN EXCLUDED.principal_ref <> '' THEN EXCLUDED.principal_ref
                          ELSE capability_grant_hosts.principal_ref END,
    updated_at     = now()
WHERE  capability_grant_hosts.tenant_id = EXCLUDED.tenant_id
  AND  capability_grant_hosts.status <> 'revoked'`

	res, err := tx.ExecContext(ctx, query,
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
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("capabilitygrant: UpsertHost %q: rows affected: %w", host.ID, err)
	}
	if n == 0 {
		// The insert conflicted and the guard refused the update.
		return ErrHostNotRegistrable
	}
	return nil
}

// createAgentTx inserts the agent, but only under a live host of the SAME
// tenant — so a registration cannot attach an identity to a host it does not
// own, and cannot register a new agent under a host that has been revoked.
func createAgentTx(ctx context.Context, tx *sql.Tx, agent Agent) error {
	const query = `
INSERT INTO capability_grant_agents (
    id, host_id, tenant_id, user_id, name, mode,
    public_key_jwk, status, session_ttl_s, max_lifetime_s,
    last_active_at, expires_at, principal_ref, created_at
)
SELECT $1::text, $2::text, $3::text, $4::text, $5::text, $6::text,
       $7::jsonb, $8::text, $9::int, $10::int,
       $11::timestamptz, $12::timestamptz, $13::text, now()
WHERE EXISTS (
    SELECT 1 FROM capability_grant_hosts h
    WHERE  h.id = $2::text AND h.tenant_id = $3::text AND h.status <> 'revoked'
)`

	res, err := tx.ExecContext(ctx, query,
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
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("capabilitygrant: CreateAgent %q: rows affected: %w", agent.ID, err)
	}
	if n == 0 {
		return ErrHostNotRegistrable
	}
	return nil
}

// replaceGrantsTx clears the agent's grants and writes the given set. Both
// statements are predicated on the agent belonging to tenantID, so a grant can
// never be written onto — or cleared from — another tenant's agent.
func replaceGrantsTx(ctx context.Context, tx *sql.Tx, tenantID, agentID string, grants []Grant) error {
	const deleteQuery = `
DELETE FROM capability_grant_grants
WHERE  agent_id = $1
  AND  EXISTS (SELECT 1 FROM capability_grant_agents a
               WHERE a.id = $1 AND a.tenant_id = $2)`

	if _, err := tx.ExecContext(ctx, deleteQuery, agentID, tenantID); err != nil {
		return fmt.Errorf("capabilitygrant: SetGrants %q: delete: %w", agentID, err)
	}

	const insertQuery = `
INSERT INTO capability_grant_grants (
    agent_id, capability_name, component_ref, constraints, status
)
SELECT $1::text, $2::text, $3::text, $4::jsonb, $5::text
WHERE EXISTS (SELECT 1 FROM capability_grant_agents a
              WHERE a.id = $1::text AND a.tenant_id = $6::text)`

	for i, g := range grants {
		constraints := g.Constraints
		if len(constraints) == 0 {
			constraints = json.RawMessage("{}")
		}
		res, err := tx.ExecContext(ctx, insertQuery,
			agentID,
			g.CapabilityName,
			g.ComponentRef,
			[]byte(constraints),
			g.Status,
			tenantID,
		)
		if err != nil {
			return fmt.Errorf("capabilitygrant: SetGrants %q: insert[%d]: %w", agentID, i, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("capabilitygrant: SetGrants %q: insert[%d]: rows affected: %w", agentID, i, err)
		}
		if n == 0 {
			return ErrAgentNotInTenant
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Host operations
// ---------------------------------------------------------------------------

// GetHost resolves a host by the id a CREDENTIAL claims, for signature
// verification — the host+jwt issuer is the thumbprint of the key that signed
// it, and the tenant on the returned row is the answer the caller is asking
// for. It therefore takes no tenant argument and MUST NOT be used to serve a
// tenant-facing read; those go through a tenant-scoped method.
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

// GetAgent resolves an agent by the id a CREDENTIAL claims (the agent+jwt
// kid/sub), for signature verification and key serving. The tenant on the
// returned row is the answer, not an input, so this takes no tenant argument
// and MUST NOT serve a tenant-facing read — use GetAgentInTenant for anything a
// request can name.
// Returns (nil, nil) when no record exists.
func (s *CapabilityGrantStore) GetAgent(ctx context.Context, agentID string) (*Agent, error) {
	return s.getAgent(ctx, agentID, "")
}

// GetAgentInTenant retrieves the agent with the given ID from within tenantID.
// An agent belonging to any other tenant reads as absent, so a caller that
// supplies an id it does not own learns nothing about it.
// Returns (nil, nil) when no such agent exists in that tenant.
func (s *CapabilityGrantStore) GetAgentInTenant(ctx context.Context, tenantID, agentID string) (*Agent, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("capabilitygrant: GetAgentInTenant %q: tenant is required", agentID)
	}
	return s.getAgent(ctx, agentID, tenantID)
}

// getAgent backs both agent reads. A non-empty tenantID adds the tenant
// predicate; the empty tenantID is reachable only from GetAgent, the
// credential-verification path.
func (s *CapabilityGrantStore) getAgent(ctx context.Context, agentID, tenantID string) (*Agent, error) {
	const selectClause = `
SELECT a.id, a.host_id, a.tenant_id, COALESCE(a.user_id, ''), a.name, a.mode,
       a.public_key_jwk, a.status, a.session_ttl_s, a.max_lifetime_s,
       a.last_active_at, a.expires_at, COALESCE(a.principal_ref, ''), a.created_at
FROM   capability_grant_agents a
WHERE  a.id = $1`

	query := selectClause
	args := []any{agentID}
	if tenantID != "" {
		query += `
  AND  a.tenant_id = $2`
		args = append(args, tenantID)
	}

	var ag Agent
	var jwk []byte
	var lastActive sql.NullTime
	var expiresAt sql.NullTime

	err := s.db.QueryRowContext(ctx, query, args...).Scan(
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

// UpdateAgentStatus sets the status column for the given agent within
// tenantID. It reports ErrAgentNotInTenant when the agent is not that tenant's,
// so a status write aimed at another tenant's agent fails loudly instead of
// silently updating nothing (or, before the predicate existed, updating it).
func (s *CapabilityGrantStore) UpdateAgentStatus(ctx context.Context, tenantID, agentID, status string) error {
	const query = `UPDATE capability_grant_agents SET status = $3 WHERE id = $1 AND tenant_id = $2`
	res, err := s.db.ExecContext(ctx, query, agentID, tenantID, status)
	if err != nil {
		return fmt.Errorf("capabilitygrant: UpdateAgentStatus %q → %q: %w", agentID, status, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("capabilitygrant: UpdateAgentStatus %q: rows affected: %w", agentID, err)
	}
	if n == 0 {
		return ErrAgentNotInTenant
	}
	return nil
}

// UpdateAgentLastActive stamps last_active_at = now() for the agent a verified
// credential just identified. Like GetAgent it takes no tenant: the caller is
// the verifier, which has already resolved the row this id names.
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

// GetGrants returns all grants for the given agent within tenantID, ordered by
// granted_at ascending (oldest first).
//
// capability_grant_grants carries no tenant column of its own — a grant belongs
// to an agent, and the agent carries the tenant — so the predicate is a join
// onto the owning agent rather than a column comparison. Asking for another
// tenant's agent returns nothing.
func (s *CapabilityGrantStore) GetGrants(ctx context.Context, tenantID, agentID string) ([]Grant, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("capabilitygrant: GetGrants %q: tenant is required", agentID)
	}
	const query = `
SELECT g.id, g.agent_id, g.capability_name, g.component_ref, g.constraints, g.status, g.granted_at
FROM   capability_grant_grants g
JOIN   capability_grant_agents a ON a.id = g.agent_id
WHERE  g.agent_id = $1
  AND  a.tenant_id = $2
ORDER BY g.granted_at ASC`

	rows, err := s.db.QueryContext(ctx, query, agentID, tenantID)
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

// HasActiveGrant reports whether principalRef holds an ACTIVE grant named
// capabilityName within tenantID, on an agent that is itself active.
//
// principalRef, not agent_id: a request-time capability check arrives with
// the caller's FGA principal ref (the CG-JWT's verified identity), never the
// capability_grant_agents row id — that id is an internal enrollment detail
// the caller does not carry on its per-RPC token. The join walks
// capability_grant_agents.principal_ref to get there.
//
// Both status predicates matter: a revoked agent's grants are not
// individually revoked (RevokeAgent flips the agent row and cascades via
// RevokeCapabilityGrant, but a grant tied to a since-revoked agent must not
// read as active either way), and a grant can be individually revoked while
// its agent stays active. Either one being non-active is a "no."
func (s *CapabilityGrantStore) HasActiveGrant(ctx context.Context, tenantID, principalRef, capabilityName string) (bool, error) {
	if tenantID == "" {
		return false, errors.New("capabilitygrant: HasActiveGrant: tenant is required")
	}
	if principalRef == "" {
		return false, errors.New("capabilitygrant: HasActiveGrant: principal_ref is required")
	}
	if capabilityName == "" {
		return false, errors.New("capabilitygrant: HasActiveGrant: capability_name is required")
	}
	const query = `
SELECT EXISTS (
  SELECT 1
  FROM   capability_grant_grants g
  JOIN   capability_grant_agents a ON a.id = g.agent_id
  WHERE  a.tenant_id = $1
    AND  a.principal_ref = $2
    AND  a.status = 'active'
    AND  g.capability_name = $3
    AND  g.status = 'active'
)`
	var exists bool
	if err := s.db.QueryRowContext(ctx, query, tenantID, principalRef, capabilityName).Scan(&exists); err != nil {
		return false, fmt.Errorf("capabilitygrant: HasActiveGrant %q: %w", capabilityName, err)
	}
	return exists, nil
}

// ActiveGrantID returns the id of the ACTIVE grant named capabilityName held
// by principalRef within tenantID, or "" when there is none.
//
// Same predicates as HasActiveGrant — this is that query with the row's id
// instead of EXISTS — because the two must never disagree: a caller that is
// authorized must always have an identifiable grant to attribute the action
// to, and a caller that is not must get "" rather than an id it could be
// blamed for. gibson#1358 records that id as the immutable lineage of a
// component-originated mission, so "which grant authorized this" survives
// the grant's later revocation.
//
// The UNIQUE(agent_id, capability_name) constraint on capability_grant_grants
// means at most one row can match per agent; LIMIT 1 guards only against a
// principal_ref shared by two agent rows, in which case any active grant is
// an equally true answer to "may this principal do it".
func (s *CapabilityGrantStore) ActiveGrantID(ctx context.Context, tenantID, principalRef, capabilityName string) (string, error) {
	if tenantID == "" {
		return "", errors.New("capabilitygrant: ActiveGrantID: tenant is required")
	}
	if principalRef == "" {
		return "", errors.New("capabilitygrant: ActiveGrantID: principal_ref is required")
	}
	if capabilityName == "" {
		return "", errors.New("capabilitygrant: ActiveGrantID: capability_name is required")
	}
	const query = `
SELECT g.id
FROM   capability_grant_grants g
JOIN   capability_grant_agents a ON a.id = g.agent_id
WHERE  a.tenant_id = $1
  AND  a.principal_ref = $2
  AND  a.status = 'active'
  AND  g.capability_name = $3
  AND  g.status = 'active'
LIMIT 1`
	var id string
	switch err := s.db.QueryRowContext(ctx, query, tenantID, principalRef, capabilityName).Scan(&id); {
	case errors.Is(err, sql.ErrNoRows):
		return "", nil
	case err != nil:
		return "", fmt.Errorf("capabilitygrant: ActiveGrantID %q: %w", capabilityName, err)
	}
	return id, nil
}

// ---------------------------------------------------------------------------
// Cascade revocations
// ---------------------------------------------------------------------------

// RevokeAgent sets the agent's status to 'revoked' and revokes all of its
// grants in a single transaction, within tenantID.
//
// It reports ErrAgentNotInTenant when the agent is not that tenant's: a
// revocation aimed at somebody else's agent must fail where the caller can see
// it, not appear to succeed.
func (s *CapabilityGrantStore) RevokeAgent(ctx context.Context, tenantID, agentID string) error {
	if tenantID == "" {
		return fmt.Errorf("capabilitygrant: RevokeAgent %q: tenant is required", agentID)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("capabilitygrant: RevokeAgent %q: begin tx: %w", agentID, err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	var res sql.Result
	if res, err = tx.ExecContext(ctx,
		`UPDATE capability_grant_agents SET status = 'revoked' WHERE id = $1 AND tenant_id = $2`,
		agentID, tenantID,
	); err != nil {
		return fmt.Errorf("capabilitygrant: RevokeAgent %q: update agent: %w", agentID, err)
	}
	var n int64
	if n, err = res.RowsAffected(); err != nil {
		return fmt.Errorf("capabilitygrant: RevokeAgent %q: rows affected: %w", agentID, err)
	}
	if n == 0 {
		err = ErrAgentNotInTenant
		return err
	}

	if _, err = tx.ExecContext(ctx, `
UPDATE capability_grant_grants
SET    status = 'revoked'
WHERE  agent_id = $1
  AND  EXISTS (SELECT 1 FROM capability_grant_agents a
               WHERE a.id = $1 AND a.tenant_id = $2)`,
		agentID, tenantID,
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
// in a single transaction, within tenantID.
//
// It reports ErrHostNotInTenant when the host is not that tenant's.
func (s *CapabilityGrantStore) RevokeHost(ctx context.Context, tenantID, hostID string) error {
	if tenantID == "" {
		return fmt.Errorf("capabilitygrant: RevokeHost %q: tenant is required", hostID)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("capabilitygrant: RevokeHost %q: begin tx: %w", hostID, err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	var res sql.Result
	if res, err = tx.ExecContext(ctx,
		`UPDATE capability_grant_hosts SET status = 'revoked', updated_at = now() WHERE id = $1 AND tenant_id = $2`,
		hostID, tenantID,
	); err != nil {
		return fmt.Errorf("capabilitygrant: RevokeHost %q: update host: %w", hostID, err)
	}
	var n int64
	if n, err = res.RowsAffected(); err != nil {
		return fmt.Errorf("capabilitygrant: RevokeHost %q: rows affected: %w", hostID, err)
	}
	if n == 0 {
		err = ErrHostNotInTenant
		return err
	}

	// Revoke grants for all agents under this host in one UPDATE via a subquery.
	if _, err = tx.ExecContext(ctx, `
UPDATE capability_grant_grants
SET    status = 'revoked'
WHERE  agent_id IN (SELECT id FROM capability_grant_agents
                    WHERE host_id = $1 AND tenant_id = $2)`,
		hostID, tenantID,
	); err != nil {
		return fmt.Errorf("capabilitygrant: RevokeHost %q: update grants: %w", hostID, err)
	}

	if _, err = tx.ExecContext(ctx,
		`UPDATE capability_grant_agents SET status = 'revoked' WHERE host_id = $1 AND tenant_id = $2`,
		hostID, tenantID,
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
