// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build integration
// +build integration

// Package capabilitygrant — enrollment_integrity_integration_test.go
//
// The enrollment invariants against a REAL Postgres carrying the real platform
// migration set. The statement-level assertions in enrollment_integrity_test.go
// say what the daemon sends; these say what the database does with it — ON
// CONFLICT DO NOTHING reporting zero rows affected, a guarded ON CONFLICT DO
// UPDATE declining to fire, and a tenant predicate hiding a row that genuinely
// exists. None of that is reproducible against a mock, and all of it is what
// the invariants rest on. Applying the migration set is also how migration 021
// itself gets exercised.
//
// Run with:
//
//	go test -tags integration ./internal/platform/capabilitygrant/...
package capabilitygrant

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	pgmigrations "github.com/zeroroot-ai/gibson/pkg/platform/migrations"
	"github.com/zeroroot-ai/gibson/tests/testhelpers"
)

// A second Ed25519 JWK, so a test can register a DIFFERENT host.
const otherHostJWK = `{"kty":"OKP","crv":"Ed25519","x":"K5Pmi0hnRLqGqhwvcvHtBmDb7Y1lNP3XvJ8_z9DmKJ0"}`

// liveEnv is one ephemeral Postgres plus a service wired to it.
type liveEnv struct {
	db  *sql.DB
	svc *CapabilityGrantService
}

// newLiveEnv starts a Postgres container, applies the whole platform migration
// set, and returns a service over it. Each test gets its own database so the
// content-addressed host ids cannot collide across tests.
func newLiveEnv(t *testing.T) *liveEnv {
	t.Helper()
	ctx := context.Background()

	pg := testhelpers.StartPostgresTLS(t, testhelpers.PostgresOptions{
		User:     "testuser",
		Password: "testpassword",
		Database: "testcapabilitygrant",
	})

	db, err := sql.Open("postgres", pg.DSN)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	require.Eventually(t, func() bool {
		return db.PingContext(ctx) == nil
	}, 30*time.Second, 200*time.Millisecond, "Postgres did not become ready")

	src, err := pgmigrations.NewPlatformSource()
	require.NoError(t, err)
	defer src.Close()
	driver, err := migratepg.WithInstance(db, &migratepg.Config{})
	require.NoError(t, err)
	mig, err := migrate.NewWithInstance("embedded", src, "postgres", driver)
	require.NoError(t, err)
	require.NoError(t, mig.Up(), "apply the platform migration set")

	// audit_log is provisioned out-of-band in production; this container owns
	// its database, so the test defines the table the Writer inserts into.
	_, err = db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL   PRIMARY KEY,
    tenant_id   TEXT        NOT NULL,
    actor_id    TEXT        NOT NULL,
    actor_type  TEXT        NOT NULL,
    action      TEXT        NOT NULL,
    target_type TEXT,
    target_id   TEXT,
    decision    TEXT,
    metadata    BYTEA       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);`)
	require.NoError(t, err)

	fga := &mockAuthorizer{}
	svc := NewCapabilityGrantService(CapabilityGrantServiceConfig{
		Store:       NewCapabilityGrantStore(db),
		FGABridge:   NewFGABridge(fga, &mockRegistry{}, noopLogger()),
		Authorizer:  fga,
		AuditWriter: audit.NewWriter(db, noopLogger()),
		AuditQuery:  audit.NewQuery(db),
		Logger:      slog.New(slog.DiscardHandler),
	})
	return &liveEnv{db: db, svc: svc}
}

func (e *liveEnv) register(tenant, hostKey, credential string) (*RegisterCapabilityGrantResult, error) {
	return e.svc.RegisterCapabilityGrant(context.Background(),
		tenant, "owner-1", "hello-agent", "autonomous", "agent_principal:acct-1",
		json.RawMessage(hostKey), json.RawMessage(agentJWK),
		"bootstrap", credential, nil,
	)
}

func (e *liveEnv) agentCount(t *testing.T, tenant string) int {
	t.Helper()
	var n int
	require.NoError(t, e.db.QueryRow(
		`SELECT COUNT(*) FROM capability_grant_agents WHERE tenant_id = $1`, tenant).Scan(&n))
	return n
}

// A leaked credential presented a second time mints nothing, and a FRESH
// credential still enrolls — the check is per-credential, not a lock on the
// host, so unattended re-enrollment keeps working.
func TestLive_CredentialBuysExactlyOneIdentity(t *testing.T) {
	env := newLiveEnv(t)

	first, err := env.register("acme", hostJWK, "cred-1")
	require.NoError(t, err)
	require.NotEmpty(t, first.AgentID)

	replayed, err := env.register("acme", hostJWK, "cred-1")
	require.Error(t, err, "a replayed credential must not register a second identity")
	assert.ErrorIs(t, err, ErrBootstrapCredentialConsumed)
	assert.Nil(t, replayed)
	assert.Equal(t, 1, env.agentCount(t, "acme"))

	_, err = env.register("acme", hostJWK, "cred-2")
	require.NoError(t, err, "a fresh credential must still enroll the same host")
	assert.Equal(t, 2, env.agentCount(t, "acme"))
}

// Registering after a revocation does not bring the host back to life.
func TestLive_RevokedHostIsNotResurrectedByRegistering(t *testing.T) {
	env := newLiveEnv(t)
	store := NewCapabilityGrantStore(env.db)

	res, err := env.register("acme", hostJWK, "cred-1")
	require.NoError(t, err)
	require.NoError(t, store.RevokeHost(context.Background(), "acme", res.HostID))

	_, err = env.register("acme", hostJWK, "cred-2")
	require.Error(t, err, "a revoked host must not be re-activated by registering again")
	assert.ErrorIs(t, err, ErrHostNotRegistrable)

	var status string
	require.NoError(t, env.db.QueryRow(
		`SELECT status FROM capability_grant_hosts WHERE id = $1`, res.HostID).Scan(&status))
	assert.Equal(t, "revoked", status)
	assert.Equal(t, 1, env.agentCount(t, "acme"))
}

// A host stays with the tenant that first registered it; a DIFFERENT host key
// still enrolls elsewhere, so the guard is about ownership of one host id
// rather than about the tenant.
func TestLive_HostBelongsToTheTenantThatRegisteredIt(t *testing.T) {
	env := newLiveEnv(t)

	_, err := env.register("acme", hostJWK, "cred-1")
	require.NoError(t, err)

	_, err = env.register("evilcorp", hostJWK, "cred-2")
	require.Error(t, err, "another tenant must not claim a registered host")
	assert.ErrorIs(t, err, ErrHostNotRegistrable)

	var tenant string
	require.NoError(t, env.db.QueryRow(
		`SELECT tenant_id FROM capability_grant_hosts LIMIT 1`).Scan(&tenant))
	assert.Equal(t, "acme", tenant)
	assert.Equal(t, 0, env.agentCount(t, "evilcorp"))

	_, err = env.register("evilcorp", otherHostJWK, "cred-3")
	require.NoError(t, err, "a distinct host must still enroll under another tenant")
	assert.Equal(t, 1, env.agentCount(t, "evilcorp"))
}

// One tenant can neither read nor revoke another tenant's agent, and the
// revoke attempt fails visibly rather than appearing to succeed.
func TestLive_AgentReadsAndRevocationAreScopedToTheTenant(t *testing.T) {
	env := newLiveEnv(t)
	ctx := context.Background()

	res, err := env.register("acme", hostJWK, "cred-1")
	require.NoError(t, err)

	own, err := env.svc.GetCapabilityGrantStatus(ctx, res.AgentID, "acme")
	require.NoError(t, err)
	require.NotNil(t, own)

	other, err := env.svc.GetCapabilityGrantStatus(ctx, res.AgentID, "evilcorp")
	require.NoError(t, err)
	assert.Nil(t, other, "another tenant's agent must read as absent")

	err = env.svc.RevokeCapabilityGrant(ctx, res.AgentID, "evilcorp", "attacker")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAgentNotInTenant)

	var status string
	require.NoError(t, env.db.QueryRow(
		`SELECT status FROM capability_grant_agents WHERE id = $1`, res.AgentID).Scan(&status))
	assert.Equal(t, "active", status, "the agent must survive another tenant's revoke")

	require.NoError(t, env.svc.RevokeCapabilityGrant(ctx, res.AgentID, "acme", "owner-1"))
	require.NoError(t, env.db.QueryRow(
		`SELECT status FROM capability_grant_agents WHERE id = $1`, res.AgentID).Scan(&status))
	assert.Equal(t, "revoked", status)
}
