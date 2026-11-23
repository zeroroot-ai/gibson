// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build integration
// +build integration

// store_integration_test.go runs the claim of a message id against a real Postgres
// server that FINDING_TEST_PG_DSN names. It applies the shipped tenant migrations
// with the migration runner, so it proves that migration 026 and the SQL of the
// store agree. The takeover statement of an expired lease is SQL that a unit test
// with a fake database cannot run.
package inboundmissionstore_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/inboundmissionstore"
	"github.com/zeroroot-ai/gibson/pkg/platform/migrations"
	"github.com/zeroroot-ai/sdk/auth"
)

type tenantPool struct{ pg *pgxpool.Pool }

func (p *tenantPool) For(_ context.Context, tenant auth.TenantID) (*datapool.Conn, error) {
	return &datapool.Conn{Tenant: tenant, Postgres: p.pg}, nil
}
func (p *tenantPool) Admin(context.Context) (*datapool.AdminConn, error) { return nil, nil }
func (p *tenantPool) SetAdminPool(datapool.AdminAcquirer)                {}
func (p *tenantPool) Close() error                                       { return nil }

// adminDSNEnv names the DSN of a Postgres server that the test may create databases
// on. The test skips when it is not set.
const adminDSNEnv = "FINDING_TEST_PG_DSN"

// newStore makes a fresh database that stands for one tenant, applies every tenant
// migration, and returns a store and a pool on it.
func newStore(t *testing.T) (inboundmissionstore.Store, *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	adminDSN := os.Getenv(adminDSNEnv)
	if adminDSN == "" {
		t.Skipf("%s is not set", adminDSNEnv)
	}
	admin, err := pgxpool.New(ctx, adminDSN)
	require.NoError(t, err)
	t.Cleanup(admin.Close)
	dbName := "inbound_" + strings.ReplaceAll(types.NewID().String(), "-", "")
	_, err = admin.Exec(ctx, "CREATE DATABASE "+dbName)
	require.NoError(t, err)

	cfg, err := pgxpool.ParseConfig(adminDSN)
	require.NoError(t, err)
	cfg.ConnConfig.Database = dbName
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	db := stdlib.OpenDB(*cfg.ConnConfig)
	t.Cleanup(func() { _ = db.Close() })
	src, err := migrations.NewTenantSource()
	require.NoError(t, err)
	driver, err := migratepg.WithInstance(db, &migratepg.Config{DatabaseName: dbName})
	require.NoError(t, err)
	m, err := migrate.NewWithInstance("iofs", src, dbName, driver)
	require.NoError(t, err)
	require.NoError(t, m.Up(), "the tenant migrations apply")

	tp := &tenantPool{pg: pool}
	return inboundmissionstore.NewPostgresStore(tp), pool
}

// expireLease moves the lease of a key into the past.
func expireLease(t *testing.T, pool *pgxpool.Pool, key string) {
	t.Helper()
	tag, err := pool.Exec(context.Background(),
		`UPDATE inbound_messages SET lease_until = now() - interval '1 minute' WHERE message_key = $1`, key)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
}

// reserveTask writes a published agent and the task row of a mission, as Reserve does
// before a mission starts.
func reserveTask(t *testing.T, store inboundmissionstore.Store, pool *pgxpool.Pool, agent, missionID string) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx,
		`INSERT INTO inbound_missions (agent, publication_id, mission_definition_id, definition_hash, target_ids, target_hashes)
		 VALUES ($1, 'pub-1', 'def-1', 'h', '["t1"]', '{"t1":"h1"}') ON CONFLICT DO NOTHING`, agent)
	require.NoError(t, err)
	_, err = store.Reserve(ctx, "acme", agent, "agent_principal:9", missionID)
	require.NoError(t, err)
}

func TestClaimMessage_NewClaimThenAClaimWhileTheLeaseRuns(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()

	got, err := store.ClaimMessage(ctx, "acme", "recon\x00webhook:okta:e1", "m-1")
	require.NoError(t, err)
	assert.Equal(t, inboundmissionstore.ClaimNew, got, "a new key is claimed")

	got, err = store.ClaimMessage(ctx, "acme", "recon\x00webhook:okta:e1", "m-2")
	require.NoError(t, err)
	assert.Equal(t, inboundmissionstore.ClaimInFlight, got, "a second call while the lease runs waits")
}

func TestClaimMessage_AnExpiredLeaseWithNoTaskRowIsTakenOver(t *testing.T) {
	store, pool := newStore(t)
	ctx := context.Background()
	const key = "recon\x00webhook:okta:e1"
	_, err := store.ClaimMessage(ctx, "acme", key, "m-1")
	require.NoError(t, err)
	expireLease(t, pool, key)

	got, err := store.ClaimMessage(ctx, "acme", key, "m-2")
	require.NoError(t, err)
	assert.Equal(t, inboundmissionstore.ClaimNew, got, "no task row exists for m-1, so the call that stopped lost the claim")

	var mission string
	require.NoError(t, pool.QueryRow(ctx, `SELECT mission_id FROM inbound_messages WHERE message_key = $1`, key).Scan(&mission))
	assert.Equal(t, "m-2", mission, "the claim names the new mission")
	require.NoError(t, store.ConfirmMessage(ctx, "acme", key, "m-2"))
	require.ErrorIs(t, store.ConfirmMessage(ctx, "acme", key, "m-1"), inboundmissionstore.ErrNotFound,
		"the call that lost the claim cannot confirm it")
}

func TestClaimMessage_AnExpiredLeaseWithATaskRowIsADuplicate(t *testing.T) {
	store, pool := newStore(t)
	ctx := context.Background()
	const key = "recon\x00webhook:okta:e1"
	_, err := store.ClaimMessage(ctx, "acme", key, "m-1")
	require.NoError(t, err)
	reserveTask(t, store, pool, "recon", "m-1") // the mission was reserved, and only its confirm failed
	expireLease(t, pool, key)

	got, err := store.ClaimMessage(ctx, "acme", key, "m-2")
	require.NoError(t, err)
	assert.Equal(t, inboundmissionstore.ClaimDuplicate, got, "the mission m-1 may run, so a retry must not start another")

	var mission string
	require.NoError(t, pool.QueryRow(ctx, `SELECT mission_id FROM inbound_messages WHERE message_key = $1`, key).Scan(&mission))
	assert.Equal(t, "m-1", mission, "the claim was not taken over")
}

func TestClaimMessage_ConfirmForgetAndTheTenantDatabase(t *testing.T) {
	store, pool := newStore(t)
	ctx := context.Background()
	const key = "recon\x00webhook:okta:e1"

	_, err := store.ClaimMessage(ctx, "acme", key, "m-1")
	require.NoError(t, err)
	require.NoError(t, store.ConfirmMessage(ctx, "acme", key, "m-1"))
	got, err := store.ClaimMessage(ctx, "acme", key, "m-2")
	require.NoError(t, err)
	assert.Equal(t, inboundmissionstore.ClaimDuplicate, got, "a confirmed key is a duplicate")

	require.NoError(t, store.ForgetMessage(ctx, "acme", key, "m-1"))
	got, err = store.ClaimMessage(ctx, "acme", key, "m-3")
	require.NoError(t, err)
	assert.Equal(t, inboundmissionstore.ClaimDuplicate, got, "a confirmed key is never forgotten")

	const other = "recon\x00webhook:okta:e2"
	_, err = store.ClaimMessage(ctx, "acme", other, "m-4")
	require.NoError(t, err)
	require.NoError(t, store.ForgetMessage(ctx, "acme", other, "m-4"))
	got, err = store.ClaimMessage(ctx, "acme", other, "m-5")
	require.NoError(t, err)
	assert.Equal(t, inboundmissionstore.ClaimNew, got, "a pending claim that is given back can be claimed again")

	// The same key in the database of another tenant is a new key.
	otherStore, _ := newStore(t)
	got, err = otherStore.ClaimMessage(ctx, "globex", key, "m-6")
	require.NoError(t, err)
	assert.Equal(t, inboundmissionstore.ClaimNew, got, "the key belongs to the database of the tenant")
	_ = pool
}
