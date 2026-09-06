// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build integration
// +build integration

// store_postgres_integration_test.go exercises the bank store against a real
// Postgres (testcontainers), running the shipped migration rather than a copy
// of it — so the test proves the migration and the DAO agree, which is the one
// thing a hand-written DDL in a test can never prove.
//
// Skipped when Docker is unavailable (testhelpers.StartPostgresTLS owns the skip).
package bank_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/platform/bank"
	"github.com/zeroroot-ai/gibson/tests/testhelpers"
	"github.com/zeroroot-ai/sdk/auth"
)

const intTenant = "acme"

// tenantPool hands every tenant the one test database. The store's isolation
// comes from the database the pool picks, so a test with one database is
// exercising the queries, not the isolation.
type tenantPool struct{ pg *pgxpool.Pool }

func (p *tenantPool) For(_ context.Context, tenant auth.TenantID) (*datapool.Conn, error) {
	return &datapool.Conn{Tenant: tenant, Postgres: p.pg}, nil
}
func (p *tenantPool) Admin(context.Context) (*datapool.AdminConn, error) { return nil, nil }
func (p *tenantPool) SetAdminPool(datapool.AdminAcquirer)                {}
func (p *tenantPool) Close() error                                       { return nil }

func newBankStore(t *testing.T) (bank.Store, *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()

	pgTLS := testhelpers.StartPostgresTLS(t, testhelpers.PostgresOptions{
		User: "testuser", Password: "testpass", Database: "testdb",
	})
	var pool *pgxpool.Pool
	require.Eventually(t, func() bool {
		var err error
		pool, err = pgxpool.New(ctx, pgTLS.DSN)
		if err != nil {
			return false
		}
		return pool.Ping(ctx) == nil
	}, 30*time.Second, 200*time.Millisecond, "Postgres not ready")
	t.Cleanup(pool.Close)

	// The shipped migration, read from disk. A copy in the test would drift.
	up, err := os.ReadFile(filepath.Join("..", "..", "..",
		"pkg", "platform", "migrations", "postgres", "tenant", "010_banks.up.sql"))
	require.NoError(t, err, "read the bank migration")
	_, err = pool.Exec(ctx, string(up))
	require.NoError(t, err, "apply 010_banks.up.sql")

	return bank.NewPostgresStore(&tenantPool{pg: pool}), pool
}

func sampleBank(name string) bank.CreateInput {
	return bank.CreateInput{
		Name: name, OwnerKind: bank.OwnerUser, OwnerID: "alice",
		DesiredCount: 2, LoginShape: bank.LoginShapeAPIKey,
		ProviderConfigName: "tenant-anthropic",
	}
}

func TestBankStore_CRUDLifecycle(t *testing.T) {
	store, _ := newBankStore(t)
	ctx := context.Background()

	created, err := store.Create(ctx, intTenant, sampleBank("nightly"))
	require.NoError(t, err)
	assert.NotEmpty(t, created.ID)
	assert.Equal(t, bank.DefaultAgentName, created.AgentName, "the store fills the defaults")
	assert.Equal(t, bank.DefaultStaleLimit, created.StaleLimit)

	_, err = store.Create(ctx, intTenant, sampleBank("nightly"))
	assert.ErrorIs(t, err, bank.ErrAlreadyExists, "names are unique inside a tenant")

	got, err := store.Get(ctx, intTenant, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "nightly", got.Name)
	assert.Equal(t, bank.LoginShapeAPIKey, got.LoginShape)
	assert.Equal(t, bank.SpillQueue, got.SpillPolicy)
	assert.Equal(t, bank.DefaultStaleLimit, got.StaleLimit, "the duration round-trips through seconds")

	four := int32(4)
	stale := 90 * time.Minute
	spill := bank.SpillEphemeral
	updated, err := store.Update(ctx, intTenant, created.ID, bank.UpdateInput{
		DesiredCount: &four, StaleLimit: &stale, SpillPolicy: &spill,
	})
	require.NoError(t, err)
	assert.Equal(t, int32(4), updated.DesiredCount)
	assert.Equal(t, 90*time.Minute, updated.StaleLimit)
	assert.Equal(t, bank.SpillEphemeral, updated.SpillPolicy)
	assert.Equal(t, "tenant-anthropic", updated.ProviderConfigName, "an absent field keeps its value")
	assert.Equal(t, bank.DefaultMaxJobsInFlight, updated.MaxJobsInFlight)

	require.NoError(t, store.Delete(ctx, intTenant, created.ID))
	_, err = store.Get(ctx, intTenant, created.ID)
	assert.ErrorIs(t, err, bank.ErrNotFound)
	assert.ErrorIs(t, store.Delete(ctx, intTenant, created.ID), bank.ErrNotFound)
}

func TestBankStore_UnknownIdIsNotFound(t *testing.T) {
	store, _ := newBankStore(t)
	_, err := store.Get(context.Background(), intTenant, "no-such-bank")
	assert.ErrorIs(t, err, bank.ErrNotFound)
	_, err = store.Update(context.Background(), intTenant, "no-such-bank", bank.UpdateInput{})
	assert.ErrorIs(t, err, bank.ErrNotFound)
}

func TestBankStore_ListPagesNewestFirst(t *testing.T) {
	store, _ := newBankStore(t)
	ctx := context.Background()

	for _, name := range []string{"one", "two", "three"} {
		_, err := store.Create(ctx, intTenant, sampleBank(name))
		require.NoError(t, err)
		// Distinct created_at values, so "newest first" is observable.
		time.Sleep(2 * time.Millisecond)
	}

	first, next, err := store.List(ctx, intTenant, bank.Page{Size: 2})
	require.NoError(t, err)
	require.Len(t, first, 2)
	require.NotEmpty(t, next, "a full page carries a token")
	assert.Equal(t, "three", first[0].Name, "newest first")
	assert.Equal(t, "two", first[1].Name)

	second, next2, err := store.List(ctx, intTenant, bank.Page{Size: 2, Token: next})
	require.NoError(t, err)
	require.Len(t, second, 1, "the last page holds the remainder")
	assert.Equal(t, "one", second[0].Name)
	assert.Empty(t, next2, "the last page carries no token")
}

func TestBankStore_ListRejectsAnUnreadableToken(t *testing.T) {
	store, _ := newBankStore(t)
	_, _, err := store.List(context.Background(), intTenant, bank.Page{Token: "!!!"})
	assert.ErrorIs(t, err, bank.ErrInvalid, "a silent restart would loop a client forever")
}

func TestBankStore_MembersCascadeWithTheirBank(t *testing.T) {
	store, pool := newBankStore(t)
	ctx := context.Background()

	created, err := store.Create(ctx, intTenant, sampleBank("nightly"))
	require.NoError(t, err)

	// The reconciler writes member rows (slice C3). Here they are inserted
	// directly, so the read path and the cascade are what the test exercises.
	for _, id := range []string{"m-1", "m-2"} {
		_, err = pool.Exec(ctx,
			`INSERT INTO bank_members (id, bank_id, state, jobs_in_flight, job_cap, active_job_ids, claude_version, last_heartbeat)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, now())`,
			id, created.ID, string(bank.MemberIdle), 0, 1, []string{}, "2.0.1")
		require.NoError(t, err)
		time.Sleep(2 * time.Millisecond)
	}

	members, next, err := store.ListMembers(ctx, intTenant, created.ID, bank.Page{})
	require.NoError(t, err)
	require.Len(t, members, 2)
	assert.Equal(t, "m-1", members[0].ID, "oldest first: the order they were launched")
	assert.Equal(t, bank.MemberIdle, members[0].State)
	assert.Equal(t, int32(1), members[0].JobCap)
	assert.False(t, members[0].LastHeartbeat.IsZero())
	assert.Empty(t, next)

	page, next, err := store.ListMembers(ctx, intTenant, created.ID, bank.Page{Size: 1})
	require.NoError(t, err)
	require.Len(t, page, 1)
	require.NotEmpty(t, next)
	rest, _, err := store.ListMembers(ctx, intTenant, created.ID, bank.Page{Size: 1, Token: next})
	require.NoError(t, err)
	require.Len(t, rest, 1)
	assert.Equal(t, "m-2", rest[0].ID)

	require.NoError(t, store.Delete(ctx, intTenant, created.ID))
	var count int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM bank_members`).Scan(&count))
	assert.Zero(t, count, "member rows cascade with their bank")
}

func TestBankStore_RefusesAnInvalidInput(t *testing.T) {
	store, _ := newBankStore(t)
	in := sampleBank("bad")
	in.LoginShape = "oauth"
	_, err := store.Create(context.Background(), intTenant, in)
	assert.ErrorIs(t, err, bank.ErrInvalid, "validation runs before the database is touched")
}
