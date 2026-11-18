// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build integration
// +build integration

// store_integration_test.go runs the Agent Skill store against a real Postgres
// server that AGENTSKILL_TEST_PG_DSN names. It applies the shipped tenant
// migrations with the migration runner, so it proves that the migration and the
// SQL of the store agree. The unit tests use a fake SQL, and a fake cannot prove
// a transaction, a unique index or a cascade.
package agentskillstore_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/agentskill"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/agentskillstore"
	"github.com/zeroroot-ai/gibson/pkg/platform/migrations"
	"github.com/zeroroot-ai/sdk/auth"
)

// adminDSNEnv names the DSN of a Postgres server on which the test may create
// databases. The test fails when it is not set.
const adminDSNEnv = "AGENTSKILL_TEST_PG_DSN"

type tenantPool struct{ pg *pgxpool.Pool }

func (p *tenantPool) For(_ context.Context, tenant auth.TenantID) (*datapool.Conn, error) {
	return &datapool.Conn{Tenant: tenant, Postgres: p.pg}, nil
}
func (p *tenantPool) Admin(context.Context) (*datapool.AdminConn, error) { return nil, nil }
func (p *tenantPool) SetAdminPool(datapool.AdminAcquirer)                {}
func (p *tenantPool) Close() error                                       { return nil }

// newStore makes a fresh database, applies every tenant migration, and returns
// a store on it with the pool, for direct checks of the rows.
func newStore(t *testing.T) (agentskillstore.Store, *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	adminDSN := os.Getenv(adminDSNEnv)
	require.NotEmpty(t, adminDSN, "%s must name a Postgres server for this test", adminDSNEnv)
	admin, err := pgxpool.New(ctx, adminDSN)
	require.NoError(t, err)
	t.Cleanup(admin.Close)
	dbName := "skills_" + strings.ReplaceAll(types.NewID().String(), "-", "")
	_, err = admin.Exec(ctx, "CREATE DATABASE "+dbName)
	require.NoError(t, err)

	cfg, err := pgxpool.ParseConfig(adminDSN)
	require.NoError(t, err)
	cfg.ConnConfig.Database = dbName
	cfg.MaxConns = 16
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

	return agentskillstore.NewPostgresStore(&tenantPool{pg: pool}), pool
}

// pulled builds one version of the skill name. The tag makes the digest unique.
func pulled(name, tag string) *agentskill.Pulled {
	skill := fmt.Sprintf("---\nname: %s\ndescription: version %s\n---\nbody of %s\n", name, tag, tag)
	return &agentskill.Pulled{
		Manifest: &agentskill.Manifest{Name: name, Description: "version " + tag, Body: "body of " + tag + "\n"},
		Digest:   "sha256:" + tag,
		Files: []agentskill.File{
			{Path: agentskill.SkillFile, Content: []byte(skill)},
			{Path: "references/guide.md", Content: []byte("guide " + tag)},
		},
	}
}

func publish(t *testing.T, s agentskillstore.Store, name, tag string) *agentskillstore.Entry {
	t.Helper()
	e, err := s.Publish(context.Background(), "acme", "registry.test/"+name+"@sha256:"+tag,
		agentskillstore.SourceTenant, pulled(name, tag))
	require.NoError(t, err)
	return e
}

func count(t *testing.T, pool *pgxpool.Pool, query string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(), query, args...).Scan(&n))
	return n
}

// A publish moves the current flag to the new version in one transaction. The
// old version stays readable by its digest.
func TestStore_Integration_PublishMovesTheCurrentFlag(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	v1 := publish(t, s, "web-recon", "aa01")
	assert.True(t, v1.Current)
	v2 := publish(t, s, "web-recon", "bb02")
	assert.True(t, v2.Current)

	assert.Equal(t, 1, count(t, pool, `SELECT count(*) FROM agent_skills WHERE name = 'web-recon' AND is_current`),
		"one current row for the name")
	cur, err := s.Get(ctx, "acme", "web-recon", "")
	require.NoError(t, err)
	assert.Equal(t, "sha256:bb02", cur.Digest)

	old, err := s.Get(ctx, "acme", "web-recon", "sha256:aa01")
	require.NoError(t, err)
	assert.False(t, old.Current, "the old version is no longer current")

	current, err := s.List(ctx, "acme", "", false)
	require.NoError(t, err)
	require.Len(t, current, 1)
	all, err := s.List(ctx, "acme", "web-recon", true)
	require.NoError(t, err)
	assert.Len(t, all, 2)

	// A publish of a digest that the tenant has changes nothing but the flag.
	again := publish(t, s, "web-recon", "aa01")
	assert.True(t, again.Current, "a publish of an old digest makes it current again")
	assert.Equal(t, 1, count(t, pool, `SELECT count(*) FROM agent_skills WHERE name = 'web-recon' AND is_current`))
	assert.Equal(t, 2, count(t, pool, `SELECT count(*) FROM agent_skills WHERE name = 'web-recon'`))
	assert.Equal(t, 4, count(t, pool, `SELECT count(*) FROM agent_skill_files`), "no file row is written twice")
}

// Parallel publishes of one name keep exactly one current row, and each
// publish succeeds.
func TestStore_Integration_ParallelPublishesKeepOneCurrentRow(t *testing.T) {
	s, pool := newStore(t)

	const parallel = 8
	var wg sync.WaitGroup
	errs := make([]error, parallel)
	start := make(chan struct{})
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, errs[i] = s.Publish(context.Background(), "acme", fmt.Sprintf("registry.test/x@sha256:%02x", i),
				agentskillstore.SourceTenant, pulled("web-recon", fmt.Sprintf("%02x", i)))
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "publish %d", i)
	}
	assert.Equal(t, parallel, count(t, pool, `SELECT count(*) FROM agent_skills WHERE name = 'web-recon'`))
	assert.Equal(t, 1, count(t, pool, `SELECT count(*) FROM agent_skills WHERE name = 'web-recon' AND is_current`),
		"exactly one current row")
}

// A mission keeps the digest that it first loaded, even after a new publish.
func TestStore_Integration_TheMissionPinSurvivesAPublish(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	publish(t, s, "web-recon", "aa01")

	first, err := s.Resolve(ctx, "acme", "mission-1", "web-recon")
	require.NoError(t, err)
	assert.Equal(t, "sha256:aa01", first)

	publish(t, s, "web-recon", "bb02")

	again, err := s.Resolve(ctx, "acme", "mission-1", "web-recon")
	require.NoError(t, err)
	assert.Equal(t, "sha256:aa01", again, "the pin does not move")
	other, err := s.Resolve(ctx, "acme", "mission-2", "web-recon")
	require.NoError(t, err)
	assert.Equal(t, "sha256:bb02", other, "a new mission gets the current version")
	assert.Equal(t, 2, count(t, pool, `SELECT count(*) FROM agent_skill_mission_pins`))

	// The pinned version stays loadable, with its files.
	loaded, err := s.Load(ctx, "acme", "web-recon", first)
	require.NoError(t, err)
	assert.Equal(t, "body of aa01\n", loaded.Body)
	require.Len(t, loaded.Files, 1)
	assert.Equal(t, "references/guide.md", loaded.Files[0].Path)
	file, err := s.ReadFile(ctx, "acme", "web-recon", first, "references/guide.md")
	require.NoError(t, err)
	assert.Equal(t, "guide aa01", string(file))

	_, err = s.Resolve(ctx, "acme", "mission-1", "no-such-skill")
	require.ErrorIs(t, err, agentskillstore.ErrNotFound)
}

// A delete of a name removes its versions, and the files and the mission pins
// go with them by the foreign keys.
func TestStore_Integration_DeleteCascades(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	publish(t, s, "web-recon", "aa01")
	publish(t, s, "web-recon", "bb02")
	publish(t, s, "other", "cc03")
	_, err := s.Resolve(ctx, "acme", "mission-1", "web-recon")
	require.NoError(t, err)
	_, err = s.Resolve(ctx, "acme", "mission-1", "other")
	require.NoError(t, err)

	n, err := s.Delete(ctx, "acme", "web-recon")
	require.NoError(t, err)
	assert.EqualValues(t, 2, n, "both versions")

	assert.Equal(t, 0, count(t, pool, `SELECT count(*) FROM agent_skills WHERE name = 'web-recon'`))
	assert.Equal(t, 2, count(t, pool, `SELECT count(*) FROM agent_skill_files`), "only the files of the other skill stay")
	assert.Equal(t, 1, count(t, pool, `SELECT count(*) FROM agent_skill_mission_pins`), "only the pin of the other skill stays")

	_, err = s.Delete(ctx, "acme", "web-recon")
	require.ErrorIs(t, err, agentskillstore.ErrNotFound)
}

// The fixture that fails: a stored file that changed after its sha256 was
// written is refused.
func TestStore_Integration_ACorruptFileIsRefused(t *testing.T) {
	s, pool := newStore(t)
	publish(t, s, "web-recon", "aa01")
	_, err := pool.Exec(context.Background(),
		`UPDATE agent_skill_files SET content = 'tampered' WHERE digest = 'sha256:aa01' AND path = 'references/guide.md'`)
	require.NoError(t, err)

	_, err = s.ReadFile(context.Background(), "acme", "web-recon", "sha256:aa01", "references/guide.md")
	require.ErrorIs(t, err, agentskillstore.ErrCorrupt)
}
