// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build integration
// +build integration

// The Timeline export and retention against a real Postgres and a real MinIO
// (testcontainers), with the shipped tenant migrations 013 and 014. MinIO
// stands in for the durable bucket: the bucket has object lock (gibson#992).
package timelinearchive_test

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/timelinearchive"
	"github.com/zeroroot-ai/gibson/tests/testhelpers"
	"github.com/zeroroot-ai/sdk/auth"
)

const (
	minioImage     = "ghcr.io/zeroroot-ai/mirror/minio:RELEASE.2024-09-13T20-26-02Z"
	minioAccessKey = "timeline-export"
	minioSecretKey = "timeline-export-secret"
	minioBucket    = "durable"
	tenantName     = "acme"
)

// heldConn is a tenant connection whose Release does nothing: the test owns
// the pool.
type heldConn struct{ *datapool.Conn }

func (heldConn) Release() {}

type onePool struct{ pg *pgxpool.Pool }

func (p onePool) For(_ context.Context, tenant auth.TenantID) (timelinearchive.TenantDB, error) {
	return heldConn{&datapool.Conn{Tenant: tenant, Postgres: p.pg}}, nil
}

// startPostgres starts Postgres, applies the two tenant migrations of the
// history, and adds the platform table that lists the tenants. One database
// plays both parts: the archive reads the tenant list from the platform
// handle and the history through the tenant pool.
func startPostgres(t *testing.T) (*pgxpool.Pool, *sql.DB) {
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

	base := filepath.Join("..", "..", "..", "pkg", "platform", "migrations", "postgres", "tenant")
	for _, name := range []string{"013_timeline_events.up.sql", "015_timeline_export.up.sql"} {
		up, err := os.ReadFile(filepath.Join(base, name))
		require.NoError(t, err, "read %s", name)
		_, err = pool.Exec(ctx, string(up))
		require.NoError(t, err, "apply %s", name)
	}
	// The audit retention period of a tenant lives in the platform table of
	// migration 043. The archive reads it through audit.RetentionSettings.
	platformUp, err := os.ReadFile(filepath.Join("..", "..", "..", "pkg", "platform", "migrations", "postgres", "platform", "043_audit_retention_tenant.up.sql"))
	require.NoError(t, err)
	_, err = pool.Exec(ctx, string(platformUp))
	require.NoError(t, err, "apply 043_audit_retention_tenant")
	_, err = pool.Exec(ctx, `CREATE TABLE tenant_secrets_broker_config (tenant_id TEXT PRIMARY KEY)`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO tenant_secrets_broker_config (tenant_id) VALUES ($1)`, tenantName)
	require.NoError(t, err)

	platform := stdlib.OpenDBFromPool(pool)
	t.Cleanup(func() { _ = platform.Close() })
	return pool, platform
}

// startLockedMinio starts MinIO with an object-lock bucket.
func startLockedMinio(t *testing.T) (audit.ExportConfig, *minio.Client) {
	t.Helper()
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        minioImage,
			ExposedPorts: []string{"9000/tcp"},
			Env:          map[string]string{"MINIO_ROOT_USER": minioAccessKey, "MINIO_ROOT_PASSWORD": minioSecretKey},
			Cmd:          []string{"server", "/data"},
			WaitingFor:   wait.ForHTTP("/minio/health/ready").WithPort("9000/tcp").WithStartupTimeout(90 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("MinIO container did not start: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })
	host, err := c.Host(ctx)
	require.NoError(t, err)
	port, err := c.MappedPort(ctx, "9000")
	require.NoError(t, err)
	cfg := audit.ExportConfig{
		Endpoint:  &url.URL{Scheme: "http", Host: fmt.Sprintf("%s:%s", host, port.Port())},
		Bucket:    minioBucket,
		Region:    "us-east-1",
		AccessKey: minioAccessKey,
		SecretKey: minioSecretKey,
		Policy:    audit.ExportPolicy{LockMode: audit.LockModeGovernance, LockDays: 400},
	}
	client, err := minio.New(cfg.Endpoint.Host, &minio.Options{
		Creds: credentials.NewStaticV4(minioAccessKey, minioSecretKey, ""), Region: cfg.Region,
	})
	require.NoError(t, err)
	require.NoError(t, client.MakeBucket(ctx, minioBucket, minio.MakeBucketOptions{Region: cfg.Region, ObjectLocking: true}))
	return cfg, client
}

// insertEvent writes one history row with its age.
func insertEvent(t *testing.T, pool *pgxpool.Pool, ms, seq int64, recordedAt time.Time) {
	t.Helper()
	ev := fmt.Sprintf(`{"kind":"test.event","payload":{"n":%d}}`, ms)
	_, err := pool.Exec(context.Background(),
		`INSERT INTO timeline_events (stream_ms, stream_seq, kind, event, recorded_at) VALUES ($1, $2, 'test.event', $3::jsonb, $4)`,
		ms, seq, ev, recordedAt)
	require.NoError(t, err)
}

func remainingRows(t *testing.T, pool *pgxpool.Pool) []int64 {
	t.Helper()
	rows, err := pool.Query(context.Background(), `SELECT stream_ms FROM timeline_events ORDER BY stream_ms, stream_seq`)
	require.NoError(t, err)
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var ms int64
		require.NoError(t, rows.Scan(&ms))
		out = append(out, ms)
	}
	require.NoError(t, rows.Err())
	return out
}

func listObjects(t *testing.T, client *minio.Client) []string {
	t.Helper()
	var names []string
	for obj := range client.ListObjects(context.Background(), minioBucket, minio.ListObjectsOptions{Prefix: "audit/", Recursive: true}) {
		require.NoError(t, obj.Err)
		names = append(names, obj.Key)
	}
	sort.Strings(names)
	return names
}

func readObject(t *testing.T, client *minio.Client, key string) []timelinearchive.ExportedEvent {
	t.Helper()
	obj, err := client.GetObject(context.Background(), minioBucket, key, minio.GetObjectOptions{})
	require.NoError(t, err)
	body, err := io.ReadAll(obj)
	require.NoError(t, err)
	var out []timelinearchive.ExportedEvent
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		var ev timelinearchive.ExportedEvent
		require.NoError(t, json.Unmarshal(sc.Bytes(), &ev))
		out = append(out, ev)
	}
	require.NoError(t, sc.Err())
	return out
}

func silentLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func settings(t *testing.T, platform *sql.DB) *audit.RetentionSettings {
	t.Helper()
	s, err := audit.NewRetentionSettings(platform, audit.MinRetentionMonths)
	require.NoError(t, err)
	return s
}

func TestArchive_ExportsEachRowThenRemovesOnlyOldExportedRows(t *testing.T) {
	pool, platform := startPostgres(t)
	cfg, client := startLockedMinio(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Two rows of 14 months, one row of 12 months, one new row.
	insertEvent(t, pool, 1000, 0, now.AddDate(0, -14, 0))
	insertEvent(t, pool, 1001, 0, now.AddDate(0, -14, 0))
	insertEvent(t, pool, 2000, 0, now.AddDate(0, -12, 0))
	insertEvent(t, pool, 3000, 0, now)

	// With no bucket, nothing is exported, so retention removes no row.
	noExport, err := timelinearchive.New(platform, onePool{pg: pool}, settings(t, platform), nil, audit.ExportPolicy{}, silentLogger())
	require.NoError(t, err)
	exported, removed, err := noExport.RunOnce(ctx)
	require.NoError(t, err)
	assert.Zero(t, exported)
	assert.Zero(t, removed, "retention must not remove a row that the export did not write")
	assert.Equal(t, []int64{1000, 1001, 2000, 3000}, remainingRows(t, pool))

	store, err := audit.NewS3Store(cfg)
	require.NoError(t, err)
	archive, err := timelinearchive.New(platform, onePool{pg: pool}, settings(t, platform), store, cfg.Policy, silentLogger())
	require.NoError(t, err)
	exported, removed, err = archive.RunOnce(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 4, exported)
	assert.EqualValues(t, 2, removed, "only the two exported rows older than 13 months leave")
	assert.Equal(t, []int64{2000, 3000}, remainingRows(t, pool))

	keys := listObjects(t, client)
	require.Equal(t, []string{timelinearchive.ObjectKey(tenantName,
		timelinearchive.StreamID{Ms: 1000}, timelinearchive.StreamID{Ms: 3000})}, keys)
	events := readObject(t, client, keys[0])
	require.Len(t, events, 4)
	for i, ms := range []int64{1000, 1001, 2000, 3000} {
		assert.Equal(t, ms, events[i].StreamMs)
		assert.Equal(t, tenantName, events[i].TenantID)
		assert.Equal(t, "test.event", events[i].Kind)
		assert.JSONEq(t, fmt.Sprintf(`{"kind":"test.event","payload":{"n":%d}}`, ms), string(events[i].Event))
	}

	// A second run with no new row writes nothing and removes nothing.
	exported, removed, err = archive.RunOnce(ctx)
	require.NoError(t, err)
	assert.Zero(t, exported)
	assert.Zero(t, removed)

	// A new row goes to a new object. The cursor does not write a row twice.
	insertEvent(t, pool, 4000, 0, now)
	exported, _, err = archive.RunOnce(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 1, exported)
	assert.Len(t, listObjects(t, client), 2)
}

func TestArchive_TheAuditPeriodOfTheTenantKeepsRowsLonger(t *testing.T) {
	pool, platform := startPostgres(t)
	cfg, _ := startLockedMinio(t)
	ctx := context.Background()
	now := time.Now().UTC()

	insertEvent(t, pool, 1000, 0, now.AddDate(0, -14, 0))
	insertEvent(t, pool, 2000, 0, now.AddDate(0, -30, 0))

	// A tenant admin keeps the audit log for 24 months. The Timeline
	// history follows the same period.
	require.NoError(t, settings(t, platform).SetTenantMonths(ctx, tenantName, 24, "user:admin"))

	store, err := audit.NewS3Store(cfg)
	require.NoError(t, err)
	archive, err := timelinearchive.New(platform, onePool{pg: pool}, settings(t, platform), store, cfg.Policy, silentLogger())
	require.NoError(t, err)
	exported, removed, err := archive.RunOnce(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 2, exported)
	assert.EqualValues(t, 1, removed, "the tenant period of 24 months keeps the row of 14 months")
	assert.Equal(t, []int64{1000}, remainingRows(t, pool))
}

func TestArchive_ARestartWritesTheSameRangeUnderTheSameName(t *testing.T) {
	pool, platform := startPostgres(t)
	cfg, client := startLockedMinio(t)
	ctx := context.Background()
	now := time.Now().UTC()
	insertEvent(t, pool, 1000, 0, now)
	insertEvent(t, pool, 1000, 1, now)

	// A write that started and did not finish leaves its range pending.
	_, err := pool.Exec(ctx, `
INSERT INTO timeline_export (id, pending_first_ms, pending_first_seq, pending_last_ms, pending_last_seq)
VALUES (TRUE, 1000, 0, 1000, 0)`)
	require.NoError(t, err)

	store, err := audit.NewS3Store(cfg)
	require.NoError(t, err)
	archive, err := timelinearchive.New(platform, onePool{pg: pool}, settings(t, platform), store, cfg.Policy, silentLogger())
	require.NoError(t, err)
	exported, _, err := archive.RunOnce(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 2, exported)
	assert.Equal(t, []string{
		timelinearchive.ObjectKey(tenantName, timelinearchive.StreamID{Ms: 1000, Seq: 0}, timelinearchive.StreamID{Ms: 1000, Seq: 0}),
		timelinearchive.ObjectKey(tenantName, timelinearchive.StreamID{Ms: 1000, Seq: 1}, timelinearchive.StreamID{Ms: 1000, Seq: 1}),
	}, listObjects(t, client))
}
