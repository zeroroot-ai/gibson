// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build integration
// +build integration

// The audit export against a real Postgres and a real MinIO
// (testcontainers). MinIO stands in for any S3-compatible store: the bucket
// has object lock, as the durable bucket has (gibson#764).
package audit

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"sort"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	minioImage     = "ghcr.io/zeroroot-ai/mirror/minio:RELEASE.2024-09-13T20-26-02Z"
	minioAccessKey = "audit-export"
	minioSecretKey = "audit-export-secret"
	minioBucket    = "durable"
)

// startLockedMinio starts MinIO and makes a bucket with object lock. It
// returns the export config of that bucket and a client to read it.
func startLockedMinio(t *testing.T) (ExportConfig, *minio.Client) {
	t.Helper()
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        minioImage,
		ExposedPorts: []string{"9000/tcp"},
		Env: map[string]string{
			"MINIO_ROOT_USER":     minioAccessKey,
			"MINIO_ROOT_PASSWORD": minioSecretKey,
		},
		Cmd:        []string{"server", "/data"},
		WaitingFor: wait.ForHTTP("/minio/health/ready").WithPort("9000/tcp").WithStartupTimeout(90 * time.Second),
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
	if err != nil {
		t.Fatalf("MinIO container did not start: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })
	host, err := c.Host(ctx)
	require.NoError(t, err)
	port, err := c.MappedPort(ctx, "9000")
	require.NoError(t, err)

	cfg := ExportConfig{
		Endpoint:  &url.URL{Scheme: "http", Host: fmt.Sprintf("%s:%s", host, port.Port())},
		Bucket:    minioBucket,
		Region:    "us-east-1",
		AccessKey: minioAccessKey,
		SecretKey: minioSecretKey,
		Policy:    ExportPolicy{LockMode: LockModeGovernance, LockDays: 400},
	}
	client, err := minio.New(cfg.Endpoint.Host, &minio.Options{
		Creds:  credentials.NewStaticV4(minioAccessKey, minioSecretKey, ""),
		Region: cfg.Region,
	})
	require.NoError(t, err)
	require.NoError(t, client.MakeBucket(ctx, minioBucket, minio.MakeBucketOptions{Region: cfg.Region, ObjectLocking: true}))
	return cfg, client
}

// listObjects returns the names under prefix, sorted.
func listObjects(t *testing.T, client *minio.Client, prefix string) []string {
	t.Helper()
	var names []string
	for obj := range client.ListObjects(context.Background(), minioBucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		require.NoError(t, obj.Err)
		names = append(names, obj.Key)
	}
	sort.Strings(names)
	return names
}

func readObject(t *testing.T, client *minio.Client, key string) []ExportedRecord {
	t.Helper()
	obj, err := client.GetObject(context.Background(), minioBucket, key, minio.GetObjectOptions{})
	require.NoError(t, err)
	body, err := io.ReadAll(obj)
	require.NoError(t, err)
	return decodeObject(t, body)
}

// TestExport_RealPostgresAndMinio writes records with the real writer,
// exports them, and reads them back from the bucket: each record is there
// once, with its lock, and the objects verify as the chain of the tenant.
func TestExport_RealPostgresAndMinio(t *testing.T) {
	db := setupAuditPostgres(t)
	cfg, client := startLockedMinio(t)
	ctx := context.Background()
	w := NewWriter(db, auditSilentLogger())
	for i := 0; i < 5; i++ {
		require.NoError(t, w.WriteSync(ctx, auditTestEvent("acme", fmt.Sprintf("event.%d", i))))
	}
	require.NoError(t, w.WriteSync(ctx, auditTestEvent("beta", "beta.event")))

	store, err := NewS3Store(cfg)
	require.NoError(t, err)
	e, err := NewExporter(db, store, cfg.Policy, auditSilentLogger())
	require.NoError(t, err)
	e.batch = 2

	n, err := e.Export(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(6), n)

	names := listObjects(t, client, ExportPrefix+"acme/")
	require.Equal(t, []string{
		ExportObjectKey("acme", 1, 2), ExportObjectKey("acme", 3, 4), ExportObjectKey("acme", 5, 5),
	}, names)
	assert.Equal(t, []string{ExportObjectKey("beta", 1, 1)}, listObjects(t, client, ExportPrefix+"beta/"))

	// The objects of a tenant, in order, are its chain: each link holds
	// across the object boundary, and each hash matches its fields.
	var all []ExportedRecord
	for _, name := range names {
		all = append(all, readObject(t, client, name)...)
	}
	require.NoError(t, checkExportRange(all, 1, 5))
	assert.Equal(t, chainGenesis(), all[0].PrevHash)

	// Each object carries the lock that the bucket policy requires.
	mode, until, err := client.GetObjectRetention(ctx, minioBucket, names[0], "")
	require.NoError(t, err)
	require.NotNil(t, mode)
	assert.Equal(t, minio.Governance, *mode)
	assert.WithinDuration(t, time.Now().UTC().AddDate(0, 0, 400), *until, time.Hour)

	// Nothing waits, so the lag is zero, and a second run writes nothing.
	lag, err := exportLag(ctx, db, time.Now())
	require.NoError(t, err)
	assert.Zero(t, lag)
	n, err = e.Export(ctx)
	require.NoError(t, err)
	assert.Zero(t, n)

	// A new record waits until the next run.
	require.NoError(t, w.WriteSync(ctx, auditTestEvent("acme", "later")))
	lag, err = exportLag(ctx, db, time.Now().Add(time.Minute))
	require.NoError(t, err)
	assert.Greater(t, lag, 30*time.Second)
	n, err = e.Export(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
	assert.Contains(t, listObjects(t, client, ExportPrefix+"acme/"), ExportObjectKey("acme", 6, 6))
}

// TestExport_ARestartWritesNoRecordUnderTwoNames: the exporter stopped after
// it stored a pending range and before it moved the position. More records
// arrive. The next run writes the pending range again under its own name,
// and the new records go to the next object. No record is in two objects.
func TestExport_ARestartWritesNoRecordUnderTwoNames(t *testing.T) {
	db := setupAuditPostgres(t)
	cfg, client := startLockedMinio(t)
	ctx := context.Background()
	w := NewWriter(db, auditSilentLogger())
	for i := 0; i < 2; i++ {
		require.NoError(t, w.WriteSync(ctx, auditTestEvent("acme", "before.stop")))
	}

	store, err := NewS3Store(cfg)
	require.NoError(t, err)
	e, err := NewExporter(db, store, cfg.Policy, auditSilentLogger())
	require.NoError(t, err)

	// The first run claims 1..2 and stops before the write.
	first, last, ok, err := e.claimRange(ctx, "acme")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, [2]int64{1, 2}, [2]int64{first, last})

	for i := 0; i < 2; i++ {
		require.NoError(t, w.WriteSync(ctx, auditTestEvent("acme", "after.stop")))
	}
	n, err := e.Export(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(4), n)
	assert.Equal(t, []string{ExportObjectKey("acme", 1, 2), ExportObjectKey("acme", 3, 4)},
		listObjects(t, client, ExportPrefix+"acme/"))
}

// TestExport_RetentionRemovesOnlyExportedRows: retention keeps old rows
// until the export wrote them, and then removes them.
func TestExport_RetentionRemovesOnlyExportedRows(t *testing.T) {
	db := setupAuditPostgres(t)
	cfg, _ := startLockedMinio(t)
	ctx := context.Background()
	w := NewWriter(db, auditSilentLogger())
	writeAged(t, db, w, "acme", 3, time.Now().UTC().AddDate(0, -20, 0))

	r, err := NewRetention(db, MinRetentionMonths, auditSilentLogger())
	require.NoError(t, err)
	removed, err := r.Prune(ctx)
	require.NoError(t, err)
	assert.Zero(t, removed, "no row is in the bucket yet")

	store, err := NewS3Store(cfg)
	require.NoError(t, err)
	e, err := NewExporter(db, store, cfg.Policy, auditSilentLogger())
	require.NoError(t, err)
	n, err := e.Export(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(3), n)

	removed, err = r.Prune(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(3), removed)
	assert.True(t, mustVerify(t, db, "acme").Intact())
}
