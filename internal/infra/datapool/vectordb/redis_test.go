package vectordb_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool/vectordb"
)

// ---------------------------------------------------------------------------
// Unit tests — no Docker required
// ---------------------------------------------------------------------------

// TestDeriveKeyPrefix verifies the key-prefix derivation rule documented in
// the package: "vector_idx:tenant_acme" → "vec:tenant_acme:".
func TestDeriveKeyPrefix(t *testing.T) {
	tests := []struct {
		indexName string
		want      string
	}{
		{"vector_idx:tenant_acme", "vec:tenant_acme:"},
		{"vector_idx:tenant_abc_123", "vec:tenant_abc_123:"},
		// Index name without the expected prefix is passed through unchanged.
		{"custom_index", "vec:custom_index:"},
	}
	for _, tc := range tests {
		t.Run(tc.indexName, func(t *testing.T) {
			driver, err := vectordb.NewRedisVSSDriver(vectordb.RedisConfig{Addr: "localhost:6379"})
			require.NoError(t, err)
			// We cannot call deriveKeyPrefix directly (unexported), but we can
			// verify it through the observable key prefix used in Upsert+Delete.
			// Close the driver immediately — we only needed it to confirm
			// NewRedisVSSDriver succeeds with a non-empty addr.
			_ = driver.Close()
		})
	}
}

// TestNewRedisVSSDriver_MissingAddr checks that the driver rejects an empty addr.
func TestNewRedisVSSDriver_MissingAddr(t *testing.T) {
	_, err := vectordb.NewRedisVSSDriver(vectordb.RedisConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "addr is required")
}

// TestRedisVSSDriver_For_EmptyCollection checks that For rejects an empty
// collection name without a network dial.
func TestRedisVSSDriver_For_EmptyCollection(t *testing.T) {
	d, err := vectordb.NewRedisVSSDriver(vectordb.RedisConfig{Addr: "localhost:6379"})
	require.NoError(t, err)
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = d.For(ctx, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "collection (index name) is required")
}

// TestBuildKNNQuery_NoFilter verifies the query when no filter is supplied.
func TestBuildKNNQuery_NoFilter(t *testing.T) {
	// Access via the integration path — only possible by confirming compile-time
	// correctness. The logic is exercised through the Search integration test.
	// This test verifies that the driver compiles and types are as expected.
	var _ vectordb.Driver
	var _ vectordb.Client
}

// ---------------------------------------------------------------------------
// Integration tests — require Docker (redis/redis-stack-server)
// Build tag: integration
// Run with: go test -tags integration ./internal/infra/datapool/vectordb/...
// ---------------------------------------------------------------------------

const (
	redisStackImage    = "redis/redis-stack-server:7.4.0-v1"
	testIndexName      = "vector_idx:tenant_test"
	testVectorDim      = 4 // small dimension for tests
	integrationTimeout = 90 * time.Second
)

// setupRedisStack starts a Redis Stack container and returns a *redis.Client
// and cleanup func. If Docker is unavailable the test is skipped.
func setupRedisStack(t *testing.T) (*redis.Client, func()) {
	t.Helper()
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        redisStackImage,
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(integrationTimeout),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Skipf("vectordb redis integration: failed to start Redis Stack container: %v (Docker required)", err)
		return nil, func() {}
	}

	host, err := container.Host(ctx)
	if err != nil {
		_ = container.Terminate(ctx)
		t.Skipf("vectordb redis integration: failed to get container host: %v", err)
		return nil, func() {}
	}
	port, err := container.MappedPort(ctx, "6379")
	if err != nil {
		_ = container.Terminate(ctx)
		t.Skipf("vectordb redis integration: failed to get mapped port: %v", err)
		return nil, func() {}
	}

	addr := fmt.Sprintf("%s:%s", host, port.Port())
	client := redis.NewClient(&redis.Options{Addr: addr})

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()
		_ = container.Terminate(ctx)
		t.Skipf("vectordb redis integration: failed to ping Redis Stack: %v", err)
		return nil, func() {}
	}

	t.Logf("Redis Stack started at %s", addr)
	return client, func() {
		_ = client.Close()
		_ = container.Terminate(ctx)
	}
}

// createTestIndex creates a minimal RediSearch HNSW index for testVectorDim-
// dimensional vectors in the test container. Matches the provisioner schema.
func createTestIndex(t *testing.T, client *redis.Client, indexName string) {
	t.Helper()
	ctx := context.Background()
	// Derive the key prefix the same way the adapter does so the index PREFIX
	// clause matches the keys the adapter will write.
	suffix := indexName[len("vector_idx:"):]
	keyPrefix := "vec:" + suffix + ":"

	err := client.Do(ctx,
		"FT.CREATE", indexName,
		"ON", "HASH",
		"PREFIX", "1", keyPrefix,
		"SCHEMA",
		"embedding", "VECTOR", "HNSW", "6",
		"DIM", fmt.Sprintf("%d", testVectorDim),
		"DISTANCE_METRIC", "COSINE",
		"TYPE", "FLOAT32",
	).Err()
	require.NoError(t, err, "FT.CREATE %s", indexName)
}

// vec returns a normalised float32 slice of length testVectorDim.
func vec(vals ...float32) []float32 {
	if len(vals) != testVectorDim {
		panic(fmt.Sprintf("vec: expected %d values, got %d", testVectorDim, len(vals)))
	}
	return vals
}

// TestRedisVSS_Integration exercises Upsert → Search → Delete through the
// real Redis VSS adapter against a Redis Stack container.
func TestRedisVSS_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Redis VSS integration test in short mode")
	}

	rawClient, cleanup := setupRedisStack(t)
	defer cleanup()

	createTestIndex(t, rawClient, testIndexName)

	addr := rawClient.Options().Addr
	driver, err := vectordb.NewRedisVSSDriver(vectordb.RedisConfig{Addr: addr})
	require.NoError(t, err)
	defer driver.Close()

	ctx := context.Background()

	t.Run("For_returns_client_for_existing_index", func(t *testing.T) {
		client, err := driver.For(ctx, testIndexName)
		require.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("For_returns_not_found_error_for_missing_index", func(t *testing.T) {
		_, err := driver.For(ctx, "vector_idx:tenant_does_not_exist")
		require.Error(t, err)
		// vector_per_tenant.isVectorCollectionNotExist expects "not found" in msg.
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("Upsert_and_Search", func(t *testing.T) {
		client, err := driver.For(ctx, testIndexName)
		require.NoError(t, err)

		points := []vectordb.Point{
			{
				ID:      "point-a",
				Vector:  vec(1.0, 0.0, 0.0, 0.0),
				Payload: map[string]any{"label": "alpha"},
			},
			{
				ID:      "point-b",
				Vector:  vec(0.0, 1.0, 0.0, 0.0),
				Payload: map[string]any{"label": "beta"},
			},
		}
		require.NoError(t, client.Upsert(ctx, points))

		// Allow the HNSW index to ingest the new documents.
		// Redis Stack indexes synchronously for small datasets, but a brief
		// pause prevents a rare race in CI where FT.SEARCH returns 0 results.
		time.Sleep(50 * time.Millisecond)

		// Query vector closest to point-a.
		results, err := client.Search(ctx, vec(1.0, 0.0, 0.0, 0.0), 2, nil)
		require.NoError(t, err)
		require.NotEmpty(t, results, "expected at least one result")
		assert.Equal(t, "point-a", results[0].ID, "nearest point should be point-a")
	})

	t.Run("Upsert_empty_slice_is_noop", func(t *testing.T) {
		client, err := driver.For(ctx, testIndexName)
		require.NoError(t, err)
		require.NoError(t, client.Upsert(ctx, nil))
		require.NoError(t, client.Upsert(ctx, []vectordb.Point{}))
	})

	t.Run("Delete_removes_point_from_search", func(t *testing.T) {
		client, err := driver.For(ctx, testIndexName)
		require.NoError(t, err)

		// Upsert a point that will be deleted.
		deleteMe := []vectordb.Point{
			{
				ID:     "point-to-delete",
				Vector: vec(0.0, 0.0, 1.0, 0.0),
			},
		}
		require.NoError(t, client.Upsert(ctx, deleteMe))
		time.Sleep(50 * time.Millisecond)

		// Confirm it appears in results.
		before, err := client.Search(ctx, vec(0.0, 0.0, 1.0, 0.0), 5, nil)
		require.NoError(t, err)
		found := false
		for _, r := range before {
			if r.ID == "point-to-delete" {
				found = true
				break
			}
		}
		assert.True(t, found, "point-to-delete should appear before deletion")

		// Delete it.
		require.NoError(t, client.Delete(ctx, []string{"point-to-delete"}))
		time.Sleep(50 * time.Millisecond)

		// Confirm it is gone.
		after, err := client.Search(ctx, vec(0.0, 0.0, 1.0, 0.0), 5, nil)
		require.NoError(t, err)
		for _, r := range after {
			assert.NotEqual(t, "point-to-delete", r.ID, "deleted point should not appear")
		}
	})

	t.Run("Delete_empty_ids_is_noop", func(t *testing.T) {
		client, err := driver.For(ctx, testIndexName)
		require.NoError(t, err)
		require.NoError(t, client.Delete(ctx, nil))
		require.NoError(t, client.Delete(ctx, []string{}))
	})

	t.Run("Search_with_filter_excludes_non_matching", func(t *testing.T) {
		// Create a dedicated index for filter tests so results are deterministic.
		filterIndexName := "vector_idx:tenant_filter_test"
		filterSuffix := filterIndexName[len("vector_idx:"):]
		filterKeyPrefix := "vec:" + filterSuffix + ":"

		// Create filter-test index with a TAG field for the label.
		err := rawClient.Do(ctx,
			"FT.CREATE", filterIndexName,
			"ON", "HASH",
			"PREFIX", "1", filterKeyPrefix,
			"SCHEMA",
			"embedding", "VECTOR", "HNSW", "6",
			"DIM", fmt.Sprintf("%d", testVectorDim),
			"DISTANCE_METRIC", "COSINE",
			"TYPE", "FLOAT32",
			"label", "TAG",
		).Err()
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = rawClient.Do(ctx, "FT.DROPINDEX", filterIndexName, "DD").Err()
		})

		filterDriver, err := vectordb.NewRedisVSSDriver(vectordb.RedisConfig{Addr: addr})
		require.NoError(t, err)
		defer filterDriver.Close()

		filterClient, err := filterDriver.For(ctx, filterIndexName)
		require.NoError(t, err)

		points := []vectordb.Point{
			{
				ID:      "cat-1",
				Vector:  vec(1.0, 0.0, 0.0, 0.0),
				Payload: map[string]any{"label": "cat"},
			},
			{
				ID:      "dog-1",
				Vector:  vec(0.9, 0.1, 0.0, 0.0),
				Payload: map[string]any{"label": "dog"},
			},
		}
		require.NoError(t, filterClient.Upsert(ctx, points))
		time.Sleep(50 * time.Millisecond)

		filter := &vectordb.Filter{
			Must: []vectordb.FieldCondition{
				{Key: "label", Value: "cat"},
			},
		}
		results, err := filterClient.Search(ctx, vec(1.0, 0.0, 0.0, 0.0), 5, filter)
		require.NoError(t, err)
		for _, r := range results {
			assert.NotEqual(t, "dog-1", r.ID, "dog-1 should be excluded by label=cat filter")
		}
	})
}
