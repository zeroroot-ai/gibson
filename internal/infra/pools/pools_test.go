package pools_test

import (
	"context"
	"testing"
	"time"

	neo4j "github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/zeroroot-ai/gibson/internal/infra/pools"
)

// ---------------------------------------------------------------------------
// NewNeo4j — required-override unit tests
// ---------------------------------------------------------------------------

func TestNewNeo4j_RequiredOverrides(t *testing.T) {
	t.Parallel()

	validURI := "bolt://localhost:7687"
	validAuth := neo4j.BasicAuth("neo4j", "password", "")

	cases := []struct {
		name    string
		uri     string
		opts    pools.Neo4jOptions
		wantErr bool
	}{
		{
			name:    "missing uri",
			uri:     "",
			opts:    pools.Neo4jOptions{MaxConnectionLifetime: time.Hour, ConnectionAcquisitionTimeout: 60 * time.Second},
			wantErr: true,
		},
		{
			name:    "missing MaxConnectionLifetime",
			uri:     validURI,
			opts:    pools.Neo4jOptions{ConnectionAcquisitionTimeout: 60 * time.Second},
			wantErr: true,
		},
		{
			name:    "missing ConnectionAcquisitionTimeout",
			uri:     validURI,
			opts:    pools.Neo4jOptions{MaxConnectionLifetime: time.Hour},
			wantErr: true,
		},
		{
			name:    "all required fields present",
			uri:     validURI,
			opts:    pools.Neo4jOptions{MaxConnectionLifetime: time.Hour, ConnectionAcquisitionTimeout: 60 * time.Second},
			wantErr: false,
		},
		{
			name:    "with optional MaxConnectionPoolSize",
			uri:     validURI,
			opts:    pools.Neo4jOptions{MaxConnectionLifetime: time.Hour, ConnectionAcquisitionTimeout: 60 * time.Second, MaxConnectionPoolSize: 50},
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			driver, err := pools.NewNeo4j(tc.uri, validAuth, tc.opts)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if driver == nil {
				t.Fatal("expected non-nil driver")
			}
			_ = driver.Close(context.Background())
		})
	}
}

// ---------------------------------------------------------------------------
// NewRedis — required-override unit tests
// ---------------------------------------------------------------------------

func TestNewRedis_RequiredOverrides(t *testing.T) {
	t.Parallel()

	validOpts := pools.RedisOptions{
		Addr:            "localhost:6379",
		PoolSize:        10,
		DialTimeout:     5 * time.Second,
		ReadTimeout:     3 * time.Second,
		WriteTimeout:    3 * time.Second,
		ConnMaxLifetime: 30 * time.Minute,
	}

	cases := []struct {
		name    string
		mutate  func(*pools.RedisOptions)
		wantErr bool
	}{
		{
			name:    "valid — all required fields set",
			mutate:  func(_ *pools.RedisOptions) {},
			wantErr: false,
		},
		{
			name:    "missing Addr",
			mutate:  func(o *pools.RedisOptions) { o.Addr = "" },
			wantErr: true,
		},
		{
			name:    "missing PoolSize",
			mutate:  func(o *pools.RedisOptions) { o.PoolSize = 0 },
			wantErr: true,
		},
		{
			name:    "negative PoolSize",
			mutate:  func(o *pools.RedisOptions) { o.PoolSize = -1 },
			wantErr: true,
		},
		{
			name:    "missing DialTimeout",
			mutate:  func(o *pools.RedisOptions) { o.DialTimeout = 0 },
			wantErr: true,
		},
		{
			name:    "missing ReadTimeout",
			mutate:  func(o *pools.RedisOptions) { o.ReadTimeout = 0 },
			wantErr: true,
		},
		{
			name:    "missing WriteTimeout",
			mutate:  func(o *pools.RedisOptions) { o.WriteTimeout = 0 },
			wantErr: true,
		},
		{
			name:    "missing ConnMaxLifetime",
			mutate:  func(o *pools.RedisOptions) { o.ConnMaxLifetime = 0 },
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := validOpts
			tc.mutate(&opts)
			client, err := pools.NewRedis(opts)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if client == nil {
				t.Fatal("expected non-nil client")
			}
			_ = client.Close()
		})
	}
}

// ---------------------------------------------------------------------------
// NewPgxPool — required-override unit tests
// ---------------------------------------------------------------------------

func TestNewPgxPool_RequiredOverrides(t *testing.T) {
	t.Parallel()

	// A well-formed DSN that will parse cleanly even when no server is running.
	// ParseConfig does not dial; the pool dials lazily on first Acquire.
	validDSN := "postgres://postgres:password@localhost:5432/testdb"

	cases := []struct {
		name    string
		dsn     string
		opts    pools.PgxPoolOptions
		wantErr bool
	}{
		{
			name:    "valid — all required fields set",
			dsn:     validDSN,
			opts:    pools.PgxPoolOptions{MaxConnLifetime: time.Hour, MaxConnIdleTime: 30 * time.Minute},
			wantErr: false,
		},
		{
			name:    "empty DSN",
			dsn:     "",
			opts:    pools.PgxPoolOptions{MaxConnLifetime: time.Hour, MaxConnIdleTime: 30 * time.Minute},
			wantErr: true,
		},
		{
			name:    "missing MaxConnLifetime",
			dsn:     validDSN,
			opts:    pools.PgxPoolOptions{MaxConnIdleTime: 30 * time.Minute},
			wantErr: true,
		},
		{
			name:    "missing MaxConnIdleTime",
			dsn:     validDSN,
			opts:    pools.PgxPoolOptions{MaxConnLifetime: time.Hour},
			wantErr: true,
		},
		{
			name:    "with optional MaxConns",
			dsn:     validDSN,
			opts:    pools.PgxPoolOptions{MaxConnLifetime: time.Hour, MaxConnIdleTime: 30 * time.Minute, MaxConns: 20},
			wantErr: false,
		},
		{
			name:    "invalid DSN",
			dsn:     "not-a-valid-dsn://::::",
			opts:    pools.PgxPoolOptions{MaxConnLifetime: time.Hour, MaxConnIdleTime: 30 * time.Minute},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			pool, err := pools.NewPgxPool(ctx, tc.dsn, tc.opts)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if pool == nil {
				t.Fatal("expected non-nil pool")
			}
			pool.Close()
		})
	}
}

// ---------------------------------------------------------------------------
// Integration tests — skipped under -short; require testcontainers
// ---------------------------------------------------------------------------

func TestNewRedis_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	ctx := context.Background()

	container, addr := startRedisContainer(t, ctx)
	defer container.Terminate(ctx) //nolint:errcheck

	client, err := pools.NewRedis(pools.RedisOptions{
		Addr:            addr,
		PoolSize:        5,
		DialTimeout:     5 * time.Second,
		ReadTimeout:     3 * time.Second,
		WriteTimeout:    3 * time.Second,
		ConnMaxLifetime: 30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewRedis: %v", err)
	}
	defer func() { _ = client.Close() }()

	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("ping failed: %v", err)
	}
}

func TestNewPgxPool_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	ctx := context.Background()

	container, dsn := startPostgresContainer(t, ctx)
	defer container.Terminate(ctx) //nolint:errcheck

	pool, err := pools.NewPgxPool(ctx, dsn, pools.PgxPoolOptions{
		MaxConnLifetime: time.Hour,
		MaxConnIdleTime: 30 * time.Minute,
		MaxConns:        5,
	})
	if err != nil {
		t.Fatalf("NewPgxPool: %v", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping failed: %v", err)
	}
}

func TestNewNeo4j_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	ctx := context.Background()

	container, boltURI := startNeo4jContainer(t, ctx)
	defer container.Terminate(ctx) //nolint:errcheck

	driver, err := pools.NewNeo4j(
		boltURI,
		neo4j.BasicAuth("neo4j", "password", ""),
		pools.Neo4jOptions{
			MaxConnectionLifetime:        time.Hour,
			ConnectionAcquisitionTimeout: 60 * time.Second,
			MaxConnectionPoolSize:        10,
		},
	)
	if err != nil {
		t.Fatalf("NewNeo4j: %v", err)
	}
	defer func() { _ = driver.Close(ctx) }()

	if err := driver.VerifyConnectivity(ctx); err != nil {
		t.Fatalf("VerifyConnectivity failed: %v", err)
	}
}
