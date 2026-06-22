package pools_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// containerHandle is returned from each container start helper so the caller
// can defer Terminate on the generic Container interface.
// The variadic TerminateOption matches testcontainers.Container.Terminate.
type containerHandle interface {
	Terminate(ctx context.Context, opts ...testcontainers.TerminateOption) error
}

// startRedisContainer launches a Redis testcontainer and returns the handle
// and "host:port" address. Only called when testing.Short() is false.
func startRedisContainer(t *testing.T, ctx context.Context) (containerHandle, string) {
	t.Helper()

	req := testcontainers.ContainerRequest{
		Image:        "redis:7-alpine",
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(60 * time.Second),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start redis container: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("redis container host: %v", err)
	}
	port, err := container.MappedPort(ctx, "6379")
	if err != nil {
		t.Fatalf("redis container port: %v", err)
	}

	return container, fmt.Sprintf("%s:%s", host, port.Port())
}

// startPostgresContainer launches a Postgres testcontainer and returns the
// handle and a pgx DSN. Only called when testing.Short() is false.
func startPostgresContainer(t *testing.T, ctx context.Context) (containerHandle, string) {
	t.Helper()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "testuser",
			"POSTGRES_PASSWORD": "testpass",
			"POSTGRES_DB":       "testdb",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(60 * time.Second),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("postgres container host: %v", err)
	}
	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		t.Fatalf("postgres container port: %v", err)
	}

	dsn := fmt.Sprintf("postgres://testuser:testpass@%s:%s/testdb", host, port.Port())
	return container, dsn
}

// startNeo4jContainer launches a Neo4j testcontainer and returns the handle
// and bolt URI. Only called when testing.Short() is false.
func startNeo4jContainer(t *testing.T, ctx context.Context) (containerHandle, string) {
	t.Helper()

	req := testcontainers.ContainerRequest{
		Image:        "neo4j:5-community",
		ExposedPorts: []string{"7687/tcp"},
		Env: map[string]string{
			"NEO4J_AUTH":                        "neo4j/password",
			"NEO4J_PLUGINS":                     "[]",
			"NEO4J_dbms_security_auth__enabled": "true",
		},
		WaitingFor: wait.ForLog("Started.").WithStartupTimeout(120 * time.Second),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start neo4j container: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("neo4j container host: %v", err)
	}
	port, err := container.MappedPort(ctx, "7687")
	if err != nil {
		t.Fatalf("neo4j container port: %v", err)
	}

	boltURI := fmt.Sprintf("bolt://%s:%s", host, port.Port())
	return container, boltURI
}
