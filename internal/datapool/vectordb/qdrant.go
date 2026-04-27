package vectordb

import (
	"context"
	"fmt"
)

// TODO(database-per-tenant-data-plane B2): Replace this stub with the real
// Qdrant adapter once github.com/qdrant/go-client is confirmed safe to add
// as a transitive dep. The interface (Driver + Client) is fully defined;
// only the gRPC transport to Qdrant is stubbed here.
//
// To enable the real adapter:
//   1. Run: go get github.com/qdrant/go-client
//   2. Implement NewQdrantDriver below using the Qdrant gRPC client.
//   3. Remove the stub error from For().
//   4. Wire NewQdrantDriver into NewPool in pool_impl.go.

// QdrantConfig holds connection parameters for the Qdrant adapter.
type QdrantConfig struct {
	// Addr is the host:port of the Qdrant gRPC endpoint.
	Addr string

	// TLS enables TLS when connecting to Qdrant.
	TLS bool

	// APIKey is the optional Qdrant API key.
	APIKey string

	// VectorSize is the dimension of the dense vectors stored in the
	// collection (e.g., 384 for all-MiniLM-L6-v2).
	VectorSize uint64
}

// qdrantDriver is the Qdrant implementation of Driver.
type qdrantDriver struct {
	cfg QdrantConfig
	// conn is the underlying Qdrant gRPC connection.
	// TODO(database-per-tenant-data-plane B2): add real Qdrant gRPC conn.
}

// NewQdrantDriver creates a Driver backed by Qdrant at cfg.Addr.
// The driver holds a single gRPC connection shared across all tenant
// Client instances.
func NewQdrantDriver(cfg QdrantConfig) (Driver, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("vectordb: qdrant: addr is required")
	}
	return &qdrantDriver{cfg: cfg}, nil
}

// For returns a Client scoped to the named collection.
// TODO(database-per-tenant-data-plane B2): implement real Qdrant For.
func (d *qdrantDriver) For(_ context.Context, collection string) (Client, error) {
	if collection == "" {
		return nil, fmt.Errorf("vectordb: qdrant: collection name is required")
	}
	return &qdrantClient{
		driver:     d,
		collection: collection,
	}, nil
}

// Close releases the Qdrant gRPC connection.
func (d *qdrantDriver) Close() error {
	// TODO(database-per-tenant-data-plane B2): close real gRPC conn.
	return nil
}

// qdrantClient is the Qdrant implementation of Client.
type qdrantClient struct {
	driver     *qdrantDriver
	collection string
}

// Upsert inserts or updates points in the Qdrant collection.
// TODO(database-per-tenant-data-plane B2): implement real Qdrant Upsert.
func (c *qdrantClient) Upsert(_ context.Context, points []Point) error {
	if len(points) == 0 {
		return nil
	}
	return fmt.Errorf("vectordb: qdrant: Upsert not yet implemented (stub) — collection=%s", c.collection)
}

// Search performs a k-nearest-neighbour search.
// TODO(database-per-tenant-data-plane B2): implement real Qdrant Search.
func (c *qdrantClient) Search(_ context.Context, _ []float32, _ uint64, _ *Filter) ([]SearchResult, error) {
	return nil, fmt.Errorf("vectordb: qdrant: Search not yet implemented (stub) — collection=%s", c.collection)
}

// Delete removes points by ID from the Qdrant collection.
// TODO(database-per-tenant-data-plane B2): implement real Qdrant Delete.
func (c *qdrantClient) Delete(_ context.Context, _ []string) error {
	return fmt.Errorf("vectordb: qdrant: Delete not yet implemented (stub) — collection=%s", c.collection)
}
