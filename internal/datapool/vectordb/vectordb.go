// Package vectordb defines the narrow vector-store abstraction used by the
// daemon's data-plane pool. The interface is intentionally minimal — only
// operations Gibson actually performs against the vector store are exposed.
// Vendor-specific types do not appear in the interface signatures.
//
// The default adapter targets Qdrant (qdrant.go). Weaviate, Milvus, and
// pgvector adapters can be added by implementing Driver + Client without
// touching handler code.
//
// Spec: database-per-tenant-data-plane, Phase B, task 2.2.
package vectordb

import "context"

// Point is a single vector record. The embedding and payload are kept
// abstract so the interface does not depend on any specific vector dimension
// or metadata schema.
type Point struct {
	// ID uniquely identifies the point within the collection. UUID string.
	ID string

	// Vector is the dense embedding. Dimension must match the collection's
	// configured vector size.
	Vector []float32

	// Payload is arbitrary key-value metadata stored alongside the vector.
	// Keys must be strings; values must be JSON-serializable scalars or
	// string slices.
	Payload map[string]any
}

// SearchResult is one result from a vector similarity search.
type SearchResult struct {
	// ID of the matched point.
	ID string

	// Score is the similarity score (higher is more similar for cosine;
	// lower is more similar for Euclidean — callers should be aware of the
	// configured distance metric).
	Score float32

	// Payload is the metadata stored with the point.
	Payload map[string]any
}

// Filter is a structured predicate applied during search to limit results
// to points whose payload matches the condition. The exact structure is
// intentionally simple; complex filter trees should be composed by the
// caller and passed as a pre-built Filter.
type Filter struct {
	// Must is a list of key=value conditions that ALL must match (AND).
	Must []FieldCondition
}

// FieldCondition matches points whose named payload field equals Value.
type FieldCondition struct {
	// Key is the payload field name.
	Key string

	// Value is the scalar value to match.
	Value any
}

// Driver creates per-tenant Clients. It holds any cluster-level connection
// state (e.g., a gRPC connection to the Qdrant cluster) and is shared across
// tenants. The Driver must be safe for concurrent use.
type Driver interface {
	// For returns a Client scoped to the given collection name. The Client
	// is bound to that collection for its lifetime.
	//
	// Returns *datapool.NotProvisionedError (as a wrapped error) if the
	// collection does not exist.
	For(ctx context.Context, collection string) (Client, error)

	// Close releases any resources held by the Driver.
	Close() error
}

// Client is a vector-store client scoped to a single collection (tenant).
// It is NOT safe for use after the owning Conn is released.
type Client interface {
	// Upsert inserts or updates points in the collection. Points with
	// existing IDs are overwritten.
	Upsert(ctx context.Context, points []Point) error

	// Search performs a k-nearest-neighbour search using the given query
	// vector. filter may be nil (no payload filter). Returns up to k results
	// ordered by descending similarity score.
	Search(ctx context.Context, vector []float32, k uint64, filter *Filter) ([]SearchResult, error)

	// Delete removes the points identified by ids from the collection. IDs
	// that do not exist are silently ignored.
	Delete(ctx context.Context, ids []string) error
}
