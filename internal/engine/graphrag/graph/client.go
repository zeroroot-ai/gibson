package graph

import (
	"context"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// GraphClient provides an interface for graph database operations.
// Implementations must be thread-safe for concurrent access.
type GraphClient interface {
	// Connect establishes a connection to the graph database.
	// Returns an error if connection fails.
	Connect(ctx context.Context) error

	// Close releases all resources and closes the database connection.
	// Should be called when the client is no longer needed.
	Close(ctx context.Context) error

	// Health returns the current health status of the graph database connection.
	Health(ctx context.Context) types.HealthStatus

	// Query executes a Cypher query with the given parameters.
	// Returns QueryResult containing the result set or an error.
	Query(ctx context.Context, cypher string, params map[string]any) (QueryResult, error)

	// CreateNode creates a new node with the specified labels and properties.
	// Returns the ID of the created node or an error.
	CreateNode(ctx context.Context, labels []string, props map[string]any) (string, error)

	// CreateRelationship creates a relationship between two nodes.
	// fromID and toID are the node identifiers, relType is the relationship type.
	// props contains optional relationship properties.
	CreateRelationship(ctx context.Context, fromID, toID, relType string, props map[string]any) error

	// DeleteNode deletes a node by its ID.
	// Note: This may fail if the node has relationships in some graph databases.
	DeleteNode(ctx context.Context, nodeID string) error

	// ExecuteRead runs fn inside a managed read transaction opened on the
	// client's underlying session. The semantics differ by implementation:
	//
	//   - Neo4jClient opens a fresh session from the shared DriverWithContext
	//     (the shared, cross-tenant connection pool). Use this for platform-level
	//     reads that are not scoped to a specific tenant database.
	//
	//   - SessionGraphClient delegates to the pre-opened per-tenant session
	//     injected via the data-plane Pool. Use this for tenant-scoped reads
	//     that must run against the correct tenant database without re-routing.
	//
	// fn receives a neo4j.ManagedTransaction and must return (any, error).
	// The driver retries fn on transient failures; fn must be idempotent.
	ExecuteRead(ctx context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error)

	// ExecuteWrite runs fn inside a managed write transaction opened on the
	// client's underlying session. The semantics mirror ExecuteRead — see that
	// method's documentation for the per-tenant vs shared pool distinction.
	//
	// fn receives a neo4j.ManagedTransaction and must return (any, error).
	// The driver retries fn on transient failures; fn must be idempotent.
	ExecuteWrite(ctx context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error)
}

// QueryResult represents the result of a Cypher query execution.
// It provides access to records, columns, and summary information.
type QueryResult struct {
	// Records contains the result rows as maps of column name to value.
	Records []map[string]any

	// Columns contains the names of the columns in the result set.
	Columns []string

	// Summary contains metadata about the query execution.
	Summary QuerySummary
}

// QuerySummary provides metadata about query execution.
type QuerySummary struct {
	// ExecutionTime is the duration of query execution.
	ExecutionTime time.Duration

	// NodesCreated is the number of nodes created by the query.
	NodesCreated int

	// NodesDeleted is the number of nodes deleted by the query.
	NodesDeleted int

	// RelationshipsCreated is the number of relationships created.
	RelationshipsCreated int

	// RelationshipsDeleted is the number of relationships deleted.
	RelationshipsDeleted int

	// PropertiesSet is the number of properties set.
	PropertiesSet int
}

// GraphClientConfig contains configuration options for graph database clients.
type GraphClientConfig struct {
	// URI is the connection URI for the graph database.
	// For Neo4j, use:
	//   - "bolt://host:port" for unencrypted connections
	//   - "bolt+s://host:port" for TLS encrypted connections
	//   - "bolt+ssc://host:port" for TLS with self-signed certificates
	//   - "neo4j://" or "neo4j+s://" for routing
	URI string

	// Username for authentication.
	Username string

	// Password for authentication.
	Password string

	// Database name to connect to.
	// Empty string uses the default database.
	Database string

	// MaxConnectionPoolSize limits the number of connections in the pool.
	// Zero or negative values use the driver default.
	MaxConnectionPoolSize int

	// ConnectionTimeout is the maximum time to wait for a connection.
	ConnectionTimeout time.Duration

	// MaxTransactionRetryTime is the maximum time to retry failed transactions.
	MaxTransactionRetryTime time.Duration
}

// DefaultConfig returns a GraphClientConfig with sensible defaults.
func DefaultConfig() GraphClientConfig {
	return GraphClientConfig{
		URI:                     "bolt://localhost:7687",
		Username:                "neo4j",
		Password:                "password",
		Database:                "",
		MaxConnectionPoolSize:   50,
		ConnectionTimeout:       30 * time.Second,
		MaxTransactionRetryTime: 30 * time.Second,
	}
}

// Validate checks if the configuration is valid.
func (c GraphClientConfig) Validate() error {
	if c.URI == "" {
		return types.NewError(ErrCodeGraphInvalidConfig, "URI cannot be empty")
	}
	if c.Username == "" {
		return types.NewError(ErrCodeGraphInvalidConfig, "Username cannot be empty")
	}
	if c.Password == "" {
		return types.NewError(ErrCodeGraphInvalidConfig, "Password cannot be empty")
	}
	if c.ConnectionTimeout <= 0 {
		return types.NewError(ErrCodeGraphInvalidConfig, "ConnectionTimeout must be positive")
	}
	if c.MaxTransactionRetryTime <= 0 {
		return types.NewError(ErrCodeGraphInvalidConfig, "MaxTransactionRetryTime must be positive")
	}
	return nil
}
