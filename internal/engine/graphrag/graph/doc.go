// Package graph provides graph database client abstraction for GraphRAG integration.
//
// This package defines a generic GraphClient interface that can be implemented
// for different graph database backends. The primary implementation is for Neo4j,
// but the interface design allows for other graph databases to be integrated.
//
// # Architecture
//
// The package follows a clean interface-based design:
//
//   - GraphClient: Core interface defining graph database operations
//   - Neo4jClient: Production implementation using the Neo4j Go driver
//   - MockGraphClient: Test implementation for unit testing
//
// # Usage
//
// Basic usage with Neo4j:
//
//	config := graph.DefaultConfig()
//	config.URI = "bolt://localhost:7687"
//	config.Username = "neo4j"
//	config.Password = "password"
//
//	client, err := graph.NewNeo4jClient(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	ctx := context.Background()
//	if err := client.Connect(ctx); err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close(ctx)
//
//	// Create a node
//	nodeID, err := client.CreateNode(ctx,
//	    []string{"Person"},
//	    map[string]any{"name": "Alice", "age": 30},
//	)
//
//	// Execute a Cypher query
//	result, err := client.Query(ctx,
//	    "MATCH (n:Person {name: $name}) RETURN n",
//	    map[string]any{"name": "Alice"},
//	)
//
// # Connection Management
//
// The Neo4j client uses connection pooling with configurable limits:
//
//   - MaxConnectionPoolSize: Maximum connections in the pool (default: 50)
//   - ConnectionTimeout: Timeout for acquiring a connection (default: 30s)
//   - MaxTransactionRetryTime: Maximum retry time for transactions (default: 30s)
//
// Connections are automatically retried with exponential backoff on failure.
//
// # TLS/Encryption
//
// Encryption is controlled via the URI scheme:
//
//   - bolt://     - Unencrypted connection
//   - bolt+s://   - TLS encrypted with system CA verification
//   - bolt+ssc:// - TLS encrypted, self-signed certificates accepted
//   - neo4j://    - Routing with unencrypted connections
//   - neo4j+s://  - Routing with TLS encryption
//
// # Health Monitoring
//
// The Health() method returns a types.HealthStatus indicating the connection state:
//
//	status := client.Health(ctx)
//	if status.IsHealthy() {
//	    log.Println("Graph database is healthy")
//	}
//
// # Error Handling
//
// All errors are wrapped in types.GibsonError with specific error codes:
//
//   - ErrCodeGraphConnectionFailed: Connection establishment failed
//   - ErrCodeGraphConnectionClosed: Operation on closed connection
//   - ErrCodeGraphQueryFailed: Query execution failed
//   - ErrCodeGraphNodeCreateFailed: Node creation failed
//   - ErrCodeGraphNodeNotFound: Node not found
//
// # Testing
//
// Use MockGraphClient for unit testing:
//
//	mock := graph.NewMockGraphClient()
//	mock.Connect(ctx)
//
//	// Configure responses
//	mock.AddQueryResult(graph.QueryResult{
//	    Records: []map[string]any{{"name": "Alice"}},
//	    Columns: []string{"name"},
//	})
//
//	// Verify calls
//	calls := mock.GetCallsByMethod("Query")
//	assert.Len(t, calls, 1)
//
// # Thread Safety
//
// All implementations must be thread-safe for concurrent access. The Neo4j
// driver handles connection pooling and thread safety internally.
//
// # Query Results
//
// Query results are returned as QueryResult containing:
//
//   - Records: Slice of maps representing result rows
//   - Columns: Column names from the query
//   - Summary: Execution metadata (counters, timing)
//
// # Node IDs
//
// Node IDs are opaque strings that vary by implementation:
//
//   - Neo4j: Uses element IDs (e.g., "4:abc123:0")
//   - Mock: Uses sequential IDs (e.g., "mock-node-1")
//
// Applications should treat node IDs as opaque identifiers.
package graph
