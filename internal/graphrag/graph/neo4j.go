package graph

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/zero-day-ai/gibson/internal/types"
)

// Neo4jClient implements GraphClient for Neo4j graph databases.
// It provides connection pooling, automatic retries, and health monitoring.
type Neo4jClient struct {
	config GraphClientConfig
	driver neo4j.DriverWithContext
}

// NewNeo4jClient creates a new Neo4j client with the given configuration.
// The client must be connected via Connect() before use.
func NewNeo4jClient(config GraphClientConfig) (*Neo4jClient, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &Neo4jClient{
		config: config,
	}, nil
}

// Driver returns the underlying neo4j.DriverWithContext after Connect has
// succeeded, or nil before connection is established. Exposed so callers that
// need direct driver access (e.g., orchestrator graph intelligence) can build
// query helpers without re-establishing a connection.
func (c *Neo4jClient) Driver() neo4j.DriverWithContext {
	return c.driver
}

// Connect establishes a connection to the Neo4j database.
// Uses exponential backoff for connection retries.
func (c *Neo4jClient) Connect(ctx context.Context) error {
	// Configure authentication
	auth := neo4j.BasicAuth(c.config.Username, c.config.Password, "")

	// Configure driver options
	driverConfig := func(config *neo4j.Config) {
		config.MaxConnectionPoolSize = c.config.MaxConnectionPoolSize
		config.ConnectionAcquisitionTimeout = c.config.ConnectionTimeout
		config.MaxTransactionRetryTime = c.config.MaxTransactionRetryTime
		// Note: Encryption is controlled by URI scheme (bolt:// vs bolt+s://)
		// TLS configuration can be set via config.TlsConfig if needed
	}

	// Create driver with exponential backoff
	var driver neo4j.DriverWithContext
	var lastErr error
	maxRetries := 5
	baseDelay := 100 * time.Millisecond

	for attempt := 0; attempt < maxRetries; attempt++ {
		var err error
		driver, err = neo4j.NewDriverWithContext(c.config.URI, auth, driverConfig)
		if err == nil {
			// Verify connectivity
			err = driver.VerifyConnectivity(ctx)
			if err == nil {
				c.driver = driver
				return nil
			}
		}

		lastErr = err

		// Check if context is cancelled
		if ctx.Err() != nil {
			return types.WrapError(ErrCodeGraphConnectionFailed,
				"connection attempt cancelled", ctx.Err())
		}

		// Calculate backoff delay: baseDelay * 2^attempt
		delay := baseDelay * time.Duration(math.Pow(2, float64(attempt)))
		if delay > c.config.ConnectionTimeout {
			delay = c.config.ConnectionTimeout
		}

		select {
		case <-time.After(delay):
			continue
		case <-ctx.Done():
			return types.WrapError(ErrCodeGraphConnectionFailed,
				"connection attempt cancelled", ctx.Err())
		}
	}

	return types.WrapError(ErrCodeGraphConnectionFailed,
		fmt.Sprintf("failed to connect after %d attempts", maxRetries), lastErr)
}

// Close releases all resources and closes the database connection.
func (c *Neo4jClient) Close(ctx context.Context) error {
	if c.driver == nil {
		return nil
	}

	if err := c.driver.Close(ctx); err != nil {
		return types.WrapError(ErrCodeGraphConnectionClosed,
			"failed to close driver", err)
	}

	c.driver = nil
	return nil
}

// Health returns the current health status of the Neo4j connection.
func (c *Neo4jClient) Health(ctx context.Context) types.HealthStatus {
	if c.driver == nil {
		return types.Unhealthy("driver not initialized")
	}

	// Verify connectivity with a timeout
	healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := c.driver.VerifyConnectivity(healthCtx); err != nil {
		return types.Unhealthy(fmt.Sprintf("connectivity check failed: %v", err))
	}

	return types.Healthy("connected to Neo4j")
}

// Query executes a Cypher query with the given parameters.
// Automatically detects write queries (CREATE, MERGE, SET, DELETE, REMOVE)
// and uses ExecuteWrite; otherwise uses ExecuteRead for better performance.
func (c *Neo4jClient) Query(ctx context.Context, cypher string, params map[string]any) (QueryResult, error) {
	if c.driver == nil {
		return QueryResult{}, types.NewError(ErrCodeGraphConnectionClosed,
			"driver not connected")
	}

	startTime := time.Now()

	// Create session
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{
		DatabaseName: c.config.Database,
	})
	defer session.Close(ctx)

	// Detect if query is a write operation
	isWriteQuery := isWriteOperation(cypher)

	// Transaction work function
	txWork := func(tx neo4j.ManagedTransaction) (any, error) {
		neoResult, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}

		// Collect all records
		records, err := neoResult.Collect(ctx)
		if err != nil {
			return nil, err
		}

		// Get result summary
		summary, err := neoResult.Consume(ctx)
		if err != nil {
			return nil, err
		}

		// Convert Neo4j records to our QueryResult format
		return convertNeo4jResult(records, summary), nil
	}

	var result any
	var err error

	if isWriteQuery {
		result, err = session.ExecuteWrite(ctx, txWork)
	} else {
		result, err = session.ExecuteRead(ctx, txWork)
	}

	if err != nil {
		return QueryResult{}, types.WrapError(ErrCodeGraphQueryFailed,
			"query execution failed", err)
	}

	queryResult := result.(QueryResult)
	queryResult.Summary.ExecutionTime = time.Since(startTime)

	return queryResult, nil
}

// CreateNode creates a new node with the specified labels and properties.
func (c *Neo4jClient) CreateNode(ctx context.Context, labels []string, props map[string]any) (string, error) {
	if c.driver == nil {
		return "", types.NewError(ErrCodeGraphConnectionClosed,
			"driver not connected")
	}

	// No tenant_id property: tenant isolation is provided by the per-tenant
	// Neo4j database (database-per-tenant-data-plane, Requirement 2.6).

	// Build CREATE query
	labelStr := ""
	for i, label := range labels {
		if i == 0 {
			labelStr = ":" + label
		} else {
			labelStr += ":" + label
		}
	}

	cypher := fmt.Sprintf("CREATE (n%s) SET n = $props RETURN elementId(n) as id", labelStr)

	// Create session
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{
		DatabaseName: c.config.Database,
	})
	defer session.Close(ctx)

	// Execute in write transaction
	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		neoResult, err := tx.Run(ctx, cypher, map[string]any{"props": props})
		if err != nil {
			return nil, err
		}

		record, err := neoResult.Single(ctx)
		if err != nil {
			return nil, err
		}

		id, ok := record.Get("id")
		if !ok {
			return nil, fmt.Errorf("id not found in result")
		}

		return id.(string), nil
	})

	if err != nil {
		return "", types.WrapError(ErrCodeGraphNodeCreateFailed,
			"failed to create node", err)
	}

	return result.(string), nil
}

// CreateRelationship creates a relationship between two nodes.
func (c *Neo4jClient) CreateRelationship(ctx context.Context, fromID, toID, relType string, props map[string]any) error {
	if c.driver == nil {
		return types.NewError(ErrCodeGraphConnectionClosed,
			"driver not connected")
	}

	// Build MATCH + CREATE query using id property (Gibson UUIDs stored as node.id)
	// Note: We match on the 'id' property, not Neo4j's internal elementId(),
	// because relationships reference Gibson node IDs, not Neo4j element IDs.
	cypher := fmt.Sprintf(`
		MATCH (from {id: $fromId}), (to {id: $toId})
		CREATE (from)-[r:%s]->(to)
		SET r = $props
		RETURN r
	`, relType)

	params := map[string]any{
		"fromId": fromID,
		"toId":   toID,
		"props":  props,
	}

	// Create session
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{
		DatabaseName: c.config.Database,
	})
	defer session.Close(ctx)

	// Execute in write transaction
	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		neoResult, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}

		// Ensure the query executed successfully
		_, err = neoResult.Single(ctx)
		return nil, err
	})

	if err != nil {
		return types.WrapError(ErrCodeGraphRelationshipCreateFailed,
			"failed to create relationship", err)
	}

	return nil
}

// DeleteNode deletes a node by its element ID.
func (c *Neo4jClient) DeleteNode(ctx context.Context, nodeID string) error {
	if c.driver == nil {
		return types.NewError(ErrCodeGraphConnectionClosed,
			"driver not connected")
	}

	// DETACH DELETE removes the node and all its relationships
	cypher := "MATCH (n) WHERE elementId(n) = $id DETACH DELETE n"
	params := map[string]any{"id": nodeID}

	// Create session
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{
		DatabaseName: c.config.Database,
	})
	defer session.Close(ctx)

	// Execute in write transaction
	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		_, err := tx.Run(ctx, cypher, params)
		return nil, err
	})

	if err != nil {
		return types.WrapError(ErrCodeGraphNodeDeleteFailed,
			"failed to delete node", err)
	}

	return nil
}

// ExecuteWriteQuery executes a Cypher write query string with the given parameters.
// This method is useful for executing custom write operations like MERGE, CREATE, SET, DELETE, etc.
// The query is executed within a write transaction for consistency and automatic retries.
//
// Deprecated: prefer ExecuteWrite (the interface method accepting a closure) for new callers.
func (c *Neo4jClient) ExecuteWriteQuery(ctx context.Context, cypher string, params map[string]any) (QueryResult, error) {
	if c.driver == nil {
		return QueryResult{}, types.NewError(ErrCodeGraphConnectionClosed,
			"driver not connected")
	}

	startTime := time.Now()

	// Create session
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{
		DatabaseName: c.config.Database,
	})
	defer session.Close(ctx)

	// Execute query in a write transaction
	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		neoResult, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}

		// Collect all records
		records, err := neoResult.Collect(ctx)
		if err != nil {
			return nil, err
		}

		// Get result summary
		summary, err := neoResult.Consume(ctx)
		if err != nil {
			return nil, err
		}

		// Convert Neo4j records to our QueryResult format
		return convertNeo4jResult(records, summary), nil
	})

	if err != nil {
		return QueryResult{}, types.WrapError(ErrCodeGraphQueryFailed,
			"write query execution failed", err)
	}

	queryResult := result.(QueryResult)
	queryResult.Summary.ExecutionTime = time.Since(startTime)

	return queryResult, nil
}

// ExecuteRead opens a fresh read-mode session from the shared driver pool and
// runs fn inside a managed read transaction. The session is closed after fn
// returns. Use this for platform-level reads that are not tied to a specific
// tenant database (see GraphClient.ExecuteRead for the full contract).
func (c *Neo4jClient) ExecuteRead(ctx context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
	if c.driver == nil {
		return nil, types.NewError(ErrCodeGraphConnectionClosed, "driver not connected")
	}
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{
		DatabaseName: c.config.Database,
		AccessMode:   neo4j.AccessModeRead,
	})
	defer session.Close(ctx)
	return session.ExecuteRead(ctx, fn)
}

// ExecuteWrite opens a fresh write-mode session from the shared driver pool and
// runs fn inside a managed write transaction. The session is closed after fn
// returns. Use this for platform-level writes that are not tied to a specific
// tenant database (see GraphClient.ExecuteWrite for the full contract).
func (c *Neo4jClient) ExecuteWrite(ctx context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
	if c.driver == nil {
		return nil, types.NewError(ErrCodeGraphConnectionClosed, "driver not connected")
	}
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{
		DatabaseName: c.config.Database,
		AccessMode:   neo4j.AccessModeWrite,
	})
	defer session.Close(ctx)
	return session.ExecuteWrite(ctx, fn)
}

// isWriteOperation detects if a Cypher query is a write operation.
// Write operations include CREATE, MERGE, SET, DELETE, REMOVE, and DETACH DELETE.
func isWriteOperation(cypher string) bool {
	// Convert to uppercase for case-insensitive matching
	upper := strings.ToUpper(cypher)

	// Check for write keywords
	writeKeywords := []string{
		"CREATE",
		"MERGE",
		"SET ", // Space to avoid matching OFFSET
		"DELETE",
		"REMOVE",
		"DETACH",
	}

	for _, keyword := range writeKeywords {
		if strings.Contains(upper, keyword) {
			return true
		}
	}

	return false
}

// convertNeo4jResult converts Neo4j records and summary to our QueryResult format.
func convertNeo4jResult(records []*neo4j.Record, summary neo4j.ResultSummary) QueryResult {
	result := QueryResult{
		Records: make([]map[string]any, 0, len(records)),
		Columns: []string{},
	}

	// Extract column names from first record
	if len(records) > 0 {
		result.Columns = records[0].Keys
	}

	// Convert records
	for _, record := range records {
		recordMap := make(map[string]any)
		for i, key := range record.Keys {
			recordMap[key] = record.Values[i]
		}
		result.Records = append(result.Records, recordMap)
	}

	// Extract counters from summary
	if summary != nil && summary.Counters() != nil {
		counters := summary.Counters()
		result.Summary = QuerySummary{
			NodesCreated:         counters.NodesCreated(),
			NodesDeleted:         counters.NodesDeleted(),
			RelationshipsCreated: counters.RelationshipsCreated(),
			RelationshipsDeleted: counters.RelationshipsDeleted(),
			PropertiesSet:        counters.PropertiesSet(),
		}
	}

	return result
}
