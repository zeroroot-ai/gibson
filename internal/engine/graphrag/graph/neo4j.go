// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package graph

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// Neo4jClient implements GraphClient for Neo4j graph databases.
// It provides connection pooling, automatic retries, and health monitoring.
type Neo4jClient struct {
	config GraphClientConfig
	driver neo4j.DriverWithContext
}

// NewNeo4jClient connects to the Neo4j database of config and returns the
// client. It retries with exponential backoff. A client never exists without
// its driver, so each method can use the driver without a check (gibson#681).
func NewNeo4jClient(ctx context.Context, config GraphClientConfig) (*Neo4jClient, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	driver, err := connectNeo4j(ctx, config)
	if err != nil {
		return nil, err
	}
	return &Neo4jClient{config: config, driver: driver}, nil
}

// Driver returns the underlying neo4j.DriverWithContext. Exposed so callers
// that need direct driver access (e.g., orchestrator graph intelligence) can
// build query helpers without re-establishing a connection.
func (c *Neo4jClient) Driver() neo4j.DriverWithContext {
	return c.driver
}

// Connect checks that the database answers. NewNeo4jClient already
// connected the driver.
func (c *Neo4jClient) Connect(ctx context.Context) error {
	if err := c.driver.VerifyConnectivity(ctx); err != nil {
		return types.WrapError(ErrCodeGraphConnectionFailed, "database does not answer", err)
	}
	return nil
}

// connectNeo4j makes a driver and verifies its connectivity. It uses
// exponential backoff for connection retries.
func connectNeo4j(ctx context.Context, cfg GraphClientConfig) (neo4j.DriverWithContext, error) {
	// Configure authentication
	auth := neo4j.BasicAuth(cfg.Username, cfg.Password, "")

	// Configure driver options
	driverConfig := func(config *neo4j.Config) {
		config.MaxConnectionPoolSize = cfg.MaxConnectionPoolSize
		config.ConnectionAcquisitionTimeout = cfg.ConnectionTimeout
		config.MaxTransactionRetryTime = cfg.MaxTransactionRetryTime
		// Note: Encryption is controlled by URI scheme (bolt:// vs bolt+s://)
		// TLS configuration can be set via config.TlsConfig if needed
	}

	var lastErr error
	maxRetries := 5
	baseDelay := 100 * time.Millisecond

	for attempt := 0; attempt < maxRetries; attempt++ {
		driver, err := neo4j.NewDriverWithContext(cfg.URI, auth, driverConfig)
		if err == nil {
			// Verify connectivity
			err = driver.VerifyConnectivity(ctx)
			if err == nil {
				return driver, nil
			}
			_ = driver.Close(ctx)
		}

		lastErr = err

		// Check if context is cancelled
		if ctx.Err() != nil {
			return nil, types.WrapError(ErrCodeGraphConnectionFailed,
				"connection attempt cancelled", ctx.Err())
		}

		// Calculate backoff delay: baseDelay * 2^attempt
		delay := baseDelay * time.Duration(math.Pow(2, float64(attempt)))
		if delay > cfg.ConnectionTimeout {
			delay = cfg.ConnectionTimeout
		}

		select {
		case <-time.After(delay):
			continue
		case <-ctx.Done():
			return nil, types.WrapError(ErrCodeGraphConnectionFailed,
				"connection attempt cancelled", ctx.Err())
		}
	}

	return nil, types.WrapError(ErrCodeGraphConnectionFailed,
		fmt.Sprintf("failed to connect after %d attempts", maxRetries), lastErr)
}

// Close releases all resources and closes the database connection. A
// method called after Close returns the error of the closed driver.
func (c *Neo4jClient) Close(ctx context.Context) error {
	if err := c.driver.Close(ctx); err != nil {
		return types.WrapError(ErrCodeGraphConnectionClosed,
			"failed to close driver", err)
	}
	return nil
}

// Health returns the current health status of the Neo4j connection.
func (c *Neo4jClient) Health(ctx context.Context) types.HealthStatus {
	// Verify connectivity with a timeout
	healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := c.driver.VerifyConnectivity(healthCtx); err != nil {
		return types.Unhealthy(fmt.Sprintf("connectivity check failed: %v", err))
	}

	return types.Healthy("connected to Neo4j")
}

// Query runs a Cypher query in a read transaction on a read-mode session. A
// write statement fails: Query never opens a write transaction (ADR-0112).
func (c *Neo4jClient) Query(ctx context.Context, cypher string, params map[string]any) (QueryResult, error) {
	startTime := time.Now()

	session := c.driver.NewSession(ctx, neo4j.SessionConfig{
		DatabaseName: c.config.Database,
		AccessMode:   neo4j.AccessModeRead,
	})
	defer session.Close(ctx)

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

	result, err := session.ExecuteRead(ctx, txWork)
	if err != nil {
		return QueryResult{}, types.WrapError(ErrCodeGraphQueryFailed,
			"query execution failed", err)
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
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{
		DatabaseName: c.config.Database,
		AccessMode:   neo4j.AccessModeRead,
	})
	defer session.Close(ctx)
	return session.ExecuteRead(ctx, fn)
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
