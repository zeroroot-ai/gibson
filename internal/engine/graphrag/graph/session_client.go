// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package graph

import (
	"context"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// SessionGraphClient implements GraphClient using a pre-opened neo4j.SessionWithContext.
// It is the per-call GraphClient used by the GraphRAGBridgeAdapter when constructing
// an ephemeral LocalGraphRAGProvider from the data-plane Pool's tenant session.
//
// Unlike Neo4jClient (which manages a DriverWithContext and opens sessions per-query),
// SessionGraphClient holds one session for its lifetime and executes all queries on it.
// The session is owned by the datapool.Conn and closed via conn.Release() — callers
// must NOT call Close() on the returned session separately.
//
// Thread safety: neo4j.SessionWithContext is not safe for concurrent use; use a new
// SessionGraphClient per-request (which is the per-call bridge pattern).
type SessionGraphClient struct {
	session neo4j.SessionWithContext
}

// NewSessionGraphClient wraps an existing neo4j.SessionWithContext as a GraphClient.
// The session must already be open. Ownership of the session remains with the caller;
// Close() on this client is a no-op so the pool can manage the session lifecycle.
func NewSessionGraphClient(session neo4j.SessionWithContext) *SessionGraphClient {
	return &SessionGraphClient{session: session}
}

// Driver returns nil. SessionGraphClient is session-backed and does not expose the
// underlying DriverWithContext. Callers that check for a non-nil driver (e.g.,
// orchestrator.NewNeo4jGraphQueries) will gracefully skip graph-intelligence features.
func (c *SessionGraphClient) Driver() neo4j.DriverWithContext {
	return nil
}

// Connect is a no-op — the session is already open at construction time.
func (c *SessionGraphClient) Connect(_ context.Context) error {
	return nil
}

// Close is a no-op — session lifecycle is managed by the datapool.Conn.
func (c *SessionGraphClient) Close(_ context.Context) error {
	return nil
}

// Health returns healthy when a session is present. No round-trip is performed
// because the per-call pattern closes the provider before the session is reused.
func (c *SessionGraphClient) Health(_ context.Context) types.HealthStatus {
	if c.session == nil {
		return types.Unhealthy("session graph client: no session")
	}
	return types.Healthy("session graph client: session present")
}

// Query executes a Cypher query on the held session.
// Read queries use ExecuteRead; write queries use ExecuteWrite.
func (c *SessionGraphClient) Query(ctx context.Context, cypher string, params map[string]any) (QueryResult, error) {
	if c.session == nil {
		return QueryResult{}, types.NewError(ErrCodeGraphConnectionClosed, "session graph client: no session")
	}

	start := time.Now()
	txWork := func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}
		records, err := result.Collect(ctx)
		if err != nil {
			return nil, err
		}
		summary, err := result.Consume(ctx)
		if err != nil {
			return nil, err
		}
		return convertNeo4jResult(records, summary), nil
	}

	var res any
	var err error
	if isWriteOperation(cypher) {
		res, err = c.session.ExecuteWrite(ctx, txWork)
	} else {
		res, err = c.session.ExecuteRead(ctx, txWork)
	}
	if err != nil {
		return QueryResult{}, types.WrapError(ErrCodeGraphQueryFailed, "session client: query failed", err)
	}

	qr := res.(QueryResult)
	qr.Summary.ExecutionTime = time.Since(start)
	return qr, nil
}

// ExecuteRead runs fn inside a managed read transaction on the held per-tenant
// session. The session lifecycle is owned by the datapool.Conn (closed via
// conn.Release()); this method does NOT close the session after use.
func (c *SessionGraphClient) ExecuteRead(ctx context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
	if c.session == nil {
		return nil, types.NewError(ErrCodeGraphConnectionClosed, "session graph client: no session")
	}
	return c.session.ExecuteRead(ctx, fn)
}
