package graph

import (
	"context"
	"fmt"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/zero-day-ai/gibson/internal/types"
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

// CreateNode creates a node with the given labels and properties.
func (c *SessionGraphClient) CreateNode(ctx context.Context, labels []string, props map[string]any) (string, error) {
	if c.session == nil {
		return "", types.NewError(ErrCodeGraphConnectionClosed, "session graph client: no session")
	}

	labelStr := ""
	for i, lbl := range labels {
		if i == 0 {
			labelStr = ":" + lbl
		} else {
			labelStr += ":" + lbl
		}
	}

	cypher := fmt.Sprintf("CREATE (n%s) SET n = $props RETURN elementId(n) as id", labelStr)

	res, err := c.session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
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
		return "", types.WrapError(ErrCodeGraphNodeCreateFailed, "session client: create node failed", err)
	}
	return res.(string), nil
}

// CreateRelationship creates a relationship between two nodes identified by their id property.
func (c *SessionGraphClient) CreateRelationship(ctx context.Context, fromID, toID, relType string, props map[string]any) error {
	if c.session == nil {
		return types.NewError(ErrCodeGraphConnectionClosed, "session graph client: no session")
	}

	cypher := fmt.Sprintf(`
		MATCH (from {id: $fromId}), (to {id: $toId})
		CREATE (from)-[r:%s]->(to)
		SET r = $props
		RETURN r
	`, relType)

	_, err := c.session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, cypher, map[string]any{
			"fromId": fromID,
			"toId":   toID,
			"props":  props,
		})
		if err != nil {
			return nil, err
		}
		_, err = result.Single(ctx)
		return nil, err
	})
	if err != nil {
		return types.WrapError(ErrCodeGraphRelationshipCreateFailed, "session client: create relationship failed", err)
	}
	return nil
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

// ExecuteWrite runs fn inside a managed write transaction on the held per-tenant
// session. The session lifecycle is owned by the datapool.Conn (closed via
// conn.Release()); this method does NOT close the session after use.
func (c *SessionGraphClient) ExecuteWrite(ctx context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
	if c.session == nil {
		return nil, types.NewError(ErrCodeGraphConnectionClosed, "session graph client: no session")
	}
	return c.session.ExecuteWrite(ctx, fn)
}

// DeleteNode deletes a node by its Gibson id property.
func (c *SessionGraphClient) DeleteNode(ctx context.Context, nodeID string) error {
	if c.session == nil {
		return types.NewError(ErrCodeGraphConnectionClosed, "session graph client: no session")
	}

	_, err := c.session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, "MATCH (n {id: $id}) DETACH DELETE n", map[string]any{"id": nodeID})
		if err != nil {
			return nil, err
		}
		_, err = result.Consume(ctx)
		return nil, err
	})
	if err != nil {
		return types.WrapError(ErrCodeGraphNodeDeleteFailed, "session client: delete node failed", err)
	}
	return nil
}
