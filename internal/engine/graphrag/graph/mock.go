package graph

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// MockCall represents a recorded method call on the mock graph client.
type MockCall struct {
	Method    string
	Args      []interface{}
	Timestamp time.Time
}

// MockGraphClient is a mock implementation of GraphClient for testing.
// It provides configurable responses and tracks all method calls for verification.
type MockGraphClient struct {
	mu sync.RWMutex

	// State
	connected     bool
	healthStatus  types.HealthStatus
	nodes         map[string]mockNode
	relationships []mockRelationship
	calls         []MockCall
	nextNodeID    int

	// Configurable responses
	queryResults    []QueryResult
	queryError      error
	connectError    error
	closeError      error
	createNodeError error
	createRelError  error
	deleteNodeError error
}

// mockNode represents a stored node for the mock.
type mockNode struct {
	ID     string
	Labels []string
	Props  map[string]any
}

// mockRelationship represents a stored relationship for the mock.
type mockRelationship struct {
	FromID string
	ToID   string
	Type   string
	Props  map[string]any
}

// NewMockGraphClient creates a new mock graph client for testing.
func NewMockGraphClient() *MockGraphClient {
	return &MockGraphClient{
		connected:     false,
		healthStatus:  types.NewHealthStatus(types.HealthStateHealthy, "mock graph client"),
		nodes:         make(map[string]mockNode),
		relationships: make([]mockRelationship, 0),
		calls:         make([]MockCall, 0),
		queryResults:  make([]QueryResult, 0),
		nextNodeID:    1,
	}
}

// Connect records the call and simulates connection.
func (m *MockGraphClient) Connect(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls = append(m.calls, MockCall{
		Method:    "Connect",
		Args:      []interface{}{},
		Timestamp: time.Now(),
	})

	if m.connectError != nil {
		return m.connectError
	}

	m.connected = true
	return nil
}

// Close records the call and simulates disconnection.
func (m *MockGraphClient) Close(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls = append(m.calls, MockCall{
		Method:    "Close",
		Args:      []interface{}{},
		Timestamp: time.Now(),
	})

	if m.closeError != nil {
		return m.closeError
	}

	m.connected = false
	return nil
}

// Health records the call and returns the configured health status.
func (m *MockGraphClient) Health(ctx context.Context) types.HealthStatus {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls = append(m.calls, MockCall{
		Method:    "Health",
		Args:      []interface{}{},
		Timestamp: time.Now(),
	})

	if !m.connected {
		return types.Unhealthy("not connected")
	}

	return m.healthStatus
}

// Query records the call and returns the configured query results.
func (m *MockGraphClient) Query(ctx context.Context, cypher string, params map[string]any) (QueryResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls = append(m.calls, MockCall{
		Method:    "Query",
		Args:      []interface{}{cypher, params},
		Timestamp: time.Now(),
	})

	if !m.connected {
		return QueryResult{}, types.NewError(ErrCodeGraphConnectionClosed,
			"not connected")
	}

	if m.queryError != nil {
		return QueryResult{}, m.queryError
	}

	// Return the first configured result (FIFO)
	if len(m.queryResults) > 0 {
		result := m.queryResults[0]
		m.queryResults = m.queryResults[1:]
		return result, nil
	}

	// Return empty result if no results configured
	return QueryResult{
		Records: []map[string]any{},
		Columns: []string{},
		Summary: QuerySummary{},
	}, nil
}

// CreateNode records the call and creates a mock node.
func (m *MockGraphClient) CreateNode(ctx context.Context, labels []string, props map[string]any) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls = append(m.calls, MockCall{
		Method:    "CreateNode",
		Args:      []interface{}{labels, props},
		Timestamp: time.Now(),
	})

	if !m.connected {
		return "", types.NewError(ErrCodeGraphConnectionClosed,
			"not connected")
	}

	if m.createNodeError != nil {
		return "", m.createNodeError
	}

	// Generate a unique node ID
	nodeID := fmt.Sprintf("mock-node-%d", m.nextNodeID)
	m.nextNodeID++

	// Store the node
	m.nodes[nodeID] = mockNode{
		ID:     nodeID,
		Labels: labels,
		Props:  props,
	}

	return nodeID, nil
}

// CreateRelationship records the call and creates a mock relationship.
func (m *MockGraphClient) CreateRelationship(ctx context.Context, fromID, toID, relType string, props map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls = append(m.calls, MockCall{
		Method:    "CreateRelationship",
		Args:      []interface{}{fromID, toID, relType, props},
		Timestamp: time.Now(),
	})

	if !m.connected {
		return types.NewError(ErrCodeGraphConnectionClosed,
			"not connected")
	}

	if m.createRelError != nil {
		return m.createRelError
	}

	// Verify nodes exist
	if _, exists := m.nodes[fromID]; !exists {
		return types.NewError(ErrCodeGraphNodeNotFound,
			fmt.Sprintf("from node not found: %s", fromID))
	}
	if _, exists := m.nodes[toID]; !exists {
		return types.NewError(ErrCodeGraphNodeNotFound,
			fmt.Sprintf("to node not found: %s", toID))
	}

	// Store the relationship
	m.relationships = append(m.relationships, mockRelationship{
		FromID: fromID,
		ToID:   toID,
		Type:   relType,
		Props:  props,
	})

	return nil
}

// DeleteNode records the call and removes the mock node.
func (m *MockGraphClient) DeleteNode(ctx context.Context, nodeID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls = append(m.calls, MockCall{
		Method:    "DeleteNode",
		Args:      []interface{}{nodeID},
		Timestamp: time.Now(),
	})

	if !m.connected {
		return types.NewError(ErrCodeGraphConnectionClosed,
			"not connected")
	}

	if m.deleteNodeError != nil {
		return m.deleteNodeError
	}

	// Check if node exists
	if _, exists := m.nodes[nodeID]; !exists {
		return types.NewError(ErrCodeGraphNodeNotFound,
			fmt.Sprintf("node not found: %s", nodeID))
	}

	// Delete the node
	delete(m.nodes, nodeID)

	// Delete associated relationships
	filteredRels := make([]mockRelationship, 0)
	for _, rel := range m.relationships {
		if rel.FromID != nodeID && rel.ToID != nodeID {
			filteredRels = append(filteredRels, rel)
		}
	}
	m.relationships = filteredRels

	return nil
}

// ExecuteRead records the call and runs fn with a nil ManagedTransaction.
// The mock does not execute real Cypher; fn is called with nil to satisfy the
// interface. Tests that need real transaction behaviour should use a real driver.
func (m *MockGraphClient) ExecuteRead(ctx context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls = append(m.calls, MockCall{
		Method:    "ExecuteRead",
		Args:      []interface{}{fn},
		Timestamp: time.Now(),
	})

	if !m.connected {
		return nil, types.NewError(ErrCodeGraphConnectionClosed, "not connected")
	}
	if m.queryError != nil {
		return nil, m.queryError
	}
	return fn(nil)
}

// ExecuteWrite records the call and runs fn with a nil ManagedTransaction.
// The mock does not execute real Cypher; fn is called with nil to satisfy the
// interface. Tests that need real transaction behaviour should use a real driver.
func (m *MockGraphClient) ExecuteWrite(ctx context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls = append(m.calls, MockCall{
		Method:    "ExecuteWrite",
		Args:      []interface{}{fn},
		Timestamp: time.Now(),
	})

	if !m.connected {
		return nil, types.NewError(ErrCodeGraphConnectionClosed, "not connected")
	}
	if m.queryError != nil {
		return nil, m.queryError
	}
	return fn(nil)
}

// SetQueryResults configures what Query() should return (FIFO queue).
func (m *MockGraphClient) SetQueryResults(results []QueryResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.queryResults = results
}

// AddQueryResult adds a single query result to the queue.
func (m *MockGraphClient) AddQueryResult(result QueryResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.queryResults = append(m.queryResults, result)
}

// SetHealthStatus configures what Health() should return.
func (m *MockGraphClient) SetHealthStatus(status types.HealthStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthStatus = status
}

// SetConnectError configures Connect() to return an error.
func (m *MockGraphClient) SetConnectError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connectError = err
}

// SetCloseError configures Close() to return an error.
func (m *MockGraphClient) SetCloseError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeError = err
}

// SetQueryError configures Query() to return an error.
func (m *MockGraphClient) SetQueryError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.queryError = err
}

// SetCreateNodeError configures CreateNode() to return an error.
func (m *MockGraphClient) SetCreateNodeError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createNodeError = err
}

// SetCreateRelationshipError configures CreateRelationship() to return an error.
func (m *MockGraphClient) SetCreateRelationshipError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createRelError = err
}

// SetDeleteNodeError configures DeleteNode() to return an error.
func (m *MockGraphClient) SetDeleteNodeError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteNodeError = err
}

// GetCalls returns all recorded method calls.
func (m *MockGraphClient) GetCalls() []MockCall {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy to prevent race conditions
	calls := make([]MockCall, len(m.calls))
	copy(calls, m.calls)
	return calls
}

// GetCallsByMethod returns all calls to a specific method.
func (m *MockGraphClient) GetCallsByMethod(method string) []MockCall {
	m.mu.RLock()
	defer m.mu.RUnlock()

	calls := make([]MockCall, 0)
	for _, call := range m.calls {
		if call.Method == method {
			calls = append(calls, call)
		}
	}
	return calls
}

// CallCount returns the total number of method calls.
func (m *MockGraphClient) CallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.calls)
}

// GetNodes returns all stored nodes.
func (m *MockGraphClient) GetNodes() map[string]mockNode {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy
	nodes := make(map[string]mockNode, len(m.nodes))
	for k, v := range m.nodes {
		nodes[k] = v
	}
	return nodes
}

// GetRelationships returns all stored relationships.
func (m *MockGraphClient) GetRelationships() []mockRelationship {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy
	rels := make([]mockRelationship, len(m.relationships))
	copy(rels, m.relationships)
	return rels
}

// IsConnected returns whether the mock is in connected state.
func (m *MockGraphClient) IsConnected() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.connected
}

// Reset clears all recorded calls and resets the mock to its initial state.
func (m *MockGraphClient) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.connected = false
	m.healthStatus = types.NewHealthStatus(types.HealthStateHealthy, "mock graph client")
	m.nodes = make(map[string]mockNode)
	m.relationships = make([]mockRelationship, 0)
	m.calls = make([]MockCall, 0)
	m.queryResults = make([]QueryResult, 0)
	m.nextNodeID = 1
	m.queryError = nil
	m.connectError = nil
	m.closeError = nil
	m.createNodeError = nil
	m.createRelError = nil
	m.deleteNodeError = nil
}
