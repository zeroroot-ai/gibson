// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package graph

import (
	"context"
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
	connected    bool
	healthStatus types.HealthStatus
	calls        []MockCall

	// Configurable responses
	queryResults []QueryResult
	queryError   error
	connectError error
	closeError   error
}

// NewMockGraphClient creates a new mock graph client for testing.
func NewMockGraphClient() *MockGraphClient {
	return &MockGraphClient{
		connected:    false,
		healthStatus: types.NewHealthStatus(types.HealthStateHealthy, "mock graph client"),
		calls:        make([]MockCall, 0),
		queryResults: make([]QueryResult, 0),
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
	m.calls = make([]MockCall, 0)
	m.queryResults = make([]QueryResult, 0)
	m.queryError = nil
	m.connectError = nil
	m.closeError = nil
}
