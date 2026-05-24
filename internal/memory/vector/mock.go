package vector

import (
	"context"
	"sync"
	"time"

	"github.com/zero-day-ai/gibson/internal/types"
)

// MockCall represents a recorded method call on the mock vector store.
type MockCall struct {
	Method    string
	Args      []interface{}
	Timestamp time.Time
}

// MockVectorStore is a mock implementation of VectorStore for testing.
// It provides configurable responses and tracks all method calls for verification.
type MockVectorStore struct {
	mu            sync.RWMutex
	records       map[string]VectorRecord
	searchResults []VectorResult
	healthStatus  types.HealthStatus
	calls         []MockCall
	storeError    error
	searchError   error
	getError      error
	deleteError   error
}

// NewMockVectorStore creates a new mock vector store for testing.
func NewMockVectorStore() *MockVectorStore {
	return &MockVectorStore{
		records:       make(map[string]VectorRecord),
		searchResults: make([]VectorResult, 0),
		calls:         make([]MockCall, 0),
		healthStatus:  types.NewHealthStatus(types.HealthStateHealthy, "mock vector store"),
	}
}

// Store records the call and stores the record if no error is configured.
func (m *MockVectorStore) Store(ctx context.Context, record VectorRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls = append(m.calls, MockCall{
		Method:    "Store",
		Args:      []interface{}{record},
		Timestamp: time.Now(),
	})

	if m.storeError != nil {
		return m.storeError
	}

	m.records[record.ID] = record
	return nil
}

// StoreBatch records the call and stores the records if no error is configured.
func (m *MockVectorStore) StoreBatch(ctx context.Context, records []VectorRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls = append(m.calls, MockCall{
		Method:    "StoreBatch",
		Args:      []interface{}{records},
		Timestamp: time.Now(),
	})

	if m.storeError != nil {
		return m.storeError
	}

	for _, record := range records {
		m.records[record.ID] = record
	}
	return nil
}

// Search records the call and returns the configured search results.
func (m *MockVectorStore) Search(ctx context.Context, query VectorQuery) ([]VectorResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls = append(m.calls, MockCall{
		Method:    "Search",
		Args:      []interface{}{query},
		Timestamp: time.Now(),
	})

	if m.searchError != nil {
		return nil, m.searchError
	}

	// Return a copy of the configured results
	results := make([]VectorResult, len(m.searchResults))
	copy(results, m.searchResults)
	return results, nil
}

// Get records the call and returns the record if found.
func (m *MockVectorStore) Get(ctx context.Context, id string) (*VectorRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls = append(m.calls, MockCall{
		Method:    "Get",
		Args:      []interface{}{id},
		Timestamp: time.Now(),
	})

	if m.getError != nil {
		return nil, m.getError
	}

	record, exists := m.records[id]
	if !exists {
		return nil, nil
	}

	return &record, nil
}

// Delete records the call and removes the record.
func (m *MockVectorStore) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls = append(m.calls, MockCall{
		Method:    "Delete",
		Args:      []interface{}{id},
		Timestamp: time.Now(),
	})

	if m.deleteError != nil {
		return m.deleteError
	}

	delete(m.records, id)
	return nil
}

// Health records the call and returns the configured health status.
func (m *MockVectorStore) Health(ctx context.Context) types.HealthStatus {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls = append(m.calls, MockCall{
		Method:    "Health",
		Args:      []interface{}{},
		Timestamp: time.Now(),
	})

	return m.healthStatus
}

// Close records the call and clears the mock state.
func (m *MockVectorStore) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls = append(m.calls, MockCall{
		Method:    "Close",
		Args:      []interface{}{},
		Timestamp: time.Now(),
	})

	m.records = make(map[string]VectorRecord)
	return nil
}

// SetSearchResults configures what Search() should return.
func (m *MockVectorStore) SetSearchResults(results []VectorResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.searchResults = results
}

// SetHealthStatus configures what Health() should return.
func (m *MockVectorStore) SetHealthStatus(status types.HealthStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthStatus = status
}

// SetStoreError configures Store() to return an error.
func (m *MockVectorStore) SetStoreError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.storeError = err
}

// SetSearchError configures Search() to return an error.
func (m *MockVectorStore) SetSearchError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.searchError = err
}

// SetGetError configures Get() to return an error.
func (m *MockVectorStore) SetGetError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getError = err
}

// SetDeleteError configures Delete() to return an error.
func (m *MockVectorStore) SetDeleteError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteError = err
}

// GetCalls returns all recorded method calls.
func (m *MockVectorStore) GetCalls() []MockCall {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a copy to prevent race conditions
	calls := make([]MockCall, len(m.calls))
	copy(calls, m.calls)
	return calls
}

// GetCallsByMethod returns all calls to a specific method.
func (m *MockVectorStore) GetCallsByMethod(method string) []MockCall {
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
func (m *MockVectorStore) CallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.calls)
}

// Reset clears all recorded calls and resets the mock to its initial state.
func (m *MockVectorStore) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.records = make(map[string]VectorRecord)
	m.searchResults = make([]VectorResult, 0)
	m.calls = make([]MockCall, 0)
	m.storeError = nil
	m.searchError = nil
	m.getError = nil
	m.deleteError = nil
	m.healthStatus = types.NewHealthStatus(types.HealthStateHealthy, "mock vector store")
}
