package ingest

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/loader"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
)

// MockGraphClient is a mock implementation of graph.GraphClient for testing.
type MockGraphClient struct {
	mock.Mock
}

func (m *MockGraphClient) Connect(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockGraphClient) Close(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockGraphClient) Health(ctx context.Context) types.HealthStatus {
	args := m.Called(ctx)
	if result := args.Get(0); result != nil {
		return result.(types.HealthStatus)
	}
	return types.HealthStatus{}
}

func (m *MockGraphClient) Query(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
	args := m.Called(ctx, cypher, params)
	if result := args.Get(0); result != nil {
		return args.Get(0).(graph.QueryResult), args.Error(1)
	}
	return graph.QueryResult{}, args.Error(1)
}

func (m *MockGraphClient) CreateNode(ctx context.Context, labels []string, props map[string]any) (string, error) {
	args := m.Called(ctx, labels, props)
	return args.String(0), args.Error(1)
}

func (m *MockGraphClient) CreateRelationship(ctx context.Context, fromID, toID, relType string, props map[string]any) error {
	args := m.Called(ctx, fromID, toID, relType, props)
	return args.Error(0)
}

func (m *MockGraphClient) DeleteNode(ctx context.Context, nodeID string) error {
	args := m.Called(ctx, nodeID)
	return args.Error(0)
}

func (m *MockGraphClient) ExecuteRead(ctx context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
	args := m.Called(ctx, fn)
	return args.Get(0), args.Error(1)
}

func (m *MockGraphClient) ExecuteWrite(ctx context.Context, fn func(neo4j.ManagedTransaction) (any, error)) (any, error) {
	args := m.Called(ctx, fn)
	return args.Get(0), args.Error(1)
}

// Test helper to create a test execution context
func testExecContext() loader.ExecContext {
	return loader.ExecContext{
		MissionRunID:    "mission-run-123",
		MissionID:       "mission-456",
		AgentName:       "network-recon",
		AgentRunID:      "agent-run-789",
		ToolExecutionID: "tool-exec-abc",
	}
}

func TestNewDiscoveryProcessor(t *testing.T) {
	mockClient := &MockGraphClient{}
	graphLoader := loader.NewGraphLoader(mockClient)
	logger := slog.Default()

	processor := NewDiscoveryProcessor(graphLoader, mockClient, logger)

	assert.NotNil(t, processor)
	assert.IsType(t, &discoveryProcessor{}, processor)
}

func TestNewDiscoveryProcessor_NilLogger(t *testing.T) {
	mockClient := &MockGraphClient{}
	graphLoader := loader.NewGraphLoader(mockClient)

	// Should not panic with nil logger (uses default)
	processor := NewDiscoveryProcessor(graphLoader, mockClient, nil)

	assert.NotNil(t, processor)
}

func TestProcess_NilLoader(t *testing.T) {
	mockClient := &MockGraphClient{}
	logger := slog.Default()

	processor := NewDiscoveryProcessor(nil, mockClient, logger)

	ctx := context.Background()
	execCtx := testExecContext()
	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{{Ip: "192.168.1.1"}},
	}

	result, err := processor.Process(ctx, execCtx, discovery)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "GraphLoader is nil")
}

func TestProcess_NilDiscovery(t *testing.T) {
	mockClient := &MockGraphClient{}
	graphLoader := loader.NewGraphLoader(mockClient)
	logger := slog.Default()

	processor := NewDiscoveryProcessor(graphLoader, mockClient, logger)

	ctx := context.Background()
	execCtx := testExecContext()

	result, err := processor.Process(ctx, execCtx, nil)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, result.NodesCreated)
	assert.Equal(t, 0, result.RelationshipsCreated)
	assert.False(t, result.HasErrors())
}

func TestProcess_EmptyDiscovery(t *testing.T) {
	mockClient := &MockGraphClient{}
	graphLoader := loader.NewGraphLoader(mockClient)
	logger := slog.Default()

	processor := NewDiscoveryProcessor(graphLoader, mockClient, logger)

	ctx := context.Background()
	execCtx := testExecContext()
	discovery := &graphragpb.DiscoveryResult{} // Empty discovery

	result, err := processor.Process(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, result.NodesCreated)
	assert.Equal(t, 0, result.RelationshipsCreated)
	assert.False(t, result.HasErrors())
}

func TestProcess_SuccessfulStorage(t *testing.T) {
	mockClient := &MockGraphClient{}
	logger := slog.Default()

	// Mock Query responses for LoadBatch
	// First call creates nodes, subsequent calls create relationships
	mockClient.On("Query", mock.Anything, mock.Anything, mock.Anything).Return(
		graph.QueryResult{
			Records: []map[string]any{
				{"element_id": "4:node-1", "idx": int64(0)},
			},
		}, nil)

	graphLoader := loader.NewGraphLoader(mockClient)
	processor := NewDiscoveryProcessor(graphLoader, mockClient, logger)

	ctx := context.Background()
	execCtx := testExecContext()

	// Create a discovery with some nodes
	hostname1 := "web-server"
	hostname2 := "db-server"
	state1 := "up"
	state2 := "open"
	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Ip: "192.168.1.1", Hostname: &hostname1, State: &state1},
			{Ip: "192.168.1.2", Hostname: &hostname2, State: &state1},
		},
		Ports: []*graphragpb.Port{
			{HostId: "192.168.1.1", Number: 80, Protocol: "tcp", State: &state2},
			{HostId: "192.168.1.1", Number: 443, Protocol: "tcp", State: &state2},
		},
	}

	result, err := processor.Process(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Greater(t, result.NodesCreated, 0)
	assert.Greater(t, result.Duration, time.Duration(0))

	mockClient.AssertExpectations(t)
}

func TestProcess_StorageFailure(t *testing.T) {
	mockClient := &MockGraphClient{}
	logger := slog.Default()

	// Mock Query to return error
	storageErr := errors.New("neo4j connection failed")
	mockClient.On("Query", mock.Anything, mock.Anything, mock.Anything).Return(
		graph.QueryResult{}, storageErr)

	graphLoader := loader.NewGraphLoader(mockClient)
	processor := NewDiscoveryProcessor(graphLoader, mockClient, logger)

	ctx := context.Background()
	execCtx := testExecContext()

	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{{Ip: "192.168.1.1"}},
	}

	result, err := processor.Process(ctx, execCtx, discovery)

	// Error should not be propagated (best-effort storage)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.HasErrors())
	assert.Greater(t, len(result.Errors), 0)
	// LoadDiscovery wraps errors from individual loaders (e.g., "failed to load hosts")
	assert.Contains(t, result.Errors[0].Error(), "failed to load hosts")

	mockClient.AssertExpectations(t)
}

func TestProcess_ComplexHierarchy(t *testing.T) {
	mockClient := &MockGraphClient{}
	logger := slog.Default()

	// Mock Query to return success with element IDs
	mockClient.On("Query", mock.Anything, mock.Anything, mock.Anything).Return(
		graph.QueryResult{
			Records: []map[string]any{
				{"element_id": "4:node-1", "idx": int64(0)},
			},
		}, nil)

	graphLoader := loader.NewGraphLoader(mockClient)
	processor := NewDiscoveryProcessor(graphLoader, mockClient, logger)

	ctx := context.Background()
	execCtx := testExecContext()

	// Create a complete hierarchy: Host -> Port -> Service -> Endpoint
	hostname := "web-server"
	portState := "open"
	version := "nginx/1.18.0"
	method := "GET"
	statusCode := int32(200)
	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Ip: "192.168.1.1", Hostname: &hostname},
		},
		Ports: []*graphragpb.Port{
			{HostId: "192.168.1.1", Number: 443, Protocol: "tcp", State: &portState},
		},
		Services: []*graphragpb.Service{
			{PortId: "192.168.1.1:443/tcp", Name: "https", Version: &version},
		},
		Endpoints: []*graphragpb.Endpoint{
			{ServiceId: "192.168.1.1:443/tcp:https", Url: "/api/v1/users", Method: &method, StatusCode: &statusCode},
		},
	}

	result, err := processor.Process(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Greater(t, result.NodesCreated, 0)

	mockClient.AssertExpectations(t)
}

func TestProcess_DurationTracking(t *testing.T) {
	mockClient := &MockGraphClient{}
	logger := slog.Default()

	// Mock Query with a small delay
	mockClient.On("Query", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		time.Sleep(10 * time.Millisecond)
	}).Return(graph.QueryResult{
		Records: []map[string]any{
			{"element_id": "4:node-1", "idx": int64(0)},
		},
	}, nil)

	graphLoader := loader.NewGraphLoader(mockClient)
	processor := NewDiscoveryProcessor(graphLoader, mockClient, logger)

	ctx := context.Background()
	execCtx := testExecContext()

	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{{Ip: "192.168.1.1"}},
	}

	startTime := time.Now()
	result, err := processor.Process(ctx, execCtx, discovery)
	elapsed := time.Since(startTime)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Greater(t, result.Duration, time.Duration(0))
	assert.LessOrEqual(t, result.Duration, elapsed)
	assert.GreaterOrEqual(t, result.Duration, 10*time.Millisecond)

	mockClient.AssertExpectations(t)
}

func TestProcessResult_HasErrors(t *testing.T) {
	tests := []struct {
		name     string
		errors   []error
		expected bool
	}{
		{
			name:     "no errors",
			errors:   nil,
			expected: false,
		},
		{
			name:     "empty errors slice",
			errors:   []error{},
			expected: false,
		},
		{
			name:     "one error",
			errors:   []error{errors.New("test error")},
			expected: true,
		},
		{
			name:     "multiple errors",
			errors:   []error{errors.New("error 1"), errors.New("error 2")},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ProcessResult{Errors: tt.errors}
			assert.Equal(t, tt.expected, result.HasErrors())
		})
	}
}

func TestProcessResult_AddError(t *testing.T) {
	result := &ProcessResult{}

	assert.False(t, result.HasErrors())
	assert.Len(t, result.Errors, 0)

	// Add first error
	err1 := errors.New("first error")
	returned := result.AddError(err1)

	assert.True(t, result.HasErrors())
	assert.Len(t, result.Errors, 1)
	assert.Equal(t, err1, result.Errors[0])
	assert.Equal(t, result, returned) // Chaining support

	// Add second error
	err2 := errors.New("second error")
	result.AddError(err2)

	assert.True(t, result.HasErrors())
	assert.Len(t, result.Errors, 2)
	assert.Equal(t, err1, result.Errors[0])
	assert.Equal(t, err2, result.Errors[1])
}

func TestProcess_AllNodeTypes(t *testing.T) {
	mockClient := &MockGraphClient{}
	logger := slog.Default()

	// Mock Query to return success
	mockClient.On("Query", mock.Anything, mock.Anything, mock.Anything).Return(
		graph.QueryResult{
			Records: []map[string]any{
				{"element_id": "4:node-1", "idx": int64(0)},
			},
		}, nil)

	graphLoader := loader.NewGraphLoader(mockClient)
	processor := NewDiscoveryProcessor(graphLoader, mockClient, logger)

	ctx := context.Background()
	execCtx := testExecContext()

	// Create discovery with various node types
	version := "1.18.0"
	subName := "www"
	discovery := &graphragpb.DiscoveryResult{
		Hosts:        []*graphragpb.Host{{Ip: "192.168.1.1"}},
		Ports:        []*graphragpb.Port{{HostId: "192.168.1.1", Number: 80, Protocol: "tcp"}},
		Services:     []*graphragpb.Service{{PortId: "192.168.1.1:80:tcp", Name: "http"}},
		Domains:      []*graphragpb.Domain{{Name: "example.com"}},
		Subdomains:   []*graphragpb.Subdomain{{DomainId: "example.com", Name: subName}},
		Technologies: []*graphragpb.Technology{{Name: "nginx", Version: &version}},
	}

	result, err := processor.Process(ctx, execCtx, discovery)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Greater(t, result.NodesCreated, 0)

	mockClient.AssertExpectations(t)
}
