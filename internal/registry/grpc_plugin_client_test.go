package registry

import (
	"context"
	"encoding/json"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/plugin"
	"github.com/zero-day-ai/gibson/internal/schema"
	proto "github.com/zero-day-ai/sdk/api/gen/proto"
	commonpb "github.com/zero-day-ai/sdk/api/gen/commonpb"
	"github.com/zero-day-ai/sdk/registry"
)

// createTestListener creates a TCP listener on a random port for testing
func createTestListener(t *testing.T) (net.Listener, string) {
	t.Helper()

	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}

	return lis, lis.Addr().String()
}

// mockPluginService implements proto.PluginServiceServer for testing
type mockPluginService struct {
	proto.UnimplementedPluginServiceServer

	// Test hooks
	initializeFunc  func(context.Context, *proto.PluginInitializeRequest) (*proto.PluginInitializeResponse, error)
	shutdownFunc    func(context.Context, *proto.PluginShutdownRequest) (*proto.PluginShutdownResponse, error)
	listMethodsFunc func(context.Context, *proto.PluginListMethodsRequest) (*proto.PluginListMethodsResponse, error)
	queryFunc       func(context.Context, *proto.PluginQueryRequest) (*proto.PluginQueryResponse, error)
	healthFunc      func(context.Context, *proto.PluginHealthRequest) (*proto.HealthStatus, error)
}

func (m *mockPluginService) Initialize(ctx context.Context, req *proto.PluginInitializeRequest) (*proto.PluginInitializeResponse, error) {
	if m.initializeFunc != nil {
		return m.initializeFunc(ctx, req)
	}
	return &proto.PluginInitializeResponse{}, nil
}

func (m *mockPluginService) Shutdown(ctx context.Context, req *proto.PluginShutdownRequest) (*proto.PluginShutdownResponse, error) {
	if m.shutdownFunc != nil {
		return m.shutdownFunc(ctx, req)
	}
	return &proto.PluginShutdownResponse{}, nil
}

func (m *mockPluginService) ListMethods(ctx context.Context, req *proto.PluginListMethodsRequest) (*proto.PluginListMethodsResponse, error) {
	if m.listMethodsFunc != nil {
		return m.listMethodsFunc(ctx, req)
	}
	// Default implementation returns empty methods
	return &proto.PluginListMethodsResponse{
		Methods: []*proto.PluginMethodDescriptor{},
	}, nil
}

func (m *mockPluginService) Query(ctx context.Context, req *proto.PluginQueryRequest) (*proto.PluginQueryResponse, error) {
	if m.queryFunc != nil {
		return m.queryFunc(ctx, req)
	}
	return &proto.PluginQueryResponse{}, nil
}

func (m *mockPluginService) Health(ctx context.Context, req *proto.PluginHealthRequest) (*proto.HealthStatus, error) {
	if m.healthFunc != nil {
		return m.healthFunc(ctx, req)
	}
	return &proto.HealthStatus{
		State:   "healthy",
		Message: "OK",
	}, nil
}

// setupTestPluginServer creates a test gRPC server with the mock plugin service
func setupTestPluginServer(t *testing.T, mock *mockPluginService) (*grpc.Server, string, func()) {
	t.Helper()

	// Create listener on random port
	lis, endpoint := createTestListener(t)

	// Create gRPC server
	server := grpc.NewServer()
	proto.RegisterPluginServiceServer(server, mock)

	// Start server in background
	go func() {
		if err := server.Serve(lis); err != nil {
			t.Logf("Server error: %v", err)
		}
	}()

	cleanup := func() {
		server.Stop()
		lis.Close()
	}

	return server, endpoint, cleanup
}

// TestGRPCPluginClient_Name tests the Name method
func TestGRPCPluginClient_Name(t *testing.T) {
	mock := &mockPluginService{}
	_, endpoint, cleanup := setupTestPluginServer(t, mock)
	defer cleanup()

	// Create connection
	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	// Create client with test ServiceInfo
	info := registry.ServiceInfo{
		Name:     "test-plugin",
		Version:  "1.0.0",
		Endpoint: endpoint,
	}
	client := NewGRPCPluginClient(conn, info)

	assert.Equal(t, "test-plugin", client.Name())
}

// TestGRPCPluginClient_Version tests the Version method
func TestGRPCPluginClient_Version(t *testing.T) {
	mock := &mockPluginService{}
	_, endpoint, cleanup := setupTestPluginServer(t, mock)
	defer cleanup()

	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	info := registry.ServiceInfo{
		Name:     "test-plugin",
		Version:  "2.1.0",
		Endpoint: endpoint,
	}
	client := NewGRPCPluginClient(conn, info)

	assert.Equal(t, "2.1.0", client.Version())
}

// TestGRPCPluginClient_Initialize tests the Initialize method
func TestGRPCPluginClient_Initialize(t *testing.T) {
	tests := []struct {
		name        string
		config      plugin.PluginConfig
		mockFunc    func(context.Context, *proto.PluginInitializeRequest) (*proto.PluginInitializeResponse, error)
		expectError bool
		errorMsg    string
	}{
		{
			name: "successful initialization",
			config: plugin.PluginConfig{
				Name: "test-plugin",
				Settings: map[string]any{
					"key": "value",
				},
			},
			mockFunc: func(ctx context.Context, req *proto.PluginInitializeRequest) (*proto.PluginInitializeResponse, error) {
				// Verify config was marshaled correctly
				var cfg plugin.PluginConfig
				err := json.Unmarshal([]byte(req.ConfigJson), &cfg)
				assert.NoError(t, err)
				assert.Equal(t, "test-plugin", cfg.Name)
				return &proto.PluginInitializeResponse{}, nil
			},
			expectError: false,
		},
		{
			name: "initialization error from plugin",
			config: plugin.PluginConfig{
				Name: "test-plugin",
			},
			mockFunc: func(ctx context.Context, req *proto.PluginInitializeRequest) (*proto.PluginInitializeResponse, error) {
				return &proto.PluginInitializeResponse{
					Error: &proto.Error{
						Code:    "INIT_FAILED",
						Message: "initialization failed",
					},
				}, nil
			},
			expectError: true,
			errorMsg:    "INIT_FAILED: initialization failed",
		},
		{
			name: "RPC error",
			config: plugin.PluginConfig{
				Name: "test-plugin",
			},
			mockFunc: func(ctx context.Context, req *proto.PluginInitializeRequest) (*proto.PluginInitializeResponse, error) {
				return nil, status.Error(codes.Internal, "internal error")
			},
			expectError: true,
			errorMsg:    "plugin initialization failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockPluginService{
				initializeFunc: tt.mockFunc,
			}
			_, endpoint, cleanup := setupTestPluginServer(t, mock)
			defer cleanup()

			conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)
			defer conn.Close()

			info := registry.ServiceInfo{
				Name:     "test-plugin",
				Version:  "1.0.0",
				Endpoint: endpoint,
			}
			client := NewGRPCPluginClient(conn, info)

			err = client.Initialize(context.Background(), tt.config)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestGRPCPluginClient_Shutdown tests the Shutdown method
func TestGRPCPluginClient_Shutdown(t *testing.T) {
	tests := []struct {
		name        string
		mockFunc    func(context.Context, *proto.PluginShutdownRequest) (*proto.PluginShutdownResponse, error)
		expectError bool
		errorMsg    string
	}{
		{
			name: "successful shutdown",
			mockFunc: func(ctx context.Context, req *proto.PluginShutdownRequest) (*proto.PluginShutdownResponse, error) {
				return &proto.PluginShutdownResponse{}, nil
			},
			expectError: false,
		},
		{
			name: "shutdown error from plugin",
			mockFunc: func(ctx context.Context, req *proto.PluginShutdownRequest) (*proto.PluginShutdownResponse, error) {
				return &proto.PluginShutdownResponse{
					Error: &proto.Error{
						Code:    "SHUTDOWN_FAILED",
						Message: "failed to cleanup resources",
					},
				}, nil
			},
			expectError: true,
			errorMsg:    "SHUTDOWN_FAILED: failed to cleanup resources",
		},
		{
			name: "RPC error",
			mockFunc: func(ctx context.Context, req *proto.PluginShutdownRequest) (*proto.PluginShutdownResponse, error) {
				return nil, status.Error(codes.Unavailable, "service unavailable")
			},
			expectError: true,
			errorMsg:    "plugin shutdown failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockPluginService{
				shutdownFunc: tt.mockFunc,
			}
			_, endpoint, cleanup := setupTestPluginServer(t, mock)
			defer cleanup()

			conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)

			info := registry.ServiceInfo{
				Name:     "test-plugin",
				Version:  "1.0.0",
				Endpoint: endpoint,
			}
			client := NewGRPCPluginClient(conn, info)

			err = client.Shutdown(context.Background())

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestGRPCPluginClient_Methods tests the Methods method
func TestGRPCPluginClient_Methods(t *testing.T) {
	tests := []struct {
		name            string
		mockFunc        func(context.Context, *proto.PluginListMethodsRequest) (*proto.PluginListMethodsResponse, error)
		expectedMethods []string
	}{
		{
			name: "returns cached methods",
			mockFunc: func(ctx context.Context, req *proto.PluginListMethodsRequest) (*proto.PluginListMethodsResponse, error) {
				// Create schemas as JSON strings
				searchInputSchema, _ := json.Marshal(map[string]any{
					"type": "object",
					"properties": map[string]any{
						"query": map[string]any{"type": "string"},
					},
					"required": []string{"query"},
				})
				searchOutputSchema, _ := json.Marshal(map[string]any{
					"type": "array",
				})
				getInputSchema, _ := json.Marshal(map[string]any{
					"type": "object",
					"properties": map[string]any{
						"id": map[string]any{"type": "string"},
					},
					"required": []string{"id"},
				})
				getOutputSchema, _ := json.Marshal(map[string]any{
					"type": "object",
				})

				return &proto.PluginListMethodsResponse{
					Methods: []*proto.PluginMethodDescriptor{
						{
							Name:        "search",
							Description: "Search for items",
							InputSchema: &commonpb.JSONSchema{
								Json: string(searchInputSchema),
							},
							OutputSchema: &commonpb.JSONSchema{
								Json: string(searchOutputSchema),
							},
						},
						{
							Name:        "get",
							Description: "Get an item by ID",
							InputSchema: &commonpb.JSONSchema{
								Json: string(getInputSchema),
							},
							OutputSchema: &commonpb.JSONSchema{
								Json: string(getOutputSchema),
							},
						},
					},
				}, nil
			},
			expectedMethods: []string{"search", "get"},
		},
		{
			name: "handles empty methods",
			mockFunc: func(ctx context.Context, req *proto.PluginListMethodsRequest) (*proto.PluginListMethodsResponse, error) {
				return &proto.PluginListMethodsResponse{
					Methods: []*proto.PluginMethodDescriptor{},
				}, nil
			},
			expectedMethods: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockPluginService{
				listMethodsFunc: tt.mockFunc,
			}
			_, endpoint, cleanup := setupTestPluginServer(t, mock)
			defer cleanup()

			conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)
			defer conn.Close()

			info := registry.ServiceInfo{
				Name:     "test-plugin",
				Version:  "1.0.0",
				Endpoint: endpoint,
			}
			client := NewGRPCPluginClient(conn, info)

			methods := client.Methods()

			assert.Len(t, methods, len(tt.expectedMethods))
			for i, name := range tt.expectedMethods {
				assert.Equal(t, name, methods[i].Name)
			}

			// Verify methods are cached (second call should return same result)
			methods2 := client.Methods()
			assert.Equal(t, methods, methods2)
		})
	}
}

// TestGRPCPluginClient_Query tests the Query method
func TestGRPCPluginClient_Query(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		params         map[string]any
		mockListFunc   func(context.Context, *proto.PluginListMethodsRequest) (*proto.PluginListMethodsResponse, error)
		mockQueryFunc  func(context.Context, *proto.PluginQueryRequest) (*proto.PluginQueryResponse, error)
		expectedResult any
		expectError    bool
		errorMsg       string
	}{
		{
			name:   "successful query",
			method: "search",
			params: map[string]any{
				"query": "test",
			},
			mockListFunc: func(ctx context.Context, req *proto.PluginListMethodsRequest) (*proto.PluginListMethodsResponse, error) {
				return &proto.PluginListMethodsResponse{
					Methods: []*proto.PluginMethodDescriptor{
						{
							Name:        "search",
							Description: "Search for items",
						},
					},
				}, nil
			},
			mockQueryFunc: func(ctx context.Context, req *proto.PluginQueryRequest) (*proto.PluginQueryResponse, error) {
				assert.Equal(t, "search", req.Method)

				// Verify params were marshaled correctly
				var params map[string]any
				err := json.Unmarshal([]byte(req.ParamsJson), &params)
				assert.NoError(t, err)
				assert.Equal(t, "test", params["query"])

				// Return result
				result := map[string]any{
					"count": 5,
					"items": []string{"a", "b", "c"},
				}
				resultJSON, _ := json.Marshal(result)
				return &proto.PluginQueryResponse{
					ResultJson: string(resultJSON),
				}, nil
			},
			expectedResult: map[string]any{
				"count": float64(5), // JSON unmarshals numbers as float64
				"items": []any{"a", "b", "c"},
			},
			expectError: false,
		},
		{
			name:   "method not found",
			method: "nonexistent",
			params: map[string]any{},
			mockListFunc: func(ctx context.Context, req *proto.PluginListMethodsRequest) (*proto.PluginListMethodsResponse, error) {
				return &proto.PluginListMethodsResponse{
					Methods: []*proto.PluginMethodDescriptor{
						{Name: "search"},
					},
				}, nil
			},
			expectError: true,
			errorMsg:    "method 'nonexistent' not found",
		},
		{
			name:   "query error from plugin",
			method: "search",
			params: map[string]any{
				"query": "test",
			},
			mockListFunc: func(ctx context.Context, req *proto.PluginListMethodsRequest) (*proto.PluginListMethodsResponse, error) {
				return &proto.PluginListMethodsResponse{
					Methods: []*proto.PluginMethodDescriptor{
						{Name: "search"},
					},
				}, nil
			},
			mockQueryFunc: func(ctx context.Context, req *proto.PluginQueryRequest) (*proto.PluginQueryResponse, error) {
				return &proto.PluginQueryResponse{
					Error: &proto.Error{
						Code:    "QUERY_FAILED",
						Message: "query execution failed",
					},
				}, nil
			},
			expectError: true,
			errorMsg:    "QUERY_FAILED: query execution failed",
		},
		{
			name:   "RPC error",
			method: "search",
			params: map[string]any{},
			mockListFunc: func(ctx context.Context, req *proto.PluginListMethodsRequest) (*proto.PluginListMethodsResponse, error) {
				return &proto.PluginListMethodsResponse{
					Methods: []*proto.PluginMethodDescriptor{
						{Name: "search"},
					},
				}, nil
			},
			mockQueryFunc: func(ctx context.Context, req *proto.PluginQueryRequest) (*proto.PluginQueryResponse, error) {
				return nil, status.Error(codes.Internal, "internal error")
			},
			expectError: true,
			errorMsg:    "plugin query failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockPluginService{
				listMethodsFunc: tt.mockListFunc,
				queryFunc:       tt.mockQueryFunc,
			}
			_, endpoint, cleanup := setupTestPluginServer(t, mock)
			defer cleanup()

			conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)
			defer conn.Close()

			info := registry.ServiceInfo{
				Name:     "test-plugin",
				Version:  "1.0.0",
				Endpoint: endpoint,
			}
			client := NewGRPCPluginClient(conn, info)

			result, err := client.Query(context.Background(), tt.method, tt.params)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResult, result)
			}
		})
	}
}

// TestGRPCPluginClient_Health tests the Health method
func TestGRPCPluginClient_Health(t *testing.T) {
	tests := []struct {
		name          string
		mockFunc      func(context.Context, *proto.PluginHealthRequest) (*proto.HealthStatus, error)
		expectedState string
	}{
		{
			name: "healthy status",
			mockFunc: func(ctx context.Context, req *proto.PluginHealthRequest) (*proto.HealthStatus, error) {
				return &proto.HealthStatus{
					State:   "healthy",
					Message: "All systems operational",
				}, nil
			},
			expectedState: "healthy",
		},
		{
			name: "degraded status",
			mockFunc: func(ctx context.Context, req *proto.PluginHealthRequest) (*proto.HealthStatus, error) {
				return &proto.HealthStatus{
					State:   "degraded",
					Message: "Some issues detected",
				}, nil
			},
			expectedState: "degraded",
		},
		{
			name: "unhealthy status",
			mockFunc: func(ctx context.Context, req *proto.PluginHealthRequest) (*proto.HealthStatus, error) {
				return &proto.HealthStatus{
					State:   "unhealthy",
					Message: "Critical failure",
				}, nil
			},
			expectedState: "unhealthy",
		},
		{
			name: "RPC error",
			mockFunc: func(ctx context.Context, req *proto.PluginHealthRequest) (*proto.HealthStatus, error) {
				return nil, status.Error(codes.Unavailable, "service unavailable")
			},
			expectedState: "unhealthy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockPluginService{
				healthFunc: tt.mockFunc,
			}
			_, endpoint, cleanup := setupTestPluginServer(t, mock)
			defer cleanup()

			conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)
			defer conn.Close()

			info := registry.ServiceInfo{
				Name:     "test-plugin",
				Version:  "1.0.0",
				Endpoint: endpoint,
			}
			client := NewGRPCPluginClient(conn, info)

			health := client.Health(context.Background())

			assert.Equal(t, tt.expectedState, health.State.String())
		})
	}
}

// TestGRPCPluginClient_SchemaConversion tests schema conversion from proto to internal types
func TestGRPCPluginClient_SchemaConversion(t *testing.T) {
	mockListFunc := func(ctx context.Context, req *proto.PluginListMethodsRequest) (*proto.PluginListMethodsResponse, error) {
		// Create complex input schema as JSON
		inputSchema, _ := json.Marshal(map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name": map[string]any{
					"type":        "string",
					"description": "Name field",
					"minLength":   1,
					"maxLength":   255,
				},
				"age": map[string]any{
					"type":        "integer",
					"description": "Age field",
					"minimum":     0,
					"maximum":     100,
				},
				"status": map[string]any{
					"type":        "string",
					"description": "Status enum",
					"enum":        []string{"active", "inactive"},
				},
			},
			"required": []string{"name"},
		})

		outputSchema, _ := json.Marshal(map[string]any{
			"type": "object",
			"properties": map[string]any{
				"success": map[string]any{"type": "boolean"},
			},
		})

		return &proto.PluginListMethodsResponse{
			Methods: []*proto.PluginMethodDescriptor{
				{
					Name:        "complex_method",
					Description: "A method with complex schemas",
					InputSchema: &commonpb.JSONSchema{
						Json: string(inputSchema),
					},
					OutputSchema: &commonpb.JSONSchema{
						Json: string(outputSchema),
					},
				},
			},
		}, nil
	}

	mock := &mockPluginService{
		listMethodsFunc: mockListFunc,
	}
	_, endpoint, cleanup := setupTestPluginServer(t, mock)
	defer cleanup()

	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	info := registry.ServiceInfo{
		Name:     "test-plugin",
		Version:  "1.0.0",
		Endpoint: endpoint,
	}
	client := NewGRPCPluginClient(conn, info)

	methods := client.Methods()
	require.Len(t, methods, 1)

	method := methods[0]
	assert.Equal(t, "complex_method", method.Name)
	assert.Equal(t, "A method with complex schemas", method.Description)

	// Verify input schema conversion
	assert.Equal(t, "object", method.InputSchema.Type)
	assert.Len(t, method.InputSchema.Properties, 3)
	assert.Contains(t, method.InputSchema.Required, "name")

	// Check name field
	nameField := method.InputSchema.Properties["name"]
	assert.Equal(t, "string", nameField.Type)
	assert.Equal(t, "Name field", nameField.Description)
	assert.NotNil(t, nameField.MinLength)
	assert.Equal(t, 1, *nameField.MinLength)
	assert.NotNil(t, nameField.MaxLength)
	assert.Equal(t, 255, *nameField.MaxLength)

	// Check age field
	ageField := method.InputSchema.Properties["age"]
	assert.Equal(t, "integer", ageField.Type)
	assert.NotNil(t, ageField.Minimum)
	assert.Equal(t, 0.0, *ageField.Minimum)
	assert.NotNil(t, ageField.Maximum)
	assert.Equal(t, 100.0, *ageField.Maximum)

	// Check status field
	statusField := method.InputSchema.Properties["status"]
	assert.Equal(t, "string", statusField.Type)
	assert.Equal(t, []string{"active", "inactive"}, statusField.Enum)

	// Verify output schema
	assert.Equal(t, "object", method.OutputSchema.Type)
	assert.Len(t, method.OutputSchema.Properties, 1)
	successField := method.OutputSchema.Properties["success"]
	assert.Equal(t, "boolean", successField.Type)
}

// TestConvertJSONSchema tests the convertJSONSchema helper function
func TestConvertJSONSchema(t *testing.T) {
	t.Run("nil schema", func(t *testing.T) {
		result := convertJSONSchema(nil)
		assert.Equal(t, schema.JSONSchema{}, result)
	})

	t.Run("empty schema", func(t *testing.T) {
		result := convertJSONSchema(&commonpb.JSONSchema{})
		assert.Equal(t, schema.JSONSchema{}, result)
	})

	t.Run("valid JSON schema", func(t *testing.T) {
		schemaJSON, _ := json.Marshal(map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name": map[string]any{
					"type": "string",
				},
			},
			"required": []string{"name"},
		})

		protoSchema := &commonpb.JSONSchema{
			Json: string(schemaJSON),
		}

		result := convertJSONSchema(protoSchema)
		assert.Equal(t, "object", result.Type)
		assert.Len(t, result.Properties, 1)
		assert.Contains(t, result.Required, "name")
	})

	t.Run("invalid JSON returns empty schema", func(t *testing.T) {
		protoSchema := &commonpb.JSONSchema{
			Json: "invalid-json",
		}

		result := convertJSONSchema(protoSchema)
		assert.Equal(t, schema.JSONSchema{}, result)
	})
}
