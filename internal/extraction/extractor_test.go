package extraction

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/sdk/api/gen/graphragpb"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

// mockExtractor is a mock implementation of EntityExtractor for testing
type mockExtractor struct {
	toolName      string
	canExtract    bool
	extractErr    error
	extractResult *ExtractionResult
}

func (m *mockExtractor) ToolName() string {
	return m.toolName
}

func (m *mockExtractor) CanExtract(msg proto.Message) bool {
	return m.canExtract
}

func (m *mockExtractor) Extract(ctx context.Context, msg proto.Message) (*ExtractionResult, error) {
	if m.extractErr != nil {
		return nil, m.extractErr
	}
	return m.extractResult, nil
}

// TestNewExtractorRegistry tests the creation of a new registry
func TestNewExtractorRegistry(t *testing.T) {
	registry := NewExtractorRegistry()
	require.NotNil(t, registry)
	assert.Empty(t, registry.ListTools())
}

// TestRegister tests registering extractors
func TestRegister(t *testing.T) {
	tests := []struct {
		name          string
		extractor     EntityExtractor
		expectError   bool
		errorContains string
	}{
		{
			name: "valid extractor",
			extractor: &mockExtractor{
				toolName:   "test-tool",
				canExtract: true,
			},
			expectError: false,
		},
		{
			name:          "nil extractor",
			extractor:     nil,
			expectError:   true,
			errorContains: "extractor cannot be nil",
		},
		{
			name: "empty tool name",
			extractor: &mockExtractor{
				toolName: "",
			},
			expectError:   true,
			errorContains: "tool name cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := NewExtractorRegistry()
			err := registry.Register(tt.extractor)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestRegisterDuplicate tests registering duplicate extractors
func TestRegisterDuplicate(t *testing.T) {
	registry := NewExtractorRegistry()

	extractor1 := &mockExtractor{toolName: "nmap"}
	extractor2 := &mockExtractor{toolName: "nmap"}

	// First registration should succeed
	err := registry.Register(extractor1)
	require.NoError(t, err)

	// Second registration with same tool name should fail
	err = registry.Register(extractor2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")
}

// TestGet tests retrieving extractors
func TestGet(t *testing.T) {
	registry := NewExtractorRegistry()

	extractor := &mockExtractor{toolName: "nmap"}
	err := registry.Register(extractor)
	require.NoError(t, err)

	t.Run("existing extractor", func(t *testing.T) {
		retrieved, err := registry.Get("nmap")
		require.NoError(t, err)
		assert.Equal(t, extractor, retrieved)
	})

	t.Run("non-existent extractor", func(t *testing.T) {
		_, err := registry.Get("non-existent")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no extractor registered")
	})
}

// TestHas tests checking for extractor existence
func TestHas(t *testing.T) {
	registry := NewExtractorRegistry()

	extractor := &mockExtractor{toolName: "nmap"}
	err := registry.Register(extractor)
	require.NoError(t, err)

	assert.True(t, registry.Has("nmap"))
	assert.False(t, registry.Has("non-existent"))
}

// TestUnregister tests removing extractors
func TestUnregister(t *testing.T) {
	registry := NewExtractorRegistry()

	extractor := &mockExtractor{toolName: "nmap"}
	err := registry.Register(extractor)
	require.NoError(t, err)

	t.Run("existing extractor", func(t *testing.T) {
		err := registry.Unregister("nmap")
		require.NoError(t, err)
		assert.False(t, registry.Has("nmap"))
	})

	t.Run("non-existent extractor", func(t *testing.T) {
		err := registry.Unregister("non-existent")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no extractor registered")
	})
}

// TestListTools tests listing registered tools
func TestListTools(t *testing.T) {
	registry := NewExtractorRegistry()

	// Empty registry
	tools := registry.ListTools()
	assert.Empty(t, tools)

	// Register some extractors
	err := registry.Register(&mockExtractor{toolName: "nmap"})
	require.NoError(t, err)

	err = registry.Register(&mockExtractor{toolName: "nuclei"})
	require.NoError(t, err)

	err = registry.Register(&mockExtractor{toolName: "httpx"})
	require.NoError(t, err)

	// List tools
	tools = registry.ListTools()
	assert.Len(t, tools, 3)
	assert.Contains(t, tools, "nmap")
	assert.Contains(t, tools, "nuclei")
	assert.Contains(t, tools, "httpx")
}

// TestExtractFromResponse tests the full extraction flow
func TestExtractFromResponse(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		toolName       string
		msg            proto.Message
		extractor      *mockExtractor
		expectError    bool
		errorContains  string
		validateResult func(t *testing.T, result *ExtractionResult)
	}{
		{
			name:     "successful extraction",
			toolName: "nmap",
			msg:      &emptypb.Empty{},
			extractor: &mockExtractor{
				toolName:   "nmap",
				canExtract: true,
				extractResult: &ExtractionResult{
					Discovery: &graphragpb.DiscoveryResult{
						Hosts: []*graphragpb.Host{
							{Ip: "192.168.1.1"},
						},
					},
					RootEntityID: "host-1",
				},
			},
			expectError: false,
			validateResult: func(t *testing.T, result *ExtractionResult) {
				require.NotNil(t, result)
				require.NotNil(t, result.Discovery)
				assert.Len(t, result.Discovery.Hosts, 1)
				assert.Equal(t, "192.168.1.1", result.Discovery.Hosts[0].Ip)
				assert.Equal(t, "host-1", result.RootEntityID)
			},
		},
		{
			name:     "extractor not registered",
			toolName: "unknown",
			msg:      &emptypb.Empty{},
			extractor: &mockExtractor{
				toolName: "nmap",
			},
			expectError:   true,
			errorContains: "no extractor registered",
		},
		{
			name:     "extractor cannot process message type",
			toolName: "nmap",
			msg:      &emptypb.Empty{},
			extractor: &mockExtractor{
				toolName:   "nmap",
				canExtract: false,
			},
			expectError:   true,
			errorContains: "cannot process message type",
		},
		{
			name:     "extraction fails",
			toolName: "nmap",
			msg:      &emptypb.Empty{},
			extractor: &mockExtractor{
				toolName:   "nmap",
				canExtract: true,
				extractErr: assert.AnError,
			},
			expectError:   true,
			errorContains: "extraction failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := NewExtractorRegistry()

			// Register the extractor
			err := registry.Register(tt.extractor)
			require.NoError(t, err)

			// Perform extraction
			result, err := registry.ExtractFromResponse(ctx, tt.toolName, tt.msg)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
				if tt.validateResult != nil {
					tt.validateResult(t, result)
				}
			}
		})
	}
}

// TestConcurrentRegistration tests thread-safety of concurrent registration
func TestConcurrentRegistration(t *testing.T) {
	registry := NewExtractorRegistry()

	const numGoroutines = 100
	done := make(chan bool, numGoroutines)

	// Concurrently register different extractors
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			extractor := &mockExtractor{
				toolName: fmt.Sprintf("tool-%d", id),
			}
			err := registry.Register(extractor)
			assert.NoError(t, err)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify all extractors were registered
	tools := registry.ListTools()
	assert.Len(t, tools, numGoroutines)
}

// TestConcurrentExtraction tests thread-safety of concurrent extraction
func TestConcurrentExtraction(t *testing.T) {
	registry := NewExtractorRegistry()
	ctx := context.Background()

	// Register a test extractor
	extractor := &mockExtractor{
		toolName:   "nmap",
		canExtract: true,
		extractResult: &ExtractionResult{
			Discovery: &graphragpb.DiscoveryResult{
				Hosts: []*graphragpb.Host{{Ip: "192.168.1.1"}},
			},
		},
	}
	err := registry.Register(extractor)
	require.NoError(t, err)

	const numGoroutines = 100
	done := make(chan bool, numGoroutines)

	// Concurrently extract from the same tool
	for i := 0; i < numGoroutines; i++ {
		go func() {
			result, err := registry.ExtractFromResponse(ctx, "nmap", &emptypb.Empty{})
			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.NotNil(t, result.Discovery)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

// TestExtractionResultMetadata tests extraction result metadata handling
func TestExtractionResultMetadata(t *testing.T) {
	ctx := context.Background()
	registry := NewExtractorRegistry()

	extractor := &mockExtractor{
		toolName:   "nmap",
		canExtract: true,
		extractResult: &ExtractionResult{
			Discovery: &graphragpb.DiscoveryResult{
				Hosts: []*graphragpb.Host{{Ip: "192.168.1.1"}},
			},
			RootEntityID: "host-1",
			Metadata: map[string]string{
				"tool_version":    "7.80",
				"extraction_time": "2024-01-01T00:00:00Z",
				"scan_type":       "full",
			},
		},
	}

	err := registry.Register(extractor)
	require.NoError(t, err)

	result, err := registry.ExtractFromResponse(ctx, "nmap", &emptypb.Empty{})
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "host-1", result.RootEntityID)
	assert.NotNil(t, result.Metadata)
	assert.Equal(t, "7.80", result.Metadata["tool_version"])
	assert.Equal(t, "2024-01-01T00:00:00Z", result.Metadata["extraction_time"])
	assert.Equal(t, "full", result.Metadata["scan_type"])
}
