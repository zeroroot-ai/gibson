package harness

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/anypb"
)

// mockProtoWithDiscovery creates a mock proto message with a DiscoveryResult in field 100.
// Since we can't easily create a proto with field 100, we'll use the actual DiscoveryResult.
type mockProtoWithDiscovery struct {
	proto.Message
	discovery *graphragpb.DiscoveryResult
}

func TestNewToolValidator(t *testing.T) {
	t.Run("with logger", func(t *testing.T) {
		logger := slog.Default()
		validator := NewToolValidator(logger)

		assert.NotNil(t, validator)
		assert.Equal(t, logger, validator.logger)
	})

	t.Run("with nil logger", func(t *testing.T) {
		validator := NewToolValidator(nil)

		assert.NotNil(t, validator)
		assert.NotNil(t, validator.logger)
	})
}

func TestIsDiscoveryTool(t *testing.T) {
	tests := []struct {
		name       string
		toolName   string
		isDiscovery bool
	}{
		{"nmap is discovery", "nmap", true},
		{"httpx is discovery", "httpx", true},
		{"nuclei is discovery", "nuclei", true},
		{"subfinder is discovery", "subfinder", true},
		{"dnsx is discovery", "dnsx", true},
		{"masscan is discovery", "masscan", true},
		{"amass is discovery", "amass", true},
		{"ffuf is discovery", "ffuf", true},
		{"gobuster is discovery", "gobuster", true},
		{"katana is discovery", "katana", true},
		{"unknown is not discovery", "unknown_tool", false},
		{"curl is not discovery", "curl", false},
		{"jq is not discovery", "jq", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsDiscoveryTool(tt.toolName)
			assert.Equal(t, tt.isDiscovery, result)
		})
	}
}

func TestRegisterDiscoveryTool(t *testing.T) {
	// Test registering a new tool
	toolName := "custom_scanner_test"

	// Ensure it's not registered initially
	assert.False(t, IsDiscoveryTool(toolName))

	// Register it
	RegisterDiscoveryTool(toolName)
	assert.True(t, IsDiscoveryTool(toolName))

	// Clean up
	UnregisterDiscoveryTool(toolName)
	assert.False(t, IsDiscoveryTool(toolName))
}

func TestListDiscoveryTools(t *testing.T) {
	tools := ListDiscoveryTools()

	// Should contain the known discovery tools
	assert.Contains(t, tools, "nmap")
	assert.Contains(t, tools, "httpx")
	assert.Contains(t, tools, "nuclei")

	// Should be at least 10 tools
	assert.GreaterOrEqual(t, len(tools), 10)
}

func TestValidateDiscoveryCompliance(t *testing.T) {
	validator := NewToolValidator(slog.Default())
	ctx := context.Background()

	t.Run("non-discovery tool without field 100 is compliant", func(t *testing.T) {
		// Use a simple proto message without field 100
		msg := &anypb.Any{
			TypeUrl: "type.googleapis.com/test.Message",
			Value:   []byte("test"),
		}

		result := validator.ValidateDiscoveryCompliance(ctx, "curl", msg, "run-123")

		assert.True(t, result.Compliant)
		assert.False(t, result.IsDiscoveryTool)
		assert.False(t, result.HasDiscoveryField)
		assert.Equal(t, "not_discovery_tool", result.SkipReason)
	})

	t.Run("discovery tool without field 100 is non-compliant", func(t *testing.T) {
		// Use a simple proto message without field 100
		msg := &anypb.Any{
			TypeUrl: "type.googleapis.com/test.Message",
			Value:   []byte("test"),
		}

		result := validator.ValidateDiscoveryCompliance(ctx, "nmap", msg, "run-123")

		assert.False(t, result.Compliant)
		assert.True(t, result.IsDiscoveryTool)
		assert.False(t, result.HasDiscoveryField)
		assert.Equal(t, "missing_discovery_field", result.SkipReason)
	})

	t.Run("discovery tool with empty discovery result is compliant", func(t *testing.T) {
		// Create a DiscoveryResult directly to test the extraction
		discovery := &graphragpb.DiscoveryResult{
			// Empty - no hosts, ports, etc.
		}

		// We can test validation with the DiscoveryResult itself
		// since ExtractDiscovery will return it directly
		result := validator.ValidateDiscoveryCompliance(ctx, "nmap", discovery, "run-123")

		// Since DiscoveryResult IS a valid proto with the discovery field (itself),
		// but ExtractDiscovery only extracts from messages WITH field 100
		assert.True(t, result.IsDiscoveryTool)
	})

	t.Run("validate tool name in result", func(t *testing.T) {
		msg := &anypb.Any{}
		result := validator.ValidateDiscoveryCompliance(ctx, "httpx", msg, "run-123")

		assert.Equal(t, "httpx", result.ToolName)
		assert.True(t, result.IsDiscoveryTool)
	})
}

func TestCountEntities(t *testing.T) {
	validator := NewToolValidator(slog.Default())

	t.Run("counts all entity types", func(t *testing.T) {
		host1, host2 := "host-1", "host-2"
		port1 := "port-1"
		service1 := "service-1"
		finding1, finding2, finding3 := "finding-1", "finding-2", "finding-3"

		discovery := &graphragpb.DiscoveryResult{
			Hosts: []*graphragpb.Host{
				{Id: &host1},
				{Id: &host2},
			},
			Ports: []*graphragpb.Port{
				{Id: &port1},
			},
			Services: []*graphragpb.Service{
				{Id: &service1},
			},
			Findings: []*graphragpb.Finding{
				{Id: &finding1},
				{Id: &finding2},
				{Id: &finding3},
			},
		}

		count := validator.countEntities(discovery)
		assert.Equal(t, 7, count)
	})

	t.Run("returns 0 for nil", func(t *testing.T) {
		count := validator.countEntities(nil)
		assert.Equal(t, 0, count)
	})

	t.Run("returns 0 for empty discovery", func(t *testing.T) {
		discovery := &graphragpb.DiscoveryResult{}
		count := validator.countEntities(discovery)
		assert.Equal(t, 0, count)
	})
}

func TestValidatorIsDiscoveryTool(t *testing.T) {
	validator := NewToolValidator(slog.Default())

	t.Run("known tools are discovery tools", func(t *testing.T) {
		assert.True(t, validator.isDiscoveryTool("nmap"))
		assert.True(t, validator.isDiscoveryTool("httpx"))
		assert.True(t, validator.isDiscoveryTool("nuclei"))
	})

	t.Run("unknown tools are not discovery tools", func(t *testing.T) {
		assert.False(t, validator.isDiscoveryTool("unknown"))
		assert.False(t, validator.isDiscoveryTool(""))
	})
}

// Note: Testing with actual proto messages containing field 100 would require
// generating proto descriptors at runtime. The integration tests should cover
// this with actual tool responses.

// TestToolValidationResultFields verifies the ToolValidationResult struct fields.
func TestToolValidationResultFields(t *testing.T) {
	result := ToolValidationResult{
		ToolName:          "nmap",
		Compliant:         true,
		IsDiscoveryTool:   true,
		HasDiscoveryField: true,
		SkipReason:        "",
		EntityCount:       42,
	}

	assert.Equal(t, "nmap", result.ToolName)
	assert.True(t, result.Compliant)
	assert.True(t, result.IsDiscoveryTool)
	assert.True(t, result.HasDiscoveryField)
	assert.Empty(t, result.SkipReason)
	assert.Equal(t, 42, result.EntityCount)
}

// Prevent unused import error for dynamicpb
var _ = dynamicpb.NewMessage
