// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
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

// Which tools are discovery tools comes from the CATALOG now, so the test asks
// the catalog rather than restating a list.
//
// The test this replaces asserted that amass, ffuf, gobuster and katana ARE
// discovery tools. The executor ships none of them, so those four cases were
// asserting the drift rather than catching it — and the same test said nothing
// about naabu, tlsx, trivy, kube-bench or trivy-k8s, which it does ship.
func TestIsDiscoveryTool_ComesFromTheCatalog(t *testing.T) {
	v := NewToolValidator(slog.Default())

	tools := 0
	for _, ref := range componentcatalog.Refs() {
		if ref.Kind != authz.KindTool {
			continue
		}
		tools++
		entry, ok := componentcatalog.LookupTool(ref.ID)
		require.True(t, ok, "the catalog lists tool %q but cannot resolve it", ref.ID)
		want := entry.OutputProtoType == componentcatalog.DiscoveryResultProtoType
		assert.Equal(t, want, v.isDiscoveryTool(ref.ID),
			"tool %q emits %q", ref.ID, entry.OutputProtoType)
	}
	require.NotZero(t, tools, "the catalog lists no tools; this test would pass on anything")
}

// A tool the catalog does not list is not a discovery tool. Same answer the old
// map gave for a name it did not hold, and the safe direction: a tool the
// catalog does not list cannot be dispatched at all.
func TestIsDiscoveryTool_AnUnknownToolIsNotOne(t *testing.T) {
	v := NewToolValidator(slog.Default())
	for _, name := range []string{"unknown_tool", "curl", "jq", "amass", "ffuf", "gobuster", "katana"} {
		assert.False(t, v.isDiscoveryTool(name), "tool %q", name)
	}
}

// Every tool the executor ships today emits a DiscoveryResult, so the catalog
// answer is "yes" for all of them. Asserted so the day one does not, this test
// says so rather than the classification quietly changing.
func TestIsDiscoveryTool_EveryShippedToolEmitsADiscoveryResult(t *testing.T) {
	v := NewToolValidator(slog.Default())
	for _, ref := range componentcatalog.Refs() {
		if ref.Kind != authz.KindTool {
			continue
		}
		assert.True(t, v.isDiscoveryTool(ref.ID),
			"tool %q no longer emits a DiscoveryResult; update this test and check the dispatch path still reports it", ref.ID)
	}
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
