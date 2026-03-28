//go:build integration
// +build integration

package extraction

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/sdk/api/gen/graphragpb"
)

// TestExtraction_EndToEnd_NmapToRelationships tests the full extraction pipeline
// from nmap proto response through relationship building.
func TestExtraction_EndToEnd_NmapToRelationships(t *testing.T) {
	ctx := context.Background()

	// Create registry and register extractors
	registry := NewExtractorRegistry()
	require.NoError(t, registry.Register(NewNmapExtractor()))

	// Create a sample nmap response with multiple hosts and ports
	nmapResponse := createSampleNmapResponse()

	// Extract entities
	result, err := registry.ExtractFromResponse(ctx, "nmap", nmapResponse)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Discovery)

	// Verify extracted entities
	discovery := result.Discovery
	assert.Len(t, discovery.Hosts, 2, "should extract 2 hosts")
	assert.True(t, len(discovery.Ports) >= 3, "should extract at least 3 ports")
	assert.True(t, len(discovery.Services) >= 2, "should extract at least 2 services")

	// Build relationships
	builder := NewRelationshipBuilder(time.Now())
	relationships := builder.BuildRelationships(discovery)

	// Verify relationships
	assert.NotEmpty(t, relationships, "should build relationships")

	// Check for HAS_PORT relationships
	hasPortCount := 0
	for _, rel := range relationships {
		if rel.Type == "HAS_PORT" {
			hasPortCount++
		}
	}
	assert.True(t, hasPortCount >= 3, "should have at least 3 HAS_PORT relationships")

	// Check for RUNS_SERVICE relationships
	runsServiceCount := 0
	for _, rel := range relationships {
		if rel.Type == "RUNS_SERVICE" {
			runsServiceCount++
		}
	}
	assert.True(t, runsServiceCount >= 2, "should have at least 2 RUNS_SERVICE relationships")
}

// TestExtraction_EndToEnd_HttpxToRelationships tests httpx extraction pipeline.
func TestExtraction_EndToEnd_HttpxToRelationships(t *testing.T) {
	ctx := context.Background()

	// Create registry and register extractors
	registry := NewExtractorRegistry()
	require.NoError(t, registry.Register(NewHttpxExtractor()))

	// Create a sample httpx response
	httpxResponse := createSampleHttpxResponse()

	// Extract entities
	result, err := registry.ExtractFromResponse(ctx, "httpx", httpxResponse)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Discovery)

	// Verify extracted entities
	discovery := result.Discovery
	assert.NotEmpty(t, discovery.Endpoints, "should extract endpoints")

	// Build relationships
	builder := NewRelationshipBuilder(time.Now())
	relationships := builder.BuildRelationships(discovery)

	// If we have endpoints and technologies, verify USES_TECHNOLOGY relationships
	if len(discovery.Technologies) > 0 {
		usesTechCount := 0
		for _, rel := range relationships {
			if rel.Type == "USES_TECHNOLOGY" {
				usesTechCount++
			}
		}
		assert.True(t, usesTechCount > 0, "should have USES_TECHNOLOGY relationships")
	}
}

// TestExtraction_EndToEnd_NucleiToRelationships tests nuclei extraction pipeline.
func TestExtraction_EndToEnd_NucleiToRelationships(t *testing.T) {
	ctx := context.Background()

	// Create registry and register extractors
	registry := NewExtractorRegistry()
	require.NoError(t, registry.Register(NewNucleiExtractor()))

	// Create a sample nuclei response
	nucleiResponse := createSampleNucleiResponse()

	// Extract entities
	result, err := registry.ExtractFromResponse(ctx, "nuclei", nucleiResponse)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Discovery)

	// Verify extracted entities
	discovery := result.Discovery
	assert.NotEmpty(t, discovery.Findings, "should extract findings")

	// Build relationships
	builder := NewRelationshipBuilder(time.Now())
	relationships := builder.BuildRelationships(discovery)

	// Verify AFFECTS relationships for findings
	if len(discovery.Findings) > 0 {
		affectsCount := 0
		for _, rel := range relationships {
			if rel.Type == "AFFECTS" {
				affectsCount++
			}
		}
		assert.True(t, affectsCount > 0, "should have AFFECTS relationships for findings")
	}
}

// TestExtraction_Deduplication tests that multiple extractions don't create duplicates.
func TestExtraction_Deduplication(t *testing.T) {
	ctx := context.Background()

	registry := NewExtractorRegistry()
	require.NoError(t, registry.Register(NewNmapExtractor()))

	// Extract the same data twice
	nmapResponse := createSampleNmapResponse()

	result1, err := registry.ExtractFromResponse(ctx, "nmap", nmapResponse)
	require.NoError(t, err)

	result2, err := registry.ExtractFromResponse(ctx, "nmap", nmapResponse)
	require.NoError(t, err)

	// Both extractions should produce the same entity counts
	assert.Equal(t, len(result1.Discovery.Hosts), len(result2.Discovery.Hosts))
	assert.Equal(t, len(result1.Discovery.Ports), len(result2.Discovery.Ports))
	assert.Equal(t, len(result1.Discovery.Services), len(result2.Discovery.Services))

	// Entity IDs should be deterministic
	if len(result1.Discovery.Hosts) > 0 && len(result2.Discovery.Hosts) > 0 {
		// IDs are generated deterministically, so they should match
		assert.Equal(t, result1.Discovery.Hosts[0].Id, result2.Discovery.Hosts[0].Id)
	}
}

// TestExtraction_AllExtractors_Registry tests registry with all extractors.
func TestExtraction_AllExtractors_Registry(t *testing.T) {
	registry := NewExtractorRegistry()

	// Register all extractors
	require.NoError(t, registry.Register(NewNmapExtractor()))
	require.NoError(t, registry.Register(NewHttpxExtractor()))
	require.NoError(t, registry.Register(NewNucleiExtractor()))

	// Verify all are registered
	assert.True(t, registry.Has("nmap"))
	assert.True(t, registry.Has("httpx"))
	assert.True(t, registry.Has("nuclei"))

	// List should return all
	tools := registry.ListTools()
	assert.Len(t, tools, 3)
}

// TestExtraction_RelationshipProvenance tests that provenance is correctly attached.
func TestExtraction_RelationshipProvenance(t *testing.T) {
	discoveredAt := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)

	builder := NewRelationshipBuilder(discoveredAt)

	discovery := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Ip: "192.168.1.1"},
		},
		Ports: []*graphragpb.Port{
			{HostId: "192.168.1.1", Number: 22, Protocol: "tcp"},
		},
	}

	relationships := builder.BuildRelationships(discovery)
	require.NotEmpty(t, relationships)

	// Check that provenance fields are set
	for _, rel := range relationships {
		assert.NotNil(t, rel.Properties)
		assert.Contains(t, rel.Properties, "discovered_at")
	}
}

// Helper functions to create sample responses

func createSampleNmapResponse() *graphragpb.DiscoveryResult {
	// Create a DiscoveryResult directly since extractors work with this
	return &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Ip: "192.168.1.1", Hostname: ptrStr("host1.example.com")},
			{Ip: "192.168.1.2", Hostname: ptrStr("host2.example.com")},
		},
		Ports: []*graphragpb.Port{
			{HostId: "192.168.1.1", Number: 22, Protocol: "tcp", State: ptrStr("open")},
			{HostId: "192.168.1.1", Number: 80, Protocol: "tcp", State: ptrStr("open")},
			{HostId: "192.168.1.2", Number: 443, Protocol: "tcp", State: ptrStr("open")},
		},
		Services: []*graphragpb.Service{
			{PortId: "192.168.1.1:22:tcp", Name: "ssh", Version: ptrStr("OpenSSH 8.0")},
			{PortId: "192.168.1.1:80:tcp", Name: "http", Version: ptrStr("nginx 1.18")},
			{PortId: "192.168.1.2:443:tcp", Name: "https"},
		},
	}
}

func createSampleHttpxResponse() *graphragpb.DiscoveryResult {
	parentType := "service"
	portID := "192.168.1.1:80:tcp"

	return &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Ip: "192.168.1.1"},
		},
		Ports: []*graphragpb.Port{
			{HostId: "192.168.1.1", Number: 80, Protocol: "tcp"},
		},
		Services: []*graphragpb.Service{
			{PortId: portID, Name: "http"},
		},
		Endpoints: []*graphragpb.Endpoint{
			{
				ServiceId:  &portID,
				Url:        "http://192.168.1.1/",
				Method:     ptrStr("GET"),
				StatusCode: ptrInt32(200),
			},
		},
		Technologies: []*graphragpb.Technology{
			{ParentId: &portID, ParentType: &parentType, Name: "nginx"},
			{ParentId: &portID, ParentType: &parentType, Name: "PHP"},
		},
	}
}

func createSampleNucleiResponse() *graphragpb.DiscoveryResult {
	return &graphragpb.DiscoveryResult{
		Findings: []*graphragpb.Finding{
			{
				Title:      ptrStr("SQL Injection Vulnerability"),
				Severity:   ptrStr("high"),
				TemplateId: ptrStr("sqli-detection"),
				TargetUrl:  ptrStr("http://example.com/login"),
			},
			{
				Title:      ptrStr("Missing Security Headers"),
				Severity:   ptrStr("info"),
				TemplateId: ptrStr("security-headers"),
				TargetUrl:  ptrStr("http://example.com/"),
			},
		},
		Evidence: []*graphragpb.Evidence{
			{
				FindingId:   ptrStr("finding-1"),
				Type:        ptrStr("request"),
				Description: ptrStr("HTTP request showing SQL injection"),
			},
		},
	}
}

func ptrInt32(i int32) *int32 {
	return &i
}
