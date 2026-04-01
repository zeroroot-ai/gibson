package extraction

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
	"github.com/zero-day-ai/sdk/api/gen/toolspb"
)

func TestNucleiExtractor_ToolName(t *testing.T) {
	extractor := NewNucleiExtractor()
	assert.Equal(t, "nuclei", extractor.ToolName())
}

func TestNucleiExtractor_CanExtract(t *testing.T) {
	extractor := NewNucleiExtractor()

	t.Run("valid NucleiResponse", func(t *testing.T) {
		result := extractor.CanExtract(&toolspb.NucleiResponse{})
		assert.True(t, result)
	})

	t.Run("invalid type", func(t *testing.T) {
		result := extractor.CanExtract(&graphragpb.DiscoveryResult{})
		assert.False(t, result)
	})
}

func TestNucleiExtractor_Extract_EmptyResults(t *testing.T) {
	extractor := NewNucleiExtractor()
	ctx := context.Background()

	resp := &toolspb.NucleiResponse{
		Results:           []*toolspb.TemplateMatch{},
		TotalRequests:     10,
		TotalMatches:      0,
		Duration:          1.5,
		TemplatesLoaded:   100,
		TemplatesExecuted: 50,
	}

	result, err := extractor.Extract(ctx, resp)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result.Discovery)

	// Should have empty entities
	assert.Empty(t, result.Discovery.Findings)
	assert.Empty(t, result.Discovery.Evidence)
	assert.Empty(t, result.Discovery.Endpoints)

	// Should have metadata
	assert.Equal(t, "no_matches_found", result.Metadata["status"])
	assert.Equal(t, "10", result.Metadata["total_requests"])
	assert.Equal(t, "0", result.Metadata["total_matches"])
	assert.Equal(t, "100", result.Metadata["templates_loaded"])
	assert.Equal(t, "50", result.Metadata["templates_executed"])
}

func TestNucleiExtractor_Extract_SingleFinding(t *testing.T) {
	extractor := NewNucleiExtractor()
	ctx := context.Background()

	resp := &toolspb.NucleiResponse{
		Results: []*toolspb.TemplateMatch{
			{
				TemplateId:   "CVE-2021-12345",
				TemplateName: "Test Vulnerability",
				Type:         "http",
				Host:         "example.com",
				Url:          "https://example.com/admin",
				MatchedAt:    "https://example.com/admin",
				MatcherName:  "status-code",
				ExtractedResults: []string{
					"admin panel exposed",
					"version 1.2.3",
				},
				Info: &toolspb.TemplateInfo{
					Name:        "Admin Panel Exposure",
					Author:      "security-team",
					Severity:    "high",
					Description: "Admin panel is publicly accessible",
					Reference:   []string{"https://example.com/advisory"},
					Tags:        []string{"admin", "exposure", "misconfig"},
					Classification: &toolspb.TemplateClassification{
						CveId:       []string{"CVE-2021-12345"},
						CweId:       []string{"CWE-200"},
						CvssMetrics: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
						CvssScore:   7.5,
					},
					Remediation: "Restrict access to admin panel",
				},
			},
		},
		TotalRequests:     100,
		TotalMatches:      1,
		Duration:          5.2,
		TemplatesLoaded:   200,
		TemplatesExecuted: 150,
	}

	result, err := extractor.Extract(ctx, resp)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result.Discovery)

	// Verify findings
	require.Len(t, result.Discovery.Findings, 1)
	finding := result.Discovery.Findings[0]
	assert.NotNil(t, finding.Id)
	assert.Equal(t, "Admin Panel Exposure", finding.Title)
	assert.Equal(t, "high", finding.Severity)
	assert.NotNil(t, finding.Description)
	assert.Equal(t, "Admin panel is publicly accessible", *finding.Description)
	assert.NotNil(t, finding.Remediation)
	assert.Equal(t, "Restrict access to admin panel", *finding.Remediation)
	assert.NotNil(t, finding.Category)
	assert.Equal(t, "admin,exposure,misconfig", *finding.Category)
	assert.NotNil(t, finding.CveIds)
	assert.Equal(t, "CVE-2021-12345", *finding.CveIds)
	assert.NotNil(t, finding.CvssScore)
	assert.Equal(t, 7.5, *finding.CvssScore)
	assert.NotNil(t, finding.Confidence)
	assert.Equal(t, 1.0, *finding.Confidence)

	// Verify finding is linked to endpoint
	assert.NotNil(t, finding.ParentId)
	assert.NotNil(t, finding.ParentType)
	assert.Equal(t, "endpoint", *finding.ParentType)

	// Verify endpoints
	require.Len(t, result.Discovery.Endpoints, 1)
	endpoint := result.Discovery.Endpoints[0]
	assert.NotNil(t, endpoint.Id)
	assert.Equal(t, "https://example.com/admin", endpoint.Url)
	assert.NotNil(t, endpoint.Method)
	assert.Equal(t, "GET", *endpoint.Method)

	// Verify finding's parent_id matches endpoint's id
	assert.Equal(t, *endpoint.Id, *finding.ParentId)

	// Verify evidence
	require.Len(t, result.Discovery.Evidence, 2)
	evidence1 := result.Discovery.Evidence[0]
	assert.NotNil(t, evidence1.Id)
	assert.Equal(t, *finding.Id, evidence1.FindingId)
	assert.Equal(t, "extracted_data", evidence1.Type)
	assert.NotNil(t, evidence1.Content)
	assert.Equal(t, "admin panel exposed", *evidence1.Content)
	assert.NotNil(t, evidence1.Url)
	assert.Equal(t, "https://example.com/admin", *evidence1.Url)

	evidence2 := result.Discovery.Evidence[1]
	assert.NotNil(t, evidence2.Id)
	assert.Equal(t, *finding.Id, evidence2.FindingId)
	assert.Equal(t, "extracted_data", evidence2.Type)
	assert.NotNil(t, evidence2.Content)
	assert.Equal(t, "version 1.2.3", *evidence2.Content)

	// Verify metadata
	assert.Equal(t, "nuclei", result.Metadata["tool_name"])
	assert.Equal(t, "1", result.Metadata["finding_count"])
	assert.Equal(t, "2", result.Metadata["evidence_count"])
	assert.Equal(t, "1", result.Metadata["endpoint_count"])
	assert.Equal(t, "100", result.Metadata["total_requests"])
	assert.Equal(t, "1", result.Metadata["total_matches"])

	// Verify root entity
	assert.Equal(t, *finding.Id, result.RootEntityID)
}

func TestNucleiExtractor_Extract_MultipleFindingsSameEndpoint(t *testing.T) {
	extractor := NewNucleiExtractor()
	ctx := context.Background()

	resp := &toolspb.NucleiResponse{
		Results: []*toolspb.TemplateMatch{
			{
				TemplateId:  "CVE-2021-00001",
				Type:        "http",
				Host:        "example.com",
				Url:         "https://example.com/api",
				MatchedAt:   "https://example.com/api/v1",
				MatcherName: "status",
				Info: &toolspb.TemplateInfo{
					Name:        "API Exposure 1",
					Severity:    "medium",
					Description: "API endpoint exposed",
				},
			},
			{
				TemplateId:  "CVE-2021-00002",
				Type:        "http",
				Host:        "example.com",
				Url:         "https://example.com/api",
				MatchedAt:   "https://example.com/api/v2",
				MatcherName: "body",
				Info: &toolspb.TemplateInfo{
					Name:        "API Exposure 2",
					Severity:    "low",
					Description: "Another API issue",
				},
			},
		},
		TotalMatches: 2,
	}

	result, err := extractor.Extract(ctx, resp)
	require.NoError(t, err)

	// Should have 2 findings
	require.Len(t, result.Discovery.Findings, 2)

	// Should have only 1 endpoint (same URL)
	require.Len(t, result.Discovery.Endpoints, 1)
	endpoint := result.Discovery.Endpoints[0]
	assert.Equal(t, "https://example.com/api", endpoint.Url)

	// Both findings should reference the same endpoint
	assert.Equal(t, *endpoint.Id, *result.Discovery.Findings[0].ParentId)
	assert.Equal(t, *endpoint.Id, *result.Discovery.Findings[1].ParentId)
}

func TestNucleiExtractor_Extract_FindingWithoutExtractedResults(t *testing.T) {
	extractor := NewNucleiExtractor()
	ctx := context.Background()

	resp := &toolspb.NucleiResponse{
		Results: []*toolspb.TemplateMatch{
			{
				TemplateId:       "test-template",
				Type:             "http",
				Host:             "example.com",
				Url:              "https://example.com",
				MatchedAt:        "https://example.com/login",
				MatcherName:      "status-code",
				ExtractedResults: []string{}, // No extracted results
				Info: &toolspb.TemplateInfo{
					Name:     "Test Finding",
					Severity: "info",
				},
			},
		},
		TotalMatches: 1,
	}

	result, err := extractor.Extract(ctx, resp)
	require.NoError(t, err)

	// Should have 1 finding
	require.Len(t, result.Discovery.Findings, 1)

	// Should have 1 evidence (from matched_at)
	require.Len(t, result.Discovery.Evidence, 1)
	evidence := result.Discovery.Evidence[0]
	assert.Equal(t, "match_location", evidence.Type)
	assert.NotNil(t, evidence.Content)
	assert.Contains(t, *evidence.Content, "https://example.com/login")
	assert.Contains(t, *evidence.Content, "status-code")
}

func TestNucleiExtractor_Extract_SeverityNormalization(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"lowercase", "critical", "critical"},
		{"uppercase", "HIGH", "high"},
		{"mixed case", "MeDiUm", "medium"},
		{"with spaces", "  low  ", "low"},
		{"unknown", "unknown", "info"},
		{"empty", "", "info"},
	}

	extractor := NewNucleiExtractor()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractor.normalizeSeverity(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNucleiExtractor_Extract_InvalidMessageType(t *testing.T) {
	extractor := NewNucleiExtractor()
	ctx := context.Background()

	// Pass wrong message type
	_, err := extractor.Extract(ctx, &graphragpb.DiscoveryResult{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected *toolspb.NucleiResponse")
}

func TestNucleiExtractor_Extract_NilInfo(t *testing.T) {
	extractor := NewNucleiExtractor()
	ctx := context.Background()

	resp := &toolspb.NucleiResponse{
		Results: []*toolspb.TemplateMatch{
			{
				TemplateId: "test",
				Host:       "example.com",
				Info:       nil, // Nil info should be skipped
			},
		},
		TotalMatches: 1,
	}

	result, err := extractor.Extract(ctx, resp)
	require.NoError(t, err)

	// Should skip the match with nil info
	assert.Empty(t, result.Discovery.Findings)
}

func TestNucleiExtractor_DeterministicIDs(t *testing.T) {
	extractor := NewNucleiExtractor()
	ctx := context.Background()

	// Create same response twice
	createResponse := func() *toolspb.NucleiResponse {
		return &toolspb.NucleiResponse{
			Results: []*toolspb.TemplateMatch{
				{
					TemplateId:       "CVE-2021-12345",
					Type:             "http",
					Host:             "example.com",
					Url:              "https://example.com/test",
					MatchedAt:        "https://example.com/test",
					ExtractedResults: []string{"data"},
					Info: &toolspb.TemplateInfo{
						Name:     "Test",
						Severity: "high",
					},
				},
			},
		}
	}

	// Extract twice
	result1, err := extractor.Extract(ctx, createResponse())
	require.NoError(t, err)

	result2, err := extractor.Extract(ctx, createResponse())
	require.NoError(t, err)

	// IDs should be identical (deterministic)
	require.Len(t, result1.Discovery.Findings, 1)
	require.Len(t, result2.Discovery.Findings, 1)
	assert.Equal(t, *result1.Discovery.Findings[0].Id, *result2.Discovery.Findings[0].Id)

	require.Len(t, result1.Discovery.Endpoints, 1)
	require.Len(t, result2.Discovery.Endpoints, 1)
	assert.Equal(t, *result1.Discovery.Endpoints[0].Id, *result2.Discovery.Endpoints[0].Id)

	require.Len(t, result1.Discovery.Evidence, 1)
	require.Len(t, result2.Discovery.Evidence, 1)
	assert.Equal(t, *result1.Discovery.Evidence[0].Id, *result2.Discovery.Evidence[0].Id)
}

func TestNucleiExtractor_ComplexClassification(t *testing.T) {
	extractor := NewNucleiExtractor()
	ctx := context.Background()

	resp := &toolspb.NucleiResponse{
		Results: []*toolspb.TemplateMatch{
			{
				TemplateId: "complex-vuln",
				Type:       "http",
				Host:       "example.com",
				Url:        "https://example.com",
				MatchedAt:  "https://example.com/vuln",
				Info: &toolspb.TemplateInfo{
					Name:     "Complex Vulnerability",
					Severity: "critical",
					Classification: &toolspb.TemplateClassification{
						CveId: []string{
							"CVE-2021-00001",
							"CVE-2021-00002",
							"CVE-2021-00003",
						},
						CweId: []string{
							"CWE-79",
							"CWE-89",
						},
						CvssMetrics: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
						CvssScore:   10.0,
					},
				},
			},
		},
	}

	result, err := extractor.Extract(ctx, resp)
	require.NoError(t, err)

	require.Len(t, result.Discovery.Findings, 1)
	finding := result.Discovery.Findings[0]

	// Verify multiple CVEs are joined
	assert.NotNil(t, finding.CveIds)
	assert.Equal(t, "CVE-2021-00001,CVE-2021-00002,CVE-2021-00003", *finding.CveIds)

	// Verify CVSS score
	assert.NotNil(t, finding.CvssScore)
	assert.Equal(t, 10.0, *finding.CvssScore)
}

func TestNucleiExtractor_ExtractorRegistry_Integration(t *testing.T) {
	// Test that NucleiExtractor works with ExtractorRegistry
	registry := NewExtractorRegistry()
	extractor := NewNucleiExtractor()

	err := registry.Register(extractor)
	require.NoError(t, err)

	// Verify registration
	assert.True(t, registry.Has("nuclei"))

	// Create test response
	resp := &toolspb.NucleiResponse{
		Results: []*toolspb.TemplateMatch{
			{
				TemplateId: "test",
				Host:       "example.com",
				Url:        "https://example.com",
				MatchedAt:  "https://example.com",
				Info: &toolspb.TemplateInfo{
					Name:     "Test Finding",
					Severity: "medium",
				},
			},
		},
	}

	// Extract via registry
	ctx := context.Background()
	result, err := registry.ExtractFromResponse(ctx, "nuclei", resp)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Discovery.Findings, 1)
}
