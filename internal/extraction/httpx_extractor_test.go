package extraction

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/sdk/api/gen/graphragpb"
	httpxpb "github.com/zero-day-ai/tools/discovery/httpx/gen"
	"google.golang.org/protobuf/proto"
)

func TestHttpxExtractor_ToolName(t *testing.T) {
	extractor := NewHttpxExtractor()
	assert.Equal(t, "httpx", extractor.ToolName())
}

func TestHttpxExtractor_CanExtract(t *testing.T) {
	extractor := NewHttpxExtractor()

	tests := []struct {
		name     string
		msg      proto.Message
		expected bool
	}{
		{
			name:     "valid HttpxResponse",
			msg:      &httpxpb.HttpxResponse{},
			expected: true,
		},
		{
			name:     "invalid message type",
			msg:      &graphragpb.Host{},
			expected: false,
		},
		{
			name:     "nil message",
			msg:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractor.CanExtract(tt.msg)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHttpxExtractor_Extract_InvalidMessageType(t *testing.T) {
	extractor := NewHttpxExtractor()
	ctx := context.Background()

	// Pass wrong message type
	_, err := extractor.Extract(ctx, &graphragpb.Host{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected *httpxpb.HttpxResponse")
}

func TestHttpxExtractor_Extract_EmptyResults(t *testing.T) {
	extractor := NewHttpxExtractor()
	ctx := context.Background()

	resp := &httpxpb.HttpxResponse{
		Results:      []*httpxpb.HttpxResult{},
		TotalScanned: 10,
		TotalSuccess: 0,
		TotalFailed:  10,
		Duration:     5.5,
	}

	result, err := extractor.Extract(ctx, resp)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should return empty discovery result
	assert.Empty(t, result.Discovery.Endpoints)
	assert.Empty(t, result.Discovery.Technologies)
	assert.Empty(t, result.Discovery.Certificates)

	// Should have metadata
	assert.Equal(t, "no_results_found", result.Metadata["status"])
	assert.Equal(t, "10", result.Metadata["total_scanned"])
	assert.Equal(t, "0", result.Metadata["total_success"])
	assert.Equal(t, "10", result.Metadata["total_failed"])
	assert.Equal(t, "5.50", result.Metadata["duration"])
}

func TestHttpxExtractor_Extract_BasicEndpoint(t *testing.T) {
	extractor := NewHttpxExtractor()
	ctx := context.Background()

	resp := &httpxpb.HttpxResponse{
		Results: []*httpxpb.HttpxResult{
			{
				Url:           "https://example.com",
				StatusCode:    200,
				ContentLength: 1234,
				ContentType:   "text/html",
				Title:         "Example Domain",
				Method:        "GET",
				Failed:        false,
			},
		},
		TotalScanned: 1,
		TotalSuccess: 1,
		TotalFailed:  0,
		Duration:     1.5,
	}

	result, err := extractor.Extract(ctx, resp)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Check endpoint extraction
	require.Len(t, result.Discovery.Endpoints, 1)
	endpoint := result.Discovery.Endpoints[0]

	assert.NotNil(t, endpoint.Id)
	assert.Equal(t, "https://example.com", endpoint.Url)
	assert.NotNil(t, endpoint.StatusCode)
	assert.Equal(t, int32(200), *endpoint.StatusCode)
	assert.NotNil(t, endpoint.ContentType)
	assert.Equal(t, "text/html", *endpoint.ContentType)
	assert.NotNil(t, endpoint.ContentLength)
	assert.Equal(t, int64(1234), *endpoint.ContentLength)
	assert.NotNil(t, endpoint.Title)
	assert.Equal(t, "Example Domain", *endpoint.Title)
	assert.NotNil(t, endpoint.Method)
	assert.Equal(t, "GET", *endpoint.Method)

	// Check root entity ID
	assert.Equal(t, *endpoint.Id, result.RootEntityID)

	// Check metadata
	assert.Equal(t, "httpx", result.Metadata["tool_name"])
	assert.Equal(t, "1", result.Metadata["endpoint_count"])
	assert.Equal(t, "1", result.Metadata["total_success"])
}

func TestHttpxExtractor_Extract_WithTechnologies(t *testing.T) {
	extractor := NewHttpxExtractor()
	ctx := context.Background()

	resp := &httpxpb.HttpxResponse{
		Results: []*httpxpb.HttpxResult{
			{
				Url:        "https://example.com",
				StatusCode: 200,
				Failed:     false,
				Technologies: []*httpxpb.Technology{
					{
						Name:       "nginx",
						Version:    "1.21.0",
						Category:   "web-server",
						Confidence: 0.95,
					},
					{
						Name:       "PHP",
						Version:    "8.1.2",
						Category:   "language",
						Confidence: 0.85,
					},
				},
			},
		},
		TotalScanned: 1,
		TotalSuccess: 1,
	}

	result, err := extractor.Extract(ctx, resp)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Check endpoint
	require.Len(t, result.Discovery.Endpoints, 1)
	endpointID := *result.Discovery.Endpoints[0].Id

	// Check technologies
	require.Len(t, result.Discovery.Technologies, 2)

	// Check nginx technology
	nginx := result.Discovery.Technologies[0]
	assert.NotNil(t, nginx.Id)
	assert.Equal(t, "nginx", nginx.Name)
	assert.NotNil(t, nginx.Version)
	assert.Equal(t, "1.21.0", *nginx.Version)
	assert.NotNil(t, nginx.Category)
	assert.Equal(t, "web-server", *nginx.Category)
	assert.NotNil(t, nginx.Confidence)
	assert.Equal(t, int32(95), *nginx.Confidence) // 0.95 * 100
	assert.NotNil(t, nginx.ParentId)
	assert.Equal(t, endpointID, *nginx.ParentId)
	assert.NotNil(t, nginx.ParentType)
	assert.Equal(t, "endpoint", *nginx.ParentType)

	// Check PHP technology
	php := result.Discovery.Technologies[1]
	assert.Equal(t, "PHP", php.Name)
	assert.NotNil(t, php.Version)
	assert.Equal(t, "8.1.2", *php.Version)
	assert.NotNil(t, php.Confidence)
	assert.Equal(t, int32(85), *php.Confidence) // 0.85 * 100

	// Check metadata
	assert.Equal(t, "2", result.Metadata["technology_count"])
}

func TestHttpxExtractor_Extract_WithCertificate(t *testing.T) {
	extractor := NewHttpxExtractor()
	ctx := context.Background()

	resp := &httpxpb.HttpxResponse{
		Results: []*httpxpb.HttpxResult{
			{
				Url:        "https://example.com",
				StatusCode: 200,
				Failed:     false,
				Tls: &httpxpb.TLSInfo{
					Version:            "TLS 1.3",
					SubjectDn:          "CN=example.com",
					IssuerDn:           "CN=Let's Encrypt Authority X3",
					SerialNumber:       "03:AB:CD:EF:12:34:56:78",
					NotBefore:          "2024-01-01T00:00:00Z",
					NotAfter:           "2024-12-31T23:59:59Z",
					Sans:               []string{"example.com", "www.example.com"},
					Expired:            false,
					SelfSigned:         false,
					SignatureAlgorithm: "SHA256-RSA",
					PublicKeyAlgorithm: "RSA",
					PublicKeySize:      2048,
				},
			},
		},
		TotalScanned: 1,
		TotalSuccess: 1,
	}

	result, err := extractor.Extract(ctx, resp)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Check endpoint
	require.Len(t, result.Discovery.Endpoints, 1)
	endpointID := *result.Discovery.Endpoints[0].Id

	// Check certificate
	require.Len(t, result.Discovery.Certificates, 1)
	cert := result.Discovery.Certificates[0]

	assert.NotNil(t, cert.Id)
	assert.NotNil(t, cert.Subject)
	assert.Equal(t, "CN=example.com", *cert.Subject)
	assert.NotNil(t, cert.Issuer)
	assert.Equal(t, "CN=Let's Encrypt Authority X3", *cert.Issuer)
	assert.NotNil(t, cert.SerialNumber)
	assert.Equal(t, "03:AB:CD:EF:12:34:56:78", *cert.SerialNumber)
	assert.NotNil(t, cert.NotBefore)
	assert.NotNil(t, cert.NotAfter)
	assert.NotNil(t, cert.San)
	assert.Equal(t, "example.com,www.example.com", *cert.San)
	assert.NotNil(t, cert.ParentId)
	assert.Equal(t, endpointID, *cert.ParentId)
	assert.NotNil(t, cert.ParentType)
	assert.Equal(t, "endpoint", *cert.ParentType)

	// Check metadata
	assert.Equal(t, "1", result.Metadata["certificate_count"])
}

func TestHttpxExtractor_Extract_SkipsFailedRequests(t *testing.T) {
	extractor := NewHttpxExtractor()
	ctx := context.Background()

	resp := &httpxpb.HttpxResponse{
		Results: []*httpxpb.HttpxResult{
			{
				Url:        "https://example.com",
				StatusCode: 200,
				Failed:     false,
			},
			{
				Url:    "https://failed.com",
				Failed: true,
				Error:  "connection timeout",
			},
			{
				Url:        "https://another.com",
				StatusCode: 404,
				Failed:     false,
			},
		},
		TotalScanned: 3,
		TotalSuccess: 2,
		TotalFailed:  1,
	}

	result, err := extractor.Extract(ctx, resp)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should only extract successful requests (2 endpoints)
	require.Len(t, result.Discovery.Endpoints, 2)
	assert.Equal(t, "https://example.com", result.Discovery.Endpoints[0].Url)
	assert.Equal(t, "https://another.com", result.Discovery.Endpoints[1].Url)

	// Check metadata
	assert.Equal(t, "2", result.Metadata["endpoint_count"])
	assert.Equal(t, "3", result.Metadata["total_scanned"])
	assert.Equal(t, "1", result.Metadata["total_failed"])
}

func TestHttpxExtractor_Extract_CompleteScenario(t *testing.T) {
	extractor := NewHttpxExtractor()
	ctx := context.Background()

	resp := &httpxpb.HttpxResponse{
		Results: []*httpxpb.HttpxResult{
			{
				Url:           "https://api.example.com/v1",
				StatusCode:    200,
				ContentType:   "application/json",
				ContentLength: 5678,
				Title:         "API v1",
				Method:        "GET",
				Failed:        false,
				Technologies: []*httpxpb.Technology{
					{
						Name:       "Express",
						Version:    "4.18.0",
						Category:   "web-framework",
						Confidence: 0.90,
					},
				},
				Tls: &httpxpb.TLSInfo{
					Version:      "TLS 1.3",
					SubjectDn:    "CN=api.example.com",
					IssuerDn:     "CN=DigiCert",
					SerialNumber: "12:34:56:78:90:AB",
					NotBefore:    "2024-01-01T00:00:00Z",
					NotAfter:     "2025-01-01T00:00:00Z",
					Sans:         []string{"api.example.com"},
				},
			},
			{
				Url:        "https://www.example.com",
				StatusCode: 200,
				Failed:     false,
				Technologies: []*httpxpb.Technology{
					{
						Name:     "WordPress",
						Version:  "6.2.0",
						Category: "cms",
					},
				},
			},
		},
		TotalScanned: 2,
		TotalSuccess: 2,
		TotalFailed:  0,
		Duration:     3.5,
	}

	result, err := extractor.Extract(ctx, resp)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify all entities
	assert.Len(t, result.Discovery.Endpoints, 2)
	assert.Len(t, result.Discovery.Technologies, 2)
	assert.Len(t, result.Discovery.Certificates, 1)

	// Verify root entity
	assert.NotEmpty(t, result.RootEntityID)

	// Verify metadata
	assert.Equal(t, "httpx", result.Metadata["tool_name"])
	assert.Equal(t, "2", result.Metadata["endpoint_count"])
	assert.Equal(t, "2", result.Metadata["technology_count"])
	assert.Equal(t, "1", result.Metadata["certificate_count"])
	assert.Equal(t, "2", result.Metadata["total_success"])
	assert.Equal(t, "0", result.Metadata["total_failed"])
	assert.Equal(t, "3.50", result.Metadata["scan_duration"])
}

func TestHttpxExtractor_DeterministicIDs(t *testing.T) {
	extractor := NewHttpxExtractor()
	ctx := context.Background()

	// Same response run twice should produce same IDs
	resp := &httpxpb.HttpxResponse{
		Results: []*httpxpb.HttpxResult{
			{
				Url:        "https://example.com",
				StatusCode: 200,
				Failed:     false,
				Technologies: []*httpxpb.Technology{
					{
						Name:    "nginx",
						Version: "1.21.0",
					},
				},
			},
		},
		TotalScanned: 1,
		TotalSuccess: 1,
	}

	// First extraction
	result1, err := extractor.Extract(ctx, resp)
	require.NoError(t, err)

	// Second extraction
	result2, err := extractor.Extract(ctx, resp)
	require.NoError(t, err)

	// IDs should be identical
	assert.Equal(t, *result1.Discovery.Endpoints[0].Id, *result2.Discovery.Endpoints[0].Id)
	assert.Equal(t, *result1.Discovery.Technologies[0].Id, *result2.Discovery.Technologies[0].Id)
	assert.Equal(t, result1.RootEntityID, result2.RootEntityID)
}

func TestHttpxExtractor_URLNormalization(t *testing.T) {
	extractor := NewHttpxExtractor()

	tests := []struct {
		name        string
		url1        string
		url2        string
		shouldMatch bool
	}{
		{
			name:        "exact same URLs",
			url1:        "https://example.com",
			url2:        "https://example.com",
			shouldMatch: true,
		},
		{
			name:        "different URLs",
			url1:        "https://example.com",
			url2:        "https://different.com",
			shouldMatch: false,
		},
		{
			name:        "same path different host",
			url1:        "https://example.com/path",
			url2:        "https://other.com/path",
			shouldMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id1 := extractor.generateEndpointID(tt.url1)
			id2 := extractor.generateEndpointID(tt.url2)

			if tt.shouldMatch {
				assert.Equal(t, id1, id2)
			} else {
				assert.NotEqual(t, id1, id2)
			}
		})
	}
}

func TestHttpxExtractor_GenerateEndpointID_InvalidURL(t *testing.T) {
	extractor := NewHttpxExtractor()

	// Test with invalid URL (contains space which is not allowed in URLs)
	invalidURL := "ht tp://invalid url with spaces"
	id := extractor.generateEndpointID(invalidURL)

	// Should still generate a valid UUID (using raw URL)
	assert.NotEmpty(t, id)
	assert.Len(t, id, 36) // UUID format is 36 characters

	// Should be deterministic even for invalid URLs
	id2 := extractor.generateEndpointID(invalidURL)
	assert.Equal(t, id, id2)
}

func TestHttpxExtractor_ParseTimestamp(t *testing.T) {
	tests := []struct {
		name      string
		timestamp string
		wantErr   bool
	}{
		{
			name:      "RFC3339 format",
			timestamp: "2024-01-01T00:00:00Z",
			wantErr:   false,
		},
		{
			name:      "RFC3339 with offset",
			timestamp: "2024-01-01T00:00:00-07:00",
			wantErr:   false,
		},
		{
			name:      "simple date",
			timestamp: "2024-01-01",
			wantErr:   false,
		},
		{
			name:      "unix timestamp string",
			timestamp: "1704067200",
			wantErr:   false,
		},
		{
			name:      "invalid format",
			timestamp: "not a timestamp",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseTimestamp(tt.timestamp)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHttpxExtractor_ExtractEndpoint_AllFields(t *testing.T) {
	extractor := NewHttpxExtractor()

	result := &httpxpb.HttpxResult{
		Url:           "https://example.com/api",
		StatusCode:    201,
		ContentLength: 9999,
		ContentType:   "application/json",
		Title:         "API Endpoint",
		Method:        "POST",
	}

	endpointID := "test-id"
	endpoint := extractor.extractEndpoint(result, endpointID)

	assert.Equal(t, endpointID, *endpoint.Id)
	assert.Equal(t, "https://example.com/api", endpoint.Url)
	assert.Equal(t, int32(201), *endpoint.StatusCode)
	assert.Equal(t, int64(9999), *endpoint.ContentLength)
	assert.Equal(t, "application/json", *endpoint.ContentType)
	assert.Equal(t, "API Endpoint", *endpoint.Title)
	assert.Equal(t, "POST", *endpoint.Method)
}

func TestHttpxExtractor_ExtractEndpoint_MinimalFields(t *testing.T) {
	extractor := NewHttpxExtractor()

	result := &httpxpb.HttpxResult{
		Url: "https://example.com",
	}

	endpointID := "test-id"
	endpoint := extractor.extractEndpoint(result, endpointID)

	assert.Equal(t, endpointID, *endpoint.Id)
	assert.Equal(t, "https://example.com", endpoint.Url)
	// Optional fields should be nil or have default values
	assert.Nil(t, endpoint.StatusCode)
	assert.Nil(t, endpoint.ContentLength)
	assert.Nil(t, endpoint.ContentType)
	assert.Nil(t, endpoint.Title)
}

func TestHttpxExtractor_ExtractTechnology_AllFields(t *testing.T) {
	extractor := NewHttpxExtractor()

	tech := &httpxpb.Technology{
		Name:       "React",
		Version:    "18.2.0",
		Category:   "javascript-framework",
		Confidence: 0.92,
	}

	techID := "tech-id"
	parentID := "parent-id"
	technology := extractor.extractTechnology(tech, techID, parentID)

	assert.Equal(t, techID, *technology.Id)
	assert.Equal(t, "React", technology.Name)
	assert.Equal(t, "18.2.0", *technology.Version)
	assert.Equal(t, "javascript-framework", *technology.Category)
	assert.Equal(t, int32(92), *technology.Confidence)
	assert.Equal(t, parentID, *technology.ParentId)
	assert.Equal(t, "endpoint", *technology.ParentType)
}

func TestHttpxExtractor_ExtractCertificate_AllFields(t *testing.T) {
	extractor := NewHttpxExtractor()

	tls := &httpxpb.TLSInfo{
		SubjectDn:    "CN=test.com",
		IssuerDn:     "CN=Test CA",
		SerialNumber: "AA:BB:CC",
		NotBefore:    "2024-01-01T00:00:00Z",
		NotAfter:     "2025-01-01T00:00:00Z",
		Sans:         []string{"test.com", "www.test.com", "api.test.com"},
	}

	certID := "cert-id"
	parentID := "parent-id"
	cert := extractor.extractCertificate(tls, certID, parentID)

	assert.Equal(t, certID, *cert.Id)
	assert.Equal(t, "CN=test.com", *cert.Subject)
	assert.Equal(t, "CN=Test CA", *cert.Issuer)
	assert.Equal(t, "AA:BB:CC", *cert.SerialNumber)
	assert.NotNil(t, cert.NotBefore)
	assert.NotNil(t, cert.NotAfter)
	assert.Equal(t, "test.com,www.test.com,api.test.com", *cert.San)
	assert.Equal(t, parentID, *cert.ParentId)
	assert.Equal(t, "endpoint", *cert.ParentType)
}

func TestHttpxExtractor_Integration_WithRegistry(t *testing.T) {
	// Create registry
	registry := NewExtractorRegistry()

	// Register httpx extractor
	extractor := NewHttpxExtractor()
	err := registry.Register(extractor)
	require.NoError(t, err)

	// Verify it's registered
	assert.True(t, registry.Has("httpx"))

	// Create test response
	resp := &httpxpb.HttpxResponse{
		Results: []*httpxpb.HttpxResult{
			{
				Url:        "https://api.example.com",
				StatusCode: 200,
				Failed:     false,
				Technologies: []*httpxpb.Technology{
					{Name: "nginx", Version: "1.21.0"},
				},
			},
		},
		TotalScanned: 1,
		TotalSuccess: 1,
	}

	// Extract using registry
	ctx := context.Background()
	result, err := registry.ExtractFromResponse(ctx, "httpx", resp)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify extraction worked
	assert.Len(t, result.Discovery.Endpoints, 1)
	assert.Len(t, result.Discovery.Technologies, 1)
}

// Benchmark tests

func BenchmarkHttpxExtractor_Extract_SingleEndpoint(b *testing.B) {
	extractor := NewHttpxExtractor()
	ctx := context.Background()

	resp := &httpxpb.HttpxResponse{
		Results: []*httpxpb.HttpxResult{
			{
				Url:        "https://example.com",
				StatusCode: 200,
				Failed:     false,
			},
		},
		TotalScanned: 1,
		TotalSuccess: 1,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = extractor.Extract(ctx, resp)
	}
}

func BenchmarkHttpxExtractor_Extract_MultipleEndpoints(b *testing.B) {
	extractor := NewHttpxExtractor()
	ctx := context.Background()

	// Create 100 endpoints
	results := make([]*httpxpb.HttpxResult, 100)
	for i := 0; i < 100; i++ {
		results[i] = &httpxpb.HttpxResult{
			Url:        "https://example.com/endpoint/" + string(rune(i)),
			StatusCode: 200,
			Failed:     false,
			Technologies: []*httpxpb.Technology{
				{Name: "nginx", Version: "1.21.0"},
			},
		}
	}

	resp := &httpxpb.HttpxResponse{
		Results:      results,
		TotalScanned: 100,
		TotalSuccess: 100,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = extractor.Extract(ctx, resp)
	}
}
