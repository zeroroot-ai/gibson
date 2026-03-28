package extraction_test

import (
	"context"
	"fmt"

	"github.com/zero-day-ai/gibson/internal/extraction"
	httpxpb "github.com/zero-day-ai/tools/discovery/httpx/gen"
)

// Example demonstrates basic usage of the HttpxExtractor.
func ExampleHttpxExtractor() {
	// Create extractor
	extractor := extraction.NewHttpxExtractor()

	// Create httpx response
	resp := &httpxpb.HttpxResponse{
		Results: []*httpxpb.HttpxResult{
			{
				Url:        "https://example.com",
				StatusCode: 200,
				Method:     "GET",
				Failed:     false,
			},
		},
		TotalScanned: 1,
		TotalSuccess: 1,
	}

	// Extract entities
	ctx := context.Background()
	result, err := extractor.Extract(ctx, resp)
	if err != nil {
		panic(err)
	}

	// Access extracted endpoints
	fmt.Printf("Extracted %d endpoints\n", len(result.Discovery.Endpoints))
	for _, endpoint := range result.Discovery.Endpoints {
		fmt.Printf("  - %s (status: %d)\n", endpoint.Url, *endpoint.StatusCode)
	}

	// Output:
	// Extracted 1 endpoints
	//   - https://example.com (status: 200)
}

// Example_withTechnologies demonstrates extracting technologies from httpx results.
func Example_httpxWithTechnologies() {
	// Create extractor
	extractor := extraction.NewHttpxExtractor()

	// Create httpx response with technology detection
	resp := &httpxpb.HttpxResponse{
		Results: []*httpxpb.HttpxResult{
			{
				Url:        "https://api.example.com",
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
						Name:       "Express",
						Version:    "4.18.0",
						Category:   "web-framework",
						Confidence: 0.90,
					},
				},
			},
		},
		TotalScanned: 1,
		TotalSuccess: 1,
	}

	// Extract entities
	ctx := context.Background()
	result, err := extractor.Extract(ctx, resp)
	if err != nil {
		panic(err)
	}

	// Access extracted technologies
	fmt.Printf("Found %d technologies:\n", len(result.Discovery.Technologies))
	for _, tech := range result.Discovery.Technologies {
		fmt.Printf("  - %s %s (category: %s, confidence: %d%%)\n",
			tech.Name, *tech.Version, *tech.Category, *tech.Confidence)
	}

	// Output:
	// Found 2 technologies:
	//   - nginx 1.21.0 (category: web-server, confidence: 95%)
	//   - Express 4.18.0 (category: web-framework, confidence: 90%)
}

// Example_withCertificate demonstrates extracting TLS certificates from httpx results.
func Example_httpxWithCertificate() {
	// Create extractor
	extractor := extraction.NewHttpxExtractor()

	// Create httpx response with TLS information
	resp := &httpxpb.HttpxResponse{
		Results: []*httpxpb.HttpxResult{
			{
				Url:        "https://secure.example.com",
				StatusCode: 200,
				Failed:     false,
				Tls: &httpxpb.TLSInfo{
					Version:      "TLS 1.3",
					SubjectDn:    "CN=secure.example.com",
					IssuerDn:     "CN=Let's Encrypt Authority X3",
					SerialNumber: "03:AB:CD:EF:12:34:56:78",
					Sans:         []string{"secure.example.com", "www.secure.example.com"},
				},
			},
		},
		TotalScanned: 1,
		TotalSuccess: 1,
	}

	// Extract entities
	ctx := context.Background()
	result, err := extractor.Extract(ctx, resp)
	if err != nil {
		panic(err)
	}

	// Access extracted certificate
	if len(result.Discovery.Certificates) > 0 {
		cert := result.Discovery.Certificates[0]
		fmt.Printf("Certificate found:\n")
		fmt.Printf("  Subject: %s\n", *cert.Subject)
		fmt.Printf("  Issuer: %s\n", *cert.Issuer)
		fmt.Printf("  Serial: %s\n", *cert.SerialNumber)
		fmt.Printf("  SANs: %s\n", *cert.San)
	}

	// Output:
	// Certificate found:
	//   Subject: CN=secure.example.com
	//   Issuer: CN=Let's Encrypt Authority X3
	//   Serial: 03:AB:CD:EF:12:34:56:78
	//   SANs: secure.example.com,www.secure.example.com
}

// Example_withRegistry demonstrates using the extractor with the registry.
func Example_httpxWithRegistry() {
	// Create registry and register extractor
	registry := extraction.NewExtractorRegistry()
	extractor := extraction.NewHttpxExtractor()
	if err := registry.Register(extractor); err != nil {
		panic(err)
	}

	// Create httpx response
	resp := &httpxpb.HttpxResponse{
		Results: []*httpxpb.HttpxResult{
			{
				Url:        "https://example.com/api",
				StatusCode: 200,
				Method:     "GET",
				Failed:     false,
			},
		},
		TotalScanned: 1,
		TotalSuccess: 1,
	}

	// Extract using registry
	ctx := context.Background()
	result, err := registry.ExtractFromResponse(ctx, "httpx", resp)
	if err != nil {
		panic(err)
	}

	// Access metadata
	fmt.Printf("Tool: %s\n", result.Metadata["tool_name"])
	fmt.Printf("Endpoints: %s\n", result.Metadata["endpoint_count"])
	fmt.Printf("Success: %s/%s\n",
		result.Metadata["total_success"],
		result.Metadata["total_scanned"])

	// Output:
	// Tool: httpx
	// Endpoints: 1
	// Success: 1/1
}
