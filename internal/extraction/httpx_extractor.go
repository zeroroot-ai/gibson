package extraction

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
	httpxpb "github.com/zero-day-ai/tools/discovery/httpx/gen"
	"google.golang.org/protobuf/proto"
)

// HttpxExtractor extracts entities from httpx scan results.
// It converts HttpxResponse proto messages into standardized DiscoveryResult containing:
//   - Endpoint entities (URL, path, method, status code)
//   - Technology entities (name, version, category)
//   - Certificate entities (issuer, subject, expiry)
//
// All entities are linked via parent references and UUIDs are deterministically
// generated for idempotency.
type HttpxExtractor struct{}

// NewHttpxExtractor creates a new HttpxExtractor instance.
func NewHttpxExtractor() *HttpxExtractor {
	return &HttpxExtractor{}
}

// ToolName returns the identifier for the httpx tool.
func (e *HttpxExtractor) ToolName() string {
	return "httpx"
}

// CanExtract validates that this extractor can process HttpxResponse messages.
func (e *HttpxExtractor) CanExtract(msg proto.Message) bool {
	_, ok := msg.(*httpxpb.HttpxResponse)
	return ok
}

// Extract converts an HttpxResponse into a DiscoveryResult.
// It extracts:
//   - Endpoints with URL, method, status code, content type, title
//   - Technologies detected from response headers/body
//   - Certificates from TLS connections
//
// Returns an error if the message type is invalid.
// Returns an empty result (not an error) if no results were found.
func (e *HttpxExtractor) Extract(ctx context.Context, msg proto.Message) (*ExtractionResult, error) {
	// Type assertion (safe because CanExtract was called first)
	resp, ok := msg.(*httpxpb.HttpxResponse)
	if !ok {
		return nil, fmt.Errorf("expected *httpxpb.HttpxResponse, got %T", msg)
	}

	// Handle empty scan results gracefully
	if len(resp.Results) == 0 {
		return &ExtractionResult{
			Discovery: &graphragpb.DiscoveryResult{},
			Metadata: map[string]string{
				"status":        "no_results_found",
				"total_scanned": fmt.Sprintf("%d", resp.TotalScanned),
				"total_success": fmt.Sprintf("%d", resp.TotalSuccess),
				"total_failed":  fmt.Sprintf("%d", resp.TotalFailed),
				"duration":      fmt.Sprintf("%.2f", resp.Duration),
			},
		}, nil
	}

	// Create discovery result
	discovery := &graphragpb.DiscoveryResult{}
	var rootEndpointID string

	// Track statistics
	var totalTechnologies, totalCertificates int

	// Extract all results
	for _, result := range resp.Results {
		// Skip failed requests
		if result.Failed {
			continue
		}

		// Generate deterministic UUID for endpoint
		endpointID := e.generateEndpointID(result.Url)

		// Create endpoint entity
		endpoint := e.extractEndpoint(result, endpointID)
		discovery.Endpoints = append(discovery.Endpoints, endpoint)

		// Track first endpoint as root entity
		if rootEndpointID == "" {
			rootEndpointID = endpointID
		}

		// Extract technologies for this endpoint
		for _, tech := range result.Technologies {
			techID := e.generateTechnologyID(endpointID, tech.Name, tech.Version)
			technology := e.extractTechnology(tech, techID, endpointID)
			discovery.Technologies = append(discovery.Technologies, technology)
			totalTechnologies++
		}

		// Extract certificate if present
		if result.Tls != nil {
			certID := e.generateCertificateID(endpointID, result.Tls.SerialNumber)
			certificate := e.extractCertificate(result.Tls, certID, endpointID)
			discovery.Certificates = append(discovery.Certificates, certificate)
			totalCertificates++
		}
	}

	// Build extraction result with metadata
	result := &ExtractionResult{
		Discovery:    discovery,
		RootEntityID: rootEndpointID,
		Metadata: map[string]string{
			"tool_name":         "httpx",
			"endpoint_count":    fmt.Sprintf("%d", len(discovery.Endpoints)),
			"technology_count":  fmt.Sprintf("%d", totalTechnologies),
			"certificate_count": fmt.Sprintf("%d", totalCertificates),
			"total_scanned":     fmt.Sprintf("%d", resp.TotalScanned),
			"total_success":     fmt.Sprintf("%d", resp.TotalSuccess),
			"total_failed":      fmt.Sprintf("%d", resp.TotalFailed),
			"scan_duration":     fmt.Sprintf("%.2f", resp.Duration),
		},
	}

	return result, nil
}

// extractEndpoint creates an Endpoint entity from HttpxResult data.
func (e *HttpxExtractor) extractEndpoint(result *httpxpb.HttpxResult, endpointID string) *graphragpb.Endpoint {
	endpoint := &graphragpb.Endpoint{
		Id:     &endpointID,
		Url:    result.Url,
		Method: stringPtr(result.Method),
	}

	// Add status code if available
	if result.StatusCode != 0 {
		endpoint.StatusCode = int32Ptr(result.StatusCode)
	}

	// Add content type if available
	if result.ContentType != "" {
		endpoint.ContentType = stringPtr(result.ContentType)
	}

	// Add content length if available
	if result.ContentLength != 0 {
		endpoint.ContentLength = int64Ptr(result.ContentLength)
	}

	// Add title if available
	if result.Title != "" {
		endpoint.Title = stringPtr(result.Title)
	}

	return endpoint
}

// extractTechnology creates a Technology entity from Technology data.
func (e *HttpxExtractor) extractTechnology(tech *httpxpb.Technology, techID, parentID string) *graphragpb.Technology {
	technology := &graphragpb.Technology{
		Id:         &techID,
		Name:       tech.Name,
		ParentId:   stringPtr(parentID),
		ParentType: stringPtr("endpoint"),
	}

	// Add version if available
	if tech.Version != "" {
		technology.Version = stringPtr(tech.Version)
	}

	// Add category if available
	if tech.Category != "" {
		technology.Category = stringPtr(tech.Category)
	}

	// Add confidence if available (convert from 0.0-1.0 to 0-100)
	if tech.Confidence > 0 {
		confidence := int32(tech.Confidence * 100)
		technology.Confidence = int32Ptr(confidence)
	}

	return technology
}

// extractCertificate creates a Certificate entity from TLSInfo data.
func (e *HttpxExtractor) extractCertificate(tls *httpxpb.TLSInfo, certID, parentID string) *graphragpb.Certificate {
	certificate := &graphragpb.Certificate{
		Id:         &certID,
		ParentId:   stringPtr(parentID),
		ParentType: stringPtr("endpoint"),
	}

	// Add subject if available
	if tls.SubjectDn != "" {
		certificate.Subject = stringPtr(tls.SubjectDn)
	}

	// Add issuer if available
	if tls.IssuerDn != "" {
		certificate.Issuer = stringPtr(tls.IssuerDn)
	}

	// Add serial number if available
	if tls.SerialNumber != "" {
		certificate.SerialNumber = stringPtr(tls.SerialNumber)
	}

	// Parse not_before timestamp if available
	if tls.NotBefore != "" {
		if ts, err := parseTimestamp(tls.NotBefore); err == nil {
			certificate.NotBefore = int64Ptr(ts)
		}
	}

	// Parse not_after timestamp if available
	if tls.NotAfter != "" {
		if ts, err := parseTimestamp(tls.NotAfter); err == nil {
			certificate.NotAfter = int64Ptr(ts)
		}
	}

	// Add SANs if available (concatenate as comma-separated string)
	if len(tls.Sans) > 0 {
		sanStr := ""
		for i, san := range tls.Sans {
			if i > 0 {
				sanStr += ","
			}
			sanStr += san
		}
		certificate.San = stringPtr(sanStr)
	}

	// Add SHA256 fingerprint (compute from available data if needed)
	// For now, we use serial number as a proxy if fingerprint not available
	if tls.SerialNumber != "" {
		// In a real implementation, we'd compute the actual SHA256 fingerprint
		// from the certificate data. For now, use serial number.
		certificate.FingerprintSha256 = stringPtr(tls.SerialNumber)
	}

	return certificate
}

// UUID generation helpers - ensure deterministic IDs for idempotency

// generateEndpointID creates a deterministic UUID for an endpoint based on its URL.
// This ensures re-scanning the same URL produces the same ID.
func (e *HttpxExtractor) generateEndpointID(urlStr string) string {
	namespace := uuid.NameSpaceOID
	// Parse URL to normalize it (remove trailing slashes, normalize scheme, etc.)
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		// If URL parsing fails, use raw URL
		name := fmt.Sprintf("endpoint:%s", urlStr)
		return uuid.NewSHA1(namespace, []byte(name)).String()
	}

	// Use normalized URL for deterministic ID
	normalizedURL := parsedURL.String()
	name := fmt.Sprintf("endpoint:%s", normalizedURL)
	return uuid.NewSHA1(namespace, []byte(name)).String()
}

// generateTechnologyID creates a deterministic UUID for a technology.
// It's based on the parent endpoint ID, tech name, and version.
func (e *HttpxExtractor) generateTechnologyID(parentID, name, version string) string {
	namespace := uuid.NameSpaceOID
	nameStr := fmt.Sprintf("technology:%s:%s:%s", parentID, name, version)
	return uuid.NewSHA1(namespace, []byte(nameStr)).String()
}

// generateCertificateID creates a deterministic UUID for a certificate.
// It's based on the parent endpoint ID and serial number.
func (e *HttpxExtractor) generateCertificateID(parentID, serialNumber string) string {
	namespace := uuid.NameSpaceOID
	name := fmt.Sprintf("certificate:%s:%s", parentID, serialNumber)
	return uuid.NewSHA1(namespace, []byte(name)).String()
}

// Helper functions

// parseTimestamp attempts to parse a timestamp string into Unix epoch milliseconds.
// Supports various common timestamp formats.
func parseTimestamp(ts string) (int64, error) {
	// Try common timestamp formats
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, ts); err == nil {
			return t.Unix(), nil
		}
	}

	// Try parsing as Unix timestamp (string)
	if i, err := strconv.ParseInt(ts, 10, 64); err == nil {
		return i, nil
	}

	return 0, fmt.Errorf("unable to parse timestamp: %s", ts)
}

// Helper to create int32 pointers for optional proto fields
func int32Ptr(i int32) *int32 {
	return &i
}

// Helper to create int64 pointers for optional proto fields
func int64Ptr(i int64) *int64 {
	return &i
}
