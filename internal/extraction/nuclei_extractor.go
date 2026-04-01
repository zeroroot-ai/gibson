package extraction

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
	"github.com/zero-day-ai/sdk/api/gen/toolspb"
	"google.golang.org/protobuf/proto"
)

// NucleiExtractor extracts entities from nuclei vulnerability scan results.
// It converts NucleiResponse proto messages into standardized DiscoveryResult containing:
//   - Finding entities (vulnerability type, severity, title, description)
//   - Evidence entities (matched content, extracted data)
//   - Endpoint entities (target URLs)
//
// All entities are linked via parent references and relationships.
// Findings are associated with the target endpoints they affect.
type NucleiExtractor struct{}

// NewNucleiExtractor creates a new NucleiExtractor instance.
func NewNucleiExtractor() *NucleiExtractor {
	return &NucleiExtractor{}
}

// ToolName returns the identifier for the nuclei tool.
func (e *NucleiExtractor) ToolName() string {
	return "nuclei"
}

// CanExtract validates that this extractor can process NucleiResponse messages.
func (e *NucleiExtractor) CanExtract(msg proto.Message) bool {
	_, ok := msg.(*toolspb.NucleiResponse)
	return ok
}

// Extract converts a NucleiResponse into a DiscoveryResult.
// It extracts:
//   - Findings with severity, description, classification (CVE, CWE, CVSS)
//   - Evidence entities for matched content and extracted data
//   - Endpoint entities for target URLs
//
// Relationships:
//   - Finding AFFECTS Endpoint (the target URL)
//   - Evidence SUPPORTS Finding (the matched data)
//
// Returns an error if the message type is invalid.
// Returns an empty result (not an error) if no matches were found.
func (e *NucleiExtractor) Extract(ctx context.Context, msg proto.Message) (*ExtractionResult, error) {
	// Type assertion (safe because CanExtract was called first)
	resp, ok := msg.(*toolspb.NucleiResponse)
	if !ok {
		return nil, fmt.Errorf("expected *toolspb.NucleiResponse, got %T", msg)
	}

	// Handle empty scan results gracefully
	if len(resp.Results) == 0 {
		return &ExtractionResult{
			Discovery: &graphragpb.DiscoveryResult{},
			Metadata: map[string]string{
				"status":             "no_matches_found",
				"total_requests":     fmt.Sprintf("%d", resp.TotalRequests),
				"total_matches":      fmt.Sprintf("%d", resp.TotalMatches),
				"templates_loaded":   fmt.Sprintf("%d", resp.TemplatesLoaded),
				"templates_executed": fmt.Sprintf("%d", resp.TemplatesExecuted),
				"duration":           fmt.Sprintf("%.2f", resp.Duration),
			},
		}, nil
	}

	// Create discovery result
	discovery := &graphragpb.DiscoveryResult{}
	var rootFindingID string

	// Track statistics
	var totalEvidence int
	endpointMap := make(map[string]*graphragpb.Endpoint) // Deduplicate endpoints

	// Extract all template matches
	for _, match := range resp.Results {
		// Skip matches without info (shouldn't happen, but be safe)
		if match.Info == nil {
			continue
		}

		// Generate deterministic UUID for finding
		findingID := e.generateFindingID(match.TemplateId, match.Host, match.MatchedAt)

		// Create finding entity
		finding := e.extractFinding(match, findingID)
		discovery.Findings = append(discovery.Findings, finding)

		// Track first finding as root entity
		if rootFindingID == "" {
			rootFindingID = findingID
		}

		// Extract or reuse endpoint entity
		var endpointID string
		if match.Url != "" {
			endpointID = e.generateEndpointID(match.Url)
			if _, exists := endpointMap[endpointID]; !exists {
				endpoint := e.extractEndpoint(match, endpointID)
				endpointMap[endpointID] = endpoint
				discovery.Endpoints = append(discovery.Endpoints, endpoint)
			}

			// Link finding to endpoint via parent reference
			// This creates an implicit AFFECTS relationship
			finding.ParentId = stringPtr(endpointID)
			finding.ParentType = stringPtr("endpoint")
		}

		// Extract evidence from extracted results
		for idx, extracted := range match.ExtractedResults {
			evidenceID := e.generateEvidenceID(findingID, idx)
			evidence := e.extractEvidence(match, extracted, idx, evidenceID, findingID)
			discovery.Evidence = append(discovery.Evidence, evidence)
			totalEvidence++
		}

		// If there are no extracted results but we have a matched_at, create evidence
		if len(match.ExtractedResults) == 0 && match.MatchedAt != "" {
			evidenceID := e.generateEvidenceID(findingID, 0)
			evidence := e.extractMatchedAtEvidence(match, evidenceID, findingID)
			discovery.Evidence = append(discovery.Evidence, evidence)
			totalEvidence++
		}
	}

	// Build extraction result with metadata
	result := &ExtractionResult{
		Discovery:    discovery,
		RootEntityID: rootFindingID,
		Metadata: map[string]string{
			"tool_name":          "nuclei",
			"finding_count":      fmt.Sprintf("%d", len(discovery.Findings)),
			"evidence_count":     fmt.Sprintf("%d", totalEvidence),
			"endpoint_count":     fmt.Sprintf("%d", len(discovery.Endpoints)),
			"total_requests":     fmt.Sprintf("%d", resp.TotalRequests),
			"total_matches":      fmt.Sprintf("%d", resp.TotalMatches),
			"templates_loaded":   fmt.Sprintf("%d", resp.TemplatesLoaded),
			"templates_executed": fmt.Sprintf("%d", resp.TemplatesExecuted),
			"scan_duration":      fmt.Sprintf("%.2f", resp.Duration),
		},
	}

	return result, nil
}

// extractFinding creates a Finding entity from TemplateMatch data.
func (e *NucleiExtractor) extractFinding(match *toolspb.TemplateMatch, findingID string) *graphragpb.Finding {
	info := match.Info

	finding := &graphragpb.Finding{
		Id:       &findingID,
		Title:    info.Name,
		Severity: e.normalizeSeverity(info.Severity),
	}

	// Add description if available
	if info.Description != "" {
		finding.Description = stringPtr(info.Description)
	}

	// Add remediation if available
	if info.Remediation != "" {
		finding.Remediation = stringPtr(info.Remediation)
	}

	// Add category (use template tags)
	if len(info.Tags) > 0 {
		// Join tags as category
		category := strings.Join(info.Tags, ",")
		finding.Category = stringPtr(category)
	}

	// Extract classification data (CVE, CWE, CVSS)
	if info.Classification != nil {
		classification := info.Classification

		// CVE IDs
		if len(classification.CveId) > 0 {
			cveStr := strings.Join(classification.CveId, ",")
			finding.CveIds = stringPtr(cveStr)
		}

		// CVSS Score
		if classification.CvssScore > 0 {
			finding.CvssScore = float64Ptr(classification.CvssScore)
		}

		// Store CWE IDs and CVSS metrics in category if not set
		// We could extend the Finding proto to have these fields directly
	}

	// Set confidence to 1.0 for nuclei matches (they're verified)
	finding.Confidence = float64Ptr(1.0)

	return finding
}

// extractEndpoint creates an Endpoint entity from TemplateMatch data.
func (e *NucleiExtractor) extractEndpoint(match *toolspb.TemplateMatch, endpointID string) *graphragpb.Endpoint {
	endpoint := &graphragpb.Endpoint{
		Id:  &endpointID,
		Url: match.Url,
	}

	// Try to extract method from metadata or request
	if match.Type == "http" {
		// Default to GET if not specified
		endpoint.Method = stringPtr("GET")
	}

	// Add title if available (from the page, not the template)
	// This would be in the response data if we parsed it

	return endpoint
}

// extractEvidence creates an Evidence entity from extracted results.
func (e *NucleiExtractor) extractEvidence(match *toolspb.TemplateMatch, extracted string, index int, evidenceID, findingID string) *graphragpb.Evidence {
	evidence := &graphragpb.Evidence{
		Id:        &evidenceID,
		FindingId: findingID,
		Type:      "extracted_data",
	}

	// Set content to the extracted value
	if extracted != "" {
		evidence.Content = stringPtr(extracted)
	}

	// Set URL if available
	if match.Url != "" {
		evidence.Url = stringPtr(match.Url)
	}

	return evidence
}

// extractMatchedAtEvidence creates an Evidence entity from the matched_at field.
// This is used when there are no extracted results but we have a match location.
func (e *NucleiExtractor) extractMatchedAtEvidence(match *toolspb.TemplateMatch, evidenceID, findingID string) *graphragpb.Evidence {
	evidence := &graphragpb.Evidence{
		Id:        &evidenceID,
		FindingId: findingID,
		Type:      "match_location",
	}

	// Set content to the matched location
	content := fmt.Sprintf("Matched at: %s", match.MatchedAt)
	if match.MatcherName != "" {
		content += fmt.Sprintf(" (matcher: %s)", match.MatcherName)
	}
	evidence.Content = stringPtr(content)

	// Set URL if available
	if match.Url != "" {
		evidence.Url = stringPtr(match.Url)
	}

	return evidence
}

// normalizeSeverity ensures severity values are consistent.
// Nuclei uses: info, low, medium, high, critical
// We normalize to lowercase for consistency.
func (e *NucleiExtractor) normalizeSeverity(severity string) string {
	normalized := strings.ToLower(strings.TrimSpace(severity))

	// Validate known severity levels
	switch normalized {
	case "info", "low", "medium", "high", "critical":
		return normalized
	default:
		// Default to info for unknown severities
		return "info"
	}
}

// UUID generation helpers - ensure deterministic IDs for idempotency

// generateFindingID creates a deterministic UUID for a finding.
// It's based on the template ID, host, and matched location.
// This ensures re-scanning the same target with the same template produces the same finding ID.
func (e *NucleiExtractor) generateFindingID(templateID, host, matchedAt string) string {
	namespace := uuid.NameSpaceOID
	// Include all identifying information to make it unique
	name := fmt.Sprintf("finding:nuclei:%s:%s:%s", templateID, host, matchedAt)
	return uuid.NewSHA1(namespace, []byte(name)).String()
}

// generateEndpointID creates a deterministic UUID for an endpoint based on its URL.
// This ensures re-scanning the same URL produces the same ID.
func (e *NucleiExtractor) generateEndpointID(url string) string {
	namespace := uuid.NameSpaceOID
	name := fmt.Sprintf("endpoint:%s", url)
	return uuid.NewSHA1(namespace, []byte(name)).String()
}

// generateEvidenceID creates a deterministic UUID for evidence.
// It's based on the parent finding ID and the evidence index.
func (e *NucleiExtractor) generateEvidenceID(findingID string, index int) string {
	namespace := uuid.NameSpaceOID
	name := fmt.Sprintf("evidence:%s:%d", findingID, index)
	return uuid.NewSHA1(namespace, []byte(name)).String()
}

// Helper to create float64 pointers for optional proto fields
func float64Ptr(f float64) *float64 {
	return &f
}
