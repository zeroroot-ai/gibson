package extraction_test

import (
	"fmt"
	"time"

	"github.com/zero-day-ai/gibson/internal/extraction"
	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
)

// ExampleRelationshipBuilder demonstrates building relationships from a discovery result.
// This shows how a tool extractor would construct entity hierarchies after extracting
// entities from tool output.
func ExampleRelationshipBuilder() {
	// Create a relationship builder with context
	rb := extraction.NewRelationshipBuilder(
		"nmap",                      // Tool name
		"mission-run-abc123",        // Mission run ID
		time.Date(2026, 3, 24, 12, 0, 0, 0, time.UTC), // Discovery timestamp
	)

	// Simulate a discovery result from nmap
	hostID := "host-192-168-1-100"
	port443ID := "port-443-tcp"
	port80ID := "port-80-tcp"
	httpsServiceID := "service-https"
	httpServiceID := "service-http"
	apiEndpointID := "endpoint-api"

	result := &graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{
			{Id: &hostID, Ip: "192.168.1.100", Hostname: strPtr("api.example.com")},
		},
		Ports: []*graphragpb.Port{
			{Id: &port443ID, HostId: hostID, Number: 443, Protocol: "tcp", State: strPtr("open")},
			{Id: &port80ID, HostId: hostID, Number: 80, Protocol: "tcp", State: strPtr("open")},
		},
		Services: []*graphragpb.Service{
			{Id: &httpsServiceID, PortId: port443ID, Name: "https"},
			{Id: &httpServiceID, PortId: port80ID, Name: "http"},
		},
		Endpoints: []*graphragpb.Endpoint{
			{Id: &apiEndpointID, ServiceId: httpsServiceID, Url: "https://api.example.com/v1"},
		},
	}

	// Build relationships
	relationships, err := rb.BuildRelationships(result)
	if err != nil {
		fmt.Printf("Error building relationships: %v\n", err)
		return
	}

	// Validate relationships
	if err := extraction.ValidateRelationships(relationships); err != nil {
		fmt.Printf("Validation error: %v\n", err)
		return
	}

	// Display the relationship graph
	fmt.Printf("Built %d relationships:\n", len(relationships))
	for _, rel := range relationships {
		fmt.Printf("  %s -[%s]-> %s\n", rel.FromId, rel.Type, rel.ToId)
	}

	// Output:
	// Built 5 relationships:
	//   host-192-168-1-100 -[HAS_PORT]-> port-443-tcp
	//   host-192-168-1-100 -[HAS_PORT]-> port-80-tcp
	//   port-443-tcp -[RUNS_SERVICE]-> service-https
	//   port-80-tcp -[RUNS_SERVICE]-> service-http
	//   service-https -[HAS_ENDPOINT]-> endpoint-api
}

// ExampleRelationshipBuilder_withFindings demonstrates building relationships
// that include security findings.
func ExampleRelationshipBuilder_withFindings() {
	rb := extraction.NewRelationshipBuilder(
		"nuclei",
		"mission-run-def456",
		time.Date(2026, 3, 24, 13, 0, 0, 0, time.UTC),
	)

	endpointID := "endpoint-login"
	findingID := "finding-sql-injection"
	evidenceID := "evidence-request-1"
	confidence := 0.95
	category := "injection"

	result := &graphragpb.DiscoveryResult{
		Findings: []*graphragpb.Finding{
			{
				Id:         &findingID,
				Title:      "SQL Injection in login endpoint",
				Severity:   "critical",
				Confidence: &confidence,
				Category:   &category,
				ParentId:   &endpointID,
				ParentType: strPtr("endpoint"),
			},
		},
		Evidence: []*graphragpb.Evidence{
			{
				Id:        &evidenceID,
				FindingId: findingID,
				Type:      "request",
				Content:   strPtr("POST /login?id=1' OR '1'='1"),
			},
		},
	}

	relationships, _ := rb.BuildRelationships(result)

	fmt.Printf("Security finding relationships:\n")
	for _, rel := range relationships {
		fmt.Printf("  %s: %s -> %s\n", rel.Type, rel.FromId, rel.ToId)

		// Show contextual properties
		if rel.Type == "AFFECTS" {
			severity := getStringValue(rel.Properties["severity"])
			fmt.Printf("    Severity: %s\n", severity)
		}
	}

	// Output:
	// Security finding relationships:
	//   AFFECTS: finding-sql-injection -> endpoint-login
	//     Severity: critical
	//   HAS_EVIDENCE: finding-sql-injection -> evidence-request-1
}

// ExampleRelationshipBuilder_withTechnology demonstrates building technology
// associations.
func ExampleRelationshipBuilder_withTechnology() {
	rb := extraction.NewRelationshipBuilder(
		"wappalyzer",
		"mission-run-ghi789",
		time.Date(2026, 3, 24, 14, 0, 0, 0, time.UTC),
	)

	serviceID := "service-web"
	djangoID := "tech-django"
	nginxID := "tech-nginx"
	djangoVersion := "4.2.0"
	nginxVersion := "1.24.0"

	result := &graphragpb.DiscoveryResult{
		Technologies: []*graphragpb.Technology{
			{
				Id:         &djangoID,
				Name:       "Django",
				Version:    &djangoVersion,
				Category:   strPtr("web-framework"),
				ParentId:   &serviceID,
				ParentType: strPtr("service"),
			},
			{
				Id:         &nginxID,
				Name:       "Nginx",
				Version:    &nginxVersion,
				Category:   strPtr("web-server"),
				ParentId:   &serviceID,
				ParentType: strPtr("service"),
			},
		},
	}

	relationships, _ := rb.BuildRelationships(result)

	fmt.Printf("Technology stack:\n")
	for _, rel := range relationships {
		techName := getStringValue(rel.Properties["technology_name"])
		techVersion := getStringValue(rel.Properties["technology_version"])
		fmt.Printf("  %s uses %s %s\n", rel.FromId, techName, techVersion)
	}

	// Output:
	// Technology stack:
	//   service-web uses Django 4.2.0
	//   service-web uses Nginx 1.24.0
}

// ExampleRelationshipBuilder_provenanceTracking demonstrates how provenance
// properties enable traceability.
func ExampleRelationshipBuilder_provenanceTracking() {
	rb := extraction.NewRelationshipBuilder(
		"httpx",
		"mission-run-jkl012",
		time.Date(2026, 3, 24, 15, 30, 0, 0, time.UTC),
	)

	hostID := "host-example"
	portID := "port-443"

	result := &graphragpb.DiscoveryResult{
		Ports: []*graphragpb.Port{
			{Id: &portID, HostId: hostID, Number: 443, Protocol: "tcp"},
		},
	}

	relationships, _ := rb.BuildRelationships(result)

	for _, rel := range relationships {
		fmt.Printf("Relationship: %s -> %s\n", rel.FromId, rel.ToId)
		fmt.Printf("  Discovered by: %s\n", getStringValue(rel.Properties["discovered_by"]))
		fmt.Printf("  Mission run: %s\n", getStringValue(rel.Properties["mission_run_id"]))
		timestamp := getTimestampValue(rel.Properties["discovered_at"])
		fmt.Printf("  Has timestamp: %v\n", timestamp > 0)
	}

	// Output:
	// Relationship: host-example -> port-443
	//   Discovered by: httpx
	//   Mission run: mission-run-jkl012
	//   Has timestamp: true
}

// Helper functions for examples

func strPtr(s string) *string {
	return &s
}

func getStringValue(v *graphragpb.Value) string {
	if v == nil {
		return ""
	}
	if sv, ok := v.Kind.(*graphragpb.Value_StringValue); ok {
		return sv.StringValue
	}
	return ""
}

func getTimestampValue(v *graphragpb.Value) int64 {
	if v == nil {
		return 0
	}
	if tv, ok := v.Kind.(*graphragpb.Value_TimestampValue); ok {
		return tv.TimestampValue
	}
	return 0
}
