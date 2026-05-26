package export

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/finding"
	"github.com/zeroroot-ai/gibson/internal/types"
	sdkSecurity "github.com/zeroroot-ai/sdk/finding/security"
)

// createTestFindings creates a set of test findings for export testing
func createTestFindings() []*finding.EnhancedFinding {
	now := time.Now()
	targetID := types.NewID()

	// Create test findings with security metadata stored in Metadata field
	finding1 := &finding.EnhancedFinding{
		Finding: agent.Finding{
			ID:          types.NewID(),
			Title:       "SQL Injection in Login Form",
			Description: "User input is not properly sanitized before being used in SQL queries",
			Severity:    agent.SeverityCritical,
			Confidence:  0.95,
			Category:    "injection",
			TargetID:    &targetID,
			Evidence: []agent.Evidence{
				{
					Type:        "request",
					Description: "Malicious SQL payload submitted",
					Data: map[string]any{
						"payload": "' OR '1'='1",
					},
					Timestamp: now,
				},
			},
			CWE:       []string{"CWE-89"},
			Metadata:  make(map[string]any),
			CreatedAt: now,
		},
		MissionID:       types.NewID(),
		AgentName:       "sql-fuzzer",
		Subcategory:     "blind_sqli",
		Status:          finding.StatusOpen,
		RiskScore:       9.5,
		Remediation:     "Use parameterized queries and input validation",
		References:      []string{"https://owasp.org/www-community/attacks/SQL_Injection"},
		OccurrenceCount: 1,
		UpdatedAt:       now,
	}
	// Store MITRE Attack in Metadata
	finding1.Finding.Metadata[sdkSecurity.MetaKeyMitreAttack] = sdkSecurity.MitreMapping{
		TechniqueID:   "T1190",
		TechniqueName: "Exploit Public-Facing Application",
		TacticName:    "Initial Access",
	}

	return []*finding.EnhancedFinding{
		finding1,
		func() *finding.EnhancedFinding {
			finding2 := &finding.EnhancedFinding{
				Finding: agent.Finding{
					ID:          types.NewID(),
					Title:       "Cross-Site Scripting (XSS)",
					Description: "Reflected XSS vulnerability in search parameter",
					Severity:    agent.SeverityHigh,
					Confidence:  0.90,
					Category:    "xss",
					TargetID:    &targetID,
					Evidence: []agent.Evidence{
						{
							Type:        "response",
							Description: "Script executed in browser",
							Data: map[string]any{
								"script": "<script>alert('XSS')</script>",
							},
							Timestamp: now,
						},
					},
					CWE:       []string{"CWE-79"},
					Metadata:  make(map[string]any),
					CreatedAt: now.Add(-1 * time.Hour),
				},
				MissionID:       types.NewID(),
				AgentName:       "xss-scanner",
				Subcategory:     "reflected",
				Status:          finding.StatusConfirmed,
				RiskScore:       7.5,
				Remediation:     "Implement output encoding and Content Security Policy",
				References:      []string{"https://owasp.org/www-community/attacks/xss/"},
				OccurrenceCount: 3,
				UpdatedAt:       now,
			}
			// Store MITRE Attack in Metadata
			finding2.Finding.Metadata[sdkSecurity.MetaKeyMitreAttack] = sdkSecurity.MitreMapping{
				TechniqueID:   "T1189",
				TechniqueName: "Drive-by Compromise",
				TacticName:    "Initial Access",
			}
			return finding2
		}(),
		{
			Finding: agent.Finding{
				ID:          types.NewID(),
				Title:       "Information Disclosure",
				Description: "Server version exposed in HTTP headers",
				Severity:    agent.SeverityLow,
				Confidence:  1.0,
				Category:    "information_disclosure",
				TargetID:    &targetID,
				Evidence:    []agent.Evidence{},
				CWE:         []string{"CWE-200"},
				Metadata:    make(map[string]any),
				CreatedAt:   now.Add(-2 * time.Hour),
			},
			MissionID:       types.NewID(),
			AgentName:       "header-scanner",
			Subcategory:     "server_version",
			Status:          finding.StatusOpen,
			RiskScore:       2.0,
			Remediation:     "Remove or obscure server version headers",
			OccurrenceCount: 1,
			UpdatedAt:       now,
		},
		{
			Finding: agent.Finding{
				ID:          types.NewID(),
				Title:       "False Positive Test",
				Description: "This is a false positive for testing",
				Severity:    agent.SeverityMedium,
				Confidence:  0.5,
				Category:    "test",
				Metadata:    make(map[string]any),
				CreatedAt:   now.Add(-3 * time.Hour),
			},
			MissionID:       types.NewID(),
			AgentName:       "test-agent",
			Status:          finding.StatusFalsePositive,
			RiskScore:       0.0,
			OccurrenceCount: 1,
			UpdatedAt:       now,
		},
	}
}

// TestApplyFilters verifies filtering logic
func TestApplyFilters(t *testing.T) {
	findings := createTestFindings()

	t.Run("no filters returns all findings", func(t *testing.T) {
		opts := DefaultExportOptions()
		filtered := ApplyFilters(findings, opts)
		assert.Len(t, filtered, 3, "should return 3 findings (excluding false positive by default)")
	})

	t.Run("filter by min severity", func(t *testing.T) {
		opts := DefaultExportOptions()
		minSev := agent.SeverityHigh
		opts.MinSeverity = &minSev

		filtered := ApplyFilters(findings, opts)
		assert.Len(t, filtered, 2, "should return only critical and high severity")

		for _, f := range filtered {
			assert.True(t, f.Severity == agent.SeverityCritical || f.Severity == agent.SeverityHigh)
		}
	})

	t.Run("filter by date range", func(t *testing.T) {
		opts := DefaultExportOptions()
		dateFrom := time.Now().Add(-90 * time.Minute)
		opts.DateFrom = &dateFrom

		filtered := ApplyFilters(findings, opts)
		assert.Greater(t, len(filtered), 0, "should return findings within date range")

		for _, f := range filtered {
			assert.True(t, f.CreatedAt.After(dateFrom) || f.CreatedAt.Equal(dateFrom))
		}
	})

	t.Run("include resolved findings", func(t *testing.T) {
		opts := DefaultExportOptions()
		opts.IncludeResolved = true

		filtered := ApplyFilters(findings, opts)
		assert.Len(t, filtered, 4, "should include false positive when IncludeResolved is true")
	})

	t.Run("filter by category", func(t *testing.T) {
		opts := DefaultExportOptions()
		opts.Categories = []string{"injection", "xss"}

		filtered := ApplyFilters(findings, opts)
		assert.Len(t, filtered, 2, "should return only injection and xss findings")

		for _, f := range filtered {
			assert.Contains(t, []string{"injection", "xss"}, f.Category)
		}
	})

	t.Run("filter by confidence", func(t *testing.T) {
		opts := DefaultExportOptions()
		minConf := 0.9
		opts.MinConfidence = &minConf

		filtered := ApplyFilters(findings, opts)

		for _, f := range filtered {
			assert.GreaterOrEqual(t, f.Confidence, 0.9)
		}
	})

	t.Run("combined filters", func(t *testing.T) {
		opts := DefaultExportOptions()
		minSev := agent.SeverityHigh
		opts.MinSeverity = &minSev
		opts.Categories = []string{"injection", "xss"}

		filtered := ApplyFilters(findings, opts)
		assert.Len(t, filtered, 2, "should apply both severity and category filters")
	})
}

// TestJSONExporter verifies JSON export
func TestJSONExporter(t *testing.T) {
	findings := createTestFindings()
	ctx := context.Background()

	t.Run("export produces valid JSON", func(t *testing.T) {
		exporter := NewJSONExporter(true)
		opts := DefaultExportOptions()

		data, err := exporter.Export(ctx, findings, opts)
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		// Verify it's valid JSON
		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		// Check structure
		assert.Contains(t, result, "findings")
		assert.Contains(t, result, "metadata")
	})

	t.Run("format and content type", func(t *testing.T) {
		exporter := NewJSONExporter(false)
		assert.Equal(t, "json", exporter.Format())
		assert.Equal(t, "application/json", exporter.ContentType())
	})

	t.Run("redaction removes sensitive data", func(t *testing.T) {
		exporter := NewJSONExporter(true)
		opts := DefaultExportOptions()
		opts.RedactSensitive = true

		// Add sensitive metadata
		findings[0].Metadata = map[string]any{
			"password": "secret123",
			"api_key":  "key123",
			"normal":   "data",
		}

		data, err := exporter.Export(ctx, findings, opts)
		require.NoError(t, err)

		// Verify sensitive data is removed
		dataStr := string(data)
		assert.NotContains(t, dataStr, "secret123")
		assert.NotContains(t, dataStr, "key123")
	})

	t.Run("exclude evidence option", func(t *testing.T) {
		exporter := NewJSONExporter(true)
		opts := DefaultExportOptions()
		opts.IncludeEvidence = false

		data, err := exporter.Export(ctx, findings, opts)
		require.NoError(t, err)

		var result struct {
			Findings []struct {
				Evidence []agent.Evidence `json:"evidence"`
			} `json:"findings"`
		}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		// Evidence should be stripped
		for _, f := range result.Findings {
			assert.Nil(t, f.Evidence)
		}
	})
}

// TestSARIFExporter verifies SARIF export
func TestSARIFExporter(t *testing.T) {
	findings := createTestFindings()
	ctx := context.Background()

	t.Run("export produces valid SARIF", func(t *testing.T) {
		exporter := NewSARIFExporter()
		opts := DefaultExportOptions()

		data, err := exporter.Export(ctx, findings, opts)
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		// Verify it's valid JSON
		var sarifLog SarifLog
		err = json.Unmarshal(data, &sarifLog)
		require.NoError(t, err)

		// Verify SARIF structure
		assert.Equal(t, "2.1.0", sarifLog.Version)
		assert.Contains(t, sarifLog.Schema, "sarif-schema-2.1.0.json")
		assert.Len(t, sarifLog.Runs, 1)
		assert.Equal(t, "Gibson", sarifLog.Runs[0].Tool.Driver.Name)
	})

	t.Run("severity mapped to SARIF levels", func(t *testing.T) {
		exporter := NewSARIFExporter()
		opts := DefaultExportOptions()

		data, err := exporter.Export(ctx, findings, opts)
		require.NoError(t, err)

		var sarifLog SarifLog
		err = json.Unmarshal(data, &sarifLog)
		require.NoError(t, err)

		results := sarifLog.Runs[0].Results

		// Find critical finding
		for _, r := range results {
			if strings.Contains(r.Message.Text, "SQL Injection") {
				assert.Equal(t, "error", r.Level, "critical should map to error")
			}
		}
	})

	t.Run("MITRE mappings in properties", func(t *testing.T) {
		exporter := NewSARIFExporter()
		opts := DefaultExportOptions()

		data, err := exporter.Export(ctx, findings, opts)
		require.NoError(t, err)

		var sarifLog SarifLog
		err = json.Unmarshal(data, &sarifLog)
		require.NoError(t, err)

		results := sarifLog.Runs[0].Results

		// Find finding with MITRE mapping
		for _, r := range results {
			if props, ok := r.Properties["mitre_attack_techniques"]; ok {
				techniques := props.([]interface{})
				assert.Greater(t, len(techniques), 0, "should have MITRE techniques")
			}
		}
	})

	t.Run("format and content type", func(t *testing.T) {
		exporter := NewSARIFExporter()
		assert.Equal(t, "sarif", exporter.Format())
		assert.Equal(t, "application/sarif+json", exporter.ContentType())
	})
}

// TestCSVExporter verifies CSV export
func TestCSVExporter(t *testing.T) {
	findings := createTestFindings()
	ctx := context.Background()

	t.Run("export produces valid CSV", func(t *testing.T) {
		exporter := NewCSVExporter()
		opts := DefaultExportOptions()

		data, err := exporter.Export(ctx, findings, opts)
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		// Parse CSV
		reader := csv.NewReader(strings.NewReader(string(data)))
		records, err := reader.ReadAll()
		require.NoError(t, err)

		// Should have header + data rows
		assert.GreaterOrEqual(t, len(records), 2, "should have header and at least one data row")

		// Verify header
		header := records[0]
		assert.Contains(t, header, "ID")
		assert.Contains(t, header, "Title")
		assert.Contains(t, header, "Severity")
	})

	t.Run("custom columns", func(t *testing.T) {
		exporter := NewCSVExporter().WithColumns("ID", "Title", "Severity")
		opts := DefaultExportOptions()

		data, err := exporter.Export(ctx, findings, opts)
		require.NoError(t, err)

		reader := csv.NewReader(strings.NewReader(string(data)))
		records, err := reader.ReadAll()
		require.NoError(t, err)

		// Verify only specified columns
		header := records[0]
		assert.Len(t, header, 3)
		assert.Equal(t, "ID", header[0])
		assert.Equal(t, "Title", header[1])
		assert.Equal(t, "Severity", header[2])
	})

	t.Run("custom delimiter", func(t *testing.T) {
		exporter := NewCSVExporter().WithDelimiter('\t')
		opts := DefaultExportOptions()

		data, err := exporter.Export(ctx, findings, opts)
		require.NoError(t, err)

		// Should contain tabs instead of commas
		assert.Contains(t, string(data), "\t")
	})

	t.Run("format and content type", func(t *testing.T) {
		exporter := NewCSVExporter()
		assert.Equal(t, "csv", exporter.Format())
		assert.Equal(t, "text/csv", exporter.ContentType())
	})
}

// TestHTMLExporter verifies HTML export
func TestHTMLExporter(t *testing.T) {
	findings := createTestFindings()
	ctx := context.Background()

	t.Run("export produces valid HTML", func(t *testing.T) {
		exporter := NewHTMLExporter()
		opts := DefaultExportOptions()

		data, err := exporter.Export(ctx, findings, opts)
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		html := string(data)

		// Verify HTML structure
		assert.Contains(t, html, "<!DOCTYPE html>")
		assert.Contains(t, html, "<html")
		assert.Contains(t, html, "</html>")
		assert.Contains(t, html, "<head>")
		assert.Contains(t, html, "<body>")
	})

	t.Run("contains report title", func(t *testing.T) {
		exporter := NewHTMLExporter().WithTitle("Custom Report Title")
		opts := DefaultExportOptions()

		data, err := exporter.Export(ctx, findings, opts)
		require.NoError(t, err)

		html := string(data)
		assert.Contains(t, html, "Custom Report Title")
	})

	t.Run("contains severity summary", func(t *testing.T) {
		exporter := NewHTMLExporter()
		opts := DefaultExportOptions()

		data, err := exporter.Export(ctx, findings, opts)
		require.NoError(t, err)

		html := string(data)
		assert.Contains(t, html, "Critical")
		assert.Contains(t, html, "High")
		assert.Contains(t, html, "Medium")
		assert.Contains(t, html, "Low")
	})

	t.Run("contains findings", func(t *testing.T) {
		exporter := NewHTMLExporter()
		opts := DefaultExportOptions()

		data, err := exporter.Export(ctx, findings, opts)
		require.NoError(t, err)

		html := string(data)
		assert.Contains(t, html, "SQL Injection in Login Form")
		assert.Contains(t, html, "Cross-Site Scripting")
	})

	t.Run("format and content type", func(t *testing.T) {
		exporter := NewHTMLExporter()
		assert.Equal(t, "html", exporter.Format())
		assert.Contains(t, exporter.ContentType(), "text/html")
	})
}

// TestMarkdownExporter verifies Markdown export
func TestMarkdownExporter(t *testing.T) {
	findings := createTestFindings()
	ctx := context.Background()

	t.Run("export produces valid Markdown", func(t *testing.T) {
		exporter := NewMarkdownExporter()
		opts := DefaultExportOptions()

		data, err := exporter.Export(ctx, findings, opts)
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		md := string(data)

		// Verify Markdown structure
		assert.Contains(t, md, "# Security Findings Report")
		assert.Contains(t, md, "## Summary")
		assert.Contains(t, md, "## Findings")
	})

	t.Run("contains table of contents", func(t *testing.T) {
		exporter := NewMarkdownExporter()
		opts := DefaultExportOptions()

		data, err := exporter.Export(ctx, findings, opts)
		require.NoError(t, err)

		md := string(data)
		assert.Contains(t, md, "## Table of Contents")
	})

	t.Run("contains summary table", func(t *testing.T) {
		exporter := NewMarkdownExporter()
		opts := DefaultExportOptions()

		data, err := exporter.Export(ctx, findings, opts)
		require.NoError(t, err)

		md := string(data)
		assert.Contains(t, md, "| Severity | Count |")
		assert.Contains(t, md, "critical")
		assert.Contains(t, md, "high")
	})

	t.Run("contains findings with metadata", func(t *testing.T) {
		exporter := NewMarkdownExporter()
		opts := DefaultExportOptions()

		data, err := exporter.Export(ctx, findings, opts)
		require.NoError(t, err)

		md := string(data)
		assert.Contains(t, md, "SQL Injection in Login Form")
		assert.Contains(t, md, "**Severity**")
		assert.Contains(t, md, "**Risk Score**")
	})

	t.Run("contains MITRE mappings", func(t *testing.T) {
		exporter := NewMarkdownExporter()
		opts := DefaultExportOptions()

		data, err := exporter.Export(ctx, findings, opts)
		require.NoError(t, err)

		md := string(data)
		assert.Contains(t, md, "MITRE Mappings")
		assert.Contains(t, md, "T1190")
	})

	t.Run("format and content type", func(t *testing.T) {
		exporter := NewMarkdownExporter()
		assert.Equal(t, "markdown", exporter.Format())
		assert.Contains(t, exporter.ContentType(), "text/markdown")
	})
}

// TestRedactSensitiveData verifies redaction functionality
func TestRedactSensitiveData(t *testing.T) {
	findings := createTestFindings()

	// Add sensitive data
	findings[0].Metadata = map[string]any{
		"password":   "secret123",
		"api_key":    "key-abc-123",
		"token":      "bearer-token",
		"safe_field": "public-data",
	}

	findings[0].Evidence[0].Data = map[string]any{
		"password": "pass123",
		"username": "user",
	}

	// Apply redaction
	RedactSensitiveData(findings)

	// Verify sensitive fields removed from metadata
	assert.NotContains(t, findings[0].Metadata, "password")
	assert.NotContains(t, findings[0].Metadata, "api_key")
	assert.NotContains(t, findings[0].Metadata, "token")
	assert.Contains(t, findings[0].Metadata, "safe_field")

	// Verify sensitive fields redacted in evidence
	assert.Equal(t, "[REDACTED]", findings[0].Evidence[0].Data["password"])
	assert.Equal(t, "user", findings[0].Evidence[0].Data["username"])
}

// TestEmptyFindings verifies exporters handle empty input correctly
func TestEmptyFindings(t *testing.T) {
	ctx := context.Background()
	opts := DefaultExportOptions()
	empty := []*finding.EnhancedFinding{}

	exporters := []Exporter{
		NewJSONExporter(true),
		NewSARIFExporter(),
		NewCSVExporter(),
		NewHTMLExporter(),
		NewMarkdownExporter(),
	}

	for _, exporter := range exporters {
		t.Run(exporter.Format(), func(t *testing.T) {
			data, err := exporter.Export(ctx, empty, opts)
			require.NoError(t, err, "should handle empty findings without error")
			assert.NotEmpty(t, data, "should produce output even with no findings")
		})
	}
}
