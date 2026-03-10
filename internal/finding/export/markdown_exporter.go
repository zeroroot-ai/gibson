package export

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/finding"
)

// MarkdownExporter exports findings in GitHub-flavored Markdown format.
// Thread-safe for concurrent use.
type MarkdownExporter struct {
	// Title is the report title
	Title string

	// IncludeTOC controls whether to include a table of contents
	IncludeTOC bool
}

// NewMarkdownExporter creates a new Markdown exporter with defaults
func NewMarkdownExporter() *MarkdownExporter {
	return &MarkdownExporter{
		Title:      "Security Findings Report",
		IncludeTOC: true,
	}
}

// WithTitle configures a custom report title
func (m *MarkdownExporter) WithTitle(title string) *MarkdownExporter {
	m.Title = title
	return m
}

// Export converts findings to Markdown format
func (m *MarkdownExporter) Export(ctx context.Context, findings []*finding.EnhancedFinding, opts ExportOptions) ([]byte, error) {
	// Apply filters
	filtered := ApplyFilters(findings, opts)

	var buf bytes.Buffer

	// Write title and metadata
	m.writeHeader(&buf, len(filtered))

	// Write summary table
	m.writeSummaryTable(&buf, filtered)

	// Write table of contents if enabled
	if m.IncludeTOC {
		m.writeTOC(&buf, filtered)
	}

	// Write findings
	m.writeFindings(&buf, filtered, opts)

	return buf.Bytes(), nil
}

// Format returns "markdown"
func (m *MarkdownExporter) Format() string {
	return "markdown"
}

// ContentType returns "text/markdown"
func (m *MarkdownExporter) ContentType() string {
	return "text/markdown; charset=utf-8"
}

// writeHeader writes the report header
func (m *MarkdownExporter) writeHeader(buf *bytes.Buffer, count int) {
	buf.WriteString("# ")
	buf.WriteString(m.Title)
	buf.WriteString("\n\n")

	buf.WriteString("**Generated:** ")
	buf.WriteString(time.Now().Format("2006-01-02 15:04:05 MST"))
	buf.WriteString("\n\n")

	buf.WriteString("**Total Findings:** ")
	buf.WriteString(fmt.Sprintf("%d", count))
	buf.WriteString("\n\n")

	buf.WriteString("---\n\n")
}

// writeSummaryTable writes a summary table with severity counts
func (m *MarkdownExporter) writeSummaryTable(buf *bytes.Buffer, findings []*finding.EnhancedFinding) {
	buf.WriteString("## Summary\n\n")

	// Calculate severity counts
	counts := make(map[agent.FindingSeverity]int)
	for _, f := range findings {
		counts[f.Severity]++
	}

	buf.WriteString("| Severity | Count |\n")
	buf.WriteString("|----------|-------|\n")

	severities := []agent.FindingSeverity{
		agent.SeverityCritical,
		agent.SeverityHigh,
		agent.SeverityMedium,
		agent.SeverityLow,
		agent.SeverityInfo,
	}

	for _, sev := range severities {
		count := counts[sev]
		if count > 0 {
			buf.WriteString(fmt.Sprintf("| %s %s | %d |\n",
				severityEmoji(sev),
				sev,
				count))
		}
	}

	buf.WriteString("\n")
}

// writeTOC writes a table of contents
func (m *MarkdownExporter) writeTOC(buf *bytes.Buffer, findings []*finding.EnhancedFinding) {
	buf.WriteString("## Table of Contents\n\n")

	for i, f := range findings {
		// Create anchor-friendly title
		anchor := strings.ToLower(f.Title)
		anchor = strings.ReplaceAll(anchor, " ", "-")
		anchor = strings.ReplaceAll(anchor, "/", "-")

		buf.WriteString(fmt.Sprintf("%d. [%s](#%d-%s) - %s\n",
			i+1,
			f.Title,
			i+1,
			anchor,
			f.Severity))
	}

	buf.WriteString("\n---\n\n")
}

// writeFindings writes all findings in detail
func (m *MarkdownExporter) writeFindings(buf *bytes.Buffer, findings []*finding.EnhancedFinding, opts ExportOptions) {
	buf.WriteString("## Findings\n\n")

	for i, f := range findings {
		m.writeFinding(buf, f, i+1, opts)
		buf.WriteString("\n---\n\n")
	}
}

// writeFinding writes a single finding
func (m *MarkdownExporter) writeFinding(buf *bytes.Buffer, f *finding.EnhancedFinding, num int, opts ExportOptions) {
	// Anchor-friendly title for TOC links
	anchor := strings.ToLower(f.Title)
	anchor = strings.ReplaceAll(anchor, " ", "-")
	anchor = strings.ReplaceAll(anchor, "/", "-")

	// Title with severity emoji
	buf.WriteString(fmt.Sprintf("### %d. %s %s {#%d-%s}\n\n",
		num,
		severityEmoji(f.Severity),
		f.Title,
		num,
		anchor))

	// Metadata table
	buf.WriteString("| Attribute | Value |\n")
	buf.WriteString("|-----------|-------|\n")
	buf.WriteString(fmt.Sprintf("| **Severity** | %s %s |\n", severityEmoji(f.Severity), f.Severity))
	buf.WriteString(fmt.Sprintf("| **Category** | %s |\n", f.Category))
	if f.Subcategory != "" {
		buf.WriteString(fmt.Sprintf("| **Subcategory** | %s |\n", f.Subcategory))
	}
	buf.WriteString(fmt.Sprintf("| **Risk Score** | %.1f/10 |\n", f.RiskScore))
	buf.WriteString(fmt.Sprintf("| **Confidence** | %.0f%% |\n", f.Confidence*100))
	buf.WriteString(fmt.Sprintf("| **Status** | %s |\n", statusBadge(f.Status)))
	buf.WriteString(fmt.Sprintf("| **Occurrence Count** | %d |\n", f.OccurrenceCount))
	buf.WriteString(fmt.Sprintf("| **Created** | %s |\n", f.CreatedAt.Format("2006-01-02 15:04:05")))
	buf.WriteString("\n")

	// Description
	buf.WriteString("#### Description\n\n")
	buf.WriteString(f.Description)
	buf.WriteString("\n\n")

	// MITRE mappings
	mitreAttack := f.GetMitreAttack()
	mitreAtlas := f.GetMitreAtlas()

	if len(mitreAttack) > 0 || len(mitreAtlas) > 0 {
		buf.WriteString("#### MITRE Mappings\n\n")

		if len(mitreAttack) > 0 {
			buf.WriteString("**ATT&CK Techniques:**\n\n")
			for _, m := range mitreAttack {
				buf.WriteString(fmt.Sprintf("- `%s` - %s", m.TechniqueID, m.TechniqueName))
				if m.Tactic != "" {
					buf.WriteString(fmt.Sprintf(" (Tactic: %s)", m.Tactic))
				}
				buf.WriteString("\n")
			}
			buf.WriteString("\n")
		}

		if len(mitreAtlas) > 0 {
			buf.WriteString("**ATLAS Techniques:**\n\n")
			for _, m := range mitreAtlas {
				buf.WriteString(fmt.Sprintf("- `%s` - %s\n", m.TechniqueID, m.TechniqueName))
			}
			buf.WriteString("\n")
		}
	}

	// CWE
	if len(f.CWE) > 0 {
		buf.WriteString("#### CWE\n\n")
		for _, cwe := range f.CWE {
			buf.WriteString(fmt.Sprintf("- `%s`\n", cwe))
		}
		buf.WriteString("\n")
	}

	// CVSS
	if f.CVSS != nil {
		buf.WriteString("#### CVSS\n\n")
		buf.WriteString(fmt.Sprintf("- **Version:** %s\n", f.CVSS.Version))
		buf.WriteString(fmt.Sprintf("- **Vector:** `%s`\n", f.CVSS.Vector))
		buf.WriteString(fmt.Sprintf("- **Score:** %.1f\n\n", f.CVSS.Score))
	}

	// Remediation
	if f.Remediation != "" {
		buf.WriteString("#### Remediation\n\n")
		buf.WriteString("> ")
		buf.WriteString(strings.ReplaceAll(f.Remediation, "\n", "\n> "))
		buf.WriteString("\n\n")
	}

	// References
	if len(f.References) > 0 {
		buf.WriteString("#### References\n\n")
		for _, ref := range f.References {
			buf.WriteString(fmt.Sprintf("- <%s>\n", ref))
		}
		buf.WriteString("\n")
	}

	// Reproduction steps
	if len(f.ReproSteps) > 0 {
		buf.WriteString("#### Reproduction Steps\n\n")
		for _, step := range f.ReproSteps {
			buf.WriteString(fmt.Sprintf("%d. **%s**\n", step.StepNumber, step.Description))
			if step.ExpectedResult != "" {
				buf.WriteString(fmt.Sprintf("   - Expected: %s\n", step.ExpectedResult))
			}
		}
		buf.WriteString("\n")
	}

	// Evidence
	if opts.IncludeEvidence && len(f.Evidence) > 0 {
		buf.WriteString(fmt.Sprintf("#### Evidence (%d)\n\n", len(f.Evidence)))

		for i, e := range f.Evidence {
			buf.WriteString(fmt.Sprintf("**Evidence %d: %s**\n\n", i+1, e.Type))
			buf.WriteString(e.Description)
			buf.WriteString("\n\n")

			// Include evidence data if present
			if e.Data != nil && len(e.Data) > 0 {
				buf.WriteString("```json\n")
				// Simple JSON representation (could use proper JSON marshaling)
				for k, v := range e.Data {
					buf.WriteString(fmt.Sprintf("  %q: %v\n", k, v))
				}
				buf.WriteString("```\n\n")
			}
		}
	}

	// Related findings
	if len(f.RelatedIDs) > 0 {
		buf.WriteString(fmt.Sprintf("#### Related Findings (%d)\n\n", len(f.RelatedIDs)))
		for _, id := range f.RelatedIDs {
			buf.WriteString(fmt.Sprintf("- `%s`\n", id.String()))
		}
		buf.WriteString("\n")
	}
}

// severityEmoji returns an emoji for each severity level
func severityEmoji(severity agent.FindingSeverity) string {
	switch severity {
	case agent.SeverityCritical:
		return "🔴"
	case agent.SeverityHigh:
		return "🟠"
	case agent.SeverityMedium:
		return "🟡"
	case agent.SeverityLow:
		return "🔵"
	case agent.SeverityInfo:
		return "🟢"
	default:
		return "⚪"
	}
}

// statusBadge returns a badge for the finding status
func statusBadge(status finding.FindingStatus) string {
	switch status {
	case finding.StatusOpen:
		return "🔓 Open"
	case finding.StatusConfirmed:
		return "✅ Confirmed"
	case finding.StatusResolved:
		return "✔️ Resolved"
	case finding.StatusFalsePositive:
		return "❌ False Positive"
	default:
		return string(status)
	}
}

// Ensure MarkdownExporter implements Exporter interface
var _ Exporter = (*MarkdownExporter)(nil)
