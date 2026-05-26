package export

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"html/template"
	"strings"
	"time"

	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/finding"
)

// HTMLExporter exports findings as a professional HTML report.
// Thread-safe for concurrent use.
type HTMLExporter struct {
	// Title is the report title (default: "Security Findings Report")
	Title string

	// IncludeChart controls whether to include severity distribution chart
	IncludeChart bool
}

// NewHTMLExporter creates a new HTML exporter with defaults
func NewHTMLExporter() *HTMLExporter {
	return &HTMLExporter{
		Title:        "Security Findings Report",
		IncludeChart: true,
	}
}

// WithTitle configures a custom report title
func (e *HTMLExporter) WithTitle(title string) *HTMLExporter {
	e.Title = title
	return e
}

// Export converts findings to an HTML report
func (e *HTMLExporter) Export(ctx context.Context, findings []*finding.EnhancedFinding, opts ExportOptions) ([]byte, error) {
	// Apply filters
	filtered := ApplyFilters(findings, opts)

	// Build template data
	data := e.buildTemplateData(filtered, opts)

	// Parse and execute template
	tmpl, err := template.New("report").Funcs(templateFuncs).Parse(htmlTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("failed to execute HTML template: %w", err)
	}

	return buf.Bytes(), nil
}

// Format returns "html"
func (e *HTMLExporter) Format() string {
	return "html"
}

// ContentType returns "text/html"
func (e *HTMLExporter) ContentType() string {
	return "text/html; charset=utf-8"
}

// htmlTemplateData holds data for the HTML template
type htmlTemplateData struct {
	Title           string
	GeneratedAt     string
	TotalFindings   int
	FilteredCount   int
	Summary         SeveritySummary
	Findings        []*finding.EnhancedFinding
	IncludeEvidence bool
	IncludeChart    bool
}

// SeveritySummary provides severity distribution statistics
type SeveritySummary struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

// buildTemplateData prepares data for the HTML template
func (e *HTMLExporter) buildTemplateData(filtered []*finding.EnhancedFinding, opts ExportOptions) htmlTemplateData {
	summary := SeveritySummary{}

	for _, f := range filtered {
		switch f.Severity {
		case agent.SeverityCritical:
			summary.Critical++
		case agent.SeverityHigh:
			summary.High++
		case agent.SeverityMedium:
			summary.Medium++
		case agent.SeverityLow:
			summary.Low++
		case agent.SeverityInfo:
			summary.Info++
		}
	}

	return htmlTemplateData{
		Title:           e.Title,
		GeneratedAt:     time.Now().Format("2006-01-02 15:04:05 MST"),
		TotalFindings:   len(filtered),
		FilteredCount:   len(filtered),
		Summary:         summary,
		Findings:        filtered,
		IncludeEvidence: opts.IncludeEvidence,
		IncludeChart:    e.IncludeChart,
	}
}

// Template functions
var templateFuncs = template.FuncMap{
	"getMitreAttack": func(f *finding.EnhancedFinding) []finding.SimpleMitreMapping {
		return f.GetMitreAttack()
	},
	"getMitreAtlas": func(f *finding.EnhancedFinding) []finding.SimpleMitreMapping {
		return f.GetMitreAtlas()
	},
	"severityClass": func(severity agent.FindingSeverity) string {
		switch severity {
		case agent.SeverityCritical:
			return "severity-critical"
		case agent.SeverityHigh:
			return "severity-high"
		case agent.SeverityMedium:
			return "severity-medium"
		case agent.SeverityLow:
			return "severity-low"
		case agent.SeverityInfo:
			return "severity-info"
		default:
			return "severity-unknown"
		}
	},
	"escapeHTML": html.EscapeString,
	"joinStrings": func(items []string, sep string) string {
		return strings.Join(items, sep)
	},
	"formatTime": func(t time.Time) string {
		return t.Format("2006-01-02 15:04:05")
	},
	"mitreList": func(mappings []finding.SimpleMitreMapping) string {
		if len(mappings) == 0 {
			return "None"
		}
		var items []string
		for _, m := range mappings {
			items = append(items, fmt.Sprintf("%s (%s)", m.TechniqueID, m.TechniqueName))
		}
		return strings.Join(items, ", ")
	},
	"mul": func(a, b interface{}) float64 {
		af := toFloat64(a)
		bf := toFloat64(b)
		return af * bf
	},
	"div": func(a, b interface{}) float64 {
		af := toFloat64(a)
		bf := toFloat64(b)
		if bf == 0 {
			return 0
		}
		return af / bf
	},
}

// toFloat64 converts interface{} to float64
func toFloat64(v interface{}) float64 {
	switch n := v.(type) {
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case float64:
		return n
	case float32:
		return float64(n)
	default:
		return 0
	}
}

// HTML template with inline CSS
const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        header {
            border-bottom: 3px solid #2c3e50;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        h1 {
            color: #2c3e50;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .generated {
            color: #7f8c8d;
            font-size: 0.9em;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        .summary-card {
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #ccc;
        }
        .summary-card h3 {
            font-size: 0.9em;
            text-transform: uppercase;
            color: #7f8c8d;
            margin-bottom: 10px;
        }
        .summary-card .count {
            font-size: 2.5em;
            font-weight: bold;
        }
        .severity-critical { background: #fff5f5; border-color: #e74c3c; color: #e74c3c; }
        .severity-high { background: #fff9f5; border-color: #e67e22; color: #e67e22; }
        .severity-medium { background: #fffef5; border-color: #f39c12; color: #f39c12; }
        .severity-low { background: #f5f9ff; border-color: #3498db; color: #3498db; }
        .severity-info { background: #f5faf5; border-color: #27ae60; color: #27ae60; }
        .chart {
            margin: 30px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
        }
        .chart h2 {
            margin-bottom: 20px;
            color: #2c3e50;
        }
        .chart-bar {
            display: flex;
            align-items: center;
            margin: 10px 0;
        }
        .chart-label {
            width: 100px;
            font-weight: 600;
        }
        .chart-fill {
            height: 30px;
            background: #3498db;
            margin: 0 10px;
            border-radius: 4px;
            transition: width 0.3s ease;
        }
        .chart-value {
            min-width: 40px;
            font-weight: bold;
        }
        .findings {
            margin-top: 40px;
        }
        .findings h2 {
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.8em;
        }
        .finding {
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        .finding-header {
            padding: 20px;
            background: #f8f9fa;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }
        .finding-header:hover {
            background: #ecf0f1;
        }
        .finding-title {
            flex: 1;
        }
        .finding-title h3 {
            color: #2c3e50;
            margin-bottom: 8px;
            font-size: 1.3em;
        }
        .finding-meta {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            font-size: 0.9em;
            color: #7f8c8d;
        }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
        }
        .finding-body {
            padding: 20px;
            border-top: 1px solid #e0e0e0;
        }
        .finding-section {
            margin: 15px 0;
        }
        .finding-section h4 {
            color: #34495e;
            margin-bottom: 8px;
            font-size: 1em;
        }
        .finding-section p {
            color: #555;
            line-height: 1.8;
        }
        .evidence-list {
            list-style: none;
            padding: 0;
        }
        .evidence-item {
            background: #f8f9fa;
            padding: 12px;
            margin: 8px 0;
            border-left: 3px solid #3498db;
            border-radius: 4px;
        }
        .evidence-type {
            font-weight: 600;
            color: #2c3e50;
            margin-bottom: 4px;
        }
        .remediation {
            background: #e8f5e9;
            padding: 15px;
            border-left: 4px solid #27ae60;
            border-radius: 4px;
            margin: 15px 0;
        }
        .mitre-tags {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 8px;
        }
        .mitre-tag {
            background: #e3f2fd;
            color: #1976d2;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.85em;
            font-family: monospace;
        }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e0e0e0;
            text-align: center;
            color: #7f8c8d;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{{.Title}}</h1>
            <p class="generated">Generated: {{.GeneratedAt}}</p>
        </header>

        <div class="summary">
            <div class="summary-card severity-critical">
                <h3>Critical</h3>
                <div class="count">{{.Summary.Critical}}</div>
            </div>
            <div class="summary-card severity-high">
                <h3>High</h3>
                <div class="count">{{.Summary.High}}</div>
            </div>
            <div class="summary-card severity-medium">
                <h3>Medium</h3>
                <div class="count">{{.Summary.Medium}}</div>
            </div>
            <div class="summary-card severity-low">
                <h3>Low</h3>
                <div class="count">{{.Summary.Low}}</div>
            </div>
            <div class="summary-card severity-info">
                <h3>Info</h3>
                <div class="count">{{.Summary.Info}}</div>
            </div>
        </div>

        {{if .IncludeChart}}
        <div class="chart">
            <h2>Severity Distribution</h2>
            {{$max := .TotalFindings}}
            {{if gt .Summary.Critical 0}}
            <div class="chart-bar">
                <div class="chart-label severity-critical">Critical</div>
                <div class="chart-fill severity-critical" style="width: {{if gt $max 0}}{{mul (div .Summary.Critical $max) 100}}{{else}}0{{end}}%;"></div>
                <div class="chart-value">{{.Summary.Critical}}</div>
            </div>
            {{end}}
            {{if gt .Summary.High 0}}
            <div class="chart-bar">
                <div class="chart-label severity-high">High</div>
                <div class="chart-fill severity-high" style="width: {{if gt $max 0}}{{mul (div .Summary.High $max) 100}}{{else}}0{{end}}%;"></div>
                <div class="chart-value">{{.Summary.High}}</div>
            </div>
            {{end}}
            {{if gt .Summary.Medium 0}}
            <div class="chart-bar">
                <div class="chart-label severity-medium">Medium</div>
                <div class="chart-fill severity-medium" style="width: {{if gt $max 0}}{{mul (div .Summary.Medium $max) 100}}{{else}}0{{end}}%;"></div>
                <div class="chart-value">{{.Summary.Medium}}</div>
            </div>
            {{end}}
            {{if gt .Summary.Low 0}}
            <div class="chart-bar">
                <div class="chart-label severity-low">Low</div>
                <div class="chart-fill severity-low" style="width: {{if gt $max 0}}{{mul (div .Summary.Low $max) 100}}{{else}}0{{end}}%;"></div>
                <div class="chart-value">{{.Summary.Low}}</div>
            </div>
            {{end}}
        </div>
        {{end}}

        <div class="findings">
            <h2>Findings ({{.TotalFindings}})</h2>

            {{range .Findings}}
            <div class="finding">
                <div class="finding-header">
                    <div class="finding-title">
                        <h3>{{.Title}}</h3>
                        <div class="finding-meta">
                            <span class="badge {{severityClass .Severity}}">{{.Severity}}</span>
                            <span>{{.Category}}</span>
                            {{if .Subcategory}}<span>• {{.Subcategory}}</span>{{end}}
                            <span>• Risk: {{printf "%.1f" .RiskScore}}/10</span>
                            <span>• Confidence: {{printf "%.0f" (mul .Confidence 100)}}%</span>
                        </div>
                    </div>
                </div>
                <div class="finding-body">
                    <div class="finding-section">
                        <h4>Description</h4>
                        <p>{{escapeHTML .Description}}</p>
                    </div>

                    {{if .Remediation}}
                    <div class="remediation">
                        <h4>Remediation</h4>
                        <p>{{escapeHTML .Remediation}}</p>
                    </div>
                    {{end}}

                    {{if or (getMitreAttack .) (getMitreAtlas .)}}
                    <div class="finding-section">
                        <h4>MITRE Mappings</h4>
                        <div class="mitre-tags">
                            {{range getMitreAttack .}}
                            <span class="mitre-tag">ATT&CK: {{.TechniqueID}}</span>
                            {{end}}
                            {{range getMitreAtlas .}}
                            <span class="mitre-tag">ATLAS: {{.TechniqueID}}</span>
                            {{end}}
                        </div>
                    </div>
                    {{end}}

                    {{if and $.IncludeEvidence .Evidence}}
                    <div class="finding-section">
                        <h4>Evidence ({{len .Evidence}})</h4>
                        <ul class="evidence-list">
                            {{range .Evidence}}
                            <li class="evidence-item">
                                <div class="evidence-type">{{.Type}}</div>
                                <div>{{.Description}}</div>
                            </li>
                            {{end}}
                        </ul>
                    </div>
                    {{end}}
                </div>
            </div>
            {{end}}
        </div>

        <div class="footer">
            <p>Generated by Gibson Security Analysis Framework</p>
        </div>
    </div>
</body>
</html>`

// Ensure HTMLExporter implements Exporter interface
var _ Exporter = (*HTMLExporter)(nil)
