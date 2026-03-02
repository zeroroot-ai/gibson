package report

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/types"
)

// Generator creates reports using an LLM to synthesize mission data.
type Generator struct {
	aggregator DataAggregator
	llm        llm.LLMProvider
	redactor   Redactor
	store      Store
	logger     *slog.Logger
}

// GeneratorConfig contains dependencies for the Generator.
type GeneratorConfig struct {
	Aggregator DataAggregator
	LLM        llm.LLMProvider
	Redactor   Redactor // Optional, can be nil
	Store      Store    // Optional, can be nil (reports won't be persisted)
	Logger     *slog.Logger
}

// NewGenerator creates a new LLM-based report generator.
func NewGenerator(cfg GeneratorConfig) (*Generator, error) {
	if cfg.Aggregator == nil {
		return nil, fmt.Errorf("aggregator is required")
	}
	if cfg.LLM == nil {
		return nil, fmt.Errorf("llm provider is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return &Generator{
		aggregator: cfg.Aggregator,
		llm:        cfg.LLM,
		redactor:   cfg.Redactor,
		store:      cfg.Store,
		logger:     cfg.Logger,
	}, nil
}

// GenerateRequest specifies what report to generate.
type GenerateRequest struct {
	MissionID       types.ID
	Type            ReportType
	Format          ReportFormat // Currently only markdown is generated, others could be converted
	RedactSensitive bool
	CustomPrompt    string // Optional additional instructions for the LLM
}

// GenerateResult contains the generated report.
type GenerateResult struct {
	Report  *Report
	Content string // The markdown/text content
}

// Generate creates a report for the given mission using the LLM.
func (g *Generator) Generate(ctx context.Context, req GenerateRequest) (*GenerateResult, error) {
	g.logger.Info("generating report",
		"mission_id", req.MissionID,
		"type", req.Type,
	)

	// 1. Aggregate data from all sources
	opts := DefaultAggregateOptions()
	data, err := g.aggregator.Aggregate(ctx, req.MissionID, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate data: %w", err)
	}

	// 2. Build the prompt based on report type
	prompt, err := g.buildPrompt(req.Type, data, req.CustomPrompt)
	if err != nil {
		return nil, fmt.Errorf("failed to build prompt: %w", err)
	}

	// 3. Call LLM to generate the report
	llmReq := llm.CompletionRequest{
		Model:       "", // Use default model from provider
		Temperature: 0.3,
		MaxTokens:   8000,
		Messages: []llm.Message{
			llm.NewUserMessage(prompt),
		},
		SystemPrompt: g.systemPrompt(req.Type),
	}

	resp, err := g.llm.Complete(ctx, llmReq)
	if err != nil {
		return nil, fmt.Errorf("llm completion failed: %w", err)
	}

	content := resp.Message.Content

	// 4. Optionally redact sensitive data
	if req.RedactSensitive && g.redactor != nil {
		content = g.redactor.RedactString(content)
	}

	// 5. Build report metadata
	report := &Report{
		ID:          types.NewID(),
		MissionID:   req.MissionID,
		Type:        req.Type,
		Format:      FormatMarkdown,
		Title:       g.generateTitle(req.Type, data),
		Summary:     g.extractSummary(content),
		GeneratedAt: time.Now(),
		GeneratedBy: "gibson-llm",
		Metadata:    g.buildMetadata(data),
	}

	// 6. Optionally persist the report
	if g.store != nil {
		if err := g.store.Save(ctx, report, []byte(content)); err != nil {
			g.logger.Warn("failed to save report", "error", err)
			// Don't fail the request, just log
		}
	}

	return &GenerateResult{
		Report:  report,
		Content: content,
	}, nil
}

// systemPrompt returns the system prompt for the LLM based on report type.
func (g *Generator) systemPrompt(reportType ReportType) string {
	base := `You are a security report writer for Gibson, an AI-powered security assessment framework.
Generate clear, professional security reports based on the provided assessment data.
Use markdown formatting. Include Mermaid diagrams where helpful for visualizing attack chains.
Be concise but thorough. Focus on actionable insights.`

	switch reportType {
	case ReportTypeExecutive:
		return base + `

This is an EXECUTIVE SUMMARY for non-technical stakeholders.
- Use business language, avoid technical jargon
- Focus on business impact and risk
- Provide clear recommendations
- Keep it to 1-2 pages equivalent
- Include a risk score summary`

	case ReportTypeTechnical:
		return base + `

This is a TECHNICAL REPORT for security engineers.
- Include full technical details
- Show evidence and reproduction steps
- Include CVSS scores and CWE references
- Provide specific remediation guidance with code examples where applicable
- Use Mermaid diagrams for attack chains`

	case ReportTypeRemediation:
		return base + `

This is a REMEDIATION PLAYBOOK for development teams.
- Prioritize findings by risk and effort
- Provide step-by-step fix instructions
- Include code examples where possible
- Group by responsible team/component
- Include verification steps`

	case ReportTypeCompliance:
		return base + `

This is a COMPLIANCE REPORT mapping findings to frameworks.
- Map findings to OWASP Top 10, MITRE ATT&CK, NIST CSF
- Show compliance gaps
- Include evidence for auditors
- Calculate compliance scores per framework`

	default:
		return base
	}
}

// buildPrompt constructs the prompt with mission data.
func (g *Generator) buildPrompt(reportType ReportType, data *ReportData, customPrompt string) (string, error) {
	// Serialize key data for the LLM
	findingsJSON, err := json.MarshalIndent(g.summarizeFindings(data), "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to serialize findings: %w", err)
	}

	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Generate a %s report for the following security assessment:\n\n", reportType))

	// Mission context
	sb.WriteString("## Mission Information\n")
	sb.WriteString(fmt.Sprintf("- **Name**: %s\n", data.Mission.Name))
	sb.WriteString(fmt.Sprintf("- **Description**: %s\n", data.Mission.Description))
	sb.WriteString(fmt.Sprintf("- **Status**: %s\n", data.Mission.Status))
	sb.WriteString(fmt.Sprintf("- **Started**: %s\n", data.Mission.StartedAt.Format(time.RFC3339)))
	if data.Mission.CompletedAt != nil {
		sb.WriteString(fmt.Sprintf("- **Completed**: %s\n", data.Mission.CompletedAt.Format(time.RFC3339)))
	}
	sb.WriteString("\n")

	// Target info
	sb.WriteString("## Target\n")
	sb.WriteString(fmt.Sprintf("- **Type**: %s\n", data.Target.Type))
	sb.WriteString(fmt.Sprintf("- **Provider**: %s\n", data.Target.Provider))
	if data.Target.Model != "" {
		sb.WriteString(fmt.Sprintf("- **Model**: %s\n", data.Target.Model))
	}
	if data.Target.URL != "" {
		sb.WriteString(fmt.Sprintf("- **URL**: %s\n", data.Target.URL))
	}
	sb.WriteString("\n")

	// Metrics summary
	sb.WriteString("## Assessment Metrics\n")
	sb.WriteString(fmt.Sprintf("- **Total Findings**: %d\n", len(data.Findings)))
	sb.WriteString(fmt.Sprintf("- **Critical**: %d\n", data.Metrics.FindingsBySeverity["critical"]))
	sb.WriteString(fmt.Sprintf("- **High**: %d\n", data.Metrics.FindingsBySeverity["high"]))
	sb.WriteString(fmt.Sprintf("- **Medium**: %d\n", data.Metrics.FindingsBySeverity["medium"]))
	sb.WriteString(fmt.Sprintf("- **Low**: %d\n", data.Metrics.FindingsBySeverity["low"]))
	sb.WriteString(fmt.Sprintf("- **Info**: %d\n", data.Metrics.FindingsBySeverity["info"]))
	sb.WriteString(fmt.Sprintf("- **Risk Score**: %.1f/10\n", data.RiskScore))
	sb.WriteString(fmt.Sprintf("- **Duration**: %s\n", data.Metrics.TotalDuration))
	sb.WriteString("\n")

	// Findings
	sb.WriteString("## Findings Data\n")
	sb.WriteString("```json\n")
	sb.Write(findingsJSON)
	sb.WriteString("\n```\n\n")

	// Payload executions if available
	if len(data.PayloadExecutions) > 0 {
		sb.WriteString("## Payloads Executed\n")
		for _, p := range data.PayloadExecutions {
			sb.WriteString(fmt.Sprintf("- **%s** (%s): %s - Status: %s\n",
				p.Name, p.Category, p.Description, p.Status))
		}
		sb.WriteString("\n")
	}

	// Custom instructions
	if customPrompt != "" {
		sb.WriteString("## Additional Instructions\n")
		sb.WriteString(customPrompt)
		sb.WriteString("\n\n")
	}

	sb.WriteString("Please generate the report now.")

	return sb.String(), nil
}

// summarizeFindings creates a condensed view of findings for the LLM.
func (g *Generator) summarizeFindings(data *ReportData) []map[string]any {
	findings := make([]map[string]any, 0, len(data.Findings))

	for _, f := range data.Findings {
		finding := map[string]any{
			"id":          f.ID.String(),
			"title":       f.Title,
			"severity":    f.Severity,
			"category":    f.Category,
			"description": f.Description,
			"agent":       f.AgentName,
		}

		// Include evidence summary (not full data to save tokens)
		if len(f.Evidence) > 0 {
			evidenceSummary := make([]string, 0, len(f.Evidence))
			for _, e := range f.Evidence {
				evidenceSummary = append(evidenceSummary, fmt.Sprintf("%s: %s", e.Type, truncate(e.Description, 100)))
			}
			finding["evidence"] = evidenceSummary
		}

		// Include MITRE mappings (combine ATT&CK and ATLAS)
		allMitre := append(f.MitreAttack, f.MitreAtlas...)
		if len(allMitre) > 0 {
			mitre := make([]string, 0, len(allMitre))
			for _, m := range allMitre {
				mitre = append(mitre, m.TechniqueID)
			}
			finding["mitre"] = mitre
		}

		// Include remediation if available
		if f.Remediation != "" {
			finding["remediation"] = f.Remediation
		}

		// Include CWE/CVSS if available
		if len(f.CWE) > 0 {
			finding["cwe"] = f.CWE
		}
		if f.CVSS != nil && f.CVSS.Score > 0 {
			finding["cvss"] = f.CVSS.Score
		}

		findings = append(findings, finding)
	}

	return findings
}

// generateTitle creates an appropriate title for the report.
func (g *Generator) generateTitle(reportType ReportType, data *ReportData) string {
	typeNames := map[ReportType]string{
		ReportTypeExecutive:       "Executive Summary",
		ReportTypeTechnical:       "Technical Security Assessment",
		ReportTypeRemediation:     "Remediation Playbook",
		ReportTypeCompliance:      "Compliance Report",
		ReportTypeAttackNarrative: "Attack Narrative",
		ReportTypeAssetDiscovery:  "Asset Discovery Report",
	}

	typeName := typeNames[reportType]
	if typeName == "" {
		typeName = "Security Report"
	}

	return fmt.Sprintf("%s - %s", typeName, data.Mission.Name)
}

// extractSummary extracts a brief summary from the generated content.
func (g *Generator) extractSummary(content string) string {
	// Take first 200 chars as summary, or first paragraph
	lines := strings.Split(content, "\n")
	var summary strings.Builder

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		summary.WriteString(line)
		if summary.Len() > 200 {
			break
		}
		summary.WriteString(" ")
	}

	result := summary.String()
	if len(result) > 250 {
		result = result[:247] + "..."
	}
	return strings.TrimSpace(result)
}

// buildMetadata creates report metadata from aggregated data.
func (g *Generator) buildMetadata(data *ReportData) ReportMetadata {
	meta := ReportMetadata{
		FindingCount:    len(data.Findings),
		MissionDuration: data.Metrics.TotalDuration,
	}

	// Count by severity
	for _, f := range data.Findings {
		switch f.Severity {
		case "critical":
			meta.CriticalCount++
		case "high":
			meta.HighCount++
		case "medium":
			meta.MediumCount++
		case "low":
			meta.LowCount++
		case "info":
			meta.InfoCount++
		}
	}

	// Collect unique agents
	agents := make(map[string]bool)
	for _, f := range data.Findings {
		if f.AgentName != "" {
			agents[f.AgentName] = true
		}
	}
	for agent := range agents {
		meta.AgentsUsed = append(meta.AgentsUsed, agent)
	}

	// Collect MITRE coverage (combine ATT&CK and ATLAS)
	mitre := make(map[string]bool)
	for _, f := range data.Findings {
		for _, m := range f.MitreAttack {
			mitre[m.TechniqueID] = true
		}
		for _, m := range f.MitreAtlas {
			mitre[m.TechniqueID] = true
		}
	}
	for technique := range mitre {
		if strings.HasPrefix(technique, "AML") {
			meta.MitreAtlasCoverage = append(meta.MitreAtlasCoverage, technique)
		} else {
			meta.MitreAttackCoverage = append(meta.MitreAttackCoverage, technique)
		}
	}

	return meta
}

// truncate shortens a string to maxLen with ellipsis.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
