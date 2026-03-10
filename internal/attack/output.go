package attack

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/finding"
)

// OutputFormat constants define supported output formats
const (
	OutputFormatText  = "text"
	OutputFormatJSON  = "json"
	OutputFormatSARIF = "sarif"
)

// ANSI color codes for terminal output
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorGray    = "\033[90m"
	colorBold    = "\033[1m"
	colorGreen   = "\033[32m"
)

// OutputHandler formats and displays attack execution output.
// Different implementations support text, JSON, and SARIF formats.
type OutputHandler interface {
	// OnStart is called when the attack begins
	OnStart(opts *AttackOptions)

	// OnProgress is called with progress messages during execution
	OnProgress(msg string)

	// OnFinding is called when a finding is discovered
	OnFinding(f finding.EnhancedFinding)

	// OnComplete is called when the attack completes
	OnComplete(result *AttackResult)

	// OnError is called when an error occurs
	OnError(err error)
}

// NewOutputHandler creates an appropriate output handler based on format
func NewOutputHandler(format string, writer io.Writer, verbose, quiet bool) OutputHandler {
	switch format {
	case OutputFormatJSON:
		return NewJSONOutputHandler(writer)
	case OutputFormatSARIF:
		return NewSARIFOutputHandler(writer)
	default:
		return NewTextOutputHandler(writer, verbose, quiet)
	}
}

// TextOutputHandler implements OutputHandler for human-readable text output
type TextOutputHandler struct {
	writer  io.Writer
	verbose bool
	quiet   bool
}

// NewTextOutputHandler creates a new text output handler
func NewTextOutputHandler(writer io.Writer, verbose, quiet bool) *TextOutputHandler {
	return &TextOutputHandler{
		writer:  writer,
		verbose: verbose,
		quiet:   quiet,
	}
}

// OnStart displays the attack configuration
func (h *TextOutputHandler) OnStart(opts *AttackOptions) {
	if h.quiet {
		return
	}

	fmt.Fprintf(h.writer, "%s%sGibson Attack%s\n", colorBold, colorCyan, colorReset)
	fmt.Fprintf(h.writer, "%s%s%s\n\n", colorGray, strings.Repeat("=", 60), colorReset)

	// Target information
	target := opts.TargetURL
	if target == "" {
		target = opts.TargetName
	}
	fmt.Fprintf(h.writer, "%sTarget:%s        %s\n", colorBold, colorReset, target)

	if opts.TargetType != "" {
		fmt.Fprintf(h.writer, "%sTarget Type:%s   %s\n", colorBold, colorReset, opts.TargetType)
	}

	if opts.TargetProvider != "" {
		fmt.Fprintf(h.writer, "%sProvider:%s      %s\n", colorBold, colorReset, opts.TargetProvider)
	}

	// Agent information
	fmt.Fprintf(h.writer, "%sAgent:%s         %s\n", colorBold, colorReset, opts.AgentName)

	// Configuration details (verbose only)
	if h.verbose {
		fmt.Fprintf(h.writer, "\n%sConfiguration:%s\n", colorBold, colorReset)

		if opts.MaxTurns > 0 {
			fmt.Fprintf(h.writer, "  Max Turns:     %d\n", opts.MaxTurns)
		}

		if opts.Timeout > 0 {
			fmt.Fprintf(h.writer, "  Timeout:       %s\n", opts.Timeout)
		}

		if opts.MaxFindings > 0 {
			fmt.Fprintf(h.writer, "  Max Findings:  %d\n", opts.MaxFindings)
		}

		if opts.SeverityThreshold != "" {
			fmt.Fprintf(h.writer, "  Min Severity:  %s\n", opts.SeverityThreshold)
		}

		if opts.RateLimit > 0 {
			fmt.Fprintf(h.writer, "  Rate Limit:    %d req/s\n", opts.RateLimit)
		}

		if len(opts.PayloadIDs) > 0 {
			fmt.Fprintf(h.writer, "  Payload IDs:   %s\n", strings.Join(opts.PayloadIDs, ", "))
		}

		if opts.PayloadCategory != "" {
			fmt.Fprintf(h.writer, "  Category:      %s\n", opts.PayloadCategory)
		}

		if len(opts.Techniques) > 0 {
			fmt.Fprintf(h.writer, "  Techniques:    %s\n", strings.Join(opts.Techniques, ", "))
		}
	}

	fmt.Fprintf(h.writer, "\n%s%s%s\n\n", colorGray, strings.Repeat("-", 60), colorReset)
}

// OnProgress displays a progress message
func (h *TextOutputHandler) OnProgress(msg string) {
	if h.quiet || !h.verbose {
		return
	}

	fmt.Fprintf(h.writer, "%s[%s]%s %s\n",
		colorGray,
		time.Now().Format("15:04:05"),
		colorReset,
		msg)
}

// OnFinding displays a discovered finding
func (h *TextOutputHandler) OnFinding(f finding.EnhancedFinding) {
	// Determine severity color
	severityColor := getSeverityColor(f.Severity)

	// Always show findings, even in quiet mode
	fmt.Fprintf(h.writer, "\n%s%s[%s]%s %s\n",
		colorBold,
		severityColor,
		strings.ToUpper(string(f.Severity)),
		colorReset,
		f.Title)

	// Show description unless in quiet mode
	if !h.quiet {
		fmt.Fprintf(h.writer, "%s\n", wrapText(f.Description, 70, "  "))

		// Show category and confidence
		fmt.Fprintf(h.writer, "\n  %sCategory:%s    %s", colorGray, colorReset, f.Category)
		if f.Subcategory != "" {
			fmt.Fprintf(h.writer, " / %s", f.Subcategory)
		}
		fmt.Fprintf(h.writer, "\n")

		fmt.Fprintf(h.writer, "  %sConfidence:%s  %.0f%%\n", colorGray, colorReset, f.Confidence*100)

		if f.RiskScore > 0 {
			fmt.Fprintf(h.writer, "  %sRisk Score:%s  %.1f/10.0\n", colorGray, colorReset, f.RiskScore)
		}

		// Show MITRE ATT&CK mappings in verbose mode
		if mitreAttack := f.GetMitreAttack(); h.verbose && len(mitreAttack) > 0 {
			fmt.Fprintf(h.writer, "  %sMITRE ATT&CK:%s\n", colorGray, colorReset)
			for _, m := range mitreAttack {
				fmt.Fprintf(h.writer, "    - %s: %s", m.TechniqueID, m.TechniqueName)
				if m.Tactic != "" {
					fmt.Fprintf(h.writer, " (%s)", m.Tactic)
				}
				fmt.Fprintf(h.writer, "\n")
			}
		}

		// Show MITRE ATLAS mappings in verbose mode
		if mitreAtlas := f.GetMitreAtlas(); h.verbose && len(mitreAtlas) > 0 {
			fmt.Fprintf(h.writer, "  %sMITRE ATLAS:%s\n", colorGray, colorReset)
			for _, m := range mitreAtlas {
				fmt.Fprintf(h.writer, "    - %s: %s", m.TechniqueID, m.TechniqueName)
				if m.Tactic != "" {
					fmt.Fprintf(h.writer, " (%s)", m.Tactic)
				}
				fmt.Fprintf(h.writer, "\n")
			}
		}

		// Show evidence in verbose mode
		if h.verbose && len(f.Evidence) > 0 {
			fmt.Fprintf(h.writer, "  %sEvidence:%s\n", colorGray, colorReset)
			for i, e := range f.Evidence {
				if i >= 3 {
					fmt.Fprintf(h.writer, "    ... and %d more evidence items\n", len(f.Evidence)-3)
					break
				}
				fmt.Fprintf(h.writer, "    - [%s] %s\n", e.Type, e.Description)
			}
		}

		// Show remediation if available
		if h.verbose && f.Remediation != "" {
			fmt.Fprintf(h.writer, "\n  %sRemediation:%s\n%s\n",
				colorGray, colorReset,
				wrapText(f.Remediation, 70, "    "))
		}
	}

	fmt.Fprintf(h.writer, "\n")
}

// OnComplete displays the final attack results
func (h *TextOutputHandler) OnComplete(result *AttackResult) {
	if h.quiet && !result.HasFindings() {
		return
	}

	fmt.Fprintf(h.writer, "%s%s%s\n", colorGray, strings.Repeat("=", 60), colorReset)
	fmt.Fprintf(h.writer, "%s%sAttack Complete%s\n\n", colorBold, colorCyan, colorReset)

	// Show status
	statusColor := colorGreen
	if result.Status == AttackStatusFailed {
		statusColor = colorRed
	} else if result.Status == AttackStatusFindings {
		statusColor = colorYellow
	} else if result.Status == AttackStatusTimeout {
		statusColor = colorMagenta
	}

	fmt.Fprintf(h.writer, "%sStatus:%s       %s%s%s\n",
		colorBold, colorReset,
		statusColor, result.Status, colorReset)

	// Show metrics
	fmt.Fprintf(h.writer, "%sDuration:%s     %s\n", colorBold, colorReset, result.Duration.Round(time.Millisecond))
	fmt.Fprintf(h.writer, "%sTurns Used:%s   %d\n", colorBold, colorReset, result.TurnsUsed)

	if result.TokensUsed > 0 {
		fmt.Fprintf(h.writer, "%sTokens Used:%s  %d\n", colorBold, colorReset, result.TokensUsed)
	}

	// Show agent error if present
	if result.AgentOutput != "" {
		fmt.Fprintf(h.writer, "\n%s%sAgent Error:%s\n", colorBold, colorRed, colorReset)
		fmt.Fprintf(h.writer, "  %s\n", result.AgentOutput)

		if len(result.FailedNodes) > 0 {
			fmt.Fprintf(h.writer, "\n%sFailed Nodes:%s %s\n", colorBold, colorReset, strings.Join(result.FailedNodes, ", "))
		}
	}

	// Show findings summary
	if result.HasFindings() {
		fmt.Fprintf(h.writer, "\n%sFindings:%s      %d total\n", colorBold, colorReset, result.FindingCount())

		if result.CriticalFindingCount() > 0 {
			fmt.Fprintf(h.writer, "  %s●%s Critical:  %d\n", colorRed, colorReset, result.CriticalFindingCount())
		}
		if result.HighFindingCount() > 0 {
			fmt.Fprintf(h.writer, "  %s●%s High:      %d\n", colorMagenta, colorReset, result.HighFindingCount())
		}
		if result.MediumFindingCount() > 0 {
			fmt.Fprintf(h.writer, "  %s●%s Medium:    %d\n", colorYellow, colorReset, result.MediumFindingCount())
		}
		if result.LowFindingCount() > 0 {
			fmt.Fprintf(h.writer, "  %s●%s Low:       %d\n", colorBlue, colorReset, result.LowFindingCount())
		}
		if result.InfoFindingCount() > 0 {
			fmt.Fprintf(h.writer, "  %s●%s Info:      %d\n", colorCyan, colorReset, result.InfoFindingCount())
		}
	} else {
		fmt.Fprintf(h.writer, "\n%sFindings:%s      None discovered\n", colorBold, colorReset)
	}

	// Show persistence status
	if result.Persisted && result.MissionID != nil {
		fmt.Fprintf(h.writer, "\n%sMission ID:%s   %s\n", colorBold, colorReset, result.MissionID.String())
	} else if !h.quiet {
		fmt.Fprintf(h.writer, "\n%sNote:%s Results not persisted (no findings or --no-persist)\n",
			colorGray, colorReset)
	}

	fmt.Fprintf(h.writer, "\n")
}

// OnError displays an error
func (h *TextOutputHandler) OnError(err error) {
	fmt.Fprintf(h.writer, "\n%s%sError:%s %s\n\n",
		colorBold, colorRed, colorReset, err.Error())
}

// JSONOutputHandler implements OutputHandler for JSON output
type JSONOutputHandler struct {
	encoder *json.Encoder
}

// jsonEvent represents a single event in the JSON stream
type jsonEvent struct {
	Type      string      `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data"`
}

// NewJSONOutputHandler creates a new JSON output handler
func NewJSONOutputHandler(writer io.Writer) *JSONOutputHandler {
	return &JSONOutputHandler{
		encoder: json.NewEncoder(writer),
	}
}

// OnStart emits a start event
func (h *JSONOutputHandler) OnStart(opts *AttackOptions) {
	event := jsonEvent{
		Type:      "start",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"target":    getTargetIdentifier(opts),
			"agent":     opts.AgentName,
			"max_turns": opts.MaxTurns,
			"timeout":   opts.Timeout.String(),
		},
	}
	h.encoder.Encode(event)
}

// OnProgress emits a progress event
func (h *JSONOutputHandler) OnProgress(msg string) {
	event := jsonEvent{
		Type:      "progress",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"message": msg,
		},
	}
	h.encoder.Encode(event)
}

// OnFinding emits a finding event
func (h *JSONOutputHandler) OnFinding(f finding.EnhancedFinding) {
	event := jsonEvent{
		Type:      "finding",
		Timestamp: time.Now(),
		Data:      f,
	}
	h.encoder.Encode(event)
}

// OnComplete emits a complete event with full results
func (h *JSONOutputHandler) OnComplete(result *AttackResult) {
	event := jsonEvent{
		Type:      "complete",
		Timestamp: time.Now(),
		Data:      result,
	}
	h.encoder.Encode(event)
}

// OnError emits an error event
func (h *JSONOutputHandler) OnError(err error) {
	event := jsonEvent{
		Type:      "error",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"error": err.Error(),
		},
	}
	h.encoder.Encode(event)
}

// SARIFOutputHandler implements OutputHandler for SARIF 2.1.0 output
type SARIFOutputHandler struct {
	writer   io.Writer
	findings []finding.EnhancedFinding
	result   *AttackResult
}

// NewSARIFOutputHandler creates a new SARIF output handler
func NewSARIFOutputHandler(writer io.Writer) *SARIFOutputHandler {
	return &SARIFOutputHandler{
		writer:   writer,
		findings: []finding.EnhancedFinding{},
	}
}

// OnStart does nothing (SARIF is output at the end)
func (h *SARIFOutputHandler) OnStart(opts *AttackOptions) {
	// SARIF output is only generated at completion
}

// OnProgress does nothing (SARIF is output at the end)
func (h *SARIFOutputHandler) OnProgress(msg string) {
	// SARIF output is only generated at completion
}

// OnFinding collects findings for SARIF output
func (h *SARIFOutputHandler) OnFinding(f finding.EnhancedFinding) {
	h.findings = append(h.findings, f)
}

// OnComplete generates and outputs the SARIF document
func (h *SARIFOutputHandler) OnComplete(result *AttackResult) {
	h.result = result

	sarif := h.generateSARIF()
	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		// Fallback to error output
		fmt.Fprintf(h.writer, `{"error": "Failed to generate SARIF: %s"}`, err.Error())
		return
	}

	h.writer.Write(data)
	h.writer.Write([]byte("\n"))
}

// OnError outputs error in SARIF format
func (h *SARIFOutputHandler) OnError(err error) {
	// Output minimal SARIF with invocation error
	sarif := &sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:    "Gibson Attack",
						Version: "1.0.0",
					},
				},
				Invocations: []sarifInvocation{
					{
						ExecutionSuccessful: false,
						ExecutionFailure: &sarifExecutionFailure{
							Message: sarifMessage{
								Text: err.Error(),
							},
						},
					},
				},
				Results: []sarifResult{},
			},
		},
	}

	data, _ := json.MarshalIndent(sarif, "", "  ")
	h.writer.Write(data)
	h.writer.Write([]byte("\n"))
}

// generateSARIF creates a SARIF 2.1.0 document from collected findings
func (h *SARIFOutputHandler) generateSARIF() *sarifLog {
	return &sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "Gibson Attack",
						Version:        "1.0.0",
						InformationUri: "https://github.com/zero-day-ai/gibson",
						Rules:          h.buildRules(),
					},
				},
				Results: h.buildResults(),
			},
		},
	}
}

// buildRules extracts unique rules from findings
func (h *SARIFOutputHandler) buildRules() []sarifRule {
	ruleMap := make(map[string]sarifRule)

	for _, f := range h.findings {
		ruleID := h.buildRuleID(f)

		if _, exists := ruleMap[ruleID]; !exists {
			rule := sarifRule{
				ID:   ruleID,
				Name: f.Category,
				ShortDescription: sarifMessageString{
					Text: f.Title,
				},
				FullDescription: sarifMessageString{
					Text: f.Description,
				},
			}

			// Add help text with remediation
			if f.Remediation != "" {
				helpText := f.Description
				if f.Remediation != "" {
					helpText += "\n\nRemediation: " + f.Remediation
				}
				rule.Help = &sarifMessageString{
					Text: helpText,
				}
			}

			// Add properties with severity and category
			rule.Properties = &sarifRuleProperties{
				Tags: []string{string(f.Severity), f.Category},
			}

			ruleMap[ruleID] = rule
		}
	}

	// Convert map to slice
	rules := make([]sarifRule, 0, len(ruleMap))
	for _, rule := range ruleMap {
		rules = append(rules, rule)
	}

	return rules
}

// buildResults converts findings to SARIF results
func (h *SARIFOutputHandler) buildResults() []sarifResult {
	results := make([]sarifResult, 0, len(h.findings))

	for _, f := range h.findings {
		result := sarifResult{
			RuleID:  h.buildRuleID(f),
			Level:   h.mapSeverityToLevel(f.Severity),
			Message: sarifMessage{Text: f.Description},
			Properties: map[string]interface{}{
				"id":          f.ID.String(),
				"confidence":  f.Confidence,
				"risk_score":  f.RiskScore,
				"category":    f.Category,
				"subcategory": f.Subcategory,
				"created_at":  f.CreatedAt,
				"status":      f.Status,
			},
		}

		// Add MITRE ATT&CK mappings
		if mitreAttack := f.GetMitreAttack(); len(mitreAttack) > 0 {
			mitreIDs := make([]string, len(mitreAttack))
			for i, m := range mitreAttack {
				mitreIDs[i] = fmt.Sprintf("%s (%s)", m.TechniqueID, m.TechniqueName)
			}
			result.Properties["mitre_attack"] = mitreIDs
		}

		// Add MITRE ATLAS mappings
		if mitreAtlas := f.GetMitreAtlas(); len(mitreAtlas) > 0 {
			atlasIDs := make([]string, len(mitreAtlas))
			for i, m := range mitreAtlas {
				atlasIDs[i] = fmt.Sprintf("%s (%s)", m.TechniqueID, m.TechniqueName)
			}
			result.Properties["mitre_atlas"] = atlasIDs
		}

		// Add CWE if available
		if len(f.CWE) > 0 {
			result.Properties["cwe"] = f.CWE
		}

		// Add CVSS if available
		if f.CVSS != nil {
			result.Properties["cvss"] = map[string]interface{}{
				"version": f.CVSS.Version,
				"vector":  f.CVSS.Vector,
				"score":   f.CVSS.Score,
			}
		}

		results = append(results, result)
	}

	return results
}

// buildRuleID creates a consistent rule ID from a finding
func (h *SARIFOutputHandler) buildRuleID(f finding.EnhancedFinding) string {
	ruleID := strings.ReplaceAll(f.Category, " ", "_")
	ruleID = strings.ToUpper(ruleID)

	if f.Subcategory != "" {
		subcategory := strings.ReplaceAll(f.Subcategory, " ", "_")
		ruleID = fmt.Sprintf("%s/%s", ruleID, strings.ToUpper(subcategory))
	}

	return ruleID
}

// mapSeverityToLevel converts agent.FindingSeverity to SARIF level
func (h *SARIFOutputHandler) mapSeverityToLevel(severity agent.FindingSeverity) string {
	switch severity {
	case agent.SeverityCritical, agent.SeverityHigh:
		return "error"
	case agent.SeverityMedium:
		return "warning"
	case agent.SeverityLow, agent.SeverityInfo:
		return "note"
	default:
		return "warning"
	}
}

// SARIF 2.1.0 structure definitions

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationUri string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string               `json:"id"`
	Name             string               `json:"name"`
	ShortDescription sarifMessageString   `json:"shortDescription"`
	FullDescription  sarifMessageString   `json:"fullDescription,omitempty"`
	Help             *sarifMessageString  `json:"help,omitempty"`
	Properties       *sarifRuleProperties `json:"properties,omitempty"`
}

type sarifRuleProperties struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifMessageString struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string                 `json:"ruleId"`
	Level      string                 `json:"level"`
	Message    sarifMessage           `json:"message"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool                   `json:"executionSuccessful"`
	ExecutionFailure    *sarifExecutionFailure `json:"executionFailure,omitempty"`
}

type sarifExecutionFailure struct {
	Message sarifMessage `json:"message"`
}

// Helper functions

// getSeverityColor returns the ANSI color code for a severity level
func getSeverityColor(severity agent.FindingSeverity) string {
	switch severity {
	case agent.SeverityCritical:
		return colorRed
	case agent.SeverityHigh:
		return colorMagenta
	case agent.SeverityMedium:
		return colorYellow
	case agent.SeverityLow:
		return colorBlue
	case agent.SeverityInfo:
		return colorCyan
	default:
		return colorReset
	}
}

// wrapText wraps text to a specified width with a prefix
func wrapText(text string, width int, prefix string) string {
	if text == "" {
		return ""
	}

	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}

	var result strings.Builder
	result.WriteString(prefix)

	lineLen := len(prefix)
	for i, word := range words {
		wordLen := len(word)

		if i > 0 {
			if lineLen+wordLen+1 > width {
				result.WriteString("\n")
				result.WriteString(prefix)
				lineLen = len(prefix)
			} else {
				result.WriteString(" ")
				lineLen++
			}
		}

		result.WriteString(word)
		lineLen += wordLen
	}

	return result.String()
}

// getTargetIdentifier returns the target URL or name from options
func getTargetIdentifier(opts *AttackOptions) string {
	if opts.TargetURL != "" {
		return opts.TargetURL
	}
	return opts.TargetName
}
