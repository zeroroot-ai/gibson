package export

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/finding"
	sdkSecurity "github.com/zero-day-ai/sdk/finding/security"
)

// SARIFExporter exports findings in SARIF 2.1.0 format.
// SARIF (Static Analysis Results Interchange Format) is a standard format
// for static analysis tool results, widely supported by CI/CD platforms and IDEs.
//
// Thread-safe for concurrent use.
type SARIFExporter struct {
	// ToolName is the name of the tool generating the SARIF report
	ToolName string

	// ToolVersion is the version of the tool
	ToolVersion string

	// InformationURI is a URI providing more information about the tool
	InformationURI string
}

// NewSARIFExporter creates a new SARIF exporter with default tool information
func NewSARIFExporter() *SARIFExporter {
	return &SARIFExporter{
		ToolName:       "Gibson",
		ToolVersion:    "1.0.0",
		InformationURI: "https://github.com/zero-day-ai/gibson",
	}
}

// WithToolInfo configures custom tool information
func (e *SARIFExporter) WithToolInfo(name, version, uri string) *SARIFExporter {
	e.ToolName = name
	e.ToolVersion = version
	e.InformationURI = uri
	return e
}

// Export converts findings to SARIF 2.1.0 format
func (e *SARIFExporter) Export(ctx context.Context, findings []*finding.EnhancedFinding, opts ExportOptions) ([]byte, error) {
	// Apply filters
	filtered := ApplyFilters(findings, opts)

	// Build SARIF structure
	sarifLog := SarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:           e.ToolName,
						Version:        e.ToolVersion,
						InformationUri: e.InformationURI,
						Rules:          buildRules(filtered),
					},
				},
				Results: buildResults(filtered, opts),
			},
		},
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(sarifLog, "", "  ")
	return data, err
}

// Format returns "sarif"
func (e *SARIFExporter) Format() string {
	return "sarif"
}

// ContentType returns "application/sarif+json"
func (e *SARIFExporter) ContentType() string {
	return "application/sarif+json"
}

// SARIF 2.1.0 Structure Definitions

// SarifLog is the top-level SARIF document
type SarifLog struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

// Run represents a single run of an analysis tool
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

// Tool describes the analysis tool that produced the results
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver contains information about the tool
type Driver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationUri string `json:"informationUri"`
	Rules          []Rule `json:"rules,omitempty"`
}

// Rule describes a rule that can generate results
type Rule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription MessageString   `json:"shortDescription"`
	FullDescription  MessageString   `json:"fullDescription,omitempty"`
	Help             MessageString   `json:"help,omitempty"`
	Properties       *RuleProperties `json:"properties,omitempty"`
}

// RuleProperties contains additional rule metadata
type RuleProperties struct {
	Tags     []string               `json:"tags,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Result represents a single finding/issue
type Result struct {
	RuleID     string                 `json:"ruleId"`
	Level      string                 `json:"level"`
	Message    Message                `json:"message"`
	Locations  []Location             `json:"locations,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// Message describes a result message
type Message struct {
	Text string `json:"text"`
}

// MessageString is used for rule descriptions
type MessageString struct {
	Text string `json:"text"`
}

// Location identifies where a result was detected
type Location struct {
	PhysicalLocation *PhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocation  *LogicalLocation  `json:"logicalLocation,omitempty"`
}

// PhysicalLocation describes a location in a physical artifact
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           *Region          `json:"region,omitempty"`
}

// ArtifactLocation describes an artifact (file)
type ArtifactLocation struct {
	URI string `json:"uri"`
}

// Region describes a region within an artifact
type Region struct {
	StartLine   int      `json:"startLine,omitempty"`
	StartColumn int      `json:"startColumn,omitempty"`
	EndLine     int      `json:"endLine,omitempty"`
	EndColumn   int      `json:"endColumn,omitempty"`
	Snippet     *Snippet `json:"snippet,omitempty"`
}

// Snippet contains a portion of the artifact
type Snippet struct {
	Text string `json:"text"`
}

// LogicalLocation describes a logical location (e.g., function, class)
type LogicalLocation struct {
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"`
}

// buildRules extracts unique rules from findings
func buildRules(findings []*finding.EnhancedFinding) []Rule {
	ruleMap := make(map[string]Rule)

	for _, f := range findings {
		ruleID := buildRuleID(f)

		if _, exists := ruleMap[ruleID]; !exists {
			ruleMap[ruleID] = Rule{
				ID:   ruleID,
				Name: f.Category,
				ShortDescription: MessageString{
					Text: f.Title,
				},
				FullDescription: MessageString{
					Text: f.Description,
				},
				Help: MessageString{
					Text: buildHelpText(f),
				},
				Properties: &RuleProperties{
					Tags: []string{string(f.Severity)},
					Metadata: map[string]interface{}{
						"category": f.Category,
					},
				},
			}
		}
	}

	// Convert map to slice
	rules := make([]Rule, 0, len(ruleMap))
	for _, rule := range ruleMap {
		rules = append(rules, rule)
	}

	return rules
}

// buildResults converts findings to SARIF results
func buildResults(findings []*finding.EnhancedFinding, opts ExportOptions) []Result {
	results := make([]Result, 0, len(findings))

	for _, f := range findings {
		result := Result{
			RuleID:  buildRuleID(f),
			Level:   mapSeverityToLevel(f.Severity),
			Message: Message{Text: f.Description},
			Properties: map[string]interface{}{
				"id":          f.ID.String(),
				"confidence":  f.Confidence,
				"risk_score":  f.RiskScore,
				"category":    f.Category,
				"subcategory": f.Subcategory,
				"created_at":  f.CreatedAt,
			},
		}

		// Add MITRE Attack mappings from Metadata
		mitreAttack := getMitreAttackFromMetadata(&f.Finding)
		if len(mitreAttack) > 0 {
			mitreIDs := make([]string, len(mitreAttack))
			for i, m := range mitreAttack {
				mitreIDs[i] = m.TechniqueID
			}
			result.Properties["mitre_attack_techniques"] = mitreIDs
		}

		// Add MITRE Atlas mappings from Metadata
		mitreAtlas := getMitreAtlasFromMetadata(&f.Finding)
		if len(mitreAtlas) > 0 {
			atlasIDs := make([]string, len(mitreAtlas))
			for i, m := range mitreAtlas {
				atlasIDs[i] = m.TechniqueID
			}
			result.Properties["mitre_atlas_techniques"] = atlasIDs
		}

		// Add CWE - try Metadata first, then fall back to direct field
		cwe := getCWEFromMetadata(&f.Finding)
		if len(cwe) == 0 && len(f.CWE) > 0 {
			// Fall back to direct field for backward compatibility
			cwe = f.CWE
		}
		if len(cwe) > 0 {
			result.Properties["cwe"] = cwe
		}

		// Add CVSS - try Metadata first, then fall back to direct field
		if cvss, ok := getCVSSFromMetadata(&f.Finding); ok {
			result.Properties["cvss"] = map[string]interface{}{
				"version": cvss.Version,
				"vector":  cvss.Vector,
				"score":   cvss.Score,
			}
		} else if f.CVSS != nil {
			// Fall back to direct field for backward compatibility
			result.Properties["cvss"] = map[string]interface{}{
				"version": f.CVSS.Version,
				"vector":  f.CVSS.Vector,
				"score":   f.CVSS.Score,
			}
		}

		// Add locations if we have evidence with location info
		if opts.IncludeEvidence && len(f.Evidence) > 0 {
			result.Locations = buildLocations(f)
		}

		results = append(results, result)
	}

	return results
}

// buildRuleID creates a consistent rule ID from a finding
func buildRuleID(f *finding.EnhancedFinding) string {
	// Use category as base ID
	ruleID := strings.ReplaceAll(f.Category, " ", "_")
	ruleID = strings.ToUpper(ruleID)

	// Add subcategory if present
	if f.Subcategory != "" {
		subcategory := strings.ReplaceAll(f.Subcategory, " ", "_")
		ruleID = fmt.Sprintf("%s/%s", ruleID, strings.ToUpper(subcategory))
	}

	return ruleID
}

// mapSeverityToLevel converts agent.FindingSeverity to SARIF level
func mapSeverityToLevel(severity agent.FindingSeverity) string {
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

// buildHelpText creates help text for a rule
func buildHelpText(f *finding.EnhancedFinding) string {
	var help strings.Builder

	help.WriteString(f.Description)

	// Add remediation if available
	if f.Remediation != "" {
		help.WriteString("\n\nRemediation: ")
		help.WriteString(f.Remediation)
	}

	// Add references if available
	if len(f.References) > 0 {
		help.WriteString("\n\nReferences:\n")
		for _, ref := range f.References {
			help.WriteString("- ")
			help.WriteString(ref)
			help.WriteString("\n")
		}
	}

	return help.String()
}

// buildLocations extracts location information from evidence
func buildLocations(f *finding.EnhancedFinding) []Location {
	locations := make([]Location, 0)

	// Try to extract location info from evidence
	for _, evidence := range f.Evidence {
		if evidence.Data == nil {
			continue
		}

		// Look for file/line information in evidence data
		var location Location

		if file, ok := evidence.Data["file"].(string); ok {
			location.PhysicalLocation = &PhysicalLocation{
				ArtifactLocation: ArtifactLocation{
					URI: file,
				},
			}

			// Try to get line numbers
			if line, ok := evidence.Data["line"].(float64); ok {
				location.PhysicalLocation.Region = &Region{
					StartLine: int(line),
				}
			}

			locations = append(locations, location)
		}

		// Look for logical location (e.g., function name)
		if function, ok := evidence.Data["function"].(string); ok {
			location.LogicalLocation = &LogicalLocation{
				Name: function,
				Kind: "function",
			}
			locations = append(locations, location)
		}
	}

	// If no locations found from evidence, create a generic one
	if len(locations) == 0 && f.TargetID != nil {
		locations = append(locations, Location{
			LogicalLocation: &LogicalLocation{
				Name: f.TargetID.String(),
				Kind: "target",
			},
		})
	}

	return locations
}

// getMitreAttackFromMetadata retrieves MITRE ATT&CK mappings from agent.Finding's Metadata.
// Returns empty slice if not found or if conversion fails.
func getMitreAttackFromMetadata(f *agent.Finding) []finding.SimpleMitreMapping {
	if f.Metadata == nil {
		return nil
	}

	// Try to get from Metadata using the well-known key
	data, ok := f.Metadata[sdkSecurity.MetaKeyMitreAttack]
	if !ok {
		return nil
	}

	// The metadata could contain a single mapping or an array
	// Try single mapping first (sdkSecurity.MitreMapping)
	if mapping, ok := data.(sdkSecurity.MitreMapping); ok {
		return []finding.SimpleMitreMapping{
			{
				TechniqueID:   mapping.TechniqueID,
				TechniqueName: mapping.TechniqueName,
				Tactic:        mapping.TacticName,
			},
		}
	}

	// Try array of SDK mappings
	if mappings, ok := data.([]sdkSecurity.MitreMapping); ok {
		result := make([]finding.SimpleMitreMapping, len(mappings))
		for i, m := range mappings {
			result[i] = finding.SimpleMitreMapping{
				TechniqueID:   m.TechniqueID,
				TechniqueName: m.TechniqueName,
				Tactic:        m.TacticName,
			}
		}
		return result
	}

	// Try to convert from map (JSON unmarshaling might produce map[string]interface{})
	if mapData, ok := data.(map[string]interface{}); ok {
		techniqueID, _ := mapData["technique_id"].(string)
		techniqueName, _ := mapData["technique_name"].(string)
		tacticName, _ := mapData["tactic_name"].(string)
		if techniqueID != "" {
			return []finding.SimpleMitreMapping{
				{
					TechniqueID:   techniqueID,
					TechniqueName: techniqueName,
					Tactic:        tacticName,
				},
			}
		}
	}

	// Try array of maps
	if arrayData, ok := data.([]interface{}); ok {
		result := make([]finding.SimpleMitreMapping, 0, len(arrayData))
		for _, item := range arrayData {
			if mapItem, ok := item.(map[string]interface{}); ok {
				techniqueID, _ := mapItem["technique_id"].(string)
				techniqueName, _ := mapItem["technique_name"].(string)
				tacticName, _ := mapItem["tactic_name"].(string)
				if techniqueID != "" {
					result = append(result, finding.SimpleMitreMapping{
						TechniqueID:   techniqueID,
						TechniqueName: techniqueName,
						Tactic:        tacticName,
					})
				}
			}
		}
		if len(result) > 0 {
			return result
		}
	}

	return nil
}

// getMitreAtlasFromMetadata retrieves MITRE ATLAS mappings from agent.Finding's Metadata.
// Returns empty slice if not found or if conversion fails.
func getMitreAtlasFromMetadata(f *agent.Finding) []finding.SimpleMitreMapping {
	if f.Metadata == nil {
		return nil
	}

	// Try to get from Metadata using the well-known key
	data, ok := f.Metadata[sdkSecurity.MetaKeyMitreAtlas]
	if !ok {
		return nil
	}

	// The metadata could contain a single mapping or an array
	// Try single mapping first (sdkSecurity.MitreMapping)
	if mapping, ok := data.(sdkSecurity.MitreMapping); ok {
		return []finding.SimpleMitreMapping{
			{
				TechniqueID:   mapping.TechniqueID,
				TechniqueName: mapping.TechniqueName,
				Tactic:        mapping.TacticName,
			},
		}
	}

	// Try array of SDK mappings
	if mappings, ok := data.([]sdkSecurity.MitreMapping); ok {
		result := make([]finding.SimpleMitreMapping, len(mappings))
		for i, m := range mappings {
			result[i] = finding.SimpleMitreMapping{
				TechniqueID:   m.TechniqueID,
				TechniqueName: m.TechniqueName,
				Tactic:        m.TacticName,
			}
		}
		return result
	}

	// Try to convert from map (JSON unmarshaling might produce map[string]interface{})
	if mapData, ok := data.(map[string]interface{}); ok {
		techniqueID, _ := mapData["technique_id"].(string)
		techniqueName, _ := mapData["technique_name"].(string)
		tacticName, _ := mapData["tactic_name"].(string)
		if techniqueID != "" {
			return []finding.SimpleMitreMapping{
				{
					TechniqueID:   techniqueID,
					TechniqueName: techniqueName,
					Tactic:        tacticName,
				},
			}
		}
	}

	// Try array of maps
	if arrayData, ok := data.([]interface{}); ok {
		result := make([]finding.SimpleMitreMapping, 0, len(arrayData))
		for _, item := range arrayData {
			if mapItem, ok := item.(map[string]interface{}); ok {
				techniqueID, _ := mapItem["technique_id"].(string)
				techniqueName, _ := mapItem["technique_name"].(string)
				tacticName, _ := mapItem["tactic_name"].(string)
				if techniqueID != "" {
					result = append(result, finding.SimpleMitreMapping{
						TechniqueID:   techniqueID,
						TechniqueName: techniqueName,
						Tactic:        tacticName,
					})
				}
			}
		}
		if len(result) > 0 {
			return result
		}
	}

	return nil
}

// getCVSSFromMetadata retrieves CVSS score from agent.Finding's Metadata.
// Returns the score and true if found, or empty score and false if not present.
func getCVSSFromMetadata(f *agent.Finding) (agent.CVSSScore, bool) {
	if f.Metadata == nil {
		return agent.CVSSScore{}, false
	}

	// Try to get from Metadata using the well-known key
	data, ok := f.Metadata[sdkSecurity.MetaKeyCVSS]
	if !ok {
		return agent.CVSSScore{}, false
	}

	// Try direct type assertion (sdkSecurity.CVSSScore)
	if cvss, ok := data.(sdkSecurity.CVSSScore); ok {
		return agent.CVSSScore{
			Version: cvss.Version,
			Vector:  cvss.Vector,
			Score:   cvss.Score,
		}, true
	}

	// Try to convert from map (JSON unmarshaling might produce map[string]interface{})
	if mapData, ok := data.(map[string]interface{}); ok {
		version, _ := mapData["version"].(string)
		vector, _ := mapData["vector"].(string)
		score, _ := mapData["score"].(float64)
		if version != "" || vector != "" || score > 0 {
			return agent.CVSSScore{
				Version: version,
				Vector:  vector,
				Score:   score,
			}, true
		}
	}

	return agent.CVSSScore{}, false
}

// getCWEFromMetadata retrieves CWE identifiers from agent.Finding's Metadata.
// Returns the CWE IDs or empty slice if not present.
func getCWEFromMetadata(f *agent.Finding) []string {
	if f.Metadata == nil {
		return nil
	}

	// Try to get from Metadata using the well-known key
	data, ok := f.Metadata[sdkSecurity.MetaKeyCWE]
	if !ok {
		return nil
	}

	// Try direct type assertion ([]string)
	if cwe, ok := data.([]string); ok {
		return cwe
	}

	// Try to convert from []interface{}
	if arrayData, ok := data.([]interface{}); ok {
		result := make([]string, 0, len(arrayData))
		for _, item := range arrayData {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		if len(result) > 0 {
			return result
		}
	}

	return nil
}

// Ensure SARIFExporter implements Exporter interface
var _ Exporter = (*SARIFExporter)(nil)
