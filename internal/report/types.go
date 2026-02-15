package report

import (
	"fmt"
	"time"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/finding"
	"github.com/zero-day-ai/gibson/internal/types"
)

// ReportType represents the type of security report to generate
type ReportType string

const (
	ReportTypeExecutive       ReportType = "executive"
	ReportTypeTechnical       ReportType = "technical"
	ReportTypeCompliance      ReportType = "compliance"
	ReportTypeRemediation     ReportType = "remediation"
	ReportTypeAttackNarrative ReportType = "attack_narrative"
	ReportTypeAssetDiscovery  ReportType = "asset_discovery"
	ReportTypeCustom          ReportType = "custom"
)

// String returns the string representation of ReportType
func (rt ReportType) String() string {
	return string(rt)
}

// IsValid checks if the report type is a valid value
func (rt ReportType) IsValid() bool {
	switch rt {
	case ReportTypeExecutive, ReportTypeTechnical, ReportTypeCompliance,
		ReportTypeRemediation, ReportTypeAttackNarrative, ReportTypeAssetDiscovery,
		ReportTypeCustom:
		return true
	default:
		return false
	}
}

// ReportFormat represents the output format for the report
type ReportFormat string

const (
	FormatPDF      ReportFormat = "pdf"
	FormatHTML     ReportFormat = "html"
	FormatMarkdown ReportFormat = "markdown"
	FormatJSON     ReportFormat = "json"
	FormatSARIF    ReportFormat = "sarif"
	FormatCSV      ReportFormat = "csv"
	FormatDOCX     ReportFormat = "docx"
)

// String returns the string representation of ReportFormat
func (rf ReportFormat) String() string {
	return string(rf)
}

// IsValid checks if the report format is a valid value
func (rf ReportFormat) IsValid() bool {
	switch rf {
	case FormatPDF, FormatHTML, FormatMarkdown, FormatJSON,
		FormatSARIF, FormatCSV, FormatDOCX:
		return true
	default:
		return false
	}
}

// Report represents a generated security report
type Report struct {
	ID           types.ID       `json:"id"`
	MissionID    types.ID       `json:"mission_id"`
	Type         ReportType     `json:"type"`
	Format       ReportFormat   `json:"format"`
	Title        string         `json:"title"`
	Summary      string         `json:"summary"`
	GeneratedAt  time.Time      `json:"generated_at"`
	GeneratedBy  string         `json:"generated_by"` // User or system
	TemplateUsed string         `json:"template_used"`
	Options      ReportOptions  `json:"options"`
	Metadata     ReportMetadata `json:"metadata"`
	FilePath     string         `json:"file_path"`
	FileSize     int64          `json:"file_size"`
	Checksum     string         `json:"checksum"` // SHA256
}

// ReportOptions configures how a report should be generated
type ReportOptions struct {
	IncludeEvidence      bool             `json:"include_evidence"`
	IncludeMetrics       bool             `json:"include_metrics"`
	IncludeTimeline      bool             `json:"include_timeline"`
	IncludeGraphRAG      bool             `json:"include_graph_rag"`
	IncludeRemediation   bool             `json:"include_remediation"`
	RedactSensitive      bool             `json:"redact_sensitive"`
	MinSeverity          string           `json:"min_severity"`
	Categories           []string         `json:"categories,omitempty"`
	ComplianceFrameworks []string         `json:"compliance_frameworks,omitempty"`
	CustomTemplate       string           `json:"custom_template,omitempty"`
	Branding             *BrandingOptions `json:"branding,omitempty"`
	Language             string           `json:"language"`
}

// BrandingOptions configures custom branding for reports
type BrandingOptions struct {
	CompanyName    string `json:"company_name,omitempty"`
	LogoPath       string `json:"logo_path,omitempty"`
	PrimaryColor   string `json:"primary_color,omitempty"`
	SecondaryColor string `json:"secondary_color,omitempty"`
	FontFamily     string `json:"font_family,omitempty"`
	HeaderTemplate string `json:"header_template,omitempty"`
	FooterTemplate string `json:"footer_template,omitempty"`
}

// ReportMetadata contains summary statistics about a report
type ReportMetadata struct {
	FindingCount        int           `json:"finding_count"`
	CriticalCount       int           `json:"critical_count"`
	HighCount           int           `json:"high_count"`
	MediumCount         int           `json:"medium_count"`
	LowCount            int           `json:"low_count"`
	InfoCount           int           `json:"info_count"`
	AgentsUsed          []string      `json:"agents_used,omitempty"`
	ToolsUsed           []string      `json:"tools_used,omitempty"`
	MissionDuration     time.Duration `json:"mission_duration"`
	TotalTokens         int64         `json:"total_tokens"`
	TotalCost           float64       `json:"total_cost"`
	AssetsDiscovered    int           `json:"assets_discovered"`
	MitreAttackCoverage []string      `json:"mitre_attack_coverage,omitempty"`
	MitreAtlasCoverage  []string      `json:"mitre_atlas_coverage,omitempty"`
}

// ReportData represents the aggregated data from all sources for report generation
type ReportData struct {
	Mission           MissionSummary               `json:"mission"`
	Target            TargetSummary                `json:"target"`
	Workflow          WorkflowSummary              `json:"workflow"`
	Findings          []EnhancedFindingData        `json:"findings"`
	FindingsByAgent   map[string][]types.ID        `json:"findings_by_agent"`
	Metrics           AggregatedMetrics            `json:"metrics"`
	CostBreakdown     CostBreakdown                `json:"cost_breakdown"`
	Timeline          []TimelineEvent              `json:"timeline,omitempty"`
	Assets            []DiscoveredAsset            `json:"assets,omitempty"`
	Relationships     []AssetRelationship          `json:"relationships,omitempty"`
	AttackPatterns    []MitrePattern               `json:"attack_patterns,omitempty"`
	AttackChains      []AttackChain                `json:"attack_chains,omitempty"`
	PayloadExecutions []PayloadExecutionData       `json:"payload_executions,omitempty"`
	ComplianceState   map[string]ComplianceMapping `json:"compliance_state,omitempty"`
	RiskScore         float64                      `json:"risk_score"`
	ExecutiveSummary  ExecutiveSummaryData         `json:"executive_summary"`
}

// MissionSummary contains mission-level context
type MissionSummary struct {
	ID              types.ID           `json:"id"`
	Name            string             `json:"name"`
	Description     string             `json:"description"`
	StartedAt       time.Time          `json:"started_at"`
	CompletedAt     *time.Time         `json:"completed_at,omitempty"`
	Status          string             `json:"status"`
	RunNumber       int                `json:"run_number"`
	ParentMissionID *types.ID          `json:"parent_mission_id,omitempty"`
	Constraints     MissionConstraints `json:"constraints"`
}

// MissionConstraints contains mission execution constraints
type MissionConstraints struct {
	TimeLimit    *time.Duration `json:"time_limit,omitempty"`
	CostLimit    *float64       `json:"cost_limit,omitempty"`
	FindingLimit *int           `json:"finding_limit,omitempty"`
}

// TargetSummary contains information about the assessment target
type TargetSummary struct {
	ID           types.ID       `json:"id"`
	Type         string         `json:"type"`
	Provider     string         `json:"provider"`
	Model        string         `json:"model,omitempty"`
	URL          string         `json:"url,omitempty"`
	Capabilities []string       `json:"capabilities,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

// WorkflowSummary contains workflow structure information
type WorkflowSummary struct {
	Nodes      []WorkflowNode    `json:"nodes"`
	Edges      []WorkflowEdge    `json:"edges"`
	EntryPoint string            `json:"entry_point"`
	ExitPoints []string          `json:"exit_points"`
	Agents     map[string]string `json:"agents"` // node_id -> agent_name
}

// WorkflowNode represents a workflow execution node
type WorkflowNode struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Type        string         `json:"type"`
	AgentName   string         `json:"agent_name,omitempty"`
	Status      string         `json:"status"`
	StartedAt   *time.Time     `json:"started_at,omitempty"`
	CompletedAt *time.Time     `json:"completed_at,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// WorkflowEdge represents a connection between workflow nodes
type WorkflowEdge struct {
	From      string         `json:"from"`
	To        string         `json:"to"`
	Condition string         `json:"condition,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// EnhancedFindingData extends finding data with report-specific information
type EnhancedFindingData struct {
	finding.EnhancedFinding
	AttackChainID    *types.ID `json:"attack_chain_id,omitempty"`
	RemediationOrder *int      `json:"remediation_order,omitempty"`
	EffortEstimate   string    `json:"effort_estimate,omitempty"` // Low, Medium, High
	BusinessImpact   string    `json:"business_impact,omitempty"`
}

// AggregatedMetrics contains aggregated execution metrics
type AggregatedMetrics struct {
	NodesExecuted      int              `json:"nodes_executed"`
	NodesFailed        int              `json:"nodes_failed"`
	TotalDuration      time.Duration    `json:"total_duration"`
	FindingsBySeverity map[string]int   `json:"findings_by_severity"`
	TokensByProvider   map[string]int64 `json:"tokens_by_provider"`
	TotalLLMCalls      int              `json:"total_llm_calls"`
	TotalToolCalls     int              `json:"total_tool_calls"`
	TotalRetries       int              `json:"total_retries"`
	TotalErrors        int              `json:"total_errors"`
}

// CostBreakdown contains detailed cost analysis
type CostBreakdown struct {
	TotalCost      float64            `json:"total_cost"`
	CostByAgent    map[string]float64 `json:"cost_by_agent"`
	CostByProvider map[string]float64 `json:"cost_by_provider"`
	CostByPhase    map[string]float64 `json:"cost_by_phase,omitempty"`
}

// TimelineEvent represents an event in the mission timeline
type TimelineEvent struct {
	Timestamp   time.Time      `json:"timestamp"`
	Type        string         `json:"type"`
	Actor       string         `json:"actor"` // Agent or system component
	Action      string         `json:"action"`
	Description string         `json:"description"`
	FindingID   *types.ID      `json:"finding_id,omitempty"`
	TraceID     string         `json:"trace_id,omitempty"`
	SpanID      string         `json:"span_id,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// DiscoveredAsset represents an asset discovered during the assessment
type DiscoveredAsset struct {
	ID           types.ID       `json:"id"`
	Type         string         `json:"type"` // Host, Port, Service, Endpoint, Vulnerability
	Name         string         `json:"name"`
	Properties   map[string]any `json:"properties"`
	DiscoveredAt time.Time      `json:"discovered_at"`
	DiscoveredBy string         `json:"discovered_by"` // Agent name
	FindingIDs   []types.ID     `json:"finding_ids,omitempty"`
}

// AssetRelationship represents a relationship between discovered assets
type AssetRelationship struct {
	FromAssetID types.ID       `json:"from_asset_id"`
	ToAssetID   types.ID       `json:"to_asset_id"`
	Type        string         `json:"type"` // has_port, runs_service, exposes_endpoint, etc.
	Properties  map[string]any `json:"properties,omitempty"`
}

// MitrePattern represents a MITRE ATT&CK or ATLAS pattern
type MitrePattern struct {
	TechniqueID   string     `json:"technique_id"`
	TechniqueName string     `json:"technique_name"`
	Tactic        string     `json:"tactic"`
	Framework     string     `json:"framework"` // ATTACK or ATLAS
	FindingIDs    []types.ID `json:"finding_ids"`
	Frequency     int        `json:"frequency"` // Number of times this pattern was observed
}

// AttackChain represents a sequence of related findings forming an attack path
type AttackChain struct {
	ID          types.ID              `json:"id"`
	Name        string                `json:"name"`
	Description string                `json:"description"`
	FindingIDs  []types.ID            `json:"finding_ids"`            // Ordered by attack progression
	Severity    agent.FindingSeverity `json:"severity"`               // Highest severity in chain
	MitrePhases []string              `json:"mitre_phases,omitempty"` // Kill chain phases
}

// PayloadExecutionData represents information about executed payloads
type PayloadExecutionData struct {
	ID               types.ID                     `json:"id"`
	Category         string                       `json:"category"`
	Name             string                       `json:"name"`
	Description      string                       `json:"description"`
	Severity         agent.FindingSeverity        `json:"severity"`
	ExecutedAt       time.Time                    `json:"executed_at"`
	Status           string                       `json:"status"` // success, failure, partial
	ResultingFinding *types.ID                    `json:"resulting_finding,omitempty"`
	MitreMappings    []finding.SimpleMitreMapping `json:"mitre_mappings,omitempty"`
	Metadata         map[string]any               `json:"metadata,omitempty"`
}

// ComplianceMapping represents findings mapped to a compliance framework
type ComplianceMapping struct {
	Framework         string          `json:"framework"` // NIST, OWASP, CIS, etc.
	Version           string          `json:"version"`
	ControlsMapped    int             `json:"controls_mapped"`
	ControlsPassed    int             `json:"controls_passed"`
	ControlsFailed    int             `json:"controls_failed"`
	ControlsPartial   int             `json:"controls_partial"`
	ControlsNotTested int             `json:"controls_not_tested"`
	Score             float64         `json:"score"` // 0.0 - 100.0
	Grade             string          `json:"grade"` // A, B, C, D, F
	Details           []ControlDetail `json:"details"`
}

// ControlDetail represents a specific control mapping
type ControlDetail struct {
	ControlID   string        `json:"control_id"`
	ControlName string        `json:"control_name"`
	Category    string        `json:"category"`
	Status      ControlStatus `json:"status"`
	FindingIDs  []types.ID    `json:"finding_ids,omitempty"`
	Evidence    string        `json:"evidence,omitempty"`
}

// ControlStatus represents the compliance status of a control
type ControlStatus string

const (
	ControlStatusCompliant          ControlStatus = "compliant"
	ControlStatusNonCompliant       ControlStatus = "non_compliant"
	ControlStatusPartiallyCompliant ControlStatus = "partially_compliant"
	ControlStatusNotTested          ControlStatus = "not_tested"
)

// String returns the string representation of ControlStatus
func (cs ControlStatus) String() string {
	return string(cs)
}

// IsValid checks if the control status is a valid value
func (cs ControlStatus) IsValid() bool {
	switch cs {
	case ControlStatusCompliant, ControlStatusNonCompliant,
		ControlStatusPartiallyCompliant, ControlStatusNotTested:
		return true
	default:
		return false
	}
}

// ExecutiveSummaryData contains executive-level summary information
type ExecutiveSummaryData struct {
	KeyFindings        []KeyFinding `json:"key_findings"` // Top 5 critical findings
	RiskSummary        RiskSummary  `json:"risk_summary"`
	RecommendedActions []string     `json:"recommended_actions"`
	TrendComparison    *TrendData   `json:"trend_comparison,omitempty"`
}

// KeyFinding represents a critical finding for executive summary
type KeyFinding struct {
	FindingID      types.ID              `json:"finding_id"`
	Title          string                `json:"title"`
	Severity       agent.FindingSeverity `json:"severity"`
	BusinessImpact string                `json:"business_impact"`
	Summary        string                `json:"summary"`
}

// RiskSummary provides risk-level statistics
type RiskSummary struct {
	OverallRiskScore float64 `json:"overall_risk_score"` // 0.0 - 10.0
	TotalFindings    int     `json:"total_findings"`
	CriticalFindings int     `json:"critical_findings"`
	HighFindings     int     `json:"high_findings"`
	MediumFindings   int     `json:"medium_findings"`
	LowFindings      int     `json:"low_findings"`
	InfoFindings     int     `json:"info_findings"`
}

// TrendData represents comparison with previous mission runs
type TrendData struct {
	PreviousMissionID types.ID `json:"previous_mission_id"`
	FindingsChange    int      `json:"findings_change"` // Positive = more findings
	RiskScoreChange   float64  `json:"risk_score_change"`
	NewFindings       int      `json:"new_findings"`
	ResolvedFindings  int      `json:"resolved_findings"`
	RegressedFindings int      `json:"regressed_findings"` // Previously fixed, now broken
}

// GenerateOptions contains options for report generation
type GenerateOptions struct {
	MissionID            types.ID              `json:"mission_id"`
	Type                 ReportType            `json:"type"`
	Format               ReportFormat          `json:"format"`
	IncludeEvidence      bool                  `json:"include_evidence"`
	IncludeMetrics       bool                  `json:"include_metrics"`
	IncludeTimeline      bool                  `json:"include_timeline"`
	IncludeGraphRAG      bool                  `json:"include_graph_rag"`
	IncludeRemediation   bool                  `json:"include_remediation"`
	RedactSensitive      bool                  `json:"redact_sensitive"`
	MinSeverity          agent.FindingSeverity `json:"min_severity,omitempty"`
	Categories           []string              `json:"categories,omitempty"`
	ComplianceFrameworks []string              `json:"compliance_frameworks,omitempty"`
	CustomTemplate       string                `json:"custom_template,omitempty"`
	Branding             *BrandingOptions      `json:"branding,omitempty"`
	Language             string                `json:"language"`
	OutputPath           string                `json:"output_path,omitempty"`
}

// Validate checks if the GenerateOptions are valid
func (o GenerateOptions) Validate() error {
	if o.MissionID.IsZero() {
		return fmt.Errorf("mission_id is required")
	}

	if !o.Type.IsValid() {
		return fmt.Errorf("invalid report type: %s", o.Type)
	}

	if !o.Format.IsValid() {
		return fmt.Errorf("invalid report format: %s", o.Format)
	}

	if o.Language == "" {
		return fmt.Errorf("language is required")
	}

	return nil
}
