# Mission Report Synthesis - Requirements Specification

## Overview

**Spec Name:** mission-report-synthesis
**Version:** 1.0.0
**Created:** 2026-02-15
**Status:** Draft

### Problem Statement

Gibson is an autonomous security testing framework that orchestrates AI agents to perform comprehensive security assessments. During mission execution, vast amounts of security-relevant data are generated across multiple subsystems:

- **Findings** with evidence, classification, MITRE mappings, and remediation guidance
- **Mission metadata** including workflow execution, agent assignments, and constraints
- **Execution metrics** covering tokens, costs, duration, and node completion rates
- **GraphRAG knowledge** with discovered assets, relationships, and attack patterns
- **Event timelines** tracking agent actions, tool invocations, and decisions
- **Memory artifacts** from working, mission, and long-term memory stores

Currently, this data exists in disparate storage systems (SQLite, Neo4j, in-memory) with basic export capabilities (JSON, CSV, SARIF). Security teams require **comprehensive, professional reports** that synthesize all data sources into formats they understand: executive summaries, technical deep-dives, compliance mappings, and actionable remediation plans.

### Goals

1. **Unified Report Generation**: Synthesize data from all Gibson subsystems into cohesive security reports
2. **Multiple Report Types**: Support executive, technical, compliance, and remediation-focused reports
3. **Industry Standards**: Generate reports compatible with security team workflows (SARIF 2.1, NIST CSF, CIS, OWASP mappings)
4. **Actionable Output**: Provide clear remediation priorities, risk rankings, and business impact assessments
5. **Audit Trail**: Include full provenance (which agent found what, when, with what evidence)
6. **Multi-Format Export**: PDF, HTML, Markdown, JSON, and machine-readable formats
7. **Customization**: Support custom report templates and branding

---

## Functional Requirements

### FR-1: Data Aggregation Layer

#### FR-1.1: Finding Collection
**As a** security analyst
**I want** all findings from a mission aggregated with full context
**So that** I can understand the complete security posture discovered

**Acceptance Criteria:**
- [ ] Collect all `EnhancedFinding` records associated with a mission ID
- [ ] Include nested evidence arrays with full data
- [ ] Include reproduction steps (`ReproStep`) for each finding
- [ ] Resolve related findings via `RelatedIDs` into a graph structure
- [ ] Include occurrence counts for deduplicated findings
- [ ] Preserve agent attribution (`AgentName`, `DelegatedFrom`)
- [ ] Include classification metadata (method, confidence, rationale)

#### FR-1.2: Mission Metadata Collection
**As a** report generator
**I want** complete mission execution metadata
**So that** reports include full context about assessment scope and methodology

**Acceptance Criteria:**
- [ ] Retrieve mission definition (name, description, workflow JSON)
- [ ] Include target information (type, provider, URL, model, capabilities)
- [ ] Include workflow structure (nodes, edges, entry/exit points)
- [ ] Include agent assignments per workflow node
- [ ] Include mission constraints (time limits, cost limits, finding limits)
- [ ] Include checkpoint data if mission was paused/resumed
- [ ] Include parent/child mission relationships (sub-missions)
- [ ] Include run history (run numbers, previous run IDs)

#### FR-1.3: Metrics Collection
**As a** stakeholder reviewing the assessment
**I want** comprehensive execution metrics
**So that** I understand the depth and cost of the security assessment

**Acceptance Criteria:**
- [ ] Aggregate `MissionMetrics` (nodes executed, failed, findings by severity)
- [ ] Aggregate `TaskMetrics` per agent (LLM calls, tool calls, tokens, cost)
- [ ] Calculate total token usage by provider
- [ ] Calculate total cost breakdown (per agent, per finding severity)
- [ ] Include timing data (mission duration, per-node duration)
- [ ] Include retry counts and error statistics

#### FR-1.4: GraphRAG Knowledge Extraction
**As a** security analyst
**I want** discovered assets and relationships from the knowledge graph
**So that** reports show the attack surface mapped during assessment

**Acceptance Criteria:**
- [ ] Query Neo4j for all nodes created during the mission
- [ ] Include node types: Host, Port, Service, Endpoint, Vulnerability
- [ ] Include relationships between discovered assets
- [ ] Include MITRE ATT&CK patterns identified
- [ ] Include MITRE ATLAS patterns for LLM-specific findings
- [ ] Support cross-mission correlation queries
- [ ] Include vector similarity matches from long-term memory

#### FR-1.5: Event Timeline Construction
**As a** security analyst
**I want** a chronological timeline of assessment activities
**So that** I can understand the attack progression and methodology

**Acceptance Criteria:**
- [ ] Collect all events for the mission from event store
- [ ] Order events chronologically
- [ ] Include event types: mission lifecycle, agent actions, tool calls, finding discoveries
- [ ] Include OpenTelemetry trace/span IDs for correlation
- [ ] Support filtering by event type
- [ ] Support time-range queries within the mission

#### FR-1.6: Payload Execution Tracking
**As a** security analyst
**I want** details on which payloads were executed and their results
**So that** I understand the attack vectors tested

**Acceptance Criteria:**
- [ ] Collect all `PayloadExecution` records for the mission
- [ ] Include payload metadata (category, severity, MITRE mappings)
- [ ] Include execution status and results
- [ ] Map payloads to resulting findings
- [ ] Include success indicators that triggered

---

### FR-2: Report Types

#### FR-2.1: Executive Summary Report
**As an** executive or business stakeholder
**I want** a high-level summary of security findings
**So that** I can make informed decisions about security investments

**Acceptance Criteria:**
- [ ] One-page summary with key metrics dashboard
- [ ] Risk score rollup (aggregate risk rating 0-10)
- [ ] Finding counts by severity (Critical/High/Medium/Low/Info)
- [ ] Top 5 critical findings with business impact
- [ ] Trend comparison (if previous mission runs exist)
- [ ] Cost of assessment vs. estimated remediation cost
- [ ] Recommended immediate actions (prioritized)
- [ ] Executive-appropriate language (no technical jargon)

#### FR-2.2: Technical Findings Report
**As a** security engineer or penetration tester
**I want** a detailed technical report of all findings
**So that** I can understand vulnerabilities and reproduce them

**Acceptance Criteria:**
- [ ] All findings with full technical details
- [ ] Evidence sections with code snippets, API responses, screenshots
- [ ] Step-by-step reproduction instructions
- [ ] CVSS v3 scoring with vector strings
- [ ] CWE mappings with descriptions
- [ ] MITRE ATT&CK/ATLAS technique details
- [ ] Remediation guidance with code examples where applicable
- [ ] Related findings grouped by attack chain
- [ ] Agent reasoning/methodology descriptions
- [ ] Raw tool output appendices

#### FR-2.3: Compliance Mapping Report
**As a** compliance officer or auditor
**I want** findings mapped to compliance frameworks
**So that** I can assess regulatory risk and audit readiness

**Acceptance Criteria:**
- [ ] NIST Cybersecurity Framework (CSF) mappings
- [ ] OWASP Top 10 mappings (Web and LLM versions)
- [ ] CIS Controls mappings
- [ ] SOC 2 Type II control mappings
- [ ] PCI-DSS requirement mappings (where applicable)
- [ ] GDPR/privacy impact considerations
- [ ] Gap analysis showing controls tested vs. controls with findings
- [ ] Compliance posture score per framework
- [ ] Evidence package for auditors

#### FR-2.4: Remediation Playbook
**As a** development or DevSecOps team
**I want** a prioritized remediation plan
**So that** I can efficiently fix discovered vulnerabilities

**Acceptance Criteria:**
- [ ] Findings prioritized by risk score and exploitability
- [ ] Effort estimates (complexity: Low/Medium/High)
- [ ] Remediation steps with specific guidance
- [ ] Code fix examples where applicable
- [ ] Responsible team/owner suggestions based on finding location
- [ ] Dependencies between remediations
- [ ] Verification tests (how to confirm the fix)
- [ ] Ticket/issue template generation (Jira, GitHub Issues, Linear)
- [ ] Sprint planning suggestions

#### FR-2.5: Attack Narrative Report
**As a** security team lead or red team manager
**I want** a narrative description of the attack progression
**So that** I can understand the attack paths and methodology used

**Acceptance Criteria:**
- [ ] Chronological narrative of assessment activities
- [ ] Attack chain visualization (finding relationships)
- [ ] Decision points and pivots made by agents
- [ ] Failed attack attempts and why they failed
- [ ] Successful techniques with timing
- [ ] MITRE ATT&CK kill chain mapping
- [ ] Lessons learned from agent behavior

#### FR-2.6: Asset Discovery Report
**As a** IT operations or asset management team
**I want** a report of all assets discovered during assessment
**So that** I can update our CMDB and asset inventory

**Acceptance Criteria:**
- [ ] All discovered hosts with metadata
- [ ] Open ports and services per host
- [ ] Endpoints discovered (API routes, etc.)
- [ ] Technology stack fingerprinting
- [ ] Relationships between assets
- [ ] Assets with vulnerabilities highlighted
- [ ] CSV/JSON export for CMDB import

---

### FR-3: Report Generation Engine

#### FR-3.1: Template System
**As a** report author
**I want** customizable report templates
**So that** I can create reports matching my organization's style

**Acceptance Criteria:**
- [ ] Support Go template syntax for report generation
- [ ] Provide default templates for each report type
- [ ] Allow custom templates stored in `~/.gibson/templates/`
- [ ] Support template inheritance (base + overrides)
- [ ] Include conditional sections based on data availability
- [ ] Support loops for finding iterations
- [ ] Support custom helper functions

#### FR-3.2: Multi-Format Export
**As a** report consumer
**I want** reports in multiple formats
**So that** I can use them in my preferred tools

**Acceptance Criteria:**
- [ ] PDF generation (professional formatting, charts, page breaks)
- [ ] HTML generation (standalone, embeddable)
- [ ] Markdown generation (GitHub-flavored, documentation-ready)
- [ ] JSON export (machine-readable, API-compatible)
- [ ] SARIF 2.1.0 export (enhanced with Gibson-specific extensions)
- [ ] CSV export (tabular data for spreadsheet analysis)
- [ ] DOCX export (Microsoft Word for enterprise sharing)

#### FR-3.3: Visualization Components
**As a** report reader
**I want** visual representations of data
**So that** I can quickly understand security posture

**Acceptance Criteria:**
- [ ] Severity distribution pie/donut charts
- [ ] Findings timeline (discoveries over time)
- [ ] Risk heatmap by category
- [ ] Attack chain flowchart diagrams
- [ ] Asset relationship graphs
- [ ] MITRE ATT&CK matrix coverage visualization
- [ ] Token/cost breakdown charts
- [ ] Trend charts (for multi-run comparisons)

#### FR-3.4: Data Redaction
**As a** report author
**I want** sensitive data automatically redacted
**So that** reports can be shared safely

**Acceptance Criteria:**
- [ ] Auto-detect and redact credentials in evidence
- [ ] Configurable redaction patterns (regex support)
- [ ] Redact API keys, tokens, passwords, secrets
- [ ] Option to generate fully redacted vs. internal versions
- [ ] Redaction audit log (what was redacted and where)
- [ ] Reversible redaction with key (for authorized viewers)

#### FR-3.5: Internationalization
**As a** global security team
**I want** reports generated in multiple languages
**So that** stakeholders can read reports in their preferred language

**Acceptance Criteria:**
- [ ] Support for English, Spanish, French, German, Japanese, Chinese
- [ ] Translatable template strings
- [ ] Localized date/time formats
- [ ] Severity level translations
- [ ] MITRE technique name translations (where available)

---

### FR-4: Report Management

#### FR-4.1: Report Storage
**As a** security team
**I want** generated reports stored and versioned
**So that** I can retrieve historical reports

**Acceptance Criteria:**
- [ ] Store reports in `~/.gibson/reports/` with structured naming
- [ ] Include mission ID, date, and report type in filename
- [ ] Store generation metadata (templates used, options, timestamp)
- [ ] Support report versioning (regenerate with updated templates)
- [ ] Compression for large reports
- [ ] Index for quick search/retrieval

#### FR-4.2: Report Distribution
**As a** security team lead
**I want** automated report distribution
**So that** stakeholders receive reports without manual effort

**Acceptance Criteria:**
- [ ] Email distribution with configurable recipients
- [ ] Slack/Teams webhook notifications with report links
- [ ] S3/cloud storage upload for large reports
- [ ] API endpoint to retrieve generated reports
- [ ] Scheduled report generation (post-mission hooks)

#### FR-4.3: Report Comparison
**As a** security analyst
**I want** to compare reports across mission runs
**So that** I can track security posture changes

**Acceptance Criteria:**
- [ ] Diff view between two mission reports
- [ ] New findings highlighted
- [ ] Resolved findings highlighted
- [ ] Severity changes tracked
- [ ] Trend analysis over multiple runs
- [ ] Regression detection (previously fixed, now broken)

---

### FR-5: CLI Integration

#### FR-5.1: Report Command
**As a** CLI user
**I want** a `gibson report` command
**So that** I can generate reports from the command line

**Acceptance Criteria:**
- [ ] `gibson report generate --mission <id> --type <type> --format <format>`
- [ ] `gibson report list` - show available reports
- [ ] `gibson report show <id>` - display report summary
- [ ] `gibson report export <id> --format <format>` - re-export in different format
- [ ] `gibson report compare <id1> <id2>` - compare two missions
- [ ] Support `--output` flag for file path
- [ ] Support `--template` flag for custom templates
- [ ] Support `--redact` flag for sensitive data handling

#### FR-5.2: Streaming Report Generation
**As a** user running long assessments
**I want** real-time report updates
**So that** I can see findings as they're discovered

**Acceptance Criteria:**
- [ ] `gibson report watch --mission <id>` - live updating report
- [ ] Progressive report building during mission execution
- [ ] WebSocket/SSE endpoint for live report data
- [ ] Incremental PDF generation checkpoints

---

### FR-6: API Integration

#### FR-6.1: gRPC Report Service
**As a** developer integrating with Gibson
**I want** a gRPC API for report generation
**So that** I can build custom report workflows

**Acceptance Criteria:**
- [ ] `ReportService.Generate(GenerateRequest) returns (Report)`
- [ ] `ReportService.List(ListRequest) returns (ReportList)`
- [ ] `ReportService.Get(GetRequest) returns (Report)`
- [ ] `ReportService.Export(ExportRequest) returns (ExportedReport)`
- [ ] `ReportService.Compare(CompareRequest) returns (ComparisonResult)`
- [ ] `ReportService.Stream(StreamRequest) returns (stream ReportUpdate)`
- [ ] Proper error handling and status codes

#### FR-6.2: REST/HTTP API
**As a** web developer
**I want** a REST API for report access
**So that** I can integrate reports into dashboards

**Acceptance Criteria:**
- [ ] `GET /api/v1/reports` - list reports
- [ ] `POST /api/v1/reports/generate` - generate new report
- [ ] `GET /api/v1/reports/{id}` - get report
- [ ] `GET /api/v1/reports/{id}/download` - download exported file
- [ ] `GET /api/v1/reports/{id}/findings` - paginated findings
- [ ] `GET /api/v1/missions/{id}/report` - generate report for mission
- [ ] OpenAPI 3.0 specification

---

## Non-Functional Requirements

### NFR-1: Performance

#### NFR-1.1: Report Generation Speed
- Generate executive summary in < 5 seconds for missions with < 100 findings
- Generate full technical report in < 30 seconds for missions with < 1000 findings
- Support missions with up to 10,000 findings
- PDF generation should not exceed 2x the time of HTML generation

#### NFR-1.2: Memory Efficiency
- Report generation should not exceed 512MB additional memory
- Stream large datasets instead of loading entirely into memory
- Support chunked PDF generation for large reports

### NFR-2: Reliability

#### NFR-2.1: Data Integrity
- Reports must include all findings without data loss
- Checksums for report content integrity
- Atomic report generation (complete or fail, no partial reports)
- Transaction support for multi-step report operations

#### NFR-2.2: Error Handling
- Graceful degradation if GraphRAG unavailable (report without knowledge graph)
- Clear error messages for template errors
- Validation of report data before generation

### NFR-3: Security

#### NFR-3.1: Access Control
- Report generation requires mission read access
- Sensitive reports require elevated permissions
- Audit logging of report generation and access

#### NFR-3.2: Data Protection
- Encryption at rest for stored reports
- Secure transmission of reports (TLS)
- Automatic credential redaction by default

### NFR-4: Maintainability

#### NFR-4.1: Modularity
- Report types should be pluggable (add new report types without core changes)
- Export formats should be pluggable
- Template system should be extensible

#### NFR-4.2: Testability
- Unit tests for all report components
- Integration tests for report generation pipeline
- Golden file tests for report output consistency

### NFR-5: Compatibility

#### NFR-5.1: Standard Compliance
- SARIF 2.1.0 fully compliant output
- CVSS v3.1 scoring compliance
- MITRE ATT&CK v14+ framework alignment
- MITRE ATLAS current version alignment

---

## Data Model

### Report Entity

```go
type Report struct {
    ID            types.ID           `json:"id"`
    MissionID     types.ID           `json:"mission_id"`
    Type          ReportType         `json:"type"`          // executive, technical, compliance, remediation, attack_narrative, asset_discovery
    Format        ReportFormat       `json:"format"`        // pdf, html, markdown, json, sarif, csv, docx
    Title         string             `json:"title"`
    Summary       string             `json:"summary"`
    GeneratedAt   time.Time          `json:"generated_at"`
    GeneratedBy   string             `json:"generated_by"`  // User or system
    TemplateUsed  string             `json:"template_used"`
    Options       ReportOptions      `json:"options"`
    Metadata      ReportMetadata     `json:"metadata"`
    FilePath      string             `json:"file_path"`
    FileSize      int64              `json:"file_size"`
    Checksum      string             `json:"checksum"`      // SHA256
}

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

type ReportOptions struct {
    IncludeEvidence     bool              `json:"include_evidence"`
    IncludeMetrics      bool              `json:"include_metrics"`
    IncludeTimeline     bool              `json:"include_timeline"`
    IncludeGraphRAG     bool              `json:"include_graph_rag"`
    IncludeRemediation  bool              `json:"include_remediation"`
    RedactSensitive     bool              `json:"redact_sensitive"`
    MinSeverity         string            `json:"min_severity"`
    Categories          []string          `json:"categories"`
    ComplianceFrameworks []string         `json:"compliance_frameworks"`
    CustomTemplate      string            `json:"custom_template"`
    Branding            BrandingOptions   `json:"branding"`
    Language            string            `json:"language"`
}

type ReportMetadata struct {
    FindingCount        int               `json:"finding_count"`
    CriticalCount       int               `json:"critical_count"`
    HighCount           int               `json:"high_count"`
    MediumCount         int               `json:"medium_count"`
    LowCount            int               `json:"low_count"`
    InfoCount           int               `json:"info_count"`
    AgentsUsed          []string          `json:"agents_used"`
    ToolsUsed           []string          `json:"tools_used"`
    MissionDuration     time.Duration     `json:"mission_duration"`
    TotalTokens         int64             `json:"total_tokens"`
    TotalCost           float64           `json:"total_cost"`
    AssetsDiscovered    int               `json:"assets_discovered"`
    MitreAttackCoverage []string          `json:"mitre_attack_coverage"`
    MitreAtlasCoverage  []string          `json:"mitre_atlas_coverage"`
}
```

### Aggregated Report Data

```go
type ReportData struct {
    Mission         MissionSummary             `json:"mission"`
    Target          TargetSummary              `json:"target"`
    Findings        []EnhancedFindingData      `json:"findings"`
    Metrics         AggregatedMetrics          `json:"metrics"`
    Timeline        []TimelineEvent            `json:"timeline"`
    Assets          []DiscoveredAsset          `json:"assets"`
    AttackChains    []AttackChain              `json:"attack_chains"`
    ComplianceMap   map[string]ComplianceState `json:"compliance_map"`
    Remediations    []RemediationItem          `json:"remediations"`
    ExecutiveSummary ExecutiveSummaryData      `json:"executive_summary"`
}
```

---

## Compliance Framework Mappings

### MITRE ATT&CK Mapping
- Map findings to ATT&CK techniques (Txxxx)
- Support ATT&CK for Enterprise, Mobile, ICS
- Visualize coverage on ATT&CK matrix

### MITRE ATLAS Mapping
- Map LLM-specific findings to ATLAS techniques (AML.Txxxx)
- Include AI-specific attack taxonomies
- Support emerging LLM threat landscape

### OWASP Mappings
- OWASP Top 10 Web (2021)
- OWASP Top 10 LLM (2023/2025)
- OWASP API Security Top 10
- OWASP Mobile Top 10

### NIST CSF Mapping
- Identify, Protect, Detect, Respond, Recover categories
- Control mapping to findings
- Maturity assessment

### CIS Controls Mapping
- CIS Controls v8 mapping
- Implementation Groups (IG1, IG2, IG3)
- Safeguard mapping

---

## Dependencies

### Internal Dependencies
- `internal/finding` - Finding data access
- `internal/mission` - Mission data access
- `internal/database` - SQLite storage
- `internal/graphrag` - Neo4j knowledge graph
- `internal/events` - Event timeline
- `internal/memory` - Memory artifacts
- `internal/harness` - Agent context

### External Dependencies
- PDF generation library (e.g., `go-pdf`, `chromedp` for HTML→PDF)
- Chart generation (e.g., `go-echarts`, `go-chart`)
- DOCX generation (e.g., `unioffice`)
- Templating (Go `text/template` + `html/template`)
- SARIF schema validation

---

## Out of Scope (v1)

- Real-time collaborative report editing
- Report scheduling daemon
- Custom chart designer UI
- Report theming UI
- AI-powered finding summarization (future enhancement)
- Natural language report querying
- Video report generation

---

## Glossary

| Term | Definition |
|------|------------|
| **Finding** | A security vulnerability or issue discovered during assessment |
| **EnhancedFinding** | A finding with classification, evidence, and remediation data |
| **Mission** | A complete security assessment execution |
| **Workflow** | A DAG defining the assessment methodology |
| **Agent** | An AI-powered security testing component |
| **GraphRAG** | Knowledge graph for discovered assets and relationships |
| **SARIF** | Static Analysis Results Interchange Format |
| **MITRE ATT&CK** | Adversarial tactics, techniques, and common knowledge framework |
| **MITRE ATLAS** | AI-specific attack framework |
| **CVSS** | Common Vulnerability Scoring System |
| **CWE** | Common Weakness Enumeration |

---

## Success Metrics

1. **Adoption**: 80% of missions result in at least one report generated
2. **Quality**: Reports pass manual review by security professionals
3. **Performance**: Report generation times meet NFR targets
4. **Completeness**: All findings from mission included in reports
5. **Compliance**: SARIF output validates against schema
6. **User Satisfaction**: Positive feedback from security teams on report usefulness
