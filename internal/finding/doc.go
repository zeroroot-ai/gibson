// Package finding provides comprehensive security finding management for the Gibson Framework.
//
// # Overview
//
// The finding package extends the basic Finding type from internal/agent with
// enhanced classification, MITRE ATT&CK/ATLAS mapping, structured evidence,
// multiple export formats, and analytics capabilities.
//
// # Key Types
//
// EnhancedFinding embeds agent.Finding and adds classification, MITRE mappings,
// evidence management, and lifecycle tracking:
//
//	finding := &EnhancedFinding{
//		Finding: agent.Finding{
//			Title:       "Jailbreak via DAN prompt",
//			Description: "Successfully bypassed safety guardrails",
//			Severity:    agent.SeverityHigh,
//		},
//		Category:    CategoryJailbreak,
//		Subcategory: "guardrail_bypass",
//		Status:      StatusOpen,
//	}
//
// # Classification
//
// Findings can be classified using heuristic patterns or LLM-based analysis:
//
//	classifier := NewCompositeClassifier(
//		NewHeuristicClassifier(),
//		NewLLMClassifier(WithConfidenceThreshold(0.8)),
//	)
//	classification, err := classifier.Classify(ctx, finding)
//
// # Storage
//
// The DBFindingStore provides persistent storage for findings with efficient querying:
//
//	// Create database connection
//	db, err := database.New("findings.db")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Run migrations
//	migrator := database.NewMigrator(db)
//	err = migrator.Migrate(context.Background())
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Create store
//	store := finding.NewDBFindingStore(db)
//
//	// Store a finding
//	err = store.Store(ctx, enhancedFinding)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Query findings with filters
//	filter := finding.NewFindingFilter().
//		WithSeverity(agent.SeverityHigh).
//		WithStatus(finding.StatusOpen)
//	findings, err := store.List(ctx, missionID, filter)
//
// # Analytics
//
// The FindingAnalytics provides statistical analysis and trend tracking:
//
//	analytics := finding.NewFindingAnalytics(store)
//
//	// Get statistics for a mission
//	stats, err := analytics.GetStatistics(ctx, missionID)
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Printf("Total findings: %d\n", stats.Total)
//	fmt.Printf("Critical: %d\n", stats.BySeverity[agent.SeverityCritical])
//	fmt.Printf("Average risk: %.2f\n", stats.AverageRiskScore)
//
//	// Get trends over time
//	trends, err := analytics.GetTrends(ctx, missionID, 7*24*time.Hour)
//	for _, trend := range trends {
//		fmt.Printf("%s: %d findings (risk: %.2f)\n",
//			trend.Timestamp.Format("2006-01-02"),
//			trend.Count,
//			trend.RiskScore)
//	}
//
//	// Calculate mission risk score
//	riskScore, err := analytics.GetRiskScore(ctx, missionID)
//	fmt.Printf("Mission risk score: %.2f\n", riskScore)
//
// # Export
//
// Multiple export formats are supported for reporting and integration:
//
//	import "github.com/zeroroot-ai/gibson/internal/finding/export"
//
//	// Export to JSON
//	exporter := export.NewJSONExporter()
//	data, err := exporter.Export(ctx, findings, export.ExportOptions{
//		IncludeEvidence: true,
//		MinSeverity:     &agent.SeverityHigh,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	os.WriteFile("findings.json", data, 0644)
//
// Supported formats:
//   - JSON: Structured JSON with full finding details
//   - SARIF: SARIF 2.1.0 format for security tool integration
//   - CSV: Tabular format for spreadsheet analysis
//   - HTML: Human-readable HTML reports
//   - Markdown: Documentation-friendly markdown format
//
// # MITRE Mapping
//
// The MitreDatabase provides ATT&CK and ATLAS technique lookup:
//
//	db := NewMitreDatabase()
//	techniques := db.FindForCategory(CategoryPromptInjection)
//
// MITRE mappings include:
//   - MITRE ATT&CK: Traditional adversary tactics and techniques
//   - MITRE ATLAS: AI/ML-specific attack patterns
//
// # Finding Categories
//
// The package defines standard categories for LLM security findings:
//
//   - CategoryJailbreak: Attempts to bypass safety guardrails
//   - CategoryPromptInjection: Malicious prompt manipulation
//   - CategoryDataExtraction: Unauthorized data access
//   - CategoryInformationDisclosure: System information leakage
//   - CategoryPrivilegeEscalation: Unauthorized capability expansion
//   - CategoryDoS: Denial of service attacks
//   - CategoryModelManipulation: Model behavior modification
//
// # Finding Lifecycle
//
// Findings progress through several states:
//
//   - StatusOpen: Newly discovered, awaiting review
//   - StatusConfirmed: Validated as a real issue
//   - StatusResolved: Fixed or mitigated
//   - StatusFalsePositive: Determined to be not an actual issue
//
// Example lifecycle:
//
//	// Create finding
//	finding := finding.NewEnhancedFinding(baseFinding, missionID, agentName)
//	store.Store(ctx, finding)
//
//	// Confirm finding
//	finding = finding.WithStatus(finding.StatusConfirmed)
//	store.Update(ctx, finding)
//
//	// Add remediation
//	finding.Remediation = "Apply input sanitization and content filtering"
//	store.Update(ctx, finding)
//
//	// Resolve finding
//	finding = finding.WithStatus(finding.StatusResolved)
//	store.Update(ctx, finding)
//
// # Concurrency
//
// All store operations are safe for concurrent use from multiple goroutines.
// The DBFindingStore uses database transactions to ensure data consistency.
//
// # Performance
//
// The store uses optimized indexes for common query patterns:
//   - mission_id for mission-scoped queries
//   - severity for severity filtering
//   - status for lifecycle state filtering
//   - category for classification queries
//   - risk_score for risk-based sorting
//   - created_at for temporal queries
//
// # Error Handling
//
// All methods return errors that can be checked for specific conditions:
//
//	finding, err := store.Get(ctx, findingID)
//	if err != nil {
//		if strings.Contains(err.Error(), "not found") {
//			// Handle missing finding
//		} else {
//			// Handle other errors
//		}
//	}
//
// # Testing
//
// The package includes comprehensive test coverage:
//   - Unit tests for individual components
//   - Integration tests for full lifecycle scenarios
//   - Concurrent operation tests for thread safety
//
// Run tests with:
//
//	go test ./internal/finding/...
//
// Run integration tests with:
//
//	go test -tags=integration ./internal/finding/...
package finding
