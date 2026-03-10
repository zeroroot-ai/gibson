package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/finding"
	"github.com/zero-day-ai/gibson/internal/finding/export"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

var findingCmd = &cobra.Command{
	Use:   "finding",
	Short: "Manage security findings",
	Long:  `View, filter, and export security findings discovered during missions`,
}

var findingListCmd = &cobra.Command{
	Use:   "list",
	Short: "List findings with optional filtering",
	Long:  `List security findings with optional filtering by severity, category, or mission`,
	RunE:  runFindingList,
}

var findingShowCmd = &cobra.Command{
	Use:   "show FINDING_ID",
	Short: "Show detailed finding information",
	Long:  `Display full details for a specific finding including evidence, recommendations, and references`,
	Args:  cobra.ExactArgs(1),
	RunE:  runFindingShow,
}

var findingExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export findings to various formats",
	Long:  `Export findings to JSON, SARIF, CSV, or HTML format with optional filtering`,
	RunE:  runFindingExport,
}

// Flags for finding list
var (
	listSeverity string
	listCategory string
	listMission  string
	listStatus   string
	listScope    string
)

// Flags for finding export
var (
	exportFormat        string
	exportOutput        string
	exportMission       string
	exportSeverity      string
	exportCategory      string
	exportEvidence      bool
	exportResolved      bool
	exportMinConfidence float64
)

func init() {
	// List command flags
	findingListCmd.Flags().StringVar(&listSeverity, "severity", "", "Filter by severity (critical, high, medium, low, info)")
	findingListCmd.Flags().StringVar(&listCategory, "category", "", "Filter by category (e.g., jailbreak, prompt_injection)")
	findingListCmd.Flags().StringVar(&listMission, "mission", "", "Filter by mission ID")
	findingListCmd.Flags().StringVar(&listStatus, "status", "", "Filter by status (open, confirmed, resolved, false_positive)")
	findingListCmd.Flags().StringVar(&listScope, "scope", "all", "Filter scope: current_run, same_mission, all")

	// Export command flags
	findingExportCmd.Flags().StringVar(&exportFormat, "format", "json", "Export format (json, sarif, csv, html)")
	findingExportCmd.Flags().StringVar(&exportOutput, "output", "", "Output file path (default: stdout)")
	findingExportCmd.Flags().StringVar(&exportMission, "mission", "", "Filter by mission ID")
	findingExportCmd.Flags().StringVar(&exportSeverity, "severity", "", "Minimum severity (critical, high, medium, low, info)")
	findingExportCmd.Flags().StringVar(&exportCategory, "category", "", "Filter by category")
	findingExportCmd.Flags().BoolVar(&exportEvidence, "evidence", true, "Include evidence in export")
	findingExportCmd.Flags().BoolVar(&exportResolved, "resolved", false, "Include resolved/false positive findings")
	findingExportCmd.Flags().Float64Var(&exportMinConfidence, "min-confidence", 0.0, "Minimum confidence level (0.0-1.0)")

	// Add subcommands
	findingCmd.AddCommand(findingListCmd)
	findingCmd.AddCommand(findingShowCmd)
	findingCmd.AddCommand(findingExportCmd)
}

// runFindingList executes the finding list command
func runFindingList(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Load configuration to get Redis settings
	cfg, err := loadGlobalConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Create StateClient for Redis state stores
	stateCfg := &state.Config{
		URL:         cfg.Redis.URL,
		Database:    cfg.Redis.Database,
		Password:    cfg.Redis.Password,
		PoolSize:    cfg.Redis.PoolSize,
		DialTimeout: cfg.Redis.ConnectTimeout,
		ReadTimeout: cfg.Redis.ReadTimeout,
	}
	stateCfg.ApplyDefaults()

	stateClient, err := state.NewStateClient(stateCfg)
	if err != nil {
		return fmt.Errorf("failed to create state client: %w", err)
	}
	defer stateClient.Close()

	// Create finding store with Redis backend
	store := finding.NewRedisFindingStore(stateClient)

	// Build filter
	filter := finding.NewFindingFilter()

	if listSeverity != "" {
		severity := agent.FindingSeverity(listSeverity)
		filter.WithSeverity(severity)
	}

	if listCategory != "" {
		category := finding.FindingCategory(listCategory)
		filter.WithCategory(category)
	}

	if listStatus != "" {
		status := finding.FindingStatus(listStatus)
		filter.WithStatus(status)
	}

	// Validate scope flag
	var scope string
	switch listScope {
	case "current_run", "same_mission", "all", "":
		scope = listScope
		if scope == "" {
			scope = "all"
		}
	default:
		return fmt.Errorf("invalid scope: %s (must be current_run, same_mission, or all)", listScope)
	}

	// Get mission IDs based on scope
	var missionIDs []types.ID
	if listMission != "" {
		// If mission flag is provided, use it directly (ignoring scope)
		missionID, err := types.ParseID(listMission)
		if err != nil {
			return fmt.Errorf("invalid mission ID: %w", err)
		}
		missionIDs = []types.ID{missionID}
	} else if scope != "all" {
		// Determine mission IDs based on scope
		missionIDs, err = resolveMissionIDsForScope(ctx, stateClient, scope)
		if err != nil {
			return fmt.Errorf("failed to resolve mission IDs for scope %s: %w", scope, err)
		}
		if len(missionIDs) == 0 {
			cmd.Println("No findings found.")
			return nil
		}
	}

	// Query findings
	var findings []finding.EnhancedFinding
	if len(missionIDs) > 0 {
		// Collect findings from all mission IDs
		for _, missionID := range missionIDs {
			missionFindings, err := store.List(ctx, missionID, filter)
			if err != nil {
				return fmt.Errorf("failed to list findings for mission %s: %w", missionID, err)
			}
			findings = append(findings, missionFindings...)
		}
	} else {
		// List all findings across all missions (scope == "all" and no mission flag)
		findings, err = listAllFindings(ctx, store, filter)
		if err != nil {
			return fmt.Errorf("failed to list findings: %w", err)
		}
	}

	if len(findings) == 0 {
		cmd.Println("No findings found.")
		return nil
	}

	// Display results in table format
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tTITLE\tSEVERITY\tCATEGORY\tSTATUS\tMISSION")
	fmt.Fprintln(w, "--\t-----\t--------\t--------\t------\t-------")

	for _, f := range findings {
		severity := formatSeverity(f.Severity)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			f.ID.String()[:8],
			truncate(f.Title, 50),
			severity,
			f.Category,
			f.Status,
			f.MissionID.String()[:8],
		)
	}

	w.Flush()
	return nil
}

// runFindingShow executes the finding show command
func runFindingShow(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	findingIDStr := args[0]

	// Parse finding ID
	findingID, err := types.ParseID(findingIDStr)
	if err != nil {
		return fmt.Errorf("invalid finding ID: %w", err)
	}

	// Load configuration to get Redis settings
	cfg, err := loadGlobalConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Create StateClient for Redis state stores
	stateCfg := &state.Config{
		URL:         cfg.Redis.URL,
		Database:    cfg.Redis.Database,
		Password:    cfg.Redis.Password,
		PoolSize:    cfg.Redis.PoolSize,
		DialTimeout: cfg.Redis.ConnectTimeout,
		ReadTimeout: cfg.Redis.ReadTimeout,
	}
	stateCfg.ApplyDefaults()

	stateClient, err := state.NewStateClient(stateCfg)
	if err != nil {
		return fmt.Errorf("failed to create state client: %w", err)
	}
	defer stateClient.Close()

	// Create finding store with Redis backend
	store := finding.NewRedisFindingStore(stateClient)

	// Get finding
	f, err := store.Get(ctx, findingID)
	if err != nil {
		return fmt.Errorf("failed to get finding: %w", err)
	}

	// Display finding details
	displayFindingDetails(cmd, f)

	return nil
}

// runFindingExport executes the finding export command
func runFindingExport(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Load configuration to get Redis settings
	cfg, err := loadGlobalConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Create StateClient for Redis state stores
	stateCfg := &state.Config{
		URL:         cfg.Redis.URL,
		Database:    cfg.Redis.Database,
		Password:    cfg.Redis.Password,
		PoolSize:    cfg.Redis.PoolSize,
		DialTimeout: cfg.Redis.ConnectTimeout,
		ReadTimeout: cfg.Redis.ReadTimeout,
	}
	stateCfg.ApplyDefaults()

	stateClient, err := state.NewStateClient(stateCfg)
	if err != nil {
		return fmt.Errorf("failed to create state client: %w", err)
	}
	defer stateClient.Close()

	// Create finding store with Redis backend
	store := finding.NewRedisFindingStore(stateClient)

	// Build filter
	filter := finding.NewFindingFilter()

	if exportSeverity != "" {
		severity := agent.FindingSeverity(exportSeverity)
		filter.WithSeverity(severity)
	}

	if exportCategory != "" {
		category := finding.FindingCategory(exportCategory)
		filter.WithCategory(category)
	}

	// Get findings
	var findings []finding.EnhancedFinding
	if exportMission != "" {
		missionID, err := types.ParseID(exportMission)
		if err != nil {
			return fmt.Errorf("invalid mission ID: %w", err)
		}
		findings, err = store.List(ctx, missionID, filter)
		if err != nil {
			return fmt.Errorf("failed to list findings: %w", err)
		}
	} else {
		findings, err = listAllFindings(ctx, store, filter)
		if err != nil {
			return fmt.Errorf("failed to list findings: %w", err)
		}
	}

	if len(findings) == 0 {
		cmd.Println("No findings to export.")
		return nil
	}

	// Convert to pointers for export
	findingPtrs := make([]*finding.EnhancedFinding, len(findings))
	for i := range findings {
		findingPtrs[i] = &findings[i]
	}

	// Create exporter based on format
	var exporter export.Exporter
	switch strings.ToLower(exportFormat) {
	case "json":
		exporter = export.NewJSONExporter(true)
	case "sarif":
		exporter = export.NewSARIFExporter()
	case "csv":
		exporter = export.NewCSVExporter()
	case "html":
		exporter = export.NewHTMLExporter()
	case "markdown", "md":
		exporter = export.NewMarkdownExporter()
	default:
		return fmt.Errorf("unsupported export format: %s (supported: json, sarif, csv, html, markdown)", exportFormat)
	}

	// Build export options
	opts := export.DefaultExportOptions()
	opts.IncludeEvidence = exportEvidence
	opts.IncludeResolved = exportResolved

	if exportSeverity != "" {
		severity := agent.FindingSeverity(exportSeverity)
		opts.MinSeverity = &severity
	}

	if exportMinConfidence > 0 {
		opts.MinConfidence = &exportMinConfidence
	}

	if exportCategory != "" {
		opts.Categories = []string{exportCategory}
	}

	// Export findings
	data, err := exporter.Export(ctx, findingPtrs, opts)
	if err != nil {
		return fmt.Errorf("failed to export findings: %w", err)
	}

	// Write output
	if exportOutput != "" {
		if err := os.WriteFile(exportOutput, data, 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		cmd.Printf("Exported %d findings to %s (%s format)\n", len(findings), exportOutput, exportFormat)
	} else {
		cmd.Print(string(data))
	}

	return nil
}

// displayFindingDetails displays comprehensive finding information
func displayFindingDetails(cmd *cobra.Command, f *finding.EnhancedFinding) {
	// Header
	cmd.Println()
	cmd.Println(strings.Repeat("=", 80))
	cmd.Printf("Finding: %s\n", f.Title)
	cmd.Println(strings.Repeat("=", 80))
	cmd.Println()

	// Basic information
	cmd.Printf("ID:          %s\n", f.ID)
	cmd.Printf("Mission ID:  %s\n", f.MissionID)
	cmd.Printf("Agent:       %s\n", f.AgentName)
	if f.DelegatedFrom != nil {
		cmd.Printf("Delegated:   From %s\n", *f.DelegatedFrom)
	}
	cmd.Println()

	// Severity and status with color coding
	severityColor := getSeverityColor(f.Severity)
	cmd.Printf("Severity:    %s\n", severityColor.Sprint(f.Severity))
	cmd.Printf("Status:      %s\n", f.Status)
	cmd.Printf("Category:    %s\n", f.Category)
	if f.Subcategory != "" {
		cmd.Printf("Subcategory: %s\n", f.Subcategory)
	}
	cmd.Printf("Confidence:  %.2f\n", f.Confidence)
	cmd.Printf("Risk Score:  %.1f/10.0\n", f.RiskScore)
	cmd.Println()

	// Description
	cmd.Println("Description:")
	cmd.Println(wrapText(f.Description, 78))
	cmd.Println()

	// Evidence
	if len(f.Evidence) > 0 {
		cmd.Printf("Evidence (%d items):\n", len(f.Evidence))
		for i, e := range f.Evidence {
			cmd.Printf("  %d. [%s] %s\n", i+1, e.Type, e.Description)
			cmd.Printf("     Timestamp: %s\n", e.Timestamp.Format(time.RFC3339))
		}
		cmd.Println()
	}

	// CVSS
	if f.CVSS != nil {
		cmd.Println("CVSS Score:")
		cmd.Printf("  Version: %s\n", f.CVSS.Version)
		cmd.Printf("  Vector:  %s\n", f.CVSS.Vector)
		cmd.Printf("  Score:   %.1f\n", f.CVSS.Score)
		cmd.Println()
	}

	// CWE
	if len(f.CWE) > 0 {
		cmd.Printf("CWE IDs: %s\n", strings.Join(f.CWE, ", "))
		cmd.Println()
	}

	// MITRE ATT&CK
	if mitreAttack := f.GetMitreAttack(); len(mitreAttack) > 0 {
		cmd.Println("MITRE ATT&CK Mappings:")
		for _, m := range mitreAttack {
			cmd.Printf("  - %s: %s", m.TechniqueID, m.TechniqueName)
			if m.Tactic != "" {
				cmd.Printf(" (%s)", m.Tactic)
			}
			cmd.Println()
		}
		cmd.Println()
	}

	// MITRE ATLAS
	if mitreAtlas := f.GetMitreAtlas(); len(mitreAtlas) > 0 {
		cmd.Println("MITRE ATLAS Mappings:")
		for _, m := range mitreAtlas {
			cmd.Printf("  - %s: %s", m.TechniqueID, m.TechniqueName)
			if m.Tactic != "" {
				cmd.Printf(" (%s)", m.Tactic)
			}
			cmd.Println()
		}
		cmd.Println()
	}

	// Remediation
	if f.Remediation != "" {
		cmd.Println("Remediation:")
		cmd.Println(wrapText(f.Remediation, 78))
		cmd.Println()
	}

	// References
	if len(f.References) > 0 {
		cmd.Println("References:")
		for _, ref := range f.References {
			cmd.Printf("  - %s\n", ref)
		}
		cmd.Println()
	}

	// Reproduction steps
	if len(f.ReproSteps) > 0 {
		cmd.Println("Reproduction Steps:")
		for _, step := range f.ReproSteps {
			cmd.Printf("  %d. %s\n", step.StepNumber, step.Description)
			if step.ExpectedResult != "" {
				cmd.Printf("     Expected: %s\n", step.ExpectedResult)
			}
			if step.EvidenceRef != "" {
				cmd.Printf("     Evidence: %s\n", step.EvidenceRef)
			}
		}
		cmd.Println()
	}

	// Related findings
	if len(f.RelatedIDs) > 0 {
		cmd.Printf("Related Findings (%d):\n", len(f.RelatedIDs))
		for _, id := range f.RelatedIDs {
			cmd.Printf("  - %s\n", id)
		}
		cmd.Println()
	}

	// Additional Metadata (domain-specific data not already displayed)
	if len(f.Metadata) > 0 {
		// Define well-known keys that are already displayed above
		wellKnownKeys := map[string]bool{
			"mitre_attack": true,
			"mitre_atlas":  true,
			"cvss":         true,
			"cwe":          true,
			"risk_score":   true,
		}

		// Collect metadata that should be displayed
		otherMetadata := make(map[string]any)
		for key, value := range f.Metadata {
			if !wellKnownKeys[key] {
				otherMetadata[key] = value
			}
		}

		// Display other metadata if present
		if len(otherMetadata) > 0 {
			cmd.Println("Additional Metadata:")
			for key, value := range otherMetadata {
				cmd.Printf("  %s: %v\n", key, formatMetadataValue(value))
			}
			cmd.Println()
		}
	}

	// Metadata
	cmd.Printf("Occurrences: %d\n", f.OccurrenceCount)
	cmd.Printf("Created:     %s\n", f.CreatedAt.Format(time.RFC3339))
	cmd.Printf("Updated:     %s\n", f.UpdatedAt.Format(time.RFC3339))
	cmd.Println()
}

// formatSeverity returns a color-coded severity string for terminal output
func formatSeverity(severity agent.FindingSeverity) string {
	c := getSeverityColor(severity)
	return c.Sprint(severity)
}

// getSeverityColor returns the appropriate color for a severity level
func getSeverityColor(severity agent.FindingSeverity) *color.Color {
	switch severity {
	case agent.SeverityCritical:
		return color.New(color.FgRed, color.Bold)
	case agent.SeverityHigh:
		return color.New(color.FgRed)
	case agent.SeverityMedium:
		return color.New(color.FgYellow)
	case agent.SeverityLow:
		return color.New(color.FgCyan)
	case agent.SeverityInfo:
		return color.New(color.FgWhite)
	default:
		return color.New(color.Reset)
	}
}

// truncate truncates a string to a maximum length with ellipsis
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// wrapText wraps text to a specified width
func wrapText(text string, width int) string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return text
	}

	var result strings.Builder
	lineLen := 0

	for i, word := range words {
		wordLen := len(word)

		if lineLen+wordLen+1 > width && lineLen > 0 {
			result.WriteString("\n")
			lineLen = 0
		}

		if lineLen > 0 {
			result.WriteString(" ")
			lineLen++
		}

		result.WriteString(word)
		lineLen += wordLen

		if i < len(words)-1 {
			// Check if next word would overflow
			nextWordLen := len(words[i+1])
			if lineLen+nextWordLen+1 > width {
				// Don't add space, will wrap on next iteration
				continue
			}
		}
	}

	return result.String()
}

// formatMetadataValue formats a metadata value for display
func formatMetadataValue(value any) string {
	if value == nil {
		return "<nil>"
	}

	switch v := value.(type) {
	case string:
		return v
	case int, int8, int16, int32, int64:
		return fmt.Sprintf("%d", v)
	case uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", v)
	case float32, float64:
		return fmt.Sprintf("%v", v)
	case bool:
		return fmt.Sprintf("%t", v)
	case []string:
		return strings.Join(v, ", ")
	case []any:
		// Format slice elements
		parts := make([]string, len(v))
		for i, elem := range v {
			parts[i] = formatMetadataValue(elem)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]any:
		// Format as JSON-like string for complex objects
		return fmt.Sprintf("%v", v)
	default:
		// Fallback to default string representation
		return fmt.Sprintf("%v", v)
	}
}

// listAllFindings lists findings across all missions with filtering
func listAllFindings(ctx context.Context, store *finding.RedisFindingStore, filter *finding.FindingFilter) ([]finding.EnhancedFinding, error) {
	// This is a placeholder - in a real implementation, we'd need to either:
	// 1. Add a ListAll method to the store that doesn't require a mission ID
	// 2. Query all missions and aggregate their findings
	// For now, we'll use an empty mission ID which should be handled by the store
	return store.List(ctx, types.ID(""), filter)
}

// resolveMissionIDsForScope resolves mission IDs based on the scope parameter.
// - "current_run": returns the current running mission ID (or most recent if none running)
// - "same_mission": returns all mission IDs with the same name as the current/most recent mission
// - "all": returns empty slice (caller should handle all missions)
func resolveMissionIDsForScope(ctx context.Context, stateClient *state.StateClient, scope string) ([]types.ID, error) {
	missionStore := mission.NewRedisMissionStore(stateClient)

	switch scope {
	case "current_run":
		// Get the most recent running mission, or the most recent mission overall
		activeMissions, err := missionStore.GetActive(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get active missions: %w", err)
		}

		if len(activeMissions) > 0 {
			// Return the first active mission (most recent)
			return []types.ID{activeMissions[0].ID}, nil
		}

		// No active missions, get the most recent completed mission
		filter := mission.NewMissionFilter().WithPagination(1, 0)
		missions, err := missionStore.List(ctx, filter)
		if err != nil {
			return nil, fmt.Errorf("failed to get recent missions: %w", err)
		}

		if len(missions) == 0 {
			return nil, fmt.Errorf("no missions found")
		}

		return []types.ID{missions[0].ID}, nil

	case "same_mission":
		// First, get the current or most recent mission to determine the mission name
		activeMissions, err := missionStore.GetActive(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get active missions: %w", err)
		}

		var missionName string
		if len(activeMissions) > 0 {
			missionName = activeMissions[0].Name
		} else {
			// No active missions, get the most recent mission
			filter := mission.NewMissionFilter().WithPagination(1, 0)
			missions, err := missionStore.List(ctx, filter)
			if err != nil {
				return nil, fmt.Errorf("failed to get recent missions: %w", err)
			}

			if len(missions) == 0 {
				return nil, fmt.Errorf("no missions found")
			}

			missionName = missions[0].Name
		}

		// Now get all missions with the same name
		missions, err := missionStore.ListByName(ctx, missionName, 0) // 0 = no limit
		if err != nil {
			return nil, fmt.Errorf("failed to list missions by name: %w", err)
		}

		if len(missions) == 0 {
			return nil, fmt.Errorf("no missions found with name: %s", missionName)
		}

		// Extract mission IDs
		missionIDs := make([]types.ID, len(missions))
		for i, m := range missions {
			missionIDs[i] = m.ID
		}

		return missionIDs, nil

	case "all":
		// Return empty slice - caller should handle listing all findings
		return nil, nil

	default:
		return nil, fmt.Errorf("invalid scope: %s", scope)
	}
}
