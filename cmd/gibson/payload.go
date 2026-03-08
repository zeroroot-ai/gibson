package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/zero-day-ai/gibson/cmd/gibson/internal"
	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/payload"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
	"gopkg.in/yaml.v3"
)

var payloadCmd = &cobra.Command{
	Use:   "payload",
	Short: "Manage attack payloads",
	Long:  `Create, list, execute, and manage attack payloads for LLM red-teaming`,
}

var payloadListCmd = &cobra.Command{
	Use:   "list",
	Short: "List attack payloads with optional filtering",
	Long: `List attack payloads with optional filtering by category, severity, target type, or MITRE technique.

Examples:
  # List all payloads
  gibson payload list

  # List only jailbreak payloads
  gibson payload list --category jailbreak

  # List critical severity payloads
  gibson payload list --severity critical

  # List payloads for specific target type
  gibson payload list --target-type openai

  # List payloads mapped to MITRE technique
  gibson payload list --mitre AML.T0051

  # Combine multiple filters
  gibson payload list --category prompt_injection --severity high

  # Output as JSON
  gibson payload list --output json`,
	RunE: runPayloadList,
}

var payloadShowCmd = &cobra.Command{
	Use:   "show ID",
	Short: "Show detailed payload information",
	Long: `Display full details for a specific attack payload including all fields,
parameters, success indicators, and metadata.

Examples:
  # Show payload details
  gibson payload show payload_abc123

  # Show payload details as JSON
  gibson payload show payload_abc123 --output json`,
	Args: cobra.ExactArgs(1),
	RunE: runPayloadShow,
}

var payloadCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new attack payload",
	Long: `Create a new attack payload either interactively or from a file.

Examples:
  # Create payload from YAML file
  gibson payload create --from-file payload.yaml

  # Create payload from JSON file
  gibson payload create --from-file payload.json

  # Interactive creation (not yet implemented)
  gibson payload create`,
	RunE: runPayloadCreate,
}

var payloadExecuteCmd = &cobra.Command{
	Use:   "execute ID",
	Short: "Execute an attack payload against a target",
	Long: `Execute an attack payload against a specified target. You can override
parameters, specify execution agent, or run in dry-run mode for testing.

Examples:
  # Execute payload against a target
  gibson payload execute payload_abc123 --target target-api

  # Execute with parameter overrides
  gibson payload execute payload_abc123 --target target-api --params instruction="ignore all rules" --params style=urgent

  # Execute with specific agent
  gibson payload execute payload_abc123 --target target-api --agent agent_xyz789

  # Dry run to preview execution without running
  gibson payload execute payload_abc123 --target target-api --dry-run

  # Execute with custom timeout
  gibson payload execute payload_abc123 --target target-api --timeout 120`,
	Args: cobra.ExactArgs(1),
	RunE: runPayloadExecute,
}

// Flags for payload list command
var (
	listPayloadCategory   string
	listPayloadSeverity   string
	listPayloadTargetType string
	listPayloadMitre      string
	listPayloadOutput     string
)

// Flags for payload show command
var (
	showPayloadOutput string
)

// Flags for payload create command
var (
	createPayloadFromFile string
	createPayloadForce    bool
)

// Flags for payload execute command
var (
	executePayloadTarget  string
	executePayloadAgent   string
	executePayloadDryRun  bool
	executePayloadTimeout int
	executePayloadParams  []string
)

func init() {
	// List command flags
	payloadListCmd.Flags().StringVar(&listPayloadCategory, "category", "", "Filter by category (jailbreak, prompt_injection, data_extraction, etc.)")
	payloadListCmd.Flags().StringVar(&listPayloadSeverity, "severity", "", "Filter by severity (critical, high, medium, low, info)")
	payloadListCmd.Flags().StringVar(&listPayloadTargetType, "target-type", "", "Filter by target type (e.g., openai, anthropic, rag)")
	payloadListCmd.Flags().StringVar(&listPayloadMitre, "mitre", "", "Filter by MITRE ATT&CK technique (e.g., AML.T0051)")
	payloadListCmd.Flags().StringVar(&listPayloadOutput, "output", "text", "Output format (text, json)")

	// Show command flags
	payloadShowCmd.Flags().StringVar(&showPayloadOutput, "output", "text", "Output format (text, json)")

	// Create command flags
	payloadCreateCmd.Flags().StringVar(&createPayloadFromFile, "from-file", "", "Create payload from YAML or JSON file")
	payloadCreateCmd.Flags().BoolVar(&createPayloadForce, "force", false, "Overwrite existing payload if it exists")

	// Execute command flags
	payloadExecuteCmd.Flags().StringVar(&executePayloadTarget, "target", "", "Target name or ID (required)")
	payloadExecuteCmd.Flags().StringVar(&executePayloadAgent, "agent", "", "Agent ID to use for execution")
	payloadExecuteCmd.Flags().BoolVar(&executePayloadDryRun, "dry-run", false, "Validate and preview without executing")
	payloadExecuteCmd.Flags().IntVar(&executePayloadTimeout, "timeout", 0, "Execution timeout in seconds (0 = use default)")
	payloadExecuteCmd.Flags().StringSliceVar(&executePayloadParams, "params", []string{}, "Parameter overrides in key=value format")
	payloadExecuteCmd.MarkFlagRequired("target")

	// Export command flags
	payloadExportCmd.Flags().StringVar(&exportPayloadOutput, "output", "", "Output file path (required)")
	payloadExportCmd.MarkFlagRequired("output")

	// Search command flags
	payloadSearchCmd.Flags().StringVar(&searchPayloadCategory, "category", "", "Filter by category")
	payloadSearchCmd.Flags().StringVar(&searchPayloadTags, "tags", "", "Filter by tags (comma-separated)")
	payloadSearchCmd.Flags().StringVar(&searchPayloadTargetType, "target-type", "", "Filter by target type")
	payloadSearchCmd.Flags().StringVar(&searchPayloadSeverity, "severity", "", "Filter by severity")
	payloadSearchCmd.Flags().IntVar(&searchPayloadLimit, "limit", 50, "Maximum number of results")
	payloadSearchCmd.Flags().StringVar(&searchPayloadOutput, "output", "text", "Output format (text, json)")

	// Add subcommands
	payloadCmd.AddCommand(payloadListCmd)
	payloadCmd.AddCommand(payloadShowCmd)
	payloadCmd.AddCommand(payloadCreateCmd)
	payloadCmd.AddCommand(payloadExecuteCmd)
	// TODO: Re-add these commands when they're migrated to Redis
	// payloadCmd.AddCommand(payloadChainCmd)
	// payloadCmd.AddCommand(payloadStatsCmd)
	payloadCmd.AddCommand(payloadImportCmd)
	payloadCmd.AddCommand(payloadExportCmd)
	payloadCmd.AddCommand(payloadSearchCmd)
	payloadCmd.AddCommand(payloadSyncCmd)
}

// createPayloadStore creates a Redis-backed payload store using the global configuration
func createPayloadStore() (payload.PayloadStore, func(), error) {
	// Load configuration to get Redis settings
	cfg, err := loadGlobalConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load config: %w", err)
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
		return nil, nil, fmt.Errorf("failed to create state client: %w", err)
	}

	// Create Redis payload store
	store := payload.NewRedisPayloadStore(stateClient)

	// Return store and cleanup function
	cleanup := func() {
		if err := stateClient.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close state client: %v\n", err)
		}
	}

	return store, cleanup, nil
}

// runPayloadList executes the payload list command
func runPayloadList(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Create payload store using Redis
	store, cleanup, err := createPayloadStore()
	if err != nil {
		return fmt.Errorf("failed to create payload store: %w", err)
	}
	defer cleanup()

	// Build filter
	filter := &payload.PayloadFilter{}

	if listPayloadCategory != "" {
		category := payload.PayloadCategory(listPayloadCategory)
		if !category.IsValid() {
			return fmt.Errorf("invalid category: %s (valid: %s)", listPayloadCategory, getValidCategories())
		}
		filter.Categories = []payload.PayloadCategory{category}
	}

	if listPayloadSeverity != "" {
		severity := agent.FindingSeverity(listPayloadSeverity)
		if !isValidSeverity(severity) {
			return fmt.Errorf("invalid severity: %s (valid: critical, high, medium, low, info)", listPayloadSeverity)
		}
		filter.Severities = []agent.FindingSeverity{severity}
	}

	if listPayloadTargetType != "" {
		filter.TargetTypes = []string{listPayloadTargetType}
	}

	if listPayloadMitre != "" {
		filter.MitreTechniques = []string{listPayloadMitre}
	}

	// Query payloads
	payloads, err := store.List(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to list payloads: %w", err)
	}

	// Determine output format
	outputFormat := internal.FormatText
	if listPayloadOutput == "json" {
		outputFormat = internal.FormatJSON
	}

	formatter := internal.NewFormatter(outputFormat, cmd.OutOrStdout())

	// Handle JSON output
	if outputFormat == internal.FormatJSON {
		output := map[string]interface{}{
			"count":    len(payloads),
			"payloads": payloads,
		}
		return formatter.PrintJSON(output)
	}

	// Text output
	if len(payloads) == 0 {
		return formatter.PrintError("No payloads found matching the specified filters")
	}

	// Print summary
	fmt.Fprintf(cmd.OutOrStdout(), "Found %d payload(s)\n\n", len(payloads))

	// Build table
	headers := []string{"ID", "Name", "Categories", "Severity", "Version", "Built-In"}
	rows := make([][]string, 0, len(payloads))

	for _, p := range payloads {
		// Format categories
		categories := make([]string, len(p.Categories))
		for i, cat := range p.Categories {
			categories[i] = string(cat)
		}
		categoryStr := strings.Join(categories, ", ")
		if len(categoryStr) > 30 {
			categoryStr = categoryStr[:27] + "..."
		}

		// Format built-in status
		builtInStr := ""
		if p.BuiltIn {
			builtInStr = "yes"
		}

		rows = append(rows, []string{
			p.ID.String(),
			truncateString(p.Name, 30),
			categoryStr,
			string(p.Severity),
			p.Version,
			builtInStr,
		})
	}

	// Print table
	if err := formatter.PrintTable(headers, rows); err != nil {
		return fmt.Errorf("failed to print table: %w", err)
	}

	// Print filter summary
	if hasFilters() {
		fmt.Fprintf(cmd.OutOrStdout(), "\nFilters applied:")
		if listPayloadCategory != "" {
			fmt.Fprintf(cmd.OutOrStdout(), " category=%s", listPayloadCategory)
		}
		if listPayloadSeverity != "" {
			fmt.Fprintf(cmd.OutOrStdout(), " severity=%s", listPayloadSeverity)
		}
		if listPayloadTargetType != "" {
			fmt.Fprintf(cmd.OutOrStdout(), " target-type=%s", listPayloadTargetType)
		}
		if listPayloadMitre != "" {
			fmt.Fprintf(cmd.OutOrStdout(), " mitre=%s", listPayloadMitre)
		}
		fmt.Fprintln(cmd.OutOrStdout())
	}

	return nil
}

// hasFilters checks if any filters are applied
func hasFilters() bool {
	return listPayloadCategory != "" ||
		listPayloadSeverity != "" ||
		listPayloadTargetType != "" ||
		listPayloadMitre != ""
}

// getValidCategories returns a comma-separated list of valid categories
func getValidCategories() string {
	categories := payload.AllCategories()
	strs := make([]string, len(categories))
	for i, cat := range categories {
		strs[i] = string(cat)
	}
	return strings.Join(strs, ", ")
}

// isValidSeverity checks if the severity is valid
func isValidSeverity(severity agent.FindingSeverity) bool {
	switch severity {
	case agent.SeverityCritical, agent.SeverityHigh, agent.SeverityMedium,
		agent.SeverityLow, agent.SeverityInfo:
		return true
	default:
		return false
	}
}

// truncateString truncates a string to the specified length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// runPayloadShow executes the payload show command
func runPayloadShow(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	payloadID := args[0]

	// Create payload store using Redis
	store, cleanup, err := createPayloadStore()
	if err != nil {
		return fmt.Errorf("failed to create payload store: %w", err)
	}
	defer cleanup()

	// Parse payload ID
	id, err := types.ParseID(payloadID)
	if err != nil {
		return fmt.Errorf("invalid payload ID: %w", err)
	}

	// Get payload by ID
	p, err := store.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get payload: %w", err)
	}

	if p == nil {
		return fmt.Errorf("payload not found: %s", payloadID)
	}

	// Determine output format
	outputFormat := internal.FormatText
	if showPayloadOutput == "json" {
		outputFormat = internal.FormatJSON
	}

	formatter := internal.NewFormatter(outputFormat, cmd.OutOrStdout())

	// Handle JSON output
	if outputFormat == internal.FormatJSON {
		return formatter.PrintJSON(p)
	}

	// Text output - display all payload fields
	out := cmd.OutOrStdout()

	// Header
	fmt.Fprintf(out, "Payload: %s\n", p.Name)
	fmt.Fprintf(out, "ID: %s\n", p.ID.String())
	fmt.Fprintf(out, "Version: %s\n", p.Version)
	fmt.Fprintf(out, "\n")

	// Description
	if p.Description != "" {
		fmt.Fprintf(out, "Description:\n  %s\n\n", p.Description)
	}

	// Categorization
	fmt.Fprintf(out, "Categories:\n")
	if len(p.Categories) > 0 {
		for _, cat := range p.Categories {
			fmt.Fprintf(out, "  - %s\n", cat)
		}
	} else {
		fmt.Fprintf(out, "  (none)\n")
	}
	fmt.Fprintf(out, "\n")

	if len(p.Tags) > 0 {
		fmt.Fprintf(out, "Tags:\n")
		fmt.Fprintf(out, "  %s\n\n", strings.Join(p.Tags, ", "))
	}

	// Severity
	fmt.Fprintf(out, "Severity: %s\n\n", p.Severity)

	// Template
	fmt.Fprintf(out, "Template:\n")
	fmt.Fprintf(out, "  %s\n\n", formatMultilineField(p.Template, 2))

	// Parameters
	if len(p.Parameters) > 0 {
		fmt.Fprintf(out, "Parameters:\n")
		for _, param := range p.Parameters {
			fmt.Fprintf(out, "  - %s (%s)", param.Name, param.Type)
			if param.Required {
				fmt.Fprintf(out, " [required]")
			}
			fmt.Fprintf(out, "\n")
			if param.Description != "" {
				fmt.Fprintf(out, "    Description: %s\n", param.Description)
			}
			if param.Default != nil {
				fmt.Fprintf(out, "    Default: %v\n", param.Default)
			}
			if param.Generator != nil {
				fmt.Fprintf(out, "    Generator: %s\n", param.Generator.Type)
			}
		}
		fmt.Fprintf(out, "\n")
	}

	// Success Indicators
	if len(p.SuccessIndicators) > 0 {
		fmt.Fprintf(out, "Success Indicators:\n")
		for i, indicator := range p.SuccessIndicators {
			fmt.Fprintf(out, "  %d. Type: %s\n", i+1, indicator.Type)
			fmt.Fprintf(out, "     Value: %s\n", indicator.Value)
			if indicator.Description != "" {
				fmt.Fprintf(out, "     Description: %s\n", indicator.Description)
			}
			if indicator.Weight > 0 {
				fmt.Fprintf(out, "     Weight: %.2f\n", indicator.Weight)
			}
			if indicator.Negate {
				fmt.Fprintf(out, "     Negate: true\n")
			}
		}
		fmt.Fprintf(out, "\n")
	}

	// Target Types
	if len(p.TargetTypes) > 0 {
		fmt.Fprintf(out, "Target Types:\n")
		for _, targetType := range p.TargetTypes {
			fmt.Fprintf(out, "  - %s\n", targetType)
		}
		fmt.Fprintf(out, "\n")
	}

	// MITRE Techniques
	if len(p.MitreTechniques) > 0 {
		fmt.Fprintf(out, "MITRE ATT&CK Techniques:\n")
		for _, technique := range p.MitreTechniques {
			fmt.Fprintf(out, "  - %s\n", technique)
		}
		fmt.Fprintf(out, "\n")
	}

	// Metadata
	if p.Metadata.Author != "" || p.Metadata.Source != "" || len(p.Metadata.References) > 0 ||
		p.Metadata.Notes != "" || p.Metadata.Difficulty != "" || p.Metadata.Reliability > 0 {
		fmt.Fprintf(out, "Metadata:\n")
		if p.Metadata.Author != "" {
			fmt.Fprintf(out, "  Author: %s\n", p.Metadata.Author)
		}
		if p.Metadata.Source != "" {
			fmt.Fprintf(out, "  Source: %s\n", p.Metadata.Source)
		}
		if p.Metadata.Difficulty != "" {
			fmt.Fprintf(out, "  Difficulty: %s\n", p.Metadata.Difficulty)
		}
		if p.Metadata.Reliability > 0 {
			fmt.Fprintf(out, "  Reliability: %.2f\n", p.Metadata.Reliability)
		}
		if len(p.Metadata.References) > 0 {
			fmt.Fprintf(out, "  References:\n")
			for _, ref := range p.Metadata.References {
				fmt.Fprintf(out, "    - %s\n", ref)
			}
		}
		if p.Metadata.Notes != "" {
			fmt.Fprintf(out, "  Notes:\n    %s\n", formatMultilineField(p.Metadata.Notes, 4))
		}
		if len(p.Metadata.Examples) > 0 {
			fmt.Fprintf(out, "  Examples:\n")
			for i, example := range p.Metadata.Examples {
				fmt.Fprintf(out, "    %d. %s\n", i+1, formatMultilineField(example, 7))
			}
		}
		fmt.Fprintf(out, "\n")
	}

	// Status
	fmt.Fprintf(out, "Status:\n")
	fmt.Fprintf(out, "  Built-in: %v\n", p.BuiltIn)
	fmt.Fprintf(out, "  Enabled: %v\n", p.Enabled)
	fmt.Fprintf(out, "  Created: %s\n", p.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(out, "  Updated: %s\n", p.UpdatedAt.Format("2006-01-02 15:04:05"))

	return nil
}

// formatMultilineField formats a multiline field with proper indentation
func formatMultilineField(text string, indent int) string {
	lines := strings.Split(text, "\n")
	if len(lines) <= 1 {
		return text
	}

	indentStr := strings.Repeat(" ", indent)
	result := lines[0]
	for i := 1; i < len(lines); i++ {
		result += "\n" + indentStr + lines[i]
	}
	return result
}

// runPayloadCreate executes the payload create command
func runPayloadCreate(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Check if file-based creation
	if createPayloadFromFile == "" {
		// Interactive payload creation wizard
		return runInteractivePayloadCreation(ctx, cmd)
	}

	// Read payload from file
	p, err := loadPayloadFromFile(createPayloadFromFile)
	if err != nil {
		return fmt.Errorf("failed to load payload from file: %w", err)
	}

	// Validate payload
	if err := validatePayload(p); err != nil {
		return fmt.Errorf("payload validation failed: %w", err)
	}

	// Create payload store using Redis
	store, cleanup, err := createPayloadStore()
	if err != nil {
		return fmt.Errorf("failed to create payload store: %w", err)
	}
	defer cleanup()

	// Check if payload already exists by name
	existsByName, err := store.ExistsByName(ctx, p.Name)
	if err != nil {
		return fmt.Errorf("failed to check payload existence: %w", err)
	}

	if existsByName && !createPayloadForce {
		return fmt.Errorf("payload with name '%s' already exists. Use --force to overwrite", p.Name)
	}

	// Generate ID if not provided
	if p.ID.IsZero() {
		p.ID = types.NewID()
	}

	// Set timestamps
	now := time.Now()

	// Default values
	if p.Version == "" {
		p.Version = "1.0.0"
	}
	p.BuiltIn = false
	p.Enabled = true // Enable by default

	if existsByName && createPayloadForce {
		// Get existing payload and update it
		payloads, err := store.List(ctx, &payload.PayloadFilter{})
		if err != nil {
			return fmt.Errorf("failed to list payloads: %w", err)
		}

		var existingPayload *payload.Payload
		for _, existing := range payloads {
			if existing.Name == p.Name {
				existingPayload = existing
				break
			}
		}

		if existingPayload != nil {
			p.ID = existingPayload.ID
			p.CreatedAt = existingPayload.CreatedAt
		} else {
			p.CreatedAt = now
		}
		p.UpdatedAt = now

		if err := store.Update(ctx, p); err != nil {
			return fmt.Errorf("failed to update payload: %w", err)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Successfully updated payload: %s (ID: %s)\n", p.Name, p.ID.String())
	} else {
		// Create new payload
		p.CreatedAt = now
		p.UpdatedAt = now

		if err := store.Save(ctx, p); err != nil {
			return fmt.Errorf("failed to save payload: %w", err)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Successfully created payload: %s (ID: %s)\n", p.Name, p.ID.String())
	}

	return nil
}

// runInteractivePayloadCreation creates a payload interactively via prompts
func runInteractivePayloadCreation(ctx context.Context, cmd *cobra.Command) error {
	var p payload.Payload
	var err error

	fmt.Fprintf(cmd.OutOrStdout(), "=== Interactive Payload Creation ===\n\n")

	// Prompt for name
	fmt.Fprintf(cmd.OutOrStdout(), "Payload Name: ")
	p.Name, err = readLine()
	if err != nil {
		return fmt.Errorf("failed to read name: %w", err)
	}
	if p.Name == "" {
		return fmt.Errorf("name cannot be empty")
	}

	// Prompt for description
	fmt.Fprintf(cmd.OutOrStdout(), "Description: ")
	p.Description, err = readLine()
	if err != nil {
		return fmt.Errorf("failed to read description: %w", err)
	}

	// Prompt for category
	fmt.Fprintf(cmd.OutOrStdout(), "\nAvailable categories:\n")
	categories := payload.AllCategories()
	for i, cat := range categories {
		fmt.Fprintf(cmd.OutOrStdout(), "  %d. %s\n", i+1, cat)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Select category (1-%d): ", len(categories))
	categoryIdx, err := readInt()
	if err != nil || categoryIdx < 1 || categoryIdx > len(categories) {
		return fmt.Errorf("invalid category selection")
	}
	p.Categories = []payload.PayloadCategory{categories[categoryIdx-1]}

	// Prompt for severity
	fmt.Fprintf(cmd.OutOrStdout(), "\nSeverity levels: critical, high, medium, low, info\n")
	fmt.Fprintf(cmd.OutOrStdout(), "Severity: ")
	severityStr, err := readLine()
	if err != nil {
		return fmt.Errorf("failed to read severity: %w", err)
	}
	p.Severity = agent.FindingSeverity(severityStr)
	if !isValidSeverity(p.Severity) {
		p.Severity = agent.SeverityMedium // Default
		fmt.Fprintf(cmd.OutOrStdout(), "Invalid severity, using default: medium\n")
	}

	// Prompt for template
	fmt.Fprintf(cmd.OutOrStdout(), "\nPayload Template (press Enter then Ctrl+D when done):\n")
	p.Template, err = readMultiLine()
	if err != nil {
		return fmt.Errorf("failed to read template: %w", err)
	}
	if p.Template == "" {
		return fmt.Errorf("template cannot be empty")
	}

	// Add a basic success indicator
	p.SuccessIndicators = []payload.SuccessIndicator{
		{
			Type:        payload.IndicatorContains,
			Value:       "success",
			Description: "Response contains success indicator",
			Weight:      1.0,
		},
	}

	// Save the payload using Redis
	store, cleanup, err := createPayloadStore()
	if err != nil {
		return fmt.Errorf("failed to create payload store: %w", err)
	}
	defer cleanup()

	// Generate ID and timestamps
	p.ID = types.NewID()
	now := time.Now()
	p.CreatedAt = now
	p.UpdatedAt = now
	p.Version = "1.0.0"
	p.BuiltIn = false
	p.Enabled = true

	// Validate and save
	if err := validatePayload(&p); err != nil {
		return fmt.Errorf("payload validation failed: %w", err)
	}

	if err := store.Save(ctx, &p); err != nil {
		return fmt.Errorf("failed to save payload: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "\nSuccessfully created payload: %s (ID: %s)\n", p.Name, p.ID.String())

	return nil
}

// readLine reads a single line from stdin
func readLine() (string, error) {
	var line string
	_, err := fmt.Scanln(&line)
	if err != nil && err.Error() != "unexpected newline" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// readInt reads an integer from stdin
func readInt() (int, error) {
	var num int
	_, err := fmt.Scanf("%d\n", &num)
	return num, err
}

// readMultiLine reads multiple lines from stdin until EOF
func readMultiLine() (string, error) {
	var lines []string
	var line string
	for {
		n, err := fmt.Scanln(&line)
		if err != nil || n == 0 {
			break
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n"), nil
}

// loadPayloadFromFile loads a payload from a YAML or JSON file
func loadPayloadFromFile(filePath string) (*payload.Payload, error) {
	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	p := &payload.Payload{}

	// Try YAML first, then JSON
	if strings.HasSuffix(filePath, ".yaml") || strings.HasSuffix(filePath, ".yml") {
		if err := yaml.Unmarshal(data, p); err != nil {
			return nil, fmt.Errorf("failed to parse YAML: %w", err)
		}
	} else if strings.HasSuffix(filePath, ".json") {
		if err := json.Unmarshal(data, p); err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}
	} else {
		// Try JSON first, then JSON
		if err := json.Unmarshal(data, p); err != nil {
			if err := yaml.Unmarshal(data, p); err != nil {
				return nil, fmt.Errorf("failed to parse file as JSON or YAML")
			}
		}
	}

	return p, nil
}

// validatePayload validates a payload before saving
func validatePayload(p *payload.Payload) error {
	if p == nil {
		return fmt.Errorf("payload is nil")
	}

	if p.Name == "" {
		return fmt.Errorf("payload name is required")
	}

	if p.Template == "" {
		return fmt.Errorf("payload template is required")
	}

	if len(p.Categories) == 0 {
		return fmt.Errorf("at least one category is required")
	}

	// Validate categories
	for _, cat := range p.Categories {
		if !cat.IsValid() {
			return fmt.Errorf("invalid category: %s", cat)
		}
	}

	// Validate severity
	if p.Severity != "" && !isValidSeverity(p.Severity) {
		return fmt.Errorf("invalid severity: %s", p.Severity)
	}

	// Validate parameters
	for i, param := range p.Parameters {
		if param.Name == "" {
			return fmt.Errorf("parameter %d: name is required", i)
		}
		if param.Type == "" {
			return fmt.Errorf("parameter %d (%s): type is required", i, param.Name)
		}
		if !param.Type.IsValid() {
			return fmt.Errorf("parameter %d (%s): invalid type %s", i, param.Name, param.Type)
		}
	}

	// Validate success indicators
	if len(p.SuccessIndicators) == 0 {
		return fmt.Errorf("at least one success indicator is required")
	}

	for i, indicator := range p.SuccessIndicators {
		if !indicator.Type.IsValid() {
			return fmt.Errorf("success indicator %d: invalid type %s", i, indicator.Type)
		}
		if indicator.Value == "" {
			return fmt.Errorf("success indicator %d: value is required", i)
		}
	}

	return nil
}

// runPayloadExecute executes the payload execute command
func runPayloadExecute(cmd *cobra.Command, args []string) error {
	_ = cmd.Context()
	_ = args[0]

	// TODO: Implement payload execution logic with Redis backend
	// This requires:
	// 1. Loading the payload from Redis store
	// 2. Creating an execution context
	// 3. Running the payload against the specified target
	// 4. Recording execution results
	return fmt.Errorf("payload execution not yet implemented with Redis backend")
}

// runSinglePayloadStats shows statistics for a single payload
func runSinglePayloadStats(
	cmd *cobra.Command,
	ctx context.Context,
	tracker payload.EffectivenessTracker,
	formatter internal.Formatter,
	outputFormat internal.OutputFormat,
	payloadID string,
) error {
	// Parse payload ID
	id, err := types.ParseID(payloadID)
	if err != nil {
		return fmt.Errorf("invalid payload ID: %w", err)
	}

	// Get stats
	stats, err := tracker.GetPayloadStats(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get payload stats: %w", err)
	}

	// Handle JSON output
	if outputFormat == internal.FormatJSON {
		return formatter.PrintJSON(stats)
	}

	// Text output
	out := cmd.OutOrStdout()

	fmt.Fprintf(out, "Payload Statistics: %s\n", stats.PayloadName)
	fmt.Fprintf(out, "ID: %s\n", stats.PayloadID.String())
	fmt.Fprintf(out, "\n")

	// Execution counts
	fmt.Fprintf(out, "EXECUTION SUMMARY\n")
	fmt.Fprintf(out, "-------------------------------------\n")
	fmt.Fprintf(out, "Total Executions:     %d\n", stats.TotalExecutions)
	fmt.Fprintf(out, "Successful Attacks:   %d\n", stats.SuccessfulAttacks)
	fmt.Fprintf(out, "Failed Executions:    %d\n", stats.FailedExecutions)
	fmt.Fprintf(out, "Timeouts:             %d\n", stats.TimeoutCount)
	fmt.Fprintf(out, "\n")

	// Success metrics
	if stats.TotalExecutions > 0 {
		fmt.Fprintf(out, "SUCCESS METRICS\n")
		fmt.Fprintf(out, "-------------------------------------\n")
		fmt.Fprintf(out, "Success Rate:         %.2f%%\n", stats.SuccessRate*100)
		fmt.Fprintf(out, "Confidence Level:     %.2f%% (%d executions)\n", stats.ConfidenceLevel*100, stats.TotalExecutions)
		if stats.SuccessfulAttacks > 0 {
			fmt.Fprintf(out, "Average Confidence:   %.2f%%\n", stats.AverageConfidence*100)
		}
		fmt.Fprintf(out, "\n")
	}

	// Performance metrics
	if stats.TotalExecutions > 0 {
		fmt.Fprintf(out, "PERFORMANCE METRICS\n")
		fmt.Fprintf(out, "-------------------------------------\n")
		fmt.Fprintf(out, "Average Duration:     %s\n", stats.AverageDuration)
		fmt.Fprintf(out, "Median Duration:      %s\n", stats.MedianDuration)
		if stats.AverageTokensUsed > 0 {
			fmt.Fprintf(out, "Average Tokens Used:  %.0f\n", stats.AverageTokensUsed)
		}
		if stats.TotalCost > 0 {
			fmt.Fprintf(out, "Average Cost:         $%.4f\n", stats.AverageCost)
			fmt.Fprintf(out, "Total Cost:           $%.4f\n", stats.TotalCost)
		}
		fmt.Fprintf(out, "\n")
	}

	// Finding metrics
	if stats.FindingsCreated > 0 {
		fmt.Fprintf(out, "FINDING METRICS\n")
		fmt.Fprintf(out, "-------------------------------------\n")
		fmt.Fprintf(out, "Findings Created:     %d\n", stats.FindingsCreated)
		fmt.Fprintf(out, "Finding Rate:         %.2f%%\n", stats.FindingCreationRate*100)
		fmt.Fprintf(out, "\n")
	}

	// Temporal data
	if !stats.FirstExecution.IsZero() {
		fmt.Fprintf(out, "TEMPORAL DATA\n")
		fmt.Fprintf(out, "-------------------------------------\n")
		fmt.Fprintf(out, "First Execution:      %s\n", stats.FirstExecution.Format("2006-01-02 15:04:05"))
		fmt.Fprintf(out, "Last Execution:       %s\n", stats.LastExecution.Format("2006-01-02 15:04:05"))
		if stats.LastSuccess != nil {
			fmt.Fprintf(out, "Last Success:         %s\n", stats.LastSuccess.Format("2006-01-02 15:04:05"))
		}
		fmt.Fprintf(out, "\n")
	}

	// Trend data
	if stats.TotalExecutions > 0 {
		fmt.Fprintf(out, "TREND ANALYSIS\n")
		fmt.Fprintf(out, "-------------------------------------\n")
		fmt.Fprintf(out, "Recent Success Rate:  %.2f%% (last 30 days)\n", stats.RecentSuccessRate*100)
		fmt.Fprintf(out, "Trending:             %s\n", stats.Trending)
		fmt.Fprintf(out, "\n")
	}

	// Target type breakdown
	if len(stats.TargetTypeBreakdown) > 0 {
		fmt.Fprintf(out, "TARGET TYPE BREAKDOWN\n")
		fmt.Fprintf(out, "-------------------------------------\n")
		for targetType, breakdown := range stats.TargetTypeBreakdown {
			fmt.Fprintf(out, "\n%s:\n", targetType)
			fmt.Fprintf(out, "  Executions:         %d\n", breakdown.Executions)
			fmt.Fprintf(out, "  Successes:          %d\n", breakdown.Successes)
			fmt.Fprintf(out, "  Success Rate:       %.2f%%\n", breakdown.SuccessRate*100)
			if breakdown.AverageDuration > 0 {
				fmt.Fprintf(out, "  Average Duration:   %s\n", breakdown.AverageDuration)
			}
			if breakdown.AverageConfidence > 0 {
				fmt.Fprintf(out, "  Average Confidence: %.2f%%\n", breakdown.AverageConfidence*100)
			}
		}
		fmt.Fprintf(out, "\n")
	}

	if stats.TotalExecutions == 0 {
		fmt.Fprintf(out, "No execution data available for this payload.\n")
	}

	return nil
}

// runCategoryStats shows statistics for a category
func runCategoryStats(
	cmd *cobra.Command,
	ctx context.Context,
	tracker payload.EffectivenessTracker,
	formatter internal.Formatter,
	outputFormat internal.OutputFormat,
) error {
	// TODO: Re-enable when stats commands are fully migrated
	// Parse category
	// category := payload.PayloadCategory(statsPayloadCategory)
	// if !category.IsValid() {
	// 	return fmt.Errorf("invalid category: %s (valid: %s)", statsPayloadCategory, getValidCategories())
	// }
	_ = ctx
	_ = tracker
	_ = formatter
	_ = outputFormat
	return fmt.Errorf("category stats not yet implemented with Redis backend")
}

// TODO: Re-enable when stats are migrated - all code below is commented out
/*
// runCategoryStats shows statistics for a category (DISABLED - needs Redis migration)
func runCategoryStatsDisabled(
	cmd *cobra.Command,
	ctx context.Context,
	tracker payload.EffectivenessTracker,
	formatter internal.Formatter,
	outputFormat internal.OutputFormat,
) error {
	// Get category stats
	// stats, err := tracker.GetCategoryStats(ctx, category)
// 	if err != nil {
// 		return fmt.Errorf("failed to get category stats: %w", err)
// 	}
// 
// 	// Handle JSON output
// 	if outputFormat == internal.FormatJSON {
// 		return formatter.PrintJSON(stats)
// 	}
// 
// 	// Text output
// 	out := cmd.OutOrStdout()
// 
// 	fmt.Fprintf(out, "Category Statistics: %s\n", stats.Category)
// 	fmt.Fprintf(out, "\n")
// 
// 	// Payload counts
// 	fmt.Fprintf(out, "PAYLOAD SUMMARY\n")
// 	fmt.Fprintf(out, "-------------------------------------\n")
// 	fmt.Fprintf(out, "Total Payloads:       %d\n", stats.TotalPayloads)
// 	fmt.Fprintf(out, "Enabled Payloads:     %d\n", stats.EnabledPayloads)
// 	fmt.Fprintf(out, "\n")
// 
// 	// Execution counts
// 	fmt.Fprintf(out, "EXECUTION SUMMARY\n")
// 	fmt.Fprintf(out, "-------------------------------------\n")
// 	fmt.Fprintf(out, "Total Executions:     %d\n", stats.TotalExecutions)
// 	fmt.Fprintf(out, "Successful Attacks:   %d\n", stats.SuccessfulAttacks)
// 	fmt.Fprintf(out, "Failed Executions:    %d\n", stats.FailedExecutions)
// 	fmt.Fprintf(out, "\n")
// 
// 	// Aggregate metrics
// 	if stats.TotalExecutions > 0 {
// 		fmt.Fprintf(out, "AGGREGATE METRICS\n")
// 		fmt.Fprintf(out, "-------------------------------------\n")
// 		fmt.Fprintf(out, "Success Rate:         %.2f%%\n", stats.SuccessRate*100)
// 		fmt.Fprintf(out, "Average Duration:     %s\n", stats.AverageDuration)
// 		if stats.AverageConfidence > 0 {
// 			fmt.Fprintf(out, "Average Confidence:   %.2f%%\n", stats.AverageConfidence*100)
// 		}
// 		if stats.TotalCost > 0 {
// 			fmt.Fprintf(out, "Total Cost:           $%.4f\n", stats.TotalCost)
// 		}
// 		fmt.Fprintf(out, "\n")
// 	}
// 
// 	// Finding metrics
// 	if stats.FindingsCreated > 0 {
// 		fmt.Fprintf(out, "FINDING METRICS\n")
// 		fmt.Fprintf(out, "-------------------------------------\n")
// 		fmt.Fprintf(out, "Findings Created:     %d\n", stats.FindingsCreated)
// 		fmt.Fprintf(out, "Finding Rate:         %.2f%%\n", stats.FindingRate*100)
// 		fmt.Fprintf(out, "\n")
// 	}
// 
// 	// Top performing payloads
// 	if len(stats.TopPayloads) > 0 {
// 		fmt.Fprintf(out, "TOP PERFORMING PAYLOADS\n")
// 		fmt.Fprintf(out, "-------------------------------------\n")
// 		for i, ps := range stats.TopPayloads {
// 			fmt.Fprintf(out, "%d. %s\n", i+1, ps.PayloadName)
// 			fmt.Fprintf(out, "   Success Rate: %.2f%% (%d executions)\n", ps.SuccessRate*100, ps.TotalExecutions)
// 			fmt.Fprintf(out, "   Confidence:   %.2f%%\n", ps.ConfidenceLevel*100)
// 		}
// 		fmt.Fprintf(out, "\n")
// 	}
// 
// 	if stats.TotalExecutions == 0 {
// 		fmt.Fprintf(out, "No execution data available for this category.\n")
// 	}
// 
// 	return nil
// }
*/

// Import/Export commands

var payloadImportCmd = &cobra.Command{
	Use:   "import FILE",
	Short: "Import payloads from a file",
	Long: `Import one or more payloads from a YAML or JSON file.

The file can contain a single payload or an array of payloads.

Examples:
  # Import from YAML file
  gibson payload import payloads.yaml

  # Import from JSON file
  gibson payload import payloads.json`,
	Args: cobra.ExactArgs(1),
	RunE: runPayloadImport,
}

var payloadExportCmd = &cobra.Command{
	Use:   "export ID",
	Short: "Export a payload to a file",
	Long: `Export a specific payload to a YAML or JSON file.

Examples:
  # Export to YAML file
  gibson payload export payload_abc123 --output payload.yaml

  # Export to JSON file
  gibson payload export payload_abc123 --output payload.json`,
	Args: cobra.ExactArgs(1),
	RunE: runPayloadExport,
}

// Flags for import/export commands
var (
	exportPayloadOutput string
)

// Duplicate init() function - merged into main init() above
// func init() {
// 	// Export command flags
// 	payloadExportCmd.Flags().StringVar(&exportPayloadOutput, "output", "", "Output file path (required)")
// 	payloadExportCmd.MarkFlagRequired("output")
// }

// runPayloadImport executes the payload import command
func runPayloadImport(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	filePath := args[0]

	// Read and parse file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Create payload store using Redis
	store, cleanup, err := createPayloadStore()
	if err != nil {
		return fmt.Errorf("failed to create payload store: %w", err)
	}
	defer cleanup()

	// Try to parse as array first, then as single payload
	var payloads []*payload.Payload

	// Determine format from file extension
	isYAML := strings.HasSuffix(filePath, ".yaml") || strings.HasSuffix(filePath, ".yml")
	isJSON := strings.HasSuffix(filePath, ".json")

	if isYAML {
		// Try array first
		if err := yaml.Unmarshal(data, &payloads); err != nil {
			// Try single payload
			var singlePayload payload.Payload
			if err := yaml.Unmarshal(data, &singlePayload); err != nil {
				return fmt.Errorf("failed to parse YAML: %w", err)
			}
			payloads = []*payload.Payload{&singlePayload}
		}
	} else if isJSON {
		// Try array first
		if err := json.Unmarshal(data, &payloads); err != nil {
			// Try single payload
			var singlePayload payload.Payload
			if err := json.Unmarshal(data, &singlePayload); err != nil {
				return fmt.Errorf("failed to parse JSON: %w", err)
			}
			payloads = []*payload.Payload{&singlePayload}
		}
	} else {
		// Try JSON first, then YAML
		if err := json.Unmarshal(data, &payloads); err != nil {
			if err := yaml.Unmarshal(data, &payloads); err != nil {
				// Try single payload JSON
				var singlePayload payload.Payload
				if err := json.Unmarshal(data, &singlePayload); err != nil {
					// Try single payload YAML
					if err := yaml.Unmarshal(data, &singlePayload); err != nil {
						return fmt.Errorf("failed to parse file as JSON or YAML")
					}
					payloads = []*payload.Payload{&singlePayload}
				} else {
					payloads = []*payload.Payload{&singlePayload}
				}
			}
		}
	}

	if len(payloads) == 0 {
		return fmt.Errorf("no payloads found in file")
	}

	// Import each payload
	imported := 0
	skipped := 0
	updated := 0
	var errors []string

	for _, p := range payloads {
		// Validate payload
		if err := validatePayload(p); err != nil {
			errors = append(errors, fmt.Sprintf("Validation failed for %s: %v", p.Name, err))
			skipped++
			continue
		}

		// Check if payload already exists
		var existingPayload *payload.Payload
		if !p.ID.IsZero() {
			existingPayload, _ = store.Get(ctx, p.ID)
		}

		if existingPayload != nil {
			// Payload exists - ask user or skip
			// For now, we'll update it
			p.UpdatedAt = time.Now()
			if err := store.Update(ctx, p); err != nil {
				errors = append(errors, fmt.Sprintf("Failed to update %s: %v", p.Name, err))
				skipped++
				continue
			}
			updated++
		} else {
			// New payload
			if p.ID.IsZero() {
				p.ID = types.NewID()
			}
			now := time.Now()
			p.CreatedAt = now
			p.UpdatedAt = now
			p.BuiltIn = false
			p.Enabled = true

			if err := store.Save(ctx, p); err != nil {
				errors = append(errors, fmt.Sprintf("Failed to save %s: %v", p.Name, err))
				skipped++
				continue
			}
			imported++
		}
	}

	// Print summary
	fmt.Fprintf(cmd.OutOrStdout(), "Import complete:\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  Imported: %d new payloads\n", imported)
	if updated > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "  Updated:  %d existing payloads\n", updated)
	}
	if skipped > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "  Skipped:  %d payloads (errors)\n", skipped)
	}

	if len(errors) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "\nErrors:\n")
		for _, errMsg := range errors {
			fmt.Fprintf(cmd.OutOrStdout(), "  - %s\n", errMsg)
		}
	}

	return nil
}

// runPayloadExport executes the payload export command
func runPayloadExport(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	payloadID := args[0]

	// Create payload store using Redis
	store, cleanup, err := createPayloadStore()
	if err != nil {
		return fmt.Errorf("failed to create payload store: %w", err)
	}
	defer cleanup()

	// Parse payload ID
	id, err := types.ParseID(payloadID)
	if err != nil {
		return fmt.Errorf("invalid payload ID: %w", err)
	}

	// Get payload
	p, err := store.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get payload: %w", err)
	}
	if p == nil {
		return fmt.Errorf("payload not found: %s", payloadID)
	}

	// Determine format from output file extension
	isYAML := strings.HasSuffix(exportPayloadOutput, ".yaml") || strings.HasSuffix(exportPayloadOutput, ".yml")
	isJSON := strings.HasSuffix(exportPayloadOutput, ".json")

	var data []byte

	if isYAML {
		// Export as YAML
		data, err = yaml.Marshal(p)
		if err != nil {
			return fmt.Errorf("failed to marshal YAML: %w", err)
		}
	} else if isJSON {
		// Export as JSON
		data, err = json.MarshalIndent(p, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
	} else {
		// Default to JSON
		data, err = json.MarshalIndent(p, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
	}

	// Write to file
	if err := os.WriteFile(exportPayloadOutput, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Successfully exported payload to: %s\n", exportPayloadOutput)

	return nil
}

// Search command

var payloadSearchCmd = &cobra.Command{
	Use:   "search QUERY",
	Short: "Search payloads using full-text search",
	Long: `Search payloads using full-text search across name, description, and template.

Examples:
  # Search for jailbreak payloads
  gibson payload search jailbreak

  # Search with category filter
  gibson payload search "system prompt" --category data_extraction

  # Search with severity filter
  gibson payload search bypass --severity high

  # Limit results
  gibson payload search injection --limit 10`,
	Args: cobra.ExactArgs(1),
	RunE: runPayloadSearch,
}

// Flags for search command
var (
	searchPayloadCategory   string
	searchPayloadTags       string
	searchPayloadTargetType string
	searchPayloadSeverity   string
	searchPayloadLimit      int
	searchPayloadOutput     string
)

// Duplicate init() function - merged into main init() above
// func init() {
// 	// Search command flags
// 	payloadSearchCmd.Flags().StringVar(&searchPayloadCategory, "category", "", "Filter by category")
// 	payloadSearchCmd.Flags().StringVar(&searchPayloadTags, "tags", "", "Filter by tags (comma-separated)")
// 	payloadSearchCmd.Flags().StringVar(&searchPayloadTargetType, "target-type", "", "Filter by target type")
// 	payloadSearchCmd.Flags().StringVar(&searchPayloadSeverity, "severity", "", "Filter by severity")
// 	payloadSearchCmd.Flags().IntVar(&searchPayloadLimit, "limit", 50, "Maximum number of results")
// 	payloadSearchCmd.Flags().StringVar(&searchPayloadOutput, "output", "text", "Output format (text, json)")
// }

// runPayloadSearch executes the payload search command
func runPayloadSearch(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	query := args[0]

	// Create payload store using Redis
	store, cleanup, err := createPayloadStore()
	if err != nil {
		return fmt.Errorf("failed to create payload store: %w", err)
	}
	defer cleanup()

	// Create payload registry with Redis store
	registry := payload.NewPayloadRegistryWithStore(store, payload.DefaultRegistryConfig())

	// Build filter
	filter := &payload.PayloadFilter{}

	if searchPayloadCategory != "" {
		category := payload.PayloadCategory(searchPayloadCategory)
		if !category.IsValid() {
			return fmt.Errorf("invalid category: %s (valid: %s)", searchPayloadCategory, getValidCategories())
		}
		filter.Categories = []payload.PayloadCategory{category}
	}

	if searchPayloadSeverity != "" {
		severity := agent.FindingSeverity(searchPayloadSeverity)
		if !isValidSeverity(severity) {
			return fmt.Errorf("invalid severity: %s (valid: critical, high, medium, low, info)", searchPayloadSeverity)
		}
		filter.Severities = []agent.FindingSeverity{severity}
	}

	if searchPayloadTags != "" {
		tags := strings.Split(searchPayloadTags, ",")
		for i, tag := range tags {
			tags[i] = strings.TrimSpace(tag)
		}
		filter.Tags = tags
	}

	if searchPayloadTargetType != "" {
		filter.TargetTypes = []string{searchPayloadTargetType}
	}

	// Perform search
	payloads, err := registry.Search(ctx, query, filter)
	if err != nil {
		return fmt.Errorf("failed to search payloads: %w", err)
	}

	// Apply limit
	if searchPayloadLimit > 0 && len(payloads) > searchPayloadLimit {
		payloads = payloads[:searchPayloadLimit]
	}

	// Determine output format
	outputFormat := internal.FormatText
	if searchPayloadOutput == "json" {
		outputFormat = internal.FormatJSON
	}

	formatter := internal.NewFormatter(outputFormat, cmd.OutOrStdout())

	// Handle JSON output
	if outputFormat == internal.FormatJSON {
		output := map[string]interface{}{
			"query":    query,
			"count":    len(payloads),
			"payloads": payloads,
		}
		return formatter.PrintJSON(output)
	}

	// Text output
	if len(payloads) == 0 {
		return formatter.PrintError(fmt.Sprintf("No payloads found matching query: %s", query))
	}

	// Print summary
	fmt.Fprintf(cmd.OutOrStdout(), "Found %d payload(s) matching: %s\n\n", len(payloads), query)

	// Build table
	headers := []string{"ID", "Name", "Categories", "Severity", "Built-In"}
	rows := make([][]string, 0, len(payloads))

	for _, p := range payloads {
		// Format categories
		categories := make([]string, len(p.Categories))
		for i, cat := range p.Categories {
			categories[i] = string(cat)
		}
		categoryStr := strings.Join(categories, ", ")
		if len(categoryStr) > 30 {
			categoryStr = categoryStr[:27] + "..."
		}

		// Format built-in status
		builtInStr := ""
		if p.BuiltIn {
			builtInStr = "yes"
		}

		rows = append(rows, []string{
			p.ID.String(),
			truncateString(p.Name, 40),
			categoryStr,
			string(p.Severity),
			builtInStr,
		})
	}

	// Print table
	if err := formatter.PrintTable(headers, rows); err != nil {
		return fmt.Errorf("failed to print table: %w", err)
	}

	return nil
}

// Sync command

var payloadSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync payloads with Zero Day AI cloud (coming soon)",
	Long: `Sync payloads with Zero Day AI cloud service. This feature is not yet available.

For now, use 'gibson payload import' to add payloads locally.

Examples:
  # Attempt to sync (will show message)
  gibson payload sync`,
	RunE: runPayloadSync,
}

// runPayloadSync executes the payload sync command
func runPayloadSync(cmd *cobra.Command, args []string) error {
	// Check if configuration exists and payloads provider is set
	homeDir, err := getGibsonHome()
	if err == nil {
		// Try to read config
		cfgPath := homeDir + "/config.yaml"
		if data, err := os.ReadFile(cfgPath); err == nil {
			// Check if zero-day-ai provider is configured
			if strings.Contains(string(data), "provider: zero-day-ai") || strings.Contains(string(data), `provider: "zero-day-ai"`) {
				fmt.Fprintf(cmd.OutOrStdout(), "Zero Day AI cloud integration coming soon.\n")
				fmt.Fprintf(cmd.OutOrStdout(), "For now, use 'gibson payload import' to add payloads locally.\n")
				return nil
			}
		}
	}

	// Default message for local provider or no configuration
	fmt.Fprintf(cmd.OutOrStdout(), "Cloud sync not configured. Use 'gibson payload import' to add payloads locally.\n")
	return nil
}
