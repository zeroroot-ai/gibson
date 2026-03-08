package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/zero-day-ai/gibson/cmd/gibson/internal"
	"github.com/zero-day-ai/gibson/internal/database"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

var targetCmd = &cobra.Command{
	Use:   "target",
	Short: "Manage attack targets",
	Long:  `Manage targets (networks, LLMs, smart contracts, etc.) for red-team testing operations`,
}

var targetListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all targets",
	Long:  `List all configured targets with optional filtering`,
	RunE:  runTargetList,
}

var targetAddCmd = &cobra.Command{
	Use:   "add NAME",
	Short: "Add a new target",
	Long: `Add a new target with schema-based connection parameters.

Examples:
  # Add HTTP API target
  gibson target add my-api --type http_api --connection '{"url":"https://api.example.com/v1/chat"}'

  # Add Kubernetes cluster target
  gibson target add prod-k8s --type kubernetes --connection '{"cluster":"prod","namespace":"default"}'

  # Add smart contract target
  gibson target add my-contract --type smart_contract --connection '{"chain":"ethereum","address":"0x..."}'

  # Interactive mode (prompts for required fields)
  gibson target add my-target --type http_api --interactive`,
	Args: cobra.ExactArgs(1),
	RunE: runTargetAdd,
}

var targetShowCmd = &cobra.Command{
	Use:   "show NAME",
	Short: "Show detailed target information",
	Long:  `Display detailed information about a specific target`,
	Args:  cobra.ExactArgs(1),
	RunE:  runTargetShow,
}

var targetTestCmd = &cobra.Command{
	Use:   "test NAME",
	Short: "Test target connectivity",
	Long:  `Test connectivity and authentication to a target`,
	Args:  cobra.ExactArgs(1),
	RunE:  runTargetTest,
}

var targetDeleteCmd = &cobra.Command{
	Use:   "delete NAME",
	Short: "Delete a target",
	Long:  `Delete a target from the database`,
	Args:  cobra.ExactArgs(1),
	RunE:  runTargetDelete,
}

// Flags for target list
var (
	listStatusFilter   string
	listProviderFilter string
	listOutputFormat   string
)

// Flags for target add
var (
	addType        string
	addConnection  string
	addInteractive bool
	addProvider    string
	addCredential  string
	addDescription string
	addTags        string
	addTimeout     int
)

// Flags for target show
var (
	showOutputFormat string
)

// Flags for target delete
var (
	deleteForce bool
)

func init() {
	// List command flags
	targetListCmd.Flags().StringVar(&listStatusFilter, "status", "", "Filter by status (active, inactive, error)")
	targetListCmd.Flags().StringVar(&listProviderFilter, "provider", "", "Filter by provider (openai, anthropic, google, azure, ollama, custom)")
	targetListCmd.Flags().StringVarP(&listOutputFormat, "output", "o", "table", "Output format (table, json)")

	// Add command flags
	targetAddCmd.Flags().StringVar(&addType, "type", "", "Target type (http_api, kubernetes, smart_contract, etc.) - required")
	targetAddCmd.Flags().StringVar(&addConnection, "connection", "", "Connection parameters as JSON - required unless --interactive")
	targetAddCmd.Flags().BoolVar(&addInteractive, "interactive", false, "Prompt for connection fields based on schema")
	targetAddCmd.Flags().StringVar(&addProvider, "provider", "", "Provider hint (optional)")
	targetAddCmd.Flags().StringVar(&addCredential, "credential", "", "Credential name to use for authentication")
	targetAddCmd.Flags().StringVar(&addDescription, "description", "", "Target description")
	targetAddCmd.Flags().StringVar(&addTags, "tags", "", "Comma-separated tags")
	targetAddCmd.Flags().IntVar(&addTimeout, "timeout", 30, "Request timeout in seconds")
	targetAddCmd.MarkFlagRequired("type")

	// Show command flags
	targetShowCmd.Flags().StringVarP(&showOutputFormat, "output", "o", "text", "Output format (text, json)")

	// Delete command flags
	targetDeleteCmd.Flags().BoolVar(&deleteForce, "force", false, "Skip confirmation prompt")

	// Add subcommands
	targetCmd.AddCommand(targetListCmd)
	targetCmd.AddCommand(targetAddCmd)
	targetCmd.AddCommand(targetShowCmd)
	targetCmd.AddCommand(targetTestCmd)
	targetCmd.AddCommand(targetDeleteCmd)
}

// createTargetDAO creates a Redis-backed target DAO using the global configuration
func createTargetDAO() (database.TargetDAO, func(), error) {
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

	// Create Redis target DAO
	dao := database.NewRedisTargetDAO(stateClient)

	// Return DAO and cleanup function
	cleanup := func() {
		if err := stateClient.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close state client: %v\n", err)
		}
	}

	return dao, cleanup, nil
}

// createCredentialDAO creates a Redis-backed credential DAO using the global configuration
func createCredentialDAO() (database.CredentialDAO, func(), error) {
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

	// Create Redis credential DAO
	dao := database.NewRedisCredentialDAO(stateClient)

	// Return DAO and cleanup function
	cleanup := func() {
		if err := stateClient.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close state client: %v\n", err)
		}
	}

	return dao, cleanup, nil
}

// runTargetList executes the target list command
func runTargetList(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Validate output format
	if listOutputFormat != "table" && listOutputFormat != "json" {
		return fmt.Errorf("invalid output format: %s (must be 'table' or 'json')", listOutputFormat)
	}

	// Create target DAO using Redis
	dao, cleanup, err := createTargetDAO()
	if err != nil {
		return fmt.Errorf("failed to create target DAO: %w", err)
	}
	defer cleanup()

	// Create filter
	filter := types.NewTargetFilter()

	if listStatusFilter != "" {
		status := types.TargetStatus(listStatusFilter)
		if !status.IsValid() {
			return fmt.Errorf("invalid status: %s", listStatusFilter)
		}
		filter.WithStatus(status)
	}

	if listProviderFilter != "" {
		provider := types.Provider(listProviderFilter)
		if !provider.IsValid() {
			return fmt.Errorf("invalid provider: %s", listProviderFilter)
		}
		filter.WithProvider(provider)
	}

	// Query targets
	targets, err := dao.List(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to list targets: %w", err)
	}

	if len(targets) == 0 {
		if listOutputFormat == "json" {
			cmd.Println("[]")
		} else {
			cmd.Println("No targets found.")
		}
		return nil
	}

	// Output based on format
	switch listOutputFormat {
	case "json":
		return outputTargetListJSON(cmd, targets)
	default:
		return outputTargetListTable(cmd, targets)
	}
}

// outputTargetListTable displays targets in table format
func outputTargetListTable(cmd *cobra.Command, targets []*types.Target) error {
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tTYPE\tPROVIDER\tSTATUS\tCONNECTION")
	fmt.Fprintln(w, "----\t----\t--------\t------\t----------")

	for _, target := range targets {
		// Extract key connection parameter summary
		connectionSummary := extractConnectionSummary(target)

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			target.Name,
			target.Type,
			target.Provider,
			target.Status,
			connectionSummary,
		)
	}

	w.Flush()
	return nil
}

// outputTargetListJSON displays targets in JSON format
func outputTargetListJSON(cmd *cobra.Command, targets []*types.Target) error {
	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", "  ")
	return encoder.Encode(targets)
}

// extractConnectionSummary extracts key connection info for display
func extractConnectionSummary(target *types.Target) string {
	// For now, just show URL since Connection field hasn't been added yet
	// When Connection is added, this will be extended to handle different target types
	if target.URL != "" {
		return truncateString(target.URL, 50)
	}
	return "N/A"
}

// runTargetAdd executes the target add command
func runTargetAdd(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	targetName := args[0]

	// Validate required flags
	if !addInteractive && addConnection == "" {
		return fmt.Errorf("either --connection or --interactive is required")
	}

	// Parse connection parameters
	var connection map[string]any
	var err error

	if addInteractive {
		connection, err = promptForConnection(cmd, addType)
		if err != nil {
			return fmt.Errorf("interactive input failed: %w", err)
		}
	} else {
		if err := json.Unmarshal([]byte(addConnection), &connection); err != nil {
			return fmt.Errorf("invalid JSON in --connection: %w", err)
		}
	}

	// Validate connection against schema if available
	if err := validateConnectionAgainstSchema(cmd, addType, connection); err != nil {
		// Don't fail, just warn if schema not found or validation fails
		cmd.Printf("Warning: %v\n", err)
	}

	// Create target DAO using Redis
	dao, cleanup, err := createTargetDAO()
	if err != nil {
		return fmt.Errorf("failed to create target DAO: %w", err)
	}
	defer cleanup()

	// Check if target name already exists
	exists, err := dao.Exists(ctx, targetName)
	if err != nil {
		return fmt.Errorf("failed to check target name: %w", err)
	}
	if exists {
		return fmt.Errorf("target with name '%s' already exists", targetName)
	}

	// Extract URL from connection for backward compatibility
	targetURL := ""
	if urlVal, ok := connection["url"].(string); ok {
		targetURL = urlVal
	}

	// Create target with connection map
	// Note: For now, we still use the old NewTarget but will migrate to Connection-based approach
	target := types.NewTarget(targetName, targetURL, types.TargetType(addType))
	target.Provider = types.Provider(addProvider)
	target.Timeout = addTimeout
	target.Description = addDescription

	// Parse tags if provided
	if addTags != "" {
		target.Tags = strings.Split(addTags, ",")
		for i := range target.Tags {
			target.Tags[i] = strings.TrimSpace(target.Tags[i])
		}
	}

	// Store connection parameters in Connection field (schema-based connection params)
	target.Connection = connection

	// Handle credential if specified
	if addCredential != "" {
		credDAO, credCleanup, err := createCredentialDAO()
		if err != nil {
			return fmt.Errorf("failed to create credential DAO: %w", err)
		}
		defer credCleanup()

		cred, err := credDAO.GetByName(ctx, addCredential)
		if err != nil {
			return fmt.Errorf("failed to find credential '%s': %w", addCredential, err)
		}
		target.CredentialID = &cred.ID

		// Set auth type based on credential type
		switch cred.Type {
		case types.CredentialTypeAPIKey:
			target.AuthType = types.AuthTypeAPIKey
		case types.CredentialTypeBearer:
			target.AuthType = types.AuthTypeBearer
		case types.CredentialTypeBasic:
			target.AuthType = types.AuthTypeBasic
		case types.CredentialTypeOAuth:
			target.AuthType = types.AuthTypeOAuth
		default:
			target.AuthType = types.AuthTypeNone
		}
	} else {
		target.AuthType = types.AuthTypeNone
	}

	// Save to database
	if err := dao.Create(ctx, target); err != nil {
		return fmt.Errorf("failed to create target: %w", err)
	}

	cmd.Printf("Target '%s' created successfully (ID: %s)\n", target.Name, target.ID)
	return nil
}

// promptForConnection prompts the user for connection fields based on target type schema
func promptForConnection(cmd *cobra.Command, targetType string) (map[string]any, error) {
	connection := make(map[string]any)
	reader := bufio.NewReader(os.Stdin)

	// Try to get schema for the target type
	// For now, provide basic prompts for common types
	// TODO: When built-in schemas are available, use them to generate prompts

	switch targetType {
	case "http_api", "llm_api", "llm_chat":
		cmd.Print("Enter URL: ")
		url, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		connection["url"] = strings.TrimSpace(url)

		cmd.Print("Enter method (default: POST): ")
		method, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		method = strings.TrimSpace(method)
		if method != "" {
			connection["method"] = method
		} else {
			connection["method"] = "POST"
		}

	case "kubernetes":
		cmd.Print("Enter cluster name or kubeconfig context: ")
		cluster, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		connection["cluster"] = strings.TrimSpace(cluster)

		cmd.Print("Enter namespace (default: default): ")
		namespace, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		namespace = strings.TrimSpace(namespace)
		if namespace != "" {
			connection["namespace"] = namespace
		} else {
			connection["namespace"] = "default"
		}

		cmd.Print("Enter kubeconfig path (optional): ")
		kubeconfig, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		kubeconfig = strings.TrimSpace(kubeconfig)
		if kubeconfig != "" {
			connection["kubeconfig"] = kubeconfig
		}

	case "smart_contract":
		cmd.Print("Enter blockchain chain (ethereum, polygon, arbitrum, base, solana): ")
		chain, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		connection["chain"] = strings.TrimSpace(chain)

		cmd.Print("Enter contract address: ")
		address, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		connection["address"] = strings.TrimSpace(address)

		cmd.Print("Enter RPC URL (optional): ")
		rpcURL, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		rpcURL = strings.TrimSpace(rpcURL)
		if rpcURL != "" {
			connection["rpc_url"] = rpcURL
		}

	default:
		return nil, fmt.Errorf("interactive mode not yet supported for target type '%s'. Please use --connection flag", targetType)
	}

	return connection, nil
}

// validateConnectionAgainstSchema validates connection parameters against the target type schema
func validateConnectionAgainstSchema(cmd *cobra.Command, targetType string, connection map[string]any) error {
	// TODO: Once SDK built-in schemas are available via import, use them here
	// For now, perform basic validation

	switch targetType {
	case "http_api", "llm_api", "llm_chat":
		if _, ok := connection["url"]; !ok {
			return fmt.Errorf("connection validation: 'url' is required for type '%s'", targetType)
		}

	case "kubernetes":
		if _, ok := connection["cluster"]; !ok {
			return fmt.Errorf("connection validation: 'cluster' is required for type '%s'", targetType)
		}

	case "smart_contract":
		if _, ok := connection["chain"]; !ok {
			return fmt.Errorf("connection validation: 'chain' is required for type '%s'", targetType)
		}
		if _, ok := connection["address"]; !ok {
			return fmt.Errorf("connection validation: 'address' is required for type '%s'", targetType)
		}

	default:
		// Unknown target type - warn but allow
		cmd.Printf("Warning: no schema registered for type '%s', skipping validation\n", targetType)
	}

	return nil
}

// runTargetShow executes the target show command
func runTargetShow(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	targetName := args[0]

	// Validate output format
	if showOutputFormat != "text" && showOutputFormat != "json" {
		return fmt.Errorf("invalid output format: %s (must be 'text' or 'json')", showOutputFormat)
	}

	// Create target DAO using Redis
	dao, cleanup, err := createTargetDAO()
	if err != nil {
		return fmt.Errorf("failed to create target DAO: %w", err)
	}
	defer cleanup()

	// Get target
	target, err := dao.GetByName(ctx, targetName)
	if err != nil {
		return fmt.Errorf("failed to get target: %w", err)
	}

	// Output based on format
	switch showOutputFormat {
	case "json":
		return outputTargetShowJSON(cmd, target)
	default:
		return outputTargetShowText(cmd, target)
	}
}

// outputTargetShowText displays target in human-readable text format
func outputTargetShowText(cmd *cobra.Command, target *types.Target) error {
	cmd.Printf("Target: %s\n", target.Name)
	cmd.Printf("ID: %s\n", target.ID)
	cmd.Printf("Type: %s\n", target.Type)
	cmd.Printf("Provider: %s\n", target.Provider)
	cmd.Printf("URL: %s\n", target.URL)
	cmd.Printf("Model: %s\n", target.Model)
	cmd.Printf("Status: %s\n", target.Status)
	cmd.Printf("Auth Type: %s\n", target.AuthType)

	if target.CredentialID != nil {
		cmd.Printf("Credential ID: %s\n", target.CredentialID)
	}

	if target.Description != "" {
		cmd.Printf("Description: %s\n", target.Description)
	}

	cmd.Printf("Timeout: %d seconds\n", target.Timeout)

	if len(target.Tags) > 0 {
		cmd.Printf("Tags: %s\n", strings.Join(target.Tags, ", "))
	}

	if len(target.Headers) > 0 {
		cmd.Println("\nCustom Headers:")
		maskedHeaders := maskSensitiveMapValues(target.Headers)
		for k, v := range maskedHeaders {
			cmd.Printf("  %s: %s\n", k, v)
		}
	}

	if len(target.Config) > 0 {
		cmd.Println("\nConfiguration:")
		maskedConfig := maskSensitiveConfig(target.Config)
		configJSON, _ := json.MarshalIndent(maskedConfig, "  ", "  ")
		cmd.Printf("  %s\n", string(configJSON))
	}

	if len(target.Capabilities) > 0 {
		cmd.Printf("\nCapabilities: %s\n", strings.Join(target.Capabilities, ", "))
	}

	cmd.Printf("\nCreated: %s\n", target.CreatedAt.Format(time.RFC3339))
	cmd.Printf("Updated: %s\n", target.UpdatedAt.Format(time.RFC3339))

	return nil
}

// outputTargetShowJSON displays target in JSON format with sensitive fields masked
func outputTargetShowJSON(cmd *cobra.Command, target *types.Target) error {
	// Create a copy of the target with masked sensitive fields
	maskedTarget := *target
	maskedTarget.Headers = maskSensitiveMapValues(target.Headers)
	maskedTarget.Config = maskSensitiveConfig(target.Config)

	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", "  ")
	return encoder.Encode(maskedTarget)
}

// maskSensitiveMapValues masks sensitive values in string maps
func maskSensitiveMapValues(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}

	result := make(map[string]string, len(m))
	for k, v := range m {
		if isSensitiveKey(k) {
			result[k] = maskValue(v)
		} else {
			result[k] = v
		}
	}
	return result
}

// maskSensitiveConfig masks sensitive values in config map
func maskSensitiveConfig(config map[string]interface{}) map[string]interface{} {
	if config == nil {
		return nil
	}

	result := make(map[string]interface{}, len(config))
	for k, v := range config {
		if isSensitiveKey(k) {
			// Mask string values
			if strVal, ok := v.(string); ok {
				result[k] = maskValue(strVal)
			} else {
				result[k] = "[REDACTED]"
			}
		} else {
			// Recursively mask nested maps
			if mapVal, ok := v.(map[string]interface{}); ok {
				result[k] = maskSensitiveConfig(mapVal)
			} else {
				result[k] = v
			}
		}
	}
	return result
}

// isSensitiveKey checks if a key name indicates sensitive data
func isSensitiveKey(key string) bool {
	keyLower := strings.ToLower(key)
	sensitivePatterns := []string{
		"api_key", "apikey", "api-key",
		"token", "access_token", "bearer_token",
		"password", "passwd", "pwd",
		"secret", "client_secret",
		"authorization", "auth",
		"credential", "credentials",
		"private_key", "privatekey",
	}

	for _, pattern := range sensitivePatterns {
		if strings.Contains(keyLower, pattern) {
			return true
		}
	}
	return false
}

// maskValue masks a sensitive value, showing only first/last characters
func maskValue(value string) string {
	if len(value) == 0 {
		return ""
	}
	if len(value) <= 8 {
		return "********"
	}
	// Show first 4 and last 4 characters
	return value[:4] + "..." + value[len(value)-4:]
}

// runTargetTest executes the target test command
func runTargetTest(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	targetName := args[0]

	// Create target DAO using Redis
	dao, cleanup, err := createTargetDAO()
	if err != nil {
		return fmt.Errorf("failed to create target DAO: %w", err)
	}
	defer cleanup()

	// Get target
	target, err := dao.GetByName(ctx, targetName)
	if err != nil {
		return fmt.Errorf("failed to get target: %w", err)
	}

	cmd.Printf("Testing connectivity to %s...\n", target.Name)

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: time.Duration(target.Timeout) * time.Second,
	}

	// Create a simple OPTIONS request to test connectivity
	req, err := http.NewRequestWithContext(ctx, "OPTIONS", target.URL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add custom headers
	for k, v := range target.Headers {
		req.Header.Set(k, v)
	}

	// Perform request
	start := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(start)

	if err != nil {
		cmd.Printf("Failed: %v\n", err)

		// Update target status to error
		target.Status = types.TargetStatusError
		dao.Update(ctx, target)

		return fmt.Errorf("connectivity test failed")
	}
	defer internal.CloseWithLog(resp.Body, nil, "HTTP response body")

	// Check response
	if resp.StatusCode >= 200 && resp.StatusCode < 500 {
		cmd.Printf("Success: Connected in %v (Status: %d)\n", duration, resp.StatusCode)

		// Update target status to active
		if target.Status != types.TargetStatusActive {
			target.Status = types.TargetStatusActive
			dao.Update(ctx, target)
		}

		return nil
	}

	cmd.Printf("Warning: Unexpected status code %d (took %v)\n", resp.StatusCode, duration)
	return nil
}

// runTargetDelete executes the target delete command
func runTargetDelete(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	targetName := args[0]

	// Create target DAO using Redis
	dao, cleanup, err := createTargetDAO()
	if err != nil {
		return fmt.Errorf("failed to create target DAO: %w", err)
	}
	defer cleanup()

	// Get target
	target, err := dao.GetByName(ctx, targetName)
	if err != nil {
		return fmt.Errorf("failed to get target: %w", err)
	}

	// Confirm deletion unless --force is set
	if !deleteForce {
		cmd.Printf("Are you sure you want to delete target '%s'? (y/N): ", targetName)
		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}

		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			cmd.Println("Deletion cancelled.")
			return nil
		}
	}

	// Delete target
	if err := dao.Delete(ctx, target.ID); err != nil {
		return fmt.Errorf("failed to delete target: %w", err)
	}

	cmd.Printf("Target '%s' deleted successfully.\n", targetName)
	return nil
}

// detectProvider attempts to auto-detect the provider from the URL
func detectProvider(u *url.URL) string {
	host := strings.ToLower(u.Host)

	if strings.Contains(host, "openai.com") || strings.Contains(host, "api.openai.com") {
		return "openai"
	}
	if strings.Contains(host, "anthropic.com") || strings.Contains(host, "api.anthropic.com") {
		return "anthropic"
	}
	if strings.Contains(host, "googleapis.com") || strings.Contains(host, "generativelanguage.googleapis.com") {
		return "google"
	}
	if strings.Contains(host, "azure.com") || strings.Contains(host, "openai.azure.com") {
		return "azure"
	}
	if strings.Contains(host, "localhost") || strings.Contains(host, "127.0.0.1") {
		return "ollama"
	}

	return "custom"
}

// detectModel attempts to auto-detect the model from the URL and provider
func detectModel(u *url.URL, provider string) string {
	path := strings.ToLower(u.Path)

	// Try to extract model from path
	if strings.Contains(path, "gpt-4") {
		return "gpt-4"
	}
	if strings.Contains(path, "gpt-3.5") {
		return "gpt-3.5-turbo"
	}
	if strings.Contains(path, "claude-3") {
		return "claude-3-opus"
	}
	if strings.Contains(path, "gemini") {
		return "gemini-pro"
	}

	// Default models by provider
	switch provider {
	case "openai":
		return "gpt-4"
	case "anthropic":
		return "claude-3-opus"
	case "google":
		return "gemini-pro"
	case "ollama":
		return "llama2"
	default:
		return ""
	}
}

// getGibsonHome returns the Gibson home directory
func getGibsonHome() (string, error) {
	homeDir := os.Getenv("GIBSON_HOME")
	if homeDir == "" {
		userHome, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		homeDir = userHome + "/.gibson"
	}
	return homeDir, nil
}
