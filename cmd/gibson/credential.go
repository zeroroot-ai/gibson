package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/zero-day-ai/gibson/cmd/gibson/internal"
	"github.com/zero-day-ai/gibson/internal/config"
	"github.com/zero-day-ai/gibson/internal/crypto"
	"github.com/zero-day-ai/gibson/internal/database"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/llm/providers"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
	"golang.org/x/term"
)

var credentialCmd = &cobra.Command{
	Use:   "credential",
	Short: "Manage authentication credentials",
	Long: `Manage authentication credentials for external systems and services.

Credentials are stored encrypted in the database. The plaintext value is
NEVER displayed or logged. Use secure input prompts for adding credentials.`,
}

var credentialListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all credentials (names only, no secrets)",
	Long: `List all stored credentials showing names and metadata only.

SECURITY: This command NEVER displays plaintext credential values.
Only metadata such as name, type, provider, and status are shown.`,
	RunE: runCredentialList,
}

var credentialAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new credential",
	Long: `Add a new credential with secure password input.

The credential value can be provided via:
  - Interactive prompt (secure, no echo)
  - --from-env flag to read from environment variable

The credential is encrypted before storage using AES-256-GCM with
scrypt key derivation. The plaintext is never stored.

Examples:
  gibson credential add --name openai-key --type api_key --provider openai
  gibson credential add --name aws-creds --type api_key --provider aws --from-env AWS_SECRET_KEY`,
	RunE: runCredentialAdd,
}

var credentialShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show credential metadata (never displays secrets)",
	Long: `Show detailed metadata for a credential.

SECURITY: This command NEVER displays the plaintext credential value.
Only metadata such as type, provider, status, rotation info, and usage
statistics are displayed.`,
	Args: cobra.ExactArgs(1),
	RunE: runCredentialShow,
}

var credentialTestCmd = &cobra.Command{
	Use:   "test <name>",
	Short: "Test credential validity",
	Long: `Test if a credential is valid by attempting to use it with the provider's API.

This performs a minimal API call to verify the credential works. The exact
test performed depends on the provider type.

Note: This feature requires provider-specific validation logic to be implemented.`,
	Args: cobra.ExactArgs(1),
	RunE: runCredentialTest,
}

var credentialRotateCmd = &cobra.Command{
	Use:   "rotate <name>",
	Short: "Rotate a credential value",
	Long: `Rotate (update) a credential's value with secure input.

This updates the encrypted value for an existing credential. The new value
is prompted securely (no echo) or can be read from an environment variable
with --from-env.`,
	Args: cobra.ExactArgs(1),
	RunE: runCredentialRotate,
}

var credentialDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a credential",
	Long: `Delete a credential from the database.

This is a destructive operation that cannot be undone. A confirmation
prompt will be displayed unless --force is used.`,
	Args: cobra.ExactArgs(1),
	RunE: runCredentialDelete,
}

// Flags for credential add command
var (
	credName     string
	credType     string
	credProvider string
	credFromEnv  string
	credDesc     string
	credForce    bool
)

func init() {
	// Add flags for credential add
	credentialAddCmd.Flags().StringVar(&credName, "name", "", "Credential name (required)")
	credentialAddCmd.Flags().StringVar(&credType, "type", "api_key", "Credential type (api_key, bearer, basic, oauth, custom)")
	credentialAddCmd.Flags().StringVar(&credProvider, "provider", "", "Provider name (e.g., openai, anthropic, aws)")
	credentialAddCmd.Flags().StringVar(&credFromEnv, "from-env", "", "Read credential value from environment variable")
	credentialAddCmd.Flags().StringVar(&credDesc, "description", "", "Credential description")
	credentialAddCmd.MarkFlagRequired("name")

	// Add flags for credential rotate
	credentialRotateCmd.Flags().StringVar(&credFromEnv, "from-env", "", "Read new credential value from environment variable")

	// Add flags for credential delete
	credentialDeleteCmd.Flags().BoolVar(&credForce, "force", false, "Skip confirmation prompt")

	// Add subcommands
	credentialCmd.AddCommand(credentialListCmd)
	credentialCmd.AddCommand(credentialAddCmd)
	credentialCmd.AddCommand(credentialShowCmd)
	credentialCmd.AddCommand(credentialTestCmd)
	credentialCmd.AddCommand(credentialRotateCmd)
	credentialCmd.AddCommand(credentialDeleteCmd)
}

func runCredentialList(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Parse global flags
	flags, err := ParseGlobalFlags(cmd)
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to parse flags", err)
	}

	// Load configuration
	cfg, err := loadConfiguration(flags)
	if err != nil {
		return internal.WrapError(internal.ExitConfigError, "failed to load config", err)
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
		return internal.WrapError(internal.ExitDatabaseError, "failed to create state client", err)
	}
	defer stateClient.Close()

	// List credentials with Redis backend
	dao := database.NewRedisCredentialDAO(stateClient)
	credentials, err := dao.List(ctx, nil)
	if err != nil {
		return internal.WrapError(internal.ExitDatabaseError, "failed to list credentials", err)
	}

	// Create formatter
	outFormat := internal.FormatText
	if flags.OutputFormat == "json" {
		outFormat = internal.FormatJSON
	}
	formatter := internal.NewFormatter(outFormat, cmd.OutOrStdout())

	if outFormat == internal.FormatJSON {
		// Build JSON output (NEVER include secrets)
		credList := make([]map[string]interface{}, len(credentials))
		for i, cred := range credentials {
			credList[i] = map[string]interface{}{
				"name":        cred.Name,
				"type":        cred.Type.String(),
				"provider":    cred.Provider,
				"status":      cred.Status.String(),
				"description": cred.Description,
				"created_at":  cred.CreatedAt,
			}
		}
		return formatter.PrintJSON(credList)
	}

	// Text output - use table
	if len(credentials) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No credentials found")
		return nil
	}

	headers := []string{"Name", "Type", "Provider", "Status", "Created"}
	rows := make([][]string, len(credentials))
	for i, cred := range credentials {
		rows[i] = []string{
			cred.Name,
			string(cred.Type),
			cred.Provider,
			string(cred.Status),
			cred.CreatedAt.Format("2006-01-02 15:04:05"),
		}
	}

	return formatter.PrintTable(headers, rows)
}

func runCredentialAdd(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Parse global flags
	flags, err := ParseGlobalFlags(cmd)
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to parse flags", err)
	}

	// Validate credential type
	var credTypeEnum types.CredentialType
	switch strings.ToLower(credType) {
	case "api_key":
		credTypeEnum = types.CredentialTypeAPIKey
	case "bearer":
		credTypeEnum = types.CredentialTypeBearer
	case "basic":
		credTypeEnum = types.CredentialTypeBasic
	case "oauth":
		credTypeEnum = types.CredentialTypeOAuth
	case "custom":
		credTypeEnum = types.CredentialTypeCustom
	default:
		return internal.NewCLIError(internal.ExitError, fmt.Sprintf("invalid credential type: %s (must be api_key, bearer, basic, oauth, or custom)", credType))
	}

	// Get credential value securely
	var credValue string
	var credValueBytes []byte
	if credFromEnv != "" {
		// Read from environment variable
		credValue = os.Getenv(credFromEnv)
		if credValue == "" {
			return internal.NewCLIError(internal.ExitError, fmt.Sprintf("environment variable %s is not set or empty", credFromEnv))
		}
		if flags.IsVerbose() {
			cmd.PrintErrf("Read credential from environment variable: %s\n", credFromEnv)
		}
	} else {
		// Prompt for credential value securely (no echo)
		fmt.Fprint(cmd.OutOrStderr(), "Enter credential value (input hidden): ")
		var err error
		credValueBytes, err = term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(cmd.OutOrStderr()) // New line after hidden input
		if err != nil {
			return internal.WrapError(internal.ExitError, "failed to read credential value", err)
		}
		credValue = string(credValueBytes)
		if credValue == "" {
			return internal.NewCLIError(internal.ExitError, "credential value cannot be empty")
		}
	}

	// Load configuration
	cfg, err := loadConfiguration(flags)
	if err != nil {
		return internal.WrapError(internal.ExitConfigError, "failed to load config", err)
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
		return internal.WrapError(internal.ExitDatabaseError, "failed to create state client", err)
	}
	defer stateClient.Close()

	// Check if credential already exists with Redis backend
	dao := database.NewRedisCredentialDAO(stateClient)
	exists, err := dao.Exists(ctx, credName)
	if err != nil {
		return internal.WrapError(internal.ExitDatabaseError, "failed to check credential existence", err)
	}
	if exists {
		return internal.NewCLIError(internal.ExitError, fmt.Sprintf("credential already exists: %s", credName))
	}

	// Get master key
	masterKey, err := loadMasterKey(flags)
	if err != nil {
		return internal.WrapError(internal.ExitConfigError, "failed to load master key", err)
	}

	// Encrypt credential value
	encryptor := crypto.NewAESGCMEncryptor()
	encryptedValue, iv, salt, err := encryptor.Encrypt([]byte(credValue), masterKey)
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to encrypt credential", err)
	}

	// SECURITY: Clear plaintext from memory
	credValue = ""
	if len(credValueBytes) > 0 {
		for i := range credValueBytes {
			credValueBytes[i] = 0
		}
	}

	// Create credential
	cred := types.NewCredential(credName, credTypeEnum)
	cred.Provider = credProvider
	cred.Description = credDesc
	cred.EncryptedValue = encryptedValue
	cred.EncryptionIV = iv
	cred.KeyDerivationSalt = salt

	// Save to database
	if err := dao.Create(ctx, cred); err != nil {
		return internal.WrapError(internal.ExitDatabaseError, "failed to create credential", err)
	}

	// Create formatter
	outFormat := internal.FormatText
	if flags.OutputFormat == "json" {
		outFormat = internal.FormatJSON
	}
	formatter := internal.NewFormatter(outFormat, cmd.OutOrStdout())
	return formatter.PrintSuccess(fmt.Sprintf("Credential created: %s", credName))
}

func runCredentialShow(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	credName := args[0]

	// Parse global flags
	flags, err := ParseGlobalFlags(cmd)
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to parse flags", err)
	}

	// Load configuration
	cfg, err := loadConfiguration(flags)
	if err != nil {
		return internal.WrapError(internal.ExitConfigError, "failed to load config", err)
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
		return internal.WrapError(internal.ExitDatabaseError, "failed to create state client", err)
	}
	defer stateClient.Close()

	// Get credential with Redis backend
	dao := database.NewRedisCredentialDAO(stateClient)
	cred, err := dao.GetByName(ctx, credName)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return internal.NewCLIError(internal.ExitNotFound, fmt.Sprintf("credential not found: %s", credName))
		}
		return internal.WrapError(internal.ExitDatabaseError, "failed to get credential", err)
	}

	// Create formatter
	outFormat := internal.FormatText
	if flags.OutputFormat == "json" {
		outFormat = internal.FormatJSON
	}
	formatter := internal.NewFormatter(outFormat, cmd.OutOrStdout())

	if outFormat == internal.FormatJSON {
		// SECURITY: NEVER include encrypted value, IV, or salt in output
		credData := map[string]interface{}{
			"name":        cred.Name,
			"type":        cred.Type.String(),
			"provider":    cred.Provider,
			"status":      cred.Status.String(),
			"description": cred.Description,
			"tags":        cred.Tags,
			"rotation":    cred.Rotation,
			"usage":       cred.Usage,
			"created_at":  cred.CreatedAt,
			"updated_at":  cred.UpdatedAt,
		}
		if cred.LastUsed != nil {
			credData["last_used"] = cred.LastUsed
		}
		return formatter.PrintJSON(credData)
	}

	// Text output - formatted display
	fmt.Fprintf(cmd.OutOrStdout(), "Credential: %s\n", cred.Name)
	fmt.Fprintf(cmd.OutOrStdout(), "Type: %s\n", cred.Type)
	if cred.Provider != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "Provider: %s\n", cred.Provider)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Status: %s\n", cred.Status)
	if cred.Description != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "Description: %s\n", cred.Description)
	}
	if len(cred.Tags) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "Tags: %s\n", strings.Join(cred.Tags, ", "))
	}
	fmt.Fprintf(cmd.OutOrStdout(), "\nRotation:\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  Enabled: %v\n", cred.Rotation.Enabled)
	if cred.Rotation.Enabled {
		fmt.Fprintf(cmd.OutOrStdout(), "  Auto Rotate: %v\n", cred.Rotation.AutoRotate)
		if cred.Rotation.Interval != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "  Interval: %s\n", cred.Rotation.Interval)
		}
		if cred.Rotation.LastRotated != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "  Last Rotated: %s\n", cred.Rotation.LastRotated.Format(time.RFC3339))
		}
		if cred.Rotation.NextRotation != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "  Next Rotation: %s\n", cred.Rotation.NextRotation.Format(time.RFC3339))
		}
	}
	fmt.Fprintf(cmd.OutOrStdout(), "\nUsage:\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  Total Uses: %d\n", cred.Usage.TotalUses)
	fmt.Fprintf(cmd.OutOrStdout(), "  Last 24h: %d\n", cred.Usage.Usage24h)
	fmt.Fprintf(cmd.OutOrStdout(), "  Last 7d: %d\n", cred.Usage.Usage7d)
	fmt.Fprintf(cmd.OutOrStdout(), "  Failures: %d\n", cred.Usage.FailureCount)
	if cred.Usage.LastFailure != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "  Last Failure: %s\n", cred.Usage.LastFailure.Format(time.RFC3339))
	}
	fmt.Fprintf(cmd.OutOrStdout(), "\nCreated: %s\n", cred.CreatedAt.Format(time.RFC3339))
	fmt.Fprintf(cmd.OutOrStdout(), "Updated: %s\n", cred.UpdatedAt.Format(time.RFC3339))
	if cred.LastUsed != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "Last Used: %s\n", cred.LastUsed.Format(time.RFC3339))
	}

	return nil
}

func runCredentialTest(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	credName := args[0]

	// Parse global flags
	flags, err := ParseGlobalFlags(cmd)
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to parse flags", err)
	}

	// Setup verbose logging
	verboseLevel := flags.VerbosityLevel()
	cleanup := internal.SetupVerbose(cmd, verboseLevel, flags.OutputFormat == "json")
	defer cleanup()

	// Load configuration
	cfg, err := loadConfiguration(flags)
	if err != nil {
		return internal.WrapError(internal.ExitConfigError, "failed to load config", err)
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
		return internal.WrapError(internal.ExitDatabaseError, "failed to create state client", err)
	}
	defer stateClient.Close()

	// Get credential with Redis backend
	dao := database.NewRedisCredentialDAO(stateClient)
	cred, err := dao.GetByName(ctx, credName)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return internal.NewCLIError(internal.ExitNotFound, fmt.Sprintf("credential not found: %s", credName))
		}
		return internal.WrapError(internal.ExitDatabaseError, "failed to get credential", err)
	}

	// Get master key and decrypt credential
	masterKey, err := loadMasterKey(flags)
	if err != nil {
		return internal.WrapError(internal.ExitConfigError, "failed to load master key", err)
	}

	encryptor := crypto.NewAESGCMEncryptor()
	credValue, err := encryptor.Decrypt(cred.EncryptedValue, cred.EncryptionIV, cred.KeyDerivationSalt, masterKey)
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to decrypt credential", err)
	}

	// Create formatter
	outFormat := internal.FormatText
	if flags.OutputFormat == "json" {
		outFormat = internal.FormatJSON
	}
	formatter := internal.NewFormatter(outFormat, cmd.OutOrStdout())

	// Test credential based on provider
	if cred.Provider == "" {
		return formatter.PrintError("credential has no provider specified")
	}

	// Create a timeout context for API calls
	testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var testResult string
	var testErr error

	switch strings.ToLower(cred.Provider) {
	case "anthropic":
		testResult, testErr = testAnthropicCredential(testCtx, string(credValue))
	case "openai":
		testResult, testErr = testOpenAICredential(testCtx, string(credValue))
	case "google", "gemini":
		testResult, testErr = testGoogleCredential(testCtx, string(credValue))
	case "ollama":
		testResult = "Ollama uses local models and does not require API credentials"
		testErr = nil
	default:
		return formatter.PrintError(fmt.Sprintf("credential testing not supported for provider: %s", cred.Provider))
	}

	// Clear credential from memory
	for i := range credValue {
		credValue[i] = 0
	}

	if testErr != nil {
		return formatter.PrintError(fmt.Sprintf("Credential test failed: %s", testErr.Error()))
	}

	return formatter.PrintSuccess(fmt.Sprintf("Credential test passed: %s", testResult))
}

// testAnthropicCredential tests an Anthropic API key by calling the models endpoint
func testAnthropicCredential(ctx context.Context, apiKey string) (string, error) {
	// Import the anthropic provider to make a minimal API call
	providerCfg := llm.ProviderConfig{
		Type:         llm.ProviderAnthropic,
		APIKey:       apiKey,
		DefaultModel: "", // Provider will use its default model
	}

	provider, err := providers.NewProvider(providerCfg)
	if err != nil {
		return "", fmt.Errorf("failed to create Anthropic provider: %w", err)
	}

	// Call Models() which is a lightweight operation
	models, err := provider.Models(ctx)
	if err != nil {
		return "", fmt.Errorf("API call failed: %w", err)
	}

	if len(models) == 0 {
		return "", fmt.Errorf("no models returned (unexpected)")
	}

	return fmt.Sprintf("Successfully validated Anthropic API key (%d models available)", len(models)), nil
}

// testOpenAICredential tests an OpenAI API key by calling the models endpoint
func testOpenAICredential(ctx context.Context, apiKey string) (string, error) {
	providerCfg := llm.ProviderConfig{
		Type:         llm.ProviderOpenAI,
		APIKey:       apiKey,
		DefaultModel: "", // Provider will use its default model
	}

	provider, err := providers.NewProvider(providerCfg)
	if err != nil {
		return "", fmt.Errorf("failed to create OpenAI provider: %w", err)
	}

	// Call Models() which is a lightweight operation
	models, err := provider.Models(ctx)
	if err != nil {
		return "", fmt.Errorf("API call failed: %w", err)
	}

	if len(models) == 0 {
		return "", fmt.Errorf("no models returned (unexpected)")
	}

	return fmt.Sprintf("Successfully validated OpenAI API key (%d models available)", len(models)), nil
}

// testGoogleCredential tests a Google/Gemini API key by calling the models endpoint
func testGoogleCredential(ctx context.Context, apiKey string) (string, error) {
	providerCfg := llm.ProviderConfig{
		Type:         llm.ProviderGoogle,
		APIKey:       apiKey,
		DefaultModel: "", // Provider will use its default model
	}

	provider, err := providers.NewProvider(providerCfg)
	if err != nil {
		return "", fmt.Errorf("failed to create Google provider: %w", err)
	}

	// Call Models() which is a lightweight operation
	models, err := provider.Models(ctx)
	if err != nil {
		return "", fmt.Errorf("API call failed: %w", err)
	}

	if len(models) == 0 {
		return "", fmt.Errorf("no models returned (unexpected)")
	}

	return fmt.Sprintf("Successfully validated Google API key (%d models available)", len(models)), nil
}

func runCredentialRotate(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	credName := args[0]

	// Parse global flags
	flags, err := ParseGlobalFlags(cmd)
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to parse flags", err)
	}

	// Get new credential value securely
	var credValue string
	if credFromEnv != "" {
		// Read from environment variable
		credValue = os.Getenv(credFromEnv)
		if credValue == "" {
			return internal.NewCLIError(internal.ExitError, fmt.Sprintf("environment variable %s is not set or empty", credFromEnv))
		}
		if flags.IsVerbose() {
			cmd.PrintErrf("Read new credential from environment variable: %s\n", credFromEnv)
		}
	} else {
		// Prompt for new credential value securely (no echo)
		fmt.Fprint(cmd.OutOrStderr(), "Enter new credential value (input hidden): ")
		credValueBytes, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(cmd.OutOrStderr()) // New line after hidden input
		if err != nil {
			return internal.WrapError(internal.ExitError, "failed to read credential value", err)
		}
		credValue = string(credValueBytes)
		if credValue == "" {
			return internal.NewCLIError(internal.ExitError, "credential value cannot be empty")
		}

		// Confirm new value
		fmt.Fprint(cmd.OutOrStderr(), "Confirm new credential value (input hidden): ")
		confirmBytes, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(cmd.OutOrStderr()) // New line after hidden input
		if err != nil {
			return internal.WrapError(internal.ExitError, "failed to read confirmation", err)
		}
		if string(confirmBytes) != credValue {
			return internal.NewCLIError(internal.ExitError, "credential values do not match")
		}
	}

	// Load configuration
	cfg, err := loadConfiguration(flags)
	if err != nil {
		return internal.WrapError(internal.ExitConfigError, "failed to load config", err)
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
		return internal.WrapError(internal.ExitDatabaseError, "failed to create state client", err)
	}
	defer stateClient.Close()

	// Get existing credential with Redis backend
	dao := database.NewRedisCredentialDAO(stateClient)
	cred, err := dao.GetByName(ctx, credName)
	if err != nil {
		return internal.WrapError(internal.ExitDatabaseError, "failed to get credential", err)
	}

	// Get master key
	masterKey, err := loadMasterKey(flags)
	if err != nil {
		return internal.WrapError(internal.ExitConfigError, "failed to load master key", err)
	}

	// Encrypt new credential value
	encryptor := crypto.NewAESGCMEncryptor()
	encryptedValue, iv, salt, err := encryptor.Encrypt([]byte(credValue), masterKey)
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to encrypt credential", err)
	}

	// SECURITY: Clear plaintext from memory
	credValue = ""

	// Update credential
	cred.EncryptedValue = encryptedValue
	cred.EncryptionIV = iv
	cred.KeyDerivationSalt = salt
	cred.UpdatedAt = time.Now()

	// Update rotation info
	now := time.Now()
	cred.Rotation.LastRotated = &now

	// Save to database
	if err := dao.Update(ctx, cred); err != nil {
		return internal.WrapError(internal.ExitDatabaseError, "failed to update credential", err)
	}

	// Create formatter
	outFormat := internal.FormatText
	if flags.OutputFormat == "json" {
		outFormat = internal.FormatJSON
	}
	formatter := internal.NewFormatter(outFormat, cmd.OutOrStdout())
	return formatter.PrintSuccess(fmt.Sprintf("Credential rotated: %s", credName))
}

func runCredentialDelete(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	credName := args[0]

	// Parse global flags
	flags, err := ParseGlobalFlags(cmd)
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to parse flags", err)
	}

	// Confirmation prompt unless --force
	if !credForce {
		fmt.Fprintf(cmd.OutOrStderr(), "Delete credential '%s'? This cannot be undone. [y/N]: ", credName)
		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return internal.WrapError(internal.ExitError, "failed to read confirmation", err)
		}
		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			fmt.Fprintln(cmd.OutOrStderr(), "Cancelled")
			return nil
		}
	}

	// Load configuration
	cfg, err := loadConfiguration(flags)
	if err != nil {
		return internal.WrapError(internal.ExitConfigError, "failed to load config", err)
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
		return internal.WrapError(internal.ExitDatabaseError, "failed to create state client", err)
	}
	defer stateClient.Close()

	// Delete credential with Redis backend
	dao := database.NewRedisCredentialDAO(stateClient)
	if err := dao.DeleteByName(ctx, credName); err != nil {
		if strings.Contains(err.Error(), "not found") {
			return internal.NewCLIError(internal.ExitNotFound, fmt.Sprintf("credential not found: %s", credName))
		}
		return internal.WrapError(internal.ExitDatabaseError, "failed to delete credential", err)
	}

	// Create formatter
	outFormat := internal.FormatText
	if flags.OutputFormat == "json" {
		outFormat = internal.FormatJSON
	}
	formatter := internal.NewFormatter(outFormat, cmd.OutOrStdout())
	return formatter.PrintSuccess(fmt.Sprintf("Credential deleted: %s", credName))
}

// loadConfiguration loads the Gibson configuration
func loadConfiguration(flags *GlobalFlags) (*config.Config, error) {
	homeDir := flags.HomeDir
	if homeDir == "" {
		homeDir = os.Getenv("GIBSON_HOME")
	}
	if homeDir == "" {
		homeDir = config.DefaultHomeDir()
	}

	configFile := flags.ConfigFile
	if configFile == "" {
		configFile = config.DefaultConfigPath(homeDir)
	}

	loader := config.NewConfigLoader(config.NewValidator())
	cfg, err := loader.LoadWithDefaults(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load config from %s: %w", configFile, err)
	}

	return cfg, nil
}

// loadMasterKey loads the encryption master key from the key file
func loadMasterKey(flags *GlobalFlags) ([]byte, error) {
	homeDir := flags.HomeDir
	if homeDir == "" {
		homeDir = os.Getenv("GIBSON_HOME")
	}
	if homeDir == "" {
		homeDir = config.DefaultHomeDir()
	}

	keyPath := filepath.Join(homeDir, "master.key")
	keyManager := crypto.NewFileKeyManager()

	if !keyManager.KeyExists(keyPath) {
		return nil, fmt.Errorf("master key not found at %s (run 'gibson init')", keyPath)
	}

	key, err := keyManager.LoadKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load master key: %w", err)
	}

	return key, nil
}
